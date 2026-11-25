"""Deterministic rules that run in code, outside the model.

These are the safety backstop: a prompt-injected email can change what the
model *says*, but it cannot change these checks.
"""
from __future__ import annotations

import re

from .parsing import Email

# Topics that must always be escalated to a human, never auto-handled.
SENSITIVE_PATTERNS: dict[str, re.Pattern] = {
    "scheduling": re.compile(
        r"\b(schedul\w*|reschedul\w*|meeting|meet up|calendar|availability|available to|"
        r"interview\w*|appointment|zoom|google meet|teams call|calendly|invite|"
        r"time to (chat|talk|connect)|hop on a call|phone call|call (on|at|tomorrow|next))\b",
        re.I,
    ),
    "money": re.compile(
        r"(\$\s?\d|\b(usd|invoice|payment|paid|pay me|refund|salary|compensation|bank|wire|"
        r"zelle|venmo|paypal|cash ?app|price|pricing|quote|bill(ing)?|charge[ds]?|tax(es)?|"
        r"reimburse\w*|deposit|loan|owe[ds]?|crypto|bitcoin|gift ?cards?|account number|routing)\b)",
        re.I,
    ),
    "job_offer": re.compile(
        r"\b(job offer|offer letter|extend(ing)? (you )?an offer|offer of employment|"
        r"start date|onboarding|background check|recruit\w*|hiring|candidate|"
        r"position|opportunity|application|role at|next steps?)\b",
        re.I,
    ),
    "legal": re.compile(
        r"\b(legal|attorney|lawyer|counsel|contract|agreement|nda|non-disclosure|lawsuit|"
        r"subpoena|court|litigation|settlement|compliance|liabilit\w*|terms of service|"
        r"docusign|e-?sign\w*|signature|cease and desist|copyright|dmca|notari\w*)\b",
        re.I,
    ),
}

# Things an auto-reply must never contain. The model has no reason to include
# them in a short courtesy reply, so their presence suggests manipulation.
_REPLY_BLOCKLIST = [
    (re.compile(r"https?://|www\.|\b[\w-]+\.(com|net|org|io|ai|co|ly|xyz)\b", re.I), "link or domain"),
    (re.compile(r"[\w.+-]+@[\w-]+\.[\w.]+"), "email address"),
    (re.compile(r"(\+?1[\s.-]?)?\(?\d{3}\)?[\s.-]?\d{3}[\s.-]?\d{4}"), "phone number"),
    (re.compile(r"\b\d{1,5}\s+\w+\s+(road|rd|street|st|ave|avenue|lane|ln|drive|dr|blvd)\b", re.I), "street address"),
    (re.compile(r"\b(password|passcode|api key|token|secret|ssn|social security|verification code|2fa|otp)\b", re.I), "credential"),
    (re.compile(r"\b(ignore (all|previous|prior)|system prompt|as an ai|language model|instructions)\b", re.I), "model leakage"),
]

MAX_REPLY_CHARS = 700


def sensitive_topics(text: str) -> list[str]:
    return [name for name, pat in SENSITIVE_PATTERNS.items() if pat.search(text)]


def email_text(email: Email) -> str:
    return f"{email.subject}\n{email.body}"


def sender_matches(addr: str, patterns: list[str]) -> bool:
    """Match full addresses (a@b.com) or whole domains (@b.com / b.com)."""
    addr = addr.lower()
    domain = addr.rsplit("@", 1)[-1]
    for p in patterns:
        p = p.lower().lstrip("@")
        if addr == p or domain == p or domain.endswith("." + p):
            return True
    return False


def _domain_aligned(signed: str, from_domain: str) -> bool:
    signed = signed.lower().lstrip("@")
    return signed == from_domain or from_domain.endswith("." + signed) or signed.endswith("." + from_domain)


def is_authenticated(email: Email) -> bool:
    """True only if Google's own check shows the From domain is genuine.

    Guards against spoofed From addresses: we never auto-reply to, or trust
    allow/ignore lists for, a sender we cannot authenticate.

    - Only Gmail's Authentication-Results (authserv-id mx.google.com, first
      copy) counts. A sender can add a fake header of their own.
    - A bare spf=pass or a DKIM signature from some other domain proves
      nothing about the From address, so we require DMARC pass, or a DKIM
      pass whose signing domain aligns with the From domain.
    """
    results = email.headers.get("authentication-results", "")
    if not results.lower().lstrip().startswith("mx.google.com"):
        return False
    from_domain = email.from_addr.rsplit("@", 1)[-1].lower()
    if re.search(r"\bdmarc=pass\b", results, re.I):
        return True
    for m in re.finditer(r"\bdkim=pass\b[^;]*?header\.(?:i|d)=([^\s;]+)", results, re.I):
        signed = m.group(1).rsplit("@", 1)[-1]
        if _domain_aligned(signed, from_domain):
            return True
    return False


def reply_to_redirects(email: Email) -> bool:
    """Reply-To pointing at a different domain than From is a classic phishing trick."""
    if not email.reply_to:
        return False
    from email.utils import parseaddr

    _, rt = parseaddr(email.reply_to)
    if not rt or "@" not in rt:
        return False
    return rt.lower().rsplit("@", 1)[-1] != email.from_addr.rsplit("@", 1)[-1]


def check_reply(text: str) -> str | None:
    """Return a reason string if the draft reply is unsafe, else None."""
    if not text or not text.strip():
        return "empty reply"
    if len(text) > MAX_REPLY_CHARS:
        return "reply too long"
    for pattern, reason in _REPLY_BLOCKLIST:
        if pattern.search(text):
            return f"reply contains {reason}"
    topics = sensitive_topics(text)
    if topics:
        return f"reply touches sensitive topic: {', '.join(topics)}"
    return None
