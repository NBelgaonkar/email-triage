"""The decision pipeline for a single email."""
from __future__ import annotations

import logging
from dataclasses import dataclass

from . import rules
from .classifier import Classifier, Decision
from .config import Config
from .notifier import format_alert
from .parsing import Email
from .state import State

log = logging.getLogger(__name__)

VALID_TOPICS = set(rules.SENSITIVE_PATTERNS)
MAX_REPLIES_PER_SENDER_PER_DAY = 3


@dataclass
class Outcome:
    action: str  # auto_reply | escalate | mark_read | skip | retry
    reason: str
    reply: str = ""
    summary: str = ""
    suspicious: bool = False


def decide(email: Email, cfg: Config, state: State, classifier: Classifier) -> Outcome:
    """Pure decision logic (no Gmail side effects), so it can be unit tested."""
    sender = email.from_addr
    authed = rules.is_authenticated(email)

    # 1. Mail we must not act on at all
    if sender == cfg.my_email:
        return Outcome("skip", "sent by owner")
    if cfg.sms_gateway_address and rules.sender_matches(sender, ["@" + cfg.sms_gateway_address.split("@")[-1]]):
        return Outcome("mark_read", "text reply from phone gateway")

    # 2. Deterministic pre-rules (spoofed senders don't get list treatment)
    if authed and rules.sender_matches(sender, cfg.ignore_senders):
        return Outcome("mark_read", "sender on ignore list")
    vip = authed and rules.sender_matches(sender, cfg.vip_senders)

    keyword_topics: list[str] = []
    if not email.is_bulk or cfg.strict_keywords_on_bulk:
        keyword_topics = rules.sensitive_topics(rules.email_text(email))

    # 3. Model
    try:
        d: Decision = classifier.classify(email, cfg.my_email)
    except Exception as e:  # network, API, malformed output
        n = state.record_failure(email.id)
        log.warning("classify failed for %s (attempt %d): %s", email.id, n, e)
        if n >= cfg.max_failures:
            return Outcome("escalate", "triage error", summary=email.subject)
        return Outcome("retry", f"classify error: {e}")

    topics = sorted(set(keyword_topics) | {t for t in d.sensitive_topics if t in VALID_TOPICS})
    base = dict(summary=d.summary, suspicious=d.suspicious)

    # 4. Overrides, strongest first
    if d.suspicious:
        return Outcome("escalate", "suspicious", **base)
    if topics:
        return Outcome("escalate", "+".join(topics), **base)
    if vip:
        return Outcome("escalate", "VIP sender", **base)
    if not email.is_bulk and not authed and d.action != "escalate":
        # Unauthenticated mail from a person: could be spoofed. Let the human decide.
        return Outcome("escalate", "unverified sender", **base)

    if d.action == "auto_reply":
        problem = _reply_problem(email, d, cfg, state, authed)
        if problem:
            if email.is_bulk or email.is_automated:
                return Outcome("mark_read", f"automated mail ({problem})", **base)
            return Outcome("escalate", f"needs you ({problem})", **base)
        return Outcome("auto_reply", "simple message", reply=d.reply.strip(), **base)

    if d.action == "mark_read":
        if not email.is_bulk and not email.is_automated and d.confidence < 0.6:
            return Outcome("escalate", "unsure", **base)
        return Outcome("mark_read", "no action needed", **base)

    return Outcome("escalate", "needs you", **base)


def _reply_problem(email: Email, d: Decision, cfg: Config, state: State, authed: bool) -> str | None:
    if email.is_bulk:
        return "bulk mail"
    if email.is_automated:
        return "automated sender"
    if not authed:
        return "unverified sender"
    if rules.reply_to_redirects(email):
        return "reply-to mismatch"
    if d.confidence < cfg.min_reply_confidence:
        return "low confidence"
    if state.replied_to_thread(email.thread_id):
        return "already auto-replied in thread"
    if state.replies_to_sender_today(email.from_addr) >= MAX_REPLIES_PER_SENDER_PER_DAY:
        return "sender reply limit"
    return rules.check_reply(d.reply)


class Agent:
    def __init__(self, cfg: Config, gmail, classifier: Classifier, notifier, state: State):
        self.cfg, self.gmail, self.classifier, self.notifier, self.state = cfg, gmail, classifier, notifier, state

    def handle(self, message_id: str) -> Outcome | None:
        L = self.gmail.labels
        if self.state.is_processed(message_id):
            # Side effect already happened; make sure the Gmail label stuck.
            self.gmail.modify(message_id, add=[L["Processed"]])
            return None

        email = self.gmail.get(message_id)
        if L["Processed"] in email.label_ids:
            self.state.mark_processed(message_id, "already-labeled")
            return None

        out = decide(email, self.cfg, self.state, self.classifier)
        log.info("%s | %s | %s -> %s (%s)", message_id, email.from_addr, email.subject[:60], out.action, out.reason)
        if out.action == "retry":
            return out
        if self.cfg.dry_run:
            log.info("DRY RUN: no changes made. reply=%r", out.reply)
            return out

        add, remove = [L["Processed"]], []
        if out.action == "skip":
            pass
        elif out.action == "mark_read":
            add.append(L["Marked Read"])
            remove.append("UNREAD")
        elif out.action == "auto_reply":
            if self.cfg.reply_mode == "send":
                self.gmail.send_reply(email, out.reply, self.cfg.my_email)
                add.append(L["Replied"])
                remove.append("UNREAD")
            else:
                self.gmail.draft_reply(email, out.reply, self.cfg.my_email)
                add.append(L["Drafted"])
            self.state.record_reply(email.thread_id, email.from_addr)
        elif out.action == "escalate":
            self._text(email, out)
            add += [L["Escalated"], "STARRED"]
            if out.suspicious:
                add.append(L["Suspicious"])

        # Record before labeling: if labeling fails we still never redo the side effect.
        self.state.mark_processed(message_id, out.action, out.reason)
        self.gmail.modify(message_id, add=add, remove=remove)
        return out

    def _text(self, email: Email, out: Outcome) -> None:
        if self.state.texts_in_last_hour() >= self.cfg.max_texts_per_hour:
            log.warning("text rate limit hit; %s escalated by label only", email.id)
            return
        reason = "SUSPICIOUS" if out.suspicious else out.reason
        text = format_alert(email.from_name, email.subject, out.summary, reason)
        try:
            self.notifier.send(text)
            self.state.record_text()
        except Exception as e:  # a failed text should not block labeling
            log.error("failed to send text for %s: %s", email.id, e)
