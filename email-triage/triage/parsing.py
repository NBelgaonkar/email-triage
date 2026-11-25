"""Turn a Gmail API message into a clean Email object."""
from __future__ import annotations

import base64
import html
import re
from dataclasses import dataclass, field
from email.utils import parseaddr

MAX_BODY_CHARS = 8000


@dataclass
class Email:
    id: str
    thread_id: str
    from_name: str
    from_addr: str
    to: str
    cc: str
    subject: str
    body: str
    message_id_header: str
    references: str
    reply_to: str
    label_ids: list[str] = field(default_factory=list)
    headers: dict[str, str] = field(default_factory=dict)
    internal_date_ms: int = 0

    @property
    def is_bulk(self) -> bool:
        """Newsletters, marketing, mailing lists, automated notifications."""
        h = self.headers
        precedence = h.get("precedence", "").lower()
        return bool(
            "list-unsubscribe" in h
            or "list-id" in h
            or precedence in {"bulk", "list", "junk"}
            or "CATEGORY_PROMOTIONS" in self.label_ids
            or "CATEGORY_SOCIAL" in self.label_ids
            or "CATEGORY_FORUMS" in self.label_ids
        )

    @property
    def is_automated(self) -> bool:
        """Mail that must never get an auto-reply (prevents reply loops)."""
        h = self.headers
        auto_submitted = h.get("auto-submitted", "no").lower()
        local = self.from_addr.split("@")[0]
        return bool(
            auto_submitted != "no"
            or "x-autoreply" in h
            or "x-autorespond" in h
            or re.search(r"(no-?reply|do-?not-?reply|mailer-daemon|postmaster|notifications?|bounce)", local)
        )


def _decode(data: str) -> str:
    raw = base64.urlsafe_b64decode(data + "=" * (-len(data) % 4))
    return raw.decode("utf-8", errors="replace")


def html_to_text(s: str) -> str:
    s = re.sub(r"(?is)<(script|style).*?</\1>", " ", s)
    s = re.sub(r"(?i)<br\s*/?>|</p>|</div>|</tr>|</li>", "\n", s)
    s = re.sub(r"<[^>]+>", " ", s)
    s = html.unescape(s)
    s = re.sub(r"[ \t\r\f\v]+", " ", s)
    s = re.sub(r"\n\s*\n+", "\n\n", s)
    return s.strip()


def strip_quoted(text: str) -> str:
    """Drop the quoted history below 'On <date>, X wrote:' and '>' lines."""
    lines = []
    for line in text.splitlines():
        if re.match(r"^\s*On .+wrote:\s*$", line) or line.strip().startswith("-----Original Message"):
            break
        if line.lstrip().startswith(">"):
            continue
        lines.append(line)
    return "\n".join(lines).strip()


def _extract_body(payload: dict) -> str:
    plain, html_parts = [], []

    def walk(part: dict) -> None:
        mime = part.get("mimeType", "")
        data = part.get("body", {}).get("data")
        if part.get("filename"):
            return  # attachment
        if data and mime == "text/plain":
            plain.append(_decode(data))
        elif data and mime == "text/html":
            html_parts.append(_decode(data))
        for sub in part.get("parts", []) or []:
            walk(sub)

    walk(payload)
    if plain:
        text = "\n".join(plain)
    elif html_parts:
        text = html_to_text("\n".join(html_parts))
    else:
        text = ""
    text = strip_quoted(text) or text
    return text[:MAX_BODY_CHARS]


def parse_message(msg: dict) -> Email:
    payload = msg.get("payload", {})
    # Keep the FIRST occurrence of each header. Gmail prepends its own trace
    # headers (Authentication-Results), so the first copy is Google's and any
    # later copy was supplied by the sender and can't be trusted.
    headers: dict[str, str] = {}
    for h in payload.get("headers", []):
        headers.setdefault(h["name"].lower(), h["value"])
    from_name, from_addr = parseaddr(headers.get("from", ""))
    return Email(
        id=msg["id"],
        thread_id=msg.get("threadId", msg["id"]),
        from_name=from_name or from_addr,
        from_addr=from_addr.lower(),
        to=headers.get("to", ""),
        cc=headers.get("cc", ""),
        subject=headers.get("subject", "(no subject)"),
        body=_extract_body(payload) or msg.get("snippet", ""),
        message_id_header=headers.get("message-id", ""),
        references=headers.get("references", ""),
        reply_to=headers.get("reply-to", ""),
        label_ids=msg.get("labelIds", []),
        headers=headers,
        internal_date_ms=int(msg.get("internalDate", 0)),
    )
