"""Send escalation texts."""
from __future__ import annotations

import base64
import logging
import re
import urllib.parse
import urllib.request

log = logging.getLogger(__name__)

SMS_LIMIT = 160
_URL = re.compile(r"https?://\S+|www\.\S+|\b[\w-]+\.(com|net|org|io|ai|co|ly|xyz|link|app)\b\S*", re.I)
_PHONE = re.compile(r"(\+?\d[\s.-]?)?\(?\d{3}\)?[\s.-]?\d{3}[\s.-]?\d{4}")


def _clean(s: str) -> str:
    s = _URL.sub("[link]", s or "")
    s = _PHONE.sub("[number]", s)  # no call-this-number lures on the owner's phone
    s = re.sub(r"[^\x20-\x7E]", "", s)  # SMS-safe ASCII only; strips control chars and emoji
    return " ".join(s.split())


def format_alert(from_name: str, subject: str, summary: str, reason: str) -> str:
    """Build a <=160 char text. Links are stripped so a malicious email can't
    put a clickable phishing link on the owner's phone."""
    head = f"[{_clean(reason)[:20]}] {_clean(from_name)[:30]}: {_clean(subject)[:50]}"
    tail = _clean(summary)
    text = f"{head} - {tail}" if tail else head
    return text[: SMS_LIMIT - 1] + "~" if len(text) > SMS_LIMIT else text


class GatewayNotifier:
    """Carrier email-to-SMS, sent through the user's own Gmail account."""

    def __init__(self, gmail, gateway_address: str, my_email: str):
        self.gmail, self.address, self.my_email = gmail, gateway_address, my_email

    def send(self, text: str) -> None:
        self.gmail.send_plain(self.address, text, self.my_email)


class TwilioNotifier:
    def __init__(self, sid: str, token: str, from_: str, to: str):
        if not re.fullmatch(r"AC[0-9a-fA-F]{32}", sid):
            raise SystemExit("TWILIO_ACCOUNT_SID looks invalid (expected AC + 32 hex chars)")
        self.sid, self.token, self.from_, self.to = sid, token, from_, to

    def send(self, text: str) -> None:
        url = f"https://api.twilio.com/2010-04-01/Accounts/{self.sid}/Messages.json"
        data = urllib.parse.urlencode({"From": self.from_, "To": self.to, "Body": text}).encode()
        req = urllib.request.Request(url, data=data, method="POST")
        auth = base64.b64encode(f"{self.sid}:{self.token}".encode()).decode()
        req.add_header("Authorization", f"Basic {auth}")
        # Fixed https URL; the SID is validated in __init__, so no file:// or custom schemes.
        with urllib.request.urlopen(req, timeout=20) as resp:  # nosec B310
            if resp.status >= 300:
                raise RuntimeError(f"Twilio returned {resp.status}")
