import base64
import os
import sys
from pathlib import Path

import pytest

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from triage.classifier import Decision  # noqa: E402
from triage.config import Config  # noqa: E402
from triage.parsing import parse_message  # noqa: E402
from triage.state import State  # noqa: E402

AUTH_PASS = "mx.google.com; dkim=pass header.i=@example.com; spf=pass; dmarc=pass"


def b64(s: str) -> str:
    return base64.urlsafe_b64encode(s.encode()).decode()


def raw_msg(
    *, id="m1", thread="t1", frm="Jane Doe <jane@example.com>", subject="Hello", body="Hi there",
    html=None, auth=AUTH_PASS, extra_headers=None, labels=None,
):
    headers = [
        {"name": "From", "value": frm},
        {"name": "To", "value": "me@gmail.com"},
        {"name": "Subject", "value": subject},
        {"name": "Message-ID", "value": f"<{id}@example.com>"},
    ]
    if auth:
        headers.append({"name": "Authentication-Results", "value": auth})
    for k, v in (extra_headers or {}).items():
        headers.append({"name": k, "value": v})
    if html is not None:
        payload = {"mimeType": "multipart/alternative", "headers": headers,
                   "parts": [{"mimeType": "text/html", "body": {"data": b64(html)}}]}
    else:
        payload = {"mimeType": "text/plain", "headers": headers, "body": {"data": b64(body)}}
    return {"id": id, "threadId": thread, "labelIds": labels or ["INBOX", "UNREAD"],
            "payload": payload, "internalDate": "0", "snippet": body[:50]}


def email(**kw):
    return parse_message(raw_msg(**kw))


class FakeClassifier:
    def __init__(self, decision=None, exc=None):
        self.decision, self.exc, self.calls = decision, exc, 0

    def classify(self, email, owner):
        self.calls += 1
        if self.exc:
            raise self.exc
        return self.decision


def decision(action="auto_reply", topics=(), conf=0.95, reply="Hi Jane,\n\nThanks, got it.\n\nBest,\nAlex",
             summary="Says thanks", suspicious=False):
    return Decision(action, list(topics), conf, summary, reply, suspicious)


@pytest.fixture
def cfg(monkeypatch, tmp_path):
    for k in list(os.environ):
        if k in {"VIP_SENDERS", "IGNORE_SENDERS", "STRICT_KEYWORDS_ON_BULK", "REPLY_MODE", "DRY_RUN"}:
            monkeypatch.delenv(k)
    monkeypatch.setenv("MY_EMAIL", "me@gmail.com")
    monkeypatch.setenv("SMS_GATEWAY_ADDRESS", "5555550123@msg.fi.google.com")
    return Config()


@pytest.fixture
def state():
    return State(":memory:")
