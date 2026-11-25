"""Thin wrapper over the Gmail API."""
from __future__ import annotations

import base64
import binascii
import json
import logging
import os
import time
from email.message import EmailMessage
from pathlib import Path

from google.auth.transport.requests import Request
from google.oauth2.credentials import Credentials
from googleapiclient.discovery import build
from googleapiclient.errors import HttpError

from .parsing import Email, parse_message

log = logging.getLogger(__name__)

# gmail.modify = read, label, mark read, draft and send. No permanent delete.
SCOPES = ["https://www.googleapis.com/auth/gmail.modify"]

LABEL_SUFFIXES = ["Processed", "Replied", "Drafted", "Escalated", "Marked Read", "Suspicious"]


def _clean_header(value: str) -> str:
    """Strip CR/LF so attacker-controlled text can't inject extra headers."""
    return " ".join(str(value).replace("\r", " ").replace("\n", " ").split())[:250]


# Bandit B107 below is a false positive: an empty default arg, not a password.
def load_credentials(token_path: str, token_json_env: str = "") -> Credentials:  # nosec B107
    if token_json_env:
        raw = token_json_env.strip()
        if not raw.startswith("{"):
            try:
                raw = base64.b64decode(raw).decode()
            except (binascii.Error, UnicodeDecodeError) as e:
                raise SystemExit("GMAIL_TOKEN_JSON is neither JSON nor valid base64") from e
        info = json.loads(raw)
        creds = Credentials.from_authorized_user_info(info, SCOPES)
    elif Path(token_path).exists():
        creds = Credentials.from_authorized_user_file(token_path, SCOPES)
    else:
        raise SystemExit(f"No Gmail token. Run scripts/authorize.py first (looked for {token_path}).")
    if not creds.valid:
        if creds.expired and creds.refresh_token:
            creds.refresh(Request())
            if not token_json_env:
                Path(token_path).write_text(creds.to_json())
                os.chmod(token_path, 0o600)
        else:
            raise SystemExit("Gmail token is invalid and cannot refresh. Re-run scripts/authorize.py.")
    return creds


class Gmail:
    def __init__(self, creds: Credentials, label_root: str = "AI Triage", service=None):
        self.svc = service or build("gmail", "v1", credentials=creds, cache_discovery=False)
        self.label_root = label_root
        self.labels: dict[str, str] = {}

    def _call(self, request, attempts: int = 4):
        for i in range(attempts):
            try:
                return request.execute()
            except HttpError as e:
                status = getattr(e.resp, "status", 0)
                if status in (429, 500, 502, 503, 504) and i < attempts - 1:
                    time.sleep(2 ** i)
                    continue
                raise

    # Labels ------------------------------------------------------------
    def ensure_labels(self) -> dict[str, str]:
        existing = {l["name"]: l["id"] for l in self._call(self.svc.users().labels().list(userId="me"))["labels"]}
        names = [self.label_root] + [f"{self.label_root}/{s}" for s in LABEL_SUFFIXES]
        for name in names:
            if name not in existing:
                body = {"name": name, "labelListVisibility": "labelShow", "messageListVisibility": "show"}
                existing[name] = self._call(self.svc.users().labels().create(userId="me", body=body))["id"]
        self.labels = {s: existing[f"{self.label_root}/{s}"] for s in LABEL_SUFFIXES}
        return self.labels

    def processed_query_term(self) -> str:
        # Gmail search syntax: label names lowercased, spaces and slashes -> hyphens
        name = f"{self.label_root}/Processed".lower().replace(" ", "-").replace("/", "-")
        return f"-label:{name}"

    # Reading -----------------------------------------------------------
    def list_candidates(self, lookback_hours: int, max_results: int) -> list[str]:
        after = int(time.time() - lookback_hours * 3600)
        q = f"in:inbox is:unread after:{after} {self.processed_query_term()}"
        resp = self._call(self.svc.users().messages().list(userId="me", q=q, maxResults=max_results))
        return [m["id"] for m in resp.get("messages", [])]

    def get(self, message_id: str) -> Email:
        msg = self._call(self.svc.users().messages().get(userId="me", id=message_id, format="full"))
        return parse_message(msg)

    # Writing -----------------------------------------------------------
    def modify(self, message_id: str, add: list[str] = (), remove: list[str] = ()) -> None:
        body = {"addLabelIds": list(add), "removeLabelIds": list(remove)}
        self._call(self.svc.users().messages().modify(userId="me", id=message_id, body=body))

    def _build_reply(self, email: Email, body: str, my_email: str) -> dict:
        msg = EmailMessage()
        msg["To"] = _clean_header(email.from_addr)  # always the authenticated From, never Reply-To
        msg["From"] = _clean_header(my_email)
        subject = email.subject if email.subject.lower().startswith("re:") else f"Re: {email.subject}"
        msg["Subject"] = _clean_header(subject)
        if email.message_id_header:
            mid = _clean_header(email.message_id_header)
            msg["In-Reply-To"] = mid
            msg["References"] = _clean_header(f"{email.references} {mid}".strip())
        msg["Auto-Submitted"] = "auto-replied"  # RFC 3834: tells other bots not to reply back
        msg.set_content(body)
        raw = base64.urlsafe_b64encode(msg.as_bytes()).decode()
        return {"raw": raw, "threadId": email.thread_id}

    def send_reply(self, email: Email, body: str, my_email: str) -> None:
        self._call(self.svc.users().messages().send(userId="me", body=self._build_reply(email, body, my_email)))

    def draft_reply(self, email: Email, body: str, my_email: str) -> None:
        payload = {"message": self._build_reply(email, body, my_email)}
        self._call(self.svc.users().drafts().create(userId="me", body=payload))

    def send_plain(self, to: str, body: str, my_email: str, subject: str = "") -> None:
        msg = EmailMessage()
        msg["To"] = _clean_header(to)
        msg["From"] = _clean_header(my_email)
        if subject:
            msg["Subject"] = _clean_header(subject)
        msg.set_content(body)
        raw = base64.urlsafe_b64encode(msg.as_bytes()).decode()
        sent = self._call(self.svc.users().messages().send(userId="me", body={"raw": raw}))
        # Keep alert texts out of the inbox view and mark them handled
        if sent and self.labels:
            try:
                self.modify(sent["id"], add=[self.labels["Processed"]])
            except HttpError:
                pass
