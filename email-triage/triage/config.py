"""Configuration loaded from environment variables."""
from __future__ import annotations

import os
from dataclasses import dataclass, field
from pathlib import Path


def load_dotenv(path: str = ".env") -> None:
    """Minimal .env loader for local runs. Real env vars take precedence."""
    p = Path(path)
    if not p.exists():
        return
    for line in p.read_text().splitlines():
        line = line.strip()
        if not line or line.startswith("#") or "=" not in line:
            continue
        key, val = line.split("=", 1)
        os.environ.setdefault(key.strip(), val.strip().strip('"').strip("'"))


def _bool(name: str, default: bool) -> bool:
    val = os.getenv(name)
    if val is None:
        return default
    return val.strip().lower() in {"1", "true", "yes", "on"}


def _list(name: str, default: str = "") -> list[str]:
    raw = os.getenv(name, default)
    return [x.strip().lower() for x in raw.split(",") if x.strip()]


@dataclass
class Config:
    # Gmail
    my_email: str = field(default_factory=lambda: os.getenv("MY_EMAIL", "").lower())
    token_path: str = field(default_factory=lambda: os.getenv("GMAIL_TOKEN_PATH", "token.json"))
    # Base64 or raw JSON of token.json, for hosts without a persistent disk
    token_json_env: str = field(default_factory=lambda: os.getenv("GMAIL_TOKEN_JSON", ""))

    # Polling
    poll_seconds: int = field(default_factory=lambda: int(os.getenv("POLL_SECONDS", "60")))
    lookback_hours: int = field(default_factory=lambda: int(os.getenv("LOOKBACK_HOURS", "24")))
    batch_size: int = field(default_factory=lambda: int(os.getenv("BATCH_SIZE", "25")))

    # Claude
    anthropic_model: str = field(default_factory=lambda: os.getenv("ANTHROPIC_MODEL", "claude-sonnet-5-5"))
    min_reply_confidence: float = field(default_factory=lambda: float(os.getenv("MIN_REPLY_CONFIDENCE", "0.8")))
    profile_path: str = field(default_factory=lambda: os.getenv("PROFILE_PATH", "profile.md"))

    # Behaviour
    # "draft" = auto-replies are saved as Gmail drafts. "send" = sent immediately.
    reply_mode: str = field(default_factory=lambda: os.getenv("REPLY_MODE", "draft").lower())
    # If true, keyword hits force escalation even on newsletters/marketing mail.
    strict_keywords_on_bulk: bool = field(default_factory=lambda: _bool("STRICT_KEYWORDS_ON_BULK", False))
    # Senders that are always escalated / always just marked read
    vip_senders: list[str] = field(default_factory=lambda: _list("VIP_SENDERS"))
    ignore_senders: list[str] = field(default_factory=lambda: _list("IGNORE_SENDERS"))

    # Notifications
    notifier: str = field(default_factory=lambda: os.getenv("NOTIFIER", "gateway").lower())
    sms_gateway_address: str = field(default_factory=lambda: os.getenv("SMS_GATEWAY_ADDRESS", ""))
    twilio_sid: str = field(default_factory=lambda: os.getenv("TWILIO_ACCOUNT_SID", ""))
    twilio_token: str = field(default_factory=lambda: os.getenv("TWILIO_AUTH_TOKEN", ""))
    twilio_from: str = field(default_factory=lambda: os.getenv("TWILIO_FROM", ""))
    twilio_to: str = field(default_factory=lambda: os.getenv("TWILIO_TO", ""))
    max_texts_per_hour: int = field(default_factory=lambda: int(os.getenv("MAX_TEXTS_PER_HOUR", "10")))

    # State
    state_db: str = field(default_factory=lambda: os.getenv("STATE_DB", "data/state.db"))
    max_failures: int = field(default_factory=lambda: int(os.getenv("MAX_FAILURES", "3")))

    dry_run: bool = field(default_factory=lambda: _bool("DRY_RUN", False))
    label_root: str =field(default_factory=lambda: os.getenv("LABEL_ROOT", "AI Triage"))

    def validate(self) -> None:
        errors = []
        if not self.my_email:
            errors.append("MY_EMAIL is required")
        if self.reply_mode not in {"draft", "send"}:
            errors.append("REPLY_MODE must be 'draft' or 'send'")
        if self.notifier == "gateway" and not self.sms_gateway_address:
            errors.append("SMS_GATEWAY_ADDRESS is required when NOTIFIER=gateway")
        if self.notifier == "twilio" and not all(
            [self.twilio_sid, self.twilio_token, self.twilio_from, self.twilio_to]
        ):
            errors.append("TWILIO_* variables are required when NOTIFIER=twilio")
        if not os.getenv("ANTHROPIC_API_KEY"):
            errors.append("ANTHROPIC_API_KEY is required")
        if not Path(self.profile_path).exists():
            errors.append(f"Profile file not found: {self.profile_path}")
        if errors:
            raise SystemExit("Config errors:\n  - " + "\n  - ".join(errors))
