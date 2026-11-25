"""Entry point: poll Gmail forever."""
from __future__ import annotations

import logging
import os
import signal
import threading
import time
from http.server import BaseHTTPRequestHandler, HTTPServer
from pathlib import Path

from .agent import Agent
from .classifier import Classifier
from .config import Config, load_dotenv
from .gmail_client import Gmail, load_credentials
from .notifier import GatewayNotifier, TwilioNotifier
from .state import State

log = logging.getLogger("triage")
_stop = threading.Event()
_last_ok = {"t": time.time()}


def _health_server(port: int, poll_seconds: int) -> None:
    class H(BaseHTTPRequestHandler):
        def do_GET(self):  # noqa: N802
            healthy = time.time() - _last_ok["t"] < max(600, poll_seconds * 10)
            self.send_response(200 if healthy else 503)
            self.end_headers()
            self.wfile.write(b"ok" if healthy else b"stale")

        def log_message(self, *a):
            pass

    # Must listen on all interfaces inside a container; serves only "ok"/"stale"
    HTTPServer(("0.0.0.0", port), H).serve_forever()  # nosec B104


def build_agent(cfg: Config) -> Agent:
    creds = load_credentials(cfg.token_path, cfg.token_json_env)
    gmail = Gmail(creds, cfg.label_root)
    gmail.ensure_labels()
    profile = Path(cfg.profile_path).read_text()
    classifier = Classifier(cfg.anthropic_model, profile)
    if cfg.notifier == "twilio":
        notifier = TwilioNotifier(cfg.twilio_sid, cfg.twilio_token, cfg.twilio_from, cfg.twilio_to)
    else:
        notifier = GatewayNotifier(gmail, cfg.sms_gateway_address, cfg.my_email)
    return Agent(cfg, gmail, classifier, notifier, State(cfg.state_db))


def run_once(agent: Agent) -> int:
    ids = agent.gmail.list_candidates(agent.cfg.lookback_hours, agent.cfg.batch_size)
    handled = 0
    for mid in reversed(ids):  # oldest first
        if _stop.is_set():
            break
        try:
            if agent.handle(mid):
                handled += 1
        except Exception:
            log.exception("error handling %s; will retry next poll", mid)
            agent.state.record_failure(mid)
    return handled


def main() -> None:
    logging.basicConfig(
        level=os.getenv("LOG_LEVEL", "INFO"),
        format="%(asctime)s %(levelname)s %(name)s: %(message)s",
    )
    load_dotenv()
    cfg = Config()
    cfg.validate()
    agent = build_agent(cfg)
    log.info(
        "started: inbox=%s model=%s reply_mode=%s notifier=%s dry_run=%s",
        cfg.my_email, cfg.anthropic_model, cfg.reply_mode, cfg.notifier, cfg.dry_run,
    )

    if os.getenv("PORT"):
        threading.Thread(target=_health_server, args=(int(os.environ["PORT"]), cfg.poll_seconds), daemon=True).start()

    for sig in (signal.SIGINT, signal.SIGTERM):
        signal.signal(sig, lambda *_: _stop.set())

    backoff = cfg.poll_seconds
    while not _stop.is_set():
        try:
            n = run_once(agent)
            _last_ok["t"] = time.time()
            if n:
                log.info("handled %d message(s)", n)
            backoff = cfg.poll_seconds
        except Exception:
            log.exception("poll failed")
            backoff = min(backoff * 2, 900)
        _stop.wait(backoff)
    log.info("stopped")


if __name__ == "__main__":
    main()
