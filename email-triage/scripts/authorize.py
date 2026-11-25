"""Run once on your own computer to create token.json.

    python scripts/authorize.py --client-secret credentials.json

Then either keep token.json next to the app, or for a hosted server:
    python scripts/authorize.py --print-env
and paste the printed value into the GMAIL_TOKEN_JSON secret.
"""
import argparse
import base64
import os
import sys
from pathlib import Path

from google_auth_oauthlib.flow import InstalledAppFlow

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))
from triage.gmail_client import SCOPES  # noqa: E402


def main() -> None:
    p = argparse.ArgumentParser()
    p.add_argument("--client-secret", default="credentials.json")
    p.add_argument("--out", default="token.json")
    p.add_argument("--print-env", action="store_true", help="print base64 token for GMAIL_TOKEN_JSON")
    a = p.parse_args()

    if not (a.print_env and Path(a.out).exists()):
        flow = InstalledAppFlow.from_client_secrets_file(a.client_secret, SCOPES)
        creds = flow.run_local_server(port=0, access_type="offline", prompt="consent")
        Path(a.out).write_text(creds.to_json())
        os.chmod(a.out, 0o600)
        print(f"Saved {a.out}")
    if a.print_env:
        print(base64.b64encode(Path(a.out).read_bytes()).decode())


if __name__ == "__main__":
    main()
