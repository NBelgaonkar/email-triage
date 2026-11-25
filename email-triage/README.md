# AI Email Triage Assistant

![CI](../../actions/workflows/ci.yml/badge.svg)

> Example project. No API keys or credentials are included. Bring your own Gmail OAuth client and Anthropic API key (setup below). The test suite runs with no keys at all.

Watches a Gmail inbox 24/7. Claude reads each new email and picks one action:

| Action | What happens in Gmail |
|---|---|
| **Auto-reply** | Short reply in your voice. Saved as a **draft** (default) or sent. Labeled `AI Triage/Drafted` or `AI Triage/Replied` |
| **Escalate** | Texts you a one-line summary. Email stays unread, gets starred and labeled `AI Triage/Escalated` |
| **Mark read** | Marked read and labeled `AI Triage/Marked Read` |

Scheduling, money, job offers/recruiting, and legal mail is **always escalated**. This is enforced in code, not just in the prompt.

## How it works

```
poll Gmail (every 60s) -> unread, not yet labeled AI Triage/Processed
  -> skip own mail / phone-gateway replies
  -> code rules: ignore list, VIP list, keyword scan for sensitive topics
  -> Claude returns a structured decision (no ability to act on its own)
  -> code overrides: sensitive, suspicious, unverified sender, unsafe reply -> escalate
  -> act, record in SQLite, label in Gmail
```

Nothing is processed twice: every handled email gets the `AI Triage/Processed` label (survives redeploys) and a row in a local SQLite DB (survives a failed label call).

## Project structure

```
triage/
  main.py           polling loop, health endpoint, startup
  agent.py          decision pipeline and Gmail side effects
  classifier.py     Claude call with structured output
  rules.py          code-enforced rules: sensitive topics, sender auth, reply filter
  gmail_client.py   Gmail API wrapper, safe MIME building
  parsing.py        Gmail message to clean Email object
  notifier.py       email-to-SMS gateway and Twilio
  state.py          SQLite dedupe and rate limits
  config.py         environment config
scripts/authorize.py  one-time Gmail OAuth
tests/              59 tests, all external services faked
profile.md          template: how replies should sound
```

## What you need
- Python 3.12+
- A Google account with Gmail and a Google Cloud project (free)
- An Anthropic API key from https://console.anthropic.com
- A phone on a carrier with a working email-to-SMS gateway, or a Twilio account

## Setup

### 1. Gmail API credentials (once, about 10 minutes)
1. Go to https://console.cloud.google.com, create a project, enable the **Gmail API**.
2. **OAuth consent screen**: User type External, add yourself as a test user, then click **Publish app** (set it to "In production"). In Testing mode Google expires the refresh token after 7 days and the bot stops. You'll see an "unverified app" warning when you authorize; that's expected for a personal app.
3. **Credentials -> Create OAuth client ID -> Desktop app**. Download it as `credentials.json` into this folder.

### 2. Authorize (on your own computer)
```bash
python -m venv .venv && source .venv/bin/activate
pip install -r requirements.txt
python scripts/authorize.py            # opens a browser, writes token.json
```

### 3. Configure
```bash
cp .env.example .env
```
Fill in `MY_EMAIL`, `ANTHROPIC_API_KEY`, and `SMS_GATEWAY_ADDRESS`:
- Google Fi: `10digitnumber@msg.fi.google.com`
- US Cellular: `10digitnumber@email.uscc.net`

Replace the placeholders in `profile.md` so replies sound like you. Keep private details out of it (see Security).

### 4. Test safely
```bash
DRY_RUN=true python -m triage.main     # logs every decision, changes nothing
python -m triage.main                  # live, replies saved as drafts
```
Send yourself a test text first by emailing your gateway address from Gmail. Carrier gateways fail silently.

When the drafts look right for a week or so, set `REPLY_MODE=send`.

### 5. Deploy (any Docker host)
```bash
python scripts/authorize.py --print-env   # copy the output
```
Set these as **secrets** on your host: `GMAIL_TOKEN_JSON` (the copied value), `ANTHROPIC_API_KEY`, plus the rest of `.env`. Don't bake `token.json` into the image (`.dockerignore` already excludes it).

- **Railway**: New project from GitHub repo, it detects the Dockerfile. Add variables. Optionally attach a volume at `/app/data`.
- **Render**: New **Background Worker**, Docker runtime. Add env vars and a disk at `/app/data`.
- **Fly.io**: `fly launch --no-deploy`, `fly secrets set KEY=value ...`, `fly volumes create data`, mount at `/app/data`, `fly deploy`.
- **Any VPS**: `docker build -t email-triage . && docker run -d --restart unless-stopped --env-file .env -v triage-data:/app/data email-triage`

If your host requires a web port, set `PORT=8080` and point its health check at `/`.

## Configuration
See `.env.example`. Useful knobs:
- `VIP_SENDERS` always escalate (e.g. family). `IGNORE_SENDERS` always mark read. Accepts full addresses or domains. Only honored when Google verifies the sender.
- `MIN_REPLY_CONFIDENCE` (default 0.8) below this, auto-replies become escalations.
- `MAX_TEXTS_PER_HOUR` (default 10) beyond this, escalations are labeled but not texted.
- `STRICT_KEYWORDS_ON_BULK` off by default, so newsletters saying "$20 off" don't text you. The model still escalates real bills or payment problems in automated mail.

## Security

Every email is written by a stranger, so the design assumes the model **can** be tricked and limits what a tricked model can do.

**Prompt injection**
- The model has no tools that act. It only returns a decision; code carries it out.
- Email content goes inside a tag with a random per-request ID, so a sender can't "close" the email block and write their own instructions.
- Sensitive-topic escalation is a regex check in code that runs regardless of what the model says.
- Every auto-reply is checked in code before it goes out. Links, domains, email addresses, phone numbers, street addresses, credential words, sensitive topics, or prompt-leak phrases turn it into an escalation. Replies are capped at 700 characters.
- The model's output is validated. An unknown action becomes escalate.
- The model reports `suspicious` when an email tries to instruct it. Those get escalated and labeled `AI Triage/Suspicious`.

**Spoofing and phishing**
- Sender verification uses only Gmail's own `Authentication-Results` header (the first copy, from mx.google.com). It requires DMARC pass or a DKIM signature aligned with the From domain. Headers a sender adds are ignored.
- Unverified senders are never auto-replied, and VIP/ignore lists don't apply to them.
- Replies always go to the verified From address, never `Reply-To`. A Reply-To on a different domain blocks auto-reply.
- Texts have links and phone numbers stripped, so a phishing email can't put a clickable link or "call this number" on your phone.

**Loops and abuse**
- No auto-replies to bulk mail, no-reply addresses, or autoresponders (`Auto-Submitted`, RFC 3834). Outgoing replies carry `Auto-Submitted: auto-replied`.
- At most one auto-reply per thread and three per sender per day.
- Outgoing headers are stripped of CR/LF, which blocks header injection (e.g. a subject that sneaks in a `Bcc:`).

**Secrets**
- The Gmail token gives full mailbox access (read, send, label; no permanent delete). Store it only as a host secret. `token.json` is written with 0600 permissions and is git/docker-ignored.
- Container runs as a non-root user.

**Remaining risks to know about**
- A cleverly worded email could still get the model to **mark it read** instead of escalating. Skim the `AI Triage/Marked Read` label now and then, especially early on.
- Anything in `profile.md` could in principle appear in a reply. The reply filter blocks phone numbers, addresses and links, but keep the file free of private details anyway.
- Email content is sent to the Anthropic API for classification.
- Carrier gateways fail silently and are being shut down industry-wide. If texts stop arriving, switch to `NOTIFIER=twilio`.

## Tests
```bash
pip install -r requirements-dev.txt
python -m pytest -q
```
CI (GitHub Actions) runs lint, a Bandit security scan, and the tests on every push. No secrets are needed.

## License
MIT
59 tests cover the decision rules, prompt-injection and spoofing scenarios, dedupe, rate limits, MIME/header safety, and the Gmail wrapper against a fake API.
