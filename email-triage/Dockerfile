FROM python:3.12-slim

ENV PYTHONDONTWRITEBYTECODE=1 PYTHONUNBUFFERED=1
WORKDIR /app

COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

COPY triage ./triage
COPY profile.md .

# Run as an unprivileged user
RUN useradd --create-home --uid 10001 app && mkdir -p /app/data && chown -R app:app /app
USER app

# Mount a volume here so state survives restarts (optional; Gmail labels are the main record)
VOLUME ["/app/data"]

CMD ["python", "-m", "triage.main"]
