"""Local SQLite state: processed messages, failure counts, rate limits.

Gmail labels are the durable source of truth for "already handled" (they
survive a redeploy that wipes the disk). This DB is a fast second check and
holds counters for rate limiting.
"""
from __future__ import annotations

import sqlite3
import threading
import time
from pathlib import Path


class State:
    def __init__(self, path: str):
        if path != ":memory:":
            Path(path).parent.mkdir(parents=True, exist_ok=True)
        self._lock = threading.Lock()
        self.db = sqlite3.connect(path, check_same_thread=False)
        self.db.executescript(
            """
            CREATE TABLE IF NOT EXISTS processed (
                message_id TEXT PRIMARY KEY, action TEXT NOT NULL, reason TEXT, at REAL NOT NULL);
            CREATE TABLE IF NOT EXISTS failures (
                message_id TEXT PRIMARY KEY, count INTEGER NOT NULL);
            CREATE TABLE IF NOT EXISTS texts (at REAL NOT NULL);
            CREATE TABLE IF NOT EXISTS replies (
                thread_id TEXT NOT NULL, sender TEXT NOT NULL, at REAL NOT NULL);
            """
        )
        self.db.commit()

    def is_processed(self, message_id: str) -> bool:
        with self._lock:
            row = self.db.execute("SELECT 1 FROM processed WHERE message_id=?", (message_id,)).fetchone()
        return row is not None

    def mark_processed(self, message_id: str, action: str, reason: str = "") -> None:
        with self._lock:
            self.db.execute(
                "INSERT OR REPLACE INTO processed VALUES (?,?,?,?)", (message_id, action, reason, time.time())
            )
            self.db.execute("DELETE FROM failures WHERE message_id=?", (message_id,))
            self.db.commit()

    def record_failure(self, message_id: str) -> int:
        with self._lock:
            self.db.execute(
                "INSERT INTO failures VALUES (?,1) ON CONFLICT(message_id) DO UPDATE SET count=count+1",
                (message_id,),
            )
            self.db.commit()
            return self.db.execute("SELECT count FROM failures WHERE message_id=?", (message_id,)).fetchone()[0]

    # Rate limits -------------------------------------------------------
    def texts_in_last_hour(self) -> int:
        with self._lock:
            return self.db.execute("SELECT COUNT(*) FROM texts WHERE at > ?", (time.time() - 3600,)).fetchone()[0]

    def record_text(self) -> None:
        with self._lock:
            self.db.execute("INSERT INTO texts VALUES (?)", (time.time(),))
            self.db.execute("DELETE FROM texts WHERE at < ?", (time.time() - 86400,))
            self.db.commit()

    def replied_to_thread(self, thread_id: str) -> bool:
        with self._lock:
            return self.db.execute("SELECT 1 FROM replies WHERE thread_id=?", (thread_id,)).fetchone() is not None

    def replies_to_sender_today(self, sender: str) -> int:
        with self._lock:
            return self.db.execute(
                "SELECT COUNT(*) FROM replies WHERE sender=? AND at > ?", (sender, time.time() - 86400)
            ).fetchone()[0]

    def record_reply(self, thread_id: str, sender: str) -> None:
        with self._lock:
            self.db.execute("INSERT INTO replies VALUES (?,?,?)", (thread_id, sender, time.time()))
            self.db.commit()
