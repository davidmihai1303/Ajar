"""Local event log for phone notifications (stage 3). Standard library only.

Events are deliberately minimal: a type, a severity, a count and, for score changes, the scores.
They never contain an IP address, a MAC address, a host name or a device maker, because the
events service (ajar_notify.py) is reachable from the home Wi-Fi. The details stay in the app.

Writers: ajar_autoscan.py (discover, run, watch). Reader: ajar_notify.py. SQLite handles the
concurrent access; the file lives next to the consent files (~/.config/ajar, 0600).
"""
from __future__ import annotations

import datetime as dt
import os
import sqlite3
from contextlib import contextmanager
from pathlib import Path

TYPES = {
    "new_device": "info",       # count = how many devices appeared
    "new_high_risk": "high",    # count = how many more high-severity findings than the previous scan
    "score_drop": "medium",     # score fell compared with the previous full scan
}
KEEP = 500                      # older events are deleted


class EventLog:
    def __init__(self, state_dir: Path):
        self.path = Path(state_dir) / "events.sqlite"

    @contextmanager
    def _connect(self):
        """One short-lived connection per call: committed on success and ALWAYS closed
        (sqlite3's own `with` only commits; the long-running services would leak handles)."""
        self.path.parent.mkdir(parents=True, exist_ok=True, mode=0o700)
        if not self.path.exists():
            os.close(os.open(self.path, os.O_WRONLY | os.O_CREAT, 0o600))
        db = sqlite3.connect(self.path, timeout=10)
        try:
            db.execute("CREATE TABLE IF NOT EXISTS events (id INTEGER PRIMARY KEY AUTOINCREMENT, time TEXT NOT NULL, "
                       "type TEXT NOT NULL, severity TEXT NOT NULL, count INTEGER NOT NULL, "
                       "score INTEGER, previous INTEGER)")
            yield db
            db.commit()
        finally:
            db.close()

    def add(self, kind: str, count: int = 1, score: int | None = None, previous: int | None = None) -> int:
        if kind not in TYPES:
            raise ValueError(f"unknown event type {kind}")
        stamp = dt.datetime.now(dt.timezone.utc).isoformat(timespec="seconds")
        with self._connect() as db:
            cur = db.execute("INSERT INTO events (time, type, severity, count, score, previous) VALUES (?, ?, ?, ?, ?, ?)",
                             (stamp, kind, TYPES[kind], int(count), score, previous))
            db.execute("DELETE FROM events WHERE id <= (SELECT MAX(id) FROM events) - ?", (KEEP,))
            return int(cur.lastrowid)

    def last_id(self) -> int:
        with self._connect() as db:
            return int(db.execute("SELECT COALESCE(MAX(id), 0) FROM events").fetchone()[0])

    def since(self, after: int, limit: int = 50) -> list[dict]:
        with self._connect() as db:
            rows = db.execute("SELECT id, time, type, severity, count, score, previous FROM events "
                              "WHERE id > ? ORDER BY id LIMIT ?", (int(after), int(limit))).fetchall()
        keys = ("id", "time", "type", "severity", "count", "score", "previous")
        return [{k: v for k, v in zip(keys, row) if v is not None} for row in rows]
