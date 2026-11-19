"""The index: one SQLite file with every event, a full-text index over the messages, and what's been read from each file."""

from __future__ import annotations

import json
import os
import sqlite3
import sys
import time
from dataclasses import dataclass
from pathlib import Path

from .parsers import Event
from .patterns import template

SCHEMA = [
    # version 1
    """
    CREATE TABLE sources (
        id INTEGER PRIMARY KEY, path TEXT NOT NULL UNIQUE, format TEXT NOT NULL,
        size INTEGER NOT NULL DEFAULT 0, offset INTEGER NOT NULL DEFAULT 0, line INTEGER NOT NULL DEFAULT 0,
        head TEXT NOT NULL DEFAULT '', events INTEGER NOT NULL DEFAULT 0, ingested_at REAL NOT NULL DEFAULT 0);
    CREATE TABLE events (
        id INTEGER PRIMARY KEY, ts REAL, level INTEGER, source_id INTEGER NOT NULL REFERENCES sources(id) ON DELETE CASCADE,
        line INTEGER NOT NULL, service TEXT, host TEXT, message TEXT NOT NULL, fields TEXT, raw TEXT, pattern TEXT NOT NULL);
    CREATE INDEX events_by_time ON events(ts);
    CREATE INDEX events_by_level ON events(level, ts);
    CREATE INDEX events_by_service ON events(service, ts);
    CREATE INDEX events_by_pattern ON events(pattern);
    CREATE INDEX events_by_source ON events(source_id, line);
    """,
]

FTS = """
CREATE VIRTUAL TABLE events_fts USING fts5(message, content='events', content_rowid='id');
CREATE TRIGGER events_fts_insert AFTER INSERT ON events BEGIN
    INSERT INTO events_fts(rowid, message) VALUES (new.id, new.message);
END;
CREATE TRIGGER events_fts_delete AFTER DELETE ON events BEGIN
    INSERT INTO events_fts(events_fts, rowid, message) VALUES ('delete', old.id, old.message);
END;
"""


def pattern_of(ev: Event, first_line: str) -> str:
    """Web requests are grouped by method, path shape and status: a 404 and a 502 on the same URL are different problems."""
    f = ev.fields
    if isinstance(f.get("status"), int) and "method" in f and "path" in f:
        path = str(f["path"]).split("?", 1)[0]
        return f"{f['method']} {template(path)} {f['status']}"
    return template(first_line)


class StoreError(RuntimeError):
    """The index file can't be opened, or was made by a newer logsift."""


def default_path() -> Path:
    if os.environ.get("LOGSIFT_DB"):
        return Path(os.environ["LOGSIFT_DB"]).expanduser()
    if sys.platform == "win32":
        base = Path(os.environ.get("LOCALAPPDATA") or Path.home() / "AppData" / "Local")
    elif sys.platform == "darwin":
        base = Path.home() / "Library" / "Caches"
    else:
        base = Path(os.environ.get("XDG_CACHE_HOME") or Path.home() / ".cache")
    return base / "logsift" / "index.db"


@dataclass
class Source:
    id: int
    path: str
    format: str
    size: int
    offset: int
    line: int
    head: str
    events: int
    ingested_at: float


def fts5_available() -> bool:
    try:
        with sqlite3.connect(":memory:") as db:
            db.execute("CREATE VIRTUAL TABLE t USING fts5(x)")
        return True
    except sqlite3.OperationalError:
        return False


class Store:
    def __init__(self, path: str | Path = ":memory:"):
        self.path = str(path)
        if self.path != ":memory:":
            Path(self.path).parent.mkdir(parents=True, exist_ok=True)
        try:
            self.db = sqlite3.connect(self.path, check_same_thread=False)
            self.db.row_factory = sqlite3.Row
            self.db.execute("PRAGMA foreign_keys = ON")
            if self.path != ":memory:":
                self.db.execute("PRAGMA journal_mode = WAL")   # searching while a big ingest runs
            self.db.execute("PRAGMA synchronous = NORMAL")
            self._migrate()
            self.fts = bool(self.db.execute("SELECT 1 FROM sqlite_master WHERE name = 'events_fts'").fetchone())
        except sqlite3.DatabaseError as err:
            raise StoreError(f"can't open {self.path}: {err}") from err

    def _migrate(self) -> None:
        version = self.db.execute("PRAGMA user_version").fetchone()[0]
        if version > len(SCHEMA):
            raise StoreError(f"{self.path} was made by a newer version of logsift; upgrade, or delete it and ingest again")
        for number, script in enumerate(SCHEMA[version:], start=version + 1):
            # Full-text search needs SQLite's FTS5, which nearly every Python has. Without it searching still works, slower.
            extra = FTS if number == 1 and fts5_available() else ""
            self.db.executescript(f"BEGIN; {script}; {extra}; PRAGMA user_version = {number}; COMMIT;")

    def close(self) -> None:
        self.db.close()

    # -- sources ---------------------------------------------------------------------------------

    @staticmethod
    def _source(row: sqlite3.Row) -> Source:
        return Source(**{k: row[k] for k in row.keys()})

    def source(self, path: str) -> Source | None:
        row = self.db.execute("SELECT * FROM sources WHERE path = ?", (path,)).fetchone()
        return self._source(row) if row else None

    def sources(self) -> list[Source]:
        return [self._source(r) for r in self.db.execute("SELECT * FROM sources ORDER BY path")]

    def add_source(self, path: str, fmt: str) -> Source:
        self.db.execute("INSERT INTO sources (path, format) VALUES (?, ?)", (path, fmt))
        return self.source(path)  # type: ignore[return-value]

    def save_progress(self, source: Source) -> None:
        self.db.execute("UPDATE sources SET format=?, size=?, offset=?, line=?, head=?, events=?, ingested_at=? WHERE id=?",
                        (source.format, source.size, source.offset, source.line, source.head, source.events, time.time(), source.id))

    def clear_source(self, source: Source) -> None:
        """Forget everything read from a file (it was replaced or truncated), keeping the source itself."""
        self.db.execute("DELETE FROM events WHERE source_id = ?", (source.id,))
        source.offset = source.line = source.events = source.size = 0

    def forget(self, path: str) -> int:
        """Remove a file and all its events from the index."""
        src = self.source(path)
        if not src:
            return 0
        with self.db:
            self.db.execute("DELETE FROM sources WHERE id = ?", (src.id,))
        return src.events

    # -- events ----------------------------------------------------------------------------------

    def insert(self, source: Source, events: list[Event]) -> None:
        rows = []
        for ev in events:
            first = ev.message.split("\n", 1)[0]
            raw = ev.raw if ev.raw and ev.raw != ev.message else None
            rows.append((ev.ts, ev.level, source.id, ev.line, ev.service, ev.host, ev.message,
                         json.dumps(ev.fields, ensure_ascii=False, default=str) if ev.fields else None, raw, pattern_of(ev, first)))
        self.db.executemany("INSERT INTO events (ts, level, source_id, line, service, host, message, fields, raw, pattern) "
                            "VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)", rows)
        source.events += len(rows)

    def prune(self, before: float) -> int:
        """Delete events older than `before` (events with no time are kept)."""
        with self.db:
            cur = self.db.execute("DELETE FROM events WHERE ts < ?", (before,))
            for src in self.sources():
                count = self.db.execute("SELECT COUNT(*) FROM events WHERE source_id = ?", (src.id,)).fetchone()[0]
                self.db.execute("UPDATE sources SET events = ? WHERE id = ?", (count, src.id))
        return cur.rowcount

    def compact(self) -> None:
        if self.fts:
            with self.db:
                self.db.execute("INSERT INTO events_fts(events_fts) VALUES ('optimize')")
        self.db.execute("VACUUM")

    def count(self) -> int:
        return self.db.execute("SELECT COUNT(*) FROM events").fetchone()[0]
