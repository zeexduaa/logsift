"""Questions asked of the index: matching events, how many over time, the most common values, and the main patterns."""

from __future__ import annotations

import json
import sqlite3
from dataclasses import dataclass

from .query import COLUMNS, Query, json_path
from .store import Store
from .timeparse import LEVELS

INTERVALS = (1, 5, 10, 30, 60, 300, 600, 900, 1800, 3600, 3 * 3600, 6 * 3600, 12 * 3600, 86400, 7 * 86400, 30 * 86400)


@dataclass
class Hit:
    id: int
    ts: float | None
    level: int | None
    service: str | None
    host: str | None
    message: str
    fields: dict
    raw: str | None
    source: str
    line: int
    pattern: str

    @property
    def level_name(self) -> str:
        return LEVELS[self.level] if self.level is not None else "-"

    def to_dict(self) -> dict:
        return {"id": self.id, "ts": self.ts, "level": self.level_name if self.level is not None else None,
                "service": self.service, "host": self.host, "message": self.message, "fields": self.fields,
                "source": self.source, "line": self.line}


def _hit(row: sqlite3.Row) -> Hit:
    return Hit(row["id"], row["ts"], row["level"], row["service"], row["host"], row["message"],
               json.loads(row["fields"]) if row["fields"] else {}, row["raw"], row["path"], row["line"], row["pattern"])


SELECT = ("SELECT events.*, sources.path FROM events JOIN sources ON sources.id = events.source_id WHERE {where}")
# Newest first; events with no timestamp sort by where they are in their file.
ORDER = " ORDER BY events.ts IS NULL, events.ts DESC, events.id DESC"


def search(store: Store, q: Query, *, limit: int = 100, before: tuple[float | None, int] | None = None) -> list[Hit]:
    """The newest `limit` matches, newest first. `before` = (ts, id) of the last hit shown, to page further back."""
    where, params = q.where, list(q.params)
    if before is not None:
        ts, last_id = before
        if ts is None:
            where += " AND events.ts IS NULL AND events.id < ?"
            params.append(last_id)
        else:
            where += " AND (events.ts IS NULL OR events.ts < ? OR (events.ts = ? AND events.id < ?))"
            params += [ts, ts, last_id]
    sql = SELECT.format(where=where) + ORDER + " LIMIT ?"
    return [_hit(r) for r in store.db.execute(sql, params + [limit])]


def get(store: Store, event_id: int) -> Hit | None:
    row = store.db.execute(SELECT.format(where="events.id = ?"), (event_id,)).fetchone()
    return _hit(row) if row else None


def context(store: Store, hit: Hit, around: int = 5) -> list[Hit]:
    """The lines just before and after an event in its own file, the way you'd see them with `less`."""
    # By event, not by line number: a 40-line stack trace is one event, and shouldn't swallow the context.
    same_file = "events.source_id = (SELECT source_id FROM events WHERE id = ?)"
    before = store.db.execute(SELECT.format(where=f"{same_file} AND events.line < ?") + " ORDER BY events.line DESC LIMIT ?",
                              (hit.id, hit.line, around)).fetchall()
    after = store.db.execute(SELECT.format(where=f"{same_file} AND events.line > ?") + " ORDER BY events.line LIMIT ?",
                             (hit.id, hit.line, around)).fetchall()
    return [_hit(r) for r in reversed(before)] + [hit] + [_hit(r) for r in after]


def count(store: Store, q: Query) -> int:
    return store.db.execute(f"SELECT COUNT(*) FROM events WHERE {q.where}", q.params).fetchone()[0]


@dataclass
class Summary:
    total: int
    first: float | None
    last: float | None
    levels: dict[str, int]
    no_time: int


def summary(store: Store, q: Query) -> Summary:
    row = store.db.execute(f"SELECT COUNT(*), MIN(ts), MAX(ts), SUM(ts IS NULL) FROM events WHERE {q.where}", q.params).fetchone()
    levels = {LEVELS[r[0]] if r[0] is not None else "none": r[1] for r in
              store.db.execute(f"SELECT level, COUNT(*) FROM events WHERE {q.where} GROUP BY level ORDER BY level", q.params)}
    return Summary(row[0], row[1], row[2], levels, row[3] or 0)


@dataclass
class Histogram:
    interval: int
    start: float
    buckets: list[tuple[float, int, int, int]]  # bucket start, errors (error+fatal), warnings, everything else

    @property
    def peak(self) -> int:
        return max((e + w + o for _, e, w, o in self.buckets), default=0)


def pick_interval(span: float, target: int = 60) -> int:
    """The smallest round interval that shows the span in about `target` bars or fewer."""
    for step in INTERVALS:
        if span / step <= target:
            return step
    return INTERVALS[-1]


def histogram(store: Store, q: Query, *, target: int = 60) -> Histogram | None:
    lo, hi = q.since, q.until
    if lo is None or hi is None:
        row = store.db.execute(f"SELECT MIN(ts), MAX(ts) FROM events WHERE {q.where}", q.params).fetchone()
        if row[0] is None:
            return None
        lo = row[0] if lo is None else lo
        hi = row[1] if hi is None else hi
    step = pick_interval(max(hi - lo, 1), target)
    start = (lo // step) * step
    sql = (f"SELECT CAST((ts - ?) / ? AS INTEGER) AS b, SUM(level >= 4), SUM(level = 3), SUM(level IS NULL OR level < 3) "
           f"FROM events WHERE ts IS NOT NULL AND {q.where} GROUP BY b ORDER BY b")
    counts = {r[0]: (r[1] or 0, r[2] or 0, r[3] or 0) for r in store.db.execute(sql, [start, step] + q.params)}
    n = int((hi - start) // step) + 1
    buckets = [(start + i * step, *counts.get(i, (0, 0, 0))) for i in range(n)]
    return Histogram(step, start, buckets)


def top(store: Store, q: Query, key: str, *, limit: int = 10) -> list[tuple[str, int]]:
    """The most common values of a field among the matches, with how often each appears."""
    k = key.lower()
    if k in ("level", "severity"):
        sql = f"SELECT level, COUNT(*) c FROM events WHERE {q.where} GROUP BY level ORDER BY c DESC LIMIT ?"
        return [(LEVELS[r[0]] if r[0] is not None else "(none)", r[1]) for r in store.db.execute(sql, q.params + [limit])]
    if k in ("source", "file"):
        sql = (f"SELECT sources.path, COUNT(*) c FROM events JOIN sources ON sources.id = events.source_id WHERE {q.where} "
               f"GROUP BY sources.path ORDER BY c DESC LIMIT ?")
        return [(r[0], r[1]) for r in store.db.execute(sql, q.params + [limit])]
    if k in COLUMNS:
        expr, params = f"events.{COLUMNS[k]}", []
    else:
        expr, params = "json_extract(events.fields, ?)", [json_path(key)]
    sql = f"SELECT {expr} v, COUNT(*) c FROM events WHERE {q.where} AND {expr} IS NOT NULL GROUP BY v ORDER BY c DESC, v LIMIT ?"
    return [(str(r[0]), r[1]) for r in store.db.execute(sql, params + q.params + params + [limit])]


@dataclass
class Pattern:
    template: str
    count: int
    first: float | None
    last: float | None
    level: int | None
    example: str
    services: str

    @property
    def level_name(self) -> str:
        return LEVELS[self.level] if self.level is not None else "-"


def patterns(store: Store, q: Query, *, limit: int = 20) -> list[Pattern]:
    """Matching events grouped by message shape, the biggest groups first."""
    sql = (f"SELECT pattern, COUNT(*) c, MIN(ts), MAX(ts), MAX(level), MIN(id), GROUP_CONCAT(DISTINCT service) "
           f"FROM events WHERE {q.where} GROUP BY pattern ORDER BY c DESC, MAX(level) DESC LIMIT ?")
    out = []
    for r in store.db.execute(sql, q.params + [limit]).fetchall():
        example = store.db.execute("SELECT message FROM events WHERE id = ?", (r[5],)).fetchone()[0]
        out.append(Pattern(r[0], r[1], r[2], r[3], r[4], example.split("\n", 1)[0], r[6] or ""))
    return out
