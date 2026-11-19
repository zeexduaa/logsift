"""The search language, compiled to SQL.

    timeout                      words anywhere in the message ("timeout*" for words starting with it)
    "connection refused"         an exact phrase
    -healthcheck                 leave out events containing a word (works on every kind of term)
    level:error   level>=warn    severity: trace debug info warn error fatal
    service:api   host:web-1     who logged it (service:api,worker for either)
    status>=500   duration>1.5   any field, compared as a number when the value is one
    path:/api/*   user:alice     any field; * is a wildcard; nested fields with dots: db.table:orders
    source:nginx                 the file it came from (part of the path)
    since:1h   until:2026-11-19  a time window: 15m, 2h, 7d, today, yesterday, a date or "2026-11-19 07:50"
    pattern:"Timeout after <num>ms talking to <ip>"   one group from `logsift patterns`

Everything a person types ends up as a bound parameter, never as SQL text.
"""

from __future__ import annotations

import re
from dataclasses import dataclass, field

from .timeparse import LEVELS, Clock, TimeError, level_rank, parse_point


class QueryError(ValueError):
    """A search that can't be understood; the message says what to change."""


COLUMNS = {"service": "service", "app": "service", "logger": "service", "host": "host", "hostname": "host"}
OPS = (">=", "<=", "!=", ">", "<", ":", "=")
TOKEN = re.compile(r'''
    \s*(?P<neg>-)?
    (?:
        (?P<key>[A-Za-z_@][\w.@-]*)(?P<op>>=|<=|!=|>|<|:|=)(?P<value>"(?:[^"\\]|\\.)*"?|[^\s"]*)
      | (?P<phrase>"(?:[^"\\]|\\.)*"?)
      | (?P<word>[^\s"]+)
    )''', re.X)


@dataclass
class Term:
    kind: str           # text | field
    value: str
    negate: bool = False
    key: str = ""
    op: str = ":"
    phrase: bool = False


@dataclass
class Query:
    text: str = ""
    terms: list[Term] = field(default_factory=list)
    since: float | None = None
    until: float | None = None
    where: str = "1"
    params: list = field(default_factory=list)

    @property
    def words(self) -> list[str]:
        """The positive text terms, for highlighting matches."""
        return [t.value.rstrip("*") for t in self.terms if t.kind == "text" and not t.negate and t.value.rstrip("*")]


def _unquote(text: str) -> str:
    if len(text) >= 2 and text[0] == text[-1] == '"':
        return re.sub(r"\\(.)", r"\1", text[1:-1])
    return text


def tokenize(text: str) -> list[Term]:
    terms: list[Term] = []
    pos = 0
    text = text.strip()
    while pos < len(text):
        m = TOKEN.match(text, pos)
        if not m or m.end() == pos:
            raise QueryError(f"can't read the search from {text[pos:pos + 20]!r}; check for an unclosed quote")
        pos = m.end()
        neg = bool(m.group("neg"))
        if m.group("key") is not None:
            value = m.group("value")
            # "http://x", "error:" or "12:30" aren't field searches: treat them as plain words
            if value == "" or value.startswith("//"):
                terms.append(Term("text", m.group(0).strip().lstrip("-"), neg))
                continue
            if value.startswith('"') and (len(value) < 2 or not value.endswith('"')):
                raise QueryError(f"the quote after {m.group('key')}{m.group('op')} is never closed")
            terms.append(Term("field", _unquote(value), neg, m.group("key"), m.group("op"), value.startswith('"')))
        elif m.group("phrase") is not None:
            phrase = m.group("phrase")
            if len(phrase) < 2 or not phrase.endswith('"'):
                raise QueryError("a quote is never closed")
            if _unquote(phrase).strip():
                terms.append(Term("text", _unquote(phrase), neg, phrase=True))
        else:
            word = m.group("word")
            if word.startswith('"'):
                raise QueryError("a quote is never closed")
            terms.append(Term("text", word, neg))
    return terms


def _number(text: str) -> float | int | None:
    if re.fullmatch(r"-?\d+", text):
        return int(text)
    if re.fullmatch(r"-?\d*\.\d+", text):
        return float(text)
    return None


def _like(value: str) -> str:
    escaped = value.replace("\\", "\\\\").replace("%", "\\%").replace("_", "\\_")
    return escaped.replace("*", "%")


def json_path(key: str) -> str:
    """"db.table" -> '$."db"."table"' (each part quoted, so odd characters in field names can't break the path)."""
    return "$" + "".join('."' + part.replace('"', '\\"') + '"' for part in key.split("."))


def _fts_phrase(value: str) -> str:
    """One FTS5 term: always a quoted string, so FTS operators typed by a person (AND, NEAR, column:) are just text."""
    prefix = value.endswith("*") and not value.endswith("\\*")
    core = value[:-1] if prefix else value
    return '"' + core.replace('"', '""') + '"' + ("*" if prefix else "")


class Compiler:
    def __init__(self, clock: Clock, fts: bool):
        self.clock = clock
        self.fts = fts
        self.where: list[str] = []
        self.params: list = []

    def add(self, sql: str, params: list, negate: bool) -> None:
        # NOT COALESCE(...) so "-service:api" also keeps events that have no service at all
        self.where.append(f"NOT COALESCE(({sql}), 0)" if negate else f"({sql})")
        self.params += params

    def text(self, terms: list[Term]) -> None:
        positive = [t for t in terms if not t.negate]
        negative = [t for t in terms if t.negate]
        if self.fts:
            if positive:
                self.add("events.id IN (SELECT rowid FROM events_fts WHERE events_fts MATCH ?)",
                         [" ".join(_fts_phrase(t.value) for t in positive)], False)
            for t in negative:
                self.add("events.id IN (SELECT rowid FROM events_fts WHERE events_fts MATCH ?)", [_fts_phrase(t.value)], True)
        else:  # no FTS5 in this SQLite: a plain substring search, slower but the same results for whole words
            for t in terms:
                self.add("events.message LIKE ? ESCAPE '\\'", ["%" + _like(t.value.rstrip("*")) + "%"], t.negate)

    def field(self, t: Term) -> None:
        key = t.key.lower()
        if key in ("since", "until", "after", "before"):
            if t.negate or t.op != ":":
                raise QueryError(f"write {key}:<time>, e.g. {key}:1h or {key}:2026-11-19")
            try:
                point = parse_point(t.value, self.clock)
            except TimeError as err:
                raise QueryError(str(err)) from None
            self.add("events.ts >= ?" if key in ("since", "after") else "events.ts < ?", [point], False)
            return
        if key in ("level", "severity", "lvl"):
            self.level(t)
            return
        if key in ("source", "file"):
            self.add("events.source_id IN (SELECT id FROM sources WHERE path LIKE ? ESCAPE '\\')", ["%" + _like(t.value) + "%"], t.negate)
            return
        if key == "pattern":
            self.add("events.pattern = ?", [t.value], t.negate)
            return
        if key in ("message", "msg"):
            self.add("events.message LIKE ? ESCAPE '\\'", ["%" + _like(t.value) + "%"], t.negate)
            return
        expr, params = (f"events.{COLUMNS[key]}", []) if key in COLUMNS else ("json_extract(events.fields, ?)", [json_path(t.key)])
        self.compare(expr, params, t)

    def level(self, t: Term) -> None:
        ranks = []
        for name in t.value.split(","):
            rank = level_rank(name)
            if rank is None:
                raise QueryError(f"{name!r} isn't a level; use one of {', '.join(LEVELS)}")
            ranks.append(rank)
        if t.op in (":", "="):
            self.add(f"events.level IN ({','.join('?' * len(ranks))})", ranks, t.negate)
        elif t.op == "!=":
            self.add(f"events.level IN ({','.join('?' * len(ranks))})", ranks, not t.negate)
        else:
            if len(ranks) > 1:
                raise QueryError(f"level{t.op} takes one level")
            self.add(f"events.level {t.op} ?", ranks, t.negate)

    def compare(self, expr: str, params: list, t: Term) -> None:
        value, op = t.value, t.op
        if op in (">", ">=", "<", "<="):
            n = _number(value)
            if n is None:
                raise QueryError(f"{t.key}{op} needs a number, not {value!r}")
            self.add(f"CAST({expr} AS REAL) {op} ? AND {expr} IS NOT NULL", params + [n] + params, t.negate)
            return
        negate = t.negate != (op == "!=")
        options = value.split(",") if ("," in value and not t.phrase) else [value]
        parts, args = [], []
        for option in options:
            n = _number(option)
            if "*" in option:
                parts.append(f"{expr} LIKE ? ESCAPE '\\'")
                args += params + [_like(option)]
            elif n is not None:  # 404 might be stored as a number or as the text "404"
                parts.append(f"({expr} = ? OR {expr} = ?)")
                args += params + [n] + params + [option]
            else:
                parts.append(f"{expr} = ? COLLATE NOCASE")
                args += params + [option]
        self.add(" OR ".join(parts), args, negate)


def compile_query(text: str, clock: Clock, *, fts: bool = True) -> Query:
    terms = tokenize(text)
    c = Compiler(clock, fts)
    c.text([t for t in terms if t.kind == "text"])
    for t in terms:
        if t.kind == "field":
            c.field(t)
    query = Query(text=text, terms=terms, where=" AND ".join(c.where) or "1", params=c.params)
    for t in terms:
        if t.kind == "field" and t.key.lower() in ("since", "after"):
            query.since = parse_point(t.value, clock)
        if t.kind == "field" and t.key.lower() in ("until", "before"):
            query.until = parse_point(t.value, clock)
    return query
