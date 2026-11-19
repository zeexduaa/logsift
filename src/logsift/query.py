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
    a OR b   (a OR b) c          either one; brackets group; terms side by side must all match
    NOT (level:info OR health)   leave out everything in the brackets (-(...) works too)

Everything a person types ends up as a bound parameter, never as SQL text.
"""

from __future__ import annotations

import re
from dataclasses import dataclass, field

from .timeparse import LEVELS, Clock, TimeError, level_rank, parse_point


class QueryError(ValueError):
    """A search that can't be understood; the message says what to change."""


COLUMNS = {"service": "service", "app": "service", "logger": "service", "host": "host", "hostname": "host"}
TERM = re.compile(r'(?P<key>[A-Za-z_@][\w.@-]*)(?P<op>>=|<=|!=|>|<|:|=)(?P<value>.*)', re.S)
TIME_KEYS = ("since", "until", "after", "before")
# Keys whose value isn't a comma-separated list (part of a path, a phrase in the message, a whole pattern)
NOT_LISTS = TIME_KEYS + ("pattern", "source", "file", "message", "msg")


@dataclass
class Term:
    kind: str           # text | field
    value: str
    negate: bool = False
    key: str = ""
    op: str = ":"
    phrase: bool = False


@dataclass
class Group:
    """A node of the parsed search: all of `parts` (and), any of them (or), or none (not, with one part)."""
    op: str
    parts: list
    negate: bool = False


@dataclass
class Query:
    text: str = ""
    terms: list[Term] = field(default_factory=list)
    since: float | None = None
    until: float | None = None
    where: str = "1"
    params: list = field(default_factory=list)
    highlight: list[str] = field(default_factory=list)

    @property
    def words(self) -> list[str]:
        """The text terms that make an event match (not the ones it must avoid), for highlighting."""
        return self.highlight


def _unquote(text: str) -> str:
    if len(text) >= 2 and text[0] == text[-1] == '"':
        return re.sub(r"\\(.)", r"\1", text[1:-1])
    return text


def _chunk_end(text: str, i: int) -> int:
    """Where a term starting at i ends: at whitespace or an unbalanced ")", but never inside quotes."""
    j, quoted, depth = i, False, 0
    while j < len(text):
        ch = text[j]
        if ch == "\\" and quoted:
            j += 2
            continue
        if ch == '"':
            quoted = not quoted
        elif not quoted:
            if ch.isspace():
                break
            if ch == "(":
                depth += 1
            elif ch == ")":
                if depth == 0:
                    break  # closes a group: "(status:502 OR status:504)"
                depth -= 1
        j += 1
    if quoted:
        raise QueryError("a quote is never closed")
    return j


def tokenize(text: str) -> list:
    """Brackets, the operators OR / AND / NOT (in capitals, so "or" in a message is just a word), and terms."""
    tokens: list = []
    i = 0
    while i < len(text):
        ch = text[i]
        if ch.isspace():
            i += 1
        elif ch in "()":
            tokens.append(ch)
            i += 1
        elif ch == "-" and i + 1 < len(text) and text[i + 1] == "(":
            tokens.append("NOT")
            i += 1
        else:
            neg = ch == "-" and i + 1 < len(text) and not text[i + 1].isspace()
            if neg:
                i += 1
            end = _chunk_end(text, i)
            chunk = text[i:end]
            i = end
            if not neg and chunk in ("OR", "AND", "NOT"):
                tokens.append(chunk)
            else:
                tokens.append(_term(chunk, neg))
    return tokens


def _term(chunk: str, neg: bool) -> Term:
    if chunk.startswith('"'):
        return Term("text", _unquote(chunk), neg, phrase=True)
    m = TERM.fullmatch(chunk)
    if m:
        value = m.group("value")
        # "http://x", "error:" or "12:30" aren't field searches: treat them as plain words
        if value and not value.startswith("//"):
            return Term("field", _unquote(value), neg, m.group("key"), m.group("op"), value.startswith('"'))
    return Term("text", chunk, neg)


class Parser:
    """search := any ; any := all ("OR" all)* ; all := one ("AND"? one)* ; one := "NOT" one | "(" any ")" | term"""

    def __init__(self, tokens: list):
        self.tokens = tokens
        self.pos = 0

    def peek(self):
        return self.tokens[self.pos] if self.pos < len(self.tokens) else None

    def take(self):
        token = self.peek()
        self.pos += 1
        return token

    def parse(self):
        if not self.tokens:
            return Group("and", [])
        node = self.any()
        if self.peek() == ")":
            raise QueryError("there's a ')' without a matching '('")
        if self.peek() is not None:  # pragma: no cover - all() consumes everything else
            raise QueryError(f"can't read the search from {self.peek()!r}")
        return node

    def any(self):
        parts = [self.all()]
        while self.peek() == "OR":
            self.take()
            if self.peek() in (None, ")", "OR", "AND"):
                raise QueryError("OR needs something on both sides, like: status:502 OR status:504")
            parts.append(self.all())
        return parts[0] if len(parts) == 1 else Group("or", parts)

    def all(self):
        parts = []
        while self.peek() not in (None, ")", "OR"):
            if self.peek() == "AND":
                self.take()
                if not parts or self.peek() in (None, ")", "OR", "AND"):
                    raise QueryError("AND needs something on both sides (and terms side by side already all have to match)")
                continue
            parts.append(self.one())
        if not parts:
            raise QueryError("OR needs something on both sides, like: status:502 OR status:504" if self.peek() == "OR"
                             else "empty brackets: put something between ( and )")
        return parts[0] if len(parts) == 1 else Group("and", parts)

    def one(self):
        token = self.take()
        if token == "NOT":
            if self.peek() in (None, ")", "OR", "AND"):
                raise QueryError("NOT needs something after it, like: NOT level:info")
            return Group("not", [self.one()])
        if token == "(":
            node = self.any()
            if self.take() != ")":
                raise QueryError("a '(' is never closed")
            return node
        return token


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


FTS = "events.id IN (SELECT rowid FROM events_fts WHERE events_fts MATCH ?)"


def _not(sql: str) -> str:
    # NOT COALESCE(...) so "-service:api" also keeps events that have no service at all
    return f"NOT COALESCE(({sql}), 0)"


class Compiler:
    def __init__(self, clock: Clock, fts: bool):
        self.clock = clock
        self.fts = fts
        self.highlight: list[str] = []

    def node(self, node, negated: bool = False) -> tuple[str, list]:
        if isinstance(node, Term):
            sql, params = self.text(node, negated) if node.kind == "text" else self.field(node)
            return (_not(sql) if node.negate else sql), params
        if node.op == "not":
            sql, params = self.node(node.parts[0], not negated)
            return _not(sql), params
        if not node.parts:
            return "1", []
        pieces, params = [], []
        parts = _merge_alternatives(node.parts) if node.op == "or" else list(node.parts)
        if node.op == "and" and self.fts:
            # Words side by side go to the full-text index as one search rather than one each: much faster.
            words = [p for p in parts if isinstance(p, Term) and p.kind == "text" and not p.negate]
            if len(words) > 1:
                parts = [p for p in parts if p not in words]
                pieces.append(FTS)
                params.append(" ".join(_fts_phrase(w.value) for w in words))
                if not negated:
                    self.highlight += [w.value.rstrip("*") for w in words if w.value.rstrip("*")]
        for part in parts:
            sql, p = self.node(part, negated)
            pieces.append(f"({sql})")
            params += p
        return (" AND " if node.op == "and" else " OR ").join(pieces), params

    def text(self, t: Term, negated: bool) -> tuple[str, list]:
        if not negated and not t.negate and t.value.rstrip("*"):
            self.highlight.append(t.value.rstrip("*"))
        if self.fts:
            return FTS, [_fts_phrase(t.value)]
        # no FTS5 in this SQLite: a plain substring search, slower but the same results for whole words
        return "events.message LIKE ? ESCAPE '\\'", ["%" + _like(t.value.rstrip("*")) + "%"]

    def field(self, t: Term) -> tuple[str, list]:
        key = t.key.lower()
        if key in TIME_KEYS:
            if t.negate or t.op != ":":
                raise QueryError(f"write {key}:<time>, e.g. {key}:1h or {key}:2026-11-19")
            try:
                point = parse_point(t.value, self.clock)
            except TimeError as err:
                raise QueryError(str(err)) from None
            return ("events.ts >= ?" if key in ("since", "after") else "events.ts < ?"), [point]
        if key in ("level", "severity", "lvl"):
            return self.level(t)
        if key in ("source", "file"):
            return "events.source_id IN (SELECT id FROM sources WHERE path LIKE ? ESCAPE '\\')", ["%" + _like(t.value) + "%"]
        if key == "pattern":
            return "events.pattern = ?", [t.value]
        if key in ("message", "msg"):
            return "events.message LIKE ? ESCAPE '\\'", ["%" + _like(t.value) + "%"]
        expr, params = (f"events.{COLUMNS[key]}", []) if key in COLUMNS else ("json_extract(events.fields, ?)", [json_path(t.key)])
        return self.compare(expr, params, t)

    def level(self, t: Term) -> tuple[str, list]:
        ranks = []
        for name in t.value.split(","):
            rank = level_rank(name)
            if rank is None:
                raise QueryError(f"{name!r} isn't a level; use one of {', '.join(LEVELS)}")
            ranks.append(rank)
        marks = ",".join("?" * len(ranks))
        if t.op in (":", "="):
            return f"events.level IN ({marks})", ranks
        if t.op == "!=":
            return _not(f"events.level IN ({marks})"), ranks
        if len(ranks) > 1:
            raise QueryError(f"level{t.op} takes one level")
        return f"events.level {t.op} ?", ranks

    def compare(self, expr: str, params: list, t: Term) -> tuple[str, list]:
        value, op = t.value, t.op
        if op in (">", ">=", "<", "<="):
            n = _number(value)
            if n is None:
                raise QueryError(f"{t.key}{op} needs a number, not {value!r}")
            return f"CAST({expr} AS REAL) {op} ? AND {expr} IS NOT NULL", params + [n] + params
        options = value.split(",") if ("," in value and not t.phrase) else [value]
        parts, args = [], []
        exact: list = []
        for option in options:
            n = _number(option)
            if "*" in option:
                parts.append(f"{expr} LIKE ? ESCAPE '\\'")
                args += params + [_like(option)]
            elif n is not None:
                exact += [n, option]  # 404 might be stored as a number or as the text "404"
            else:
                parts.append(f"{expr} = ? COLLATE NOCASE")
                args += params + [option]
        if exact:
            # One IN (...) reads the field once; "a = ? OR a = ?" made SQLite dig it out of the JSON for every comparison.
            parts.insert(0, f"{expr} IN ({','.join('?' * len(exact))})")
            args = params + exact + args
        sql = " OR ".join(parts)
        return (_not(sql) if op == "!=" else sql), args


def _merge_alternatives(parts: list) -> list:
    """status:502 OR status:504 OR text  ->  status:502,504 OR text: one look at the field instead of one per value."""
    merged: list = []
    by_key: dict[tuple[str, str], Term] = {}
    for part in parts:
        mergeable = (isinstance(part, Term) and part.kind == "field" and not part.negate and part.op in (":", "=")
                     and not part.phrase and "," not in part.value and part.key.lower() not in NOT_LISTS)
        if not mergeable:
            merged.append(part)
            continue
        key = (part.key.lower(), part.op)
        if key in by_key:
            by_key[key].value += "," + part.value
        else:
            copy = Term(part.kind, part.value, part.negate, part.key, part.op, part.phrase)
            by_key[key] = copy
            merged.append(copy)
    return merged


def _terms(node) -> list[Term]:
    if isinstance(node, Term):
        return [node]
    return [t for part in node.parts for t in _terms(part)]


def _check_times(node, top: bool = True) -> None:
    """since/until set the time window, so they belong at the top level, not inside OR, NOT or brackets."""
    if isinstance(node, Term):
        if node.kind == "field" and node.key.lower() in TIME_KEYS and not top:
            raise QueryError(f"{node.key}: sets the time window for the whole search, so it can't go inside brackets, OR or NOT")
        return
    for part in node.parts:
        _check_times(part, top and node.op == "and")


def compile_query(text: str, clock: Clock, *, fts: bool = True) -> Query:
    tree = Parser(tokenize(text)).parse()
    _check_times(tree)
    c = Compiler(clock, fts)
    where, params = c.node(tree)
    terms = _terms(tree)
    query = Query(text=text, terms=terms, where=where or "1", params=params, highlight=c.highlight)
    for t in terms:
        if t.kind == "field" and t.key.lower() in ("since", "after"):
            query.since = parse_point(t.value, clock)
        if t.kind == "field" and t.key.lower() in ("until", "before"):
            query.until = parse_point(t.value, clock)
    return query
