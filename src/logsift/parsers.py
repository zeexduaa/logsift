"""Turning lines of text into events, whatever format the program that wrote them chose.

Each format has a parser that either understands a line or returns None. A file's format is picked by trying the
parsers on its first lines; lines that don't fit (a stack trace under an error, say) are glued onto the event before.
"""

from __future__ import annotations

import json
import re
from dataclasses import dataclass, field

from .timeparse import Clock, level_rank, match_timestamp, parse_timestamp, syslog_level

MAX_EVENT = 64 * 1024  # a runaway multi-line event is cut here


@dataclass
class Event:
    message: str
    ts: float | None = None
    level: int | None = None
    service: str | None = None
    host: str | None = None
    fields: dict = field(default_factory=dict)
    raw: str = ""
    line: int = 0

    def append(self, text: str) -> None:
        """Another line of the same event: a stack trace frame, the rest of a multi-line message."""
        if len(self.raw) + len(text) < MAX_EVENT:
            self.message += "\n" + text
            self.raw += "\n" + text


# -- JSON lines --------------------------------------------------------------------------------------

TS_KEYS = ("@timestamp", "timestamp", "time", "ts", "datetime", "date", "t", "eventTime")
LEVEL_KEYS = ("level", "severity", "lvl", "levelname", "log.level", "loglevel", "severity_text", "@level")
MESSAGE_KEYS = ("message", "msg", "@message", "event", "log", "text", "error.message")
SERVICE_KEYS = ("service", "service.name", "app", "application", "logger", "logger_name", "name", "component", "module")
HOST_KEYS = ("host", "hostname", "host.name", "server", "node")


def _take(obj: dict, keys: tuple[str, ...], *, scalar: bool = True):
    """The first of `keys` present, removed from obj. Dotted keys also look one level into nested objects, so
    {"host": {"name": "web-1"}} (the Elastic Common Schema) gives "web-1", not the whole object."""
    for key in keys:
        if key in obj and obj[key] not in (None, "") and not (scalar and isinstance(obj[key], (dict, list))):
            return obj.pop(key)
        if "." in key:
            outer, inner = key.split(".", 1)
            nested = obj.get(outer)
            if isinstance(nested, dict) and nested.get(inner) not in (None, ""):
                value = nested.pop(inner)
                if not nested:
                    del obj[outer]
                return value
    return None


def parse_json(line: str, clock: Clock) -> Event | None:
    if not line.startswith("{"):
        return None
    try:
        obj = json.loads(line)
    except ValueError:
        return None
    if not isinstance(obj, dict):
        return None
    ts_value = _take(obj, TS_KEYS)
    ts = parse_timestamp(ts_value, clock)
    if ts is None and ts_value is not None:
        obj["time"] = ts_value  # keep what we couldn't read
    level_value = _take(obj, LEVEL_KEYS)
    level = level_rank(level_value)
    if level is None and level_value is not None:
        obj["level"] = level_value
    message = _take(obj, MESSAGE_KEYS, scalar=False)
    if isinstance(message, (dict, list)):
        message = json.dumps(message, ensure_ascii=False)
    service = _take(obj, SERVICE_KEYS)
    host = _take(obj, HOST_KEYS)
    return Event(message=str(message) if message is not None else _summary(obj), ts=ts, level=level,
                 service=str(service) if service is not None else None, host=str(host) if host is not None else None,
                 fields=obj, raw=line)


def _summary(fields: dict) -> str:
    """No message field at all: show the fields themselves, so the event still says something."""
    return " ".join(f"{k}={v}" for k, v in list(fields.items())[:8]) or "(empty)"


# -- logfmt (key=value key2="quoted value") -------------------------------------------------------------

LOGFMT_PAIR = re.compile(r'([\w.@/-]+)=("(?:[^"\\]|\\.)*"|\S*)')


def parse_logfmt(line: str, clock: Clock) -> Event | None:
    pairs = LOGFMT_PAIR.findall(line)
    if len(pairs) < 2:
        return None
    covered = sum(len(k) + 1 + len(v) for k, v in pairs) + len(pairs) - 1
    if covered < len(line.strip()) * 0.8:  # mostly prose with an "a=b" in it: not logfmt
        return None
    obj: dict = {}
    for key, value in pairs:
        if value.startswith('"'):
            value = value[1:-1].replace('\\"', '"').replace("\\\\", "\\")
        obj[key] = _number(value)
    if not any(k in obj for k in ("msg", "message", "level", "lvl", "time", "ts", "t")):
        return None
    event = parse_json(json.dumps(obj), clock)
    if event:
        event.raw = line
    return event


def _number(value: str):
    if re.fullmatch(r"-?\d{1,15}", value):
        return int(value)
    if re.fullmatch(r"-?\d+\.\d+", value):
        return float(value)
    return value


# -- web server access logs (common / combined) ----------------------------------------------------------

ACCESS = re.compile(
    r'(?P<ip>\S+) \S+ (?P<user>\S+) \[(?P<time>[^\]]+)\] "(?P<request>(?:[^"\\]|\\.)*)" '
    r'(?P<status>\d{3}) (?P<bytes>\d+|-)(?: "(?P<referer>[^"]*)" "(?P<agent>[^"]*)")?(?: (?P<rest>.*))?$')
REQUEST = re.compile(r"(?P<method>[A-Z]+) (?P<path>\S+)(?: (?P<protocol>\S+))?$")


def parse_access(line: str, clock: Clock) -> Event | None:
    m = ACCESS.match(line)
    if not m:
        return None
    g = m.groupdict()
    status = int(g["status"])
    request = REQUEST.match(g["request"])
    if request:
        g.update(request.groupdict())
        fields: dict = {"ip": g["ip"], "method": g["method"], "path": g["path"], "status": status}
        message = f"{g['method']} {g['path']} {status}"
    else:
        # Scanners and broken clients send garbage (a TLS handshake to a plain-HTTP port) or nothing at all; nginx logs
        # it as "-" or escaped bytes with a 400. Still a request, with a time and a status, worth seeing.
        g["protocol"] = None
        fields = {"ip": g["ip"], "request": g["request"], "status": status}
        message = f'invalid request "{g["request"][:80]}" {status}' if g["request"] not in ("", "-") else f"empty request {status}"
    if g["bytes"] != "-":
        fields["bytes"] = int(g["bytes"])
    for key in ("user", "protocol", "referer", "agent"):
        if g[key] and g[key] != "-":
            fields[key] = g[key]
    rest = (g["rest"] or "").strip()
    if re.fullmatch(r"\d+(\.\d+)?", rest):  # nginx $request_time or Apache %D at the end
        fields["duration"] = _number(rest)
    level = level_rank("error" if status >= 500 else "warn" if status >= 400 else "info")
    return Event(message=message, ts=parse_timestamp(g["time"], clock) if g["time"] else None,
                 level=level, fields=fields, raw=line)


# -- syslog (RFC 3164 and 5424) ------------------------------------------------------------------------

# The classic "Nov 19 07:50:01", or the RFC 3339 time that rsyslog writes on current Debian and Ubuntu.
SYSLOG_3164 = re.compile(r"(?:<(?P<pri>\d{1,3})>)?(?P<time>[A-Z][a-z]{2}\s+\d{1,2} \d{2}:\d{2}:\d{2}|"
                         r"\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}(?:\.\d+)?(?:Z|[+-]\d{2}:\d{2})) (?P<host>\S+) "
                         r"(?P<app>[^\s:\[]+)(?:\[(?P<pid>\d+)\])?: ?(?P<msg>.*)$")
SYSLOG_5424 = re.compile(r"<(?P<pri>\d{1,3})>1 (?P<time>\S+) (?P<host>\S+) (?P<app>\S+) (?P<pid>\S+) (?P<msgid>\S+) "
                         r"(?P<sd>-|(?:\[.*?\])+) ?(?P<msg>.*)$")


def parse_syslog(line: str, clock: Clock) -> Event | None:
    m = SYSLOG_5424.match(line) or SYSLOG_3164.match(line)
    if not m:
        return None
    g = m.groupdict()
    ts = parse_timestamp(g["time"], clock)
    if ts is None:
        return None
    fields: dict = {}
    if g.get("pid") and g["pid"] != "-":
        fields["pid"] = _number(g["pid"])
    if g.get("msgid") and g["msgid"] != "-":
        fields["msgid"] = g["msgid"]
    message = g["msg"]
    level = syslog_level(int(g["pri"])) if g.get("pri") else _level_in(message)
    app = None if g["app"] == "-" else g["app"]
    return Event(message=message, ts=ts, level=level, service=app, host=None if g["host"] == "-" else g["host"],
                 fields=fields, raw=line)


# -- everything else: "<timestamp> <LEVEL> <logger> - message" in its many spellings -----------------------

LEVEL_WORD = re.compile(r"[\[(<]?\b(TRACE|DEBUG|INFO|NOTICE|WARN|WARNING|ERROR|ERR|SEVERE|CRITICAL|CRIT|FATAL|PANIC|"
                        r"trace|debug|info|notice|warn|warning|error|fatal|critical)\b[\])>]?:?")
PY_DEFAULT = re.compile(r"(TRACE|DEBUG|INFO|WARNING|ERROR|CRITICAL):([\w.]+):(.*)$")  # logging.basicConfig()


def _level_in(text: str) -> int | None:
    m = LEVEL_WORD.search(text[:80])
    return level_rank(m.group(1)) if m else None


def parse_text(line: str, clock: Clock, *, need_time: bool = True) -> Event | None:
    """A line starting with a timestamp, maybe followed by a level, a logger name and the message.
    With need_time=False a line with no timestamp still counts if it starts with a level ("ERROR:app.db:...")."""
    ts, used = match_timestamp(line, clock)
    if ts is None:
        m = PY_DEFAULT.match(line)
        if m and not need_time:
            return Event(message=m.group(3).strip(), level=level_rank(m.group(1)), service=m.group(2), raw=line)
        return None
    rest = line[used:].lstrip(" -|,:\t")
    level = None
    service = None
    fields: dict = {}
    # The level, a [thread] and the logger name come in any order: "ERROR app.db - ...", "[worker-3] WARN com.shop.Cart - ...",
    # "app.db: ERROR ...". Take each at most once, from the front, until none matches.
    progress = True
    while progress:
        progress = False
        m = LEVEL_WORD.match(rest) if level is None else None
        if m and level_rank(m.group(1)) is not None:
            level = level_rank(m.group(1))
            rest = rest[m.end():].lstrip(" -|:\t")
            progress = True
        thread = re.match(r"\[([^\]]{1,60})\]\s*", rest) if "thread" not in fields else None
        if thread:
            fields["thread"] = thread.group(1)
            rest = rest[thread.end():]
            progress = True
        logger = re.match(r"([A-Za-z_][\w.$-]{0,80})\s*(?: - |: |\s\|\s)", rest) if service is None else None
        # Only names that look like loggers ("app.db", "main", "com.shop.Cart"), not the first word of a message ("Timeout:").
        if logger and ("." in logger.group(1) or logger.group(1)[0].islower()) and LEVEL_WORD.fullmatch(logger.group(1)) is None:
            service = logger.group(1)
            rest = rest[logger.end():]
            progress = True
    return Event(message=rest.strip() or line, ts=ts, level=level, service=service, fields=fields, raw=line)


PARSERS = {
    "json": parse_json,
    "logfmt": parse_logfmt,
    "access": parse_access,
    "syslog": parse_syslog,
    "text": parse_text,
}
FORMATS = tuple(PARSERS)


def detect_format(sample: list[str], clock: Clock) -> str:
    """The format that understands most of a file's first lines. Text is the fallback, so it only wins outright."""
    lines = [s for s in sample if s.strip()][:200]
    if not lines:
        return "text"
    best, best_hits = "text", 0
    for name in ("json", "access", "syslog", "logfmt", "text"):
        hits = sum(1 for line in lines if PARSERS[name](line, clock))
        if hits > best_hits:
            best, best_hits = name, hits
    return best


CONTINUATION = re.compile(r"\s|Traceback |Caused by|During handling|The above exception|\.\.\. \d+ more|at |\}|\]")
EXCEPTION_LINE = re.compile(r"[A-Za-z_][\w.]*(?:Error|Exception|Exit|Interrupt|Warning)\b")  # last line of a Python traceback


def looks_like_continuation(line: str, pending: Event | None = None) -> bool:
    if CONTINUATION.match(line):
        return True
    return bool(pending and "Traceback (most recent call last)" in pending.message and EXCEPTION_LINE.match(line))


class LineParser:
    """Feeds lines in, gets finished events out. Holds back the last event until it's sure no more lines belong to it."""

    def __init__(self, fmt: str, clock: Clock):
        self.fmt = fmt
        self.clock = clock
        self.parse = PARSERS[fmt]
        self.pending: Event | None = None

    def feed(self, line: str, number: int) -> Event | None:
        line = line.rstrip("\r\n")
        if not line.strip():
            return None
        event = self.parse(line, self.clock)
        if event is None and self.fmt != "text":
            # A line in a different shape inside a structured log: a stray print(), or a stack trace.
            if self.pending is not None and looks_like_continuation(line, self.pending):
                self.pending.append(line)
                return None
            event = parse_text(line, self.clock, need_time=False)
        elif event is None and self.pending is not None:
            m = PY_DEFAULT.match(line)
            if not m:  # no timestamp of its own: part of the event above (stack trace, wrapped message)
                self.pending.append(line)
                return None
            event = parse_text(line, self.clock, need_time=False)
        if event is None:
            event = Event(message=line, level=_level_in(line), raw=line)
        event.line = number
        done, self.pending = self.pending, event
        return done

    def finish(self) -> Event | None:
        done, self.pending = self.pending, None
        return done
