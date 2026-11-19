"""Timestamps, durations and severity levels, as they appear in real log files.

Every timestamp is turned into seconds since the epoch (UTC). Logs often leave out the time zone ("2026-11-19 07:50:01")
or the year (syslog's "Nov 19 07:50:01"), so those are filled in from a default zone and the current year.
"""

from __future__ import annotations

import re
import time
from datetime import datetime, timedelta, timezone

MONTHS = {m: i for i, m in enumerate(("jan", "feb", "mar", "apr", "may", "jun", "jul", "aug", "sep", "oct", "nov", "dec"), 1)}

# trace < debug < info < warn < error < fatal. Stored as numbers so "level>=warn" is a simple comparison.
LEVELS = ("trace", "debug", "info", "warn", "error", "fatal")
LEVEL_RANK = {name: i for i, name in enumerate(LEVELS)}
_ALIASES = {
    "trace": "trace", "trc": "trace", "verbose": "trace", "finest": "trace", "finer": "trace",
    "debug": "debug", "dbg": "debug", "fine": "debug", "d": "debug",
    "info": "info", "inf": "info", "information": "info", "informational": "info", "notice": "info", "i": "info",
    "warn": "warn", "warning": "warn", "wrn": "warn", "w": "warn",
    "error": "error", "err": "error", "eror": "error", "severe": "error", "e": "error",
    "fatal": "fatal", "critical": "fatal", "crit": "fatal", "crt": "fatal", "alert": "fatal", "emerg": "fatal",
    "emergency": "fatal", "panic": "fatal", "f": "fatal",
}
# syslog severities 0..7 (emerg .. debug)
_SYSLOG = ("fatal", "fatal", "fatal", "error", "warn", "info", "info", "debug")


class TimeError(ValueError):
    """A date, time or duration someone typed can't be understood."""


def level_rank(value: object) -> int | None:
    """"WARNING", "err", "E", 40 (pino/bunyan numbers) -> a rank in LEVELS, or None if it isn't a level."""
    if value is None or isinstance(value, bool):
        return None
    if isinstance(value, (int, float)):
        n = int(value)
        if n >= 10 and n % 10 == 0 and n <= 60:          # pino / bunyan: 10 trace .. 60 fatal
            return n // 10 - 1
        return None
    name = _ALIASES.get(str(value).strip().lower())
    return LEVEL_RANK[name] if name else None


def syslog_level(pri: int) -> int:
    return LEVEL_RANK[_SYSLOG[pri % 8]]


class Clock:
    """How to read timestamps that leave things out. `zone` is None for the computer's local time."""

    def __init__(self, zone: timezone | None = None, now: float | None = None):
        self.zone = zone
        self.now = time.time() if now is None else now

    def stamp(self, dt: datetime) -> float:
        if dt.tzinfo is None:
            dt = dt.replace(tzinfo=self.zone) if self.zone else dt.astimezone()  # astimezone() on naive = local time
        return dt.timestamp()

    def year_for(self, month: int, day: int) -> int:
        """Syslog has no year. Use this year, unless that puts the date more than a day in the future
        (a file from December read in January), then last year."""
        now = datetime.fromtimestamp(self.now, self.zone or None)
        year = now.year
        try:
            if datetime(year, month, day) > now.replace(tzinfo=None) + timedelta(days=1):
                year -= 1
        except ValueError:  # 29 Feb in a non-leap year
            year -= 1
        return year


def parse_zone(text: str) -> timezone | None:
    """"local" -> None, "UTC"/"Z" -> UTC, "+05:00" / "-0330" -> a fixed offset."""
    text = text.strip()
    if text.lower() == "local":
        return None
    if text.upper() in ("UTC", "Z", "GMT"):
        return timezone.utc
    m = re.fullmatch(r"([+-])(\d{1,2}):?(\d{2})?", text)
    if not m:
        raise TimeError(f"time zone should be local, UTC or an offset like +05:00, not {text!r}")
    minutes = int(m.group(2)) * 60 + int(m.group(3) or 0)
    if minutes > 18 * 60:
        raise TimeError(f"{text!r} is not a real time zone offset")
    return timezone(timedelta(minutes=minutes if m.group(1) == "+" else -minutes))


def _offset(text: str | None) -> timezone | None:
    if not text:
        return None
    if text in ("Z", "z"):
        return timezone.utc
    sign = 1 if text[0] == "+" else -1
    digits = text[1:].replace(":", "")
    return timezone(sign * timedelta(hours=int(digits[:2]), minutes=int(digits[2:4] or 0)))


def _fraction(text: str | None) -> int:
    return int((text or "0")[:6].ljust(6, "0"))


ISO = re.compile(r"(\d{4})-(\d{2})-(\d{2})[T ](\d{2}):(\d{2}):(\d{2})(?:[.,](\d{1,9}))?(?:\s?(Z|z|[+-]\d{2}:?\d{2}))?")
APACHE = re.compile(r"(\d{2})/([A-Za-z]{3})/(\d{4}):(\d{2}):(\d{2}):(\d{2})(?:\s([+-]\d{4}))?")
SYSLOG = re.compile(r"([A-Za-z]{3})\s+(\d{1,2}) (\d{2}):(\d{2}):(\d{2})")
SLASHED = re.compile(r"(\d{4})/(\d{2})/(\d{2})[ T](\d{2}):(\d{2}):(\d{2})(?:[.,](\d{1,9}))?")


def parse_timestamp(value: object, clock: Clock) -> float | None:
    """Any common timestamp, at the very start of `value` (for text) or a number of seconds or milliseconds."""
    if value is None or isinstance(value, bool):
        return None
    if isinstance(value, (int, float)):
        n = float(value)
        if n > 1e17:      # nanoseconds
            n /= 1e9
        elif n > 1e14:    # microseconds
            n /= 1e6
        elif n > 1e11:    # milliseconds
            n /= 1e3
        return n if 0 < n < 4e9 else None
    text = str(value).strip()
    if re.fullmatch(r"\d{9,19}(\.\d+)?", text):
        return parse_timestamp(float(text), clock)
    return match_timestamp(text, clock)[0]


def match_timestamp(text: str, clock: Clock) -> tuple[float | None, int]:
    """A timestamp at the start of `text` (after an optional "["), and how many characters it took."""
    start = 1 if text[:1] == "[" else 0
    try:
        m = ISO.match(text, start) or SLASHED.match(text, start)
        if m:
            y, mo, d, h, mi, s = (int(g) for g in m.groups()[:6])
            zone = _offset(m.group(8)) if m.re is ISO else None
            dt = datetime(y, mo, d, h, mi, s, _fraction(m.group(7)), tzinfo=zone)
            return clock.stamp(dt), m.end() + (1 if text[m.end():m.end() + 1] == "]" and start else 0)
        m = APACHE.match(text, start)
        if m and m.group(2).lower() in MONTHS:
            d, mon, y, h, mi, s, off = m.groups()
            dt = datetime(int(y), MONTHS[mon.lower()], int(d), int(h), int(mi), int(s), tzinfo=_offset(off))
            return clock.stamp(dt), m.end()
        m = SYSLOG.match(text, start)
        if m and m.group(1).lower() in MONTHS:
            mon, d, h, mi, s = m.groups()
            month = MONTHS[mon.lower()]
            dt = datetime(clock.year_for(month, int(d)), month, int(d), int(h), int(mi), int(s))
            return clock.stamp(dt), m.end()
    except ValueError:  # 2026-13-45 and friends: not a real date, so not a timestamp
        return None, 0
    return None, 0


# Longest spellings first, and not followed by another letter: "2 days" must not stop at "d", "5ms" isn't 5 minutes.
DURATION = re.compile(r"(\d+(?:\.\d+)?)\s*(seconds?|secs?|s|minutes?|mins?|m|hours?|hrs?|h|days?|d|weeks?|w)(?![a-z])", re.I)
_UNIT = {"s": 1, "m": 60, "h": 3600, "d": 86400, "w": 604800}


def parse_duration(text: str) -> float:
    """"90s", "15m", "1h30m", "2d", "1 week" -> seconds."""
    text = text.strip()
    total, pos = 0.0, 0
    for m in DURATION.finditer(text):
        if text[pos:m.start()].strip():
            break
        unit = m.group(2).lower()
        total += float(m.group(1)) * _UNIT["m" if unit.startswith("mi") or unit == "m" else unit[0]]
        pos = m.end()
    if not total or text[pos:].strip():
        raise TimeError(f"{text!r} isn't a duration like 15m, 2h or 7d")
    return total


def parse_point(text: str, clock: Clock) -> float:
    """When something starts or ends: "1h" (an hour ago), "today", "yesterday", "2026-11-19", "2026-11-19 07:50"."""
    text = text.strip()
    lowered = text.lower()
    local_now = datetime.fromtimestamp(clock.now, clock.zone or None)
    if lowered in ("now",):
        return clock.now
    if lowered in ("today", "yesterday"):
        midnight = local_now.replace(hour=0, minute=0, second=0, microsecond=0)
        if lowered == "yesterday":
            midnight -= timedelta(days=1)
        return midnight.timestamp()
    if re.fullmatch(r"\d{4}-\d{2}-\d{2}", text):
        try:
            return clock.stamp(datetime.fromisoformat(text))
        except ValueError:
            raise TimeError(f"{text!r} isn't a real date") from None
    m = re.fullmatch(r"(\d{4}-\d{2}-\d{2})[ T](\d{1,2}):(\d{2})", text)
    if m:
        return clock.stamp(datetime.fromisoformat(f"{m.group(1)}T{int(m.group(2)):02d}:{m.group(3)}"))
    stamp, used = match_timestamp(text, clock)
    if stamp is not None and used == len(text):
        return stamp
    try:
        return clock.now - parse_duration(text)
    except TimeError:
        raise TimeError(f"{text!r} isn't a time: use something like 15m, 2h, 7d, today, 2026-11-19 or 2026-11-19 07:50") from None


def iso(ts: float | None, zone: timezone | None = None) -> str:
    """Seconds -> "2026-11-19 07:50:01.123" in the chosen zone (local time by default)."""
    if ts is None:
        return "-" * 23
    dt = datetime.fromtimestamp(ts, zone) if zone else datetime.fromtimestamp(ts)
    return dt.strftime("%Y-%m-%d %H:%M:%S.") + f"{dt.microsecond // 1000:03d}"
