from datetime import datetime, timedelta, timezone

import pytest

from logsift.timeparse import (LEVEL_RANK, Clock, TimeError, level_rank, match_timestamp, parse_duration, parse_point,
                               parse_timestamp, parse_zone)

from .conftest import NOW


def utc(*args) -> float:
    return datetime(*args, tzinfo=timezone.utc).timestamp()


@pytest.mark.parametrize("text, expected", [
    ("2026-11-19T07:50:01Z", utc(2026, 11, 19, 7, 50, 1)),
    ("2026-11-19T07:50:01.250Z", utc(2026, 11, 19, 7, 50, 1, 250000)),
    ("2026-11-19 07:50:01,123", utc(2026, 11, 19, 7, 50, 1, 123000)),          # Python logging, no zone: the clock's (UTC)
    ("2026-11-19T12:50:01+05:00", utc(2026, 11, 19, 7, 50, 1)),
    ("2026-11-19T02:20:01-0530", utc(2026, 11, 19, 7, 50, 1)),
    ("2026/11/19 07:50:01", utc(2026, 11, 19, 7, 50, 1)),                       # Go's log package
    ("19/Nov/2026:07:50:01 +0000", utc(2026, 11, 19, 7, 50, 1)),               # nginx / Apache
    ("Nov 19 07:50:01", utc(2026, 11, 19, 7, 50, 1)),                          # syslog: no year
    ("[2026-11-19 07:50:01] rest", utc(2026, 11, 19, 7, 50, 1)),
    (1795074601, utc(2026, 11, 19, 7, 50, 1)),                                 # epoch seconds
    (1795074601000, utc(2026, 11, 19, 7, 50, 1)),                              # milliseconds
    ("1795074601123", utc(2026, 11, 19, 7, 50, 1, 123000)),
])
def test_timestamps(text, expected, clock):
    assert parse_timestamp(text, clock) == pytest.approx(expected)


@pytest.mark.parametrize("text", ["not a time", "2026-13-45 10:00:00", "Foo 19 07:50:01", "", None, True, -5])
def test_not_timestamps(text, clock):
    assert parse_timestamp(text, clock) is None


def test_syslog_in_january_means_last_december():
    january = Clock(timezone.utc, now=utc(2027, 1, 2, 9, 0, 0))
    assert parse_timestamp("Dec 31 23:59:00", january) == utc(2026, 12, 31, 23, 59, 0)
    assert parse_timestamp("Jan  2 08:00:00", january) == utc(2027, 1, 2, 8, 0, 0)


def test_local_time_when_no_zone_given():
    local = Clock(None, now=NOW)
    assert parse_timestamp("2026-11-19 07:50:01", local) == datetime(2026, 11, 19, 7, 50, 1).astimezone().timestamp()


def test_match_reports_length(clock):
    ts, used = match_timestamp("2026-11-19 07:50:01,123 - app - INFO - hi", clock)
    assert ts is not None and used == len("2026-11-19 07:50:01,123")


@pytest.mark.parametrize("value, level", [
    ("ERROR", "error"), ("err", "error"), ("Warning", "warn"), ("W", "warn"), ("CRITICAL", "fatal"), ("notice", "info"),
    ("dbg", "debug"), (30, "info"), (50, "error"), (60, "fatal"),
])
def test_levels(value, level):
    assert level_rank(value) == LEVEL_RANK[level]


@pytest.mark.parametrize("value", ["loud", "", None, 35, 7, True])
def test_not_levels(value):
    assert level_rank(value) is None


def test_durations():
    assert parse_duration("90s") == 90
    assert parse_duration("15m") == 900
    assert parse_duration("1h30m") == 5400
    assert parse_duration("2 days") == 172800
    assert parse_duration("1w") == 604800
    for bad in ("", "soon", "5", "1h then"):
        with pytest.raises(TimeError):
            parse_duration(bad)


def test_points(clock):
    assert parse_point("1h", clock) == NOW - 3600
    assert parse_point("today", clock) == utc(2026, 11, 19)
    assert parse_point("yesterday", clock) == utc(2026, 11, 18)
    assert parse_point("2026-11-01", clock) == utc(2026, 11, 1)
    assert parse_point("2026-11-19 07:05", clock) == utc(2026, 11, 19, 7, 5)
    assert parse_point("2026-11-19T07:05:30", clock) == utc(2026, 11, 19, 7, 5, 30)
    with pytest.raises(TimeError):
        parse_point("whenever", clock)
    with pytest.raises(TimeError):
        parse_point("2026-02-30", clock)


def test_zones():
    assert parse_zone("local") is None
    assert parse_zone("UTC") == timezone.utc
    assert parse_zone("+05:00") == timezone(timedelta(hours=5))
    assert parse_zone("-0330") == timezone(-timedelta(hours=3, minutes=30))
    for bad in ("Mars", "+25:00"):
        with pytest.raises(TimeError):
            parse_zone(bad)
