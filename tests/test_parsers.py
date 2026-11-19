from logsift.parsers import LineParser, detect_format, parse_access, parse_json, parse_logfmt, parse_syslog, parse_text
from logsift.patterns import template
from logsift.timeparse import LEVEL_RANK

from .conftest import FIXTURES

ERROR, WARN, INFO = LEVEL_RANK["error"], LEVEL_RANK["warn"], LEVEL_RANK["info"]


def lines(name):
    return (FIXTURES / name).read_text(encoding="utf-8").splitlines()


def test_detects_every_format(clock):
    expected = {"app.jsonl": "json", "access.log": "access", "syslog.log": "syslog", "python.log": "text", "logfmt.log": "logfmt"}
    for name, fmt in expected.items():
        assert detect_format(lines(name), clock) == fmt, name


def test_json(clock):
    ev = parse_json('{"@timestamp":"2026-11-19T07:50:01Z","log.level":"WARN","message":"disk low","host":{"name":"web-1"},'
                    '"service":{"name":"api"},"free_mb":512}', clock)
    assert ev.level == WARN and ev.message == "disk low" and ev.host == "web-1" and ev.service == "api"
    assert ev.fields == {"free_mb": 512}  # what's left after taking out the known fields
    assert parse_json("{not json", clock) is None and parse_json("[1,2]", clock) is None


def test_json_keeps_what_it_cannot_read(clock):
    ev = parse_json('{"time":"sometime","level":"loud","count":3}', clock)
    assert ev.ts is None and ev.level is None
    assert ev.fields == {"time": "sometime", "level": "loud", "count": 3}
    assert "count=3" in ev.message  # no message field: the fields stand in


def test_logfmt(clock):
    ev = parse_logfmt('time=2026-11-19T07:50:02Z level=error msg="payment declined" order=1182 reason="card \\"expired\\""', clock)
    assert ev.level == ERROR and ev.message == "payment declined"
    assert ev.fields == {"order": 1182, "reason": 'card "expired"'}
    assert parse_logfmt("the value a=b appears in this sentence", clock) is None


def test_access_log(clock):
    ev = parse_access('198.51.100.4 - alice [19/Nov/2026:07:50:07 +0000] "GET /admin HTTP/1.1" 403 87 "https://e.test/" "Mozilla/5.0" 0.003', clock)
    assert ev.level == WARN and ev.message == "GET /admin 403"
    assert ev.fields["status"] == 403 and ev.fields["user"] == "alice" and ev.fields["duration"] == 0.003
    assert parse_access('1.2.3.4 - - [19/Nov/2026:07:50:07 +0000] "GET / HTTP/1.1" 503 -', clock).level == ERROR


def test_syslog(clock):
    ev = parse_syslog("<11>Nov 19 07:51:30 web-2 nginx[88]: upstream timed out", clock)
    assert ev.host == "web-2" and ev.service == "nginx" and ev.fields == {"pid": 88} and ev.level == ERROR  # PRI 11 = err
    ev = parse_syslog("<165>1 2026-11-19T07:52:00.003Z db-1 postgres 7731 - - checkpoint complete", clock)
    assert ev.service == "postgres" and ev.level == INFO and ev.message == "checkpoint complete"


def test_text_layouts(clock):
    ev = parse_text("2026-11-19 07:50:02,001 - app.payments - ERROR - charge failed", clock)
    assert (ev.service, ev.level, ev.message) == ("app.payments", ERROR, "charge failed")
    ev = parse_text("2026-11-19 07:50:03,410 [worker-3] WARN com.shop.Cart - cart 77 has 0 items", clock)
    assert (ev.service, ev.level, ev.message, ev.fields) == ("com.shop.Cart", WARN, "cart 77 has 0 items", {"thread": "worker-3"})
    ev = parse_text("2026-11-19T07:50:01Z INFO Timeout: retrying in 5s", clock)
    assert ev.service is None and ev.message == "Timeout: retrying in 5s"  # a capitalised first word isn't a logger
    assert parse_text("no timestamp here", clock) is None


def test_multiline_stack_traces(clock):
    parser = LineParser("text", clock)
    events = [e for n, line in enumerate(lines("python.log"), 1) if (e := parser.feed(line, n))] + [parser.finish()]
    charge = next(e for e in events if e.message.startswith("charge failed"))
    assert charge.message.count("\n") == 4 and charge.message.endswith("ConnectionError: gateway unreachable")
    assert len(events) == 5


def test_traceback_inside_json_log(clock):
    parser = LineParser("json", clock)
    events = [e for n, line in enumerate(lines("app.jsonl"), 1) if (e := parser.feed(line, n))] + [parser.finish()]
    assert len(events) == 5
    assert events[3].message.endswith("TimeoutError: database did not answer")


def test_stray_line_in_json_log_is_its_own_event(clock):
    parser = LineParser("json", clock)
    parser.feed('{"msg":"a","level":"info"}', 1)
    first = parser.feed("Starting worker pool with 4 threads", 2)
    assert first.message == "a" and parser.finish().message == "Starting worker pool with 4 threads"


def test_templates():
    assert template("Timeout after 3012ms talking to 10.0.4.17:5432") == "Timeout after <num>ms talking to <ip>"
    assert template("user 8f14e45f-ceea-467a-9575-3c2e1f1f0a1b from 192.168.1.4") == "user <uuid> from <ip>"
    assert template("request a3f9c2e81b7d failed: deadline exceeded") == "request <hex> failed: deadline exceeded"
    assert template("Retrying 1, 2, 3 times") == "Retrying <num> times"
    assert template("GET /api/users/4821 500") == "GET /api/users/<num> <num>"
    assert template("disk at 93% on /dev/sda1") == "disk at <num>% on /dev/sda1"
    assert template("mail to a.b@example.com: No such key 'x'") == "mail to <email>: No such key '<str>'"
    assert template("first line\nsecond line 42") == "first line"


def test_access_log_bad_requests(clock):
    """nginx logs scanners and broken clients with a "-" or garbage request line; they still have a time and status."""
    empty = parse_access('198.51.100.7 - - [19/Nov/2026:07:50:02 +0000] "-" 400 0 "-" "-"', clock)
    assert empty.ts is not None and empty.level == WARN and empty.message == "empty request 400"
    garbage = parse_access('198.51.100.8 - - [19/Nov/2026:07:50:03 +0000] "\\x16\\x03\\x01\\x02\\x00" 400 157 "-" "-"', clock)
    assert garbage.fields["status"] == 400 and garbage.fields["request"] == "\\x16\\x03\\x01\\x02\\x00"
    assert garbage.message == 'invalid request "\\x16\\x03\\x01\\x02\\x00" 400'  # as nginx wrote it, not doubled
    ipv6 = parse_access('2001:db8::1 - - [19/Nov/2026:07:50:04 +0000] "GET /api?q=a%20b HTTP/2.0" 502 10 "-" "x"', clock)
    assert ipv6.fields["ip"] == "2001:db8::1" and ipv6.fields["path"] == "/api?q=a%20b" and ipv6.level == ERROR
