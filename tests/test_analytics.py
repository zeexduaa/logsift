import pytest

from logsift import analytics
from logsift.ingest import ingest
from logsift.query import compile_query
from logsift.store import Store

from .conftest import FIXTURES


@pytest.fixture
def store(clock):
    s = Store()
    ingest(s, [str(FIXTURES)], clock)
    return s


def q(clock, text=""):
    return compile_query(text, clock)


def test_summary(store, clock):
    s = analytics.summary(store, q(clock))
    assert s.total == 21 and s.no_time == 1  # "ERROR:app.mail:..." has no timestamp
    assert s.levels == {"info": 7, "warn": 4, "error": 8, "none": 2}


def test_top_values(store, clock):
    assert analytics.top(store, q(clock), "level")[0] == ("error", 8)
    assert analytics.top(store, q(clock), "status") == [("200", 2), ("201", 1), ("402", 1), ("403", 1), ("502", 1)]
    assert analytics.top(store, q(clock, "level>=error"), "service", limit=2) == [("api", 1), ("app.mail", 1)]
    assert analytics.top(store, q(clock), "db.table") == [("orders", 1)]
    assert analytics.top(store, q(clock), "nonexistent") == []
    files = dict(analytics.top(store, q(clock), "source"))
    assert sorted(v for v in files.values()) == [3, 4, 4, 5, 5]


def test_patterns_group_the_same_problem(store, clock):
    rows = analytics.patterns(store, q(clock, "level>=error"))
    top = rows[0]
    assert (top.template, top.count, top.level_name) == ("Timeout after <num>ms talking to <ip>", 2, "error")
    assert set(top.services.split(",")) == {"api", "worker"}
    web = next(p for p in rows if p.template.startswith("GET"))
    assert web.template == "GET /api/orders/<num> 502"  # web requests keep their status: a 404 isn't a 502


def test_histogram(store, clock):
    h = analytics.histogram(store, q(clock, "since:2026-11-19T07:50:00 until:2026-11-19T07:53:00"))
    assert h.interval == 5 and len(h.buckets) == 37
    assert sum(e + w + o for _, e, w, o in h.buckets) == 19
    assert h.peak >= 1
    assert analytics.histogram(store, q(clock, "nothingmatchesthis")) is None


def test_pick_interval():
    assert analytics.pick_interval(60) == 1
    assert analytics.pick_interval(3600) == 60
    assert analytics.pick_interval(86400) == 1800
    assert analytics.pick_interval(86400 * 365 * 10) == 30 * 86400


def test_context_skips_over_stack_traces(store, clock):
    hit = analytics.search(store, q(clock, '"charge failed"'))[0]
    around = analytics.context(store, hit, 1)
    assert [h.message.split("\n")[0] for h in around] == ["connected to postgres", "charge failed for order 1182", "cart 77 has 0 items"]


def test_histogram_for_a_recent_window_runs_up_to_now(clock):
    """'Errors in the last hour' must show the last half hour being quiet, not stop at the last error."""
    from logsift.parsers import Event
    s = Store()
    src = s.add_source("x", "json")
    s.insert(src, [Event("a", ts=clock.now - 3000, level=4), Event("b", ts=clock.now - 1800, level=4)])
    h = analytics.histogram(s, q(clock, "since:1h"), now=clock.now)
    assert h.buckets[-1][0] + h.interval >= clock.now
    assert sum(e for _, e, _, _ in h.buckets) == 2
    assert all(e == 0 for start, e, _, _ in h.buckets if start > clock.now - 1700)  # the quiet end is there, and empty
    whole = analytics.histogram(s, q(clock), now=clock.now)  # no window asked for: just the span of the data
    assert whole.buckets[-1][0] <= clock.now - 1800
