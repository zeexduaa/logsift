import pytest

from logsift import analytics
from logsift.ingest import ingest
from logsift.query import QueryError, compile_query, json_path, tokenize
from logsift.store import Store

from .conftest import FIXTURES


@pytest.fixture(params=[True, False], ids=["fts5", "no-fts5"])
def store(request, clock):
    """Every search is checked with SQLite's full-text index and with the plain fallback, which must agree."""
    s = Store()
    if not request.param:
        s.fts = False
    ingest(s, [str(FIXTURES)], clock)
    return s


def count(store, clock, text):
    return analytics.count(store, compile_query(text, clock, fts=store.fts))


@pytest.mark.parametrize("text, expected", [
    ("", 21),
    ("timeout", 2),
    ("Timeout", 2),                          # case doesn't matter
    ('"timed out"', 1),
    ("time*", 3),                            # timeout x2, timed
    ("-timeout", 19),
    ("timeout service:worker", 1),
    ("level:error", 8),
    ("level>=warn", 12),
    ("level<info", 0),
    ("level:warn,error", 12),
    ("level!=info", 14),                     # includes the 2 events with no level
    ("-level:info", 14),
    ("status>=500", 1),
    ("status:403", 1),
    ("status:200,201", 3),                   # two from the access log, one from logfmt
    ("status!=200", 19),                     # events without a status count as "not 200"
    ("duration>1", 1),
    ("path:/api/*", 3),
    ("db.table:orders", 1),
    ("job.id:991", 1),
    ('reason:"card expired"', 1),
    ("host:web-1", 2),
    ("host:web-1,web-2", 3),
    ("-service:api", 18),                    # keeps events with no service at all
    ("source:syslog", 4),
    ("since:2026-11-19T07:50:30", 3),
    ("until:2026-11-19T07:50:02", 6),
    ("since:2026-11-19T07:50:00 until:2026-11-19T07:51:00 level>=error", 4),  # until is exclusive
    ('pattern:"Timeout after <num>ms talking to <ip>"', 2),
    ('msg:"order 1182"', 1),
    ("10.0.4.17", 1),
    ("NEAR(timeout", 0),                     # FTS syntax typed by a person is just text
    ('AND OR NOT "*"', 0),
])
def test_searches(store, clock, text, expected):
    assert count(store, clock, text) == expected


@pytest.mark.parametrize("text, message", [
    ("level:loud", "isn't a level"),
    ("status>=lots", "needs a number"),
    ('"unclosed', "quote"),
    ('path:"unclosed', "never closed"),
    ("since:soon", "isn't a time"),
    ("-since:1h", "since:<time>"),
    ("level>=warn,error", "one level"),
])
def test_helpful_errors(clock, text, message):
    with pytest.raises(QueryError, match=message):
        compile_query(text, clock)


def test_words_that_look_like_fields(clock):
    terms = tokenize("http://example.test error: 12:30")
    assert [t.kind for t in terms] == ["text", "text", "text"]


def test_values_never_become_sql(store, clock):
    for evil in ("service:\"x' OR 1=1 --\"", "'); DROP TABLE events; --", 'db.table":1}', "path:%", "path:_",
                 'x" OR 1=1 OR "', "level:error) OR (1=1"):
        try:
            assert count(store, clock, evil) == 0, evil
        except QueryError:
            pass  # refusing to run it is fine too; what matters is that nothing else happens
    assert store.count() == 21
    assert json_path('a"b.c') == '$."a\\"b"."c"'


def test_search_order_and_paging(store, clock):
    q = compile_query("", clock, fts=store.fts)
    first = analytics.search(store, q, limit=5)
    assert [h.ts for h in first] == sorted([h.ts for h in first], reverse=True)
    second = analytics.search(store, q, limit=5, before=(first[-1].ts, first[-1].id))
    assert not {h.id for h in first} & {h.id for h in second}
    everything, cursor = [], None
    while True:
        page = analytics.search(store, q, limit=4, before=cursor)
        if not page:
            break
        everything += page
        cursor = (page[-1].ts, page[-1].id)
    assert len(everything) == 21 and len({h.id for h in everything}) == 21  # no event skipped or repeated, untimed ones last


def test_words_for_highlighting(clock):
    assert compile_query('timeout "connection refused" -noise status:500 retr*', clock).words == ["timeout", "connection refused", "retr"]
