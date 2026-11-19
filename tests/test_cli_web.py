import json
import re
import threading
import urllib.error
import urllib.request

import pytest

from logsift.cli import main
from logsift.ingest import ingest
from logsift.store import Store
from logsift.web import App, make_server

from .conftest import FIXTURES


@pytest.fixture
def run(tmp_path, capsys, clock):
    db = tmp_path / "index.db"

    def go(*args):
        code = main(["--db", str(db), "--tz", "UTC", *args], clock=clock)
        out = capsys.readouterr()
        return code, out.out, out.err

    return go


def test_cli_flow(run):
    code, out, _ = run("ingest", str(FIXTURES))
    assert code == 0 and "Added 21 events from 5 files" in out
    assert "no new lines" in run("ingest", str(FIXTURES))[1]
    _, out, _ = run("search", "level>=error", "-n", "3")
    assert out.splitlines()[-1].startswith("(showing the newest 3 of 8")
    assert "2026-11-19 07:51:30.000 ERROR web-2/nginx upstream timed out" in out  # newest at the bottom, like tail
    _, out, _ = run("search", "timeout", "service:worker", "--full")
    assert "TimeoutError: database did not answer" in out
    assert run("count", "status>=400")[1].strip() == "3"
    _, out, _ = run("search", "status>=500", "--json")
    event = json.loads(out)
    assert event["fields"]["status"] == 502 and event["level"] == "error"
    _, out, _ = run("search", "level:warn", "--csv")
    assert out.startswith("time,level,service,host,message,source,line") and out.count("\n") == 5
    _, out, _ = run("stats")
    assert "21 events" in out and "error" in out and "Events per" in out
    assert "403" in run("top", "status")[1]
    _, out, _ = run("patterns", "level>=error", "-n", "1")
    assert "Timeout after <num>ms talking to <ip>" in out and "e.g." in out
    _, out, _ = run("search", "-C", "1", '"charge failed"')
    assert "> " in out and "cart 77" in out
    assert "access" in run("sources")[1]
    code, _, err = run("search", "level:loud")
    assert code == 1 and "isn't a level" in err
    code, _, err = run("forget", "/no/such/file")
    assert code == 1 and "isn't in the index" in err
    assert "Deleted" in run("prune", "--older-than", "30d")[1]
    assert "level>=warn" in run("help-query")[1]


def test_bad_time_zone(tmp_path, capsys):
    assert main(["--db", str(tmp_path / "i.db"), "--tz", "Mars", "sources"]) == 2
    assert "time zone" in capsys.readouterr().err


def test_empty_index_messages(run):
    assert "index is empty" in run("search", "anything")[1]
    assert "Nothing in the index" in run("sources")[1]


# -- web --------------------------------------------------------------------------------------------

@pytest.fixture
def app(clock):
    store = Store()
    ingest(store, [str(FIXTURES)], clock)
    return App(store, clock)


def page(app, path):
    r = app.request("GET", path)
    return r.status, r.body.decode()


def test_dashboard(app):
    status, html = page(app, "/?q=level%3E%3Derror")
    assert status == 200
    assert "<strong>8</strong>" in html                                  # 8 events
    assert "Timeout after &lt;num&gt;ms talking to &lt;ip&gt;" in html    # the top pattern, escaped
    assert "<svg class='hist'" in html and "click a bar to zoom in" in html
    assert html.count("<details class='ev") == 8


def test_highlights_and_escapes(app, clock):
    store = app.store
    store.db.execute("UPDATE events SET message = ? WHERE id = 1", ("<script>alert(1)</script> timeout",))
    store.db.execute("INSERT INTO events_fts(events_fts) VALUES ('rebuild')")
    _, html = page(app, "/?q=timeout")
    assert "<script>alert" not in html and "&lt;script&gt;" in html
    assert "<mark>timeout</mark>" in html or "<mark>Timeout</mark>" in html
    _, html = page(app, "/?q=" + "%3Cscript%3E")
    assert "<script>" not in html


def test_bad_search_is_explained(app):
    status, html = page(app, "/?q=level%3Aloud")
    assert status == 400 and "isn&#x27;t a level" in html


def test_event_context_page(app):
    _, html = page(app, "/?q=%22charge+failed%22")
    event_id = re.search(r"/event/(\d+)", html).group(1)
    status, html = page(app, f"/event/{event_id}")
    assert status == 200 and "cart 77 has 0 items" in html and "ev focus" in html
    assert page(app, "/event/99999")[0] == 404


def test_paging_link(app, clock):
    store = app.store
    src = store.sources()[0]
    from logsift.parsers import Event
    store.insert(src, [Event(f"filler {i}", ts=clock.now - i, level=2) for i in range(150)])
    _, html = page(app, "/?q=filler")
    link = re.search(r"href='(/\?[^']*before_id=[^']*)'", html).group(1).replace("&amp;", "&")
    _, older = page(app, link)
    assert older.count("<details class='ev") == 50 and "Older events" in older


def test_api_and_sources(app):
    r = app.request("GET", "/api/search?q=status%3E%3D400&limit=2")
    body = json.loads(r.body)
    assert body["total"] == 3 and len(body["events"]) == 2
    assert app.request("GET", "/api/search?q=level%3Aloud").status == 400
    assert "syslog.log" in page(app, "/sources")[1]


def test_read_only_and_locked_down(app):
    assert app.request("POST", "/").status == 405
    app.allowed_hosts = {"127.0.0.1:8800"}
    assert app.request("GET", "/", {"Host": "evil.test:8800"}).status == 421
    r = app.request("GET", "/", {"Host": "127.0.0.1:8800"})
    assert r.status == 200 and "default-src 'self'" in r.headers["Content-Security-Policy"]
    assert "style=" not in r.body.decode()  # the CSP allows no inline styles, so the page must not use any


def test_empty_index_page(clock):
    status, html = page(App(Store(), clock), "/")
    assert status == 200 and "No logs yet" in html


def test_real_server(tmp_path, clock):
    store = Store(tmp_path / "x.db")
    ingest(store, [str(FIXTURES)], clock)
    server = make_server(store, clock, port=0)
    threading.Thread(target=server.serve_forever, daemon=True).start()
    try:
        base = f"http://127.0.0.1:{server.server_address[1]}"
        assert "logsift" in urllib.request.urlopen(base + "/").read().decode()
        with pytest.raises(urllib.error.HTTPError) as err:
            urllib.request.urlopen(urllib.request.Request(base + "/", headers={"Host": "attacker.test"}))
        assert err.value.code == 421
    finally:
        server.shutdown()
        server.server_close()


def test_one_bad_file_does_not_stop_the_rest(run, tmp_path):
    bad = tmp_path / "a-image.log"
    bad.write_bytes(b"\x89PNG\x00\x00binary")
    code, out, err = run("ingest", str(bad), str(tmp_path / "missing.log"), str(FIXTURES))
    assert code == 1                                   # scripts still learn something went wrong
    assert "Added 21 events from 5 files" in out       # but everything readable was read
    assert "skipped" in err and "binary" in err and "missing.log" in err


def test_escape_codes_in_logs_are_not_sent_to_the_terminal(run, tmp_path):
    """A log message can contain terminal escape codes put there by whoever sent the request. Printing them raw lets
    them clear the screen, retitle the window or hide lines; they must show up as harmless text."""
    log = tmp_path / "evil.jsonl"
    log.write_text('{"time":"2026-11-19T07:50:02Z","level":"warn","msg":"login failed for \\u001b]0;pwned\\u0007\\u001b[2Jadmin",'
                   '"user":"\\u001b[8mhidden"}\n', encoding="utf-8")
    run("ingest", str(log))
    for args in (("search", "login"), ("search", "login", "--full"), ("patterns",), ("top", "user")):
        out = run(*args)[1]
        assert "\x1b" not in out and "\x07" not in out, args
    assert "\\x1b]0;pwned\\x07\\x1b[2Jadmin" in run("search", "login")[1]
