"""The search dashboard, served to your own computer only. Read-only: it never changes the index, and needs no JavaScript."""

from __future__ import annotations

import json
import re
import threading
import time
from dataclasses import dataclass, field
from datetime import datetime
from html import escape
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from urllib.parse import parse_qs, urlencode, urlsplit

from . import __version__, analytics
from .query import Query, QueryError, compile_query
from .store import Store
from .timeparse import LEVELS, Clock, TimeError, iso

NEEDS_QUOTES = re.compile(r'[\s,"]')
RANGES = (("15m", "15 min"), ("1h", "1 hour"), ("24h", "24 hours"), ("7d", "7 days"), ("30d", "30 days"), ("", "All time"))


def e(value: object) -> str:
    return escape(str(value), quote=True)


@dataclass
class Response:
    status: int = 200
    body: bytes = b""
    headers: dict[str, str] = field(default_factory=dict)

    @classmethod
    def html(cls, text: str, status: int = 200) -> "Response":
        return cls(status, text.encode(), {"Content-Type": "text/html; charset=utf-8"})


CSS = """
:root { --bg:#f4f5f7; --surface:#fff; --text:#1b1f27; --muted:#6a7280; --line:#e3e6eb; --accent:#4b5fd6; --soft:#eceffd;
        --error:#d64545; --warn:#d99a1e; --info:#3a8fd9; --other:#a9b1bd; --mark:#fff1a8; color-scheme: light; }
@media (prefers-color-scheme: dark) { :root { --bg:#111317; --surface:#1a1d23; --text:#e6e8ec; --muted:#9097a3; --line:#2b2f37;
        --accent:#8b9bff; --soft:#232947; --error:#f06b6b; --warn:#f0b54a; --info:#5aa9f0; --other:#59606b; --mark:#5a4b00; color-scheme: dark; } }
* { box-sizing: border-box; }
body { margin: 0; background: var(--bg); color: var(--text); font: 14px/1.45 system-ui, -apple-system, "Segoe UI", Roboto, sans-serif; }
a { color: var(--accent); text-decoration: none; } a:hover { text-decoration: underline; }
header { background: var(--surface); border-bottom: 1px solid var(--line); position: sticky; top: 0; z-index: 2; }
.bar { max-width: 1400px; margin: 0 auto; padding: .6rem 1rem; display: flex; gap: .7rem; align-items: center; flex-wrap: wrap; }
.brand { font-weight: 800; font-size: 1.1rem; color: var(--text); }
form.search { flex: 1; display: flex; gap: .5rem; min-width: min(100%, 22rem); flex-wrap: wrap; }
form.search input[type=search] { flex: 1; min-width: 12rem; font: 15px ui-monospace, SFMono-Regular, Menlo, Consolas, monospace; padding: .55rem .7rem;
       border: 1px solid var(--line); border-radius: 8px; background: var(--bg); color: var(--text); }
select, button { font: inherit; padding: .5rem .7rem; border-radius: 8px; border: 1px solid var(--line); background: var(--surface); color: var(--text); }
button { background: var(--accent); border-color: var(--accent); color: #fff; font-weight: 600; cursor: pointer; }
nav a { color: var(--muted); font-weight: 600; margin-left: .6rem; }
main { max-width: 1400px; margin: 0 auto; padding: 1rem; }
.grid { display: grid; grid-template-columns: minmax(0, 1fr) 22rem; gap: 1rem; align-items: start; }
@media (max-width: 1000px) { .grid { grid-template-columns: 1fr; } }
.card { background: var(--surface); border: 1px solid var(--line); border-radius: 10px; padding: .8rem 1rem; margin-bottom: 1rem; }
.card h2 { font-size: .8rem; text-transform: uppercase; letter-spacing: .06em; color: var(--muted); margin: 0 0 .6rem; }
.stats { display: flex; gap: 1.6rem; flex-wrap: wrap; align-items: baseline; }
.stats strong { font-size: 1.4rem; font-variant-numeric: tabular-nums; }
.muted { color: var(--muted); } .small { font-size: .85rem; }
.error-box { background: color-mix(in srgb, var(--error) 12%, var(--surface)); border: 1px solid var(--error); border-radius: 10px; padding: .7rem 1rem; margin-bottom: 1rem; }
svg.hist { width: 100%; height: 120px; display: block; }
svg.hist rect.e { fill: var(--error); } svg.hist rect.w { fill: var(--warn); } svg.hist rect.o { fill: var(--other); }
svg.hist a:hover rect { opacity: .75; }
.legend span { display: inline-flex; align-items: center; gap: .3rem; margin-right: 1rem; }
.legend i { width: .7rem; height: .7rem; border-radius: 2px; display: inline-block; }
.events { font: 13px/1.45 ui-monospace, SFMono-Regular, Menlo, Consolas, monospace; }
.ev { border-bottom: 1px solid var(--line); padding: .35rem 0; }
.ev:last-child { border: 0; }
.ev summary { cursor: pointer; list-style: none; display: grid; grid-template-columns: 12.5rem 3.6rem minmax(0, 1fr); gap: .6rem; }
.ev summary::-webkit-details-marker { display: none; }
.ev .msg { white-space: pre-wrap; word-break: break-word; }
.ev .who { color: #9a4fb5; }
.lv { font-weight: 700; } .lv.error, .lv.fatal { color: var(--error); } .lv.warn { color: var(--warn); } .lv.info { color: var(--info); } .lv.debug, .lv.trace, .lv.none { color: var(--muted); }
.detail { margin: .4rem 0 .3rem 13.1rem; padding: .5rem .7rem; background: var(--bg); border-radius: 8px; }
.detail pre { margin: 0 0 .5rem; white-space: pre-wrap; word-break: break-word; }
.detail table { border-collapse: collapse; } .detail td { padding: .1rem .8rem .1rem 0; vertical-align: top; }
.detail td:first-child { color: var(--muted); }
@media (max-width: 700px) { .ev summary { grid-template-columns: 1fr; gap: 0; } .detail { margin-left: 0; } }
mark { background: var(--mark); color: inherit; border-radius: 2px; }
table.top { width: 100%; border-collapse: collapse; }
table.top td { padding: .25rem 0; border-bottom: 1px solid var(--line); vertical-align: top; }
table.top tr:last-child td { border: 0; }
table.top td.n { text-align: right; font-variant-numeric: tabular-nums; color: var(--muted); padding-left: .6rem; white-space: nowrap; }
.pattern { font: 12.5px ui-monospace, SFMono-Regular, Menlo, Consolas, monospace; word-break: break-word; }
.more { display: block; text-align: center; padding: .6rem; }
.help code { background: var(--bg); padding: .05rem .3rem; border-radius: 4px; }
.empty { text-align: center; padding: 3rem 1rem; color: var(--muted); }
.c-error { color: var(--error); } .c-warn { color: var(--warn); }
.k-error { background: var(--error); } .k-warn { background: var(--warn); } .k-other { background: var(--other); }
.axis { display: flex; justify-content: space-between; gap: .5rem; flex-wrap: wrap; margin-top: .3rem; }
.ev.focus { background: var(--soft); border-radius: 6px; }
.fieldform { display: flex; gap: .4rem; margin-bottom: .6rem; }
.fieldform input { flex: 1; min-width: 0; padding: .4rem .6rem; border: 1px solid var(--line); border-radius: 8px; background: var(--bg); color: var(--text); font: inherit; }
.empty h1 { color: var(--text); }
.card h2 .path { text-transform: none; letter-spacing: 0; font-family: ui-monospace, SFMono-Regular, Menlo, Consolas, monospace; word-break: break-all; }
footer { text-align: center; color: var(--muted); font-size: .8rem; padding: 1.5rem; }
"""


class App:
    def __init__(self, store: Store, clock: Clock, *, allowed_hosts: set[str] | None = None):
        self.store = store
        self.clock = clock
        self.allowed_hosts = allowed_hosts
        self.live = False          # a running server: "since:1h" means an hour before each request, not before startup
        self.lock = threading.Lock()  # one SQLite connection, shared by the server's threads

    def request(self, method: str, target: str, headers: dict[str, str] | None = None) -> Response:
        headers = {k.lower(): v for k, v in (headers or {}).items()}
        if self.allowed_hosts is not None and headers.get("host", "") not in self.allowed_hosts:
            return Response(421, b"Unknown host", {"Content-Type": "text/plain"})  # blocks DNS rebinding
        if method not in ("GET", "HEAD"):
            return Response(405, b"logsift's dashboard is read-only", {"Content-Type": "text/plain", "Allow": "GET"})
        url = urlsplit(target)
        query = {k: v[0] for k, v in parse_qs(url.query, keep_blank_values=True).items()}
        if self.live:
            self.clock.now = time.time()
        routes = {"/": self.home, "/sources": self.sources, "/api/search": self.api_search, "/style.css": self.css}
        m = re.fullmatch(r"/event/(\d+)", url.path)
        with self.lock:
            if m:
                response = self.event(query, int(m.group(1)))
            elif url.path in routes:
                response = routes[url.path](query)
            else:
                response = self.page("Not found", "<div class='empty'><p>There's no such page.</p><a href='/'>Back to search</a></div>", status=404)
        response.headers.setdefault("Cache-Control", "no-store")
        response.headers.update({"Content-Security-Policy": "default-src 'self'; style-src 'self'; img-src 'self' data:; frame-ancestors 'none'; form-action 'self'",
                                 "X-Content-Type-Options": "nosniff", "Referrer-Policy": "same-origin", "X-Frame-Options": "DENY"})
        return response

    def css(self, query) -> Response:
        return Response(200, CSS.encode(), {"Content-Type": "text/css; charset=utf-8", "Cache-Control": "max-age=300"})

    def page(self, title: str, body: str, *, q: str = "", rng: str = "", status: int = 200) -> Response:
        options = "".join(f"<option value='{v}' {'selected' if v == rng else ''}>{label}</option>" for v, label in RANGES)
        return Response.html(f"""<!doctype html><html lang="en"><head><meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1"><title>{e(title)} · logsift</title>
<link rel="stylesheet" href="/style.css">
<link rel="icon" href="data:image/svg+xml,%3Csvg xmlns='http://www.w3.org/2000/svg' viewBox='0 0 32 32'%3E%3Crect width='32' height='32' rx='7' fill='%234b5fd6'/%3E%3Cpath d='M8 10h16M8 16h10M8 22h13' stroke='white' stroke-width='3' stroke-linecap='round'/%3E%3C/svg%3E">
</head><body><header><div class="bar"><a class="brand" href="/">logsift</a>
<form class="search" method="get" action="/"><input type="search" name="q" value="{e(q)}" placeholder='level>=error service:api "timed out"' aria-label="Search" autofocus>
<select name="range" aria-label="Time range">{options}</select><button>Search</button></form>
<nav><a href="/sources">Files</a></nav></div></header><main>{body}</main>
<footer>logsift {e(__version__)} · {self.store.count():,} events in the index</footer></body></html>""", status)

    def compile(self, q: str, rng: str) -> Query:
        return compile_query(f"{q} since:{rng}" if rng else q, self.clock, fts=self.store.fts)

    def link(self, **params: str) -> str:
        return "/?" + urlencode({k: v for k, v in params.items() if v})

    # -- pages -----------------------------------------------------------------------------------

    def home(self, query: dict[str, str]) -> Response:
        q, rng = query.get("q", "").strip(), query.get("range", "")
        if not self.store.count():
            return self.page("Search", """<div class='card empty'><h1>No logs yet</h1>
<p>Read some files into the index, then come back:</p><p><code>logsift ingest /var/log/nginx/access.log ./logs</code></p></div>""")
        try:
            compiled = self.compile(q, rng)
        except (QueryError, TimeError) as err:
            return self.page("Search", f"<div class='error-box' role='alert'><strong>Can't run that search:</strong> {e(err)}</div>{HELP}",
                             q=q, rng=rng, status=400)
        before = None
        if query.get("before_id", "").isdigit():
            ts = query.get("before_ts", "")
            before = (float(ts) if re.fullmatch(r"\d+(\.\d+)?", ts) else None, int(query["before_id"]))
        hits = analytics.search(self.store, compiled, limit=100, before=before)
        summary = analytics.summary(self.store, compiled)
        errors = summary.levels.get("error", 0) + summary.levels.get("fatal", 0)
        stats = (f"<div class='card stats'><div><strong>{summary.total:,}</strong> <span class='muted'>events</span></div>"
                 f"<div><strong class='c-error'>{errors:,}</strong> <span class='muted'>errors</span></div>"
                 f"<div><strong class='c-warn'>{summary.levels.get('warn', 0):,}</strong> <span class='muted'>warnings</span></div>"
                 + (f"<div class='muted small'>{e(iso(summary.first, self.clock.zone)[:19])} → {e(iso(summary.last, self.clock.zone)[:19])}</div>"
                    if summary.first else "") + "</div>")
        chart = self.histogram(compiled, q) if summary.total else ""
        events = self.event_list(hits, compiled)
        more = ""
        if len(hits) == 100:
            last = hits[-1]
            more = f"<a class='more' href='{e(self.link(q=q, range=rng, before_id=str(last.id), before_ts='' if last.ts is None else repr(last.ts)))}'>Older events →</a>"
        side = self.sidebar(compiled, q, rng, query.get("field", ""))
        body = (f"{stats}{chart}<div class='grid'><div class='card events'><h2>{'Older events' if before else 'Newest first'}</h2>"
                f"{events or '<p class=empty>No events match.</p>'}{more}</div><div>{side}</div></div>")
        return self.page(q or "Search", body, q=q, rng=rng)

    def histogram(self, compiled: Query, q: str) -> str:
        h = analytics.histogram(self.store, compiled, target=80, now=self.clock.now)
        if not h or not h.peak:
            return ""
        n = len(h.buckets)
        width, height = 1000, 110
        bar = width / n
        parts = []
        for i, (start, err, warn, other) in enumerate(h.buckets):
            total = err + warn + other
            if not total:
                continue
            x = i * bar
            y = height
            title = f"{iso(start, self.clock.zone)[:16]}: {total:,} events ({err:,} errors, {warn:,} warnings)"
            rects = []
            for count, cls in ((other, "o"), (warn, "w"), (err, "e")):
                if count:
                    h_px = max(count / h.peak * (height - 4), 1.5)
                    y -= h_px
                    rects.append(f"<rect class='{cls}' x='{x + bar * .08:.1f}' y='{y:.1f}' width='{bar * .84:.1f}' height='{h_px:.1f}'/>")
            since = datetime.fromtimestamp(start, self.clock.zone).strftime("%Y-%m-%dT%H:%M:%S")
            until = datetime.fromtimestamp(start + h.interval, self.clock.zone).strftime("%Y-%m-%dT%H:%M:%S")
            href = self.link(q=re.sub(r"\s*\b(since|until):\S+", "", q).strip() + f" since:{since} until:{until}")
            parts.append(f"<a href='{e(href)}'><title>{e(title)}</title>{''.join(rects)}</a>")
        first = iso(h.buckets[0][0], self.clock.zone)[:16]
        last = iso(h.buckets[-1][0], self.clock.zone)[:16]
        return (f"<div class='card'><svg class='hist' viewBox='0 0 {width} {height}' preserveAspectRatio='none' role='img' "
                f"aria-label='Events over time'>{''.join(parts)}</svg><div class='axis small muted'>"
                f"<span>{e(first)}</span><span class='legend'><span><i class='k-error'></i>errors</span>"
                f"<span><i class='k-warn'></i>warnings</span><span><i class='k-other'></i>other</span>"
                f"· one bar = {analytics_interval(h.interval)} · click a bar to zoom in</span><span>{e(last)}</span></div></div>")

    def highlight(self, text: str, words: list[str]) -> str:
        if not words:
            return e(text)
        pattern = re.compile("|".join(re.escape(w) for w in sorted(words, key=len, reverse=True) if w), re.I)
        out, pos = [], 0
        for m in pattern.finditer(text):
            out.append(e(text[pos:m.start()]) + f"<mark>{e(m.group(0))}</mark>")
            pos = m.end()
        return "".join(out) + e(text[pos:])

    def event_list(self, hits: list[analytics.Hit], compiled: Query, focus: int | None = None) -> str:
        rows = []
        for hit in hits:
            first, _, rest = hit.message.partition("\n")
            who = (hit.host + "/" if hit.host else "") + (hit.service or "")
            fields = "".join(f"<tr><td>{e(k)}</td><td>{e(json.dumps(v, ensure_ascii=False) if isinstance(v, (dict, list)) else v)}</td></tr>"
                             for k, v in hit.fields.items())
            detail = (f"<div class='detail'>{'<pre>' + self.highlight(hit.message, compiled.words) + '</pre>' if rest else ''}"
                      f"{'<table>' + fields + '</table>' if fields else ''}"
                      f"{'<pre class=muted>' + e(hit.raw) + '</pre>' if hit.raw else ''}"
                      f"<div class='small muted'>{e(hit.source)}:{hit.line} · <a href='/event/{hit.id}'>lines around it</a> · "
                      f"<a href='{e(self.link(q='pattern:' + json.dumps(hit.pattern)))}'>same pattern</a></div></div>")
            rows.append(f"<details class='ev{' focus' if focus == hit.id else ''}'{' open' if focus == hit.id else ''}><summary><span class='muted'>{e(iso(hit.ts, self.clock.zone))}</span>"
                        f"<span class='lv {e(hit.level_name if hit.level is not None else 'none')}'>{e(hit.level_name.upper())}</span>"
                        f"<span class='msg'>{f'<span class=who>{e(who)}</span> ' if who else ''}{self.highlight(first, compiled.words)}"
                        f"{' <span class=muted>(+' + str(rest.count(chr(10)) + 1) + ' lines)</span>' if rest else ''}</span></summary>{detail}</details>")
        return "".join(rows)

    def sidebar(self, compiled: Query, q: str, rng: str, chosen: str) -> str:
        def table(rows, key):
            if not rows:
                return "<p class='muted small'>Nothing to show.</p>"
            out = []
            for value, n in rows:
                term = f"{key}:{json.dumps(value) if NEEDS_QUOTES.search(value) else value}"
                href = self.link(q=f"{q} {term}".strip(), range=rng)
                out.append(f"<tr><td><a href='{e(href)}'>{e(value)}</a></td><td class='n'>{n:,}</td></tr>")
            return "<table class='top'>" + "".join(out) + "</table>"
        patterns = analytics.patterns(self.store, compiled, limit=8)
        pattern_rows = "".join(
            f"<tr><td><a class='pattern' href='{e(self.link(q=(q + ' ' if q else '') + 'pattern:' + json.dumps(p.template), range=rng))}'>"
            f"<span class='lv {e(p.level_name if p.level is not None else 'none')}'>{e(p.level_name.upper())}</span> {e(p.template)}</a></td>"
            f"<td class='n'>{p.count:,}</td></tr>" for p in patterns)
        parts = [f"<div class='card'><h2>Patterns</h2><table class='top'>{pattern_rows}</table></div>" if patterns else "",
                 f"<div class='card'><h2>Levels</h2>{table(analytics.top(self.store, compiled, 'level'), 'level')}</div>",
                 f"<div class='card'><h2>Services</h2>{table(analytics.top(self.store, compiled, 'service', limit=8), 'service')}</div>"]
        field_form = (f"<form method='get' action='/' class='fieldform'><input type='hidden' name='q' value='{e(q)}'>"
                      f"<input type='hidden' name='range' value='{e(rng)}'><input name='field' value='{e(chosen)}' placeholder='status, path, user…' "
                      f"aria-label='Field'>"
                      f"<button>Top</button></form>")
        field_rows = table(analytics.top(self.store, compiled, chosen, limit=10), chosen) if chosen else ""
        parts.append(f"<div class='card'><h2>Top values of a field</h2>{field_form}{field_rows}</div>")
        parts.append(HELP)
        return "".join(parts)

    def event(self, query: dict[str, str], event_id: int) -> Response:
        hit = analytics.get(self.store, event_id)
        if not hit:
            return self.page("Not found", "<div class='empty'><p>That event isn't in the index any more.</p><a href='/'>Back to search</a></div>", status=404)
        near = analytics.context(self.store, hit, 15)
        body = (f"<div class='card'><h2>Around line {hit.line} of <span class='path'>{e(hit.source)}</span></h2><div class='events'>"
                f"{self.event_list(near, Query(), focus=hit.id)}</div></div>")
        return self.page(f"Line {hit.line}", body)

    def sources(self, query) -> Response:
        rows = "".join(f"<tr><td>{e(s.path)}</td><td>{e(s.format)}</td><td class='n'>{s.events:,}</td>"
                       f"<td class='n'>{e(iso(s.ingested_at, self.clock.zone)[:19])}</td></tr>" for s in self.store.sources())
        body = (f"<div class='card'><h2>Files in the index</h2><table class='top'><tr><td class='muted'>File</td><td class='muted'>Format</td>"
                f"<td class='n'>Events</td><td class='n'>Last read</td></tr>{rows}</table>"
                f"<p class='small muted'>To pick up new lines, run <code>logsift refresh</code> (or put it in a scheduled task).</p></div>")
        return self.page("Files", body)

    def api_search(self, query: dict[str, str]) -> Response:
        try:
            compiled = self.compile(query.get("q", ""), query.get("range", ""))
            limit = min(int(query.get("limit", "100") or 100), 1000)
        except (QueryError, TimeError, ValueError) as err:
            return Response(400, json.dumps({"error": str(err)}).encode(), {"Content-Type": "application/json"})
        hits = analytics.search(self.store, compiled, limit=limit)
        body = {"total": analytics.count(self.store, compiled), "events": [h.to_dict() for h in hits]}
        return Response(200, json.dumps(body, ensure_ascii=False, default=str).encode(), {"Content-Type": "application/json; charset=utf-8"})


def analytics_interval(seconds: int) -> str:
    for size, name in ((86400, "day"), (3600, "hour"), (60, "min"), (1, "sec")):
        if seconds % size == 0:
            n = seconds // size
            return f"{n} {name}{'s' if n > 1 and name in ('day', 'hour') else ''}"
    return f"{seconds}s"


HELP = """<div class='card help small'><h2>Search tips</h2>
<p><code>timeout</code> words · <code>"connection refused"</code> phrase · <code>-healthcheck</code> leave out</p>
<p><code>level>=warn</code> · <code>service:api,worker</code> · <code>host:web-1</code></p>
<p><code>status>=500</code> · <code>path:/api/*</code> · <code>db.table:orders</code></p>
<p><code>since:2h</code> · <code>until:2026-11-19</code> · <code>source:nginx</code></p></div>"""


class Handler(BaseHTTPRequestHandler):
    app: App
    server_version = "logsift"

    def do_GET(self) -> None:  # noqa: N802
        self.respond("GET")

    def do_HEAD(self) -> None:  # noqa: N802
        self.respond("HEAD")

    def do_POST(self) -> None:  # noqa: N802
        self.respond("POST")

    def respond(self, method: str) -> None:
        response = self.app.request(method, self.path, dict(self.headers.items()))
        self.send_response(response.status)
        for key, value in response.headers.items():
            self.send_header(key, value)
        self.send_header("Content-Length", str(len(response.body)))
        self.end_headers()
        if method != "HEAD":
            self.wfile.write(response.body)

    def log_message(self, format: str, *args) -> None:  # noqa: A002
        pass


def make_server(store: Store, clock: Clock, port: int = 8800, host: str = "127.0.0.1") -> ThreadingHTTPServer:
    app = App(store, clock)
    app.live = True
    server = ThreadingHTTPServer((host, port), type("BoundHandler", (Handler,), {"app": app}))
    real = server.server_address[1]
    app.allowed_hosts = {f"127.0.0.1:{real}", f"localhost:{real}", f"[::1]:{real}"}
    return server
