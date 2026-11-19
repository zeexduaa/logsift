"""The logsift command."""

from __future__ import annotations

import argparse
import csv
import json
import os
import re
import sys
import time
import webbrowser
from pathlib import Path

from . import __version__, analytics
from .ingest import IngestError, Result, ingest, ingest_stream, refresh
from .parsers import FORMATS
from .query import QueryError, compile_query
from .store import Store, StoreError, default_path
from .timeparse import LEVELS, Clock, TimeError, iso, parse_duration, parse_zone

COLORS = {"trace": "2", "debug": "2", "info": "36", "warn": "33", "error": "31", "fatal": "1;31"}


class Output:
    def __init__(self, color: bool):
        self.color = color

    def paint(self, text: str, code: str) -> str:
        return f"\033[{code}m{text}\033[0m" if self.color and code else text


def use_color(stream) -> bool:
    if os.environ.get("NO_COLOR") or not hasattr(stream, "isatty") or not stream.isatty():
        return False
    if sys.platform == "win32":
        os.system("")  # turns on ANSI colours in the Windows console
    return True


def positive(text: str) -> int:
    """-n must be a count of at least 1 (SQLite reads a negative LIMIT as "no limit at all")."""
    try:
        n = int(text)
    except ValueError:
        raise argparse.ArgumentTypeError(f"{text!r} isn't a number") from None
    if n < 1:
        raise argparse.ArgumentTypeError("must be 1 or more")
    return n


def build_parser() -> argparse.ArgumentParser:
    p = argparse.ArgumentParser(prog="logsift", description="Search and make sense of log files.",
                                epilog="Quote searches that contain > < or spaces: logsift search 'status>=500 since:1h'")
    p.add_argument("--version", action="version", version=f"logsift {__version__}")
    p.add_argument("--db", type=Path, help="index file (default: LOGSIFT_DB or your cache folder)")
    p.add_argument("--tz", default="local", help="time zone for times without one, and for showing times: local, UTC, +05:00")
    sub = p.add_subparsers(dest="command", metavar="command")

    s = sub.add_parser("ingest", help="read log files (or folders, or globs, or - for stdin) into the index")
    s.add_argument("paths", nargs="+")
    s.add_argument("--format", choices=FORMATS, help="skip detection and read the files as this format")
    sub.add_parser("refresh", help="read new lines from every file already in the index")

    def query_args(s, required=False):
        s.add_argument("query", nargs="+" if required else "*", help="search terms (see 'logsift help-query')")

    s = sub.add_parser("search", help="show matching events, newest last")
    query_args(s)
    s.add_argument("-n", "--limit", type=positive, default=50, help="how many events (default 50)")
    s.add_argument("--json", action="store_true", help="one JSON object per line, for jq and scripts")
    s.add_argument("--csv", action="store_true", help="CSV for a spreadsheet")
    s.add_argument("--full", action="store_true", help="show every line of multi-line events (stack traces)")
    s.add_argument("-C", "--context", type=int, metavar="N", help="also show N events before and after each match, from its file")
    s = sub.add_parser("count", help="how many events match")
    query_args(s)
    s = sub.add_parser("stats", help="totals, levels and a timeline of matching events")
    query_args(s)
    s = sub.add_parser("top", help="the most common values of a field, e.g. top status 'level>=warn'")
    s.add_argument("field")
    query_args(s)
    s.add_argument("-n", "--limit", type=positive, default=10)
    s = sub.add_parser("patterns", help="group matching messages by shape: the distinct things happening")
    query_args(s)
    s.add_argument("-n", "--limit", type=positive, default=20)
    sub.add_parser("sources", help="list the files in the index")
    s = sub.add_parser("forget", help="remove a file and its events from the index")
    s.add_argument("path")
    s = sub.add_parser("prune", help="delete events older than a given age")
    s.add_argument("--older-than", required=True, metavar="AGE", help="e.g. 30d, 12h")
    s = sub.add_parser("serve", help="open the search dashboard in your browser")
    s.add_argument("--port", type=int, default=8800)
    s.add_argument("--no-browser", action="store_true")
    sub.add_parser("help-query", help="explain the search language")
    return p


def show_result(r: Result) -> None:
    if r.status == "unchanged":
        print(f"  {r.path}: no new lines")
    else:
        note = {"new": "", "appended": "", "rotated": " (file was rotated or truncated; read from the top)",
                "replaced": " (compressed file changed; read again)"}[r.status]
        print(f"  {r.path}: {r.added:,} events as {r.format}{note}")


CONTROL = re.compile(r"[\x00-\x08\x0b-\x1f\x7f-\x9f]")


def safe(text: str) -> str:
    """Log lines often carry text an attacker chose (a user agent, a URL, a username). Escape codes in it would be run
    by the terminal: clearing the screen, retitling the window, hiding lines. Show them as \\x1b instead."""
    return CONTROL.sub(lambda m: f"\\x{ord(m.group(0)):02x}", text).replace("\t", "    ")


def cell(text: str) -> str:
    """Spreadsheets run a cell that starts with = + - @ as a formula. Log text is often chosen by an attacker, so such
    cells get a leading ' and open as plain text."""
    return "'" + text if text[:1] in ("=", "+", "-", "@", "\t", "\r") else text


def event_line(hit: analytics.Hit, out: Output, zone, full: bool) -> str:
    level = hit.level_name
    who = safe(hit.service or "")
    if hit.host:
        who = f"{safe(hit.host)}/{who}" if who else safe(hit.host)
    message = hit.message if full else hit.message.split("\n", 1)[0] + (" …" if "\n" in hit.message else "")
    message = safe(message)
    head = f"{out.paint(iso(hit.ts, zone), '2')} {out.paint(level.upper().ljust(5), COLORS.get(level, ''))}"
    return f"{head} {out.paint(who, '35') + ' ' if who else ''}{message}"


def run(args: argparse.Namespace, store: Store, clock: Clock, out: Output) -> int:
    cmd = args.command
    zone = clock.zone
    if cmd == "ingest":
        started = time.time()
        results: list[Result] = []
        if args.paths == ["-"]:
            results.append(ingest_stream(store, sys.stdin, clock, fmt=args.format))
            show_result(results[-1])
        else:
            print("Reading:")
            skipped: list[str] = []

            def problem(path: str, reason: str) -> None:
                skipped.append(path)
                print(f"  skipped {path}: {reason.removeprefix(path + ' ')}", file=sys.stderr)

            results = ingest(store, args.paths, clock, fmt=args.format, report=show_result, problem=problem)
        added = sum(r.added for r in results)
        print(f"Added {added:,} events from {len(results)} file{'s' if len(results) != 1 else ''} in {time.time() - started:.1f}s. "
              f"The index has {store.count():,}.")
        if args.paths != ["-"] and skipped:
            print(f"{len(skipped)} could not be read (see above).", file=sys.stderr)
            return 1  # so a script or scheduled task notices
        return 0
    if cmd == "refresh":
        results = refresh(store, clock, report=show_result)
        print(f"Added {sum(r.added for r in results):,} events." if results else "Nothing in the index yet. Start with: logsift ingest <files>")
        return 0
    if cmd == "sources":
        rows = store.sources()
        if not rows:
            print("Nothing in the index yet. Start with: logsift ingest <files>")
        for src in rows:
            print(f"{src.events:>10,}  {src.format:7} {src.path}")
        return 0
    if cmd == "forget":
        path = args.path if args.path == "<stdin>" else str(Path(args.path).resolve())
        if store.source(path) is None:
            print(f"logsift: {path} isn't in the index (see 'logsift sources')", file=sys.stderr)
            return 1
        removed = store.forget(path)
        print(f"Removed {path} and its {removed:,} events.")
        return 0
    if cmd == "prune":
        removed = store.prune(clock.now - parse_duration(args.older_than))
        store.compact()
        print(f"Deleted {removed:,} events older than {args.older_than}.")
        return 0
    if cmd == "serve":
        from .web import make_server
        try:
            server = make_server(store, clock, args.port)
        except OSError as err:
            print(f"logsift: can't use port {args.port} ({err.strerror}); try --port", file=sys.stderr)
            return 1
        url = f"http://127.0.0.1:{server.server_address[1]}/"
        print(f"logsift is running at {url}  (Ctrl+C to stop)")
        if not args.no_browser:
            webbrowser.open(url)
        try:
            server.serve_forever()
        except KeyboardInterrupt:
            print("\nStopped.")
        finally:
            server.server_close()
        return 0
    if cmd == "help-query":
        from . import query
        print(query.__doc__.split("\n\n", 1)[1].rsplit("\n\n", 1)[0])
        return 0

    q = compile_query(" ".join(args.query), clock, fts=store.fts)
    if cmd == "count":
        print(analytics.count(store, q))
        return 0
    if cmd == "search":
        hits = analytics.search(store, q, limit=args.limit)
        hits.reverse()  # newest last, like tail
        if args.json:
            for hit in hits:
                print(json.dumps(hit.to_dict(), ensure_ascii=False, default=str))
            return 0
        if args.csv:
            writer = csv.writer(sys.stdout, lineterminator="\n")
            writer.writerow(["time", "level", "service", "host", "message", "source", "line"])
            for hit in hits:
                writer.writerow([iso(hit.ts, zone), hit.level_name, cell(hit.service or ""), cell(hit.host or ""),
                                 cell(hit.message), cell(hit.source), hit.line])
            return 0
        if not hits:
            print("No events match." if store.count() else "The index is empty. Start with: logsift ingest <files>")
            return 0
        for hit in hits:
            if args.context:
                for near in analytics.context(store, hit, args.context):
                    mark = out.paint(">", "1") if near.id == hit.id else " "
                    print(mark, event_line(near, out, zone, args.full))
                print(out.paint("--", "2"))
            else:
                print(event_line(hit, out, zone, args.full))
        total = analytics.count(store, q)
        if total > len(hits):
            print(out.paint(f"(showing the newest {len(hits)} of {total:,}; use -n for more)", "2"))
        return 0
    if cmd == "stats":
        s = analytics.summary(store, q)
        print(f"{s.total:,} events" + (f", {iso(s.first, zone)} to {iso(s.last, zone)}" if s.first else ""))
        for name in list(LEVELS) + ["none"]:
            if s.levels.get(name):
                print(f"  {out.paint(name.ljust(6), COLORS.get(name, ''))}{s.levels[name]:>10,}")
        h = analytics.histogram(store, q, target=30, now=clock.now)
        if h and h.peak:
            print(f"\nEvents per {_interval(h.interval)}:")
            quiet = 0
            for i, (start, errors, warns, other) in enumerate(h.buckets):
                total = errors + warns + other
                # A long quiet stretch is shown as one "⋮" instead of a screen of empty rows.
                if not total and 0 < i < len(h.buckets) - 1:
                    quiet += 1
                    continue
                if quiet:
                    print(f"  {'⋮':16} {out.paint(f'({quiet} quiet)', '2')}" if quiet > 2 else
                          "\n".join(f"  {iso(h.buckets[i - k][0], zone)[:16]}" for k in range(quiet, 0, -1)))
                    quiet = 0
                width = round(total / h.peak * 40)
                bar = out.paint("█" * round(errors / h.peak * 40), "31") + out.paint("█" * round(warns / h.peak * 40), "33")
                bar += "█" * max(0, width - round(errors / h.peak * 40) - round(warns / h.peak * 40))
                print(f"  {iso(start, zone)[:16]} {bar} {total:,}" if total else f"  {iso(start, zone)[:16]}")
        return 0
    if cmd == "top":
        rows = analytics.top(store, q, args.field, limit=args.limit)
        if not rows:
            print(f"No matching events have a {args.field!r} field.")
        width = max((len(v) for v, _ in rows), default=0)
        for value, n in rows:
            print(f"  {safe(value).ljust(min(width, 60))[:60]}  {n:>8,}")
        return 0
    if cmd == "patterns":
        rows = analytics.patterns(store, q, limit=args.limit)
        for p in rows:
            level = out.paint(p.level_name.upper().ljust(5), COLORS.get(p.level_name, ""))
            print(f"{p.count:>8,}  {level}  {safe(p.template)}")
            print(out.paint(f"{'':17}e.g. {safe(p.example[:120])}", "2"))
        if not rows:
            print("No events match.")
        return 0
    return 2


def _interval(seconds: int) -> str:
    for size, name in ((604800, "week"), (86400, "day"), (3600, "hour"), (60, "minute"), (1, "second")):
        if seconds % size == 0:
            n = seconds // size
            return name if n == 1 else f"{n} {name}s"
    return f"{seconds}s"


def main(argv: list[str] | None = None, *, clock: Clock | None = None) -> int:
    for stream in (sys.stdout, sys.stderr):
        try:
            stream.reconfigure(errors="replace")  # type: ignore[union-attr]
        except (AttributeError, ValueError):
            pass
    parser = build_parser()
    args = parser.parse_args(argv)
    if not args.command:
        parser.print_help()
        return 0
    try:
        zone = parse_zone(args.tz)
    except TimeError as err:
        print(f"logsift: {err}", file=sys.stderr)
        return 2
    clock = clock or Clock(zone)
    try:
        store = Store(args.db or default_path())
    except StoreError as err:
        print(f"logsift: {err}", file=sys.stderr)
        return 1
    try:
        return run(args, store, clock, Output(use_color(sys.stdout)))
    except (QueryError, TimeError, IngestError) as err:
        print(f"logsift: {err}", file=sys.stderr)
        return 1
    except BrokenPipeError:  # logsift search ... | head
        try:
            sys.stdout = open(os.devnull, "w")
        except OSError:
            pass
        return 0
    except KeyboardInterrupt:
        return 130
    finally:
        store.close()
