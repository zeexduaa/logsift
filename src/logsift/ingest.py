"""Reading log files into the index, a little at a time.

Each file's position is remembered, so ingesting again only reads lines added since. A file that was rotated
(replaced by a new one) or truncated is noticed by its first bytes changing or it getting shorter, and read from the top.
"""

from __future__ import annotations

import glob
import gzip
import hashlib
import io
import time
from dataclasses import dataclass
from pathlib import Path
from typing import Callable, Iterable, Iterator

from .parsers import FORMATS, LineParser, detect_format
from .store import Source, Store
from .timeparse import Clock

LOG_SUFFIXES = (".log", ".jsonl", ".ndjson", ".txt", ".out", ".err", ".gz")
BATCH = 2000
SETTLED = 2.0  # seconds since the last write before a final line without a newline is taken as complete


class IngestError(ValueError):
    """A path that can't be read as a log file."""


@dataclass
class Result:
    path: str
    format: str
    added: int
    status: str  # new | appended | unchanged | rotated | replaced


def expand(paths: Iterable[str]) -> list[Path]:
    """Files named directly, every log-like file in a folder (recursively), and globs (Windows shells don't expand them)."""
    found: list[Path] = []
    for raw in paths:
        matches = [Path(p) for p in glob.glob(raw)] if any(c in raw for c in "*?[") else [Path(raw)]
        if not matches:
            raise IngestError(f"nothing matches {raw}")
        for path in matches:
            if path.is_dir():
                found += sorted(p for p in path.rglob("*") if p.is_file() and _looks_like_log(p))
            elif path.is_file():
                found.append(path)
            else:
                raise IngestError(f"{path} doesn't exist")
    unique: dict[str, Path] = {}
    for path in found:
        unique.setdefault(str(path.resolve()), path)
    return list(unique.values())


def _looks_like_log(path: Path) -> bool:
    name = path.name.lower()
    return name.endswith(LOG_SUFFIXES) or ".log." in name  # app.log.1, app.log.2.gz


def _is_binary(sample: bytes) -> bool:
    return b"\x00" in sample[:4096]


HEAD = 1024


def _head(path: Path, size: int = HEAD) -> str:
    """A fingerprint of a file's first bytes ("<how many>:<hash>"). A file still under 1 KB only fingerprints what it had,
    so lines added to a small file don't look like a new file."""
    with open(path, "rb") as f:
        data = f.read(min(size, HEAD))
    return f"{len(data)}:{hashlib.sha256(data).hexdigest()[:20]}"


def _same_file(path: Path, head: str) -> bool:
    try:
        length = int(head.split(":", 1)[0])
    except ValueError:
        return False
    return _head(path, length) == head


def _open(path: Path, offset: int) -> io.BufferedReader:
    if path.suffix == ".gz":
        return gzip.open(path, "rb")  # type: ignore[return-value]
    f = open(path, "rb")
    f.seek(offset)
    return f  # type: ignore[return-value]


def _lines(f: io.BufferedReader, offset: int, settled: bool) -> Iterator[tuple[str, int]]:
    """Complete lines with the offset just after each. A last line with no newline is held back while the file is
    still being written (it may be half a line), and taken once the file has settled."""
    first = offset == 0
    for chunk in f:
        if not chunk.endswith(b"\n") and not settled:
            return
        offset += len(chunk)
        text = chunk.decode("utf-8", "replace")
        if first:
            text = text.removeprefix("\ufeff")  # the byte-order mark Notepad and other Windows tools put at the start
            first = False
        yield text, offset


def _encoding(path: Path) -> str:
    """UTF-16 if the file says so with a byte-order mark (PowerShell 5's "> file" writes that), otherwise UTF-8."""
    if path.suffix == ".gz":
        return "utf-8"
    with open(path, "rb") as f:
        start = f.read(2)
    return {b"\xff\xfe": "utf-16-le", b"\xfe\xff": "utf-16-be"}.get(start, "utf-8")


def _utf16_lines(path: Path, offset: int, codec: str, settled: bool) -> Iterator[tuple[str, int]]:
    """Like _lines, for UTF-16: offsets stay in bytes, so reading can resume exactly where it stopped."""
    with open(path, "rb") as f:
        f.seek(offset)
        data = f.read()
    if offset == 0:
        data, offset = data[2:], 2  # the byte-order mark
    data = data[:len(data) - len(data) % 2]  # half a character at the end is still being written
    text = data.decode(codec, "replace")
    pieces = text.split("\n")
    for i, piece in enumerate(pieces):
        last = i == len(pieces) - 1
        if last and (not piece or not settled):
            return  # nothing after the final newline, or a line still being written
        line = piece if last else piece + "\n"
        offset += len(line.encode(codec))
        yield line, offset


def ingest_file(store: Store, path: Path, clock: Clock, *, fmt: str | None = None) -> Result:
    if fmt is not None and fmt not in FORMATS:
        raise IngestError(f"unknown format {fmt!r}; choose from {', '.join(FORMATS)}")
    key = str(path.resolve())
    stat = path.stat()
    try:
        with _open(path, 0) as f:
            sample = f.read(4096)
    except (OSError, EOFError) as err:  # includes a ".gz" that isn't really gzip
        raise IngestError(f"can't read {path}: {err}") from None
    codec = _encoding(path)
    if codec == "utf-8" and _is_binary(sample):
        raise IngestError(f"{path} looks like a binary file, not a log")
    src = store.source(key)
    status = "appended"
    with store.db:
        if src is None:
            src = store.add_source(key, fmt or "text")
            status = "new"
        elif not _same_file(path, src.head) or stat.st_size < src.offset:
            # Rotated (a new file under the same name) or truncated: start again from the top. Events already read
            # from the old file are kept, since they're still history.
            status = "rotated"
            src.offset = src.line = 0
        elif src.size == stat.st_size and src.offset == stat.st_size:
            return Result(str(path), src.format, 0, "unchanged")
        if path.suffix == ".gz":
            if status != "new":
                if src.size == stat.st_size and _same_file(path, src.head):
                    return Result(str(path), src.format, 0, "unchanged")
                store.clear_source(src)   # compressed files are read whole; a changed one replaces what was read
                status = "replaced"
            src.offset = src.line = 0
        if fmt:
            src.format = fmt
        elif src.offset == 0:
            if codec == "utf-8":
                with _open(path, 0) as f:
                    sample = [line.decode("utf-8", "replace").removeprefix("\ufeff") for _, line in zip(range(200), f)]
            else:
                sample = [line for (line, _), _ in zip(_utf16_lines(path, 0, codec, True), range(200))]
            src.format = detect_format(sample, clock)
        before = src.events
        settled = time.time() - stat.st_mtime > SETTLED or path.suffix == ".gz"
        parser = LineParser(src.format, clock)
        batch = []
        number = src.line
        offset = src.offset
        with _open(path, src.offset) as f:
            lines = _lines(f, src.offset, settled) if codec == "utf-8" else _utf16_lines(path, src.offset, codec, settled)
            for text, offset in lines:
                number += 1
                event = parser.feed(text, number)
                if event:
                    batch.append(event)
                    if len(batch) >= BATCH:
                        store.insert(src, batch)
                        batch = []
        last = parser.finish()
        if last:
            batch.append(last)
        store.insert(src, batch)
        src.offset = offset if path.suffix != ".gz" else stat.st_size
        src.line = number
        src.size = stat.st_size
        src.head = _head(path)
        store.save_progress(src)
    return Result(str(path), src.format, src.events - before, status)


def ingest(store: Store, paths: Iterable[str], clock: Clock, *, fmt: str | None = None,
           report: Callable[[Result], None] | None = None,
           problem: Callable[[str, str], None] | None = None) -> list[Result]:
    """Ingest every file the paths name. A path or file that can't be read is reported through `problem(path, reason)`
    and skipped, so one bad file in a folder doesn't stop the rest; without `problem` the first one raises."""
    results = []
    for raw in paths:
        try:
            files = expand([raw])
        except IngestError as err:
            if problem is None:
                raise
            problem(raw, str(err))
            continue
        for path in files:
            try:
                result = ingest_file(store, path, clock, fmt=fmt)
            except (IngestError, OSError) as err:
                if problem is None:
                    raise
                problem(str(path), str(err))
                continue
            results.append(result)
            if report:
                report(result)
    return results


def refresh(store: Store, clock: Clock, report: Callable[[Result], None] | None = None) -> list[Result]:
    """Read new lines from every file already in the index. Files that have disappeared are skipped, not forgotten."""
    results = []
    for src in store.sources():
        path = Path(src.path)
        if not path.is_file():
            continue
        result = ingest_file(store, path, clock)
        results.append(result)
        if report:
            report(result)
    return results


def ingest_stream(store: Store, stream: io.TextIOBase, clock: Clock, name: str = "<stdin>", fmt: str | None = None) -> Result:
    """Logs piped in (`kubectl logs pod | logsift ingest -`). Each run adds what it receives."""
    lines = stream.read().removeprefix("\ufeff").splitlines()
    with store.db:
        src = store.source(name) or store.add_source(name, fmt or "text")
        src.format = fmt or detect_format(lines[:200], clock)
        parser = LineParser(src.format, clock)
        before = src.events
        batch = [e for n, line in enumerate(lines, src.line + 1) if (e := parser.feed(line, n))]
        last = parser.finish()
        if last:
            batch.append(last)
        store.insert(src, batch)
        src.line += len(lines)
        store.save_progress(src)
    return Result(name, src.format, src.events - before, "appended")

