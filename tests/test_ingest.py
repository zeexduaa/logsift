import gzip
import io
import os
import time

import pytest

from logsift.ingest import IngestError, expand, ingest, ingest_file, ingest_stream, refresh
from logsift.store import Store

from .conftest import FIXTURES


@pytest.fixture
def store():
    return Store()


def settle(path):
    """Make a file look like nobody has written to it for a while."""
    old = time.time() - 60
    os.utime(path, (old, old))


def test_ingest_folder(store, clock):
    results = ingest(store, [str(FIXTURES)], clock)
    assert {r.path.rsplit(os.sep, 1)[-1]: (r.format, r.added) for r in results} == {
        "access.log": ("access", 4), "app.jsonl": ("json", 5), "logfmt.log": ("logfmt", 3), "python.log": ("text", 5),
        "syslog.log": ("syslog", 4)}
    assert store.count() == 21
    again = ingest(store, [str(FIXTURES)], clock)
    assert all(r.status == "unchanged" and r.added == 0 for r in again)
    assert store.count() == 21


def test_only_new_lines_are_read(store, clock, tmp_path):
    log = tmp_path / "app.log"
    log.write_text("2026-11-19 07:00:00 INFO one\n2026-11-19 07:00:01 INFO two\n")
    settle(log)
    assert ingest_file(store, log, clock).added == 2
    with open(log, "a") as f:
        f.write("2026-11-19 07:00:02 ERROR three\n")
    settle(log)
    result = ingest_file(store, log, clock)
    assert (result.status, result.added) == ("appended", 1)
    lines = [r[0] for r in store.db.execute("SELECT line FROM events ORDER BY id")]
    assert lines == [1, 2, 3]  # line numbers carry on


def test_half_written_last_line_waits(store, clock, tmp_path):
    log = tmp_path / "live.log"
    log.write_text("2026-11-19 07:00:00 INFO done\n2026-11-19 07:00:01 INFO half wri")  # just written, no newline yet
    assert ingest_file(store, log, clock).added == 1
    with open(log, "a") as f:
        f.write("tten\n")
    assert ingest_file(store, log, clock).added == 1
    assert store.db.execute("SELECT message FROM events ORDER BY id DESC").fetchone()[0] == "half written"


def test_settled_file_without_final_newline(store, clock, tmp_path):
    log = tmp_path / "old.log"
    log.write_text("2026-11-19 07:00:00 INFO a\n2026-11-19 07:00:01 INFO b")
    settle(log)
    assert ingest_file(store, log, clock).added == 2


def test_rotation_and_truncation(store, clock, tmp_path):
    log = tmp_path / "app.log"
    log.write_text("2026-11-19 07:00:00 INFO old one\n2026-11-19 07:00:01 INFO old two\n")
    settle(log)
    ingest_file(store, log, clock)
    log.write_text("2026-11-19 08:00:00 INFO brand new\n")  # replaced, and shorter
    settle(log)
    result = ingest_file(store, log, clock)
    assert (result.status, result.added) == ("rotated", 1)
    assert store.count() == 3  # what was read from the old file is kept


def test_gzip_files(store, clock, tmp_path):
    gz = tmp_path / "app.log.1.gz"
    gz.write_bytes(gzip.compress(b"2026-11-18 07:00:00 ERROR from yesterday\n2026-11-18 07:00:01 INFO ok\n"))
    assert ingest_file(store, gz, clock).added == 2
    assert ingest_file(store, gz, clock).status == "unchanged"
    gz.write_bytes(gzip.compress(b"2026-11-18 09:00:00 INFO replaced\n"))
    result = ingest_file(store, gz, clock)
    assert (result.status, result.added) == ("replaced", 1) and store.count() == 1


def test_refuses_binary_and_missing(store, clock, tmp_path):
    binary = tmp_path / "image.log"
    binary.write_bytes(b"\x89PNG\x00\x00\x00binary")
    with pytest.raises(IngestError, match="binary"):
        ingest_file(store, binary, clock)
    with pytest.raises(IngestError):
        expand([str(tmp_path / "nope.log")])
    fake_gz = tmp_path / "fake.gz"
    fake_gz.write_text("not compressed")
    with pytest.raises(IngestError, match="can't read"):
        ingest_file(store, fake_gz, clock)


def test_expand_folders_and_globs(tmp_path):
    (tmp_path / "a.log").write_text("x\n")
    (tmp_path / "sub").mkdir()
    (tmp_path / "sub" / "b.log.2").write_text("x\n")
    (tmp_path / "notes.md").write_text("x\n")
    assert sorted(p.name for p in expand([str(tmp_path)])) == ["a.log", "b.log.2"]
    assert [p.name for p in expand([str(tmp_path / "*.log"), str(tmp_path / "a.log")])] == ["a.log"]  # no duplicates


def test_forced_format(store, clock, tmp_path):
    log = tmp_path / "odd.txt"
    log.write_text('{"msg": "json in a .txt"}\n')
    settle(log)
    assert ingest_file(store, log, clock, fmt="text").format == "text"
    with pytest.raises(IngestError):
        ingest_file(store, log, clock, fmt="xml")


def test_refresh_reads_known_files(store, clock, tmp_path):
    log = tmp_path / "app.log"
    log.write_text("2026-11-19 07:00:00 INFO one\n")
    settle(log)
    ingest_file(store, log, clock)
    with open(log, "a") as f:
        f.write("2026-11-19 07:00:01 INFO two\n")
    settle(log)
    (tmp_path / "gone.log").write_text("2026-11-19 07:00:00 INFO bye\n")
    settle(tmp_path / "gone.log")
    ingest_file(store, tmp_path / "gone.log", clock)
    (tmp_path / "gone.log").unlink()
    assert sum(r.added for r in refresh(store, clock)) == 1


def test_stdin(store, clock):
    result = ingest_stream(store, io.StringIO('{"level":"error","msg":"boom"}\n{"level":"info","msg":"ok"}\n'), clock)
    assert (result.format, result.added) == ("json", 2)
    ingest_stream(store, io.StringIO('{"level":"info","msg":"more"}\n'), clock)
    assert store.count() == 3


def test_forget_and_prune(store, clock):
    ingest(store, [str(FIXTURES)], clock)
    path = str((FIXTURES / "syslog.log").resolve())
    assert store.forget(path) == 4 and store.count() == 17
    removed = store.prune(clock.now - 1800)  # older than 07:30 UTC: only the +05:00 line, at 02:50 UTC
    assert removed == 1
    assert store.forget("/not/there") == 0


def test_byte_order_mark_is_ignored(store, clock, tmp_path):
    """Notepad and many Windows tools start UTF-8 files with a BOM; the first event must still be read properly."""
    log = tmp_path / "bom.jsonl"
    log.write_bytes('﻿{"time":"2026-11-19T07:50:01Z","level":"error","msg":"first"}\n'
                    '{"time":"2026-11-19T07:50:02Z","level":"info","msg":"second"}\n'.encode("utf-8"))
    settle(log)
    assert ingest_file(store, log, clock).format == "json"
    first = store.db.execute("SELECT message, level, ts FROM events ORDER BY line").fetchone()
    assert first["message"] == "first" and first["level"] == 4 and first["ts"] is not None
