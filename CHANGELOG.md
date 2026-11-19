# Changelog

## 0.1.0 — unreleased

The first version.

- Reads JSON lines, logfmt, nginx/Apache access logs, syslog (RFC 3164 and 5424), Python/Java/Go-style text logs and
  gzipped files, detecting the format of each file.
- Keeps stack traces with the error they belong to.
- Incremental ingest: only new lines are read; rotated and truncated files are read from the top; a half-written last
  line waits until it's complete. Also reads from stdin.
- SQLite index with full-text search (FTS5), and a plain fallback when FTS5 isn't available.
- Query language: words, phrases, negation, levels, any field (numbers, wildcards, nested fields, lists), source file,
  time windows and patterns.
- Patterns (messages grouped by shape), timeline, top values of any field, and the lines around an event.
- Command line (`ingest`, `refresh`, `search`, `count`, `stats`, `top`, `patterns`, `sources`, `forget`, `prune`,
  `serve`) and a read-only local dashboard.
- `scripts/demo_logs.py` writes realistic demo logs to try it on.
