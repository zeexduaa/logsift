# Changelog

## 0.2.0 — unreleased

- **OR, NOT and brackets in searches**: `(status:502 OR status:504) service:api NOT (healthcheck OR level:debug)`.
  `-( ... )` works as NOT. Operators are only recognised in capitals, so "or" in a message is still a word, and a word
  like `price_cart(item)` isn't mistaken for a group. Mistakes ("OR with nothing after it", an unclosed bracket, since:
  inside OR) get a message saying what to change.
- Searching a field for several values is faster: the value is read once (`IN (...)`) instead of once per comparison,
  and `status:502 OR status:504` is looked up like `status:502,504`. On 90,000 events this took one such search from
  0.66 s to 0.16 s.

### Fixed

- **Security:** escape codes inside log messages (which an attacker can plant through a request) were sent to the
  terminal by `search`, `patterns` and `top`, where they could clear the screen, retitle the window or hide lines.
  They're now shown as `\x1b`.
- **Security:** `search --csv` cells starting with `=`, `+`, `-` or `@` ran as formulas in Excel and LibreOffice.
- syslog lines with RFC 3339 timestamps (rsyslog on current Debian and Ubuntu) were read as plain text.
- Clicking a pattern, a top value or a timeline bar on an OR search changed its meaning, or showed an error.
- `-n -1` printed every event, and `-n 0` said nothing matched.

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

### Fixed before release

- The first line of a file saved with a byte-order mark (Notepad, many Windows tools) wasn't recognised.
- nginx/Apache lines for empty or garbage requests (`"-" 400`, scanners) lost their time, status and level.
- UTF-16 files (PowerShell 5's `> out.log`) were refused as binary.
- One unreadable file stopped `logsift ingest`, so later files were never read; now it's skipped and reported.
- "Last hour" timelines stopped at the last event instead of running to now.
