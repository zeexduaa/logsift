# Roadmap

logsift 0.1 reads the common formats, keeps an incremental index, and answers searches, patterns, timelines and top
values from the command line and a local dashboard. These are the next steps, roughly in order.

## Next

- [ ] **Live tail**: `logsift tail QUERY` follows files as they're written and prints matching lines, and the dashboard
      gets a live mode.
- [ ] **Alerts**: `logsift watch 'level>=error' --more-than 20 --per 5m --run "notify-send ..."`, so a scheduled task
      can warn you before users do.
- [ ] **Compare two periods**: which patterns are new or growing since yesterday. Usually the fastest way to find what a
      deploy broke.
- [ ] **Custom formats**: a named regex in a small config file for logs in a shape logsift doesn't know.

## Later

- [ ] **Smarter duplicates on rotation**: recognise when `app.log.1` is the old `app.log` and skip lines already read.
- [ ] **Field statistics**: percentiles for numeric fields (`p95 duration by path`).
- [ ] **Saved searches** on the dashboard.
- [ ] **Smaller index**: store raw lines compressed, and only when they say more than the parsed event.
- [ ] **More sources**: the systemd journal (`journalctl -o json`), Docker container logs, Windows Event Log exports.
- [ ] **Export** a search as NDJSON or CSV from the dashboard.

## Done

- [x] Format detection: JSON lines, logfmt, access logs, syslog 3164/5424, text logs, gzip
- [x] Multi-line events (Python and Java stack traces)
- [x] Incremental ingest with rotation, truncation and half-written-line handling
- [x] Query language with fields, numbers, wildcards, nested fields, time windows and negation
- [x] Patterns, timeline, top values, context
- [x] Command line and read-only local dashboard
- [x] OR, NOT and brackets in searches (0.2)
