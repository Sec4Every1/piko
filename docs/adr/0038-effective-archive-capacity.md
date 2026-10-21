# ADR 0038: report the effective SQLite capacity

2026-10-21. Reporting change; retention and write admission unchanged.

The observed archive hit its 1-GiB SQLite page limit with roughly 1 GiB of aggregate
files, while its configured operational budget was 2 GiB. The budget includes
transaction/checkpoint headroom. These are different limits; reporting the entire
budget as consumed would be misleading.

The storage worker now reads max_page_count times page_size from its connection,
using checked arithmetic, rather than assuming budget/2 in telemetry. The UI
accepts bounded page-aligned effective limits, displays them and distinguishes a
full internal database from a still-unexhausted aggregate budget when fresh active
page measurements support that conclusion. Missing/stale values stay explicit.

The configured half-budget reserve is retained. WAL auto-checkpoint and
journal_size_limit are soft settings, not hard WAL size bounds. Reducing the
reserve alone would not establish safe aggregate use under pinned readers,
retention deletes, compression and startup index writes. A future capacity change
needs admission/checkpoint evidence for every writer, including near-budget and
long-reader tests. No records were removed, no quota increased and the 12-month
stop-on-full policy is unchanged.

References: [SQLite PRAGMAs](https://www.sqlite.org/pragma.html),
[WAL checkpoints](https://www.sqlite.org/wal.html).
