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

## STORE-02 bounded investigation

The real pinned-reader regression (`tests/pinned_wal.rs`, 8-MiB fixture) accepted
196 records before explicit admission refusal: observed aggregate peak 8,305,352
bytes, WAL 8,202,952 bytes. A retained read transaction continued to see one record.
After releasing it and verifying a successful TRUNCATE checkpoint, integrity/head
were unchanged and the refused record could be appended. The test checks the
aggregate after every commit; this is empirical coverage, not a worst-case bound.

Writer audit before any reserve change:

| Path | Existing constraint | Remaining capacity argument |
|---|---|---|
| Startup schema/index migration | SQLite page cap; aggregate sampled after initial DDL | Admission before archive-scale index creation and postconditions |
| Startup detection backfill | 16-KiB estimate per insert | Index/WAL amplification, scan-pinned snapshot |
| Append | 128 records/4 MiB; estimated amplification | Worst-case index/WAL/SHM and annotations, writer exclusion |
| Compression | 32 rows/4-MiB originals, smaller replacements | WAL can grow even when logical payload shrinks; no admission |
| Retention | 32 records/4 MiB; bounded checkpoint metadata | Deletes and checkpoint rewrites need WAL admission |
| Offline noise copy | Admitted event batches | Direct annotation/provenance writes, combined destination/backup space |
| Checkpoint | Soft auto-checkpoint, explicit truncate | Inspect completion and account for simultaneous DB/WAL allocation |

ADR0040 adds pending main-file headroom and bounded small-WAL recovery. ADR0041
adds conservative pre-writer startup migration admission and near-budget fixtures
with missing indexes/pinned readers. Neither is a complete peak-size proof. Next
bound startup detection backfill and maintenance. Keep the half reserve until all
paths have an admission argument; no live archive changes.
