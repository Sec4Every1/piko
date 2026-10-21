# ADR 0040: append headroom and bounded WAL recovery

2026-10-21. Safe Rust, no new dependency/FFI/privilege. Budget and half reserve stay.

Append admission now adds the pending main-file allocation (SQLite page_count
times page_size minus physical main-file length, including freelist pages) to
the existing estimated transaction growth. Checkpoint may allocate the main
file before physically truncating WAL: ignoring this would understate the peak.

When admission fails, an append can attempt one TRUNCATE checkpoint only when
the current aggregate plus pending main-file growth fits its configured budget.
Both WAL and pending growth must be at most 16 MiB; larger work remains explicit
maintenance rather than archive-scale I/O on an append. It temporarily uses a
zero busy timeout, inspects the checkpoint busy result and restores the previous
timeout even on SQLite errors. Pinned readers produce explicit capacity refusal.
After a completed checkpoint it measures admission again before any record insert.
Runtime's existing bounded flush retry can resume after a short reader releases.
No event is evicted, changed or falsely acknowledged; retained raw evidence and
chain semantics are unchanged. This cannot fix a database already at its page cap.

The real 8-MiB fixture refuses near capacity, preserves a pinned snapshot, rejects
further retries while pinned and automatically appends the refused record after
release. A 32-MiB fixture demonstrates the large-WAL gate and verified manual
checkpoint/retry in the test only. Both check observed aggregate and projected
main/WAL coexistence, record count and integrity. A connection-level test checks
busy timeout restoration after external-reader busy, success and SQLite locked
errors. File samples are not instrumentation of transient peaks.

This closes the known pending-main allocation omission and small-WAL retry trap;
it does not prove the transaction-growth heuristic for all indexes/page splits,
exclude independent writers or bound startup/retention/compression/copy writes.
The 16-MiB input gate is an I/O-size bound, not a wall-clock latency guarantee.
Do not reduce the half reserve on this evidence. ADR0038 lists remaining work.
