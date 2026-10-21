# ADR 0042: bounded startup annotation backfill without a pinned scan

2026-10-21. Safe Rust, existing event store/core, no new dependency or privilege.

Startup previously held a SELECT over all unannotated historical candidates while
writing each derived detection with a fixed16KiB estimate. That reader could pin
the writer's WAL throughout backfill, and admission omitted serialized annotation
size. Events themselves were already integrity-verified before backfill.

The scan now uses ascending event position/keyset batches, at most32 candidates
and4MiB combined event/annotation bytes admitted per batch. The next candidate is
decoded before the byte decision; this is not a4MiB process-memory guarantee.
The cursor advances for unsupported candidates too, preventing an empty first
batch from stopping later detections or repeating indefinitely. It closes rows
and statement before checkpoint/admission or any annotation writes.

Annotation admission includes serialized derived payload, existing index/WAL
amplification estimate and pending main-file checkpoint allocation (ADR0040).
Each annotation batch commits atomically. A failed later batch can leave earlier
valid derived annotations; restart skips these by event reference. No source
event/raw payload, chain/head, disposition or rule identifier is rewritten and
backfill does not enforce any response. Complete admission failure remains visible.

Tests cover empty/unsupported scan batches, more than32 detections restored to
their exact original derived rows, repeated startup idempotence and source
integrity. A pinned8MiB fixture refuses the first batch without partial annotations;
after test-only reader release/checkpoint, all original annotations are restored.
The4MiB byte limit has a separate large-record regression.

This removes the known self-pinned scan and fixed-size annotation omission.
Transaction amplification is still an estimate; this is not proof of every WAL/
index peak, exclusion of independent writers or a basis for reducing reserves.
Retention/compression/direct-copy writers remain the next capacity work.
