# ADR 0041: refuse near-budget schema migration before writer startup

2026-10-21. Safe Rust, no new dependencies/privileges. Conservative policy gate;
not a worst-case bound or reserve redesign.

Previously startup changed journal/schema/metadata before sampling aggregate
usage. Startup now samples database/WAL/SHM before opening a writing connection
and refuses an already over-budget archive. For an existing nonempty archive,
read-only inspection validates the current host/schema version and checks the
static table/index set used by startup. If an object is missing, at least half
the configured budget must remain free before automatic migration. Complete
schemas do not acquire this extra migration headroom requirement.

Interrupted first initialization is handled separately: an existing empty
known Piko schema (at most32 objects, no unknown tables/views/triggers) may finish
bootstrap only if event/raw/detection tables contain no records and metadata
is empty or solely storage_version=1. No existing host, checkpoint, unknown
metadata or evidence is reidentified. Links/reparse points are refused. The
inspection opens no writer; SQLite can maintain transient SHM read marks.

Near-budget fixtures pin a real reader: complete-schema restart works; a missing
index refuses with main/WAL hashes unchanged; verified test-only checkpoint frees
space and startup migration then succeeds with the same integrity/head. An
over-budget file remains untouched without journal files. Initialization crash
fixtures resume; host-deleted archives with evidence, foreign objects and unknown
metadata remain refused unchanged.

The half-budget headroom gate is deliberately coarse and can refuse a migration
whose actual index would fit. It does not prove DDL temporary-file/WAL peaks,
provide maintenance UI, solve startup detection backfill amplification, exclude
external concurrent writers or bound retention/compression/copy paths. Large
backups/temp files need their own free-space policy. Keep ADR0038 limitations.
