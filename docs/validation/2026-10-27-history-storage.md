# Observation history storage checkpoint

Base: e3109b7. This checkpoint adds observation_page and two typed query fields,
event.observed_at and process.parent_instance. Pages use descending observation
time plus canonical event UUID, with bound cursor parameters and a 129th row
sentinel for 128 displayed observations. A cursor is not an archive snapshot:
later arrivals and retention can change subsequent pages.

Only the observation_page hunk of event-storage/src/lib.rs is included; protected
storage, maintenance, recovery and all other local changes are excluded. The
complete query_language.rs delta and new observation_history integration tests
belong here. There is no lockfile/dependency, IPC, service or UI change.

Review also tightened individual stored-payload admission: SQLite checks row
length before copying into a Rust Vec, and an oversized row returns
QueryResultTooLarge before schema decoding. The aggregate page remains limited
to MAX_QUERY_BYTES and refuses rather than silently returning partial history.
This bounds application payload copies, not all SQLite engine memory/CPU.

Validation used an ignored archive of the base plus exactly those hunks/files,
with existing locked offline dependencies. It did not test the dirty checkout
as a substitute for the intended commit.

- cargo test --offline --locked -p piko-event-storage: 47 tests passed,
  including 6 new history cases; no failures.
- cargo clippy --offline --locked -p piko-event-storage --all-targets --
  -D warnings: passed.
- rustfmt --edition 2021 --check on the three changed Rust files: passed.
- New tests cover equal-time page continuity across 260 events, observation
  versus wall time, parent identity/unknown semantics, bound SQL-looking data,
  invalid query types/syntax, aggregate payload refusal and an oversized stored
  JSON row that bypasses append gates. All data and paths are synthetic.

Snapshot/logs: .build/consolidation-history-storage-20261027, storage-tests.log
and storage-clippy.log. No generated/runtime files are included. This is a local
source prerequisite, not end-to-end delivery, remote CI, installed qualification
or security enforcement. Host installation/protections remain untouched.
