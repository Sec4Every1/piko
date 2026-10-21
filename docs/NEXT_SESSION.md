# Piko: resume checkpoint

Updated: 2026-10-21. Read AGENTS.md and WORK_QUEUE.md; check git status first.

## Delivered / verification
- Public 526f185 includes recovery ADR0036, trial network contract ADR0037,
  capacity telemetry ADR0038, parent lifetime view ADR0039 and Vite7.3.7 fix.
  Run39560604506: dependencies passed; Windows still in progress when inspected.
  Prior706abfa Windows passed, audit failed on Vite7.3.6 (now patched).
- Local e0b68e6: append reserves pending main allocation; small released-reader
  WAL recovery, zero busy wait/restored timeout,16MiB input gate (ADR0040).
- New local migration slice: pre-writer aggregate/headroom gate; missing indexes
  refuse near budget without DB/WAL mutation. Empty interrupted initialization
  resumes; unknown objects/metadata or existing evidence never reidentified
  (ADR0041). git log identifies the completed checkpoint.
- Workspace with initial migration tests164 passed/5 ignored, Clippy clean;
  after bootstrap correction, affected storage/service48 passed, Clippy/fmt clean.
  Frontend check,92 unit,67 browser tests,build passed on Vite7.3.7; audit zero.
  Final runtime/desktop release builds passed; package refresh follows checkpoint.
- Existing local recovery fixtures20 each PS5.1/7; actual benign AppContainer token
  modes/cleanup passed without network IO. Native trial is not outbound qualification.

## Live installation / limits
- Recovery UAC CANCELLED before helper execution. No live replacement, stop/restart
  or recovery archive copy. Do not reopen without renewed user direction.
- Installed service remains running with binary/manifest mismatch. Earlier private
  originals backup remains ProgramData/piko-recovery-*/originals.
- Last trusted health:273668 events,dropped0,SQLite FULL,DBlimit1GiB,aggregate~1GiB,
  budget2GiB,retention12months. Small-WAL recovery cannot fix the DB page cap.
- Persistent installed-app file/system/update mediation, live deployment/reboot/
  rollback and outbound trial packet tests remain unqualified/unsupported.

## Exact next action
- STORE-02: bound startup detection backfill. Current startup keeps a SELECT open
  while inserting annotations. Use bounded position/keyset batches, release reader
  before writes, include serialized annotation bytes in admission, test idempotent
  replay, unsupported records, near-budget atomic refusal and unchanged evidence.
  Then retention/compression/direct-copy admission and checkpoint peak proofs.
- No reserve reduction or budget increase. Existing estimates/coarse migration gate
  are not formal worst-case bounds. Preserve unexpired evidence and unknowns.
- Storage checkpoints remain local while public526f185 full CI runs; do not cancel
  that expensive run with repeated small pushes. Publish reviewed code once when
  appropriate and record exact matching CI; avoid idle polling/cold build repeats.

Constraints:MIT,no personal identifiers/runtime artifacts in tracked source;
compact grouped UI with progressive details/raw;12months within2GiB,stop on full.
Replace this checkpoint at the next milestone.
