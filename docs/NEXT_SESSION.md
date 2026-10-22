# Piko: resume checkpoint

Updated:2026-10-22. Read AGENTS.md and WORK_QUEUE.md; check git status first.

## Delivered and evidence
- Public526f185: recovery ADR0036, frozen trial network contract ADR0037, measured
  archive capacity ADR0038, observed parent lifetimes ADR0039, Vite7.3.7 patch.
  Run39560604506 completed: both Windows and dependencies passed.
- Reviewed storage group published as3b0653f: run39562792228 completed successfully,
  verified2026-10-22. e0b68e6 reserves pending main-file allocation and reclaims
  small released-reader WALs with zero busy wait/restored timeout (ADR0040).
  73de1fa gates startup migration before writer/DDL, preserving safe interrupted
  empty bootstrap and refusing unknown/nonempty archives (ADR0041).
- Latest storage slice:32-row/4MiB keyset detection backfill closes SELECT before
  admitted atomic annotation batches, includes derived bytes and advances through
  unsupported candidates (ADR0042), code851ef6c. Exact publication commit is in git log.
- Final Rust workspace169 passed/5 ignored; workspace Clippy/fmt passed. Frontend
  check,92 unit,67 browser,build passed on Vite7.3.7; npm audit zero vulnerabilities.
  New backfill tests preserve exact annotations/count/head, cover byte/row splits,
  idempotence and pinned-reader quota refusal/recovery. Runtime and desktop release
  rebuilds passed; package refresh and4 executable hashes verified at completion.
- Local recovery fixtures20 each PS5.1/7; native benign AppContainer modes/cleanup
  passed without network IO. No outbound connectivity or live install qualification.

## Live installation and limits
- Recovery UAC CANCELLED before helper execution. No live replacement, stop/restart
  or recovery archive copy. Do not reopen without renewed user direction.
- Installed service remains running with binary/manifest mismatch. Earlier private
  originals backup remains ProgramData/piko-recovery-*/originals.
- Last trusted health:273668 events,dropped0,SQLite FULL,DBlimit1GiB,aggregate~1GiB,
  budget2GiB,retention12months. Small-WAL recovery cannot fix the DB page cap.
- Persistent installed-app file/system/update mediation, live deployment/reboot/
  rollback and outbound trial packet tests remain unqualified/unsupported.

## Exact next action
- Latest local source: compression now reserves pending checkpoint allocation and
  estimated WAL/index growth before rewriting any selected legacy evidence.
  No-op scans remain permitted. Storage suite and targeted atomic refusal test
  passed; Clippy clean. Not rebuilt/installed; estimate is not a worst-case proof.
- Retention admission now includes pending main allocation, verified event/raw
  bytes, deleted annotation bytes and serialized checkpoint metadata before DELETE.
  Real pinned8/32MiB fixtures preserve all records/checkpoint on refusal; no-op
  expiry remains allowed. Storage41 tests and Clippy passed; worker test recorded
  in .build/retention-worker-test.txt. Source only, not rebuilt or installed.
- Direct-copy admission now covers annotations/provenance; annotation text/payload
  reads are bounded, final checkpoint completion and aggregate usage checked.
  Oversized annotations refuse without altering source evidence. Storage suite,
  final affected noise test and Clippy pass; source not rebuilt/installed.
- Next: maintenance retry/peak regression tests and conservative bound review for
  all writers, then installed runtime qualification. Do not reduce reserve/quota.
- STORE-02: design admission for retention and compression, then direct-copy
  annotations/provenance. Cover main/WAL coexistence, pinned readers and rollback
  without losing evidence; bounded implementation/tests before reserve changes.
- No reserve reduction or budget increase. Existing transaction estimates and
  coarse migration gate are not formal worst-case proofs. Preserve unexpired
  evidence. Detailed audit and limits in ADR0038,0040-0042 and VALIDATION.
- Storage group was published after526f185 CI passed, without cancelling its run.
  Its matching CI39562792228 also passed. Later changes need their own verification.
  Continue independent ready work rather than idle polling or repeating passed builds.

Constraints:MIT,no personal identifiers/runtime artifacts in tracked source;
compact grouped UI with details/raw;12months within2GiB,stop on full.
Replace this checkpoint at the next milestone.
