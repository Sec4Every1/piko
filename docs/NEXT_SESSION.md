# Piko: resume checkpoint

Updated: 2026-10-21. Read AGENTS.md and WORK_QUEUE.md; check git status first.

## Delivered source and verification
- Published 706abfa: explicit inconsistent-install recovery (ADR0036), frozen
  AppContainer None/InternetClient contract (ADR0037), effective archive capacity
  reporting (ADR0038). CI run39558256349 Windows passed; dependency audit failed on Vite7.3.6.
  Previous e0b6217 / run39441703542 passed both jobs.
- Local checkpoint e8e2912: STORE-02 pinned-reader regression/writer audit and
  GRAPH-01 one-hop Windows-reported parent lifetime (ADR0039). Complete same
  snapshot, exact creation ordering, PID reuse/partial/unknown checks; historic
  compact UI and event/raw refs. No initiating-actor causal claim.
- Sensor/core/storage suites 61 passed; service 11 passed including normalized
  record -> SQLite worker -> GetInvestigation -> IPC JSON. Clippy/fmt clean;
  frontend check, 3 contract tests, 4 affected browser scenarios and UI build pass.
  Runtime and desktop release rebuilds passed. Package refresh follows checkpoint.
- No new native boundary, dependency or privilege. Source evidence in VALIDATION.

Vite patched to7.3.7: npm audit zero vulnerabilities; check,92 unit,67 browser and build passed. Patch checkpoint remote validation pending.

## Live installation / limitations
- Recovery UAC was CANCELLED before helper execution. No live replacement,
  stop/restart or recovery archive copy. Do not reopen without renewed direction.
- Installed service remains running with binary/manifest mismatch. Earlier private
  original-file copy remains in ProgramData/piko-recovery-*/originals.
- Last trusted CLI health: 273668 events, dropped 0, SQLite FULL, effective DB
  1 GiB; aggregate ~1.0005 GiB; budget 2 GiB; retention 12 months.
- Live recovery/reboot/rollback, outbound AppContainer connectivity and persistent
  installed-app file/system/update mediation remain unqualified/unsupported.

## Next action
- STORE-02: account for uncheckpointed main-file growth in append admission;
  attempt checkpoint/retry only when its projected DB/WAL aggregate fits budget.
  Test pinned-reader refusal then release/recovery without losing records.
- Startup migration admission, retention/compression/direct annotations still lack
  complete capacity bounds. Keep half reserve and user budget; never discard
  unexpired evidence. Current empirical regression is not a worst-case proof.
- Publish reviewed checkpoints once for full CI, continue independent work;
  inspect matching run before claiming remote verification. Avoid cancelling
  expensive in-progress CI with repeated small pushes.

Constraints: MIT, no personal identifiers/runtime artifacts in tracked source;
minimal grouped UI, progressive details/raw. Retain 12 months within 2 GiB and
suspend on capacity. Replace this checkpoint at the next milestone.
