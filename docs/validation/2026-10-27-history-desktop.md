# Observation history desktop integration checkpoint

Base: c0e4141. Completes the source path from storage/service/IPC through Tauri
to the investigation UI. Adds the native observation-window/cursor arguments,
bounded parent/child navigation, observation timeline filters/details and
explicit archive-page continuation. The UI validates response shape, process
attribution, ordering, UTF-8 label budget and cursor progress. Older services
without paging produce an unavailable result rather than a fabricated history.

Included: the get_investigation function hunk in native main.rs,
Investigation.svelte, ObservationTimeline.svelte, investigation.ts, queries.ts,
investigationHistory.test.ts and observations.spec.ts. No evidence-key,
maintenance, APP-03, manifest, dependency or lockfile changes are included.
desktop.spec.ts and unrelated APIs remain at the base version.

Checks ran on an ignored archive of c0e4141 plus only the selected files/hunk.
Existing frontend dependencies were linked into the snapshot; nothing was
installed or updated. Local generated dist and logs remain ignored.

- npm run check: Svelte/TypeScript passed with zero errors or warnings.
  The initial sandboxed attempt could not read a compiler parent directory;
  rerunning with the required filesystem access passed.
- npm test -- src/lib/investigation.test.ts
  src/lib/investigationHistory.test.ts src/lib/queries.test.ts: 11 tests passed.
- npm run build: production frontend build passed.
- CI=1 npm run test:ui -- observations.spec.ts: 8 Chromium scenarios passed;
  a dedicated local server and synthetic bridge replies were used. Timeline
  expansion, actual observation name, attribution disclaimer and empty filtered
  sample are covered in the relationship scenario.
- cargo check --offline --locked on snapshot src-tauri/Cargo.toml: passed,
  reusing existing build artifacts without changing dependencies.
- rustfmt --edition 2021 --check on the extracted changed native function:
  passed; no whole-native or whole-workspace formatting claim.

Snapshot/logs: .build/consolidation-history-desktop-20261027,
desktop-check.log, desktop-tests.log, desktop-build.log, desktop-playwright.log
and desktop-tauri.log. This proves source integration and local mocked-browser
behavior, not a running installed service-to-desktop session or Windows release
qualification. No host installation/protection changes or manual CI dispatch.
