# Recoverable-key core and existing dependency graph

Base: bbc1fe0. Consolidates the existing safe-Rust piko-crypto crate: bounded
age-X25519 evidence envelopes bound to an archive UUID, expected-recipient
recovery, local key wrapping through an injected KeyProtector, proof-before-
rebind checks and redacted secret Debug output. No Windows adapter, key-file
persistence, IPC disclosure/consent, activation or installed protection belongs
to this checkpoint. It does not make encryption active or qualified.

## Dependency boundary

This checkpoint includes the already-present root workspace/consumer manifest
changes and both existing lockfiles unchanged. No resolver was run to produce
a smaller graph, and no dependency or tool was downloaded/updated here.
The consumer edges prepare the subsequent key/IPC/platform/helper integration;
IPC/service app-control edges also prepare deferred APP-03, without importing
its uncommitted source or enabling any behavior.

The inherited root lock is not a minimal crypto-only delta: it grows from 132
to 222 package entries and changes existing versions, including tokio 1.49.0
to 1.53.2, serde 1.0.228 to 1.0.229, serde_json 1.0.149 to 1.0.151 and uuid
1.21.0 to 1.27.0. age is pinned exactly to 0.12.1 in the existing manifest.
The broad inherited graph was therefore checked across the entire workspace.
The separate desktop lock adds zeroize 1.9.1 and the declared dependency edges,
with no existing package version upgrades. These local checks are not a security
advisory, licensing or release qualification of the dependency graph.

## Exact-source checks

Validation used an archived bbc1fe0 plus crypto source/tests, root workspace and
existing changed consumer manifests, and both existing locks. Other provider,
key workflow and APP-03 source remained at the committed baseline.

- cargo test --offline --locked --workspace --all-targets: 205 tests passed,
  5 ignored, zero failed. The first sandboxed attempt could not access fixture
  files; rerunning with filesystem access passed without changing source/locks.
- Eight new crypto tests exercise real age operations with a deliberately fake
  local KeyProtector: archive/key binding, tampered/truncated ciphertext,
  expected-recipient recovery, wrap bounds/domain/version/provider failure,
  proof failure before wrapping, successful rebind and Debug redaction.
- Workspace all-target Clippy with -D warnings passed. The final crypto test
  file was rerun after replacing a test error unwrap with an explicit error.
- Targeted rustfmt --edition 2021 --check on crypto source/tests passed.
- Offline locked Tauri cargo check passed against its separate copied lock;
  unchanged frontend assets from the prior validated snapshot were reused.
- Both lockfiles remain byte-identical to the pre-existing working copies.

Snapshot/logs: .build/consolidation-crypto-20261027, workspace-tests.log,
workspace-clippy.log, crypto-tests.log, desktop-tauri.log and lock-report.json.
The generated lock inventory and build outputs remain ignored. Test keys are
ephemeral and not printed. The fake wrapper does not qualify DPAPI or Windows
identity/recovery behavior. No installed runtime/protection changes, release,
main merge or manual remote CI dispatch occurred.
