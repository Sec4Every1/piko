# Validation

Validation evidence in this repository is limited to reproducible automated checks. Machine-specific logs, databases, screenshots, and installation records are intentionally excluded.

Run the checks locally from the repository root:

```powershell
cargo fmt --all -- --check
cargo test --workspace
cargo clippy --workspace --all-targets -- -D warnings
npm ci --prefix apps/desktop-ui
npm run check --prefix apps/desktop-ui
npm run build --prefix apps/desktop-ui
```

Windows service installation, ETW collection, Firewall changes, reboot behavior, load testing, and code signing require separate tests on suitable Windows systems. Results must be recorded with the OS version, exact command, and test scope; a passing unit test does not qualify production behavior.

## 2026-10-20: account lifecycle activity (ADR 0033)

Core/storage tests: four passed, including TargetSid attribution, unsupported
versions, filtering/pagination and archive integrity. Workspace fmt and Clippy
passed locally. Full workspace suite: 147 passed, two ignored. Frontend: 89 tests
passed, Svelte/TypeScript check clean, account activity Playwright scenario passed.
Release runtime and desktop builds passed. No real account changes are performed
by these tests. CI corrections preserve the wildcard dependency prohibition and
add explicit internal package versions; remote dependency audit is not rerun here.
Packaging instructions no longer embed the packager's Windows SID.

## 2026-10-20: pinned toolchain and installation qualification gate

Rust1.99.0/MSVC is pinned for local, CI and release builds. Desktop all-target
Clippy passed with this version. The first remote checkpoint ed11d96 passed core
lint and dependency policy but exposed two platform-dependent native test
assumptions and an invalid cargo-deny option position for the desktop audit.

Native tests now assert elevated-caller denial and explicit raw/decode-failure
fallback only for a confirmed absent TDH schema (OS1168). Start-v0 decoding stays
mandatory; Windows Server2022 cannot qualify Windows11-only event versions.
Targeted local tests: seven ETW and three process tests passed on a normal token;
elevated-denial branch remains to verify on the CI token. CI records passing-test
output to retain these coverage diagnostics. Production access guards are unchanged.

Test-PikoService.ps1 validates all installed executable hashes and an optional
expected package before any service lifecycle operation. Its -ReadOnly mode was
covered by nine benign mocked checks on both PowerShell7 and Windows PowerShell5.1.
On this machine it refused an installed service/manifest hash mismatch and left
the service running. The refreshed package differs from installed binaries;
upgrade/reboot/uninstall qualification remains incomplete. No live update occurred.

Desktop dependency audit now runs through its policy: five existing unchanged MPL
crates have documented exact-version review and release source bundles, verified
against Cargo.lock. Core advisory checks are unchanged; no vulnerability exception
was added. Vitest upgraded to5.0.5:89 tests, frontend check/build pass; npm audit
reports zero vulnerabilities. cargo-cyclonedx0.5.9 generated14 actual package-named
.cdx.json files; collector corrected to those names (not nonexistent bom.json).

Same-version refresh: ten full-script fixture scenarios passed on PowerShell7
and Windows PowerShell5.1, including source-stage tampering, initial stopped
state and rollback after start/IPC-version failure. No real update was applied.
Last remote Windows job for5acb14a succeeded (run39427136418); dependency fixes
and the updater require the next reviewed CI checkpoint.

Full scripts/ci-sbom.ps1 passed locally at 6b8293f: advisory, bans, licenses and
sources checks for both Rust graphs; 14 Rust SBOMs plus frontend SBOM; npm audit
zero vulnerabilities; no lockfile drift. Refreshed local release package contains
four manifest-verified executables, updater and five checksum-verified MPL source
archives. This packages existing compiled binaries; it does not update the live
installation. Remote run [39429554940](https://github.com/Sec4Every1/piko/actions/runs/39429554940)
for commit 6b8293f1ce81d1bf8aea590e4d7431e02d9f1951 completed successfully:
both Windows checks (tests/lint/desktop build/IPC smoke) and dependency audit passed.
DEV-01 is complete; this does not qualify the installed runtime or a signed release.

Read-only installation diagnosis found a historical protected service backup that
matches the installed manifest. None of the scanned backups or four available
local build/package candidates matches the current installed service executable.
This is consistent with a stale development manifest, but does not establish the
current executable's provenance. No binary/manifest was overwritten and no old
binary was run against current evidence.

## 2026-10-20: network batches and helper lifetime (ADR 0035)

Browser network suite: 22 scenarios passed, including three new bidirectional
batch/undo/partial-outcome cases; one additional plan-limit/partial-preparation
scenario passed separately. Bridge fixtures never modify real Firewall rules.
Frontend check/build passed. Targeted Rust: app-control 26 passed, one live
AppContainer test ignored; network helper lifecycle four passed, two subprocess
entrypoints ignored standalone but invoked by their parent tests. Tests cover
cross-process exclusion/release, abandonment/retry, original desktop exit and
creation-time mismatch, plus legacy payload rejection. Workspace tests passed:
151 passed, four ignored. Targeted Clippy and workspace formatting passed.

Runtime workspace and native desktop release builds passed. No dependency/lockfile
changes were introduced, so the prior audit was not needlessly rerun locally.
The new source checkpoint triggers the full remote pipeline separately; the prior
green run is not evidence for these changes. No real Firewall/installation change
was made. Packet blocking, OS restart and alternate-admin global-mutex access
remain qualification work, as does installed recovery from the manifest mismatch.

## 2026-10-20: original installation preserved for recovery

Backup-PikoInstallation.ps1 holds read handles for all six originals while copying
and checks each destination SHA-256. It preserves the original inconsistent
manifest, configuration and ACL metadata; it neither executes binaries nor copies
the event archive. Destination creation uses an explicit private ACL for caller,
SYSTEM and administrators. Reparse paths and untrusted writable destination
ancestors are refused. A completion report is written only after successful copies.
The backup does not establish source authenticity or implement restoration.

PowerShell7 and Windows PowerShell5.1 fixtures pass: WhatIf/no writes, six exact
copies with manifest mismatch retained, private ACL and existing-destination
refusal. A real six-file backup completed successfully in a private ProgramData
directory. Service state remained Running; no installed file was replaced and no
event archive was changed. Machine-specific copy metadata is intentionally excluded.

## 2026-10-21: recovery, trial network contract and effective capacity

Prior source e0b6217 is remotely green: Windows and dependency jobs passed in run
[39441703542](https://github.com/Sec4Every1/piko/actions/runs/39441703542).
New changes below need their own remote checkpoint; this prior run does not cover them.

Explicit recovery (ADR0036): 20 fixture scenarios pass on PowerShell7 and Windows
PowerShell5.1, including default refusal, read-only modes, strict replacement checks,
changed originals, offline archive backup/gate, both initial states, exact rollback,
known pre-existing quota warnings and rejection of newly introduced quota failures.
Native read-only archive verification/gate tests pass. The live UAC launch was
cancelled before execution; service and installed files remained unchanged. There
is no live recovery/rollback qualification. Archive status already showed a full
internal page limit; no quota/retention change or archive deletion was attempted.

AppContainer (ADR0037): three contract unit tests and seven browser scenarios pass.
An explicitly invoked benign native test created actual None and InternetClient
tokens, wrote readiness in its own profile, stopped/removed both trials and
confirmed original hashes. No network requests or global policy changes. This
qualifies token creation/cleanup on the development Windows host, not outbound
connectivity or a broad Windows matrix. Evidence: ignored .build/ logs.

Capacity reporting (ADR0038): storage fixture confirms a controlled effective cap
change is observed and event integrity stays valid. API/restricted contract tests:
24 passed; archive browser scenarios: two passed. Reserve/admission policy unchanged.
Full Rust workspace: 156 passed, five ignored (including the separately executed
native token fixture and child harness fixtures invoked by parent tests).
Targeted changed-crate Clippy and formatting passed; frontend check passed.
Runtime and native desktop release builds passed. Native token qualification ran
on Windows 10.0.26200.0. The local package is rebuilt and hash-checked separately;
none of these build results establishes live installed recovery.
