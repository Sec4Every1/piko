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
