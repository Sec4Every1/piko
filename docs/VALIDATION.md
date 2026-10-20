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
