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
