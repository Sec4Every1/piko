# First-release CI security triage, 2026-10-27

Read-only inspection of automatic [run 40526941564](https://github.com/Sec4Every1/piko/actions/runs/40526941564)
for ce18649 confirmed a failed dependency job. The Windows job was still running
at inspection. No workflow was manually dispatched. Logs remain in ignored
`.build/first-checks-ci-20261027`; credentials and downloaded logs are not source.

The root audit reported three advisories; licenses, bans and sources passed for
that root audit. Later desktop/npm/SBOM steps were not thereby qualified:

- [RUSTSEC-2026-0386](https://rustsec.org/advisories/RUSTSEC-2026-0386.html):
  Tokio's Unix AsyncFd constructors violate I/O safety. Both locked graphs had
  Tokio 1.53.2. Windows uses a different I/O boundary; this is not evidence of a
  reproduced Windows exploit. Apply the supported patch rather than suppressing
  the audit finding.
- [RUSTSEC-2026-0387](https://rustsec.org/advisories/RUSTSEC-2026-0387.html):
  crypto-bigint 0.5.5 via elliptic-curve/p256/hpke/age is below patched 0.7.6.
  An incompatible major dependency cannot be replaced by editing a lock entry.
  Piko selects X25519; no claim of exploitability or non-exploitability follows
  from that fact alone. Compatibility and actual call-path review remain open.
- [RUSTSEC-2026-0374](https://rustsec.org/advisories/RUSTSEC-2026-0374.html):
  basic-toml 0.1.10 via i18n-config and age's localization macros is unmaintained,
  with no patched version. It is a build-time dependency in this observed chain.

Official registry metadata and upstream age manifest were inspected: stable age
remains 0.12.1 and i18n-config 0.4.8. No stable compatible correction for both age
findings was established. Do not silently replace the cryptographic format,
vendor custom cryptographic fixes or add advisory ignores to make CI green.
The audit/release gate remains blocked on a reviewed resolution of those findings.

## Minimal Tokio correction

Exact-source snapshot: `.build/first-checks-tokio-20261027`, archived ce18649,
excluding all dirty APP-03 source. Six existing direct Tokio requirements now
start at 1.53.3; both lockfiles select exactly 1.53.3. Review confirmed that the
only locked package version/checksum change is Tokio 1.53.2 -> 1.53.3, with no
added/removed package. This is remediation of a concrete advisory, not generic
dependency churn to enable checks. The existing Cargo tool fetched that patch;
no tools were installed/updated. No new FFI, privilege or dependency was added.

Passed against that snapshot:

- Locked workspace tests: 224 passed, 5 ignored.
- Offline locked workspace all-target Clippy with warnings denied.
- Offline locked desktop/Tauri all-target compiler check; matching previously
  checked frontend assets were reused, not rebuilt.
- Staged scope/format checks and exact-source blob comparisons.

Logs: `workspace-tests.log`, `workspace-clippy.log`, `desktop-check.log`.
This does not establish a new cargo-deny success: its two age-chain findings
remain open, and no local audit tool was installed. No installed runtime changed.
The earlier debug preview predates this patch and must not be called the current
candidate without rebuilding and checking matching binaries.

## CI artifact completeness

CI now retains and hashes piko-network-helper.exe alongside the other three
executables, matching the package's four-executable inventory. PowerShell parser
and CiPreflight fixtures passed on PS5.1 and PS7.6.8. A local inventory comparison
confirmed all four names occur once in package, hash list and workflow artifact
list. Remote upload/hash generation for this change remains unverified.
