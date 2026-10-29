# Parser CI follow-up (2026-10-29)

Automatic run [40787796606](https://github.com/Sec4Every1/piko/actions/runs/40787796606)
used exact commit 0b4a64cdf8316f5cb047d13da3afa549b9f91418. Both jobs completed
with failure. Logs retrieved read-only; no manual dispatch.

Windows passed workspace formatting, release compilation, script fixture checks
and Clippy before stopping at localization_parser: six passed, one failed.
actual_age_macro_configuration_and_crlf replaced every LF with CRLF even when
include_str already contained checkout CRLF. The resulting CRCRLF was correctly
rejected by toml. Git core.autocrlf is true locally; earlier isolated archive
validation used LF and did not expose this test construction defect.

The test-only correction first normalizes CRLF to LF and tests the original,
explicit LF and explicit CRLF forms. Parser and cryptographic source are unchanged.
A separate ignored snapshot has the corrected test and a CRLF embedded fixture.

## Current local checks

MSVC tools remain unavailable: vswhere has no active installation, although stale
instance records exist. No tools were installed. An existing independent Windows
GNU toolchain and MinGW compiler allowed targeted verification without changing
the source graph or locks: rustc 1.93.1, stable-x86_64-pc-windows-gnu.

On the isolated prior candidate (production Rust sources/manifests/lockfiles
matched HEAD; only the corrected test differs):

- Before correction, with the embedded fixture converted to CRLF: reproduced
  the CI failure, six tests passed and actual_age_macro_configuration_and_crlf
  failed on CRCRLF.
- Corrected test with embedded CRLF: all seven passed.
- Corrected test with embedded LF: all seven passed.
- Offline locked Clippy for piko-crypto --test localization_parser with warnings
  denied: passed on the GNU toolchain.
- rustfmt --edition 2021 --check for the test: passed.
- git diff --check: passed.
- Source-copy script on PowerShell 5.1 and 7.6.8: passed against separate ignored
  destinations; its explicit inventory verifies SHA-256 equality, including the
  modified test. Both copies used the tested isolated source.

Commands use --offline --locked --manifest-path
.build/first-deps-parser-20261029/Cargo.toml -p piko-crypto --test
localization_parser. CARGO_TARGET_DIR points at the ignored follow-up target-gnu;
MinGW bin was prepended only inside the check process. No global environment,
installed runtime or dependency files were changed.

Logs: .build/ci-followup-20261029/{windows,dependencies,reproduce}.log and
parser-gnu-{before,crlf,lf,clippy}.log plus source-copy-ps{5,7}.log.
The earlier MSVC attempt remains blocked; GNU targeted success is not a full
workspace/MSVC CI pass. No service, real evidence or protection changes.

## Dependency result and upstream review

Dependency CI reports RUSTSEC-2026-0387; basic-toml is absent. The job stops at
its root audit, so this is not completion of both graphs, npm audit or SBOMs.
Live registry metadata still selects age 0.12.1 -> hpke ^0.12 / p256 ^0.13 ->
elliptic-curve ^0.13.1 -> crypto-bigint ^0.5. Disabling age default features
cannot remove mandatory HPKE/P-256 dependencies.

A fixed stable downstream chain exists (hpke 0.15.1, p256 0.14.0,
elliptic-curve 0.14.3, crypto-bigint 0.7.10), but published age excludes it.
crypto-bigint 0.7.6 through 0.7.8 are yanked; 0.7.9/0.7.10 are not.
Sources: [age](https://docs.rs/crate/age/0.12.1),
[HPKE](https://docs.rs/crate/hpke/0.15.1),
[P-256](https://docs.rs/crate/p256/0.14.0),
[elliptic-curve](https://docs.rs/crate/elliptic-curve/0.14.3),
[advisory](https://rustsec.org/advisories/RUSTSEC-2026-0387.html).
Upstream [rage PR 649](https://github.com/str4d/rage/pull/649) and
[PR 648](https://github.com/str4d/rage/pull/648) are open/unmerged at inspection.
An unreleased revision would need its own source and compatibility review;
no compatible lock-only update, advisory ignore or risk acceptance is established.

Next: publish the reviewed test correction and inspect its automatic MSVC CI.
Preserve the dependency release block; a full green CI or package qualification
is not implied by these targeted checks.
