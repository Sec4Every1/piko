# Localization parser remediation, 2026-10-29

## Included source

Candidate `.build/first-deps-parser-20261029` starts from `21ee3f6`, excluding
the dirty APP-03/browser work. It retains age 0.12.1 and all cryptographic source.
Root Cargo patches i18n-config 0.4.8 to the reviewed local copy described in
[ADR 0055](../adr/0055-build-time-localization-parser-backport.md) and
[vendor provenance](../../vendor/i18n-config/PIKO_PATCH.md).

Only basic-toml is removed; toml 1.1.6 and its parser support packages are added.
No existing registry package version/checksum is updated. The patched local
i18n-config loses its registry checksum deliberately. Desktop manifest/lock are
unchanged: contrary to the earlier broad assumption, that graph has no age or
i18n-config path. No Cargo advisory exception is added.

## Passed local checks

- Same seven parser tests passed against original basic-toml and patched toml:
  actual age config, CRLF, fluent/gettext defaults and paths, malformed/duplicate
  keys, wrong types/locales, missing/unreadable files and typed errors.
- Final candidate: `cargo test --offline --locked --workspace --all-targets`,
  **231 passed / 5 ignored**, including the seven parser regressions registered
  in piko-crypto. Real age localization macros compiled with the patched parser.
- Final candidate: offline locked workspace all-target Clippy with warnings denied.
- Changed test/fixture Rust formatting check, edition 2021.
- Copy-PikoThirdPartySources.ps1 executed successfully on PowerShell 5.1 and
  7.6.8 against separate ignored destinations. It retains the reviewed MPL
  sources and copies all ten parser source/test/license/provenance files with
  matching SHA-256 hashes. Generated lockfiles, binaries and build paths are
  outside that explicit inventory.
- Both locked Windows-target metadata graphs resolve. An OSV batch queried 355
  registry package/version pairs: basic-toml is absent. crypto-bigint's advisory
  remains. This is supplemental review, **not a cargo-deny pass**; no audit tool
  was installed and no manual CI dispatch occurred.

OSV also returned GHSA-qwgh-2vcv-g2f7 for block-buffer 0.10.4 with an overbroad
range. The [maintainer advisory](https://github.com/RustCrypto/utils/security/advisories/GHSA-qwgh-2vcv-g2f7)
specifies >=0.11.0,<0.12.1. Source inspection confirms 0.10.4 has a separate pos
field rather than the vulnerable inline cursor. No ignore or dependency change
was made for that mismatched feed result.

Final logs: `workspace-tests.log`, `workspace-clippy.log`, `parser-resolution.log`,
`package-sources.log`, `package-sources-ps5.log`, `osv-both-graphs.json` under the
candidate directory. Shared ignored Cargo target output was reused; source paths
in logs identify the final candidate. No installed data or runtime was used.

## Rejected alternative and retained reproduction

`.build/first-deps-20261029` contains a separate, **rejected** age 0.11.5 experiment.
The fixture source is scripts/tests/fixtures/evidence_compatibility.rs. Copy it
to crates/crypto/examples/evidence_compatibility.rs in isolated old/new snapshots
and run generate then reciprocal verify, with fresh destinations under .build.
It creates only synthetic keys/data; no fixture keys or ciphertexts are tracked.

Eight payload sizes (empty through 4 MiB) passed both directions between original
0.12.1 and candidate 0.11.5, including recovery code import, fake local envelope
wrapping, recovery proof, wrong key/archive, three tamper points and four
truncations. The wrapping provider is fake and does not test DPAPI. Logs are
compat-{baseline,candidate}-{generate,verify}.log in the experiment directory.

However, inspection of published age 0.11.5 src/x25519.rs found the explicit
sk_base32 zeroization TODO in Identity::to_string; 0.12.1's
src/native/x25519.rs uses the revised encoder. The downgrade is therefore not
included despite interoperability success. Its proc-macro-error2 replacement
experiment is also excluded. These experiments do not constitute remediation of
crypto-bigint or permission to weaken key handling.

## Remaining gate

RUSTSEC-2026-0387 remains unresolved; upstream requires crypto-bigint >=0.7.6,
outside the compatible range of the currently selected elliptic-curve/P-256.
Review compatible upstream remediation or obtain an explicit risk disposition.
Do not claim a green dependency audit, build a release around the rejected
downgrade, or install the candidate. Windows qualification remains separate.
