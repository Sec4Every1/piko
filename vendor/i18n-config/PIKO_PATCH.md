# Piko build-time parser backport

This is a local patched copy of **i18n-config 0.4.8**, not a new upstream release.
Piko maintainers own this patch until a compatible maintained release replaces it.
MIT copyright/license is retained in LICENSE.txt.

Published source provenance: cargo-i18n commit
`ae88dc79fda061e1bbf96b8d8e8fe8d23f1e52e7`, directory `i18n-config`.
The normalized manifest and source originate from the crates.io 0.4.8 archive.
Original archive SHA-256:
`3e06b90c8a0d252e203c94344b21e35a30f3a3a85dc7db5af8f8df9f3e0c63ef`.
Registry packaging metadata, generated lockfiles and build artifacts are omitted.

Upstream parser replacement:
https://github.com/kellpossible/cargo-i18n/commit/2ce7b1dfe9a8cc224288bf50cbc2a67a6de863c4

Only these functional changes are backported:

- Replace unmaintained basic-toml with toml =1.1.6, using std/serde/parse features.
- Replace two basic_toml::from_str calls with toml::from_str.
- Change CannotDeserializeToml's payload to toml::de::Error.

The last change is technically a public Rust API change. Piko's actual consumers
format errors and do not match or construct that payload. Error variant names,
configuration fields and paths remain unchanged; parser diagnostics and accepted
TOML syntax need not be byte-identical. No broad upstream edition/thiserror/API
modernization is included. This parser handles build-time localization metadata,
not evidence, keys or encrypted archives. No cryptographic source is patched.

The standalone workspace declaration isolates the vendored package from automatic
workspace membership. Seven parser regression tests are also registered as a
piko-crypto integration target so normal locked workspace tests run them. The
age i18n.toml fixture is copied from age 0.12.1 (MIT OR Apache-2.0).

Source distribution: scripts/Copy-PikoThirdPartySources.ps1 copies this patched
source, tests, provenance and MIT notice to third-party-sources/i18n-config-0.4.8-piko.
Cargo metadata/SBOM reports the local path package; it must not be represented as
the unchanged registry archive or assigned that archive's checksum.

Removal condition: a published compatible i18n-config release removes basic-toml
and passes the parser/macro consumer checks. Then remove the root Cargo patch,
vendor directory, associated test target and source-copy entry together.
