# ADR 0055: reviewed build-time localization parser backport

Date: 2026-10-29. Status: accepted for source; release audit remains blocked.

## Problem and decision

age 0.12.1 requires i18n-config 0.4.8 through its localization build macros.
That crate uses unmaintained basic-toml (RUSTSEC-2026-0374), with no compatible
published correction found. Disabling age's default features does not remove it.

Retain age 0.12.1 and the existing X25519 evidence/key format. Apply a local
source patch to **i18n-config only**, backporting upstream's toml parser change.
The root Cargo patch is explicit; the separate desktop graph has neither age
nor i18n-config and needs no patch or lockfile change. No advisory ignore is added.

The backport replaces basic-toml with toml 1.1.6 using std/serde/parse, two parse
calls and the parser error payload. Existing public variant names are preserved.
The error payload type is technically an API change; the actual macro consumers
compile and format it without depending on basic-toml's concrete type. Tests
cover configuration values and error classification, not identical diagnostics.
The root lock adds the TOML parser's support packages without unrelated upgrades.
This is build-time metadata handling, with no new privilege, FFI or runtime
evidence algorithm. Existing Rust tools and cached parser dependencies suffice.

Provenance, license, ownership and removal conditions live in
../../vendor/i18n-config/PIKO_PATCH.md. Package source copying verifies the local
dependency identity and includes an explicit source/test/license inventory. The
patched package has no unchanged registry archive checksum. Normal workspace
tests include its seven parser regressions via piko-crypto's test-only dependency.

## Rejected age backlevel

An isolated age 0.11.5 graph removes crypto-bigint and passes bidirectional
archive/key compatibility checks with 0.12.1, including authenticated recovery,
tampering, truncation and payloads through 4 MiB. It nevertheless changes secret
handling: 0.11.5's x25519 Identity::to_string creates a sk_base32 vector which
the source explicitly says is not zeroized. The 0.12.1 encoder avoids that vector.
Passing format tests does not justify reintroducing that residual-memory issue.
Do not adopt the downgrade or its additional localization macro backport.

No cryptographic fork or dependency-major substitution is made. crypto-bigint
0.5.5 through HPKE/P-256 remains a release blocker (RUSTSEC-2026-0387). Piko's
X25519 selection is not, by itself, a complete exploitability/risk disposition.
Closure requires compatible reviewed upstream changes or an explicitly approved
risk decision; the parser change alone cannot make the release audit green.

## Evidence and limits

See ../validation/2026-10-29-localization-parser.md. Local parser, workspace,
Clippy and source-distribution checks do not qualify Windows installation,
DPAPI recovery, active protection or the full release package.
