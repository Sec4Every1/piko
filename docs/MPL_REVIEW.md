# Review: existing MPL dependencies

2026-10-20. Scope: five unchanged crates in the locked Tauri dependency graph,
not a relicensing of Piko. Piko's own source remains MIT. This is a scoped
distribution decision; other MPL crates/versions still fail the dependency gate.

| Crate | Reviewed version | Dependency path |
|---|---|---|
| cssparser | 0.37.0 | Tauri utils / dom_query |
| cssparser-macros | 0.7.1 | cssparser |
| dtoa-short | 0.3.5 | cssparser |
| option-ext | 0.2.0 | dirs-sys / dirs / Tauri |
| selectors | 0.38.0 | dom_query / Tauri utils |

The review checked registry license declarations and upstream source/license
files. These crates are consumed unchanged; their files are not copied into MIT
application source. Mozilla's FAQ Q8/Q11 describes distributing unchanged MPL
components in a larger work while preserving source availability and MPL rights:
https://www.mozilla.org/en-US/MPL/2.0/FAQ/

The release package includes THIRD_PARTY_MPL.md, the MPL license text, and the five
original source archives. Packaging verifies each archive against Cargo.lock's
SHA-256 before copying it; no local registry paths or account details are recorded
in the notices. Existing upstream copyright and license notices remain in those
archives. Build and runtime dependencies are both covered conservatively.

deny.toml grants exact-version exceptions only. Every change of these versions,
new MPL dependency or vendor patch needs a new review and matching source bundle.
This does not claim a full inventory of every third-party license; full SBOM and
dependency checks remain release requirements. No advisory, wildcard, unknown
source or license-confidence gate is disabled.
