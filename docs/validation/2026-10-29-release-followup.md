# First-release follow-up, 2026-10-29

## Published Tokio correction

Commit `dba078b` was pushed to `development/first-release` after confirming
the remote still pointed to `ce18649`. The eight manifest/lock files are
byte-identical to the previously tested `.build/first-checks-tokio-20261027`
snapshot. Its retained logs confirm completed workspace tests, all-target
Clippy and desktop compiler checks; these checks were not repeated.
The reviewed commit also includes the four-executable CI artifact/hash inventory
and its existing validation record. No deferred APP-03 source was staged.

## Remaining dependency paths

Live upstream review confirms that feature selection cannot remove either
remaining finding: Piko already uses `default-features = false`, while age
0.12.1 requires HPKE/P-256 and localization unconditionally.

- [Published age source](https://docs.rs/crate/age/0.12.1/source/Cargo.toml):
  P-256/elliptic-curve requires crypto-bigint 0.5; the advisory requires
  [0.7.6 or newer](https://rustsec.org/advisories/RUSTSEC-2026-0387.html).
  A lockfile substitution across those incompatible APIs is not remediation.
- [Published i18n-config](https://docs.rs/crate/i18n-config/0.4.8/source/Cargo.toml)
  still depends on basic-toml. Its
  [advisory](https://rustsec.org/advisories/RUSTSEC-2026-0374.html) has no patched
  version. [Upstream master](https://github.com/kellpossible/cargo-i18n/blob/master/i18n-config/Cargo.toml)
  replaces it with toml, but this is not an established published compatible fix.
- [Upstream age main](https://github.com/str4d/rage/blob/main/age/Cargo.toml)
  is migrating a broad cryptographic stack and still uses localization. Adopting
  main does not establish that both findings are fixed.

Possible further investigation: review an older age X25519-only dependency graph
and a minimal upstream localization parser substitution in an isolated snapshot.
Neither is an accepted remediation here. Any backlevel needs a full advisory
review and bidirectional archive/key compatibility fixtures; a parser patch needs
API/error/format and supply-chain review. No downgrade, vendored patch, advisory
exception or archive format change was made. FIRST-DEPS remains open.

## Complete browser rerun

All tracked frontend files outside src-tauri in
`.build/first-checks-frontend-20261027` were compared with HEAD using Git blob
hashes (including normal line-ending normalization); no differences were found.
This excludes the dirty checkout's deferred APP-03 changes.

`CI=1 npm.cmd run test:ui` from that snapshot's `apps/desktop-ui` passed all
70 Chromium scenarios in 26.2 seconds. Existing dependencies/browser were reused;
no installation occurred. The first sandbox attempt could not start esbuild;
the permitted rerun outside the sandbox passed the complete suite. Log:
`.build/first-checks-frontend-20261027/frontend-browser-complete-20261029.log`.
Bridge replies are synthetic: this closes the incomplete full browser rerun,
not installed response, collection, encryption or Windows qualification.

No installed runtime/protection changes, manual CI dispatch, main merge or
release publication occurred. Automatic CI from a development push is separate
from local validation and remains unverified here.
