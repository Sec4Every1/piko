# Recovery entry points and first-delivery preview

Base: 5f60108. Consolidates the UI-named key restore/activation-resume wrappers,
interactive routing, updater/resume pair, fresh installation/profile policy and
launcher availability. Package inventory supplies the wrapper dependencies.
README, installation guide, first-release scope and the relevant manual sections
match delivered history/maintenance/key source. APP-03 manual/source changes
remain excluded; its experiments are preserved locally.

New installations/profiles default to 2048 MiB and 12 calendar months. Existing
configurations remain byte-exact. Installed stopped collection still opens the
installed non-elevated UI and never creates a console fallback. A failing local
collector also leaves its disconnected dashboard reachable. Recovery modes are
mutually exclusive and cannot silently become fresh installation/update.

## Exact-source local evidence

An archived baseline plus selected scripts/docs was checked; all runtime code
in the candidate is the committed source, without local APP-03 additions.

- Extended updater fixtures passed on PowerShell 5.1 and 7.6.8, including new
  interactive restore/resume, helper refusal/launch failure, missing-service,
  all six conflicting-mode pairs and explicit/pending-marker update resume.
  Service/process/ACL/account boundaries are doubled. The fixture SID is
  synthetic; tests do not depend on an installed service account.
- Seven launcher/default cases passed on both PowerShell versions: installed
  running/stopped UI, missing UI and elevation refusal, fresh per-user defaults,
  exact custom-configuration preservation and actual installer ParamBlock defaults.
- Four production recovery-metadata function cases passed on both versions:
  exact field/type contracts, oversize refusal without mutation and handle release
  after malformed JSON. ACL is doubled; top-level key recovery never executes.
- These checks reproduced a PowerShell 7 parse failure in the restore script's
  typographic apostrophe inside a single-quoted diagnostic. It was replaced
  with an ASCII apostrophe in a correctly quoted string; both parsers pass.
- Four unsigned debug executables built offline/locked from the same snapshot:
  service, CLI, helper and actual desktop. Unchanged validated frontend assets
  from the key-desktop snapshot were used by the native desktop build.
- Actual package assembly with Profile debug succeeded at a fresh ignored
  preview destination. All four binary SHA-256 entries match; required recovery
  entry points, scope and source-license archives are present. Targeted package
  text scanning found no local-user/secret pattern. Existing and out-of-scope
  explicit destinations refuse without overwriting/creating output.

Snapshot/logs: .build/consolidation-recovery-package-20261027;
update-fixtures-ps5/ps7.log, start-fixtures-ps5/ps7.log,
metadata-fixtures-ps5/ps7.log, package-backend-build.log,
package-desktop-build.log, package-preview.log and package-refusal-*.log.
preview-path.txt records the local generated preview, which is not tracked or
published. The updater's fixture-only target/release probe is a copy of the
already-built debug service for its read-only capability query, not release-build
evidence. No actual installation/UAC/SCM update/key restore/activation or Event
Log persistence qualification occurred. Debug preview is not a release, signing
proof, binary privacy qualification or authorization to change the host runtime.
