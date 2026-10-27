# Observed history core checkpoint

This checkpoint adds bounded observed history to the core investigation model:
direct and corroborated child process instances retain their own names and raw
references, UDP endpoints represent local binds, and observation-time ordering
does not claim causality. Missing lifetime facts do not establish parentage.
Timeline admission is limited to 128 rows and 64 KiB of aggregate labels;
truncation and absence of storage paging are explicit. New serialized fields
have defaults so missing older-service history is not presented as available.

## Exact source boundary

Base: 5c48145. Changed source is limited to security-core's investigation.rs,
lib.rs exports and tests/investigation_history.rs. No storage/IPC/UI integration,
dependency or lockfile change belongs to this checkpoint. Existing integration
and experimental changes remain outside this commit; this core prerequisite
alone does not deliver a new end-to-end UI capability.

Validation ran against an ignored archive of that base plus only the listed
source files, not the dirty checkout. Existing tools and locked offline
dependencies were used; target artifacts were reused without changing source.

- cargo test --offline --locked -p piko-security-core: 25 tests passed
  (17 unit, 3 identity integration, 5 history integration), no failures.
- cargo clippy --offline --locked -p piko-security-core --all-targets --
  -D warnings: passed.
- rustfmt --edition 2021 --check on the three source files: passed.
- Targeted private-data/secret-pattern review: no matches. Test names, IDs and
  endpoints are synthetic; no generated/runtime artifacts are included.

Exact snapshot and logs: .build/consolidation-core-20261027, core-tests.log and
core-clippy.log. These are local evidence only, not remote CI or Windows
installation/security qualification. No installation or protection change.
