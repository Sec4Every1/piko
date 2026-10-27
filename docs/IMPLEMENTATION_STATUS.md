# Project status

First-delivery scope is frozen in [FIRST_RELEASE.md](FIRST_RELEASE.md);
current qualification gates are tracked in [NEXT_SESSION.md](NEXT_SESSION.md).
Published source includes bounded observation history/navigation, protected
storage admission and automatic maintenance, recoverable-key core, the real
backend -> IPC -> desktop/helper key workflow and guarded update/recovery
entry points. New installations/profiles default to 2048 MiB and 12 months;
existing configurations are preserved. Relevant local checks passed on selected
source snapshots: [history](validation/2026-10-27-history-desktop.md),
[storage](validation/2026-10-27-storage-foundation.md),
[maintenance](validation/2026-10-27-maintenance-vertical.md),
[crypto/dependency graph](validation/2026-10-27-recoverable-key-core.md),
[key backend](validation/2026-10-27-key-backend.md),
[key desktop/helper](validation/2026-10-27-key-desktop.md) and
[recovery/package](validation/2026-10-27-recovery-package.md).
These tests, fixture scenarios and compiled candidates do not qualify the
installed Windows runtime or DPAPI/UAC/SCM recovery. New-evidence protection
flags default off. The inherited locked dependency graph was checked locally;
a complete security dependency audit and first-release qualification remain
open. Historical limitations below still apply where these checkpoints do not
explicitly extend them.

Piko is an early-stage Windows security-monitoring prototype. It is not a complete endpoint protection product; use the feature matrix and security model to understand current capabilities and limits.

## Implemented areas

2026-10-21: observed relationships include a one-hop Windows-reported parent
lifetime resolved within a complete process snapshot, with creation-time/PID
reuse checks and event/raw evidence. The compact view names the parent and marks
observations as historical. This is not initiating-actor attribution, recursive
ancestry or attack-path analysis. See ADR0039; live deployment remains unqualified.

2026-10-20: account activity includes creation, enabling, disabling and deletion
(Security 4720/4722/4725/4726, version 0), with affected/requesting identities,
paged filters and original evidence. These are observed historical facts;
account policy enforcement remains unimplemented. See ADR 0033.

The repository contains a Windows service, desktop UI, CLI, local event store, event-log and selected ETW collectors, application inventory, event grouping and MITRE ATT&CK mappings. It also includes user-confirmed workflows for selected file recovery/quarantine and per-executable network rules, plus an installer and uninstall scripts. Availability depends on Windows permissions and policy.

The dashboard separates grouped, human-readable alerts from event details and raw records. Its 0–100 score is an explainable heuristic; it is not a calibrated probability that an alert is a false positive or a measure of overall system risk.

## Known limits

General mediation of application access to files, registry and devices is not implemented. Piko does not provide a kernel driver, self-defense, general behavioral detection, automatic patching, signed updates, fleet management, or a complete recovery system. Network enforcement and service collection require testing on the target Windows configuration. The event store is local and does not protect against a sufficiently privileged local attacker; its integrity chain is not an external trust anchor.

See [the requirement matrix](REQUIREMENT_MATRIX.md), [security model](SECURITY_MODEL.md), [installation guide](INSTALLATION.md), and [user manual](MANUALE_UTENTE.md). Reproducible checks and qualification gaps are in [VALIDATION.md](VALIDATION.md). Do not treat local development results as release qualification.

2026-10-20: same-version binary refresh is implemented with hash preflight,
protected staging/backup and attempted rollback (ADR0034), routed from the
interactive installer. Mocked tests passed on PowerShell5.1/7. Live refresh is
not qualified and refuses the currently inconsistent installed manifest. Secure
signed updates, cross-version migration and automatic crash recovery remain open.

2026-10-21: explicit inconsistent-installation recovery adds protected original and
archive copies, strict replacement validation, offline read-only integrity gate and
exact binary/manifest rollback (ADR0036). Known pre-existing storage capacity failure
is reported explicitly rather than mislabelled active. Live UAC was cancelled;
the installed runtime was not changed.

AppContainer trials now offer default-denied or explicit InternetClient network
capability, bound to the preview and verified token (ADR0037). Actual benign token
creation and stop/profile cleanup passed in both modes; packet connectivity and
broader installed-app file/system/update controls remain unqualified/unsupported.
Effective SQLite capacity is measured directly (ADR0038); budget/retention and
write-reserve policy are unchanged.
