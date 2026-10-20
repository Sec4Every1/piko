# Project status

Piko is an early-stage Windows security-monitoring prototype. It is not a complete endpoint protection product; use the feature matrix and security model to understand current capabilities and limits.

## Implemented areas

2026-10-20: account activity includes creation, enabling, disabling and deletion
(Security 4720/4722/4725/4726, version 0), with affected/requesting identities,
paged filters and original evidence. These are observed historical facts;
account policy enforcement remains unimplemented. See ADR 0033.

The repository contains a Windows service, desktop UI, CLI, local event store, event-log and selected ETW collectors, application inventory, event grouping and MITRE ATT&CK mappings. It also includes user-confirmed workflows for selected file recovery/quarantine and per-executable network rules, plus an installer and uninstall scripts. Availability depends on Windows permissions and policy.

The dashboard separates grouped, human-readable alerts from event details and raw records. Its 0–100 score is an explainable heuristic; it is not a calibrated probability that an alert is a false positive or a measure of overall system risk.

## Known limits

General mediation of application access to files, registry and devices is not implemented. Piko does not provide a kernel driver, self-defense, general behavioral detection, automatic patching, signed updates, fleet management, or a complete recovery system. Network enforcement and service collection require testing on the target Windows configuration. The event store is local and does not protect against a sufficiently privileged local attacker; its integrity chain is not an external trust anchor.

See [the requirement matrix](REQUIREMENT_MATRIX.md), [security model](SECURITY_MODEL.md), [installation guide](INSTALLATION.md), and [user manual](MANUALE_UTENTE.md). Reproducible checks and qualification gaps are in [VALIDATION.md](VALIDATION.md). Do not treat local development results as release qualification.
