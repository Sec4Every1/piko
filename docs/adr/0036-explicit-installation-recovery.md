# ADR 0036: explicit recovery of inconsistent installations

2026-10-21. Fixture-tested implementation; live recovery awaits Windows consent.

Normal updates still reject installed executable/manifest mismatches. Recovery
requires the explicit RecoverInconsistentInstallation switch, also exposed through
Recover-Piko.cmd; the ordinary installer never silently enables it. Product,
architecture, executable names and same-version restriction remain mandatory.
Replacement package hashes remain strict. An inconsistent manifest's version does
not prove the original binary's provenance or evidence compatibility.

Recovery captures fresh observed hashes and exact original manifest bytes. The
existing protected transaction preserves originals and SDDL, configuration copy
and hash before stopping the service. Repeated snapshot checks reject subsequent
changes. No original manifest is rewritten to make it appear consistent.

With service fully Stopped, recovery copies events.db and any WAL/SHM sidecars
into a protected evidence-before directory and verifies hashes. Space is checked
first. The strictly checked staged service's --verify-evidence command opens the
existing archive read-only and checks integrity before replacement. Running,
paused, pending, wrong-type or missing installed services are rejected by that
command. No new dependencies/FFI or OS permission grants are needed.

Failure restores exact prior binaries/manifest, ACLs and Running/Stopped state.
An inconsistent original CLI is never executed for rollback health checks;
rollback is explicitly health-unqualified. Restoring Running necessarily starts
the original service. Evidence is not automatically rolled back or discarded;
startup can write new evidence. The archive backup is outside its operational
budget, so recovery temporarily needs additional disk space. Process/power-loss
automatic recovery and cross-version migration remain unsupported.

If the strictly staged CLI observes a zero-drop running service with an existing
known capacity failure before stopping it, the same explicit quota condition after
recovery can be reported as updated with storage_state=capacity_exhausted and a
warning. That is binary recovery, not active collection qualification. A newly
introduced quota failure still triggers rollback; it is never silently accepted.

Read-only preflight/WhatIf, invalid replacement, changed originals, incompatible
archive, success and start/health-failure rollback are covered by fixtures. The
UAC attempt on this machine was cancelled before execution; no live replacement
or archive copy from this recovery path occurred.
