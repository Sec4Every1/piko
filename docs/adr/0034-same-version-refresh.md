# ADR 0034: bounded same-version binary refresh

2026-10-20. Implemented in scripts; real installed update remains unqualified.

The interactive installer routes an existing service to Update-Piko.ps1, keeping
the enrolled viewer, configuration, evidence and OS permissions. The updater
accepts same-version packages only. Cross-version schema migration is unsupported.

Preflight checks exact executable names/hashes, installed manifest consistency,
administrative file ownership/write ACLs, no reparse paths, expected virtual SCM
account/command and closed clients. PreflightOnly/WhatIf do not mutate installation
or service state. Unsigned package hashes check integrity, not publisher identity.

An exclusive lock serializes refreshes. A unique admin/SYSTEM-only transaction
directory contains staged files and a verified backup of old binaries/manifest.
Staging is checked against the original manifest bytes before stopping the service.
The refresh verifies copied files, preserved config/directory ACLs, SCM/IPC version
and storage health, then restores the original Running/Stopped state. It temporarily
starts a previously stopped service for health validation.

Failure attempts rollback and previous runtime health verification. Transaction
files remain available, including on failure; no evidence/config migration or
deletion occurs. Power-loss/process-crash automatic recovery is not implemented.
Interrupted upgrades and unsuccessful rollback require explicit diagnosis using
retained protected backups; the updater does not silently repair manifest mismatch.

Ten benign full-script fixture checks pass on PowerShell7 and Windows PowerShell5.1,
including source-stage tampering, open clients, WhatIf, initial stopped state,
start failure, IPC-version failure and interactive dispatch. Actual installation
qualification is blocked by an existing installed service/manifest hash mismatch;
no real upgrade or restart was performed. Reboot, power-loss and platform-matrix
qualification remain open. This is not the signed update system in requirement64.
