# First deliverable: frozen scope

Accepted direction: 2026-10-23. First usable Windows delivery, not completion of
all 116 requirements. Existing technical version stays 0.2.0; no downgrade or
renaming to 0.1. Progress and blockers are tracked in `docs/NEXT_SESSION.md`
in the source repository.

## Included

- Windows x64 local monitoring: installed service or existing per-user mode,
  real collection/health, visible unavailable sources, bounded queues and durable
  local events with raw evidence and integrity verification.
- Desktop dashboard: compact alerts, event/raw details, application inventory,
  observed process/network history and existing manual response workflows.
  Every shipped enabled action must have its existing backend/IPC/result path
  qualified; a button alone is not acceptance.
- Existing reversible per-executable network controls and selected file
  quarantine/restore, with their existing consent, scope and evidence boundaries.
- New user profiles/installations use 2 GiB and 12-month calendar retention;
  exhausted capacity stops/refuses writes rather than silently shortening history.
  Existing configurations are preserved. Low-level development configs and
  explicitly supplied installer arguments retain their existing meanings.
- Double-click entry points, non-elevated UI, standard Windows consent for
  privileged changes, private installed data and an understandable disconnected
  state. An installed stopped service must not cause a console fallback or hide
  the dashboard's guarded activation-resume path.
- Protected evidence/recovery source already present is retained. Defaults stay
  off; activation remains explicit and its reachable mutation paths must be
  qualified before release. Unrecognized recovery state refuses with data kept.
- A matching, installable package with manifest/checksums, MIT license, bundled
  manual and accurate capability/recovery limits. An unsigned preview must be
  described as unsigned; publisher authenticity is not claimed from hashes.

## Explicitly after this delivery

No new implementation is required for kernel enforcement, broad behavioral or
ransomware prevention, causal/attack-path/counterfactual engines, general app
permission mediation, version probation, fleet or automatic patching.

Portable archive/key import, key rotation/TPM, full database encryption, signed
anchors, automatic repair of corrupt/legacy recovery state and a generalized
peak-storage manager spanning retained external backups are separate milestones.
Conservative SQLite admission is not a worst-case physical-bound proof. Manual
maintenance/update backups require additional space outside the operational
SQLite budget, as documented. No universal 12-month capacity guarantee is made.

Existing source for experiments is preserved; its presence does not expand this
release's claims or acceptance. RELEASE-01 signing/secure distribution remains
the subsequent distribution milestone, separate from a labelled unsigned preview.

## Finite exit gates

1. SOURCE: close concrete source blockers in included paths; keep docs/defaults
   consistent. Then freeze features. Reopen only a reproduced/reviewed defect,
   acceptance failure or explicit user scope change.
2. CHECKS: run the required Rust, frontend, Tauri and PowerShell checks against
   the exact source/package candidate. Record actual results in VALIDATION.md.
   Event Log persistence across restart and the full release gate must pass;
   targeted local successes alone do not qualify installed behavior.
3. WINDOWS: after authorized consent, qualify clean install, service collection,
   UI reconnect, supported response/undo, archive full/restart and enabled recovery
   paths on the target Windows configuration. Existing inconsistent installation
   is a separate DEV-02 recovery qualification; preserve its evidence.
4. PACKAGE: assemble and inspect a matching unsigned preview in ignored `.build`;
   final artifact/checksum review follows Windows qualification. Reviewed source
   may be pushed to the authorized development branch; main merge and release
   publication remain separate.

No gate is marked passed from documentation, source edits or elapsed time.
