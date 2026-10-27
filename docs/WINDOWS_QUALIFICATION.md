# First-release Windows qualification

Status: prepared, not executed. This plan does not authorize installation or
runtime changes. Use an authorized disposable Windows x64 VM with snapshots or
a separate test PC. Never use the existing development-host installation for
fault injection, profile loss or archive replacement.

Use one identified candidate throughout. Record source commit, package profile,
four manifest hashes, OS build, PowerShell versions and results in a dated
validation record. The current debug preview is unsigned and not a qualified
release. It may contain development paths in debug information; keep it private.
Take a baseline VM snapshot before installation and a second before each
destructive/recovery drill. Use only synthetic applications and evidence.

| Case | Action in the isolated environment | Required observable result |
|---|---|---|
| Clean installation | Use Install-Piko.cmd with the intended ordinary viewer account; exercise UAC accept and cancel in separate baseline snapshots. | Cancel leaves no claimed success. Accepted install has the expected private data/installation ACLs, service identity and manifest-matched executables; UI runs without elevation. |
| Fresh and existing configuration | Inspect fresh defaults; separately refresh an installation containing a custom configuration. | Fresh capacity is 2048 MiB and calendar retention 12 months. Existing configuration bytes and ACLs are preserved. Protection defaults are off. |
| Collection and reconnect | Open the dashboard, inspect real sensor health/event/raw evidence, close and reopen it, then restart the test VM. | Collection continues without the UI; unavailable sources are visible. Reconnect works; previous events and original evidence remain verifiable. No unsupported protection is shown active. |
| Stopped service | Stop only the VM's test service, then use Open-Piko.cmd. | Installed UI opens in a disconnected state. No parallel console archive is created; guarded resume remains reachable when applicable. |
| Event Log persistence | Run the matching source's event-log-smoke.ps1 and its matching probe in the VM. Retain both runs' diagnostics. | System/Application subscriptions are active, the original benign probe XML is readable, first-run event UUIDs remain available after restart, no replay duplicates appear and integrity verifies. A newer 100-row page alone is insufficient. |
| Capacity and restart | Use a separate synthetic archive/configuration for bounded full-capacity testing; preserve normal installation defaults. | Full storage visibly refuses/stops writes without silent deletion, quota increase or retention shortening. Evidence still reads/verifies after restart. Record actual physical usage separately from the configured operational budget. |
| Manual response and undo | With explicit per-operation consent, block/undo traffic for a disposable executable in each supported direction; quarantine/restore a disposable file. | Actual traffic and file effects match the reviewed scope; undo restores the supported state and failures remain visible. Rule presence alone is insufficient evidence of traffic blocking. |
| Same-version update and guarded resume | Preserve VM snapshot and original files; exercise successful refresh, refusal, cancelled consent and interruption points using known journals. | Original evidence/configuration/ACLs remain intact. Candidate archive verification runs under the original service identity. Known transactions resume forward; unknown/malformed/changed state refuses and retains guards/backups. No automatic evidence restore. |
| Recoverable evidence | In a fresh test archive, export and independently save the test recovery code, confirm by re-entry, then separately consent to activation. Exercise cancellation, wrong code, interrupted activation and same-installation profile-loss recovery from a VM snapshot. | Fresh activation requires confirmed backup and distinct authorization; actual new protected records decrypt and verify after restart. Recovery verifies the complete archive before rebind, preserves original copies and resumes only recognized state. Failed/ambiguous operations retain evidence and cannot silently disable protection. Legacy DPAPI-only evidence is not recovered by a new-format code. |

For recovery, enumerate interruption points from ADR0047, ADR0050 and ADR0052
before executing that drill. Snapshot rollback is test-environment recovery, not
evidence that Piko's own recovery worked. Keep pre/post hashes and failure state
before resetting a VM. Do not delete pending markers to make a case pass.

Record PASS/FAIL/BLOCKED for each case with observations and retained evidence.
A cancelled consent, missing permission or unavailable environment is not PASS.
Any reproduced included-path defect reopens FIRST-SOURCE and its affected checks.
Close FIRST-WINDOWS only after all shipped enabled paths meet their acceptance
criteria. Then rebuild/review a matching final candidate and perform the remaining
full release/package gate; main merge and publication still require separate
authorization. APP-03 driver enforcement and browser prevention are outside this
plan and remain unavailable.
