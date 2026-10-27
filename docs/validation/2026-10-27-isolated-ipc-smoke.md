# Isolated development IPC smoke, 2026-10-27

Reviewed `scripts/smoke.ps1` and `smoke-runtime.ps1` changes against the recovery
snapshot's matching debug service/CLI from the locally built efaf465 candidate.
Only the two smoke scripts were overlaid for this run; no APP-03 source entered
the candidate. Later formatter changes do not change runtime behavior.

Executed the compatibility wrapper with explicit binary/evidence directories on
Windows PowerShell 5.1 and PowerShell 7.6.8. Both returned PASS, nine checks and
14 verified events. A separate bounded development process and synthetic local
archive were used for each run. Logs and results remain under ignored
`.build/consolidation-recovery-package-20261027` (`smoke-ps5.log`,
`smoke-ps7.log`, `.build/ipc-smoke-ps5`, `.build/ipc-smoke-ps7`).

The direct development pipe covered health/runtime identity, persisted events
belonging to the created process, protocol/query refusals, integrity and bounded
shutdown/client-independent runtime. The CLI round trip was explicitly skipped
on both runs because the installed service was running; invoking the CLI there
would select that service rather than the test process. Results accurately
report `skipped_installed_service_running` and nine rather than ten checks.

The wrapper resolves default paths after parameter binding for PowerShell 5.1;
this run supplied explicit paths. No claim of a newly executed no-argument path
test is made. No installed service action, Event Log probe emission, evidence
recovery/activation or live protection change was performed. This is development
IPC evidence, not installed Windows qualification or a complete release gate.
