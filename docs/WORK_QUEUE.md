# Piko: execution queue

Updated: 2026-10-20. This is the ordered work queue, not a second specification.
Full coverage and limitations: [REQUIREMENT_MATRIX.md](REQUIREMENT_MATRIX.md).
Resume evidence: [NEXT_SESSION.md](NEXT_SESSION.md).

Statuses: READY / ACTIVE / BLOCKED / VERIFIED-LOCAL / QUALIFIED / DONE.
VERIFIED-LOCAL does not mean installed, remotely green or production-qualified.
Take the highest-priority ready item and resolve dependencies. Each delivery must
have a concrete user-visible result, tests/evidence and accurate capability status.

| ID | Priority / state | Outcome and acceptance | Dependencies / relevant files |
|---|---|---|---|
| DEV-01 | P0 ACTIVE | Establish a green remote CI baseline. Review pending fixes, run matching toolchains/audits, resolve actual failures without relaxing gates; record commit/run/evidence. | Pending changes; `.github/workflows/ci.yml`, `scripts/ci-checks.ps1`, `scripts/ci-sbom.ps1`, `deny.toml` |
| DEV-02 | P0 BLOCKED | Qualify the updated Windows installation: service/UI versions agree, account categories work over real IPC, restart/reboot/uninstall/reader ACL failures are visible. Use benign fixtures; record Windows build and limitations. | Compiled package exists; current installed service fails manifest hash validation; installer has no upgrade path. Preserve data and resolve upgrade before lifecycle tests. Installer scripts, ADR 0008/0031/0033. Review authorized scope before changing a running installation. |
| APP-01 | P1 READY | Complete application network-rule workflow qualification: discovery, multi-select, prepare/confirm, both directions, partial failure, restart and undo; show effective supported controls clearly. | Existing app-control, helper, AppGrid; ADR 0010 and relevant network-control ADRs. Inspect current implementations before changing them. |
| APP-02 | P1 READY | Define and implement the first usable per-app capability contract. Compare supported Windows isolation mechanisms for outside-install paths/system files/update writes; implement one real enforceable scope with verification and undo. Unsupported controls stay explicit. | APP-01; requirements 20-23/42, architecture addendum, existing AppContainer path. No generic file blocking claim from path-only Firewall rules. |
| DET-01 | P2 BLOCKED | Behavioral/ransomware slice with measured file-change/canary signals, benign replay, bounded noise, evidence and remediation. Define measurable coverage and loss before claiming prevention. | Reliable sensors + APP-02 feasibility; requirements 24-27. Kernel mediation, if needed, is its own qualified milestone. |
| GRAPH-01 | P2 READY | Verified process ancestry/observed relationships with event references, PID reuse and stale/unknown tests; compact investigation view. | Existing investigation/ETW; requirements 15-16, ATTACK_PATH_MODEL. Potential/counterfactual engines depend on valid evidence. |
| STORE-01 | P2 READY | Next log-protection slice: encryption/key lifecycle and integrity checkpoint design, then bounded implementation with recovery/corruption tests. Preserve 12-month/2-GiB stop-on-full preference and noise filtering. | Existing storage/DPAPI; requirements 7-14/61-63, ADR 0028-0032. Local chain alone is not independent anchoring. |
| RELEASE-01 | P2 BLOCKED | Signed/verifiable updates and qualified distribution, failure/rollback tests and installable artifacts for nontechnical users. | DEV-01/02; requirements 64/96-99; signing infrastructure/credentials need owner provision when required. |
| FLEET-01 | P3 BLOCKED | Optional enrollment, authenticated sharing and response across real endpoints, minimum telemetry and offline autonomy. | Reliable single-host capabilities; requirements 56-60 and roadmap phase 15. |

Other open requirements (identity/token lineage, devices, boot/driver integrity,
vulnerability/patch feeds, deception, PQC and deep diagnostics) remain in the
requirement matrix. Split into ready, testable tasks when prerequisites justify
them; do not mark an entire requirement complete from a small monitoring slice.

## Active task brief (replace when work starts)

- ID: DEV-01
- Result: green remote CI for the reviewed development checkpoint.
- First action: inspect pending diff, lockfile/toolchain policy and last remote run.
- Acceptance: Windows checks + dependency audit pass for a recorded commit;
  unresolved infrastructure/credential constraints are explicit.
- Delegation: one independent CI/audit helper if needed; coordinator owns integration.

## Completion evidence

Keep detailed commands/results in VALIDATION.md or an item-specific ADR. Mark the
queue state only after its acceptance criteria are met. Update NEXT_SESSION with
the smallest restart context and next command/action. No append-only chat transcript.
