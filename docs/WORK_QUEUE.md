# Piko: execution queue

Updated: 2026-10-21. This is the ordered work queue, not a second specification.
Full coverage and limitations: [REQUIREMENT_MATRIX.md](REQUIREMENT_MATRIX.md).
Resume evidence: [NEXT_SESSION.md](NEXT_SESSION.md).

Statuses: READY / ACTIVE / BLOCKED / VERIFIED-LOCAL / QUALIFIED / DONE.
VERIFIED-LOCAL does not mean installed, remotely green or production-qualified.
Take the highest-priority ready item and resolve dependencies. Each delivery must
have a concrete user-visible result, tests/evidence and accurate capability status.

| ID | Priority / state | Outcome and acceptance | Dependencies / relevant files |
|---|---|---|---|
| DEV-01 | P0 DONE | Green remote CI baseline: e0b6217, run 39441703542; Windows and dependency jobs passed. Later checkpoints require their own results. | `.github/workflows/ci.yml`, scripts/ci-checks.ps1 and ci-sbom.ps1; VALIDATION.md |
| DEV-02 | P0 BLOCKED | Qualify the updated Windows installation and lifecycle/ACL behavior. Explicit inconsistent-installation recovery is implemented with protected original/archive copies and read-only compatibility gate; fixtures pass. | Live UAC attempt cancelled; installed runtime unchanged and archive already at internal capacity. Use Recover-Piko.cmd only when Windows consent is renewed. ADR0036; no automatic manifest rewrite or evidence restoration. |
| APP-01 | P1 VERIFIED-LOCAL | Added both-direction selection, batch undo of verified selected rules and per-direction outcomes. Fixed helper lifetime/serialization across desktop instances; browser/native fixture checks pass. Live packet/restart/installed qualification remains open, so this is not DONE. | ADR 0035; AppGrid, app-control, network_elevation. Installed deployment still depends on DEV-02; exact verification in VALIDATION.md. |
| APP-02 | P1 VERIFIED-LOCAL | Per-trial network contract: None(default)/InternetClient frozen in preview/session; exact token SID verified before resume; consent invalidation and cleanup. Actual benign processes passed both modes. | ADR0037. Outbound packet connectivity unqualified; persistent installed-app file/system/update mediation and version probation remain unsupported. |
| DET-01 | P2 BLOCKED | Behavioral/ransomware slice with measured file-change/canary signals, benign replay, bounded noise, evidence and remediation. Define measurable coverage and loss before claiming prevention. | Reliable sensors + APP-02 feasibility; requirements 24-27. Kernel mediation, if needed, is its own qualified milestone. |
| GRAPH-01 | P2 VERIFIED-LOCAL | One-hop Windows-reported parent lifetime with same-snapshot identity/time checks, PID reuse/unknown/partial cases, event/raw refs and compact historical view. | ADR0039. Collector -> storage worker -> IPC and UI tests passed. Recursive ancestry, initiating-actor causality, live installed collection and attack paths remain open. |
| STORE-01 | P2 READY | Next log-protection slice: encryption/key lifecycle and integrity checkpoint design, then bounded implementation with recovery/corruption tests. Preserve 12-month/2-GiB stop-on-full preference and noise filtering. | Existing storage/DPAPI; requirements 7-14/61-63, ADR 0028-0032. Local chain alone is not independent anchoring. |
| STORE-02 | P1 ACTIVE | Effective-limit telemetry and bounded pinned-reader regression delivered; writer audit records missing startup/maintenance admission and checkpoint peaks. Continue checkpoint headroom/recovery before reserve redesign. | ADR0038. 8-MiB fixture refuses without losing records; this does not bound every writer. No quota increase or reserve reduction; startup, retention, compression and annotations remain open. |
| RELEASE-01 | P2 BLOCKED | Signed/verifiable updates and qualified distribution, failure/rollback tests and installable artifacts for nontechnical users. | DEV-01/02; requirements 64/96-99; signing infrastructure/credentials need owner provision when required. |
| FLEET-01 | P3 BLOCKED | Optional enrollment, authenticated sharing and response across real endpoints, minimum telemetry and offline autonomy. | Reliable single-host capabilities; requirements 56-60 and roadmap phase 15. |

Other open requirements (identity/token lineage, devices, boot/driver integrity,
vulnerability/patch feeds, deception, PQC and deep diagnostics) remain in the
requirement matrix. Split into ready, testable tasks when prerequisites justify
them; do not mark an entire requirement complete from a small monitoring slice.

## Active task brief (replace when work starts)

- ID: STORE-02, bounded investigation milestone before reserve changes.
- First action: account for uncheckpointed main-file growth in append admission;
  test bounded checkpoint/retry after a pinned reader releases. Startup migration
  admission follows; do not mistake smaller payloads or soft WAL limits for bounds.
- Acceptance: empirical regression coverage, explicitly not a worst-case bound.
  Every writer/checkpoint path needs a separate admission argument before a new
  reserve policy. Live DEV-02 still needs renewed Windows consent after cancellation.
- Delegation: at most one bounded independent review; coordinator owns integration.

## Completion evidence

Keep detailed commands/results in VALIDATION.md or an item-specific ADR. Mark the
queue state only after its acceptance criteria are met. Update NEXT_SESSION with
the smallest restart context and next command/action. No append-only chat transcript.
