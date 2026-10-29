# Piko: execution queue

Updated: 2026-10-29. This is the ordered work queue, not a second specification.
First-delivery scope: [FIRST_RELEASE.md](FIRST_RELEASE.md). Current progress is only in NEXT_SESSION.md. The first-delivery gates below take priority over the product backlog. Full coverage and limitations: [REQUIREMENT_MATRIX.md](REQUIREMENT_MATRIX.md).
Resume evidence: [NEXT_SESSION.md](NEXT_SESSION.md).
Delivery batches and continuation policy: [DEVELOPMENT_PLAN.md](DEVELOPMENT_PLAN.md).
Targeted local checks are authorized again (2026-10-24); installed-runtime
qualification, driver loading and installation remain separate. On 2026-10-27
the user accepted consolidation and checked development-branch pushes; main
merge, release publication and manual remote CI dispatch remain separate.
First usable release now takes precedence over APP-03/browser development.

Statuses: READY / ACTIVE / BLOCKED / VERIFIED-LOCAL / QUALIFIED / DONE.
VERIFIED-LOCAL does not mean installed, remotely green or production-qualified.
Take the highest-priority ready item and resolve dependencies. Each delivery must
have a concrete user-visible result, tests/evidence and accurate capability status.

## First-delivery closure (frozen scope)

| ID | State | Finite outcome |
|---|---|---|
| DELIVERY-CONSOLIDATE | DONE for included first-release source; deferred work preserved | development/first-release includes reviewed history, storage/maintenance, key backend/UI, recovery/update/package and check-script source through 3551f55 plus the documentation checkpoint. Exact-source local evidence is in docs/validation. Deferred APP-03/browser changes remain local. No installed qualification, main merge or release is implied. |
| FIRST-SOURCE | VERIFIED-LOCAL; installed behavior unqualified | Included paths only; fresh 2048MiB/12month policy, installed stopped-service UI and aligned package/manual source. Evidence in VALIDATION.md. |
| FIRST-DEPS | ACTIVE: crypto-bigint unresolved | Reviewed local i18n-config parser backport removes basic-toml; age remains 0.12.1. Final candidate passes 231 workspace tests / 5 ignored, Clippy and PS5/7 source-copy checks. Age 0.11.5 experiment rejected for weaker temporary key clearing despite format compatibility. crypto-bigint0.5.5 / RUSTSEC-2026-0387 still blocks release; no advisory ignores. Evidence: validation/2026-10-29-localization-parser.md; ADR0055. |
| FIRST-CHECKS | ACTIVE: Event Log persistence gate failed; recheck pending | Rust/frontend/Tauri, runtime IPC smoke, package preview, PowerShell 5.1/7 fixtures and 68 Playwright cases passed before the latest source changes. Event Log smoke previously said first-run records were missing after restart. Script source now checks IDs that fall outside the later 100-row page individually, including the probe and raw XML; isolated exact-query fixtures pass on PS5/7; the actual probe is unrun. If the next authorized run still fails, investigate stored rows/bookmarks. Evidence: VALIDATION.md. |
| FIRST-WINDOWS | BLOCKED: qualification/consent | Install, collection/reconnect/full, supported response/undo and reachable recovery qualification; preserve existing runtime until authorized. |
| FIRST-PACKAGE | ACTIVE: unsigned local preview inspected; final gate pending | Debug preview has manifest-matched binaries, third-party sources and privacy checks. Final package/checksum review follows Windows qualification; source pushed to development branch; no release publication. |

## Product backlog (does not expand first delivery)
| ID | Priority / state | Outcome and acceptance | Dependencies / relevant files |
|---|---|---|---|
| DEV-01 | P0 DONE | Green baseline526f185/run39560604506: Windows and dependency jobs passed after Vite7.3.7 patch. Later storage group through851ef6c passes local checks and is published as one reviewed checkpoint; matching new CI pending. | `.github/workflows/ci.yml`, scripts/ci-checks.ps1 and ci-sbom.ps1; VALIDATION.md |
| DEV-02 | P0 BLOCKED | Qualify the updated Windows installation and lifecycle/ACL behavior. Explicit inconsistent-installation recovery is implemented with protected original/archive copies and read-only compatibility gate; fixtures pass. | Live UAC attempt cancelled; installed runtime unchanged and archive already at internal capacity. Use Recover-Piko.cmd only when Windows consent is renewed. ADR0036; no automatic manifest rewrite or evidence restoration. |
| APP-01 | P1 VERIFIED-LOCAL | Added both-direction selection, batch undo of verified selected rules and per-direction outcomes. Fixed helper lifetime/serialization across desktop instances; browser/native fixture checks pass. Live packet/restart/installed qualification remains open, so this is not DONE. | ADR 0035; AppGrid, app-control, network_elevation. Installed deployment still depends on DEV-02; exact verification in VALIDATION.md. |
| APP-02 | P1 VERIFIED-LOCAL | Per-trial network contract: None(default)/InternetClient frozen in preview/session; exact token SID verified before resume; consent invalidation and cleanup. Actual benign processes passed both modes. | ADR0037. Outbound packet connectivity unqualified. |
| APP-03 | P1 DEFERRED behind first usable release (2026-10-27) | Persistent installed-app limits for writes outside reviewed roots, protected Windows files and version freeze. Real service -> IPC -> UI path, with qualified kernel enforcement before any active control. | ADR0054; restart context in NEXT_SESSION. Configured-only snapshot/receipts/recovery/removal and protocol v7 with specific health causes reach service/IPC/Tauri/UI. Existing/new targets are corroborated with pre/post identity or parent/epoch/configuration/root bitmap; malformed intent, aliases and stale samples remain unknown. 227 production-module simulated fault scenarios (including real process-table lifecycle/capacity/lineage), focused Rust/frontend/Tauri checks and unsigned WDK compile/link pass locally. Real kernel/race/performance behavior is unqualified. All callbacks pass through; drafts remain not_enforced. Next: live principal/image-content validity, then pre-effect mediation under ADR0054. Package/altitude/signing and VM qualification remain open. |
| BROW-01 | P1 READY (after active APP-03) | Browser/profile inventory and per-layer capability status through service → IPC → UI, without reading secret values. Qualify supported discovery with synthetic profiles; missing scope/browser/API remains unknown. Document feasible adapter and resource-read boundaries before prevention work. | User requirement extension 2026-10-25; REQUIREMENTS 40/41 and `BROWSER_REALTIME_PROTECTION.md` (preserved local deferred design), R41.01/R41.09/R41.10. No browser protection is implemented by this specification. |
| BROW-02 | P1 BLOCKED (BROW-01 and qualified boundaries) | Deliver and qualify browser real-time protections in vertical slices: credential/session resource access, pre-request navigation blocks, extensions, exploit/download/endpoint containment and recovery, with per-layer active/degraded status. | BROW-01; requirements 40/41, 32–35 and identity/response. Credential-read/mapping mediation is additional to APP-03 write observations; native browser APIs, secure adapter distribution and isolated Windows qualification are required. Acceptance matrix and primary-source research in BROWSER_REALTIME_PROTECTION.md. |
| DET-01 | P2 BLOCKED | Behavioral/ransomware slice with measured file-change/canary signals, benign replay, bounded noise, evidence and remediation. Define measurable coverage and loss before claiming prevention. | Reliable sensors + APP-02 feasibility; requirements 24-27. Kernel mediation, if needed, is its own qualified milestone. |
| GRAPH-01 | P2 VERIFIED-LOCAL | Parent/child genealogy, UDP binds and bounded temporal sequence with search, category filters and event/raw drill-down. | ADR0043/0051. Workspace tests and 67 browser scenarios pass; causal/attack-path engines and live deployment remain open. |
| STORE-01 | P2 ACTIVE (locally built; live qualification open) | v1/v2 raw protection, guided backup and same-installation profile-loss restore with durable rebind/resume, maintenance and guarded refresh source. | ADR0044-0050/0052. Flags off. Mocked UI scenario passes; UAC, interruption and Windows recovery qualification remain open; portable import, unrecognized recovery state, rotation and full-log encryption remain deferred. |
| STORE-02 | P1 VERIFIED-LOCAL | Effective capacity telemetry; checkpoint headroom/retry; pre-writer migration gate; safe empty bootstrap; bounded keyset detection backfill and writer-locked storage admission. | ADR0038,0040-0042,0053. Workspace tests pass. No quota/reserve change; external backups and physical peak proofs remain open. |
| RELEASE-01 | P2 BLOCKED | Signed/verifiable updates and qualified distribution, failure/rollback tests and installable artifacts for nontechnical users. | DEV-01/02; requirements 64/96-99; signing infrastructure/credentials need owner provision when required. |
| FLEET-01 | P3 BLOCKED | Optional enrollment, authenticated sharing and response across real endpoints, minimum telemetry and offline autonomy. | Reliable single-host capabilities; requirements 56-60 and roadmap phase 15. |

Other open requirements (identity/token lineage, devices, boot/driver integrity,
vulnerability/patch feeds, deception, PQC and deep diagnostics) remain in the
requirement matrix. Split into ready, testable tasks when prerequisites justify
them; do not mark an entire requirement complete from a small monitoring slice.

## Active task brief (replace when work starts)

- ID: FIRST-DEPS / FIRST-CHECKS (dependency gate remains open, 2026-10-29).
- Tokio 1.53.3 correction and complete CI binary inventory are published in dba078b;
  complete HEAD-matched Chromium rerun passed 70/70. Evidence:
  validation/2026-10-29-release-followup.md.
- Parser CI inspected: Windows regression test creates CRCRLF from checkout CRLF.
  Corrected tests pass 7/7 for embedded LF and CRLF using existing Windows GNU
  tools; targeted Clippy, formatting and PS5/7 source-copy checks pass.
  Inspect automatic MSVC CI after publishing the reviewed correction.
  basic-toml is absent; crypto-bigint still fails dependency CI.
- Resolve crypto-bigint through compatible upstream changes or an explicitly
  approved risk disposition. Do not adopt the rejected age downgrade or add ignores.
- Resolve age-chain audit findings, rebuild a matching candidate, then execute WINDOWS_QUALIFICATION.md in an authorized environment.
- APP-03/browser remain deferred; exact evidence and next action are in NEXT_SESSION.md.

## Completion evidence

Keep detailed commands/results in VALIDATION.md or an item-specific ADR. Mark the
queue state only after its acceptance criteria are met. Update NEXT_SESSION with
the smallest restart context and next command/action. No append-only chat transcript.
