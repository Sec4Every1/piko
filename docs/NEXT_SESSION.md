# Piko: development progress and remaining work


## Latest finite delivery (2026-10-27)

Recovery/package source is now committed and pushed as efaf465. Eighteen staged
files matched the tested exact-source snapshot (documentation evidence reviewed
separately). PS5.1/7.6.8 updater 26, launcher 7 and recovery metadata 4 fixture
groups passed; all four debug binaries built and the unsigned preview assembled
with matching hashes. Existing/out-of-scope destinations refused. No installation,
SCM/UAC/DPAPI recovery qualification or release publication occurred.
Evidence: validation/2026-10-27-recovery-package.md.

9ce7cd3 publishes the PS5/7 isolated persistence/preflight fixtures and CI wiring.
73b4ff7/fbbbb4e consolidate mechanical Windows-module formatting, correcting an
initial wrong-edition check. Actual workspace edition-2021 formatting and offline
locked workspace all-target compilation now pass on the selected snapshot.
Evidence: validation/2026-10-27-check-script-guards.md and win-platform-format.md.

3551f55 publishes the isolated IPC smoke fixes; PS5/7 both pass nine checks
with 14 verified events. CLI was skipped because the installed service was
running; direct development IPC passed. No installed runtime was changed.
Evidence: validation/2026-10-27-isolated-ipc-smoke.md.

Included ADR/audit/matrix/status and workflow documentation are consolidated in
the accompanying documentation checkpoint. Historical source-only notes are
explicitly dated and linked to the newer local evidence. Deferred APP-03/browser
source and unrelated documentation remain local and preserved.

Exact next action: establish the authorized isolated Windows environment, record
its OS/snapshot/candidate identity and execute docs/WINDOWS_QUALIFICATION.md.
The local debug preview is prepared, unsigned and private; no installation is
authorized on this host. Event Log persistence, SCM/UAC/DPAPI interruption/recovery
and the full release gate remain open. VM availability was asked while source
work continued; no answer or installation authorization has been assumed.

## Current delivery direction (accepted 2026-10-27)

Prioritize a usable FIRST_RELEASE delivery over further APP-03/browser research.
Preserve experimental source and its not_enforced status. "Continua/vai avanti"
confirms the agreed direction; do not ask the user to restate priorities.
Proceed through finite outcomes and their relevant local checks autonomously.
This section supersedes the older APP-03-first continuation instructions below.

Immediate outcome: consolidate the accumulated changes into coherent reviewed
commits, then push checked source to a development branch. The user accepted
that workflow; main merge, release publication and manual remote CI dispatch
remain separate. Never push the dirty checkout wholesale or include private
data/generated artifacts. Review dependencies before splitting mixed files.
Then close FIRST-CHECKS/local source blockers and prepare FIRST-WINDOWS.
VM availability/access and authorization for its installs/runtime tests are still
needed; do not infer permission to change the installed host runtime.

Remote main was verified read-only at dc47a24 on 2026-10-27 and remains
unchanged. development/first-release was created and pushed through 3551f55:
e3109b7 consolidates the observed-history core; f1b665d storage paging/query
fields; c0e4141 IPC/service; 4e00996 Tauri/desktop timeline and navigation.
16bbeb5 consolidates protected evidence and bounded maintenance storage logic.
bbc1fe0 connects bounded maintenance through worker/IPC/Tauri to the archive UI.
9770b16 adds the recoverable-key core plus the existing manifest/lock graph.
28c458c integrates the actual provider/key worker/guarded service backend;
5f60108 adds guided key UI/native/helper and embedded activation source.
efaf465 adds recovery/update wrappers, fresh defaults, matching manual and tested debug package source.
Earlier local 245e77a/5c48145 storage fixes were also
reviewed and published on that branch. Substantial local source remains
uncommitted; the development branch is not a complete mirror of this checkout.
No release or manual remote CI dispatch occurred; remote CI success is unverified.

Consolidation review: shared runtime/IPC/Tauri/CLI matches, manifests/lockfiles
and desktop tests interleave history, protected storage, recovery and APP-03.
Do not stage those entire files as independent feature commits. Review and
partition hunks with dependency checks: history; protected-storage/maintenance
foundation; recoverable evidence/lifecycle; preserved inactive APP-03; final
release integration/docs. Keep mechanical fixes with their affected modules
unless they are independently necessary. Avoid an artificial commit split
that creates uncompilable intermediate source.

First renewed local evidence: PowerShell 7.6.8 Update-Piko.Tests.ps1 fixtures
passed on 2026-10-27, no real installation/SCM changes; log in VALIDATION.
History source path is consolidated through UI. Checks used archived HEAD plus
exactly selected files/hunks, not the dirty checkout: core 25, storage 47,
service 15 and IPC 2 tests; affected all-target Clippy; targeted Rust formatting;
frontend type check, 11 unit tests, 8 Playwright scenarios and production build;
Tauri offline locked check. Index blobs matched tested snapshots before each
partial-file commit. No dependency/lockfile changes. Evidence is in
validation/2026-10-27-history-{core,storage,backend,desktop}.md.
The paging path also bounds stored payloads before copying into Rust. Browser
results use synthetic bridge replies; installed service/desktop is unqualified.

Storage foundation is now separately checked/pushed, without a crypto dependency
or lockfile change. Storage 54/service 15 tests, all-target workspace compiler
check, affected Clippy and formatting passed on an exact-source snapshot.
Regression reproduced/fixed implicit policy reconstruction when all protection
metadata was missing; writers now refuse even with the original provider.
Evidence: validation/2026-10-27-storage-foundation.md. Injected-provider tests
do not qualify DPAPI/age, key recovery or installed encryption; defaults stay off.

Maintenance vertical source is consolidated/pushed: service 20/IPC 2 tests,
affected Clippy/formatting, frontend types/25 unit/4 Playwright/build and Tauri
check passed on the exact selected snapshot. Queue coalescing/full retry,
worker loss and synthetic real-worker scan/integrity are covered. UI claims
logical reduction only, not physical disk savings. Evidence:
validation/2026-10-27-maintenance-vertical.md. No installed runtime change.

Recoverable-key core is checked/pushed with the already-existing dependency
graph; no resolver update/download occurred. The root lock has inherited broad
version churn (132 -> 222 package entries), not a minimal crypto-only change.
205 workspace all-target tests passed / 5 ignored after fixture filesystem
access was allowed; workspace all-target Clippy, crypto formatting and separate
desktop locked check passed. Eight focused tests use real age operations with
a fake local key wrapper. Existing frontend assets were reused for the native
check. Evidence: validation/2026-10-27-recoverable-key-core.md. Windows local
key wrapping, backup/recovery and installed protection remain unqualified.

Key backend/desktop/helper source is consolidated/pushed. Backend service 30,
IPC 5 and platform 43 tests passed (3 platform cases ignored), affected Clippy
and service/CLI build passed. Expired key jobs now refuse before occupying the
single queue slot. Desktop 6 unit / guided browser scenario plus existing browser
error case, type/build/Tauri check, helper 5 negative tests/Clippy/build and
PowerShell 5.1/7 activation-function fixtures passed. No actual activation ran.
Evidence: validation/2026-10-27-key-backend.md and key-desktop.md.

Recovery/package source was published in efaf465 from the exact-source snapshot
.build/consolidation-recovery-package-20261027. It includes recovery wrappers,
interactive routing, updater/resume, fresh defaults and matching package/manual.
Four debug binaries built and the unsigned preview assembled; all four hashes,
recovery inventory and package destination refusal checks passed. See
validation/2026-10-27-recovery-package.md. Artifacts remain ignored.

9ce7cd3 publishes isolated persistence-query and CI-preflight guards. Both new
fixtures pass four groups each on PowerShell 5.1 and 7.6.8. Exact-event lookup
refuses missing, malformed or ambiguous rows; CI now wires the included script
fixtures on both runners. See validation/2026-10-27-check-script-guards.md.
No actual Event Log probe or full CI ran.

The included source/check-script/documentation consolidation is complete for this
checkpoint. Exact next action is the isolated Windows qualification plan above;
fix any reproduced included-path failure before package/release closure. Do not
resume deferred APP-03/browser implementation to replace this release gate.

## Continuation workflow (2026-10-24)

The user requested a structured plan to reduce repeated manual continuation.
[DEVELOPMENT_PLAN.md](DEVELOPMENT_PLAN.md) defines complete APP-03 delivery
batches A-D, completion criteria, current boundaries, and a proposed finite
Goal for A. The user subsequently reauthorized targeted local checks on
2026-10-24: affected tests, type/compiler checks, Clippy, formatting and builds
when needed. Start with the unverified affected source, fix failures, then
continue APP-03/A. Existing goal text may still contain the old no-checks
restriction; this newer user authorization takes precedence.
The existing persistent thread goal was read in state `usageLimited`; it is
not complete. This state alone does not identify the specific underlying quota.
User/system-controlled availability must permit continuation; do not create a
duplicate goal or promise that a new prompt overrides usage limits. No scheduled
task, runner, install or live-protection change was made for this plan.

## Deferred follow-up: APP-03 persistent installed-app protections (2026-10-27)

APP-03 is deferred behind first-delivery closure. All file callbacks pass through; EnforcementReady is
zero and every draft remains not_enforced. Source/build/test success does not
qualify installed runtime, prevention or release.

Current restart context:
- Snapshot content v2 binds reviewed executable/root identities, hashes, flags
  and revision/digest; 48-byte header, 37,380 bytes/policy, at most 128 policies.
  Native preparation pins handles with 256 MiB/image and 512 MiB total hashing
  limits, refuses aliases/overlaps and re-prepares the exact reviewed digest.
- Service journals the wire commitment before bounded begin/chunk/commit.
  Driver validates coverage/content/digest and atomically publishes configured
  data plus separate nonpaged indices. Configuration is separate from applied
  enforcement. Partial staging disappears on disconnect; exact repeated commit
  is idempotent. Commit filesystem queries run at PASSIVE_LEVEL with APCs enabled.
- Durable configured receipts, exact readback and pending-state reconciliation
  protect interruption recovery. Empty-snapshot removal uses generation/digest
  CAS and preserves drafts. No ambiguous/legacy pending state is auto-cleared.
- Protocol v7 has a 172-byte reply: five bounded inside/outside/unknown operation
  groups plus process/image/target/root degradation bits. All three draft flags
  select observations. Successful opens/rename are distinct from write/delete/
  writable-section requests; none proves a denied operation or actual mapped write.
  Service -> IPC -> Tauri -> UI validates/displays health causes. Older/malformed
  replies are protocol errors; missing/unknown fields never imply readiness.
- Direct process matching uses process object/start key and image volume/file ID;
  ancestors are diagnostic only. Reviewed image content is NOT attested at runtime:
  same file ID does not prove unchanged hash/version. Existing/unobserved processes
  and incomplete identities remain unknown.
- Root trust is invalidated by observed root/ancestor namespace mutations or
  unresolved names. Reconfiguration reopens reviewed root identities and advances
  its validation watermark. Alternate aliases and lower-stack/unobserved changes
  remain unresolved; namespace tokens detect some overlaps, not atomic topology.
- Pre-create uses a read-attributes-only existing-target probe. Identity/kind must
  match the opened object in one observed epoch. Explicit not-found results may
  sample a parent directory with bounded ancestry/root bitmap/configured generation.
  New-file classification requires FILE_CREATED and matching post-open parent,
  epoch, generation and bitmap. Errors are not treated as absence. Transacted,
  unsafe, stale and aliased samples stay unknown.
- Production modules: precreate.c, target_cache.c, ancestry.c,
  namespace_preop.c, namespace_completion.c, namespace_path.c and
  section_observation.c; identity_context.h is internal, not wire ABI.
  The real post-create cache and cleanup now run in the user-mode fault harness.
  The real process notification/table/start-key lookup and lineage propagation
  now also run in the harness. Name/metadata/process APIs, configuration tables,
  atomics and scheduling remain simulated. Kernel builds use the real WDK,
  never tests/include.
- Bounds: 4096 process entries, separate 4096 image/target contexts, 1024 namespace
  completion contexts, 1024 pre-create samples, 32 directory identities per walk.
  Capacity/reference/queue/draining failures release ownership and expose loss.
  Target context allocation/capacity/set failure now reports target degradation.
  Successful queued rename observation may delay completion; latency is unmeasured.
- The walker rejects cross-volume/repeated identities and inconsistent volume
  names, and stops when the epoch expires. Malformed delete intent invalidates
  root trust even for unrelated requestors; valid deletion cancellation skips
  mutation bookkeeping. Root path comparison handles trailing separators.
- ADR0054 defines operation-specific mediation prerequisites. Section
  synchronization is not a generic deny hook, and post-create cancellation
  cannot roll back create/overwrite effects. Cached paths/identities and these
  corroboration samples do not constitute an atomic authorization boundary.

Local evidence:
- Final isolated production-module harness: 227 scenarios / 193,958 assertions
  passed, including real process-table lifecycle, saturation and lineage logic.
  Receipt/logs: .build/piko-guard-tests/ee066dc3039342998ce17ea09bab92f9.
- Final unsigned x64 WDK compile/link passed.
  Receipt/logs: .build/piko-guard/cb47d5269bf34662a329888485d091a4.
- Health-protocol slice: app-control 15, IPC 1 and service 2 focused tests passed;
  affected all-target Clippy, Tauri check, frontend type check, 11 unit tests,
  3 Playwright scenarios and frontend production build passed.
  The later invalid-transport-error mapping passed service all-target Clippy.
  No whole-workspace, formatting or live-runtime gate was rerun.
- Exact commands, failures, receipts and source-review scope are in VALIDATION.md.
  No driver load, installation, active-protection change, remote CI or push.

The configured principal index preserves reviewed SHA-256 as an expectation;
ContentEvidence remains PikoGuardContentUnmeasured. Failed process lookup now
clears output even for a null process, preventing reuse of stale caller facts.

Exact next action: address valid principal/version facts before mediation.
Bind reviewed executable content to the live process (including same-file-ID
content changes and stale attestations) with callback-safe immutable facts;
current process/image ID samples must not authorize enforcement. Define the
actual live-image proof producer before adding a trusted evidence state: a
later disk hash or data-scan section does not attest an existing image section.
Any future immutable facts must bind process start key, image identity, reviewed
digest, configuration generation and revocation generation. Extend the existing
production process-lifecycle harness when adding that producer. Do not acquire
restrictive handles or change access at configured-only publication. Then
implement operation-specific pre-effect authorization with dedicated failure/race
coverage under ADR0054. Package/INF, assigned altitude, signing and disposable-VM
qualification remain open in drivers/piko-guard/QUALIFICATION.md. Preserve
pass-through/not_enforced until all required proof and qualification exist.

Updated: 2026-10-27. Preserve the existing dirty tree; stage explicitly.

## Browser requirement extension (2026-10-25)

The user requested real-time browser protection against saved-credential theft
and malicious-site compromise, supported by cybersecurity research. Expanded
existing requirement 41 instead of adding a duplicate numbered requirement;
clarified requirement 40 must cover reads/copies/mappings as well as writes.
`BROWSER_REALTIME_PROTECTION.md` (preserved local deferred design) contains
R41.01–R41.10, primary sources, threat model, backend/IPC/UI and browser-adapter
boundaries, privacy/failure contracts and an isolated acceptance matrix.
This is documentation only: no protection, browser integration or qualification
was implemented, and no local tests/builds were needed or run for this change.

WORK_QUEUE now has BROW-01 (inventory/capability slice, ready after active
APP-03) and BROW-02 (preventive layers, blocked on qualified prerequisites).
The requirement matrix retains 40/41 as not implemented. APP-03 remains the
deferred source task; first-release priorities above take precedence. Browser
navigation, credential-store reads and endpoint containment must not share an
unqualified aggregate claim of protection.

## Constraints
Targeted local validation is authorized again (2026-10-24); do not treat the
historical source-only notes as a current ban on local checks. APP-03 local
checks are recorded above; isolated script guards and IPC smoke pass locally.
Use existing tools
and dependencies, keep test data isolated from installed runtime/real evidence,
and fix affected failures before proceeding. Source, lockfiles and local build
artifacts are present; no push, remote CI dispatch, installation, driver loading
or live protection change is authorized by this local-checks permission. Windows release
qualification remains incomplete and the candidate is not installed or released.
Retain the agreed 12 months / 2 GiB policy, stop on full. No silent weakening,
quota increase, reserve reduction or evidence deletion to make room.

## First-delivery direction (user approved 2026-10-23)
Scope is frozen in FIRST_RELEASE.md; existing artifact version remains 0.2.0.
Close the first usable monitoring/manual-response delivery, not all116 requirements.
No new graph, storage manager or recovery engine unless an included-path defect
or an acceptance failure requires it. Preserve all source already present.

Current source candidate includes two closure fixes: fresh installer/per-user
profiles use 2048MiB/12months without rewriting existing configurations; Open-Piko
opens the installed UI even if its service is stopped and never starts a parallel
console archive. Portable opening/premature runtime exit also reaches the real
disconnected UI. Package source includes the frozen scope; README/manual defaults
align. Rust, frontend, desktop and available PowerShell fixture checks pass locally.
Installed behavior and release qualification remain unverified.

## Source delivered
- STORE-01 (ADR0048-0050/0052): recoverable v2 raw evidence, local DPAPI key,
  guided external backup confirmation, same-installation key restoration and
  opt-in activation across backend/IPC/Tauri/UI. Defaults remain disabled.
- Added a Playwright UI scenario for STORE-01 (mocked backend only): secret reveal
  consent, wrong-code/external-copy gates, backup confirmation, then separate
  activation consent and monitor-confirmed status. The scenario is source-only and
  was not run under the current no-checks instruction.
- Activation procedure is embedded in the manifest-owned network helper, so
  existing updater snapshot/rollback/resume delivers matching code. No loose
  installed activation script is executed. Bounded stdin/process lifetime,
  hidden PowerShell, no new dependency or FFI.
- Protocol-2 activation journal binds original configuration, confirmed key,
  receipt and installed manifest. Publish flushed journal before changing flags.
  Resume moves forward, never restores disabled flags after possible v2 writes.
  Real runtime IPC confirms completion. Explicit recovery preserves one bounded
  partial stage before rebuilding only from an exact original configuration.
  Desktop resume works while disconnected; CMD fallback uses installed helper.
- STORE-02: compression stages verified rows before checkpoint admission and
  conditionally commits under writer lock; retention retries admission once after
  releasing its reader/transaction and re-verifies the prefix. Writer-locked
  accounting also covers append, protection metadata and offline-copy writes.
  Offline noise-copy admissions include source + destination DB/WAL/SHM within
  one configured quota. External backups remain outside that API's accounting.
- GRAPH-01 (ADR0043/0051): observed genealogy/UDP/temporal evidence, bounded
  observation-time windows and 128-row timestamp/UUID cursor pages through
  storage/IPC/Tauri/UI. No silent fallback, borrowed child attribution or frozen
  archive snapshot; late arrivals and retention can change later pages.
- Earlier guarded update/maintenance source retained (ADR0044-0047), including
  service-identity archive verification and exact transaction resume.

## First-delivery gates and exact next action
1. Source candidate prepared; no feature expansion. Preserve FIRST_RELEASE scope.
2. FIRST-CHECKS: prior local gates passed except Event Log persistence after
   restart. `event-log-smoke.ps1` now rechecks first-run IDs and probe XML outside
   the later 100-row page; isolated query fixtures pass on PS5/7; the actual probe is unrun. Full `ci-checks.ps1` remains
   unrun. PowerShell 7 is available in ignored `.build/tools`. See VALIDATION.md.
3. Windows qualification remains pending under the separate live-runtime boundary:
   clean install, stopped-service UI,
   collection/restart/full capacity, supported response/undo and reachable evidence
   activation/recovery. Existing installed recovery is DEV-02, never an auto-repair.
4. Unsigned package preview built and inspected in ignored `.build`; final matching
   package/checksum review follows Windows qualification. Publication remains unauthorized.

When live-runtime checks are authorized, rerun Event Log smoke against the updated exact-ID query;
preserve the generated benign probe evidence. A repeat failure requires storage
and bookmark diagnosis. FIRST-WINDOWS needs a separate authorized install/live
qualification. The development-only CLI check was skipped because an installed
service was already running; direct local IPC passed. The no-argument runtime
smoke entry point works in PowerShell 5.1.
Do not expand the frozen feature scope or claim installation/release qualification.

## After first delivery (not release blockers by themselves)
Generalized peak-storage accounting across external retained backups; automatic
repair of missing/corrupt/legacy recovery states; portable import; key rotation/
TPM; full-log encryption; signed anchors/distribution; kernel/behavioral prevention,
causal/attack-path/counterfactual engines, version probation and fleet.
Existing safe refusal and truthful limits remain required in included paths.
SQLite admission estimates and source+destination accounting are not hard peak
proofs. Manual maintenance backups need separate free space; no capacity guarantee
for arbitrary 12-month workloads. Qualification failures can reopen an actual
release blocker, but a backlog item alone cannot expand the frozen scope.
## Installed/remote state
Installed runtime/protections untouched. Prior public 3b0653f/run39562792228 does
not qualify this source. Historical UAC cancellation, installed manifest mismatch
and archive capacity issue remain unresolved live. DEV-02 qualification needs
renewed Windows consent; no installation or recovery was attempted here.
