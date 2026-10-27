# ADR 0043: bounded navigation of observed process genealogy

## Validation update, 2026-10-27

Relevant selected source has now passed the local checks recorded in [2026-10-27-history-core.md](../validation/2026-10-27-history-core.md), [2026-10-27-history-storage.md](../validation/2026-10-27-history-storage.md), [2026-10-27-history-backend.md](../validation/2026-10-27-history-backend.md), [2026-10-27-history-desktop.md](../validation/2026-10-27-history-desktop.md).
The original decision below records its source-only state at the earlier date;
its deferred-check and missing-integration statements are historical, not the
current execution instruction. See [NEXT_SESSION](../NEXT_SESSION.md) for
remaining gates. Installed Windows behavior, UAC/SCM/DPAPI recovery and security
qualification remain open. Protection defaults remain off; no current host
configuration was changed. Local checks do not imply a completed dependency
security audit, portable archive import or release qualification.

## Original decision and limitations


2026-10-22. Development source only, unverified at the user's explicit request.
No tests, Clippy, format commands, builds or CI dispatch for this slice.
No new dependency, native boundary, privilege or OS policy change.

Investigation nodes optionally expose an instance UUID. The requested process
and validated parent/child nodes have one; identity and endpoint nodes do not.
Parent legacy responses without an instance remain readable but not navigable.
Observed child edges require a process snapshot with the requested parent UUID,
known compatible creation times, a distinct nonnil child instance and distinct
PID. Root labels come from the parent context in child events; the child's SID
and network observations never become associations of its parent.

The existing GetInvestigation IPC now retrieves own observations plus child
snapshots referencing process.parent_instance. That query field maps to a fixed
JSON expression with the existing bound-parameter grammar. The UI query builder
also exposes it. Events, raw evidence and stored normalized records are unchanged.

UI parent/child navigation loads one real investigation on demand, at most eight
links from the initial process. The trail stores UUIDs only; revisiting a trail
instance is refused and Back/Initial controls remain available. Each view retains
five relationships per page,500 events,64 nodes and16 references per edge.
No unbounded tree or graph cache. Empty observations remain explicitly unknown.
An asynchronous generation guard rejects replies belonging to a previous root;
child-edge evidence is opened using the child's process instance rather than
the displayed parent. Different levels can cover different historical intervals:
the navigation does not establish a simultaneous causal path or initiating actor.

The graph also admits existing normalized local UDP binds, clearly separated
from TCP. No remote UDP destination, sent packet or communication content is
inferred. Account display names are used when available; identity keys remain SIDs.

Deferred validation: Rust/TypeScript compilation, IPC compatibility, child
attribution, matching-instance evidence, changed-root/in-flight replies, cycles,
eight-level bound, old responses, absent history and narrow viewport behavior.
Old automated results do not cover these source changes. No package/install claim.
