# ADR 0039: observed parent lifetime in process investigations

2026-10-21. Safe Rust collector/core change; existing storage/IPC investigation
command and compact view. No new dependency, native call, privilege or OS policy.

The polling collector can resolve a Windows-reported parent PID to a lifetime
only within a complete single process snapshot. Both processes need creation
FILETIMEs and no access errors; parent creation must strictly precede child
creation. Child creation must be strictly earlier than snapshot start, including
millisecond uncertainty. Missing, duplicated parent PID, reused/newer parent,
self-parent, incomplete snapshot or inaccessible identity remains unresolved.
The native collector already clears PPIDs for queried processes created after
snapshot start. This slice adds no inference from ETW header PID or later snapshots.

The resolved parent uses the existing host/PID/full-FILETIME UUID. A change in
resolution emits a changed observation even when child metadata is unchanged.
Absence events do not acquire a new parent identity. Original process data and
the resolved lifetime remain in raw evidence; causal_parents remains empty.

The investigation graph adds observed_parent edges keyed by lifetime UUID,
never name or reusable PID. It requires compatible known creation times and
retains event/raw references, observed interval and existing 500-event/64-node/
16-reference limits. Millisecond timestamps can round distinct FILETIMEs equal;
the collector performs the strict comparison before normalization. Same-name
parent lifetimes remain separate nodes. Existing IPC carries the result.

The compact view names the parent, paginates five relationships and opens evidence
on request. It explicitly describes historical observations, not necessarily the
current state. Windows-reported parentage is not proof of the initiating actor:
parent selection/spoofing and missing observations preclude causal attribution.
No attack verdict, enforcement, recursive ancestry or potential/counterfactual
path is inferred. Old events without parent instance remain unresolved; evidence
is never rewritten. Live installed collection still depends on DEV-02 deployment.

Acceptance: sensor PID reuse/unknown/partial tests; graph identity/time/reference
tests; normalized record -> real SQLite worker -> GetInvestigation -> IPC JSON
roundtrip; frontend validation and parent-name/evidence browser scenario.
