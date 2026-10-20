# ADR 0035: bidirectional batches, undo and helper lifetime

2026-10-20. Source implementation; installed runtime qualification remains open.

The application grid can prepare outbound/inbound rules together, and remove
verified piko rules for selected executables/directions. The native per-direction
plan/confirmation path is reused; no new Firewall template or global policy change
is introduced. Limits remain 10 applications, 20 executable paths and 32 plans.
Removal reads a complete current snapshot and remains possible when policy prevents
new blocks. Changed/unselected rules are excluded. Failed preparation discards
already prepared plans; execution stops on first error and preserves individual
direction-specific outcomes. Completed changes are not automatically rolled back.

Previously a 60-second wait could return while an elevated helper remained alive.
A refreshed snapshot cannot exclude future effects from that helper. The blocking
worker now waits for terminal helper completion. Each plan includes its originating
process PID and creation FILETIME (decimal string, avoiding JavaScript precision
loss). The helper takes a cross-process global mutex without waiting, verifies
origin identity/liveness, and checks liveness again immediately before mutation.
The guard remains held through final audit. A delayed helper from a closed desktop
is rejected; an already-started change can finish after the desktop closes, while
the mutex excludes another concurrent helper. These are scheduling/lifetime
controls, not a new authorization source or packet-filtering proof.

Win32 handles use RAII; the mutex guard is thread-bound. Minimal process query and
synchronize rights suffice. No dependency or global OS permission is added. Access
denial, mismatched origin and busy/abandoned mutex fail closed. Desktop and helper
must be rebuilt together: legacy payloads omit mandatory origin and are rejected.
Alternate administrator credentials and global-namespace access remain platform
qualification cases. A hung helper keeps its caller pending; automatic termination
or cancellation of an in-progress COM mutation is not implemented.

Validation uses browser bridge fixtures and benign native subprocesses, without
changing real Firewall policy. See VALIDATION.md for results. Live packet tests,
OS restart and installed upgrade qualification are not implied by those fixtures.
