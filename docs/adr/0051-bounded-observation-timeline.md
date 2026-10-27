# ADR 0051: bounded temporal observations in investigation

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


2026-10-23. SOURCE UNVERIFIED. No tests/builds/checks/CI or live deployment.

The existing investigation query/IPC/Tauri path now carries the individual
observations behind the graph. Admission stays limited to the root instance's
process/TCP/UDP snapshots and validated child process snapshots. Child network
activity/identity is never attributed to the root. Entries carry event UUID,
optional original-evidence UUID, actual process instance, its own name/path,
event type and observation timestamp. Missing names use that instance UUID.

Retain at most128 entries from the existing500-event sample. Label bounds8192
bytes individually and64KiB combined keep serialized growth within the existing
IPC budget, including JSON escaping. Explicit truncation covers omitted rows or
oversized-label fallback. Stable ordering is observation time then event UUID;
ties do not establish action order. No causal inference or attack verdict.

An explicit observations_available field defaults false on deserialization, so
older services cannot silently appear to have an empty timeline when a newer
Tauri client supplies serde defaults. New responses set it true. The frontend
validates limits, types, ordering, duplicate references, UUIDs and label budget.

The collapsed sequence shows five rows per page, program search, process/TCP/UDP
filters and oldest/newest ordering. All filters apply only to the loaded sample.
Each row opens its own event using both event UUID and actual process instance;
the existing detail offers raw evidence. Navigation/remount cancels stale replies
and resets pagination. No archive copies, collection changes, dependencies or FFI.

The additional GetInvestigationWindow command takes typed UTC millisecond bounds
and applies event.observed_at >= from AND < until before the SQL limit. The new
static numeric query field reads observation_time from stored normalized payload;
it never substitutes event wall time. The previous command remains unchanged.
No supplied SQL column or expression fragments are accepted from the UI. Invalid,
negative, inverted and out-of-JavaScript-date-range bounds are refused in service
and Tauri. Existing queue, deadline, query-byte and501-row read bounds remain.

A collapsed period picker uses local datetime input, explicitly excludes the end
and labels the loaded range. Parent/child navigation keeps that range. Failed
loads retain the previous graph/range; returning to the original instance clears
filters only when the external root changes. Old services may refuse the new
command; there is no fallback that silently ignores requested bounds.

This is a temporal evidence view, not a causal/attack-path engine or simultaneous
complete genealogy. Observation timestamps can differ from action times and host
clock changes can affect order. Cursor pagination within a dense period remains open.
Deferred checks include bounded escaped output, old/new service compatibility,
child attribution, time ties, omitted names, filter/page resets, time-window
boundary and old-command compatibility, SQL deadlines and stale replies.

## Cursor extension — source unverified (2026-10-23)
Storage now queries 128 rows plus one lookahead ordered by observation time/UUID; IPC GetInvestigationPage and Tauri/UI preserve the period and expose an older-page cursor. No silent fallback. Label budget reserves UUID fallbacks. Pages replace graph relationships; retention and late arrivals mean this is not a frozen snapshot. Deferred: timestamp ties, cursor progress, malformed responses, empty admitted pages, old-service errors and stale replies. No checks executed.
