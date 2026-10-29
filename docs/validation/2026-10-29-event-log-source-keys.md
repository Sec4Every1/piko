# Event Log smoke source-key verification (2026-10-29)

## Reviewed gaps

The existing restart check queried older UUIDs outside the latest 100-row page,
but duplicate detection grouped only that page. A replay with a different UUID
could remain outside it. First-run diagnostic discovery also searched only the
same general Windows page, so a busy System channel could hide an Application
probe already persisted correctly. The original eight-second first lifetime left
about three seconds for all IPC checks after fixed startup sleeps.

## Source changes

The restart stage now queries each first-run sampled Windows source identity
(sensor.id plus target.identifier) with limit two and requires exactly one row
with the original UUID and identity. This detects missing/replaced/replayed rows
even outside the newest page. The actual diagnostic record is included in this
sample even if absent from the general page. Summary wording explicitly describes
sampled source-key uniqueness; this is not an exhaustive archive duplicate scan.

Probe discovery uses an independent bounded Application/piko query, then verifies
the fresh token in raw XML as before. A saturated 128-candidate page refuses as
inconclusive. It does not assert absence from a truncated page. Quoted source keys
use JSON encoding, matching the existing query language; malformed/oversized keys
refuse before IPC. The general page duplicate guard remains as an extra check.

Finite service lifetimes are now 30/60 seconds instead of 8/20, providing more
verification time. This is margin, not a proof that arbitrary slow/hung IPC will
complete: no new operation-level timeout mechanism is claimed. CI retains its
outer timeout and finally cleanup. No installed runtime settings are changed.

## Verification and limits

Production functions are extracted by PowerShell AST without executing collection
or emitting an Event Log probe. Nine assertion groups pass on PowerShell 5.1 and
7.6.8: malformed UUIDs, older exact UUID lookup, missing/ambiguous rows, parsing,
source-key retrieval, missing/replaced/replayed source keys, malformed source
identities, escaped query literals, and provider-specific probe lookup/saturation.
The existing CI preflight fixtures also pass on both shells. git diff --check
passes. Logs: .build/ci-followup-20261029/event-source-ps{5,7}.log.

These PowerShell fixtures verify query construction and refusal behavior against
synthetic IPC responses. An additional Rust integration regression reopens a real
isolated SQLite store, inserts a replay with a new UUID/runtime and 150 newer
records, confirms both original and replay are absent from the latest 100, and
recovers both through the exact source-key and provider queries. It also verifies
the integrity of all 152 synthetic records. The targeted test, affected storage
integration-target Clippy and formatting pass on the existing Windows GNU
rustc 1.93.1 toolchain. Logs: event-source-storage{,-clippy}.log in the follow-up
directory. This adds direct SQL/parser/storage verification without real evidence.

Real Windows collection/bookmark persistence and new full IPC/timing behavior
await automatic Windows CI. No live probe,
service installation, driver, real evidence or protection change was performed.
