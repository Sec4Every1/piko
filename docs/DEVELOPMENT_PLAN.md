# Piko: development and delivery workflow

## Accepted direction, 2026-10-27

Complete the first usable monitoring/manual-response release defined in
[FIRST_RELEASE.md](FIRST_RELEASE.md). Keep its scope frozen. Preserve existing
APP-03/browser experiments and their `not_enforced` status; they follow this
release. Current state and exact next action belong in
[NEXT_SESSION.md](NEXT_SESSION.md); priorities belong in
[WORK_QUEUE.md](WORK_QUEUE.md).

"Continua/vai avanti" confirms this direction. Continue through finite outcomes
without requesting repeated approval or stopping merely to record a checkpoint.
Ask for missing access, environment or product decisions while continuing
independent authorized work. A checkpoint records progress; it is not completion.

## Delivery sequence

1. Consolidate accumulated included source into coherent commits. For mixed
   files, select only relevant hunks and verify an exact-source snapshot.
2. Close included source defects and FIRST-CHECKS. Run affected checks with
   existing tooling/dependencies; fix failures before advancing. Record commands,
   results and limits in focused validation notes, not repeated chat history.
3. Qualify FIRST-WINDOWS in an available, authorized isolated Windows environment:
   install, collection/restart/reconnect/full archive, supported response/undo
   and reachable recovery paths. Preserve the current host runtime.
4. Inspect a matching package and checksums. Label unsigned previews accurately.
   Source/build success alone does not qualify installed security behavior.

## Authorized work and boundaries

Targeted local tests, compiler/type checks, Clippy, formatting and affected builds
are authorized. Use isolated temporary data and existing tools/dependencies;
never rewrite lockfiles or install tools merely to enable a check. Avoid duplicate
builds/checks unless a change, failure or unresolved concern justifies them.

Reviewed, relevantly checked source may be committed locally and pushed to
`development/first-release`. Review exact staged scope and private data/artifacts
before each push; preserve unrelated changes and never use broad staging.
Main merges, releases and manual remote CI dispatch remain separate.

Installation, driver loading and live protection changes are not authorized by
local validation. Event Log emission/runtime qualification also remains a
distinct boundary. Recovery never silently removes guards, replaces evidence,
weakens protection or changes configured retention/quota to make room.

## Coordination and resumption

Read repository instructions, NEXT_SESSION, the active queue item and Git status.
One coordinator owns integration and final verification. Use one bounded helper
when independent work materially helps; assign owned files, exact outcome,
checks and exclusions. Avoid simultaneous shared-file edits and duplicate builds.

At a milestone or interruption replace stale checkpoint state with outcome,
evidence, blocker and exact next action, then continue if authorized work remains.
Do not activate scheduled runners, create duplicate persistent goals, expand the
release scope or promise unattended execution based on this document alone.
Deferred APP-03 technical restart details remain in NEXT_SESSION and ADR0054;
their presence does not move them ahead of the first-release gates.
