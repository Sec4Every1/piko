# First-release check script guards, 2026-10-27

Scope: `scripts/ci-checks.ps1`, `scripts/event-log-smoke.ps1` and their new
`CiPreflight.Tests.ps1` / `EventLogPersistence.Tests.ps1` isolated fixtures.

The CI entry point reports every missing required executable before filesystem,
build, dependency or smoke actions. Release compilation precedes updater tests
because their capability probe requires the candidate executable. Both Windows
PowerShell and PowerShell 7 now run the activation, recovery metadata, launcher,
persistence-query and preflight fixtures alongside existing checks.

The Event Log smoke targets its own development pipe instead of the CLI's
installed-service selection. Records absent from the latest 100-row page are
queried individually by their original UUID. The original probe and its raw XML
are rechecked after restart. Exact queries reject malformed IDs before IPC and
refuse absent, mismatched or ambiguous rows. This corrects the test's page-bound
assumption; it does not establish that the earlier live persistence failure is
resolved.

Executed locally on Windows PowerShell 5.1 and PowerShell 7.6.8:

- Persistence fixture: four PASS groups on each runner. Imports only the actual
  production query function from its parsed AST; IPC replies are synthetic.
  Covers bounded exact lookup, malformed identifiers, missing/wrong/duplicate
  rows and a matching row accompanied by unrelated data.
- CI preflight fixture: four PASS groups on each runner. Parses the entry point
  and fixture scripts, then invokes the actual CI entry point with executable
  discovery replaced for three missing-tool sets. Assertions refuse any ensuing
  filesystem, location, OS probe or executable action.
- Targeted `git diff --check` passed.

No Event Log probe, collector, installed service, UAC, dependency installation,
full CI or remote workflow dispatch was run. Actual Event Log persistence across
restart, full release checks and Windows qualification remain open. CI wiring
alone is not evidence that the wired suites or release build passed together.
