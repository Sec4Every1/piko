# Independent dependency CI evidence (2026-10-29)

## Defect and change

Run 40843256431 repeats the root dependency audit failure. The existing entrypoint
throws immediately, so the desktop graph, both Rust SBOMs, npm SBOM/audit and
lock integrity check do not run. A root vulnerability must remain fatal while
independent gates still report their own results.

ci-sbom.ps1 now catches failures at named phase boundaries, runs the remaining
independent phases and throws an aggregate failure at the end. Tool discovery
remains fail-fast. npm install remains a prerequisite for npm audit/SBOM;
SBOM generation remains a prerequisite for copying its graph's files. Direct
generated *.cdx.json files in the evidence destination are cleared before a new
invocation so a failed regeneration cannot retain an older destination SBOM. A failed
frontend SBOM does not suppress npm audit. No audit threshold, lock, advisory
ignore, dependency or product capability changes.

Package path containment now uses full paths plus a directory-boundary prefix
rather than Path.GetRelativePath, which is unavailable on Windows PowerShell 5.
Frontend JSON is written explicitly as BOM-free UTF-8 on both supported shells.

## Verification

Nine fixture scenarios execute the production entrypoint against temporary
synthetic files and mocked cargo/npm/git: all green, root audit failure, both
audits failing, stale core SBOM with failed generation, outside-root metadata,
npm install failure, npm SBOM failure, npm audit plus lock-integrity failure,
and unavailable audit tool. Command order and final failure state are asserted;
every independent result still runs, and stale prerequisite-dependent work does
not run. Both graph manifests and their source files are represented by the mock.

Fixtures retain previous outputs between cases and explicitly verify old destination
SBOMs disappear, including success followed by generation failure.

All nine passed on PowerShell 5.1.26100.8875 and 7.6.8. git diff --check passed.
Fixtures are wired into the dependencies job before tool installation. Tests
install nothing and invoke no real audit tools, network checks or product runtime.
Logs: .build/ci-followup-20261029/dependency-fixtures-ps{5,7}.log.

This is verification of CI orchestration, not a cargo-deny/SBOM qualification.
The actual independent audit outcomes remain pending automatic CI after push;
crypto-bigint remains an unresolved release blocker.

Supplemental current npm lock-only audit on the isolated matching frontend lock
reported zero moderate/high/critical and three low findings (deepmerge plus its
two transitive Svelte Vite dependents), with no available fix reported. No npm
install/update or lock rewrite was performed. This does not replace the complete
CI dependency job. Ignored report: npm-audit-lock.json in the follow-up directory.

## Automatic run 40845440758

On commit 777dd42, the independent CI phases executed. The root Rust audit
failed on RUSTSEC-2026-0387; desktop Rust advisories, bans, licenses and sources
passed. npm audit reported three low issues, no available fix, and no findings
at or above the configured moderate threshold. The final job failure identifies
only the root Rust audit. Windows was still running at inspection. The full
ignored log is dependencies-777dd42.log in the follow-up directory. This result
is not overall dependency qualification and does not authorize a risk exception.

## Upstream refresh

The current crates.io age metadata still reports latest stable 0.12.1. GitHub
API inspection shows rage PRs 648 and 649 open and unmerged. No dependency or
lockfile changed. Automatic run 40846609834 was still in progress at inspection;
its results are not inferred from the previous run.
