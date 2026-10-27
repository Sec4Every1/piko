# Guided evidence-key desktop and helper integration

Base: 28c458c. Consolidates the native/TypeScript/Svelte key flow, helper purpose
dispatch and embedded activation source. Backup disclosure, matching-code
confirmation and activation have separate steps/consent. Pending activation
can use a dedicated resume request while service IPC is unavailable.
The UI states that a ready key does not mean encryption is enabled and that
normalized events/indexes and historical plaintext are not encrypted by this flow.

Included: network-helper main/key module/tests; native key module and command
registration hunks; EvidenceKeys component/types/tests, ArchiveUsage integration,
the required API error-code addition; key-only browser fixtures/scenario;
read-only maintenance/evidence-key-status CLI command/help; embedded
Enable-PikoEvidenceProtection.ps1 and its isolated function fixtures.
APP-03 and the unused volume-GUID platform changes are excluded. No dependency,
manifest or lockfile changes are included.

The helper now resolves Windows PowerShell through the existing native
windows_directory boundary instead of the SystemRoot environment variable.
No new FFI is introduced. It executes only its compiled-in constant activation
source, with bounded stdin/process lifetime and hidden child windows; no secret
is placed in command arguments. Read-only CLI status is an actual prerequisite
of the embedded script's runtime confirmation and is included here.

## Selected-source checks

Checks used an archived baseline plus exactly the selected source/hunks:

- Frontend Svelte/TypeScript check: zero errors/warnings; production build passed.
- Six new frontend tests passed: status consistency, bounded/expired tickets,
  matching backup reply, recovery-code input, no native invoke for invalid input,
  and secret-safe invocation errors. No speculative regex defect was found.
- Two Chromium scenarios matched the recoverable filter and passed: the guided
  backup/re-entry/separate-activation scenario and an existing browser-error case.
  The guided scenario uses a synthetic native bridge, not installed IPC/UAC.
- Five helper negative decoding tests passed before privilege/IPC/process paths.
  Initial test expect calls were replaced to meet project Clippy policy.
- Helper/CLI all-target Clippy with -D warnings, targeted Rust formatting,
  offline locked helper/CLI debug build and separate Tauri cargo check passed.
- CLI --help exposes both read-only status commands without accessing IPC.
- Four selected production activation-function cases passed on Windows
  PowerShell 5.1 and PowerShell 7.6.8: exact baseline, no-overwrite durable create,
  malformed hash refusal and changed-receipt preservation. The harness extracts
  function ASTs; top-level activation, services, UAC and ACL writes never run.

Snapshot/logs: .build/consolidation-key-desktop-20261027, key-ui-check.log,
key-ui-build.log, key-ui-tests.log,
key-ui-playwright.log, helper-tests.log, helper-clippy.log, helper-build.log,
key-tauri-check.log and activation-fixtures-ps5/ps7.log.

Package recovery wrappers named by the UI still require their separate coherent
installer/updater/packaging checkpoint. Existing code and tests do not qualify
installed UAC/SCM activation, actual backup media, key restoration, interrupted
service updates or process termination behavior. No host installation, active
protection, real evidence, main merge, release or manual remote CI dispatch changed.
