# Browser registration inventory: first vertical slice

The local BROW-01 slice classifies bounded machine uninstall-registry metadata
as unverified Edge, Chrome or Firefox candidates. It never reads browser profile
or secret data, does not treat the service account HKCU as the viewer, and does
not establish that a candidate executable, profile or browser protection exists.
The UI shows these limitations and exposes incomplete scans and failures. Exact
name matching misses some installations; portable and user-only installations
are explicitly not ruled out. Registry labels/version/publisher are claims, not
identity or provenance proof.

A single-flight blocking worker prevents requests from accumulating unbounded
registry scans even if the client times out. Results traverse service, IPC,
Tauri and UI. Source and output bounds, invalid data and scope failures are
covered by synthetic tests. No installed service or real browser data was used.

## Local verification

- Offline locked workspace GNU: security-core browser inventory 4 tests,
  service browser inventory 4 tests, IPC browser inventory 1 test.
- Full frontend unit suite: 121 tests; focused Chromium UI scenario: 1 test.
- Svelte/TypeScript check, frontend production build, Tauri check and CLI check.
- New Rust modules: rustfmt check; security-core all-target Clippy passed.
- Service/IPC Clippy passed with duplicated_attributes allowed: strict Clippy
  otherwise stops on an existing duplicate cfg in deferred filter_manager.rs.
  Vendor i18n-config produced two warnings. The default MSVC linker is absent.

Logs remain under ignored `.build/browser-*.log`. The browser scenario uses a
mocked desktop bridge, not a real registry-to-UI run. These results do not
qualify installed behavior, profile coverage, executable identity, preventive
capability or a release. The new vertical slice is mixed with pre-existing dirty
APP-03 changes; review and isolate exact dependent source before committing.

## Isolated exact-source candidate

A separate ignored snapshot from development commit 210af8f contains only the
12 browser-slice files, excluding the deferred APP-03 changes. In that snapshot,
4 core, 4 service and 1 IPC tests, 110 frontend unit tests and one Chromium
scenario passed; frontend type check/build and GNU locked offline CLI/Tauri
checks passed. Strict all-target Clippy for core/service/IPC and rustfmt checks
passed on the isolated snapshot; vendor dependency warnings remain visible.
The UI test uses synthetic IPC responses; no real registry or installed runtime
was exercised. Candidate logs are in the ignored candidate directory.
