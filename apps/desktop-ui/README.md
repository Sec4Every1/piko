# piko desktop

Unprivileged Svelte 5 / TypeScript presentation layer, packaged with Tauri 2. Detection rules, authorization, quarantine and recovery run in the Rust backend. Version 0.2.0 presents real Event Log alerts and confirmed file actions; it does not provide general endpoint prevention.

## Development

```powershell
npm ci
npm run dev
```

The standalone browser preview is at `http://127.0.0.1:1420`. It intentionally reports an unavailable runtime: it does not substitute demo events. Start the native desktop app with `npm run tauri dev` after starting the local runtime as described in the root README.

```powershell
npm run check
npm test
npm run build
npm run test:ui:install
npm run test:ui
```

The browser installer downloads a headless test browser under `node_modules/.cache/ms-playwright`; it does not install a system browser. Browser tests cover unavailable-service presentation, filtering, keyboard navigation, English/Italian localization, persistent appearance preferences, live system theme changes and a narrow viewport. Unit tests contain synthetic fixtures only under `*.test.ts`; no fixtures are imported by the production app.

## Native contract

Typed commands are used through `@tauri-apps/api/core`. Query commands are available to the enrolled viewer; response mutations are authorized by the runtime independently of UI controls:

| Command | Arguments | Response |
| --- | --- | --- |
| `get_health` | none | `common-model::HealthSnapshot` |
| `list_events` | `{ filter: { limit, search?, severity?, event_type?, since_unix_ms? } }` | `event-schema::SecurityEvent[]` |
| `verify_store` | none | `{ verified_events, head_hash, externally_anchored: false }` |
| `get_evidence` | `{ evidenceId }` | Original raw evidence |
| `list_alerts` | none | Up to 100 explainable detections |
| `response_status` | none | Authorized roots, limits and last 100 actions |
| `prepare_quarantine` | `{ path }` | Expiring preview with exact file identity/hash |
| `prepare_restore` | `{ actionId }` | Preview of non-overwriting recovery |
| `execute_action` | `{ actionId, expectedSha256 }` | Journaled result; never blindly replayed |
| `open_attack_reference` | `{ techniqueId }` | Opens only one of three compiled-in official MITRE HTTPS pages in the default browser; not a runtime/privileged command |

The presentation boundary validates response structure and schema version. Invalid values produce a visible error, never a healthy default. Unsupported unsafe integer values are rejected, rather than silently displaying rounded counters or event sequence identities. Source identifiers, evidence and technical messages are shown verbatim, using escaped Svelte text. Source state `active` means operational telemetry, not endpoint protection.

Dashboard reads up to 100 persisted detections, sorts them by priority and excludes raw runtime heartbeats. It explains each supported rule version in plain language, distinguishes observed behavior from possible ATT&CK context, and provides manual remediation guidance. Raw Windows XML can be read as labeled source fields or expanded as escaped text. Unknown rule versions get no invented mapping. Failed reads retain explicitly stale data and do not become a reassuring zero count.

Technical logs requests up to 200 filtered events, including heartbeats; JSON export contains precisely the loaded result set. Filters are submitted explicitly. Dashboard, file actions, logs and Settings refresh every 15 seconds while visible. Guide is static documentation; App permissions reads actual inventory and Firewall status on entry and explicit refresh. Closing the UI terminates the frontend and its polling; the runtime has a separate lifecycle. App permissions prepares and confirms outbound executable-path blocks through the native helper; file/device/child-process controls are explicitly unavailable.

Hash verification is explicitly local and has no external anchoring. The UI does not claim that successful local verification prevents wholesale log rewriting. Automatic retention is unimplemented; the disk budget is configured by the runtime, outside this UI.

## Presentation

Italian is the default language; reviewed alert explanations and the in-app guide also support English. Original technical runtime details remain as supplied by the backend. Blue indicates navigation/information, amber partial coverage or review, red high priority/errors, violet recovery, and green verified outcomes. Language and system/light/dark appearance are stored in local UI preferences. Response confirmations are explicit runtime actions, not preferences. No telemetry is sent externally, fonts are local, and no remote assets are loaded. Official MITRE pages open externally only on an explicit click, through an exact technique-ID allowlist; arbitrary URLs, paths and shell commands are rejected.

`Ctrl+K` opens page navigation and event search. Native modal dialogs provide focus trapping and Escape dismissal. Semantic controls, focus indicators, textual status, reduced-motion support and high-contrast adjustments are included. A complete accessibility audit is still required before production release.

## Application network controls

`software_inventory` and `network_snapshot` use local, read-only Windows adapters.
`prepare_network_action` and `execute_network_action` delegate to safe Rust app-control;
the latter consumes a stored plan and invokes the adjacent `piko-network-helper.exe`
via Windows UAC. Package all four binaries together. For development, copy the helper
from the workspace `target/debug` next to `src-tauri/target/debug/piko-desktop.exe`.
No framework or browser fixture grants privileges. See ADR 0010 and the user manual.
