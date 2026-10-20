# ADR 0033: account lifecycle facts

2026-10-20. Accepted, partial identity monitoring.

Extend the existing read-only authentication activity endpoint with Security
events 4720 (created), 4722 (enabled), 4725 (disabled) and 4726 (deleted), version 0.
Reuse the existing collector, raw XML validation, SQLite snapshot/cursor and
five-row Svelte panel. No additional collection, permissions, FFI or dependency.

The affected account uses TargetUserName, TargetDomainName and **TargetSid**,
not TargetUserSid. The requesting account uses Subject fields. SubjectLogonId
does not identify a new session for the affected account. Execution PID is the
event provider, not an attributed caller: process/address/logon-type fields are
not exposed for these event kinds. Unknown versions, missing or mismatched raw
remain explicit. These are historical facts, not current account state.

The view provides account names, suggested checks and access to original
evidence. It does not veto account creation, change account permissions, restore
accounts or infer malicious intent. Existing dashboard detection is unchanged.
Availability depends on Windows auditing, Security access and retained evidence.
Enabling/disabling events can also describe computer accounts.

Microsoft schemas:
- https://learn.microsoft.com/en-us/previous-versions/windows/it-pro/windows-10/security/threat-protection/auditing/event-4720
- https://learn.microsoft.com/en-us/previous-versions/windows/it-pro/windows-10/security/threat-protection/auditing/event-4722
- https://learn.microsoft.com/en-us/previous-versions/windows/it-pro/windows-10/security/threat-protection/auditing/event-4725
- https://learn.microsoft.com/en-us/previous-versions/windows/it-pro/windows-10/security/threat-protection/auditing/event-4726

Validation covers field attribution, unsupported versions, pagination/filtering
without archive mutation, frontend kind/event mismatch and UI detail/raw flow.
Fixtures are synthetic: no real account is created, disabled or removed by tests.
