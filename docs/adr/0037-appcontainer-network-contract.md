# ADR 0037: per-trial network capability selection

2026-10-21. AppContainer trial scope only; installed app permissions unchanged.

Each trial prepares None (default) or InternetClient network access. The mode and
count are frozen with executable identity in the single-use plan and session.
Native code accepts a closed enum, not arbitrary capability names/SIDs. Internet
mode constructs exactly WinCapabilityInternetClientSid via CreateWellKnownSid.
This new FFI stays inside win-platform; no dependencies or global policy changes.

Before resuming the suspended process, existing AppContainer/job checks additionally
verify the complete capability count, bounded SID pointer, exact SID bytes and
enabled attributes. Unexpected/deny-only/extra capabilities fail closed. The
one-process/512-MiB job, staged read-only exe, environment filtering, original-file
protection and stop/profile cleanup remain. No normal-execution fallback exists.

The UI defaults to denial, shows the requested expansion before consent and
invalidates preview/consent after edits. Responses with different network modes
are rejected; uncertain launches still expose owned trials for cleanup. Legacy
responses without mode are accepted only for zero capabilities. Sessions display
their frozen mode independently of the next preview's selection.

Benign native qualification created actual processes in both modes, verified
readiness after token inspection, then stopped/removed them and confirmed original
hashes. No network traffic was generated. Outbound connectivity is not qualified;
loopback is not a valid substitute. No private-network/server capability or
loopback exception is added, and existing Firewall policy still applies.

References: [Microsoft AppContainer launch](https://learn.microsoft.com/en-us/windows/win32/secauthz/implementing-an-appcontainer),
[capability SIDs](https://learn.microsoft.com/en-us/windows/win32/secauthz/capability-sid-constants).
This is not persistent per-installed-app file/system/update mediation or automatic
probation of new versions.
