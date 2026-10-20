# 0021 — AppContainer trials of an explicit executable copy

Status: implemented, normal-user native fixture verified on 2026-10-12.

## Scope

`app-control/restricted` prepares a five-minute, single-use plan bound to the
canonical executable path and SHA-256. Preparation only reads. After an explicit
UI confirmation, launch rechecks the source under held file/parent handles and
copies one executable into a new UUID directory owned by piko. Installed files,
their ACLs, existing user directories, Firewall policy and services are unchanged.

The process is created with an AppContainer profile unique to the UUID, no
capability SIDs, a child-process denial policy, and an anonymous job containing at
at process creation. The initial thread is suspended until piko verifies the
AppContainer token, matching package SID, zero capabilities and job membership.
There is no fallback to ordinary execution on any failure.

Only new staging file/directory DACLs are changed: SYSTEM and the current user
retain full access; the new package SID receives read/execute. The verified copy
and parents stay open without write/delete sharing for the entire trial. No
arguments, shell, UAC or inherited handles are used. A minimal environment excludes
the parent's environment secrets; local app-data is obtained from the Windows
known-folder API before Windows redirects it to the AppContainer profile.

## Ownership and limits

Win32 FFI remains in `win-platform/restricted.rs`; orchestration and UI remain
safe Rust and TypeScript/Svelte. Handle, SID, security-descriptor and attribute
allocations have RAII cleanup. Handles are process-wide, stored as owned integer
values and never exposed to the frontend. Profile creation refuses an existing
name and refuses an elevated caller. Profile removal uses only the newly created
owned name.

Maximum two live trials, eight pending plans, four staging directories and one
256-MiB executable per trial. `stop_restricted` terminates only the owned job,
waits for the owned process handle, removes the fixed copy/empty staging directory
and asks Windows to remove the owned profile. UI process exit also closes the job
and attempts cleanup. Failed cleanup is surfaced on explicit stop; a crash or
cleanup failure can leave staging/profile data. There is no recursive host-file
deletion or path accepted from the frontend for cleanup.

## What this does not enforce

This is a separately launched **copy on the host**, not a VM or a permission rule
covering all instances of the installed app. AppContainer access follows Windows
ACLs: shared Windows files, registry keys and other resources may be readable
outside the installation folder. piko adds no personal-data access. The profile
has writable private data. No capability enables direct network access; Windows
broker behavior and pre-existing loopback exemptions remain platform policy.
The original installation and its updates are not frozen. The held executable
copy cannot be modified during the trial, but neither CPU usage nor profile disk
usage is capped. DLLs, app data, dependency trees and licensing state are not
copied; many desktop apps will fail to run with these restrictions.

AppContainer is used with documented Win32 APIs; no C migration, driver, hooking
or new global security policy is justified by this component. Windows Sandbox
remains the separate choice for a disposable VM trial.

## Verification

Four unit tests passed: plan cancellation/expiry/replay and changed source are
rejected before effects; profile names and attribute allocation are bounded.
Two frontend parser tests reject missing execution state or weaker policy DTOs.

An explicit ignored native test compiles its own harmless Rust fixture, then
launches only that copy. The fixture attempts a loopback connection to a test-owned
listener, child creation, writing its own staged executable and reading a private
fixture file. All are denied on this host; its private profile permits the test
report. The parent environment marker is absent. Stop removes the copy and profile,
leaves the original SHA-256 unchanged, and clears live session state. This verifies
those operations on this host; it is not malware analysis, universal compatibility
or a claim that every outside-folder access is denied.

Run the explicit native qualification:

```powershell
cargo test -p piko-app-control restricted::tests::native_fixture_has_denials_and_cleans_up --offline -- --ignored --nocapture
```

Sources: [AppContainer launch/token/ACL contracts](https://learn.microsoft.com/en-us/windows/win32/secauthz/implementing-an-appcontainer),
[profile creation](https://learn.microsoft.com/en-us/windows/win32/api/userenv/nf-userenv-createappcontainerprofile),
[process attributes](https://learn.microsoft.com/en-us/windows/win32/api/processthreadsapi/nf-processthreadsapi-updateprocthreadattribute),
[AppContainer folder path](https://learn.microsoft.com/en-us/windows/win32/api/userenv/nf-userenv-getappcontainerfolderpath).

