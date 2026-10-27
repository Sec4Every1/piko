use std::{
    io::{self, Write},
    os::windows::process::CommandExt,
    process::{Command as ProcessCommand, Stdio},
    time::{Duration, SystemTime, UNIX_EPOCH},
};

// The updater snapshots this executable, so activation code moves and rolls
// back with the authorized helper. Never execute a loose installed script.
const ACTIVATION_SOURCE: &str = include_str!("../../../scripts/Enable-PikoEvidenceProtection.ps1");

fn now_ms(denied: impl Fn() -> io::Error) -> io::Result<u64> {
    u64::try_from(
        SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .map_err(|_| denied())?
            .as_millis(),
    )
    .map_err(|_| denied())
}

pub(super) fn resume_activation() -> io::Result<()> {
    if !piko_win_platform::current_process_elevated()? {
        return Err(io::Error::other(
            "Windows authorization required for activation recovery",
        ));
    }
    // The embedded procedure requires an existing exact journal. This entry
    // cannot create a fresh activation or bypass backup confirmation at startup.
    run_activation_script(true)
}

fn run_activation_script(resume: bool) -> io::Result<()> {
    let denied = || io::Error::other("evidence protection activation was refused");
    if ACTIVATION_SOURCE.len() > 64 * 1024 {
        return Err(denied());
    }
    // Resolve the OS directory through the existing native boundary, rather
    // than selecting an elevated executable from a caller's environment.
    let powershell = piko_win_platform::network_elevation::windows_directory()
        .map_err(|_| denied())?
        .join("System32")
        .join("WindowsPowerShell")
        .join("v1.0")
        .join("powershell.exe");
    if !powershell.is_absolute() || !powershell.is_file() {
        return Err(denied());
    }
    // Only constant source enters stdin; no secret or path is interpolated into
    // PowerShell code. A small fixed command avoids the Windows argv size limit.
    let command = if resume {
        "$ErrorActionPreference='Stop'; try { [Console]::InputEncoding = New-Object Text.UTF8Encoding($false); & ([scriptblock]::Create([Console]::In.ReadToEnd())) -ResumeInterruptedActivation; exit 0 } catch { exit 1 }"
    } else {
        "$ErrorActionPreference='Stop'; try { [Console]::InputEncoding = New-Object Text.UTF8Encoding($false); & ([scriptblock]::Create([Console]::In.ReadToEnd())); exit 0 } catch { exit 1 }"
    };
    let mut child = ProcessCommand::new(powershell)
        .args([
            "-NoLogo",
            "-NoProfile",
            "-NonInteractive",
            "-ExecutionPolicy",
            "Bypass",
            "-Command",
            command,
        ])
        .stdin(Stdio::piped())
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .creation_flags(0x0800_0000) // CREATE_NO_WINDOW; consent belongs to the desktop helper.
        .spawn()
        .map_err(|_| denied())?;
    let Some(mut input) = child.stdin.take() else {
        let _ = child.kill();
        let _ = child.wait();
        return Err(denied());
    };
    // Feed on a bounded helper thread so even a child that never drains stdin
    // cannot prevent the parent enforcing its operation deadline.
    let writer = match std::thread::Builder::new()
        .name("piko-activation-input".into())
        .spawn(move || input.write_all(ACTIVATION_SOURCE.as_bytes()))
    {
        Ok(writer) => writer,
        Err(_) => {
            let _ = child.kill();
            let _ = child.wait();
            return Err(denied());
        }
    };
    let deadline = std::time::Instant::now() + Duration::from_secs(150);
    let status = loop {
        match child.try_wait() {
            Ok(Some(status)) => break status,
            Ok(None) if std::time::Instant::now() < deadline => {
                std::thread::sleep(Duration::from_millis(100))
            }
            _ => {
                let _ = child.kill();
                let _ = child.wait();
                return Err(denied());
            }
        }
    };
    if !matches!(writer.join(), Ok(Ok(()))) {
        return Err(denied());
    }
    if !status.success() {
        return Err(denied());
    }
    let deadline = std::time::Instant::now() + Duration::from_secs(35);
    loop {
        let result = tokio::runtime::Builder::new_current_thread()
            .enable_all()
            .build()?
            .block_on(async { piko_ipc::call(piko_ipc::Command::GetEvidenceKeyStatus).await });
        if matches!(result, Ok(piko_ipc::ApiData::EvidenceKeyStatus(ref state)) if state.backup_confirmed && state.new_raw_enabled && state.recoverable_mode && !state.activation_pending)
        {
            return Ok(());
        }
        if std::time::Instant::now() >= deadline {
            return Err(denied());
        }
        std::thread::sleep(Duration::from_millis(250));
    }
}

pub(super) fn try_authorize(encoded: &str) -> Option<io::Result<()>> {
    if encoded.is_empty()
        || encoded.len() > 24576
        || !encoded.len().is_multiple_of(2)
        || !encoded.bytes().all(|b| b.is_ascii_hexdigit())
    {
        return None;
    }
    let bytes: Vec<u8> = (0..encoded.len())
        .step_by(2)
        .map(|i| u8::from_str_radix(&encoded[i..i + 2], 16))
        .collect::<Result<_, _>>()
        .ok()?;
    let value: serde_json::Value = serde_json::from_slice(&bytes).ok()?;
    let purpose = value
        .get("purpose")
        .and_then(serde_json::Value::as_str)?
        .to_owned();
    if !matches!(
        purpose.as_str(),
        "evidence-key-backup-v1"
            | "evidence-protection-activation-v1"
            | "evidence-protection-resume-v1"
    ) {
        return None;
    }
    let denied = || io::Error::other("evidence key operation was refused");
    Some((|| {
        if purpose == "evidence-protection-resume-v1" {
            let request: piko_ipc::EvidenceProtectionResumeAuthorization =
                serde_json::from_value(value).map_err(|_| denied())?;
            let now = now_ms(denied)?;
            if request.expires_at_unix_ms < now
                || request.expires_at_unix_ms > now.saturating_add(300_000)
            {
                return Err(denied());
            }
            let operation =
                piko_win_platform::network_elevation::begin_network_operation(&request.origin)?;
            operation.ensure_origin_alive()?;
            return resume_activation();
        }
        let (ticket_id, expires_at_unix_ms, origin, command, activate) =
            if purpose == "evidence-key-backup-v1" {
                let request: piko_ipc::KeyBackupAuthorization =
                    serde_json::from_value(value).map_err(|_| denied())?;
                (
                    request.ticket_id,
                    request.expires_at_unix_ms,
                    request.origin,
                    piko_ipc::Command::AuthorizeKeyBackup {
                        ticket_id: request.ticket_id,
                    },
                    false,
                )
            } else {
                let request: piko_ipc::EvidenceProtectionAuthorization =
                    serde_json::from_value(value).map_err(|_| denied())?;
                (
                    request.ticket_id,
                    request.expires_at_unix_ms,
                    request.origin,
                    piko_ipc::Command::AuthorizeEvidenceProtection {
                        ticket_id: request.ticket_id,
                    },
                    true,
                )
            };
        let now = now_ms(denied)?;
        if ticket_id.is_nil()
            || expires_at_unix_ms < now
            || expires_at_unix_ms > now.saturating_add(300_000)
            || !piko_win_platform::current_process_elevated()?
        {
            return Err(io::Error::other("evidence key operation was refused"));
        }
        let operation = piko_win_platform::network_elevation::begin_network_operation(&origin)?;
        operation.ensure_origin_alive()?;
        tokio::runtime::Builder::new_current_thread()
            .enable_all()
            .build()?
            .block_on(async {
                match piko_ipc::call(command).await? {
                    piko_ipc::ApiData::EvidenceKeyStatus(_) => Ok(()),
                    _ => Err(io::Error::other("evidence key operation was refused")),
                }
            })?;
        if activate {
            run_activation_script(false)?;
        }
        Ok(())
    })())
}

#[cfg(test)]
mod tests;
