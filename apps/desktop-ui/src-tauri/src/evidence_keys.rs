use piko_ipc::{ApiData, Command, EvidenceKeyStatus, KeyBackupReply, KeyBackupTicket, SecretText};
use std::time::{SystemTime, UNIX_EPOCH};

#[tauri::command]
pub(crate) async fn resume_evidence_protection() -> Result<(), String> {
    // Service IPC may be unavailable precisely because activation was interrupted.
    // The elevated helper instead requires an exact durable activation journal.
    tauri::async_runtime::spawn_blocking(move || {
        let now = u64::try_from(
            SystemTime::now()
                .duration_since(UNIX_EPOCH)
                .map_err(|_| "Clock unavailable")?
                .as_millis(),
        )
        .map_err(|_| "Clock unavailable")?;
        let request = piko_ipc::EvidenceProtectionResumeAuthorization {
            purpose: "evidence-protection-resume-v1".into(),
            origin: piko_win_platform::network_elevation::current_network_plan_origin()
                .map_err(|_| "Desktop identity unavailable")?,
            expires_at_unix_ms: now.saturating_add(300_000),
        };
        let bytes = serde_json::to_vec(&request).map_err(|_| "Resume request unavailable")?;
        let payload = bytes
            .iter()
            .map(|byte| format!("{byte:02x}"))
            .collect::<String>();
        let helper = std::env::current_exe()
            .map_err(|_| "Helper path unavailable")?
            .with_file_name("piko-network-helper.exe");
        let exit = piko_win_platform::network_elevation::launch_network_helper(&helper, &payload)
            .map_err(|_| "Windows authorization cancelled or unavailable")?;
        if exit != 0 {
            return Err("Activation resume refused; private transaction retained".to_string());
        }
        Ok(())
    })
    .await
    .map_err(|_| "Resume worker unavailable".to_string())?
}

#[tauri::command]
pub(crate) async fn evidence_key_status() -> Result<EvidenceKeyStatus, String> {
    match piko_ipc::call(Command::GetEvidenceKeyStatus)
        .await
        .map_err(|_| "Key status unavailable".to_string())?
    {
        ApiData::EvidenceKeyStatus(value) => Ok(value),
        _ => Err("Invalid key status response".into()),
    }
}
#[tauri::command]
pub(crate) async fn begin_evidence_key_backup() -> Result<KeyBackupTicket, String> {
    match piko_ipc::call(Command::BeginKeyBackup)
        .await
        .map_err(|_| "Cannot begin key backup; use the installed service".to_string())?
    {
        ApiData::KeyBackupTicket(value) => Ok(value),
        _ => Err("Invalid backup ticket response".into()),
    }
}
#[tauri::command]
pub(crate) async fn authorize_evidence_key_backup(ticket_id: String) -> Result<(), String> {
    let ticket_id = ticket_id
        .parse()
        .map_err(|_| "Invalid backup ticket".to_string())?;
    tauri::async_runtime::spawn_blocking(move || {
        let now = u64::try_from(
            SystemTime::now()
                .duration_since(UNIX_EPOCH)
                .map_err(|_| "Clock unavailable")?
                .as_millis(),
        )
        .map_err(|_| "Clock unavailable")?;
        let request = piko_ipc::KeyBackupAuthorization {
            purpose: "evidence-key-backup-v1".into(),
            ticket_id,
            origin: piko_win_platform::network_elevation::current_network_plan_origin()
                .map_err(|_| "Desktop identity unavailable")?,
            expires_at_unix_ms: now.saturating_add(300_000),
        };
        let bytes =
            serde_json::to_vec(&request).map_err(|_| "Authorization request unavailable")?;
        let payload = bytes
            .iter()
            .map(|byte| format!("{byte:02x}"))
            .collect::<String>();
        let helper = std::env::current_exe()
            .map_err(|_| "Helper path unavailable")?
            .with_file_name("piko-network-helper.exe");
        let exit = piko_win_platform::network_elevation::launch_network_helper(&helper, &payload)
            .map_err(|_| "Windows authorization cancelled or unavailable")?;
        if exit != 0 {
            return Err("Windows key-backup authorization was refused".to_string());
        }
        Ok(())
    })
    .await
    .map_err(|_| "Authorization worker unavailable".to_string())?
}
#[tauri::command]
pub(crate) async fn read_evidence_key_backup(ticket_id: String) -> Result<KeyBackupReply, String> {
    let ticket_id = ticket_id
        .parse()
        .map_err(|_| "Invalid backup ticket".to_string())?;
    match piko_ipc::call(Command::ReadKeyBackup { ticket_id })
        .await
        .map_err(|_| "Key backup unavailable or expired".to_string())?
    {
        ApiData::KeyBackup(value) => Ok(value),
        _ => Err("Invalid key backup response".into()),
    }
}
#[tauri::command]
pub(crate) async fn cancel_evidence_key_backup(ticket_id: String) -> Result<(), String> {
    let ticket_id = ticket_id
        .parse()
        .map_err(|_| "Invalid backup ticket".to_string())?;
    match piko_ipc::call(Command::CancelKeyBackup { ticket_id })
        .await
        .map_err(|_| "Cannot cancel key session".to_string())?
    {
        ApiData::EvidenceKeyStatus(_) => Ok(()),
        _ => Err("Invalid cancellation response".into()),
    }
}
#[tauri::command]
pub(crate) async fn confirm_evidence_key_backup(
    ticket_id: String,
    code: String,
) -> Result<EvidenceKeyStatus, String> {
    let code = SecretText::new(code).map_err(|_| "Invalid recovery code".to_string())?;
    let ticket_id = ticket_id
        .parse()
        .map_err(|_| "Invalid backup ticket".to_string())?;
    match piko_ipc::call(Command::ConfirmKeyBackup { ticket_id, code })
        .await
        .map_err(|_| "Key backup confirmation refused or expired".to_string())?
    {
        ApiData::EvidenceKeyStatus(value) => Ok(value),
        _ => Err("Invalid key status response".into()),
    }
}

#[tauri::command]
pub(crate) async fn begin_evidence_protection() -> Result<piko_ipc::EvidenceProtectionTicket, String>
{
    match piko_ipc::call(Command::BeginEvidenceProtection)
        .await
        .map_err(|_| "Cannot begin protection activation".to_string())?
    {
        ApiData::EvidenceProtectionTicket(value) => Ok(value),
        _ => Err("Invalid activation ticket response".into()),
    }
}

#[tauri::command]
pub(crate) async fn authorize_evidence_protection(ticket_id: String) -> Result<(), String> {
    let ticket_id = ticket_id
        .parse()
        .map_err(|_| "Invalid activation ticket".to_string())?;
    tauri::async_runtime::spawn_blocking(move || {
        let now = u64::try_from(
            SystemTime::now()
                .duration_since(UNIX_EPOCH)
                .map_err(|_| "Clock unavailable")?
                .as_millis(),
        )
        .map_err(|_| "Clock unavailable")?;
        let request = piko_ipc::EvidenceProtectionAuthorization {
            purpose: "evidence-protection-activation-v1".into(),
            ticket_id,
            origin: piko_win_platform::network_elevation::current_network_plan_origin()
                .map_err(|_| "Desktop identity unavailable")?,
            expires_at_unix_ms: now.saturating_add(300_000),
        };
        let bytes = serde_json::to_vec(&request).map_err(|_| "Activation request unavailable")?;
        let payload = bytes
            .iter()
            .map(|byte| format!("{byte:02x}"))
            .collect::<String>();
        let helper = std::env::current_exe()
            .map_err(|_| "Helper path unavailable")?
            .with_file_name("piko-network-helper.exe");
        let exit = piko_win_platform::network_elevation::launch_network_helper(&helper, &payload)
            .map_err(|_| "Windows authorization cancelled or unavailable")?;
        if exit != 0 {
            return Err("Windows evidence-protection activation was refused".to_string());
        }
        Ok(())
    })
    .await
    .map_err(|_| "Activation worker unavailable".to_string())?
}
