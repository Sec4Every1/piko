use std::{
    io,
    os::windows::process::CommandExt,
    path::PathBuf,
    process::{Command, Stdio},
};
#[derive(serde::Serialize)]
pub struct Status {
    pub enabled: bool,
    pub conflict: bool,
    pub command: String,
    pub last_startup_error: Option<String>,
}
#[tauri::command]
pub fn startup_status() -> Result<Status, String> {
    let value =
        piko_win_platform::startup::status(&std::env::current_exe().map_err(|e| e.to_string())?)
            .map_err(|e| e.to_string())?;
    let last_startup_error = read_diagnostic().map_err(|e| e.to_string())?;
    Ok(Status {
        enabled: value.enabled,
        conflict: value.conflict,
        command: value.command,
        last_startup_error,
    })
}
#[tauri::command]
pub fn set_startup(enabled: bool) -> Result<piko_win_platform::startup::StartupStatus, String> {
    piko_win_platform::startup::set(
        &std::env::current_exe().map_err(|e| e.to_string())?,
        enabled,
    )
    .map_err(|e| e.to_string())
}
pub fn monitor_only() -> io::Result<()> {
    if piko_win_platform::current_process_elevated()? {
        return Err(io::Error::other(
            "Monitor startup requires a normal user session",
        ));
    }
    // Installed SCM is authoritative: never launch a second per-user monitor.
    if piko_win_platform::service::installed_service_pid()?.is_some() {
        return Ok(());
    }
    if let Ok(response) =
        tauri::async_runtime::block_on(piko_ipc::call(piko_ipc::Command::GetHealth))
    {
        return match response {
            piko_ipc::ApiData::Health(health)
                if health.product == "piko" && health.version == env!("CARGO_PKG_VERSION") =>
            {
                Ok(())
            }
            _ => Err(io::Error::other("Unexpected monitor version")),
        };
    }
    let root = std::env::current_exe()?
        .parent()
        .ok_or_else(|| io::Error::other("Missing installation directory"))?
        .to_path_buf();
    let data = PathBuf::from(
        std::env::var_os("LOCALAPPDATA")
            .ok_or_else(|| io::Error::other("LOCALAPPDATA unavailable"))?,
    )
    .join("piko-monitor");
    std::fs::create_dir_all(&data)?;
    reject_reparse(&data)?;
    reject_reparse(&root.join("piko-service.exe"))?;
    let config = data.join("console.json");
    let _locks = piko_win_platform::network_elevation::lock_path_parents(&config)?;
    if config.exists() {
        reject_reparse(&config)?;
    }
    match std::fs::OpenOptions::new()
        .write(true)
        .create_new(true)
        .open(&config)
    {
        Ok(mut file) => {
            use std::io::Write;
            let value = serde_json::json!({"data_dir":data,"heartbeat_seconds":5,"flush_seconds":5,"max_disk_mib":256,"queue_capacity":256});
            file.write_all(value.to_string().as_bytes())?;
            file.sync_all()?;
        }
        Err(error) if error.kind() == io::ErrorKind::AlreadyExists => {}
        Err(error) => return Err(error),
    }
    let mut child = Command::new(root.join("piko-service.exe"))
        .arg("--config")
        .arg(config)
        .creation_flags(0x08000000)
        .stdin(Stdio::null())
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .spawn()?;
    let deadline = std::time::Instant::now() + std::time::Duration::from_secs(12);
    while std::time::Instant::now() < deadline {
        if let Some(exit) = child.try_wait()? {
            return Err(io::Error::other(format!("Monitor exited: {exit}")));
        }
        if let Ok(piko_ipc::ApiData::Health(health)) =
            tauri::async_runtime::block_on(piko_ipc::call(piko_ipc::Command::GetHealth))
        {
            if health.product == "piko" && health.version == env!("CARGO_PKG_VERSION") {
                return Ok(());
            }
            return Err(io::Error::other("Unexpected monitor version"));
        }
        std::thread::sleep(std::time::Duration::from_millis(100));
    }
    Err(io::Error::other("Monitor startup not confirmed"))
}

fn diagnostic_path() -> io::Result<PathBuf> {
    Ok(PathBuf::from(
        std::env::var_os("LOCALAPPDATA")
            .ok_or_else(|| io::Error::other("LOCALAPPDATA unavailable"))?,
    )
    .join("piko-monitor")
    .join("startup-status.txt"))
}
fn read_diagnostic() -> io::Result<Option<String>> {
    use std::io::Read;
    let path = diagnostic_path()?;
    if !path.exists() {
        return Ok(None);
    }
    let _locks = piko_win_platform::network_elevation::lock_path_parents(&path)?;
    reject_reparse(&path)?;
    let mut text = String::new();
    std::fs::File::open(path)?
        .take(4097)
        .read_to_string(&mut text)?;
    if text.len() > 4096 {
        return Err(io::Error::other("Startup diagnostic exceeds limit"));
    }
    Ok((!text.is_empty()).then_some(text))
}
pub fn run() -> io::Result<()> {
    let result = monitor_only();
    let diagnostic = (|| -> io::Result<()> {
        use std::io::Write;
        let path = diagnostic_path()?;
        std::fs::create_dir_all(
            path.parent()
                .ok_or_else(|| io::Error::other("Missing data directory"))?,
        )?;
        let _locks = piko_win_platform::network_elevation::lock_path_parents(&path)?;
        if path.exists() {
            reject_reparse(&path)?
        }
        let mut file = std::fs::OpenOptions::new()
            .write(true)
            .create(true)
            .truncate(true)
            .open(path)?;
        let text = result
            .as_ref()
            .err()
            .map(|e| {
                format!(
                    "{}: {e}",
                    std::time::SystemTime::now()
                        .duration_since(std::time::UNIX_EPOCH)
                        .unwrap_or_default()
                        .as_secs()
                )
            })
            .unwrap_or_default();
        let text = text.chars().take(1000).collect::<String>();
        file.write_all(text.as_bytes())?;
        file.sync_all()
    })();
    if let Err(error) = diagnostic {
        eprintln!("piko startup diagnostic: {error}")
    }
    result
}
fn reject_reparse(path: &std::path::Path) -> io::Result<()> {
    use std::os::windows::fs::MetadataExt;
    let metadata = std::fs::symlink_metadata(path)?;
    if metadata.file_attributes() & 0x400 != 0 {
        return Err(io::Error::other("Startup path contains a reparse point"));
    }
    Ok(())
}
