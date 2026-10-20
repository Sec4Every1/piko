use std::{
    io::{self, Read},
    os::windows::process::CommandExt,
    process::{Child, Command, Stdio},
    time::{Duration, Instant},
};
static GATE: std::sync::Mutex<()> = std::sync::Mutex::new(());
struct Probe(Child);
impl Drop for Probe {
    fn drop(&mut self) {
        let _ = self.0.kill();
        let _ = self.0.wait();
    }
}
#[tauri::command]
pub async fn executable_signature(
    path: String,
) -> Result<piko_app_control::ExecutableSignature, String> {
    tauri::async_runtime::spawn_blocking(move || inspect(path).map_err(|e| e.to_string()))
        .await
        .map_err(|e| e.to_string())?
}
fn inspect(path: String) -> io::Result<piko_app_control::ExecutableSignature> {
    let _guard = GATE
        .try_lock()
        .map_err(|_| io::Error::other("Signature inspection already running"))?;
    if path.len() > 1024 {
        return Err(io::Error::other("Executable path exceeds limit"));
    }
    let helper = std::env::current_exe()?.with_file_name("piko.exe");
    let mut probe = Probe(
        Command::new(helper)
            .arg("signature")
            .arg(&path)
            .creation_flags(0x08000000)
            .stdin(Stdio::null())
            .stdout(Stdio::piped())
            .stderr(Stdio::null())
            .spawn()?,
    );
    let deadline = Instant::now() + Duration::from_secs(20);
    loop {
        if let Some(status) = probe.0.try_wait()? {
            if !status.success() {
                return Err(io::Error::other(
                    "Signature inspection failed; verify the file path and access",
                ));
            }
            break;
        }
        if Instant::now() >= deadline {
            return Err(io::Error::new(
                io::ErrorKind::TimedOut,
                "Signature provider exceeded 20 seconds; result unavailable",
            ));
        }
        std::thread::sleep(Duration::from_millis(40));
    }
    let mut bytes = Vec::new();
    probe
        .0
        .stdout
        .take()
        .ok_or_else(|| io::Error::other("Signature output unavailable"))?
        .take(4097)
        .read_to_end(&mut bytes)?;
    if bytes.len() > 4096 {
        return Err(io::Error::other("Signature output exceeds limit"));
    }
    serde_json::from_slice(&bytes).map_err(io::Error::other)
}
