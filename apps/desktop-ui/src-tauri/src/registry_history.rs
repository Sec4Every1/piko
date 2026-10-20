use piko_app_control::registry_history::{observe, RegistryHistory};
use tauri::Manager;
#[derive(Default)]
pub struct RegistryController(pub std::sync::Arc<std::sync::Mutex<()>>);
#[tauri::command]
pub async fn registry_history(
    app: tauri::AppHandle,
    state: tauri::State<'_, RegistryController>,
    before_sequence: Option<i64>,
) -> Result<RegistryHistory, String> {
    let path = app
        .path()
        .app_local_data_dir()
        .map_err(|e| e.to_string())?
        .join("registry-history.sqlite");
    let lock = state.0.clone();
    tauri::async_runtime::spawn_blocking(move || {
        let _guard = lock.try_lock().map_err(|_| "Registry history busy")?;
        let snapshot =
            piko_win_platform::registry_history::snapshot().map_err(|e| e.to_string())?;
        let time = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .map_err(|e| e.to_string())?
            .as_millis()
            .try_into()
            .map_err(|_| "Invalid time")?;
        observe(&path, &snapshot, time, before_sequence).map_err(|e| e.to_string())
    })
    .await
    .map_err(|e| e.to_string())?
}
