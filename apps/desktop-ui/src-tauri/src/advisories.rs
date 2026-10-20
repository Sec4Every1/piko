use piko_app_control::advisories::{self, AdvisorySnapshot};
use std::path::PathBuf;
use tauri::Manager;
#[derive(Default)]
pub struct AdvisoryController(pub std::sync::Arc<std::sync::Mutex<()>>);
fn archive(app: &tauri::AppHandle) -> Result<PathBuf, String> {
    Ok(app
        .path()
        .app_local_data_dir()
        .map_err(|e| e.to_string())?
        .join("advisories.sqlite"))
}
fn now() -> Result<u64, String> {
    Ok(std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map_err(|e| e.to_string())?
        .as_secs())
}
#[tauri::command]
pub async fn advisory_status(
    app: tauri::AppHandle,
    state: tauri::State<'_, AdvisoryController>,
) -> Result<AdvisorySnapshot, String> {
    let path = archive(&app)?;
    let lock = state.0.clone();
    tauri::async_runtime::spawn_blocking(move || {
        let _guard = lock.try_lock().map_err(|_| "Advisory occupati")?;
        let inventory =
            piko_win_platform::software_inventory::inventory(true).map_err(|e| e.to_string())?;
        advisories::snapshot(&path, &inventory, now()?).map_err(|e| e.to_string())
    })
    .await
    .map_err(|e| e.to_string())?
}
#[tauri::command]
pub async fn import_advisory_feed(
    app: tauri::AppHandle,
    state: tauri::State<'_, AdvisoryController>,
    json: String,
) -> Result<(), String> {
    if json.len() > advisories::MAX_FEED_BYTES {
        return Err("Feed oltre 1 MiB".into());
    }
    let path = archive(&app)?;
    let lock = state.0.clone();
    tauri::async_runtime::spawn_blocking(move || {
        let _guard = lock.try_lock().map_err(|_| "Advisory occupati")?;
        advisories::import_feed(&path, &json, now()?).map_err(|e| e.to_string())
    })
    .await
    .map_err(|e| e.to_string())?
}
#[tauri::command]
pub async fn bind_advisory_product(
    app: tauri::AppHandle,
    state: tauri::State<'_, AdvisoryController>,
    application_id: String,
    product_id: String,
    exact_version: String,
) -> Result<(), String> {
    if application_id.len() > 2048 || product_id.len() > 120 || exact_version.len() > 80 {
        return Err("Associazione oltre il limite".into());
    }
    let path = archive(&app)?;
    let lock = state.0.clone();
    tauri::async_runtime::spawn_blocking(move || {
        let _guard = lock.try_lock().map_err(|_| "Advisory occupati")?;
        let inventory =
            piko_win_platform::software_inventory::inventory(true).map_err(|e| e.to_string())?;
        let application = inventory
            .entries
            .iter()
            .find(|a| a.id == application_id)
            .ok_or("Applicazione non osservata nell'inventario corrente")?;
        advisories::bind(&path, application, &product_id, &exact_version, now()?)
            .map_err(|e| e.to_string())
    })
    .await
    .map_err(|e| e.to_string())?
}
#[tauri::command]
pub async fn unbind_advisory_product(
    app: tauri::AppHandle,
    state: tauri::State<'_, AdvisoryController>,
    application_id: String,
) -> Result<(), String> {
    if application_id.len() > 2048 {
        return Err("Identità oltre il limite".into());
    }
    let path = archive(&app)?;
    let lock = state.0.clone();
    tauri::async_runtime::spawn_blocking(move || {
        let _guard = lock.try_lock().map_err(|_| "Advisory occupati")?;
        advisories::unbind(&path, &application_id).map_err(|e| e.to_string())
    })
    .await
    .map_err(|e| e.to_string())?
}
