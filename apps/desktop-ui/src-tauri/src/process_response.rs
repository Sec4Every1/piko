use tauri::Manager;
#[derive(Default)]
pub struct ProcessResponse(
    std::sync::Arc<std::sync::Mutex<piko_app_control::process_response::ProcessController>>,
);
#[tauri::command]
pub async fn prepare_process_stop(
    state: tauri::State<'_, ProcessResponse>,
    pid: u32,
    creation_filetime: String,
) -> Result<piko_app_control::process_response::ProcessPlan, String> {
    let controller = state.0.clone();
    tauri::async_runtime::spawn_blocking(move || {
        controller
            .try_lock()
            .map_err(|_| "Process operation in progress".to_string())?
            .prepare(pid, &creation_filetime)
            .map_err(|e| e.to_string())
    })
    .await
    .map_err(|e| e.to_string())?
}
#[tauri::command]
pub async fn confirm_process_stop(
    app: tauri::AppHandle,
    state: tauri::State<'_, ProcessResponse>,
    plan_id: String,
) -> Result<piko_app_control::process_response::ProcessAction, String> {
    let controller = state.0.clone();
    let path = app
        .path()
        .app_local_data_dir()
        .map_err(|e| e.to_string())?
        .join("process-actions.sqlite");
    let id = plan_id.parse().map_err(|_| "Invalid process plan UUID")?;
    tauri::async_runtime::spawn_blocking(move || {
        controller
            .try_lock()
            .map_err(|_| "Process operation in progress".to_string())?
            .execute(&path, id)
            .map_err(|e| e.to_string())
    })
    .await
    .map_err(|e| e.to_string())?
}
#[tauri::command]
pub fn discard_process_stop(
    state: tauri::State<'_, ProcessResponse>,
    plan_id: String,
) -> Result<(), String> {
    let id = plan_id.parse().map_err(|_| "Invalid process plan UUID")?;
    state
        .0
        .try_lock()
        .map_err(|_| "Process operation in progress")?
        .discard(id);
    Ok(())
}
#[tauri::command]
pub async fn process_actions(
    app: tauri::AppHandle,
) -> Result<Vec<piko_app_control::process_response::ProcessAction>, String> {
    let path = app
        .path()
        .app_local_data_dir()
        .map_err(|e| e.to_string())?
        .join("process-actions.sqlite");
    tauri::async_runtime::spawn_blocking(move || {
        piko_app_control::process_response::actions(&path).map_err(|e| e.to_string())
    })
    .await
    .map_err(|e| e.to_string())?
}
