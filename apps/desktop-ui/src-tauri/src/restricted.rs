//! Normal-user AppContainer trial commands, isolated from runtime policy controls.
use piko_app_control::restricted::{
    NetworkAccess, RestrictedController, RestrictedPlan, RestrictedSession,
};
use std::sync::{Arc, Mutex};
use tauri::Manager;
#[derive(Default)]
pub struct RestrictedState(pub Arc<Mutex<RestrictedController>>);
#[tauri::command]
pub async fn prepare_restricted(
    state: tauri::State<'_, RestrictedState>,
    path: String,
    network_access: Option<NetworkAccess>,
) -> Result<RestrictedPlan, String> {
    let c = state.0.clone();
    tauri::async_runtime::spawn_blocking(move || {
        c.try_lock()
            .map_err(|_| "Prova occupata".to_string())?
            .prepare_with_network(&path, network_access.unwrap_or_default())
            .map_err(|e| e.to_string())
    })
    .await
    .map_err(|e| e.to_string())?
}
#[tauri::command]
pub async fn restricted_sessions(
    state: tauri::State<'_, RestrictedState>,
) -> Result<Vec<RestrictedSession>, String> {
    let c = state.0.clone();
    tauri::async_runtime::spawn_blocking(move || {
        c.try_lock()
            .map_err(|_| "Prova occupata".to_string())?
            .sessions()
            .map_err(|e| e.to_string())
    })
    .await
    .map_err(|e| e.to_string())?
}
#[tauri::command]
pub async fn launch_restricted(
    app: tauri::AppHandle,
    state: tauri::State<'_, RestrictedState>,
    plan_id: String,
) -> Result<RestrictedSession, String> {
    let root = app
        .path()
        .app_local_data_dir()
        .map_err(|e| e.to_string())?
        .join("restricted-trials");
    let c = state.0.clone();
    tauri::async_runtime::spawn_blocking(move || {
        c.try_lock()
            .map_err(|_| "Prova occupata".to_string())?
            .launch(
                &root,
                plan_id.parse().map_err(|_| "Invalid UUID".to_string())?,
            )
            .map_err(|e| e.to_string())
    })
    .await
    .map_err(|e| e.to_string())?
}
#[tauri::command]
pub async fn stop_restricted(
    state: tauri::State<'_, RestrictedState>,
    session_id: String,
) -> Result<(), String> {
    let c = state.0.clone();
    tauri::async_runtime::spawn_blocking(move || {
        c.try_lock()
            .map_err(|_| "Prova occupata".to_string())?
            .stop(session_id.parse().map_err(|_| "Invalid UUID".to_string())?)
            .map_err(|e| e.to_string())
    })
    .await
    .map_err(|e| e.to_string())?
}
#[tauri::command]
pub fn discard_restricted(
    state: tauri::State<'_, RestrictedState>,
    plan_id: String,
) -> Result<(), String> {
    state
        .0
        .try_lock()
        .map_err(|_| "Prova occupata".to_string())?
        .discard(plan_id.parse().map_err(|_| "Invalid UUID".to_string())?);
    Ok(())
}
