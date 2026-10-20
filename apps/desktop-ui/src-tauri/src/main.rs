#![forbid(unsafe_code)]
#![cfg_attr(not(debug_assertions), windows_subsystem = "windows")]

use piko_common_model::HealthSnapshot;
use piko_event_schema::{RawEvidence, SecurityEvent};
use piko_event_storage::{EventQuery, IntegrityReport};
use piko_ipc::{ApiData, Command};
use tauri::Manager;
mod advisories;
mod registry_history;
use registry_history::{registry_history, RegistryController};
mod process_response;
mod restricted;
mod signature;
use advisories::{
    advisory_status, bind_advisory_product, import_advisory_feed, unbind_advisory_product,
    AdvisoryController,
};
use process_response::{
    confirm_process_stop, discard_process_stop, prepare_process_stop, process_actions,
    ProcessResponse,
};
use restricted::{
    discard_restricted, launch_restricted, prepare_restricted, restricted_sessions,
    stop_restricted, RestrictedState,
};
mod startup;
use signature::executable_signature;
use startup::{set_startup, startup_status};

#[tauri::command]
async fn get_health() -> Result<HealthSnapshot, String> {
    match piko_ipc::call(Command::GetHealth)
        .await
        .map_err(|error| error.to_string())?
    {
        ApiData::Health(health) => Ok(health),
        _ => Err("unexpected IPC response type".into()),
    }
}

#[tauri::command]
async fn get_investigation(
    process_instance: String,
) -> Result<piko_security_core::Investigation, String> {
    let process_instance = process_instance
        .parse()
        .map_err(|_| "invalid process instance UUID".to_string())?;
    match piko_ipc::call(Command::GetInvestigation { process_instance })
        .await
        .map_err(|error| error.to_string())?
    {
        ApiData::Investigation(value) => Ok(value),
        _ => Err("unexpected IPC response type".into()),
    }
}

#[tauri::command]
async fn authentication_activity(
    filter: piko_event_storage::AuthenticationQuery,
) -> Result<piko_event_storage::AuthenticationPage, String> {
    match piko_ipc::call(Command::GetAuthenticationActivity(filter))
        .await
        .map_err(|e| e.to_string())?
    {
        ApiData::AuthenticationActivity(value) => Ok(value),
        _ => Err("unexpected IPC response type".into()),
    }
}

#[tauri::command]
async fn list_events(filter: EventQuery) -> Result<Vec<SecurityEvent>, String> {
    match piko_ipc::call(Command::ListEvents(filter))
        .await
        .map_err(|error| error.to_string())?
    {
        ApiData::Events(events) => Ok(events),
        _ => Err("unexpected IPC response type".into()),
    }
}

#[tauri::command]
async fn verify_store() -> Result<IntegrityReport, String> {
    match piko_ipc::call(Command::VerifyStore)
        .await
        .map_err(|error| error.to_string())?
    {
        ApiData::Integrity(report) => Ok(report),
        _ => Err("unexpected IPC response type".into()),
    }
}

fn main() -> std::process::ExitCode {
    if std::env::args_os()
        .skip(1)
        .eq([std::ffi::OsString::from("--monitor-only")])
    {
        return match startup::run() {
            Ok(()) => std::process::ExitCode::SUCCESS,
            Err(error) => {
                eprintln!("piko startup: {error}");
                std::process::ExitCode::FAILURE
            }
        };
    }
    let result = tauri::Builder::default()
        .manage(NetworkController::default())
        .manage(ProcessResponse::default())
        .manage(AdvisoryController::default())
        .manage(RegistryController::default())
        .manage(RestrictedState::default())
        .manage(SandboxController::default())
        .invoke_handler(tauri::generate_handler![
            advisory_status,
            import_advisory_feed,
            bind_advisory_product,
            unbind_advisory_product,
            prepare_restricted,
            restricted_sessions,
            launch_restricted,
            stop_restricted,
            discard_restricted,
            prepare_process_stop,
            confirm_process_stop,
            discard_process_stop,
            process_actions,
            executable_signature,
            list_alert_reviews,
            save_alert_review,
            startup_status,
            set_startup,
            sandbox_status,
            sandbox_sessions,
            prepare_sandbox,
            create_sandbox,
            launch_sandbox,
            remove_sandbox,
            discard_sandbox,
            get_health,
            get_observations,
            get_investigation,
            authentication_activity,
            list_events,
            verify_store,
            get_evidence,
            list_alerts,
            response_status,
            prepare_quarantine,
            prepare_restore,
            execute_action,
            open_attack_reference,
            software_inventory,
            software_history,
            registry_history,
            application_executables,
            discard_network_plans,
            network_snapshot,
            prepare_network_action,
            execute_network_action
        ])
        .run(tauri::generate_context!());
    match result {
        Ok(()) => std::process::ExitCode::SUCCESS,
        Err(error) => {
            eprintln!("piko desktop failed: {error}");
            std::process::ExitCode::FAILURE
        }
    }
}

#[derive(Default)]
struct NetworkController(std::sync::Arc<std::sync::Mutex<piko_app_control::Controller>>);

#[tauri::command]
async fn software_inventory(
) -> Result<piko_win_platform::software_inventory::InventorySnapshot, String> {
    tauri::async_runtime::spawn_blocking(|| {
        piko_win_platform::software_inventory::inventory(true).map_err(|e| e.to_string())
    })
    .await
    .map_err(|e| e.to_string())?
}

#[tauri::command]
async fn application_executables(
    app_id: String,
) -> Result<piko_app_control::ExecutableCandidates, String> {
    tauri::async_runtime::spawn_blocking(move || {
        piko_app_control::application_executables(&app_id).map_err(|e| e.to_string())
    })
    .await
    .map_err(|e| e.to_string())?
}

#[tauri::command]
async fn discard_network_plans(
    state: tauri::State<'_, NetworkController>,
    plan_ids: Vec<String>,
) -> Result<(), String> {
    if plan_ids.len() > 32 {
        return Err("Too many plans".into());
    }
    let ids = plan_ids
        .iter()
        .map(|id| id.parse())
        .collect::<Result<Vec<_>, _>>()
        .map_err(|_| "Invalid plan UUID")?;
    state
        .0
        .try_lock()
        .map_err(|_| "Network operation in progress")?
        .discard(&ids);
    Ok(())
}

#[tauri::command]
async fn network_snapshot() -> Result<piko_win_platform::network_control::NetworkSnapshot, String> {
    tauri::async_runtime::spawn_blocking(|| {
        piko_app_control::network_snapshot().map_err(|e| e.to_string())
    })
    .await
    .map_err(|e| e.to_string())?
}

#[tauri::command]
async fn prepare_network_action(
    state: tauri::State<'_, NetworkController>,
    action: piko_app_control::NetworkAction,
    path: String,
    direction: Option<piko_win_platform::network_control::NetworkDirection>,
) -> Result<piko_app_control::NetworkPlan, String> {
    let controller = state.0.clone();
    tauri::async_runtime::spawn_blocking(move || {
        controller
            .try_lock()
            .map_err(|_| "Un'operazione di rete è già in corso.".to_string())?
            .prepare_direction(action, &path, direction.unwrap_or_default())
            .map_err(|e| e.to_string())
    })
    .await
    .map_err(|e| e.to_string())?
}

#[tauri::command]
async fn execute_network_action(
    state: tauri::State<'_, NetworkController>,
    plan_id: String,
) -> Result<(), String> {
    let controller = state.0.clone();
    tauri::async_runtime::spawn_blocking(move || {
        controller
            .try_lock()
            .map_err(|_| "Un'operazione di rete è già in corso.".to_string())?
            .execute(
                plan_id
                    .parse()
                    .map_err(|_| "Invalid plan UUID".to_string())?,
            )
            .map_err(|e| e.to_string())
    })
    .await
    .map_err(|e| e.to_string())?
}

#[tauri::command]
async fn open_attack_reference(technique_id: String) -> Result<(), String> {
    tauri::async_runtime::spawn_blocking(move || {
        piko_win_platform::references::open_attack_reference(&technique_id)
            .map_err(|e| e.to_string())
    })
    .await
    .map_err(|e| e.to_string())?
}

#[tauri::command]
async fn list_alerts() -> Result<Vec<piko_security_core::Alert>, String> {
    match piko_ipc::call(Command::ListAlerts)
        .await
        .map_err(|e| e.to_string())?
    {
        ApiData::Alerts(value) => Ok(value),
        _ => Err("unexpected IPC response".into()),
    }
}
#[tauri::command]
async fn response_status() -> Result<piko_security_core::ResponseStatus, String> {
    match piko_ipc::call(Command::GetResponseStatus)
        .await
        .map_err(|e| e.to_string())?
    {
        ApiData::ResponseStatus(value) => Ok(value),
        _ => Err("unexpected IPC response".into()),
    }
}
async fn response_action(command: Command) -> Result<piko_security_core::Action, String> {
    match piko_ipc::call(command).await.map_err(|e| e.to_string())? {
        ApiData::Action(value) => Ok(value),
        _ => Err("unexpected IPC response".into()),
    }
}
#[tauri::command]
async fn prepare_quarantine(path: String) -> Result<piko_security_core::Action, String> {
    response_action(Command::PrepareQuarantine { path }).await
}
#[tauri::command]
async fn prepare_restore(action_id: String) -> Result<piko_security_core::Action, String> {
    response_action(Command::PrepareRestore {
        action_id: action_id.parse().map_err(|_| "invalid UUID")?,
    })
    .await
}
#[tauri::command]
async fn execute_action(
    action_id: String,
    expected_sha256: String,
) -> Result<piko_security_core::Action, String> {
    response_action(Command::ExecuteAction {
        action_id: action_id.parse().map_err(|_| "invalid UUID")?,
        expected_sha256,
    })
    .await
}

#[tauri::command]
async fn get_evidence(evidence_id: String) -> Result<Option<RawEvidence>, String> {
    let evidence_id = evidence_id
        .parse()
        .map_err(|_| "invalid evidence UUID".to_string())?;
    match piko_ipc::call(Command::GetEvidence { evidence_id })
        .await
        .map_err(|error| error.to_string())?
    {
        ApiData::Evidence(evidence) => Ok(evidence),
        _ => Err("unexpected IPC response type".into()),
    }
}

#[tauri::command]
async fn get_observations() -> Result<piko_common_model::ObservationSnapshot, String> {
    match piko_ipc::call(Command::GetObservations)
        .await
        .map_err(|e| e.to_string())?
    {
        ApiData::Observations(value) => Ok(value),
        _ => Err("unexpected IPC response type".into()),
    }
}

#[derive(Default)]
struct SandboxController(
    std::sync::Arc<std::sync::Mutex<piko_app_control::sandbox::SandboxController>>,
);
fn sandbox_root(app: &tauri::AppHandle) -> Result<std::path::PathBuf, String> {
    Ok(app
        .path()
        .app_local_data_dir()
        .map_err(|e| e.to_string())?
        .join("sandbox-sessions"))
}
#[tauri::command]
async fn sandbox_status() -> Result<piko_app_control::sandbox::SandboxStatus, String> {
    tauri::async_runtime::spawn_blocking(|| {
        piko_app_control::sandbox::status().map_err(|e| e.to_string())
    })
    .await
    .map_err(|e| e.to_string())?
}
#[tauri::command]
async fn sandbox_sessions(
    app: tauri::AppHandle,
) -> Result<Vec<piko_app_control::sandbox::SandboxSession>, String> {
    let root = sandbox_root(&app)?;
    tauri::async_runtime::spawn_blocking(move || {
        piko_app_control::sandbox::sessions(&root).map_err(|e| e.to_string())
    })
    .await
    .map_err(|e| e.to_string())?
}
#[tauri::command]
async fn prepare_sandbox(
    state: tauri::State<'_, SandboxController>,
    path: String,
) -> Result<piko_app_control::sandbox::SandboxPlan, String> {
    let controller = state.0.clone();
    tauri::async_runtime::spawn_blocking(move || {
        controller
            .try_lock()
            .map_err(|_| "Sandbox occupata".to_string())?
            .prepare(&path)
            .map_err(|e| e.to_string())
    })
    .await
    .map_err(|e| e.to_string())?
}
#[tauri::command]
async fn create_sandbox(
    app: tauri::AppHandle,
    state: tauri::State<'_, SandboxController>,
    plan_id: String,
) -> Result<piko_app_control::sandbox::SandboxSession, String> {
    let root = sandbox_root(&app)?;
    let controller = state.0.clone();
    tauri::async_runtime::spawn_blocking(move || {
        controller
            .try_lock()
            .map_err(|_| "Sandbox occupata".to_string())?
            .create(
                &root,
                plan_id.parse().map_err(|_| "Invalid UUID".to_string())?,
            )
            .map_err(|e| e.to_string())
    })
    .await
    .map_err(|e| e.to_string())?
}
#[tauri::command]
async fn discard_sandbox(
    state: tauri::State<'_, SandboxController>,
    plan_id: String,
) -> Result<(), String> {
    state
        .0
        .try_lock()
        .map_err(|_| "Sandbox occupata")?
        .discard(plan_id.parse().map_err(|_| "Invalid UUID")?);
    Ok(())
}
#[tauri::command]
async fn launch_sandbox(
    app: tauri::AppHandle,
    state: tauri::State<'_, SandboxController>,
    session_id: String,
) -> Result<(), String> {
    let root = sandbox_root(&app)?;
    let controller = state.0.clone();
    tauri::async_runtime::spawn_blocking(move || {
        let _guard = controller.try_lock().map_err(|_| "Sandbox occupata")?;
        piko_app_control::sandbox::launch(&root, session_id.parse().map_err(|_| "Invalid UUID")?)
            .map_err(|e| e.to_string())
    })
    .await
    .map_err(|e| e.to_string())?
}
#[tauri::command]
async fn remove_sandbox(
    app: tauri::AppHandle,
    state: tauri::State<'_, SandboxController>,
    session_id: String,
) -> Result<(), String> {
    let root = sandbox_root(&app)?;
    let controller = state.0.clone();
    tauri::async_runtime::spawn_blocking(move || {
        let _guard = controller.try_lock().map_err(|_| "Sandbox occupata")?;
        piko_app_control::sandbox::remove(&root, session_id.parse().map_err(|_| "Invalid UUID")?)
            .map_err(|e| e.to_string())
    })
    .await
    .map_err(|e| e.to_string())?
}

#[tauri::command]
async fn software_history(
    app: tauri::AppHandle,
    before_sequence: Option<i64>,
) -> Result<piko_app_control::history::SoftwareHistory, String> {
    let path = app
        .path()
        .app_local_data_dir()
        .map_err(|e| e.to_string())?
        .join("software-history.sqlite");
    tauri::async_runtime::spawn_blocking(move || {
        let snapshot =
            piko_win_platform::software_inventory::inventory(true).map_err(|e| e.to_string())?;
        let time = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .map_err(|e| e.to_string())?
            .as_millis();
        piko_app_control::history::observe(
            &path,
            &snapshot,
            time.try_into().map_err(|_| "Invalid time")?,
            before_sequence,
        )
        .map_err(|e| e.to_string())
    })
    .await
    .map_err(|e| e.to_string())?
}

#[tauri::command]
async fn list_alert_reviews(
    app: tauri::AppHandle,
) -> Result<Vec<piko_app_control::reviews::AlertReview>, String> {
    let path = app
        .path()
        .app_local_data_dir()
        .map_err(|e| e.to_string())?
        .join("alert-reviews.sqlite");
    tauri::async_runtime::spawn_blocking(move || {
        piko_app_control::reviews::list(&path).map_err(|e| e.to_string())
    })
    .await
    .map_err(|e| e.to_string())?
}
#[tauri::command]
async fn save_alert_review(
    app: tauri::AppHandle,
    alert_id: String,
    state: piko_app_control::reviews::ReviewState,
    note: String,
) -> Result<piko_app_control::reviews::AlertReview, String> {
    let path = app
        .path()
        .app_local_data_dir()
        .map_err(|e| e.to_string())?
        .join("alert-reviews.sqlite");
    let reviewer_sid = piko_win_platform::current_identity()
        .map_err(|e| e.to_string())?
        .sid;
    let updated_at = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map_err(|e| e.to_string())?
        .as_millis()
        .try_into()
        .map_err(|_| "Invalid time")?;
    let item = piko_app_control::reviews::AlertReview {
        alert_id,
        state,
        note,
        updated_at,
        reviewer_sid,
    };
    tauri::async_runtime::spawn_blocking(move || {
        piko_app_control::reviews::save(&path, item).map_err(|e| e.to_string())
    })
    .await
    .map_err(|e| e.to_string())?
}
