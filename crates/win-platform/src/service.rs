//! SCM adapter: lifecycle and server identity checks behind safe interfaces.
use std::{ffi::OsString, io, sync::OnceLock, time::Duration};
use tokio::sync::watch;
use windows_service::{
    define_windows_service,
    service::{
        ServiceAccess, ServiceControl, ServiceControlAccept, ServiceExitCode, ServiceState,
        ServiceStatus, ServiceType,
    },
    service_control_handler::{self, ServiceControlHandlerResult, ServiceStatusHandle},
    service_dispatcher,
    service_manager::{ServiceManager, ServiceManagerAccess},
};

pub const SERVICE_NAME: &str = "piko";
pub const PIPE_NAME: &str = r"\\.\pipe\piko.service.v1";

/// Installer-only operation. SCM enforces CHANGE_CONFIG/START rights; this is not
/// exposed over IPC and does not elevate the calling process.
pub fn configure_recovery_policy() -> io::Result<()> {
    use windows_service::service::{
        ServiceAction, ServiceActionType, ServiceFailureActions, ServiceFailureResetPeriod,
    };
    let manager = ServiceManager::local_computer(None::<&str>, ServiceManagerAccess::CONNECT)
        .map_err(io::Error::other)?;
    let service = manager
        .open_service(
            SERVICE_NAME,
            ServiceAccess::CHANGE_CONFIG | ServiceAccess::START,
        )
        .map_err(io::Error::other)?;
    service
        .update_failure_actions(ServiceFailureActions {
            reset_period: ServiceFailureResetPeriod::After(Duration::from_secs(86400)),
            reboot_msg: None,
            command: None,
            actions: Some(vec![
                ServiceAction {
                    action_type: ServiceActionType::Restart,
                    delay: Duration::from_secs(10),
                },
                ServiceAction {
                    action_type: ServiceActionType::Restart,
                    delay: Duration::from_secs(30),
                },
                ServiceAction {
                    action_type: ServiceActionType::None,
                    delay: Duration::ZERO,
                },
            ]),
        })
        .map_err(io::Error::other)?;
    service
        .set_failure_actions_on_non_crash_failures(true)
        .map_err(io::Error::other)
}
type Entry = fn(ServiceContext) -> u32;
static ENTRY: OnceLock<Entry> = OnceLock::new();

pub struct ServiceContext {
    pub stop: watch::Receiver<bool>,
    /// Ephemeral SCM StartService arguments, including the service name first.
    /// These are distinct from the permanent executable command line.
    pub start_arguments: Vec<OsString>,
    status: ServiceStatusHandle,
}
impl ServiceContext {
    pub fn running(&self) -> io::Result<()> {
        self.report(ServiceState::Running, 0)
    }
    pub fn stopping(&self) -> io::Result<()> {
        self.report(ServiceState::StopPending, 0)
    }
    fn report(&self, state: ServiceState, exit: u32) -> io::Result<()> {
        self.status
            .set_service_status(status(state, exit))
            .map_err(io::Error::other)
    }
}
fn status(state: ServiceState, exit: u32) -> ServiceStatus {
    let pending = matches!(
        state,
        ServiceState::StartPending | ServiceState::StopPending
    );
    ServiceStatus {
        service_type: ServiceType::OWN_PROCESS,
        current_state: state,
        controls_accepted: if state == ServiceState::Running {
            ServiceControlAccept::STOP | ServiceControlAccept::SHUTDOWN
        } else {
            ServiceControlAccept::empty()
        },
        exit_code: ServiceExitCode::Win32(exit),
        checkpoint: u32::from(pending),
        wait_hint: if pending {
            Duration::from_secs(30)
        } else {
            Duration::ZERO
        },
        process_id: None,
    }
}

// SAFETY: windows-service owns SCM callback argument parsing and handler lifetime.
// No raw callback pointers or references cross this crate's public interface.
define_windows_service!(ffi_main, service_main);
fn service_main(arguments: Vec<OsString>) {
    let (sender, receiver) = watch::channel(false);
    let handle = match service_control_handler::register(SERVICE_NAME, move |control| match control
    {
        ServiceControl::Stop | ServiceControl::Shutdown => {
            sender.send_replace(true);
            ServiceControlHandlerResult::NoError
        }
        ServiceControl::Interrogate => ServiceControlHandlerResult::NoError,
        _ => ServiceControlHandlerResult::NotImplemented,
    }) {
        Ok(handle) => handle,
        Err(_) => return,
    };
    if handle
        .set_service_status(status(ServiceState::StartPending, 0))
        .is_err()
    {
        return;
    }
    let code = match ENTRY.get() {
        Some(entry) => entry(ServiceContext {
            stop: receiver,
            start_arguments: arguments,
            status: handle,
        }),
        None => 1,
    };
    let _ = handle.set_service_status(status(ServiceState::Stopped, code));
}

pub fn dispatch(entry: Entry) -> io::Result<()> {
    ENTRY
        .set(entry)
        .map_err(|_| io::Error::other("SCM dispatcher already initialized"))?;
    service_dispatcher::start(SERVICE_NAME, ffi_main).map_err(io::Error::other)
}

/// Offline maintenance requires an installed, stopped own-process service.
/// Missing services return NotFound; transitional/paused states never count as stopped.
pub fn require_installed_service_stopped() -> io::Result<()> {
    let manager = ServiceManager::local_computer(None::<&str>, ServiceManagerAccess::CONNECT)
        .map_err(io::Error::other)?;
    let service = match manager.open_service(SERVICE_NAME, ServiceAccess::QUERY_STATUS) {
        Ok(service) => service,
        Err(windows_service::Error::Winapi(error)) if error.raw_os_error() == Some(1060) => {
            return Err(io::Error::new(
                io::ErrorKind::NotFound,
                "offline verification requires an installed piko service",
            ));
        }
        Err(error) => return Err(io::Error::other(error)),
    };
    require_stopped_status(&service.query_status().map_err(io::Error::other)?)
}

fn require_stopped_status(status: &ServiceStatus) -> io::Result<()> {
    if status.current_state != ServiceState::Stopped
        || status.service_type != ServiceType::OWN_PROCESS
    {
        return Err(io::Error::other(
            "offline verification requires piko service to be fully stopped",
        ));
    }
    Ok(())
}

/// None means not installed. Stopped or inaccessible services are explicit errors:
/// callers must not silently fall back to an unrelated development endpoint.
pub fn installed_service_pid() -> io::Result<Option<u32>> {
    let manager = ServiceManager::local_computer(None::<&str>, ServiceManagerAccess::CONNECT)
        .map_err(io::Error::other)?;
    let service = match manager.open_service(SERVICE_NAME, ServiceAccess::QUERY_STATUS) {
        Ok(service) => service,
        Err(windows_service::Error::Winapi(error)) if error.raw_os_error() == Some(1060) => {
            return Ok(None);
        }
        Err(error) => return Err(io::Error::other(error)),
    };
    let status = service.query_status().map_err(io::Error::other)?;
    if status.current_state != ServiceState::Running
        || status.service_type != ServiceType::OWN_PROCESS
    {
        return Err(io::Error::new(
            io::ErrorKind::NotConnected,
            "installed piko service is not running",
        ));
    }
    match status.process_id.filter(|pid| *pid != 0) {
        Some(pid) => Ok(Some(pid)),
        None => Err(io::Error::new(
            io::ErrorKind::NotConnected,
            "SCM returned no service PID",
        )),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn offline_gate_accepts_only_stopped_own_process_service() {
        assert!(require_stopped_status(&status(ServiceState::Stopped, 0)).is_ok());
        for state in [
            ServiceState::Running,
            ServiceState::StartPending,
            ServiceState::StopPending,
            ServiceState::Paused,
            ServiceState::PausePending,
            ServiceState::ContinuePending,
        ] {
            assert!(require_stopped_status(&status(state, 0)).is_err());
        }
        let mut shared = status(ServiceState::Stopped, 0);
        shared.service_type = ServiceType::SHARE_PROCESS;
        assert!(require_stopped_status(&shared).is_err());
    }
}
