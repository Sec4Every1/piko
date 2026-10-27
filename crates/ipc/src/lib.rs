//! Bounded local API. Response commands require separate caller authorization.
#![forbid(unsafe_code)]

use piko_common_model::HealthSnapshot;
use piko_event_schema::{RawEvidence, SecurityEvent};
use piko_event_storage::{EventQuery, IntegrityReport};
use serde::{de::DeserializeOwned, Deserialize, Serialize};
use std::{io, time::Duration};
use tokio::io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt};

pub const PROTOCOL_VERSION: u16 = 1;
pub const MAX_REQUEST_BYTES: usize = 16 * 1024;
pub const MAX_RESPONSE_BYTES: usize = 4 * 1024 * 1024;
pub const REQUEST_TIMEOUT: Duration = Duration::from_secs(3);
pub const VERIFICATION_TIMEOUT: Duration = Duration::from_secs(32);

#[derive(Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Request {
    pub protocol_version: u16,
    pub request_id: u64,
    pub command: Command,
}

#[derive(Debug, Serialize, Deserialize)]
#[serde(
    tag = "action",
    content = "filter",
    rename_all = "snake_case",
    deny_unknown_fields
)]
pub enum Command {
    ListAlerts,
    GetResponseStatus,
    PrepareQuarantine {
        path: String,
    },
    PrepareRestore {
        action_id: uuid::Uuid,
    },
    ExecuteAction {
        action_id: uuid::Uuid,
        expected_sha256: String,
    },
    GetHealth,
    GetArchiveMaintenance,
    GetObservations,
    GetInvestigation {
        process_instance: uuid::Uuid,
    },
    GetInvestigationWindow {
        process_instance: uuid::Uuid,
        observed_from: i64,
        observed_until: i64,
    },
    GetInvestigationPage {
        process_instance: uuid::Uuid,
        observed_window: Option<(i64, i64)>,
        before: Option<(i64, uuid::Uuid)>,
    },
    ListEvents(EventQuery),
    GetAuthenticationActivity(piko_event_storage::AuthenticationQuery),
    VerifyStore,
    GetEvidence {
        evidence_id: uuid::Uuid,
    },
}

impl Command {
    pub fn is_response_mutation(&self) -> bool {
        matches!(
            self,
            Self::PrepareQuarantine { .. }
                | Self::PrepareRestore { .. }
                | Self::ExecuteAction { .. }
        )
    }
    pub fn is_response_command(&self) -> bool {
        self.is_response_mutation() || matches!(self, Self::GetResponseStatus)
    }
}

#[derive(Debug, Serialize, Deserialize)]
#[serde(tag = "type", content = "data", rename_all = "snake_case")]
pub enum ApiData {
    Alerts(Vec<piko_security_core::Alert>),
    ResponseStatus(piko_security_core::ResponseStatus),
    Action(piko_security_core::Action),
    Health(HealthSnapshot),
    ArchiveMaintenance(piko_event_storage::ArchiveMaintenanceStatus),
    Observations(piko_common_model::ObservationSnapshot),
    Investigation(piko_security_core::Investigation),
    Events(Vec<SecurityEvent>),
    AuthenticationActivity(piko_event_storage::AuthenticationPage),
    Integrity(IntegrityReport),
    Evidence(Option<RawEvidence>),
}

#[derive(Debug, Serialize, Deserialize)]
pub struct ApiError {
    pub code: String,
    pub message: String,
}

#[derive(Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Response {
    pub protocol_version: u16,
    pub request_id: u64,
    pub result: Result<ApiData, ApiError>,
}

pub async fn read_frame<T: DeserializeOwned>(
    stream: &mut (impl AsyncRead + Unpin),
    max: usize,
) -> io::Result<T> {
    let length = stream.read_u32_le().await? as usize;
    if length == 0 || length > max {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            "IPC frame exceeds permitted size",
        ));
    }
    let mut bytes = vec![0u8; length];
    stream.read_exact(&mut bytes).await?;
    serde_json::from_slice(&bytes).map_err(|err| io::Error::new(io::ErrorKind::InvalidData, err))
}

pub async fn write_frame<T: Serialize>(
    stream: &mut (impl AsyncWrite + Unpin),
    value: &T,
    max: usize,
) -> io::Result<()> {
    let bytes = serde_json::to_vec(value).map_err(io::Error::other)?;
    if bytes.is_empty() || bytes.len() > max || bytes.len() > u32::MAX as usize {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            "IPC response exceeds permitted size",
        ));
    }
    stream.write_u32_le(bytes.len() as u32).await?;
    stream.write_all(&bytes).await?;
    stream.flush().await
}

#[cfg(windows)]
pub async fn call(command: Command) -> io::Result<ApiData> {
    use std::sync::atomic::{AtomicU64, Ordering};
    use tokio::net::windows::named_pipe::ClientOptions;
    static NEXT_REQUEST: AtomicU64 = AtomicU64::new(1);
    let request_id = NEXT_REQUEST.fetch_add(1, Ordering::Relaxed);
    let identity = piko_win_platform::current_identity()?;
    let timeout = if matches!(&command, Command::VerifyStore) {
        VERIFICATION_TIMEOUT
    } else {
        REQUEST_TIMEOUT
    };
    let exchange = async {
        let service_pid = piko_win_platform::service::installed_service_pid()?;
        // Tokio's default SECURITY_IDENTIFICATION prevents a peer from using the
        // client's authority for privileged impersonation operations.
        let mut pipe = loop {
            let connection = match service_pid {
                Some(pid) => piko_win_platform::open_service_pipe(pid),
                None => ClientOptions::new().open(identity.pipe_name()),
            };
            match connection {
                Ok(pipe) => break pipe,
                Err(error) if error.raw_os_error() == Some(231) => {
                    tokio::time::sleep(Duration::from_millis(25)).await;
                }
                Err(error) => return Err(error),
            }
        };
        if service_pid.is_none() {
            piko_win_platform::authenticate_server(&pipe, &identity)?;
        }
        let request = Request {
            protocol_version: PROTOCOL_VERSION,
            request_id,
            command,
        };
        write_frame(&mut pipe, &request, MAX_REQUEST_BYTES).await?;
        let response: Response = read_frame(&mut pipe, MAX_RESPONSE_BYTES).await?;
        if response.protocol_version != PROTOCOL_VERSION || response.request_id != request_id {
            return Err(io::Error::new(
                io::ErrorKind::InvalidData,
                "IPC version/request mismatch",
            ));
        }
        response
            .result
            .map_err(|error| io::Error::other(format!("{}: {}", error.code, error.message)))
    };
    tokio::time::timeout(timeout, exchange)
        .await
        .map_err(|_| io::Error::new(io::ErrorKind::TimedOut, "piko runtime did not respond"))?
}

#[cfg(not(windows))]
pub async fn call(_command: Command) -> io::Result<ApiData> {
    Err(io::Error::new(
        io::ErrorKind::Unsupported,
        "piko IPC requires Windows",
    ))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn decoder_rejects_unknown_commands_fields_and_oversize_before_body() -> io::Result<()> {
        let runtime = tokio::runtime::Builder::new_current_thread()
            .enable_all()
            .build()?;
        runtime.block_on(async {
            assert!(serde_json::from_str::<Request>(r#"{"protocol_version":1,"request_id":1,"command":{"action":"terminate"}}"#).is_err());
            assert!(serde_json::from_str::<Request>(r#"{"protocol_version":1,"request_id":1,"command":{"action":"get_health"},"admin":true}"#).is_err());
            let header = (MAX_REQUEST_BYTES as u32 + 1).to_le_bytes();
            let mut stream = &header[..];
            let result = read_frame::<Request>(&mut stream, MAX_REQUEST_BYTES).await;
            assert_eq!(result.err().map(|e| e.kind()), Some(io::ErrorKind::InvalidData));
            Ok(())
        })
    }

    #[test]
    fn frame_roundtrip_and_truncation() -> io::Result<()> {
        let runtime = tokio::runtime::Builder::new_current_thread()
            .enable_all()
            .build()?;
        runtime.block_on(async {
            let request = Request {
                protocol_version: 1,
                request_id: 42,
                command: Command::GetHealth,
            };
            let mut bytes = Vec::new();
            write_frame(&mut bytes, &request, MAX_REQUEST_BYTES).await?;
            let received: Request = read_frame(&mut bytes.as_slice(), MAX_REQUEST_BYTES).await?;
            assert_eq!(received.request_id, 42);
            bytes.pop();
            assert!(
                read_frame::<Request>(&mut bytes.as_slice(), MAX_REQUEST_BYTES)
                    .await
                    .is_err()
            );
            Ok(())
        })
    }
}
