//! One bounded key-operation queue; no secret material in diagnostics.
use super::key_bundle;
use piko_ipc::{
    ApiData, ApiError, Command, EvidenceKeyStatus, EvidenceProtectionTicket, KeyBackupReply,
    KeyBackupTicket, SecretText,
};
use std::{
    io,
    path::PathBuf,
    time::{Duration, Instant, SystemTime, UNIX_EPOCH},
};
use tokio::sync::{mpsc, oneshot};
use uuid::Uuid;

struct Job {
    command: Command,
    deadline: Instant,
    reply: oneshot::Sender<Result<ApiData, ApiError>>,
}

#[cfg(test)]
mod tests;
#[derive(Clone, Copy, PartialEq, Eq)]
enum GrantPurpose {
    Backup,
    Activate,
}
struct Grant {
    id: Uuid,
    expires: Instant,
    authorized: bool,
    delivered: bool,
    purpose: GrantPurpose,
}
#[derive(Clone)]
pub(super) struct KeyClient {
    sender: mpsc::Sender<Job>,
}
fn denied() -> ApiError {
    ApiError {
        code: "key_operation_refused".into(),
        message:
            "Key operation unavailable, expired, unauthorized or invalid; no fallback permitted"
                .into(),
    }
}
fn marker_present(path: &std::path::Path, name: &str) -> Result<bool, ApiError> {
    match std::fs::symlink_metadata(path.join(name)) {
        Ok(_) => Ok(true),
        Err(error) if error.kind() == io::ErrorKind::NotFound => Ok(false),
        Err(_) => Err(denied()),
    }
}
fn sample(
    path: &std::path::Path,
    new_raw_enabled: bool,
    recoverable_mode: bool,
) -> EvidenceKeyStatus {
    let (state, backup_confirmed) = match key_bundle::load(path) {
        Ok(key) => (
            if key.backup_confirmed {
                "ready"
            } else {
                "backup_required"
            },
            key.backup_confirmed,
        ),
        Err(error)
            if error.kind() == io::ErrorKind::NotFound
                && std::fs::symlink_metadata(path.join("evidence-key.json"))
                    .is_err_and(|e| e.kind() == io::ErrorKind::NotFound)
                && std::fs::symlink_metadata(path.join("evidence-key.confirmed.json"))
                    .is_err_and(|e| e.kind() == io::ErrorKind::NotFound) =>
        {
            ("not_prepared", false)
        }
        Err(_) => ("unavailable", false),
    };
    let activation_pending =
        marker_present(path, "evidence-protection-activation.pending").unwrap_or(true);
    EvidenceKeyStatus {
        state: state.into(),
        backup_confirmed,
        new_raw_enabled,
        recoverable_mode,
        activation_pending,
    }
}
impl KeyClient {
    pub(super) fn start(
        path: PathBuf,
        archive_id: Uuid,
        new_raw_enabled: bool,
        recoverable_mode: bool,
        service_mode: bool,
    ) -> io::Result<Self> {
        let (sender, mut jobs) = mpsc::channel::<Job>(1);
        std::thread::Builder::new()
            .name("piko-evidence-keys".into())
            .spawn(move || {
                let mut grant: Option<Grant> = None;
                while let Some(job) = jobs.blocking_recv() {
                    if job.reply.is_closed() || Instant::now() >= job.deadline {
                        continue;
                    }
                    let result = (|| -> Result<ApiData, ApiError> {
                        if matches!(&job.command, Command::GetEvidenceKeyStatus) {
                            return Ok(ApiData::EvidenceKeyStatus(if service_mode {
                                sample(&path, new_raw_enabled, recoverable_mode)
                            } else {
                                EvidenceKeyStatus {
                                    state: "unavailable".into(),
                                    backup_confirmed: false,
                                    new_raw_enabled,
                                    recoverable_mode,
                                    activation_pending: false,
                                }
                            }));
                        }
                        if !service_mode {
                            return Err(denied());
                        }
                        for marker in [
                            "archive-verification.pending",
                            "evidence-key.recovery.pending",
                        ] {
                            if marker_present(&path, marker)? {
                                return Err(denied());
                            }
                        }
                        let activation_pending =
                            marker_present(&path, "evidence-protection-activation.pending")?;
                        if activation_pending
                            && !matches!(
                                &job.command,
                                Command::BeginEvidenceProtection
                                    | Command::AuthorizeEvidenceProtection { .. }
                                    | Command::CancelKeyBackup { .. }
                            )
                        {
                            return Err(denied());
                        }
                        if grant.as_ref().is_some_and(|g| Instant::now() >= g.expires) {
                            grant = None;
                        }
                        if let Command::CancelKeyBackup { ticket_id } = &job.command {
                            if grant.as_ref().is_some_and(|g| g.id == *ticket_id) {
                                grant = None;
                            }
                            return Ok(ApiData::EvidenceKeyStatus(sample(
                                &path,
                                new_raw_enabled,
                                recoverable_mode,
                            )));
                        }
                        if matches!(
                            &job.command,
                            Command::BeginKeyBackup | Command::BeginEvidenceProtection
                        ) {
                            if grant.is_some() {
                                return Err(denied());
                            }
                            let id = Uuid::new_v4();
                            let expires_at_unix_ms = u64::try_from(
                                SystemTime::now()
                                    .duration_since(UNIX_EPOCH)
                                    .map_err(|_| denied())?
                                    .as_millis(),
                            )
                            .map_err(|_| denied())?
                            .saturating_add(300_000);
                            let purpose =
                                if matches!(&job.command, Command::BeginEvidenceProtection) {
                                    GrantPurpose::Activate
                                } else {
                                    GrantPurpose::Backup
                                };
                            grant = Some(Grant {
                                id,
                                expires: Instant::now() + Duration::from_secs(300),
                                authorized: false,
                                delivered: false,
                                purpose,
                            });
                            return Ok(if purpose == GrantPurpose::Activate {
                                ApiData::EvidenceProtectionTicket(EvidenceProtectionTicket {
                                    id,
                                    expires_at_unix_ms,
                                })
                            } else {
                                ApiData::KeyBackupTicket(KeyBackupTicket {
                                    id,
                                    expires_at_unix_ms,
                                })
                            });
                        }
                        let ticket_id = match &job.command {
                            Command::AuthorizeKeyBackup { ticket_id }
                            | Command::ReadKeyBackup { ticket_id }
                            | Command::ConfirmKeyBackup { ticket_id, .. }
                            | Command::AuthorizeEvidenceProtection { ticket_id } => *ticket_id,
                            _ => return Err(denied()),
                        };
                        let current = grant
                            .as_mut()
                            .filter(|g| g.id == ticket_id)
                            .ok_or_else(denied)?;
                        match job.command {
                            Command::AuthorizeKeyBackup { .. } => {
                                if current.purpose != GrantPurpose::Backup {
                                    return Err(denied());
                                }
                                // serve() authenticated the elevated caller before queueing.
                                current.authorized = true;
                                Ok(ApiData::EvidenceKeyStatus(sample(
                                    &path,
                                    new_raw_enabled,
                                    recoverable_mode,
                                )))
                            }
                            Command::ReadKeyBackup { .. } if current.authorized => {
                                if current.purpose != GrantPurpose::Backup {
                                    return Err(denied());
                                }
                                let loaded = match key_bundle::load(&path) {
                                    Ok(key) => key,
                                    Err(e) if e.kind() == io::ErrorKind::NotFound => {
                                        key_bundle::prepare(&path, archive_id)
                                            .map_err(|_| denied())?
                                            .0
                                    }
                                    Err(_) => return Err(denied()),
                                };
                                if loaded.archive_id != archive_id {
                                    return Err(denied());
                                }
                                let code = loaded.key.recovery_code_for_authorized_backup();
                                current.delivered = true;
                                Ok(ApiData::KeyBackup(KeyBackupReply {
                                    ticket_id,
                                    archive_id,
                                    recipient: loaded.recipient,
                                    recovery_code: SecretText::new(
                                        code.expose_for_backup().to_owned(),
                                    )
                                    .map_err(|_| denied())?,
                                }))
                            }
                            Command::ConfirmKeyBackup { code, .. }
                                if current.authorized && current.delivered =>
                            {
                                if current.purpose != GrantPurpose::Backup {
                                    return Err(denied());
                                }
                                if key_bundle::load(&path).map_err(|_| denied())?.archive_id
                                    != archive_id
                                {
                                    return Err(denied());
                                }
                                let key = key_bundle::confirm_backup(&path, code.expose())
                                    .map_err(|_| denied())?;
                                if key.archive_id != archive_id {
                                    return Err(denied());
                                }
                                grant = None;
                                Ok(ApiData::EvidenceKeyStatus(sample(
                                    &path,
                                    new_raw_enabled,
                                    recoverable_mode,
                                )))
                            }
                            Command::AuthorizeEvidenceProtection { .. } => {
                                let fresh_activation = !new_raw_enabled && !recoverable_mode;
                                let interrupted_completion =
                                    new_raw_enabled && recoverable_mode && activation_pending;
                                if current.purpose != GrantPurpose::Activate
                                    || (!fresh_activation && !interrupted_completion)
                                {
                                    return Err(denied());
                                }
                                let loaded = key_bundle::load(&path).map_err(|_| denied())?;
                                if loaded.archive_id != archive_id || !loaded.backup_confirmed {
                                    return Err(denied());
                                }
                                grant = None;
                                Ok(ApiData::EvidenceKeyStatus(sample(
                                    &path,
                                    new_raw_enabled,
                                    recoverable_mode,
                                )))
                            }
                            _ => Err(denied()),
                        }
                    })();
                    let _ = job.reply.send(result);
                }
            })?;
        Ok(Self { sender })
    }
    pub(super) async fn call(
        &self,
        command: Command,
        deadline: Instant,
    ) -> Result<ApiData, ApiError> {
        if Instant::now() >= deadline {
            return Err(denied());
        }
        let (reply, result) = oneshot::channel();
        self.sender
            .try_send(Job {
                command,
                deadline,
                reply,
            })
            .map_err(|_| denied())?;
        tokio::time::timeout_at(deadline.into(), result)
            .await
            .map_err(|_| denied())?
            .map_err(|_| denied())?
    }
}
