//! Real key worker refusal paths; no key material, SCM or installed data.
use super::*;
use std::{error::Error, fs};

type TestResult = Result<(), Box<dyn Error>>;

struct Directory(PathBuf);
impl Directory {
    fn new() -> io::Result<Self> {
        let path = std::env::temp_dir().join(format!("piko-key-worker-test-{}", Uuid::new_v4()));
        fs::create_dir(&path)?;
        Ok(Self(path))
    }
    fn client(&self, service_mode: bool) -> io::Result<KeyClient> {
        KeyClient::start(
            self.0.clone(),
            Uuid::from_u128(1),
            false,
            false,
            service_mode,
        )
    }
    fn has_no_keys(&self) -> bool {
        !self.0.join("evidence-key.json").exists()
            && !self.0.join("evidence-key.confirmed.json").exists()
    }
}
impl Drop for Directory {
    fn drop(&mut self) {
        let _ = fs::remove_dir_all(&self.0);
    }
}
fn deadline() -> Instant {
    Instant::now() + Duration::from_secs(5)
}
fn ticket(result: Result<ApiData, ApiError>) -> Result<Uuid, Box<dyn Error>> {
    match result {
        Ok(ApiData::KeyBackupTicket(value)) => Ok(value.id),
        Ok(ApiData::EvidenceProtectionTicket(value)) => Ok(value.id),
        _ => Err("expected a bounded key ticket".into()),
    }
}

#[tokio::test]
async fn console_mode_never_prepares_or_discloses_a_key() -> TestResult {
    let directory = Directory::new()?;
    let client = directory.client(false)?;
    let status = client.call(Command::GetEvidenceKeyStatus, deadline()).await;
    let Ok(ApiData::EvidenceKeyStatus(status)) = status else {
        return Err("missing key status".into());
    };
    assert_eq!(status.state, "unavailable");
    assert!(!status.backup_confirmed && !status.new_raw_enabled && !status.recoverable_mode);
    assert!(client
        .call(Command::BeginKeyBackup, deadline())
        .await
        .is_err());
    assert!(client
        .call(Command::BeginEvidenceProtection, deadline())
        .await
        .is_err());
    assert!(directory.has_no_keys());
    Ok(())
}

#[tokio::test]
async fn grant_identity_purpose_and_disclosure_order_are_enforced() -> TestResult {
    let directory = Directory::new()?;
    let client = directory.client(true)?;
    let backup = ticket(client.call(Command::BeginKeyBackup, deadline()).await)?;
    for command in [
        Command::ReadKeyBackup { ticket_id: backup },
        Command::ConfirmKeyBackup {
            ticket_id: backup,
            code: SecretText::new("synthetic-code".into())?,
        },
        Command::AuthorizeEvidenceProtection { ticket_id: backup },
        Command::AuthorizeKeyBackup {
            ticket_id: Uuid::from_u128(2),
        },
    ] {
        assert!(client.call(command, deadline()).await.is_err());
    }
    // A stale cancellation cannot discard the currently pending authorization.
    assert!(client
        .call(
            Command::CancelKeyBackup {
                ticket_id: Uuid::from_u128(2)
            },
            deadline()
        )
        .await
        .is_ok());
    assert!(client
        .call(Command::BeginKeyBackup, deadline())
        .await
        .is_err());
    assert!(client
        .call(Command::CancelKeyBackup { ticket_id: backup }, deadline())
        .await
        .is_ok());
    let activation = ticket(
        client
            .call(Command::BeginEvidenceProtection, deadline())
            .await,
    )?;
    assert_ne!(activation, backup);
    assert!(client
        .call(
            Command::AuthorizeKeyBackup {
                ticket_id: activation
            },
            deadline()
        )
        .await
        .is_err());
    assert!(client
        .call(
            Command::ReadKeyBackup {
                ticket_id: activation
            },
            deadline()
        )
        .await
        .is_err());
    assert!(directory.has_no_keys());
    Ok(())
}

#[tokio::test]
async fn expired_request_does_not_leave_a_pending_grant() -> TestResult {
    let directory = Directory::new()?;
    let client = directory.client(true)?;
    assert!(client
        .call(
            Command::BeginKeyBackup,
            Instant::now() - Duration::from_secs(1)
        )
        .await
        .is_err());
    let id = ticket(client.call(Command::BeginKeyBackup, deadline()).await)?;
    assert!(!id.is_nil());
    assert!(directory.has_no_keys());
    Ok(())
}

#[tokio::test]
async fn guarded_recovery_markers_refuse_new_grants_without_removing_evidence() -> TestResult {
    for name in [
        "archive-verification.pending",
        "evidence-key.recovery.pending",
    ] {
        let directory = Directory::new()?;
        let marker = directory.0.join(name);
        fs::write(&marker, b"synthetic pending evidence")?;
        let client = directory.client(true)?;
        assert!(client
            .call(Command::BeginKeyBackup, deadline())
            .await
            .is_err());
        assert!(client
            .call(Command::BeginEvidenceProtection, deadline())
            .await
            .is_err());
        assert_eq!(fs::read(marker)?, b"synthetic pending evidence");
        assert!(directory.has_no_keys());
    }
    Ok(())
}

#[tokio::test]
async fn pending_activation_allows_resume_ticket_but_not_backup_or_implicit_enable() -> TestResult {
    let directory = Directory::new()?;
    let marker = directory.0.join("evidence-protection-activation.pending");
    fs::write(&marker, b"synthetic pending activation")?;
    let client = directory.client(true)?;
    let Ok(ApiData::EvidenceKeyStatus(status)) =
        client.call(Command::GetEvidenceKeyStatus, deadline()).await
    else {
        return Err("missing activation status".into());
    };
    assert!(status.activation_pending);
    assert!(!status.new_raw_enabled && !status.recoverable_mode);
    assert!(client
        .call(Command::BeginKeyBackup, deadline())
        .await
        .is_err());
    let activation = ticket(
        client
            .call(Command::BeginEvidenceProtection, deadline())
            .await,
    )?;
    // No confirmed key exists. A ticket itself must not authorize encryption.
    assert!(client
        .call(
            Command::AuthorizeEvidenceProtection {
                ticket_id: activation
            },
            deadline()
        )
        .await
        .is_err());
    assert_eq!(fs::read(marker)?, b"synthetic pending activation");
    assert!(directory.has_no_keys());
    Ok(())
}
