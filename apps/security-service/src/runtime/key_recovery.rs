//! SCM-only bootstrap: verify with the saved key before replacing local wrapping.
use super::{
    evidence_protection::RecoverableEvidenceProtection, key_bundle, storage_config, Config,
};
use piko_event_storage::{IntegrityReport, SqliteEventStore};
use piko_ipc::SecretText;
use piko_win_platform::{
    file_response::LockedFile,
    service::{ServiceContext, SERVICE_NAME},
};
use serde::{Deserialize, Serialize};
use std::{
    error::Error,
    io::{Read, Write},
    sync::Arc,
    time::{Duration, Instant},
};
use uuid::Uuid;

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct Request {
    protocol: u16,
    nonce: Uuid,
    archive_id: Uuid,
    recipient: String,
    code: SecretText,
}
#[derive(Serialize)]
struct Report {
    protocol: u16,
    nonce: Uuid,
    result: &'static str,
    read_only_archive: bool,
    key_changes: &'static str,
    integrity: Option<IntegrityReport>,
    error_code: Option<&'static str>,
}

pub(crate) fn recover_service_keys(service: ServiceContext) -> Result<(), Box<dyn Error>> {
    let args = &service.start_arguments;
    if args.len() != 3
        || !args[0]
            .to_str()
            .is_some_and(|name| name.eq_ignore_ascii_case(SERVICE_NAME))
        || args[1] != "--recover-evidence-key"
    {
        return Err("invalid key recovery SCM arguments".into());
    }
    let supplied_nonce = args[2].to_str().ok_or("invalid recovery nonce")?;
    let nonce = Uuid::parse_str(supplied_nonce)?;
    if nonce.is_nil() || supplied_nonce != nonce.to_string() {
        return Err("invalid recovery nonce".into());
    }
    let process: Vec<_> = std::env::args_os().skip(1).collect();
    if process.len() != 3 || process[0] != "--service" || process[1] != "--config" {
        return Err("installed service configuration required".into());
    }
    let config = Config::from_reader(std::fs::File::open(&process[2])?)?;
    config.validate()?;
    if !config.data_dir.is_absolute() || config.viewer_sid.is_none() {
        return Err("installed service data required".into());
    }
    match std::fs::symlink_metadata(config.data_dir.join("archive-verification.pending")) {
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => {}
        _ => return Err("resolve the guarded update before key recovery".into()),
    }
    let mut input = LockedFile::open(&config.data_dir.join("evidence-key.recovery.pending"))?;
    if input.file.metadata()?.len() > 16384 {
        return Err("recovery request exceeds bound".into());
    }
    let mut bytes = zeroize::Zeroizing::new(Vec::with_capacity(16385));
    (&mut input.file).take(16385).read_to_end(&mut bytes)?;
    if bytes.len() > 16384 {
        return Err("recovery request exceeds bound".into());
    }
    let request: Request =
        serde_json::from_slice(&bytes).map_err(|_| "invalid private recovery request")?;
    if request.protocol != 1
        || request.nonce != nonce
        || request.archive_id.is_nil()
        || request.recipient.len() > 128
    {
        return Err("recovery request identity mismatch".into());
    }
    let mut output = LockedFile::create(
        &config
            .data_dir
            .join(format!("evidence-key.recovery-report-{nonce}.json")),
    )?;
    service.running()?;
    let deadline = Instant::now() + Duration::from_secs(180);
    let mut changes = "none";
    let result = (|| -> Result<IntegrityReport, Box<dyn Error>> {
        let key = Arc::new(piko_crypto::EvidenceKey::recover(
            request.code.expose(),
            &request.recipient,
        )?);
        let verify =
            |provider: RecoverableEvidenceProtection| -> Result<IntegrityReport, Box<dyn Error>> {
                if *service.stop.borrow() || Instant::now() >= deadline {
                    return Err("recovery cancelled".into());
                }
                let mut storage = storage_config(&config);
                storage.evidence_protection = Some(Arc::new(provider));
                storage.protect_new_evidence = false;
                let reader = SqliteEventStore::reader(config.data_dir.join("events.db"), storage)?;
                if reader.host_id() != request.archive_id {
                    return Err("archive identity mismatch".into());
                }
                if reader.evidence_protection_scheme()?.as_deref() != Some("age-x25519-v1") {
                    return Err("archive has no recoverable protection policy".into());
                }
                let stop = service.stop.clone();
                reader.set_read_operation_guard(deadline, move || *stop.borrow())?;
                let report = reader.verify_integrity()?;
                if *service.stop.borrow() || Instant::now() >= deadline {
                    return Err("recovery cancelled".into());
                }
                Ok(report)
            };
        let before = verify(RecoverableEvidenceProtection::for_read_only_recovery(
            request.archive_id,
            key.clone(),
        ))?;
        // Once begun, key-file commits are not deadline-interrupted. The durable
        // guard and immutable stages cover an interrupted per-file replacement.
        changes = "possible";
        let loaded = key_bundle::rebind_after_verified_archive(
            &config.data_dir,
            nonce,
            request.archive_id,
            &key,
        )?;
        if !loaded.backup_confirmed
            || loaded.recipient != request.recipient
            || loaded.archive_id != request.archive_id
        {
            return Err("replacement key mismatch".into());
        }
        changes = "complete";
        let after = verify(RecoverableEvidenceProtection::load(&config.data_dir))?;
        if before != after {
            return Err("archive integrity changed during key recovery".into());
        }
        Ok(after)
    })();
    let passed = result.is_ok();
    let report = Report {
        protocol: 1,
        nonce,
        result: if passed { "PASS" } else { "FAIL" },
        read_only_archive: true,
        key_changes: changes,
        integrity: result.ok(),
        error_code: if passed {
            None
        } else {
            Some("evidence_key_recovery_failed")
        },
    };
    let encoded = serde_json::to_vec(&report)?;
    if encoded.len() > 4096 {
        return Err("recovery report exceeds bound".into());
    }
    output.file.write_all(&encoded)?;
    output.file.sync_all()?;
    // Guard/request is removed only by the authorized operator after validating
    // the stopped service, report nonce and unchanged archive bytes.
    Ok(())
}
