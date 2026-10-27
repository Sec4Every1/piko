//! One-shot SCM validation under the archive's original Windows account.
use super::{storage_config, Config};
use piko_event_storage::{IntegrityReport, SqliteEventStore};
use piko_win_platform::service::{ServiceContext, SERVICE_NAME};
use serde::Serialize;
use std::{
    error::Error,
    io,
    io::Write,
    os::windows::fs::MetadataExt,
    path::Path,
    time::{Duration, Instant},
};
use uuid::Uuid;

pub(crate) fn archive_capabilities() {
    println!(
        "{}",
        serde_json::json!({
            "protocol": 1,
            "service_read_only_verification": true,
            "report_version": 1,
            "key_recovery_portable": false,
            "normal_start_guard": true,
        })
    );
}

#[derive(Serialize)]
struct VerificationReport {
    protocol: u16,
    nonce: Uuid,
    result: &'static str,
    read_only: bool,
    scope: &'static str,
    integrity: Option<IntegrityReport>,
    error_code: Option<&'static str>,
}

fn existing_plain_directory(path: &Path) -> io::Result<()> {
    for ancestor in path.ancestors() {
        let metadata = std::fs::symlink_metadata(ancestor)?;
        if !metadata.is_dir() || metadata.file_attributes() & 0x400 != 0 {
            return Err(io::Error::other(
                "archive report directory must not use reparse paths",
            ));
        }
    }
    Ok(())
}

pub(crate) fn verify_service_archive(service: ServiceContext) -> Result<(), Box<dyn Error>> {
    // Never accept a path or arbitrary operation over SCM start arguments.
    let args = &service.start_arguments;
    if args.len() != 3
        || !args[0]
            .to_str()
            .is_some_and(|name| name.eq_ignore_ascii_case(SERVICE_NAME))
        || args[1] != "--verify-archive"
    {
        return Err("unsupported SCM maintenance arguments; monitor was not started".into());
    }
    let value = args[2]
        .to_str()
        .ok_or("invalid archive verification nonce")?;
    let nonce = Uuid::parse_str(value)?;
    if nonce.is_nil() || nonce.to_string() != value {
        return Err("archive verification requires a canonical non-nil UUID".into());
    }
    let process_args: Vec<_> = std::env::args_os().skip(1).collect();
    if process_args.len() != 3 || process_args[0] != "--service" || process_args[1] != "--config" {
        return Err("archive verification requires the installed service configuration".into());
    }
    let config = Config::from_reader(std::fs::File::open(&process_args[2])?)?;
    config.validate()?;
    if !config.data_dir.is_absolute() || config.viewer_sid.is_none() {
        return Err(
            "service archive verification requires absolute data_dir and viewer_sid".into(),
        );
    }
    existing_plain_directory(&config.data_dir)?;
    #[derive(serde::Deserialize)]
    #[serde(deny_unknown_fields)]
    struct PendingVerification {
        protocol: u16,
        nonce: Uuid,
    }
    let marker = config.data_dir.join("archive-verification.pending");
    let metadata = std::fs::symlink_metadata(&marker)?;
    if !metadata.is_file() || metadata.file_attributes() & 0x400 != 0 || metadata.len() > 1024 {
        return Err("invalid archive verification guard".into());
    }
    let input = std::fs::File::open(&marker)?;
    let pending: PendingVerification = serde_json::from_reader(std::io::Read::take(input, 1025))?;
    if pending.protocol != 1 || pending.nonce != nonce {
        return Err("archive verification guard does not match this operation".into());
    }
    let path = config
        .data_dir
        .join(format!("archive-verification-{nonce}.json"));
    // Existing narrow platform helper: exclusive create_new and inspected handle.
    // Inherits the private service-data ACL. Never overwrites a prior report.
    let mut output = piko_win_platform::file_response::LockedFile::create(&path)?;
    service.running()?;
    let deadline = Instant::now() + Duration::from_secs(90);
    let verification = (|| -> Result<IntegrityReport, Box<dyn Error>> {
        if *service.stop.borrow() {
            return Err("archive verification cancelled".into());
        }
        let store =
            SqliteEventStore::reader(config.data_dir.join("events.db"), storage_config(&config))?;
        let stop = service.stop.clone();
        store.set_read_operation_guard(deadline, move || *stop.borrow())?;
        let report = store.verify_integrity()?;
        if Instant::now() >= deadline || *service.stop.borrow() {
            return Err("archive verification deadline or stop requested".into());
        }
        Ok(report)
    })();
    let passed = verification.is_ok();
    let report = VerificationReport {
        protocol: 1,
        nonce,
        result: if passed { "PASS" } else { "FAIL" },
        read_only: true,
        scope: "service_identity_archive_verification",
        integrity: verification.ok(),
        // Avoid publishing evidence, paths or DPAPI diagnostics in the receipt.
        error_code: if passed {
            None
        } else {
            Some("archive_verification_failed")
        },
    };
    let bytes = serde_json::to_vec(&report)?;
    if bytes.len() > 4096 {
        return Err("archive verification report exceeds bound".into());
    }
    output.file.write_all(&bytes)?;
    output.file.sync_all()?;
    // A verification refusal is a completed diagnostic, not a crashed service:
    // SCM restart-on-failure must never turn this into a normal collector start.
    Ok(())
}
