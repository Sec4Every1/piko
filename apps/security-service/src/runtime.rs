mod evidence_protection;
mod key_bundle;
mod key_recovery;
mod key_worker;
pub(super) use key_recovery::recover_service_keys;
mod archive_verification;
pub(super) use archive_verification::{archive_capabilities, verify_service_archive};
mod image_files;
mod image_repetition;
mod performance;
mod response_worker;
mod storage_worker;

use piko_common_model::{HealthSnapshot, SensorHealth};
use piko_event_fabric::BoundedRecordQueue;
use piko_event_schema::{EventRecord, IdentityContext, SecurityEvent, Severity};
use piko_event_storage::StorageConfig;
use piko_ipc::{
    ApiData, Command, Request, Response, MAX_REQUEST_BYTES, MAX_RESPONSE_BYTES, PROTOCOL_VERSION,
};
use piko_win_platform::service::ServiceContext;
use piko_win_platform::{
    authenticate_client, create_private_pipe, create_service_pipe, current_identity, LocalIdentity,
};
use piko_win_sensors::{EtwCollector, EventLogCollector, ObservationCollector};
use serde::Deserialize;
use std::{
    error::Error,
    io::{self, Read},
    path::PathBuf,
    time::{Duration, Instant, SystemTime, UNIX_EPOCH},
};
use storage_worker::{api_error, AppendResult, StorageClient};
use tokio::{
    net::windows::named_pipe::NamedPipeServer,
    sync::{oneshot, watch},
    task::JoinSet,
};
use uuid::Uuid;

const MAX_CLIENTS: usize = 4;
const REQUEST_DEADLINE: Duration = Duration::from_millis(750);
const SHUTDOWN_DEADLINE: Duration = Duration::from_secs(7);

fn quota_exhausted(error: Option<&str>) -> bool {
    matches!(
        error,
        Some(
            "SQLite error: database or disk is full"
                | "storage budget exhausted; batch was not accepted"
        )
    )
}

pub fn verify_evidence() -> Result<(), Box<dyn Error>> {
    let args: Vec<String> = std::env::args().skip(1).collect();
    if args.len() != 3 || args[1] != "--config" || !piko_win_platform::current_process_elevated()? {
        return Err(
            "offline evidence verification requires administrator and --config <path>".into(),
        );
    }
    piko_win_platform::service::require_installed_service_stopped()?;
    let config = Config::from_reader(std::fs::File::open(&args[2])?)?;
    let report = verify_evidence_archive(&config)?;
    println!(
        "{}",
        serde_json::json!({"result":"PASS","verified_events":report.verified_events,"head_hash":report.head_hash,"expired_events":report.expired_events,"externally_anchored":report.externally_anchored,"read_only":true})
    );
    Ok(())
}

fn verify_evidence_archive(
    config: &Config,
) -> Result<piko_event_storage::IntegrityReport, Box<dyn Error>> {
    config.validate()?;
    // Reader mode refuses a missing archive and performs no schema migration.
    // SQLite can still create/update transient WAL shared-memory metadata.
    let store = piko_event_storage::SqliteEventStore::reader(
        config.data_dir.join("events.db"),
        storage_config(config),
    )?;
    Ok(store.verify_integrity()?)
}

pub fn compact_evidence() -> Result<(), Box<dyn Error>> {
    let args: Vec<String> = std::env::args().skip(1).collect();
    if args.len() != 3 || args[1] != "--config" || !piko_win_platform::current_process_elevated()? {
        return Err(
            "offline evidence compression requires administrator and --config <path>".into(),
        );
    }
    match piko_win_platform::service::installed_service_pid() {
        Ok(Some(_)) => return Err("stop piko service before offline compression".into()),
        Err(e) if e.kind() == io::ErrorKind::NotConnected => {}
        Ok(None) => {}
        Err(e) => return Err(e.into()),
    }
    let config = Config::from_reader(std::fs::File::open(&args[2])?)?;
    config.validate()?;
    require_no_pending_archive_verification(&config)?;
    let mut store = piko_event_storage::SqliteEventStore::open(
        config.data_dir.join("events.db"),
        storage_config(&config),
    )?;
    let before = store.verify_integrity()?;
    let (mut cursor, mut scanned, mut changed, mut saved) = (0, 0, 0, 0);
    loop {
        let (next, rows, compressed, bytes) = store.compress_existing_evidence(cursor)?;
        if rows == 0 {
            break;
        }
        cursor = next;
        scanned += rows;
        changed += compressed;
        saved += bytes;
    }
    let after = store.verify_integrity()?;
    if before.verified_events != after.verified_events || before.head_hash != after.head_hash {
        return Err("integrity changed during compression".into());
    }
    println!(
        "{}",
        serde_json::json!({"result":"PASS","scanned":scanned,"compressed":changed,"logical_bytes_saved":saved,"verified_events":after.verified_events,"head_hash":after.head_hash,"database_file_shrunk":false})
    );
    Ok(())
}

pub fn remove_noise() -> Result<(), Box<dyn Error>> {
    let args: Vec<String> = std::env::args().skip(1).collect();
    if args.len() != 3 || args[1] != "--config" || !piko_win_platform::current_process_elevated()? {
        return Err("offline noise cleanup requires administrator and --config <path>".into());
    }
    match piko_win_platform::service::installed_service_pid() {
        Ok(Some(_)) => return Err("stop piko service before noise cleanup".into()),
        Err(e) if e.kind() == io::ErrorKind::NotConnected => {}
        Ok(None) => {}
        Err(e) => return Err(e.into()),
    }
    let config = Config::from_reader(std::fs::File::open(&args[2])?)?;
    config.validate()?;
    require_no_pending_archive_verification(&config)?;
    let source = piko_event_storage::SqliteEventStore::reader(
        config.data_dir.join("events.db"),
        storage_config(&config),
    )?;
    let destination = config.data_dir.join("events.without-noise.db");
    let report = source.copy_without_noise(&destination)?;
    println!("{}", serde_json::to_string(&report)?);
    Ok(())
}

#[derive(Debug, Deserialize)]
#[serde(default, deny_unknown_fields)]
struct Config {
    data_dir: PathBuf,
    heartbeat_seconds: u64,
    flush_seconds: u64,
    max_disk_mib: u64,
    queue_capacity: usize,
    viewer_sid: Option<String>,
    response_roots: Option<Vec<PathBuf>>,
    retention_months: Option<u8>,
    protect_raw_evidence: bool,
    recoverable_raw_evidence: bool,
    archive_maintenance: bool,
}

impl Default for Config {
    fn default() -> Self {
        Self {
            data_dir: PathBuf::from(".runtime"),
            heartbeat_seconds: 5,
            flush_seconds: 15,
            max_disk_mib: 256,
            queue_capacity: 256,
            viewer_sid: None,
            response_roots: None,
            retention_months: None,
            protect_raw_evidence: false,
            recoverable_raw_evidence: false,
            archive_maintenance: true,
        }
    }
}

impl Config {
    fn validate(&self) -> io::Result<()> {
        if !(1..=300).contains(&self.heartbeat_seconds)
            || !(1..=300).contains(&self.flush_seconds)
            || !(8..=4096).contains(&self.max_disk_mib)
            || !(4..=4096).contains(&self.queue_capacity)
            || self
                .retention_months
                .is_some_and(|months| !(1..=120).contains(&months))
            || self.data_dir.as_os_str().is_empty()
            || self
                .response_roots
                .as_ref()
                .is_some_and(|roots| roots.len() > 16 || roots.iter().any(|p| !p.is_absolute()))
            || self
                .viewer_sid
                .as_ref()
                .is_some_and(|sid| !piko_win_platform::valid_sid_text(sid))
        {
            return Err(io::Error::new(
                io::ErrorKind::InvalidInput,
                "invalid runtime configuration",
            ));
        }
        Ok(())
    }

    fn from_reader(reader: impl Read) -> Result<Self, Box<dyn Error>> {
        let mut bytes = Vec::new();
        reader.take(16 * 1024 + 1).read_to_end(&mut bytes)?;
        if bytes.len() > 16 * 1024 {
            return Err("configuration exceeds 16 KiB".into());
        }
        Ok(serde_json::from_slice(&bytes)?)
    }
}

fn require_no_pending_archive_verification(config: &Config) -> io::Result<()> {
    match std::fs::symlink_metadata(
        config
            .data_dir
            .join("evidence-protection-activation.pending"),
    ) {
        Ok(_) if !config.protect_raw_evidence || !config.recoverable_raw_evidence => {
            return Err(io::Error::other(
                "evidence protection activation is pending; resume the guarded activation before collection",
            ));
        }
        Ok(_) => {}
        Err(error) if error.kind() == io::ErrorKind::NotFound => {}
        Err(error) => return Err(error),
    }
    match std::fs::symlink_metadata(config.data_dir.join("evidence-key.recovery.pending")) {
        Ok(_) => {
            return Err(io::Error::other(
                "evidence key recovery is pending; complete its guarded transaction before normal operation",
            ));
        }
        Err(error) if error.kind() == io::ErrorKind::NotFound => {}
        Err(error) => return Err(error),
    }
    match std::fs::symlink_metadata(config.data_dir.join("archive-verification.pending")) {
        Ok(_) => Err(io::Error::other(
            "archive verification is pending; normal collection and offline rewrites are blocked until the updater resolves its guarded transaction",
        )),
        Err(error) if error.kind() == io::ErrorKind::NotFound => Ok(()),
        Err(error) => Err(error),
    }
}

fn storage_config(config: &Config) -> StorageConfig {
    StorageConfig {
        max_disk_bytes: config.max_disk_mib * 1024 * 1024,
        retention_months: config.retention_months,
        protect_new_evidence: config.protect_raw_evidence,
        // Keep the reader available even when new-evidence protection is disabled:
        // archives may contain protected records from an earlier configuration.
        evidence_protection: Some(if config.recoverable_raw_evidence {
            std::sync::Arc::new(evidence_protection::RecoverableEvidenceProtection::load(
                &config.data_dir,
            )) as std::sync::Arc<dyn piko_event_storage::EvidenceProtection>
        } else {
            std::sync::Arc::new(evidence_protection::WindowsEvidenceProtection)
        }),
        ..StorageConfig::default()
    }
}

struct State {
    storage: StorageClient,
    host_id: Uuid,
    stored_events: u64,
    queue: BoundedRecordQueue,
    /// Retained until the worker acknowledges a durable commit, including on
    /// worker failure. At most one batch is in flight; event IDs never change.
    pending: Vec<EventRecord>,
    /// Context anchors are published only after their batch is durable.
    pending_images: Option<image_repetition::Prepared>,
    image_repetition: image_repetition::Repetition,
    in_flight: Option<oneshot::Receiver<AppendResult>>,
    identity: LocalIdentity,
    instance: Uuid,
    started: Instant,
    sequence: u64,
    reported_loss: u64,
    last_seen: Option<i64>,
    storage_error: Option<String>,
    performance_sampler: performance::Sampler,
    performance_metrics: Option<piko_common_model::RuntimePerformance>,
    performance_error: Option<String>,
    sensor_health: watch::Receiver<Vec<SensorHealth>>,
    observation_health: watch::Receiver<SensorHealth>,
    etw_health: watch::Receiver<SensorHealth>,
    etw_error: Option<String>,
    etw_rejected: u64,
    source_last_seen: std::collections::HashMap<String, i64>,
    durable_health: std::collections::HashMap<String, (String, Instant)>,
    service_mode: bool,
    response_enabled: bool,
}

impl State {
    fn record_sensor_health(&mut self, sensor: SensorHealth) -> Result<(), Box<dyn Error>> {
        // Statistics remain live in the health cache. Persist state changes and
        // periodic degraded evidence, without a new archive row every two seconds.
        let signature = if sensor.id == piko_win_sensors::ETW_SENSOR_ID
            && sensor
                .detail
                .starts_with("Real-time manifest process/image ETW;")
        {
            format!(
                "{}:{}",
                sensor.state,
                sensor
                    .detail
                    .split("ProcessTrace running:")
                    .nth(1)
                    .unwrap_or(&sensor.detail)
            )
        } else {
            format!("{}:{}", sensor.state, sensor.detail)
        };
        if self
            .durable_health
            .get(&sensor.id)
            .is_some_and(|(old, at)| {
                old == &signature
                    && (sensor.state != "degraded" || at.elapsed() < Duration::from_secs(60))
            })
        {
            return Ok(());
        }
        let mut event = self.event("telemetry.sensor_state", &sensor.state)?;
        event.target = Some(piko_event_schema::EventTarget {
            kind: sensor.id.clone(),
            identifier: sensor.detail,
        });
        if sensor.state == "degraded" {
            event.severity = Severity::Medium;
        }
        // Retry on a full queue; never mark an unwritten transition as recorded.
        if self
            .queue
            .try_push(EventRecord {
                event,
                raw_evidence: None,
            })
            .is_ok()
        {
            self.durable_health
                .insert(sensor.id, (signature, Instant::now()));
        }
        Ok(())
    }
    fn accepts_source_record(&self) -> bool {
        // Keep bounded headroom for heartbeat/health/loss records during replay.
        let reserve = (self.queue.capacity() / 4).clamp(1, 8);
        self.queue.len() < self.queue.capacity() - reserve
    }
    fn event(&mut self, event_type: &str, result: &str) -> Result<SecurityEvent, Box<dyn Error>> {
        self.sequence = self
            .sequence
            .checked_add(1)
            .ok_or("sensor sequence exhausted")?;
        let now = i64::try_from(SystemTime::now().duration_since(UNIX_EPOCH)?.as_millis())?;
        let monotonic = u64::try_from(self.started.elapsed().as_nanos())?;
        let mut event =
            SecurityEvent::heartbeat(self.host_id, self.instance, self.sequence, now, monotonic);
        event.event_type = event_type.into();
        event.operation = if event_type == "runtime.heartbeat" {
            "heartbeat"
        } else {
            "lifecycle"
        }
        .into();
        event.result = result.into();
        event.actor_identity = Some(IdentityContext {
            sid: Some(self.identity.sid.clone()),
            display_name: None,
        });
        // TokenSessionId is a desktop/Terminal Services session, not an auth LUID.
        event.logon_session = None;
        if let Some(process) = &mut event.process {
            process.name = Some("piko-service.exe".into());
        }
        self.last_seen = Some(now);
        Ok(event)
    }

    fn enqueue(&mut self, event: SecurityEvent) {
        if let Err(error) = self.queue.try_push(EventRecord {
            event,
            raw_evidence: None,
        }) {
            log("warn", &format!("telemetry_rejected: {error}"));
        }
    }

    fn begin_flush(&mut self) {
        if self.in_flight.is_some() {
            return;
        }
        if self.pending.is_empty() {
            let batch = self.queue.drain_batch(128);
            if batch.is_empty() {
                return;
            }
            let coverage = self.etw_health.borrow().state == "active";
            let prepared = self.image_repetition.prepare(batch, coverage);
            self.pending = prepared.records.clone();
            self.pending_images = Some(prepared);
        }
        if self.pending.is_empty() {
            return;
        }
        match self.storage.try_append(self.pending.clone()) {
            Ok(reply) => self.in_flight = Some(reply),
            Err(error) => self.storage_error = Some(error),
        }
    }

    fn finish_flush(&mut self, result: AppendResult) {
        self.in_flight = None;
        match result {
            Ok(count) => {
                if let Some(prepared) = self.pending_images.take() {
                    self.image_repetition.commit(&prepared);
                }
                self.pending.clear();
                self.stored_events = count;
                self.storage_error = None;
                // A full queue disables all receive branches. Continue draining
                // after a commit instead of waiting for the five-second timer.
                if self.queue.len() >= 64 {
                    self.begin_flush();
                }
            }
            Err(error) => {
                log("error", &format!("storage_write_failed: {error}"));
                self.storage_error = Some(error);
            }
        }
    }

    fn report_loss(&mut self) -> Result<(), Box<dyn Error>> {
        let dropped = self.queue.dropped_events();
        if dropped > self.reported_loss && self.queue.len() < self.queue.capacity() {
            let mut event = self.event(
                "telemetry.loss",
                &format!("dropped:{}", dropped - self.reported_loss),
            )?;
            event.severity = Severity::High;
            event.operation = "report_loss".into();
            if self
                .queue
                .try_push(EventRecord {
                    event,
                    raw_evidence: None,
                })
                .is_ok()
            {
                self.reported_loss = dropped;
            }
        }
        Ok(())
    }

    fn health(&self) -> HealthSnapshot {
        let mut sensors = vec![
            SensorHealth { id: "piko.runtime".into(), state: "active".into(), detail: "Internal runtime lifecycle and heartbeat only".into(), last_seen_unix_ms: self.last_seen },
            SensorHealth { id: "piko.storage".into(), state: if self.storage_error.is_some() {"degraded"} else {"active"}.into(), detail: self.storage_error.clone().unwrap_or_else(|| "SQLite WAL; bounded storage worker; local hash chain without external anchor".into()), last_seen_unix_ms: None },
        ];
        sensors.extend(
            self.sensor_health
                .borrow()
                .iter()
                .cloned()
                .map(|mut sensor| {
                    sensor.last_seen_unix_ms = self.source_last_seen.get(&sensor.id).copied();
                    sensor
                }),
        );
        sensors.push(self.observation_health.borrow().clone());
        let mut etw = self.etw_health.borrow().clone();
        if let Some(error) = &self.etw_error {
            etw.state = "degraded".into();
            etw.detail = format!("{}; rejected={}; {}", etw.detail, self.etw_rejected, error);
        }
        sensors.push(etw);
        sensors.push(SensorHealth {
            id: "piko.image_context".into(),
            state: if self.etw_health.borrow().state == "active" { "active" } else { "limited" }.into(),
            detail: format!(
                "{} file observations inspected; {} unchanged signed-context repeats grouped; {} loads kept as full records when verification was unavailable. Local signature does not mean safe; no absolute benign verdict.",
                self.image_repetition.inspected,
                self.image_repetition.summarized,
                self.image_repetition.passthrough,
            ),
            last_seen_unix_ms: self.source_last_seen.get(piko_win_sensors::ETW_SENSOR_ID).copied(),
        });
        for (id, status, detail) in [
            ("piko.detection", "active", "Twelve explainable Event Log rules; persisted with evidence; no automatic blocking"),
            ("piko.enforcement", "active", "File quarantine with exclusive identity/hash checks; desktop provides confirmed per-executable network controls, single-process termination and isolated AppContainer trials; no kernel enforcement"),
            ("piko.response", "active", "Expiring confirmed plans and durable action journal; service mutations require elevated administrator"),
            ("piko.recovery", "active", "DPAPI encrypted backups; verified content restore without overwriting; inherited destination permissions"),
        ] {
            sensors.push(SensorHealth {
                id: id.into(),
                state: if !self.response_enabled && matches!(id, "piko.enforcement" | "piko.recovery") { "unconfigured" } else { status }.into(),
                detail: detail.into(),
                last_seen_unix_ms: None,
            });
        }
        let archive = self.storage.archive_metrics();
        HealthSnapshot {
            product: "piko".into(),
            version: env!("CARGO_PKG_VERSION").into(),
            protection_state: if self.storage_error.is_some()
                || self.queue.dropped_events() > 0
                || sensors.iter().any(|s| s.state == "degraded")
            {
                "degraded"
            } else {
                "limited"
            }
            .into(),
            runtime_mode: if self.service_mode {
                "windows_service"
            } else {
                "development_console"
            }
            .into(),
            uptime_seconds: self.started.elapsed().as_secs(),
            stored_events: self.stored_events,
            queue_depth: self.queue.len() + self.pending.len(),
            dropped_events: self.queue.dropped_events(),
            sensors,
            performance: self.performance_metrics.clone(),
            performance_error: self.performance_error.clone(),
            archive: archive.usage,
            archive_error: archive.error,
        }
    }
}

pub async fn run(mut service: Option<ServiceContext>) -> Result<(), Box<dyn Error>> {
    let mut config = Config::default();
    let mut run_for = None;
    let mut args = std::env::args().skip(1);
    while let Some(arg) = args.next() {
        match arg.as_str() {
            "--service" if service.is_some() => {}
            "--config" => {
                let path = args.next().ok_or("--config needs a path")?;
                config = Config::from_reader(std::fs::File::open(path)?)?;
            }
            "--run-for-seconds" => {
                let seconds: u64 = args.next().ok_or("missing duration")?.parse()?;
                if !(1..=86400).contains(&seconds) {
                    return Err("duration must be 1..=86400 seconds".into());
                }
                run_for = Some(seconds);
            }
            "--help" => {
                println!("piko-service 0.2.0\n\nEvent Log detection, confirmed file quarantine and verified content recovery.\nNo kernel, process or network prevention.\n\n  --config <JSON path>\n  --run-for-seconds <1..86400>\n  --service (SCM only; requires absolute data_dir and viewer_sid)\n\nConsole response roots default to Documents and Downloads. Service roots must be configured.\nDefault console data directory: .runtime.\nCtrl+C or SCM Stop requests a bounded flush. UI closes independently.");
                return Ok(());
            }
            _ => return Err(format!("unsupported argument: {arg}").into()),
        }
    }
    config.validate()?;
    if service.is_some()
        && (!config.data_dir.is_absolute() || config.viewer_sid.is_none() || run_for.is_some())
    {
        return Err(
            "SCM mode requires absolute data_dir, viewer_sid and no run-for duration".into(),
        );
    }
    require_no_pending_archive_verification(&config)?;
    let identity = current_identity()?;
    // Keep ownership of the endpoint name through shutdown and durable flush.
    let viewer = if service.is_some() {
        config.viewer_sid.clone()
    } else {
        None
    };
    let mut listener = create_listener(&identity, viewer.as_deref(), true)?;
    let (storage, host_id, stored_events, checkpoints) = StorageClient::start_with_maintenance(
        config.data_dir.join("events.db"),
        storage_config(&config),
        config.archive_maintenance,
    )
    .await
    .map_err(io::Error::other)?;
    let roots = config.response_roots.clone().unwrap_or_else(|| {
        if service.is_some() {
            return Vec::new();
        }
        std::env::var_os("USERPROFILE")
            .map(|p| {
                vec![
                    PathBuf::from(&p).join("Documents"),
                    PathBuf::from(p).join("Downloads"),
                ]
            })
            .unwrap_or_default()
    });
    let response_enabled = roots.iter().any(|p| p.is_dir());
    let response = response_worker::ResponseClient::start(config.data_dir.join("response"), roots)
        .await
        .map_err(io::Error::other)?;
    let mut collector = EventLogCollector::start(checkpoints)?;
    let mut observations = ObservationCollector::start(host_id)?;
    let mut etw = EtwCollector::start()?;
    let mut state = State {
        storage,
        host_id,
        stored_events,
        queue: BoundedRecordQueue::new(config.queue_capacity)?,
        pending: Vec::new(),
        pending_images: None,
        image_repetition: Default::default(),
        in_flight: None,
        identity,
        instance: Uuid::new_v4(),
        started: Instant::now(),
        sequence: 0,
        reported_loss: 0,
        last_seen: None,
        storage_error: None,
        performance_sampler: performance::Sampler::default(),
        performance_metrics: None,
        performance_error: None,
        sensor_health: collector.health.clone(),
        observation_health: observations.health.clone(),
        etw_health: etw.health.clone(),
        etw_error: None,
        etw_rejected: 0,
        source_last_seen: std::collections::HashMap::new(),
        durable_health: std::collections::HashMap::new(),
        service_mode: service.is_some(),
        response_enabled,
    };
    for (kind, result) in [
        (
            "runtime.started",
            if service.is_some() {
                "windows_service"
            } else {
                "development_console"
            },
        ),
        ("runtime.configuration_loaded", "validated"),
    ] {
        let event = state.event(kind, result)?;
        state.enqueue(event);
    }
    if let Err(error) = flush_all(&mut state).await {
        if !quota_exhausted(state.storage_error.as_deref()) {
            return Err(error);
        }
        log("warn","archive quota exhausted; runtime available for read-only queries, startup records not committed");
    }
    if let Some(context) = &service {
        context.running()?;
    }
    let (health_sender, health_receiver) = watch::channel(state.health());
    let mut source_changes = collector.health.clone();
    let mut etw_changes = etw.health.clone();
    let mut etw_health_open = true;
    let mut etw_records_open = true;
    let mut clients = JoinSet::new();
    log(
        "info",
        "runtime_started; detection=event_log_rules; enforcement=confirmed_file_quarantine",
    );
    let keys = key_worker::KeyClient::start(
        config.data_dir.clone(),
        host_id,
        config.protect_raw_evidence,
        config.recoverable_raw_evidence,
        state.service_mode,
    )?;
    let mut heartbeat = tokio::time::interval(Duration::from_secs(config.heartbeat_seconds));
    let mut flush = tokio::time::interval(Duration::from_secs(config.flush_seconds));
    heartbeat.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Skip);
    flush.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Skip);
    let stop = tokio::signal::ctrl_c();
    tokio::pin!(stop);
    let deadline = tokio::time::sleep(Duration::from_secs(run_for.unwrap_or(86400 * 365)));
    tokio::pin!(deadline);
    loop {
        tokio::select! {
            signal = &mut stop, if service.is_none() => { signal?; break; }
            _ = service_stop(&mut service) => break,
            _ = &mut deadline, if run_for.is_some() => break,
            _ = heartbeat.tick() => {
                match state.performance_sampler.sample() {
                    Ok(metrics) => { state.performance_metrics=Some(metrics); state.performance_error=None; }
                    Err(e) => { state.performance_metrics=None; state.performance_error=Some(e.to_string()); }
                }
                state.last_seen = Some(i64::try_from(SystemTime::now().duration_since(UNIX_EPOCH)?.as_millis())?);
                state.report_loss()?;
            }
            _ = flush.tick() => {
                state.begin_flush();
                // A full queue retries at the next tick; collection has priority.
                let _ = state.storage.try_maintain();
            },
            changed = source_changes.changed() => {
                if changed.is_err() { return Err("Event Log health channel stopped".into()); }
                let snapshot = source_changes.borrow_and_update().clone();
                for sensor in snapshot {
                    state.record_sensor_health(sensor)?;
                }
            }
            changed = etw_changes.changed(), if etw_health_open => {
                if changed.is_err() { etw_health_open = false; }
                else {
                    let sensor = etw_changes.borrow_and_update().clone();
                    state.record_sensor_health(sensor)?;
                }
            }
            record = etw.records.recv(), if etw_records_open && state.accepts_source_record() => {
                if let Some(record) = record {
                    let seed = state.event("windows.etw", "observed")?;
                    match piko_win_sensors::normalize_etw(record, seed) {
                        Ok(record) => {
                            state.source_last_seen.insert(record.event.sensor_id.clone(), record.event.observation_time);
                            state.queue.try_push(record).map_err(io::Error::other)?;
                            if state.queue.len() >= 64 || !state.queue.has_room() { state.begin_flush(); }
                        }
                        Err(error) => {
                            state.etw_rejected = state.etw_rejected.saturating_add(1);
                            state.etw_error = Some(format!("ETW normalization rejected a record: {error}"));
                            let mut event = state.event("telemetry.loss", "etw_record_rejected")?;
                            event.severity = Severity::High;
                            event.target = Some(piko_event_schema::EventTarget { kind: "windows.etw.process_image".into(), identifier: state.etw_error.clone().unwrap_or_default() });
                            state.enqueue(event);
                        }
                    }
                } else {
                    etw_records_open = false;
                    if etw.health.borrow().state != "degraded" { state.etw_error = Some("ETW collector stopped unexpectedly".into()); }
                }
            }
            result = pending_append(&mut state.in_flight) => state.finish_flush(result),
            record = collector.records.recv(), if state.accepts_source_record() => {
                if let Some(record) = record {
                    let seed = state.event("windows.event_log", "observed")?;
                    let record = piko_win_sensors::normalize(record.xml, &record.channel, record.bookmark, seed)?;
                    state.source_last_seen.insert(record.event.sensor_id.clone(), record.event.observation_time);
                    // Any failure halts ingestion before later bookmarks can be persisted.
                    state.queue.try_push(record).map_err(io::Error::other)?;
                    if state.queue.len() >= 64 || !state.queue.has_room() { state.begin_flush(); }
                } else { return Err("Event Log collector stopped unexpectedly".into()); }
            }
            record = observations.records.recv(), if state.accepts_source_record() => {
                if let Some(record) = record {
                    let seed = state.event("windows.observation", "observed")?;
                    let record = piko_win_sensors::normalize_observation(record, seed)?;
                    state.queue.try_push(record).map_err(io::Error::other)?;
                    if state.queue.len() >= 64 || !state.queue.has_room() { state.begin_flush(); }
                } else { return Err("Observation collector stopped unexpectedly".into()); }
            }
            result = clients.join_next(), if !clients.is_empty() => {
                match result {
                    Some(Ok(Err(error))) => log("warn", &format!("ipc_request_rejected: {error}")),
                    Some(Err(error)) => log("warn", &format!("ipc_task_failed: {error}")),
                    _ => {},
                }
            }
            connected = listener.connect(), if clients.len() < MAX_CLIENTS => {
                connected?;
                let next = create_listener(&state.identity, viewer.as_deref(), false)?;
                let connection = std::mem::replace(&mut listener, next);
                let identity = state.identity.clone();
                let storage = state.storage.clone();
                let health = health_receiver.clone();
                let service_mode = state.service_mode;
                let response = response.clone();
                let keys = keys.clone();
                let observations = observations.latest.clone();
                clients.spawn(async move { serve(connection, identity, storage, response, keys, health, observations, service_mode).await });
            }
        }
        health_sender.send_replace(state.health());
    }
    if let Some(context) = &service {
        context.stopping()?;
    }
    collector.stop();
    observations.stop();
    etw.stop();
    clients.abort_all();
    while clients.join_next().await.is_some() {}
    let shutdown = async {
        if state.queue.len() == state.queue.capacity() {
            flush_all(&mut state).await?;
        }
        let event = state.event("runtime.stopping", "requested")?;
        state.enqueue(event);
        flush_all(&mut state).await?;
        state.report_loss()?;
        flush_all(&mut state).await
    };
    let result = tokio::time::timeout(SHUTDOWN_DEADLINE, shutdown)
        .await
        .map_err(|_| "shutdown deadline exceeded; pending commit status may be unknown")?;
    if let Err(error) = result {
        if !quota_exhausted(state.storage_error.as_deref()) {
            return Err(error);
        }
        log(
            "warn",
            "archive quota exhausted; shutdown records not committed, no successful write claimed",
        );
    }
    log("info", "runtime_stopped");
    Ok(())
}

fn create_listener(
    identity: &LocalIdentity,
    viewer: Option<&str>,
    first: bool,
) -> io::Result<NamedPipeServer> {
    match viewer {
        Some(sid) => create_service_pipe(sid, first),
        None => create_private_pipe(identity, first),
    }
}

async fn service_stop(context: &mut Option<ServiceContext>) {
    match context {
        Some(context) => {
            if !*context.stop.borrow() {
                let _ = context.stop.changed().await;
            }
        }
        None => std::future::pending().await,
    }
}

async fn pending_append(receiver: &mut Option<oneshot::Receiver<AppendResult>>) -> AppendResult {
    match receiver {
        Some(receiver) => receiver
            .await
            .map_err(|_| "storage worker stopped before acknowledging its write".to_string())?,
        None => std::future::pending().await,
    }
}

async fn flush_all(state: &mut State) -> Result<(), Box<dyn Error>> {
    while !state.pending.is_empty() || !state.queue.is_empty() || state.in_flight.is_some() {
        state.begin_flush();
        if state.in_flight.is_none() {
            return Err(format!(
                "shutdown with unpersisted events: {}",
                state
                    .storage_error
                    .as_deref()
                    .unwrap_or("storage unavailable")
            )
            .into());
        }
        let result = pending_append(&mut state.in_flight).await;
        state.finish_flush(result);
        if let Some(error) = &state.storage_error {
            return Err(format!("shutdown with unpersisted events: {error}").into());
        }
    }
    Ok(())
}

#[allow(clippy::too_many_arguments)]
async fn serve(
    mut pipe: NamedPipeServer,
    identity: LocalIdentity,
    storage: StorageClient,
    response: response_worker::ResponseClient,
    keys: key_worker::KeyClient,
    health: watch::Receiver<HealthSnapshot>,
    observations: watch::Receiver<Option<piko_common_model::ObservationSnapshot>>,
    service_mode: bool,
) -> io::Result<()> {
    // Installed endpoint authorization is enforced by the OS DACL at open.
    // Console endpoint additionally requires the same user and interactive session.
    if !service_mode {
        authenticate_client(&pipe, &identity)?;
    }
    let request: Request = tokio::time::timeout(
        REQUEST_DEADLINE,
        piko_ipc::read_frame(&mut pipe, MAX_REQUEST_BYTES),
    )
    .await
    .map_err(|_| io::Error::new(io::ErrorKind::TimedOut, "request read timed out"))??;
    let authorized = if request.command.is_response_mutation()
        && (service_mode || piko_win_platform::current_process_elevated()?)
    {
        piko_win_platform::authorize_response_client(&pipe)
    } else {
        Ok(identity.clone())
    };
    let actor = authorized
        .as_ref()
        .map(|id| id.sid.clone())
        .unwrap_or_default();
    let deadline = Instant::now()
        + if matches!(&request.command, Command::VerifyStore) {
            Duration::from_secs(30)
        } else if request.command.is_response_command()
            || request.command.is_key_command()
        {
            Duration::from_millis(2200)
        } else {
            REQUEST_DEADLINE
        };
    // The worker owns the operation deadline; keep time to return a typed timeout.
    tokio::time::timeout_at((deadline + Duration::from_millis(500)).into(), async {
        let result = if request.protocol_version != PROTOCOL_VERSION {
            Err(api_error(
                "protocol_version",
                "unsupported protocol version",
            ))
        } else if let Err(error) = authorized {
            Err(api_error("response_unauthorized", &error.to_string()))
        } else {
            match request.command {
                Command::GetObservations => observations
                    .borrow()
                    .clone()
                    .map(ApiData::Observations)
                    .ok_or_else(|| {
                        api_error(
                            "observations_unavailable",
                            "Process/TCP snapshot unavailable or collector starting",
                        )
                    }),
                Command::GetHealth => Ok(ApiData::Health(health.borrow().clone())),
                Command::GetArchiveMaintenance => {
                    Ok(ApiData::ArchiveMaintenance(storage.maintenance_status()))
                }
                Command::GetEvidenceKeyStatus => {
                    keys.call(Command::GetEvidenceKeyStatus, deadline).await
                }
                command if command.is_key_command() => keys.call(command, deadline).await,
                command if command.is_response_command() => {
                    response.call(command, deadline, actor).await
                }
                command => storage.read(command, deadline).await,
            }
        };
        let mut response = Response {
            protocol_version: PROTOCOL_VERSION,
            request_id: request.request_id,
            result,
        };
        if piko_ipc::serialized_length(&response)? > MAX_RESPONSE_BYTES {
            response.result = Err(api_error(
                "query_result_too_large",
                "response exceeds 4 MiB; narrow filters or reduce limit",
            ));
        }
        piko_ipc::write_frame(&mut pipe, &response, MAX_RESPONSE_BYTES).await
    })
    .await
    .map_err(|_| io::Error::new(io::ErrorKind::TimedOut, "IPC request timed out"))?
}

fn log(level: &str, message: &str) {
    eprintln!(
        "{}",
        serde_json::json!({"level":level,"component":"piko.runtime","message":message})
    );
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn offline_verification_preserves_archive_and_rejects_corruption_or_missing_data(
    ) -> Result<(), Box<dyn Error>> {
        struct Fixture(PathBuf);
        impl Drop for Fixture {
            fn drop(&mut self) {
                let _ = std::fs::remove_dir_all(&self.0);
            }
        }
        let fixture =
            Fixture(std::env::temp_dir().join(format!("piko-offline-verify-{}", Uuid::new_v4())));
        std::fs::create_dir(&fixture.0)?;
        let config = Config {
            data_dir: fixture.0.clone(),
            retention_months: Some(12),
            ..Config::default()
        };
        let database = config.data_dir.join("events.db");
        assert!(verify_evidence_archive(&config).is_err());
        assert!(
            !database.exists(),
            "verification must not create an archive"
        );
        let expected = {
            let mut store = piko_event_storage::SqliteEventStore::open(
                &database,
                StorageConfig {
                    retention_months: config.retention_months,
                    ..Default::default()
                },
            )?;
            let mut event = SecurityEvent::heartbeat(store.host_id(), Uuid::new_v4(), 1, 100, 1);
            event.result = "offline-original-fixture".into();
            store.append_batch(&[event])?;
            store.verify_integrity()?
        };
        let original = std::fs::read(&database)?;
        let report = verify_evidence_archive(&config)?;
        assert_eq!(report, expected);
        assert_eq!(report.verified_events, 1);
        assert_eq!(std::fs::read(&database)?, original);

        // Change an event payload in place: retain valid SQLite structure while
        // proving that verification checks the stored chain, not just opening it.
        let mut corrupt = original;
        let marker = b"offline-original-fixture";
        let position = corrupt
            .windows(marker.len())
            .position(|bytes| bytes == marker)
            .ok_or("fixture event payload not found")?;
        corrupt[position] = b'X';
        std::fs::write(&database, &corrupt)?;
        assert!(verify_evidence_archive(&config).is_err());
        assert_eq!(std::fs::read(&database)?, corrupt);

        let invalid = Config {
            max_disk_mib: 0,
            ..config
        };
        assert!(verify_evidence_archive(&invalid).is_err());
        assert_eq!(std::fs::read(&database)?, corrupt);
        Ok(())
    }

    #[test]
    fn quota_mode_never_masks_corruption_or_other_storage_failures() {
        assert!(quota_exhausted(Some(
            "SQLite error: database or disk is full"
        )));
        assert!(quota_exhausted(Some(
            "storage budget exhausted; batch was not accepted"
        )));
        assert!(!quota_exhausted(Some("evidence corruption: hash mismatch")));
        assert!(!quota_exhausted(Some("permission denied")));
        assert!(!quota_exhausted(None));
    }

    #[tokio::test]
    async fn full_queue_continues_committing_without_a_timer_or_new_input(
    ) -> Result<(), Box<dyn Error>> {
        let path = std::env::temp_dir().join(format!("piko-drain-{}.sqlite", Uuid::new_v4()));
        let (storage, host_id, count, _) = StorageClient::start(path, Default::default()).await?;
        let (_, sensor_health) = watch::channel(Vec::new());
        let sensor = SensorHealth {
            id: "test".into(),
            state: "active".into(),
            detail: String::new(),
            last_seen_unix_ms: None,
        };
        let (_, observation_health) = watch::channel(sensor.clone());
        let (_, etw_health) = watch::channel(sensor);
        let mut state = State {
            storage,
            host_id,
            stored_events: count,
            queue: BoundedRecordQueue::new(256)?,
            pending: Vec::new(),
            pending_images: None,
            image_repetition: Default::default(),
            in_flight: None,
            identity: piko_win_platform::current_identity()?,
            instance: Uuid::new_v4(),
            started: Instant::now(),
            sequence: 0,
            reported_loss: 0,
            last_seen: None,
            storage_error: None,
            performance_sampler: performance::Sampler::default(),
            performance_metrics: None,
            performance_error: None,
            sensor_health,
            observation_health,
            etw_health,
            etw_error: None,
            etw_rejected: 0,
            source_last_seen: Default::default(),
            durable_health: Default::default(),
            service_mode: false,
            response_enabled: false,
        };
        for _ in 0..256 {
            let event = state.event("runtime.heartbeat", "test")?;
            state.enqueue(event);
        }
        state.begin_flush();
        // Refill while the first batch is in flight: all receive branches are disabled.
        for _ in 0..128 {
            let event = state.event("runtime.heartbeat", "test")?;
            state.enqueue(event);
        }
        assert!(!state.queue.has_room());
        let first = state.in_flight.take().ok_or("missing append")?.await?;
        state.finish_flush(first);
        assert!(
            state.in_flight.is_some(),
            "full backlog must schedule the next commit immediately"
        );
        tokio::time::timeout(Duration::from_secs(3), async {
            while let Some(reply) = state.in_flight.take() {
                state.finish_flush(reply.await?);
            }
            Ok::<_, Box<dyn Error>>(())
        })
        .await??;
        assert_eq!(state.stored_events, 384);
        assert_eq!(state.queue.len(), 0);
        assert_eq!(state.queue.dropped_events(), 0);
        assert!(state.pending.is_empty());
        // Live counter refreshes do not fill the archive; transitions, new errors,
        // and periodic loss snapshots still commit through the real worker.
        let sensor = |status: &str, n: u64, suffix: &str| {
            SensorHealth {
            id: piko_win_sensors::ETW_SENSOR_ID.into(), state: status.into(),
            detail: format!("Real-time manifest process/image ETW; {n} received; ProcessTrace running: {suffix}"),
            last_seen_unix_ms: Some(1000),
        }
        };
        state.record_sensor_health(sensor("active", 1, "true; error: None"))?;
        state.record_sensor_health(sensor("active", 2, "true; error: None"))?;
        state.record_sensor_health(sensor("degraded", 3, "true; error: None"))?;
        state.record_sensor_health(sensor("degraded", 4, "true; error: None"))?;
        state
            .durable_health
            .get_mut(piko_win_sensors::ETW_SENSOR_ID)
            .ok_or("missing health state")?
            .1 -= Duration::from_secs(61);
        state.record_sensor_health(sensor("degraded", 5, "true; error: None"))?;
        state.record_sensor_health(sensor("degraded", 6, "false; error: Some(5)"))?;
        state.record_sensor_health(sensor("active", 7, "true; error: None"))?;
        assert_eq!(state.queue.len(), 5);
        flush_all(&mut state).await?;
        assert_eq!(state.stored_events, 389);
        Ok(())
    }

    #[test]
    fn configuration_rejects_unbounded_or_unknown_settings() {
        assert!(Config::default().validate().is_ok());
        let mut config = Config {
            queue_capacity: 0,
            ..Config::default()
        };
        assert!(config.validate().is_err());
        config.queue_capacity = 256;
        config.heartbeat_seconds = 0;
        assert!(config.validate().is_err());
        assert!(serde_json::from_str::<Config>(r#"{"enable_protection":true}"#).is_err());
    }

    #[test]
    fn oversized_configuration_reader_is_bounded() {
        assert!(Config::from_reader(io::repeat(b' ')).is_err());
    }
}

#[cfg(test)]
mod key_guards_tests;
