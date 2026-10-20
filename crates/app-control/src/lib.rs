//! Explicit, bounded plans for path-scoped Windows Firewall controls.
#![forbid(unsafe_code)]

mod discovery;
pub mod history;
pub mod sandbox;
pub use discovery::{application_executables, ExecutableCandidates};

use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use std::os::windows::fs::{MetadataExt, OpenOptionsExt};
use std::{
    collections::HashMap,
    fs::{File, OpenOptions},
    io::{self, Read},
    path::{Path, PathBuf},
    time::{SystemTime, UNIX_EPOCH},
};
use uuid::Uuid;

const MAX_EXE_BYTES: u64 = 256 * 1024 * 1024;
const MAX_PAYLOAD: usize = 24576;
const PLAN_SECONDS: u64 = 300;
const REPARSE_POINT: u32 = 0x400;

#[derive(Clone, Debug, Deserialize, Serialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum NetworkAction {
    Block,
    RemoveBlock,
}

#[derive(Clone, Debug, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct NetworkPlan {
    #[serde(default)]
    pub direction: piko_win_platform::network_control::NetworkDirection,
    pub id: Uuid,
    pub action: NetworkAction,
    pub rule_id: String,
    pub executable: String,
    pub display_name: String,
    pub sha256: Option<String>,
    pub expires_at: u64,
}

#[derive(Default)]
pub struct Controller {
    plans: HashMap<Uuid, NetworkPlan>,
}

fn invalid(message: &str) -> io::Error {
    io::Error::new(io::ErrorKind::InvalidInput, message)
}
fn now() -> io::Result<u64> {
    Ok(SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map_err(io::Error::other)?
        .as_secs())
}

/// Only ordinary absolute local paths: no device paths, UNC, ADS, environment expansion or command line.
fn validate_path(path: &str) -> io::Result<()> {
    let bytes = path.as_bytes();
    if !(4..=2048).contains(&bytes.len())
        || !bytes[0].is_ascii_alphabetic()
        || bytes[1] != b':'
        || bytes[2] != b'\\'
        || path[3..].contains([':', '/', '"', '%', '\0'])
        || path.chars().any(|c| {
            c.is_control() || matches!(c, '\u{202a}'..='\u{202e}' | '\u{2066}'..='\u{2069}')
        })
        || !path.to_ascii_lowercase().ends_with(".exe")
        || path[3..].split('\\').any(|part| {
            part.is_empty() || part == "." || part == ".." || part.ends_with([' ', '.'])
        })
    {
        return Err(invalid(
            "Serve il percorso completo di un file .exe locale, senza argomenti o collegamenti.",
        ));
    }
    Ok(())
}

fn rule_id(path: &str) -> String {
    format!("{:x}", Sha256::digest(path.to_lowercase().as_bytes()))
}

/// Bind the native rule template to the application's versioned path identity.
pub fn network_snapshot() -> io::Result<piko_win_platform::network_control::NetworkSnapshot> {
    let mut snapshot = piko_win_platform::network_control::network_snapshot()?;
    for rule in &mut snapshot.rules {
        rule.verified &= rule.id == rule_id(&rule.executable);
    }
    Ok(snapshot)
}

struct Executable {
    _file: File,
    _parents: Vec<File>,
    path: String,
    sha256: String,
}

fn inspect_executable(path: &str) -> io::Result<Executable> {
    validate_path(path)?;
    let parents = piko_win_platform::network_elevation::lock_path_parents(Path::new(path))?;
    // Deny write/delete sharing while inspecting and applying the rule. Never execute this file.
    let mut file = OpenOptions::new()
        .read(true)
        .share_mode(1)
        .custom_flags(0x00200000)
        .open(path)?;
    let metadata = file.metadata()?;
    if !metadata.is_file()
        || metadata.file_attributes() & REPARSE_POINT != 0
        || !(64..=MAX_EXE_BYTES).contains(&metadata.len())
    {
        return Err(invalid(
            "Eseguibile non regolare o dimensione fuori dal limite di 256 MiB.",
        ));
    }
    let canonical = piko_win_platform::network_elevation::final_file_path(&file)?;
    let canonical = canonical
        .to_str()
        .ok_or_else(|| invalid("Percorso non Unicode."))?;
    let canonical = canonical
        .strip_prefix(r"\\?\")
        .unwrap_or(canonical)
        .to_string();
    validate_path(&canonical)?;
    let by_name = std::fs::canonicalize(path)?;
    if by_name
        .to_string_lossy()
        .trim_start_matches(r"\\?\")
        .to_lowercase()
        != canonical.to_lowercase()
    {
        return Err(invalid("Il percorso non corrisponde al file aperto."));
    }
    let windows = piko_win_platform::network_elevation::windows_directory()?;
    if Path::new(&canonical.to_lowercase()).starts_with(windows.to_string_lossy().to_lowercase()) {
        return Err(invalid(
            "Gli eseguibili di Windows sono esclusi da questo controllo per app.",
        ));
    }
    let own = std::env::current_exe()?;
    if let Some(parent) = own.parent() {
        if Path::new(&canonical.to_lowercase()).starts_with(
            parent
                .to_string_lossy()
                .trim_start_matches(r"\\?\")
                .to_lowercase(),
        ) {
            return Err(invalid(
                "Non è consentito bloccare gli eseguibili nella cartella di piko.",
            ));
        }
    }
    let mut hasher = Sha256::new();
    let mut header = [0_u8; 2];
    file.read_exact(&mut header)?;
    if header != *b"MZ" {
        return Err(invalid(
            "Il file non ha un'intestazione eseguibile Windows.",
        ));
    }
    hasher.update(header);
    let mut buffer = [0_u8; 65536];
    let mut total = 2_u64;
    loop {
        let read = file.read(&mut buffer)?;
        if read == 0 {
            break;
        }
        total += read as u64;
        if total > MAX_EXE_BYTES {
            return Err(invalid("Eseguibile oltre il limite."));
        }
        hasher.update(&buffer[..read]);
    }
    Ok(Executable {
        _file: file,
        _parents: parents,
        path: canonical,
        sha256: format!("{:x}", hasher.finalize()),
    })
}

impl Controller {
    pub fn discard(&mut self, ids: &[Uuid]) {
        for id in ids.iter().take(32) {
            self.plans.remove(id);
        }
    }
    pub fn prepare(&mut self, action: NetworkAction, path: &str) -> io::Result<NetworkPlan> {
        self.prepare_direction(
            action,
            path,
            piko_win_platform::network_control::NetworkDirection::Outbound,
        )
    }
    pub fn prepare_direction(
        &mut self,
        action: NetworkAction,
        path: &str,
        direction: piko_win_platform::network_control::NetworkDirection,
    ) -> io::Result<NetworkPlan> {
        let current = now()?;
        self.plans.retain(|_, plan| plan.expires_at > current);
        if self.plans.len() >= 32 {
            return Err(invalid("Troppe anteprime aperte. Attendi cinque minuti."));
        }
        let (executable, sha256) = match action {
            NetworkAction::Block => {
                let exe = inspect_executable(path)?;
                (exe.path, Some(exe.sha256))
            }
            NetworkAction::RemoveBlock => {
                validate_path(path)?;
                (path.to_string(), None)
            }
        };
        let id = rule_id(&executable);
        let snapshot = network_snapshot()?;
        if !snapshot.complete {
            return Err(invalid(
                "Lettura delle regole incompleta: impossibile preparare una modifica.",
            ));
        }
        let existing = snapshot
            .rules
            .iter()
            .find(|r| r.id == id && r.direction == direction);
        if existing.is_some_and(|r| !r.verified || !r.executable.eq_ignore_ascii_case(&executable))
        {
            return Err(invalid(
                "La regola esistente è stata modificata fuori da piko: verifica Windows Firewall.",
            ));
        }
        if action == NetworkAction::RemoveBlock && existing.is_none() {
            return Err(invalid("Nessun blocco piko per questo percorso."));
        }
        if action == NetworkAction::Block
            && (snapshot.active_profiles == 0
                || !matches!(
                    snapshot.local_policy_modify_state.as_str(),
                    "ok" | "inbound_blocked"
                )
                || snapshot
                    .profiles
                    .iter()
                    .any(|p| p.active && (!p.firewall_enabled || p.excluded_interfaces)))
        {
            return Err(invalid("Il firewall attivo non consente di applicare questo blocco locale. Controlla lo stato dei profili."));
        }
        let display_name = Path::new(&executable)
            .file_name()
            .and_then(|name| name.to_str())
            .ok_or_else(|| invalid("Nome eseguibile non valido."))?
            .to_string();
        let plan = NetworkPlan {
            direction,
            id: Uuid::new_v4(),
            action,
            rule_id: id,
            executable,
            display_name,
            sha256,
            expires_at: current + PLAN_SECONDS,
        };
        self.plans.insert(plan.id, plan.clone());
        Ok(plan)
    }

    /// Consumes the plan before UAC; cancellation/retry always needs a fresh preview.
    pub fn execute(&mut self, id: Uuid) -> io::Result<()> {
        let plan = self
            .plans
            .remove(&id)
            .ok_or_else(|| invalid("Anteprima non trovata o già utilizzata."))?;
        validate_plan(&plan, now()?)?;
        let helper: PathBuf = std::env::current_exe()?.with_file_name("piko-network-helper.exe");
        let payload = serde_json::to_vec(&plan).map_err(io::Error::other)?;
        let encoded = payload
            .iter()
            .map(|byte| format!("{byte:02x}"))
            .collect::<String>();
        match piko_win_platform::network_elevation::launch_network_helper(&helper, &encoded)? {
            0 => Ok(()),
            1 => Err(io::Error::other("Windows non ha completato la modifica. Aggiorna le regole e consulta il registro Application di Windows (origine piko).")),
            code => Err(io::Error::other(format!("Helper terminato con codice {code}. Aggiorna le regole prima di riprovare."))),
        }
    }
}

fn validate_plan(plan: &NetworkPlan, current: u64) -> io::Result<()> {
    validate_path(&plan.executable)?;
    if plan.id.is_nil()
        || plan.rule_id != rule_id(&plan.executable)
        || plan.expires_at <= current
        || plan.expires_at > current.saturating_add(PLAN_SECONDS)
        || plan.display_name
            != Path::new(&plan.executable)
                .file_name()
                .and_then(|v| v.to_str())
                .unwrap_or("")
    {
        return Err(invalid("Piano di rete non valido o scaduto."));
    }
    match (&plan.action, &plan.sha256) {
        (NetworkAction::Block, Some(hash))
            if hash.len() == 64
                && hash
                    .bytes()
                    .all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(&b)) =>
        {
            Ok(())
        }
        (NetworkAction::RemoveBlock, None) => Ok(()),
        _ => Err(invalid("Identità dell'eseguibile non valida.")),
    }
}

fn decode_plan(encoded: &str) -> io::Result<NetworkPlan> {
    if encoded.is_empty()
        || encoded.len() > MAX_PAYLOAD
        || !encoded.len().is_multiple_of(2)
        || !encoded.bytes().all(|b| b.is_ascii_hexdigit())
    {
        return Err(invalid("Payload helper non valido."));
    }
    let bytes = (0..encoded.len())
        .step_by(2)
        .map(|i| u8::from_str_radix(&encoded[i..i + 2], 16).map_err(io::Error::other))
        .collect::<io::Result<Vec<_>>>()?;
    let plan = serde_json::from_slice(&bytes).map_err(io::Error::other)?;
    validate_plan(&plan, now()?)?;
    Ok(plan)
}

/// Elevated helper entrypoint. No arbitrary command, write path, URL or script accepted.
pub fn execute_helper(encoded: &str) -> io::Result<()> {
    let plan = decode_plan(encoded)?;
    if !piko_win_platform::current_process_elevated()? {
        return Err(io::Error::new(
            io::ErrorKind::PermissionDenied,
            "Windows administrator token required.",
        ));
    }
    let locked = if plan.action == NetworkAction::Block {
        let exe = inspect_executable(&plan.executable)?;
        if exe.path != plan.executable || Some(&exe.sha256) != plan.sha256.as_ref() {
            return Err(invalid("Eseguibile cambiato dopo l'anteprima."));
        }
        Some(exe)
    } else {
        None
    };
    // Windows Application Event Log is the durable system journal. Failure to record intent prevents effects.
    piko_win_platform::event_log::report_diagnostic(
        &format!(
            "piko network plan {} {:?} {:?} requested: {}; SHA256={}",
            plan.id,
            plan.action,
            plan.direction,
            plan.executable,
            plan.sha256.as_deref().unwrap_or("not applicable")
        ),
        false,
    )?;
    validate_plan(&plan, now()?)?;
    match plan.action {
        NetworkAction::Block => piko_win_platform::network_control::apply_direction_block(
            &plan.rule_id,
            &plan.executable,
            plan.direction,
        )?,
        NetworkAction::RemoveBlock => piko_win_platform::network_control::remove_direction_block(
            &plan.rule_id,
            &plan.executable,
            plan.direction,
        )?,
    }
    drop(locked);
    piko_win_platform::event_log::report_diagnostic(
        &format!(
            "piko network plan {} {:?} {:?} completed: {}",
            plan.id, plan.action, plan.direction, plan.executable
        ),
        false,
    )
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn inspection_locks_file_and_parent_and_releases_them() -> io::Result<()> {
        let root = std::env::temp_dir().join(format!("piko-app-control-{}", Uuid::new_v4()));
        std::fs::create_dir(&root)?;
        let path = root.join("sample.exe");
        let mut bytes = vec![0; 128];
        bytes[..2].copy_from_slice(b"MZ");
        std::fs::write(&path, &bytes)?;
        let executable = inspect_executable(path.to_str().ok_or_else(|| invalid("Test path"))?)?;
        assert_eq!(executable.sha256, format!("{:x}", Sha256::digest(&bytes)));
        assert!(OpenOptions::new().write(true).open(&path).is_err());
        assert!(std::fs::rename(&path, root.join("moved.exe")).is_err());
        assert!(std::fs::rename(&root, root.with_extension("moved")).is_err());
        drop(executable);
        std::fs::write(&path, b"MZ")?;
        assert!(inspect_executable(path.to_str().ok_or_else(|| invalid("Test path"))?).is_err());
        std::fs::remove_file(&path)?;
        std::fs::remove_dir(&root)?;
        Ok(())
    }
    #[test]
    fn rejects_commands_devices_ads_and_ambiguous_paths() {
        for path in [
            "",
            "app.exe",
            r"\\server\app.exe",
            r"\\?\C:\app.exe",
            r"C:\app.exe:stream",
            r"C:\app.exe --arg",
            r"C:\foo\..\app.exe",
            r"C:\bad.\app.exe",
            r"C:\%windir%\app.exe",
            "C:\\a\0.exe",
        ] {
            assert!(validate_path(path).is_err(), "{path}");
        }
        assert!(validate_path(r"C:\Program Files\Example\app.exe").is_ok());
    }
    #[test]
    fn plan_validation_rejects_expiry_identity_and_action_changes() {
        let path = r"C:\Example\app.exe";
        let mut plan = NetworkPlan {
            id: Uuid::new_v4(),
            action: NetworkAction::Block,
            direction: piko_win_platform::network_control::NetworkDirection::Outbound,
            rule_id: rule_id(path),
            executable: path.into(),
            display_name: "app.exe".into(),
            sha256: Some("a".repeat(64)),
            expires_at: 1200,
        };
        assert!(validate_plan(&plan, 1000).is_ok());
        assert!(validate_plan(&plan, 1200).is_err());
        assert!(validate_plan(&plan, 899).is_err());
        plan.executable = r"C:\Other\app.exe".into();
        assert!(validate_plan(&plan, 1000).is_err());
        plan.executable = path.into();
        plan.action = NetworkAction::RemoveBlock;
        assert!(validate_plan(&plan, 1000).is_err());
        plan.sha256 = None;
        assert!(validate_plan(&plan, 1000).is_ok());
    }
    #[test]
    fn helper_input_is_bounded_and_never_a_shell_command() {
        for payload in [
            "".to_string(),
            "abc".into(),
            "00;calc".into(),
            "00".repeat(MAX_PAYLOAD),
        ] {
            assert!(decode_plan(&payload).is_err());
        }
        assert_eq!(rule_id(r"C:\Apps\Demo.exe"), rule_id(r"c:\apps\demo.exe"));
        assert!(Controller::default().execute(Uuid::new_v4()).is_err());
    }
}

pub mod reviews;

#[derive(Debug, serde::Serialize, serde::Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ExecutableSignature {
    pub executable: String,
    pub sha256: String,
    pub status: String,
    pub native_status: String,
    pub checked_at: u64,
    pub revocation_checked: bool,
    pub catalog_checked: bool,
}
pub fn executable_signature(path: &str) -> io::Result<ExecutableSignature> {
    use std::io::{Seek, SeekFrom};
    if path.len() > 1024 {
        return Err(invalid("Signature path exceeds 1024 bytes"));
    }
    let mut exe = inspect_executable(path)?;
    exe._file.seek(SeekFrom::Start(0))?;
    let code = piko_win_platform::signature::verify_embedded(&exe._file, &exe.path)?;
    let status = match code as u32 {
        0 => "verified_locally",
        0x800B0100 => "no_embedded_signature",
        0x80096010 => "digest_mismatch",
        _ => "not_verified",
    };
    Ok(ExecutableSignature {
        executable: exe.path,
        sha256: exe.sha256,
        status: status.into(),
        native_status: format!("0x{:08X}", code as u32),
        checked_at: now()?,
        revocation_checked: false,
        catalog_checked: false,
    })
}

#[cfg(test)]
mod signature_tests {
    use super::*;
    #[test]
    fn unsigned_real_pe_is_not_reported_as_trusted() -> io::Result<()> {
        let dir = std::env::temp_dir().join(format!("piko-signature-{}", Uuid::new_v4()));
        std::fs::create_dir(&dir)?;
        let path = dir.join("unsigned.exe");
        std::fs::copy(std::env::current_exe()?, &path)?;
        let before = std::fs::read(&path)?;
        let result = executable_signature(path.to_str().ok_or_else(|| invalid("test path"))?)?;
        assert_eq!(result.status, "no_embedded_signature");
        assert_eq!(result.native_status, "0x800B0100");
        assert_eq!(result.sha256, format!("{:x}", Sha256::digest(&before)));
        assert!(!result.revocation_checked);
        assert!(!result.catalog_checked);
        assert_eq!(std::fs::read(&path)?, before);
        std::fs::remove_file(path)?;
        std::fs::remove_dir(dir)?;
        Ok(())
    }
}

pub mod advisories;

pub mod restricted;

pub mod process_response;

pub mod registry_history;
