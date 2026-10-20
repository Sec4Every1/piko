#![forbid(unsafe_code)]
#![cfg(windows)]

use piko_security_core::{Action, ActionKind, ResponseStatus};
use piko_win_platform::file_response::{self, LockedFile, MAX_CONTENT};
use rusqlite::{params, Connection, OptionalExtension};
use sha2::{Digest, Sha256};
use std::{
    fs::{self, OpenOptions},
    io::{self, Read, Seek, SeekFrom, Write},
    path::{Path, PathBuf},
    time::{SystemTime, UNIX_EPOCH},
};
use uuid::Uuid;

type Result<T> = std::result::Result<T, Box<dyn std::error::Error + Send + Sync>>;
const VAULT_BUDGET: u64 = 128 * 1024 * 1024;
const MAX_QUARANTINE_PLANS: u64 = 1000;

pub struct ResponseEngine {
    actor: String,
    db: Connection,
    directory: PathBuf,
    roots: Vec<PathBuf>,
    excluded: Vec<PathBuf>,
    // Kept until after the connection drops. Separate logon sessions must not
    // recover or execute actions against the same vault concurrently.
    _lock: std::fs::File,
}
impl ResponseEngine {
    pub fn open(directory: &Path, roots: Vec<PathBuf>) -> Result<Self> {
        fs::create_dir_all(directory)?;
        let directory = fs::canonicalize(directory)?;
        if fs::symlink_metadata(&directory)?.file_type().is_symlink() {
            return Err("response directory must not be a link".into());
        }
        let lock = file_response::lock_vault(&directory)?;
        let db = Connection::open(directory.join("response.db"))?;
        db.execute_batch("PRAGMA journal_mode=DELETE; PRAGMA synchronous=FULL; PRAGMA max_page_count=8192;
          CREATE TABLE IF NOT EXISTS actions(id TEXT PRIMARY KEY, payload TEXT NOT NULL);
          CREATE TABLE IF NOT EXISTS transitions(position INTEGER PRIMARY KEY, action_id TEXT NOT NULL, payload TEXT NOT NULL);")?;
        let roots: Vec<_> = roots
            .into_iter()
            .filter(|p| p.is_dir())
            .map(fs::canonicalize)
            .collect::<io::Result<_>>()?;
        if roots.len() > 16 {
            return Err("at most 16 response roots".into());
        }
        let mut excluded = vec![directory.clone()];
        if let Some(parent) = directory.parent() {
            excluded.push(parent.into());
        }
        if let Ok(exe) = std::env::current_exe() {
            if let Some(p) = exe.parent() {
                excluded.push(fs::canonicalize(p)?);
            }
        }
        for var in [
            "SystemRoot",
            "ProgramFiles",
            "ProgramFiles(x86)",
            "ProgramData",
        ] {
            if let Some(p) = std::env::var_os(var) {
                if let Ok(p) = fs::canonicalize(p) {
                    excluded.push(p);
                }
            }
        }
        let mut engine = Self {
            actor: piko_win_platform::current_identity()?.sid,
            db,
            directory,
            roots,
            excluded,
            _lock: lock,
        };
        // No replay of effects after a crash. The backup remains available for
        // explicit restore; a conflicting destination always blocks recovery.
        // Select pending effects directly: old plans are not omitted when the
        // recovery journal contains more rows than the UI's bounded page.
        loop {
            let payload: Option<String> = engine.db.query_row(
                "SELECT payload FROM actions WHERE json_extract(payload,'$.status') IN ('executing','backup_ready') LIMIT 1",
                [], |row| row.get(0),
            ).optional()?;
            let Some(payload) = payload else {
                break;
            };
            let mut action: Action = serde_json::from_str(&payload)?;
            action.status = "uncertain".into();
            action.detail = "Runtime interrupted. Inspect destination; retry is disabled. A verified backup can be restored to an absent path.".into();
            engine.save(&action)?;
        }
        Ok(engine)
    }

    pub fn status(&self) -> Result<ResponseStatus> {
        Ok(ResponseStatus {
            roots: self.roots.iter().map(|p| display_path(p)).collect(),
            max_file_bytes: (MAX_CONTENT - 64 * 1024) as u64,
            vault_budget_bytes: VAULT_BUDGET,
            actions: self.all_actions(100)?,
        })
    }
    /// Called only by the authenticated runtime worker, never from IPC fields.
    pub fn set_actor(&mut self, sid: String) -> Result<()> {
        if !piko_win_platform::valid_sid_text(&sid) {
            return Err("invalid authenticated caller SID".into());
        }
        self.actor = sid;
        Ok(())
    }
    fn all_actions(&self, limit: u64) -> Result<Vec<Action>> {
        let mut q = self
            .db
            .prepare("SELECT payload FROM actions ORDER BY rowid DESC LIMIT ?1")?;
        let mut result = Vec::new();
        for row in q.query_map([limit], |row| row.get::<_, String>(0))? {
            result.push(serde_json::from_str(&row?)?);
        }
        Ok(result)
    }
    pub fn action(&self, id: Uuid) -> Result<Action> {
        let json: String = self.db.query_row(
            "SELECT payload FROM actions WHERE id=?1",
            [id.to_string()],
            |row| row.get(0),
        )?;
        Ok(serde_json::from_str(&json)?)
    }
    fn save(&mut self, action: &Action) -> Result<()> {
        if self.vault_bytes()?.saturating_add(128 * 1024) > VAULT_BUDGET {
            return Err("vault journal reserve exhausted; no effects authorized".into());
        }
        let json = serde_json::to_string(action)?;
        if json.len() > 16 * 1024 {
            return Err("action exceeds size limit".into());
        }
        let audit = serde_json::to_string(
            &serde_json::json!({"recorded_at": now()?, "actor_sid": self.actor, "action": action}),
        )?;
        let transaction = self.db.transaction()?;
        transaction.execute("INSERT INTO actions(id,payload) VALUES(?1,?2) ON CONFLICT(id) DO UPDATE SET payload=excluded.payload", params![action.id.to_string(), json])?;
        transaction.execute(
            "INSERT INTO transitions(action_id,payload) VALUES(?1,?2)",
            params![action.id.to_string(), audit],
        )?;
        transaction.commit()?;
        Ok(())
    }
    fn new_plan(&mut self, mut action: Action) -> Result<Action> {
        if action.kind == ActionKind::Quarantine {
            let count: u64 = self.db.query_row(
                "SELECT count(*) FROM actions WHERE json_extract(payload,'$.kind')='quarantine'",
                [],
                |row| row.get(0),
            )?;
            if count >= MAX_QUARANTINE_PLANS {
                return Err(
                    "quarantine plan limit reached (1000); recovery remains available".into(),
                );
            }
        }
        action.status = "planned".into();
        self.save(&action)?;
        Ok(action)
    }
    fn vault_bytes(&self) -> Result<u64> {
        let mut total = 0u64;
        for (index, entry) in fs::read_dir(&self.directory)?.enumerate() {
            if index > 1100 {
                return Err("unexpected vault entry count".into());
            }
            total = total.saturating_add(entry?.metadata()?.len());
        }
        Ok(total)
    }
    fn authorize_path(&self, path: &Path) -> Result<()> {
        if !self.roots.iter().any(|root| contained(path, root))
            || self.excluded.iter().any(|root| contained(path, root))
        {
            return Err("file is outside response roots or inside a protected directory".into());
        }
        Ok(())
    }
    fn locked(&self, path: &str) -> Result<LockedFile> {
        check_input_path(path)?;
        let file = LockedFile::open(Path::new(path))?;
        self.authorize_path(&file.path)?;
        Ok(file)
    }
    pub fn prepare_quarantine(&mut self, path: &str) -> Result<Action> {
        let mut file = self.locked(path)?;
        let bytes = read_content(&mut file)?;
        if bytes.len() > MAX_CONTENT - 64 * 1024 {
            return Err("file exceeds content limit with encryption overhead".into());
        }
        let now = now()?;
        self.new_plan(Action { requested_by: self.actor.clone(), confirmed_by: None, id: Uuid::new_v4(), kind: ActionKind::Quarantine, path: display_path(&file.path), sha256: hash(&bytes), bytes: bytes.len() as u64, file_identity: file.identity.clone(), created_at: now, expires_at: now + 300_000, status: String::new(), detail: "Explicit manual quarantine; this does not classify the file as malware. Removes this file after saving and verifying an encrypted backup. Does not stop running processes. Recovery restores content, inheriting destination folder permissions; original timestamps/ACL are not restored.".into(), backup_id: None })
    }
    fn backup_path(&self, id: Uuid) -> PathBuf {
        self.directory.join(format!("{id}.piko-vault"))
    }
    fn backup_content(&self, action: &Action) -> Result<Vec<u8>> {
        let id = action.backup_id.ok_or("no backup has been recorded")?;
        let mut file = LockedFile::open(&self.backup_path(id))?;
        // Ciphertext is slightly larger than the content limit; native open uses
        // the same cap, so input files reserve 64 KiB for DPAPI metadata below.
        let encrypted = read_content(&mut file)?;
        let data = file_response::unprotect(&encrypted)?;
        if data.len() as u64 != action.bytes || hash(&data) != action.sha256 {
            return Err("backup integrity verification failed".into());
        }
        Ok(data)
    }
    pub fn prepare_restore(&mut self, id: Uuid) -> Result<Action> {
        let source = self.action(id)?;
        if source.kind != ActionKind::Quarantine || source.backup_id.is_none() {
            return Err("action has no recovery backup".into());
        }
        self.backup_content(&source)?;
        self.check_destination(&source.path)?;
        let now = now()?;
        self.new_plan(Action { requested_by: self.actor.clone(), confirmed_by: None, id: Uuid::new_v4(), kind: ActionKind::Restore, path: source.path, sha256: source.sha256, bytes: source.bytes, file_identity: String::new(), created_at: now, expires_at: now + 300_000, status: String::new(), detail: "Restores verified content to its original path only if absent. Does not overwrite any file. Permissions are inherited from the destination folder. The encrypted backup is retained.".into(), backup_id: source.backup_id })
    }
    fn check_destination(&self, path: &str) -> Result<()> {
        check_input_path(path)?;
        match fs::symlink_metadata(path) {
            Ok(_) => {
                return Err(
                    "recovery conflict: destination already exists; no overwrite permitted".into(),
                )
            }
            Err(e) if e.kind() == io::ErrorKind::NotFound => {}
            Err(e) => return Err(e.into()),
        }
        let parent = Path::new(path).parent().ok_or("missing parent")?;
        let parent = fs::canonicalize(parent)?;
        self.authorize_path(&parent)?;
        Ok(())
    }
    pub fn execute(&mut self, id: Uuid, expected_sha256: &str) -> Result<Action> {
        let mut action = self.action(id)?;
        if action.sha256 != expected_sha256 {
            return Err("confirmation does not match the preview hash".into());
        }
        if action.status != "planned" {
            return Ok(action);
        } // idempotent retry: never replay effects
        let current = now()?;
        if current > action.expires_at || current < action.created_at {
            action.status = "expired".into();
            action.detail = "Plan expired. Prepare a new preview.".into();
            self.save(&action)?;
            return Ok(action);
        }
        action.status = "executing".into();
        action.confirmed_by = Some(self.actor.clone());
        self.save(&action)?; // fail closed before any effect if the journal is full
        let result = match action.kind {
            ActionKind::Quarantine => self.quarantine(&mut action),
            ActionKind::Restore => self.restore(&action),
        };
        match result {
            Ok(()) => {
                action.status = if action.kind == ActionKind::Quarantine {
                    "quarantined"
                } else {
                    "restored"
                }
                .into();
                action.detail =
                    "Effect completed and content integrity verified. Encrypted backup retained."
                        .into();
            }
            Err(error) => {
                action.status = "uncertain".into();
                action.detail = format!("Not confirmed complete: {error}. No automatic retry; inspect the file and recorded backup.");
            }
        }
        self.save(&action)?;
        Ok(action)
    }
    fn quarantine(&mut self, action: &mut Action) -> Result<()> {
        let mut file = self.locked(&action.path)?;
        let bytes = read_content(&mut file)?;
        if file.identity != action.file_identity
            || bytes.len() as u64 != action.bytes
            || hash(&bytes) != action.sha256
        {
            return Err("file changed since preview; nothing removed".into());
        }
        if bytes.len() > MAX_CONTENT - 64 * 1024 {
            return Err("file exceeds content limit with encryption overhead".into());
        }
        let encrypted = file_response::protect(&bytes)
            .map_err(|e| format!("DPAPI encryption failed; original preserved: {e}"))?;
        let used = self.vault_bytes()?;
        // Leave room for durable completion and subsequent recovery metadata.
        if used
            .saturating_add(encrypted.len() as u64)
            .saturating_add(8 * 1024 * 1024)
            > VAULT_BUDGET
        {
            return Err("vault budget exhausted; original preserved".into());
        }
        let path = self.backup_path(action.id);
        let mut backup = OpenOptions::new()
            .write(true)
            .create_new(true)
            .open(&path)?;
        backup.write_all(&encrypted)?;
        backup.sync_all()?;
        drop(backup);
        action.backup_id = Some(action.id);
        // Reopen, decrypt and hash the durable copy BEFORE source removal.
        self.backup_content(action)?;
        action.status = "backup_ready".into();
        self.save(action)?;
        file.delete()?;
        match fs::symlink_metadata(&action.path) {
            Err(e) if e.kind() == io::ErrorKind::NotFound => Ok(()),
            _ => Err(
                "destination reappeared or absence could not be verified; backup retained".into(),
            ),
        }
    }
    fn restore(&self, action: &Action) -> Result<()> {
        self.check_destination(&action.path)?;
        let bytes = self.backup_content(action)?;
        let mut output = LockedFile::create(Path::new(&action.path))?;
        let result = (|| -> Result<()> {
            self.authorize_path(&output.path)?; // validate the opened object, before writing
            output.file.write_all(&bytes)?;
            output.file.sync_all()?;
            if hash(&read_content(&mut output)?) != action.sha256 {
                return Err("restored content verification failed".into());
            }
            Ok(())
        })();
        if result.is_err() {
            let _ = output.delete();
        } // only the exclusively owned new file
        result
    }
}

fn now() -> Result<i64> {
    Ok(i64::try_from(
        SystemTime::now().duration_since(UNIX_EPOCH)?.as_millis(),
    )?)
}
fn hash(bytes: &[u8]) -> String {
    format!("{:x}", Sha256::digest(bytes))
}
fn display_path(path: &Path) -> String {
    path.to_string_lossy()
        .strip_prefix(r"\\?\")
        .unwrap_or(&path.to_string_lossy())
        .to_string()
}
fn contained(path: &Path, root: &Path) -> bool {
    // Both operands come from Windows canonical handle paths. Do not Unicode
    // lowercase them: case folding can conflate distinct Windows directory
    // names and violates NTFS directories with case sensitivity enabled.
    Path::new(&display_path(path)).starts_with(Path::new(&display_path(root)))
}
fn check_input_path(path: &str) -> Result<()> {
    let b = path.as_bytes();
    if b.len() < 4
        || b.len() > 1024
        || !b[0].is_ascii_alphabetic()
        || b[1] != b':'
        || b[2] != b'\\'
        || path[2..].contains(':')
        || path.chars().any(char::is_control)
    {
        return Err(
            "requires a local absolute drive path; device/UNC/ADS paths are forbidden".into(),
        );
    }
    Ok(())
}
fn read_content(file: &mut LockedFile) -> Result<Vec<u8>> {
    file.file.seek(SeekFrom::Start(0))?;
    let mut bytes = Vec::new();
    (&mut file.file)
        .take(MAX_CONTENT as u64 + 1)
        .read_to_end(&mut bytes)?;
    if bytes.len() > MAX_CONTENT {
        return Err("file size limit exceeded".into());
    }
    Ok(bytes)
}

#[cfg(test)]
mod tests {
    use super::*;
    fn insert_plan_fixtures(e: &mut ResponseEngine, seed: &Action, count: u64) -> Result<()> {
        let transaction = e.db.transaction()?;
        for _ in 0..count {
            let mut action = seed.clone();
            action.id = Uuid::new_v4();
            action.status = "planned".into();
            action.confirmed_by = None;
            transaction.execute(
                "INSERT INTO actions(id,payload) VALUES(?1,?2)",
                params![action.id.to_string(), serde_json::to_string(&action)?],
            )?;
        }
        transaction.commit()?;
        Ok(())
    }

    #[test]
    fn canonical_scope_does_not_conflate_distinct_names() {
        assert!(contained(
            Path::new(r"C:\scope\folder\file.txt"),
            Path::new(r"C:\scope")
        ));
        assert!(!contained(
            Path::new(r"C:\scope-other\file.txt"),
            Path::new(r"C:\scope")
        ));
        assert!(!contained(
            Path::new("C:\\i\u{0307}\\file.txt"),
            Path::new("C:\\İ")
        ));
        assert!(!contained(
            Path::new(r"C:\SCOPE\file.txt"),
            Path::new(r"C:\scope")
        ));
    }

    #[test]
    fn vault_has_one_owner_and_releases_lock_on_shutdown() -> Result<()> {
        let (temp, e, _) = setup()?;
        let directory = temp.path().join("state/response");
        let roots = vec![temp.path().join("files")];
        assert!(ResponseEngine::open(&directory, roots.clone()).is_err());
        let independent = ResponseEngine::open(&temp.path().join("other/response"), roots.clone())?;
        drop(independent);
        drop(e);
        let reopened = ResponseEngine::open(&directory, roots)?;
        assert!(reopened.status()?.actions.is_empty());
        Ok(())
    }

    #[test]
    fn quarantine_plan_limit_does_not_block_recovery() -> Result<()> {
        let (_temp, mut e, path) = setup()?;
        let plan = e.prepare_quarantine(&display_path(&path))?;
        assert_eq!(e.execute(plan.id, &plan.sha256)?.status, "quarantined");
        insert_plan_fixtures(&mut e, &plan, MAX_QUARANTINE_PLANS - 1)?;
        let another = path.with_extension("another");
        fs::write(&another, b"preserved")?;
        assert!(e.prepare_quarantine(&display_path(&another)).is_err());
        let recovery = e.prepare_restore(plan.id)?;
        assert_eq!(e.execute(recovery.id, &recovery.sha256)?.status, "restored");
        assert_eq!(fs::read(&path)?, b"piko benign response test");
        Ok(())
    }
    struct TestDir(PathBuf);
    impl TestDir {
        fn path(&self) -> &Path {
            &self.0
        }
    }
    impl Drop for TestDir {
        fn drop(&mut self) {
            if self.0.parent() == Some(std::env::temp_dir().as_path())
                && self
                    .0
                    .file_name()
                    .is_some_and(|n| n.to_string_lossy().starts_with("piko-response-test-"))
            {
                let _ = fs::remove_dir_all(&self.0);
            }
        }
    }
    fn setup() -> Result<(TestDir, ResponseEngine, PathBuf)> {
        let temp =
            TestDir(std::env::temp_dir().join(format!("piko-response-test-{}", Uuid::new_v4())));
        fs::create_dir(&temp.0)?;
        let root = temp.path().join("files");
        fs::create_dir(&root)?;
        let engine = ResponseEngine::open(&temp.path().join("state/response"), vec![root.clone()])?;
        let file = root.join("innocent.txt");
        fs::write(&file, b"piko benign response test")?;
        Ok((temp, engine, file))
    }
    #[test]
    fn quarantine_reopen_restore_and_idempotence() -> Result<()> {
        let (temp, mut e, path) = setup()?;
        let plan = e.prepare_quarantine(&display_path(&path))?;
        assert!(path.exists());
        assert!(e.execute(plan.id, "wrong hash").is_err());
        assert!(path.exists());
        let result = e.execute(plan.id, &plan.sha256)?;
        assert_eq!(result.status, "quarantined", "{}", result.detail);
        assert!(!path.exists());
        assert_eq!(e.execute(plan.id, &plan.sha256)?.status, "quarantined");
        let backup = fs::read(e.backup_path(plan.id))?;
        assert!(!backup
            .windows(24)
            .any(|w| w == b"piko benign response test"));
        drop(e);
        let mut e = ResponseEngine::open(
            &temp.path().join("state/response"),
            vec![temp.path().join("files")],
        )?;
        let restore = e.prepare_restore(plan.id)?;
        assert_eq!(e.execute(restore.id, &restore.sha256)?.status, "restored");
        assert_eq!(fs::read(&path)?, b"piko benign response test");
        assert!(e.backup_path(plan.id).exists());
        assert!(e.prepare_restore(plan.id).is_err());
        Ok(())
    }
    #[test]
    fn changed_file_and_new_recovery_destination_are_preserved() -> Result<()> {
        let (_temp, mut e, path) = setup()?;
        let plan = e.prepare_quarantine(&display_path(&path))?;
        fs::write(&path, b"new user content")?;
        assert_ne!(e.execute(plan.id, &plan.sha256)?.status, "quarantined");
        assert_eq!(fs::read(&path)?, b"new user content");
        let plan = e.prepare_quarantine(&display_path(&path))?;
        assert_eq!(e.execute(plan.id, &plan.sha256)?.status, "quarantined");
        let restore = e.prepare_restore(plan.id)?;
        fs::write(&path, b"new destination")?;
        assert_ne!(e.execute(restore.id, &restore.sha256)?.status, "restored");
        assert_eq!(fs::read(&path)?, b"new destination");
        Ok(())
    }
    #[test]
    fn expired_and_interrupted_plans_never_replay() -> Result<()> {
        let (temp, mut e, path) = setup()?;
        let mut plan = e.prepare_quarantine(&display_path(&path))?;
        plan.expires_at = 1;
        e.save(&plan)?;
        assert_eq!(e.execute(plan.id, &plan.sha256)?.status, "expired");
        let mut plan = e.prepare_quarantine(&display_path(&path))?;
        plan.status = "executing".into();
        e.save(&plan)?;
        drop(e);
        let mut e = ResponseEngine::open(
            &temp.path().join("state/response"),
            vec![temp.path().join("files")],
        )?;
        assert_eq!(e.execute(plan.id, &plan.sha256)?.status, "uncertain");
        assert!(path.exists());
        Ok(())
    }
    #[test]
    fn corrupt_backup_is_rejected_without_creating_destination() -> Result<()> {
        let (_temp, mut e, path) = setup()?;
        let plan = e.prepare_quarantine(&display_path(&path))?;
        assert_eq!(e.execute(plan.id, &plan.sha256)?.status, "quarantined");
        let restore = e.prepare_restore(plan.id)?;
        fs::write(e.backup_path(plan.id), b"corrupt")?;
        assert_ne!(e.execute(restore.id, &restore.sha256)?.status, "restored");
        assert!(!path.exists());
        Ok(())
    }
    #[test]
    fn outside_roots_hard_links_and_ads_are_rejected() -> Result<()> {
        let (temp, mut e, path) = setup()?;
        let outside = temp.path().join("outside.txt");
        fs::write(&outside, b"outside")?;
        assert!(e.prepare_quarantine(&display_path(&outside)).is_err());
        let link = path.with_extension("hardlink");
        fs::hard_link(&path, &link)?;
        assert!(e.prepare_quarantine(&display_path(&path)).is_err());
        fs::remove_file(&link)?;
        fs::write(
            format!("{}:extra", display_path(&path)),
            b"alternate stream",
        )?;
        assert!(e.prepare_quarantine(&display_path(&path)).is_err());
        assert!(e
            .prepare_quarantine(&format!("{}:extra", display_path(&path)))
            .is_err());
        assert!(path.exists());
        Ok(())
    }

    #[test]
    fn same_content_replacement_and_unavailable_journal_preserve_original() -> Result<()> {
        let (_temp, mut e, path) = setup()?;
        let plan = e.prepare_quarantine(&display_path(&path))?;
        fs::rename(&path, path.with_extension("previous"))?;
        fs::write(&path, b"piko benign response test")?;
        assert_ne!(e.execute(plan.id, &plan.sha256)?.status, "quarantined");
        assert!(path.exists());
        let plan = e.prepare_quarantine(&display_path(&path))?;
        e.db.execute_batch("CREATE TRIGGER block_journal BEFORE UPDATE ON actions BEGIN SELECT RAISE(ABORT,'test journal unavailable'); END;")?;
        assert!(e.execute(plan.id, &plan.sha256).is_err());
        assert_eq!(fs::read(&path)?, b"piko benign response test");
        assert!(!e.backup_path(plan.id).exists());
        Ok(())
    }

    #[test]
    fn interrupted_after_removal_recovers_from_recorded_backup() -> Result<()> {
        let (temp, mut e, path) = setup()?;
        let plan = e.prepare_quarantine(&display_path(&path))?;
        let mut action = e.execute(plan.id, &plan.sha256)?;
        assert_eq!(action.status, "quarantined");
        action.status = "backup_ready".into();
        e.save(&action)?;
        // A pending effect can belong to a much older plan. New recovery rows
        // must not hide it from startup reconciliation's bounded UI window.
        let mut recovery_seed = action.clone();
        recovery_seed.kind = ActionKind::Restore;
        insert_plan_fixtures(&mut e, &recovery_seed, 1001)?;
        drop(e);
        let mut e = ResponseEngine::open(
            &temp.path().join("state/response"),
            vec![temp.path().join("files")],
        )?;
        assert_eq!(e.action(plan.id)?.status, "uncertain");
        let restore = e.prepare_restore(plan.id)?;
        assert_eq!(e.execute(restore.id, &restore.sha256)?.status, "restored");
        assert_eq!(fs::read(&path)?, b"piko benign response test");
        Ok(())
    }
}
