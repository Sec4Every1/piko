//! Confirmed, single-use AppContainer launches of one verified staged executable.
//! Original app permissions/installations are never modified.
use crate::{inspect_executable, invalid, now, Executable, PLAN_SECONDS};
pub use piko_win_platform::restricted::NetworkAccess;
use piko_win_platform::restricted::{Profile, TrialProcess, MEMORY_LIMIT_BYTES, PROCESS_LIMIT};
use serde::Serialize;
use std::{
    collections::HashMap,
    fs::{self, File, OpenOptions},
    io::{self, Seek, SeekFrom},
    os::windows::fs::OpenOptionsExt,
    path::{Path, PathBuf},
};
use uuid::Uuid;
const MAX_TRIALS: usize = 2;
const MAX_STAGING: usize = 4;
#[derive(Clone, Serialize)]
pub struct RestrictedPolicy {
    pub network_access: NetworkAccess,
    pub network_capabilities: u32,
    pub max_processes: u32,
    pub memory_limit_bytes: usize,
    pub original_unchanged: bool,
    pub staged_read_only: bool,
    pub stop_on_ui_exit: bool,
}
impl Default for RestrictedPolicy {
    fn default() -> Self {
        Self {
            network_access: NetworkAccess::None,
            network_capabilities: 0,
            max_processes: PROCESS_LIMIT,
            memory_limit_bytes: MEMORY_LIMIT_BYTES,
            original_unchanged: true,
            staged_read_only: true,
            stop_on_ui_exit: true,
        }
    }
}
#[derive(Clone, Serialize)]
pub struct RestrictedPlan {
    pub id: Uuid,
    pub executable: String,
    pub sha256: String,
    pub expires_at: u64,
    pub policy: RestrictedPolicy,
}
#[derive(Clone, Serialize)]
pub struct RestrictedSession {
    pub id: Uuid,
    pub executable: String,
    pub sha256: String,
    pub pid: u32,
    pub created_at: u64,
    pub running: bool,
    pub data_directory: String,
    pub policy: RestrictedPolicy,
}
struct Session {
    view: RestrictedSession,
    process: Option<TrialProcess>,
    staged: Option<Executable>,
    locks: Vec<File>,
    directory: PathBuf,
    profile: Profile,
}
impl Session {
    fn cleanup(&mut self) -> io::Result<()> {
        if let Some(process) = &self.process {
            process.stop()?;
        }
        self.process = None;
        self.view.running = false;
        self.staged = None;
        // Locks of staging parents remain until its only file has been removed.
        match fs::remove_file(self.directory.join("payload.exe")) {
            Ok(()) => {}
            Err(e) if e.kind() == io::ErrorKind::NotFound => {}
            Err(e) => return Err(e),
        }
        self.locks.clear();
        match fs::remove_dir(&self.directory) {
            Ok(()) => {}
            Err(e) if e.kind() == io::ErrorKind::NotFound => {}
            Err(e) => return Err(e),
        }
        self.profile.remove()
    }
}
impl Drop for Session {
    fn drop(&mut self) {
        let _ = self.cleanup();
    }
}
#[derive(Default)]
pub struct RestrictedController {
    plans: HashMap<Uuid, RestrictedPlan>,
    sessions: HashMap<Uuid, Session>,
}
impl RestrictedController {
    pub fn prepare(&mut self, path: &str) -> io::Result<RestrictedPlan> {
        self.prepare_with_network(path, NetworkAccess::None)
    }
    pub fn prepare_with_network(
        &mut self,
        path: &str,
        network: NetworkAccess,
    ) -> io::Result<RestrictedPlan> {
        let time = now()?;
        self.plans.retain(|_, p| p.expires_at > time);
        if self.plans.len() >= 8 {
            return Err(invalid("Troppe anteprime aperte; attendere cinque minuti"));
        }
        let exe = inspect_executable(path)?;
        let plan = RestrictedPlan {
            id: Uuid::new_v4(),
            executable: exe.path,
            sha256: exe.sha256,
            expires_at: time + PLAN_SECONDS,
            policy: RestrictedPolicy {
                network_access: network,
                network_capabilities: network.capability_count(),
                ..RestrictedPolicy::default()
            },
        };
        self.plans.insert(plan.id, plan.clone());
        Ok(plan)
    }
    pub fn discard(&mut self, id: Uuid) {
        self.plans.remove(&id);
    }
    pub fn sessions(&self) -> io::Result<Vec<RestrictedSession>> {
        let mut result = Vec::new();
        for session in self.sessions.values() {
            let mut view = session.view.clone();
            view.running = session
                .process
                .as_ref()
                .map(|p| p.running())
                .transpose()?
                .unwrap_or(false);
            result.push(view);
        }
        result.sort_by_key(|s| std::cmp::Reverse(s.created_at));
        Ok(result)
    }
    pub fn launch(&mut self, root: &Path, id: Uuid) -> io::Result<RestrictedSession> {
        let plan = self
            .plans
            .remove(&id)
            .ok_or_else(|| invalid("Anteprima assente o già utilizzata"))?;
        let time = now()?;
        if plan.expires_at <= time || plan.expires_at > time + PLAN_SECONDS {
            return Err(invalid("Anteprima scaduta"));
        }
        if self.sessions.len() >= MAX_TRIALS {
            return Err(invalid(
                "Chiudi una prova prima di avviarne un'altra (massimo due)",
            ));
        }
        let mut source = inspect_executable(&plan.executable)?;
        if source.sha256 != plan.sha256 {
            return Err(invalid("Eseguibile cambiato dopo l’anteprima"));
        }
        fs::create_dir_all(root)?;
        let _root = piko_win_platform::network_elevation::lock_path_parents(&root.join("unused"))?;
        if fs::read_dir(root)?.take(MAX_STAGING).count() >= MAX_STAGING {
            return Err(invalid("Quattro cartelle di prova presenti; controllare le copie residue prima di continuare"));
        }
        let directory = root.join(id.to_string());
        fs::create_dir(&directory)?;
        let result = (|| {
            let locks = piko_win_platform::network_elevation::lock_path_parents(
                &directory.join("payload.exe"),
            )?;
            let profile = Profile::create(&id.to_string())?;
            // WRITE_DAC is requested only on this new owned staging directory/file.
            let acl_directory = OpenOptions::new()
                .access_mode(0x00060000)
                .share_mode(1 | 2)
                .custom_flags(0x02000000 | 0x00200000)
                .open(&directory)?;
            profile.protect_staging(&acl_directory)?;
            drop(acl_directory);
            let payload = directory.join("payload.exe");
            let mut target = OpenOptions::new()
                .write(true)
                .create_new(true)
                .open(&payload)?;
            source._file.seek(SeekFrom::Start(0))?;
            io::copy(&mut source._file, &mut target)?;
            target.sync_all()?;
            drop(target);
            let staged = inspect_executable(
                payload
                    .to_str()
                    .ok_or_else(|| invalid("Percorso non Unicode"))?,
            )?;
            if staged.sha256 != plan.sha256 {
                return Err(invalid("Copia di prova non corrispondente"));
            }
            let acl_file = OpenOptions::new()
                .access_mode(0x00060000)
                .share_mode(1)
                .custom_flags(0x00200000)
                .open(&payload)?;
            profile.protect_staging(&acl_file)?;
            drop(acl_file);
            // Keep verified source and copy handles plus all parents locked through launch.
            let process = piko_win_platform::restricted::launch_with_network(
                &profile,
                &payload,
                &directory,
                plan.policy.network_access,
            )?;
            let view = RestrictedSession {
                id,
                executable: plan.executable,
                sha256: plan.sha256,
                pid: process.pid,
                created_at: time,
                running: process.running()?,
                data_directory: profile.data_directory.to_string_lossy().into_owned(),
                policy: plan.policy,
            };
            Ok(Session {
                view,
                process: Some(process),
                staged: Some(staged),
                locks,
                directory: directory.clone(),
                profile,
            })
        })();
        match result {
            Ok(session) => {
                let view = session.view.clone();
                self.sessions.insert(id, session);
                Ok(view)
            }
            Err(error) => {
                // Fixed-file cleanup only; a failed/nonempty/replaced directory is retained.
                if let Ok(locks) = piko_win_platform::network_elevation::lock_path_parents(
                    &directory.join("payload.exe"),
                ) {
                    let _ = fs::remove_file(directory.join("payload.exe"));
                    drop(locks);
                    let _ = fs::remove_dir(directory);
                }
                Err(error)
            }
        }
    }
    pub fn stop(&mut self, id: Uuid) -> io::Result<()> {
        let session = self
            .sessions
            .get_mut(&id)
            .ok_or_else(|| invalid("Prova non presente in questa sessione piko"))?;
        session.cleanup()?;
        self.sessions.remove(&id);
        Ok(())
    }
}
#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn prepare_does_not_create_profile_or_run_and_plan_is_single_use() -> io::Result<()> {
        let root = std::env::temp_dir().join(format!("piko-restricted-{}", Uuid::new_v4()));
        fs::create_dir(&root)?;
        let exe = root.join("sample.exe");
        let mut data = vec![0u8; 128];
        data[..2].copy_from_slice(b"MZ");
        fs::write(&exe, &data)?;
        let mut c = RestrictedController::default();
        let p = c.prepare(exe.to_str().ok_or_else(|| invalid("test"))?)?;
        assert_eq!(p.policy.network_capabilities, 0);
        assert_eq!(p.policy.network_access, NetworkAccess::None);
        let online = c.prepare_with_network(
            exe.to_str().ok_or_else(|| invalid("test"))?,
            NetworkAccess::InternetClient,
        )?;
        assert_eq!(online.policy.network_access, NetworkAccess::InternetClient);
        assert_eq!(online.policy.network_capabilities, 1);
        assert_eq!(c.plans[&p.id].policy.network_access, NetworkAccess::None);
        assert_eq!(
            c.plans[&online.id].policy.network_access,
            NetworkAccess::InternetClient
        );
        assert!(c.sessions()?.is_empty());
        data[2] = 42;
        fs::write(&exe, data)?;
        assert!(c.launch(&root.join("trials"), p.id).is_err());
        assert!(c.launch(&root.join("trials"), online.id).is_err());
        assert!(!root.join("trials").exists());
        assert!(c.launch(&root.join("trials"), p.id).is_err());
        fs::remove_file(exe)?;
        fs::remove_dir(root)?;
        Ok(())
    }
    #[test]
    fn network_contract_has_closed_names_and_offline_default() -> io::Result<()> {
        assert_eq!(NetworkAccess::default(), NetworkAccess::None);
        assert_eq!(
            serde_json::to_string(&NetworkAccess::InternetClient)?,
            "\"internet_client\""
        );
        assert_eq!(
            serde_json::from_str::<NetworkAccess>("\"none\"")?,
            NetworkAccess::None
        );
        for value in [
            "\"all\"",
            "\"private_network\"",
            "\"InternetClient\"",
            "1",
            "null",
        ] {
            assert!(serde_json::from_str::<NetworkAccess>(value).is_err());
        }
        Ok(())
    }
    #[test]
    fn cancelled_expired_unknown_plans_never_launch() -> io::Result<()> {
        let mut c = RestrictedController::default();
        assert!(c.launch(Path::new(r"C:\unowned"), Uuid::new_v4()).is_err());
        let id = Uuid::new_v4();
        c.plans.insert(
            id,
            RestrictedPlan {
                id,
                executable: r"C:\absent.exe".into(),
                sha256: "0".repeat(64),
                expires_at: 0,
                policy: RestrictedPolicy::default(),
            },
        );
        assert!(c.launch(Path::new(r"C:\unowned"), id).is_err());
        c.discard(Uuid::new_v4());
        assert!(c.stop(id).is_err());
        Ok(())
    }

    /// Real token/cleanup qualification only: the fixture performs no network I/O
    /// and accesses only its own AppContainer report file.
    #[test]
    #[ignore = "explicit native None/InternetClient token and cleanup qualification"]
    fn native_network_contract_tokens_and_cleanup_without_network_io() -> io::Result<()> {
        use std::{
            process::Command,
            time::{Duration, Instant},
        };

        struct Fixture(PathBuf);
        impl Drop for Fixture {
            fn drop(&mut self) {
                // This unique directory contains only the test source and build output.
                if let Err(error) = fs::remove_dir_all(&self.0) {
                    if error.kind() != io::ErrorKind::NotFound {
                        eprintln!("native token fixture cleanup failed: {error}");
                    }
                }
            }
        }
        let fixture = Fixture(
            std::env::temp_dir().join(format!("piko-native-token-contract-{}", Uuid::new_v4())),
        );
        fs::create_dir(&fixture.0)?;
        let source = fixture.0.join("ready.rs");
        let executable = fixture.0.join("ready.exe");
        fs::write(
            &source,
            r#"
fn main() {
    let directory = std::path::PathBuf::from(std::env::var_os("LOCALAPPDATA").unwrap());
    std::fs::write(directory.join("ready.txt"), "resumed-after-native-token-check").unwrap();
    std::thread::sleep(std::time::Duration::from_secs(30));
}
"#,
        )?;
        let output = Command::new("rustc")
            .args(["--edition=2021", "-C", "opt-level=1"])
            .arg(&source)
            .arg("-o")
            .arg(&executable)
            .output()?;
        if !output.status.success() {
            return Err(io::Error::other(
                String::from_utf8_lossy(&output.stderr).into_owned(),
            ));
        }
        let path = executable.to_str().ok_or_else(|| invalid("test path"))?;
        let original_hash = inspect_executable(path)?.sha256;
        let staging = fixture.0.join("trials");
        // Declared after Fixture: owned sessions are terminated/cleaned first on failure.
        let mut controller = RestrictedController::default();
        for network in [NetworkAccess::None, NetworkAccess::InternetClient] {
            let plan = controller.prepare_with_network(path, network)?;
            assert_eq!(plan.policy.network_access, network);
            let session = controller.launch(&staging, plan.id)?;
            assert_eq!(session.policy.network_access, network);
            assert_eq!(
                session.policy.network_capabilities,
                network.capability_count()
            );
            let report = Path::new(&session.data_directory).join("ready.txt");
            let deadline = Instant::now() + Duration::from_secs(10);
            while !report.is_file() && Instant::now() < deadline {
                std::thread::sleep(Duration::from_millis(50));
            }
            // Even a failed report read must stop the owned trial before returning.
            let ready = fs::read_to_string(&report);
            controller.stop(session.id)?;
            assert_eq!(ready?, "resumed-after-native-token-check");
            assert!(controller.sessions()?.is_empty());
            assert!(!Path::new(&session.data_directory).exists());
            assert!(!staging.join(session.id.to_string()).exists());
            assert_eq!(inspect_executable(path)?.sha256, original_hash);
            eprintln!("PASS {network:?}: real capability token, readiness, stop/profile/staging cleanup; no network I/O");
        }
        drop(controller);
        fs::remove_dir_all(&fixture.0)?;
        Ok(())
    }

    /// Ignored in routine suites because it creates a disposable Windows profile and
    /// compiles/runs only the harmless source defined here. No installed target is run.
    #[test]
    #[ignore = "explicit native AppContainer qualification with a newly compiled harmless fixture"]
    fn native_fixture_has_denials_and_cleans_up() -> io::Result<()> {
        use std::{
            net::TcpListener,
            process::Command,
            time::{Duration, Instant},
        };
        let root = std::env::temp_dir().join(format!("piko-restricted-native-{}", Uuid::new_v4()));
        fs::create_dir(&root)?;
        let listener = TcpListener::bind("127.0.0.1:0")?;
        let port = listener.local_addr()?.port();
        let secret = root.join("private.txt");
        fs::write(&secret, "test fixture, no sensitive data")?;
        let source = root.join("probe.rs");
        let executable = root.join("probe.exe");
        let fixture = format!(
            r#"
use std::{{fs,net::{{TcpStream,SocketAddr}},process::Command,time::Duration}};
fn main() {{
    let myself = std::env::current_exe().unwrap();
    let code_read_only = fs::OpenOptions::new().write(true).open(&myself).is_err();
    let child_denied = match Command::new(&myself).spawn() {{ Ok(mut child) => {{ let _ = child.kill(); let _ = child.wait(); false }}, Err(_) => true }};
    let network_denied = TcpStream::connect_timeout(&"127.0.0.1:{port}".parse::<SocketAddr>().unwrap(), Duration::from_secs(1)).is_err();
    let private_denied = fs::read({secret:?}).is_err();
    let environment_filtered = std::env::var("PIKO_TEST_PRIVATE_ENV").is_err();
    let report = std::path::PathBuf::from(std::env::var("LOCALAPPDATA").unwrap()).join("probe-result.txt");
    fs::write(&report, format!("code={{code_read_only}} child={{child_denied}} network={{network_denied}} private={{private_denied}} env={{environment_filtered}}")).unwrap_or_else(|error| panic!("probe report {{report:?}}: {{error}}"));
    std::thread::sleep(Duration::from_secs(30));
}}
"#,
            secret = secret.to_string_lossy()
        );
        fs::write(&source, fixture)?;
        let output = Command::new("rustc")
            .args(["--edition=2021", "-C", "opt-level=1"])
            .arg(&source)
            .arg("-o")
            .arg(&executable)
            .output()?;
        if !output.status.success() {
            return Err(io::Error::other(
                String::from_utf8_lossy(&output.stderr).into_owned(),
            ));
        }
        // This value is harmless and proves inherited environment is filtered.
        let old = std::env::var_os("PIKO_TEST_PRIVATE_ENV");
        std::env::set_var("PIKO_TEST_PRIVATE_ENV", "fixture-only");
        let mut controller = RestrictedController::default();
        let plan = controller.prepare(executable.to_str().ok_or_else(|| invalid("test"))?)?;
        let hash = plan.sha256.clone();
        let session_result = controller.launch(&root.join("trials"), plan.id);
        match old {
            Some(value) => std::env::set_var("PIKO_TEST_PRIVATE_ENV", value),
            None => std::env::remove_var("PIKO_TEST_PRIVATE_ENV"),
        };
        let session = session_result?;
        eprintln!(
            "probe profile={} exists={}",
            session.data_directory,
            Path::new(&session.data_directory).exists()
        );
        let report = Path::new(&session.data_directory).join("probe-result.txt");
        let start = Instant::now();
        while !report.is_file() && start.elapsed() < Duration::from_secs(10) {
            std::thread::sleep(Duration::from_millis(50));
        }
        let result = fs::read_to_string(&report);
        let stopped = controller.stop(session.id);
        let report = result?;
        stopped?;
        assert!(report.contains("code=true"), "{report}");
        assert!(report.contains("child=true"), "{report}");
        assert!(report.contains("network=true"), "{report}");
        assert!(report.contains("env=true"), "{report}");
        // Typical user-private ACLs are tested, not generalized to every outside path.
        assert!(report.contains("private=true"), "{report}");
        assert!(controller.sessions()?.is_empty());
        assert!(!Path::new(&session.data_directory).exists());
        assert!(!root.join("trials").join(session.id.to_string()).exists());
        assert_eq!(
            inspect_executable(executable.to_str().ok_or_else(|| invalid("test"))?)?.sha256,
            hash
        );
        for path in [&executable, &source, &secret] {
            fs::remove_file(path)?;
        }
        let pdb = executable.with_extension("pdb");
        if pdb.is_file() {
            fs::remove_file(pdb)?;
        }
        fs::remove_dir(root.join("trials"))?;
        fs::remove_dir(root)?;
        Ok(())
    }
}
