//! Opt-in Windows Sandbox profiles. Never executes the selected binary on the host.
use crate::{inspect_executable, invalid, now, PLAN_SECONDS};
use serde::{Deserialize, Serialize};
use std::os::windows::fs::OpenOptionsExt;
use std::{
    collections::HashMap,
    fs::{self, OpenOptions},
    io::{self, Read, Seek, SeekFrom, Write},
    path::{Path, PathBuf},
    process::Command,
};
use uuid::Uuid;

const MAX_SESSIONS: usize = 8;
#[derive(Clone, Serialize)]
pub struct SandboxStatus {
    pub launcher_available: bool,
    pub max_sessions: usize,
}
#[derive(Clone, Serialize)]
pub struct SandboxPlan {
    pub id: Uuid,
    pub executable: String,
    pub sha256: String,
    pub expires_at: u64,
}
#[derive(Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct SandboxSession {
    pub id: Uuid,
    pub executable: String,
    pub sha256: String,
    pub created_at: u64,
    pub configuration: String,
}
#[derive(Default)]
pub struct SandboxController {
    plans: HashMap<Uuid, SandboxPlan>,
}
fn launcher() -> io::Result<PathBuf> {
    Ok(piko_win_platform::network_elevation::windows_directory()?
        .join("System32")
        .join("WindowsSandbox.exe"))
}
pub fn status() -> io::Result<SandboxStatus> {
    Ok(SandboxStatus {
        launcher_available: launcher()?.is_file(),
        max_sessions: MAX_SESSIONS,
    })
}
fn xml(value: &str) -> String {
    value
        .replace('&', "&amp;")
        .replace('<', "&lt;")
        .replace('>', "&gt;")
        .replace('"', "&quot;")
        .replace('\'', "&apos;")
}
fn configuration(input: &Path) -> io::Result<String> {
    let path = input
        .to_str()
        .ok_or_else(|| invalid("Percorso non Unicode"))?;
    if path.chars().any(char::is_control) || path.contains('%') {
        return Err(invalid("Percorso Sandbox non supportato"));
    }
    Ok(format!("<Configuration>\n<vGPU>Disable</vGPU>\n<Networking>Disable</Networking>\n<AudioInput>Disable</AudioInput>\n<VideoInput>Disable</VideoInput>\n<PrinterRedirection>Disable</PrinterRedirection>\n<ClipboardRedirection>Disable</ClipboardRedirection>\n<ProtectedClient>Enable</ProtectedClient>\n<MemoryInMB>4096</MemoryInMB>\n<MappedFolders><MappedFolder><HostFolder>{}</HostFolder><SandboxFolder>C:\\PikoInput</SandboxFolder><ReadOnly>true</ReadOnly></MappedFolder></MappedFolders>\n</Configuration>\n", xml(path)))
}
fn lock_root(root: &Path) -> io::Result<Vec<fs::File>> {
    fs::create_dir_all(root)?;
    piko_win_platform::network_elevation::lock_path_parents(&root.join("unused"))
}
fn read_bounded(path: &Path) -> io::Result<String> {
    let file = OpenOptions::new()
        .read(true)
        .share_mode(1)
        .custom_flags(0x00200000)
        .open(path)?;
    use std::os::windows::fs::MetadataExt;
    if !file.metadata()?.is_file()
        || file.metadata()?.file_attributes() & 0x400 != 0
        || file.metadata()?.len() > 16384
    {
        return Err(invalid("File di sessione non valido"));
    }
    let mut text = String::new();
    file.take(16385).read_to_string(&mut text)?;
    if text.len() > 16384 {
        return Err(invalid("Sessione oltre limite"));
    }
    Ok(text)
}
fn load(root: &Path, id: Uuid) -> io::Result<SandboxSession> {
    let dir = root.join(id.to_string());
    let _locks = piko_win_platform::network_elevation::lock_path_parents(
        &dir.join("input").join("payload.exe"),
    )?;
    let value: SandboxSession = serde_json::from_str(&read_bounded(&dir.join("session.json"))?)
        .map_err(io::Error::other)?;
    if value.id != id
        || value.configuration != dir.join("piko.wsb").to_string_lossy()
        || value.sha256.len() != 64
        || !value.sha256.bytes().all(|b| b.is_ascii_hexdigit())
    {
        return Err(invalid("Manifest Sandbox non valido"));
    }
    Ok(value)
}
pub fn sessions(root: &Path) -> io::Result<Vec<SandboxSession>> {
    let _locks = lock_root(root)?;
    let mut values = Vec::new();
    for entry in fs::read_dir(root)?.take(MAX_SESSIONS + 1) {
        let entry = entry?;
        if values.len() == MAX_SESSIONS {
            return Err(invalid(
                "Archivio Sandbox oltre limite; controllare la cartella",
            ));
        }
        let id = entry
            .file_name()
            .to_string_lossy()
            .parse()
            .map_err(|_| invalid("Elemento inatteso nell’archivio Sandbox"))?;
        values.push(load(root, id)?);
    }
    values.sort_by_key(|v| std::cmp::Reverse(v.created_at));
    Ok(values)
}
fn create_file(path: &Path, bytes: &[u8]) -> io::Result<()> {
    let mut file = OpenOptions::new().write(true).create_new(true).open(path)?;
    file.write_all(bytes)?;
    file.sync_all()
}
impl SandboxController {
    pub fn prepare(&mut self, path: &str) -> io::Result<SandboxPlan> {
        let time = now()?;
        self.plans.retain(|_, p| p.expires_at > time);
        if self.plans.len() >= 8 {
            return Err(invalid("Troppe anteprime Sandbox; attendere cinque minuti"));
        }
        let exe = inspect_executable(path)?;
        let plan = SandboxPlan {
            id: Uuid::new_v4(),
            executable: exe.path,
            sha256: exe.sha256,
            expires_at: time + PLAN_SECONDS,
        };
        self.plans.insert(plan.id, plan.clone());
        Ok(plan)
    }
    pub fn discard(&mut self, id: Uuid) {
        self.plans.remove(&id);
    }
    pub fn create(&mut self, root: &Path, id: Uuid) -> io::Result<SandboxSession> {
        let plan = self
            .plans
            .remove(&id)
            .ok_or_else(|| invalid("Anteprima Sandbox assente o già utilizzata"))?;
        let time = now()?;
        if plan.expires_at <= time || plan.expires_at > time + PLAN_SECONDS {
            return Err(invalid("Anteprima Sandbox scaduta; prepararla di nuovo"));
        }
        let mut exe = inspect_executable(&plan.executable)?;
        if exe.sha256 != plan.sha256 {
            return Err(invalid("Il file è cambiato dopo l’anteprima"));
        }
        let _root = lock_root(root)?;
        if fs::read_dir(root)?.take(MAX_SESSIONS).count() >= MAX_SESSIONS {
            return Err(invalid(
                "Limite di otto sessioni salvate: elimina una sessione prima di continuare",
            ));
        }
        let dir = root.join(id.to_string());
        fs::create_dir(&dir)?;
        let result = (|| {
            let input = dir.join("input");
            fs::create_dir(&input)?;
            let _locks = piko_win_platform::network_elevation::lock_path_parents(
                &input.join("payload.exe"),
            )?;
            let mut target = OpenOptions::new()
                .write(true)
                .create_new(true)
                .open(input.join("payload.exe"))?;
            exe._file.seek(SeekFrom::Start(0))?;
            io::copy(&mut exe._file, &mut target)?;
            target.sync_all()?;
            drop(target);
            let staged = inspect_executable(
                input
                    .join("payload.exe")
                    .to_str()
                    .ok_or_else(|| invalid("Percorso non Unicode"))?,
            )?;
            if staged.sha256 != plan.sha256 {
                return Err(invalid("Verifica della copia Sandbox fallita"));
            }
            let config = dir.join("piko.wsb");
            create_file(&config, configuration(&input)?.as_bytes())?;
            let session = SandboxSession {
                id,
                executable: plan.executable,
                sha256: plan.sha256,
                created_at: time,
                configuration: config.to_string_lossy().into_owned(),
            };
            create_file(
                &dir.join("session.json"),
                &serde_json::to_vec_pretty(&session).map_err(io::Error::other)?,
            )?;
            Ok(session)
        })();
        // An incomplete session is retained for inspection; never traverse a failed path for cleanup.
        result
    }
}
pub fn remove(root: &Path, id: Uuid) -> io::Result<()> {
    let _root = lock_root(root)?;
    let dir = root.join(id.to_string());
    // Reject reparse points before deleting any child. Held handles prevent replacement.
    let locks = piko_win_platform::network_elevation::lock_path_parents(
        &dir.join("input").join("payload.exe"),
    )?;
    for name in [
        dir.join("input").join("payload.exe"),
        dir.join("piko.wsb"),
        dir.join("session.json"),
    ] {
        match fs::remove_file(name) {
            Ok(()) => {}
            Err(e) if e.kind() == io::ErrorKind::NotFound => {}
            Err(e) => return Err(e),
        }
    }
    drop(locks);
    fs::remove_dir(dir.join("input"))?;
    fs::remove_dir(dir)
}
pub fn launch(root: &Path, id: Uuid) -> io::Result<()> {
    let _root = lock_root(root)?;
    let session = load(root, id)?;
    let dir = root.join(id.to_string());
    let staged = inspect_executable(
        dir.join("input")
            .join("payload.exe")
            .to_str()
            .ok_or_else(|| invalid("Percorso non Unicode"))?,
    )?;
    // Never accept arbitrary files in the shared folder, even after user edits on disk.
    let entries = fs::read_dir(dir.join("input"))?
        .take(2)
        .collect::<io::Result<Vec<_>>>()?;
    if entries.len() != 1
        || entries[0].file_name() != "payload.exe"
        || staged.sha256 != session.sha256
    {
        return Err(invalid("La copia Sandbox è cambiata; ricreare la sessione"));
    }
    if read_bounded(&dir.join("piko.wsb"))? != configuration(&dir.join("input"))? {
        return Err(invalid(
            "La configurazione Sandbox è cambiata; ricreare la sessione",
        ));
    }
    // Fixed OS launcher, one path argument, no shell, no automatic target execution.
    Command::new(launcher()?)
        .arg(dir.join("piko.wsb"))
        .spawn()?;
    Ok(()) // Request accepted, not proof of isolation or successful guest startup.
}

#[cfg(test)]
mod tests {
    use super::*;
    fn fixture() -> io::Result<(PathBuf, PathBuf)> {
        let root = std::env::temp_dir().join(format!("piko-sandbox-{}", Uuid::new_v4()));
        fs::create_dir(&root)?;
        let exe = root.join("sample.exe");
        let mut bytes = vec![0u8; 128];
        bytes[..2].copy_from_slice(b"MZ");
        fs::write(&exe, bytes)?;
        Ok((root, exe))
    }
    #[test]
    fn config_disables_exposure_and_escapes_xml() -> io::Result<()> {
        let config = configuration(Path::new(r"C:\a&b\<input>"))?;
        for tag in [
            "vGPU",
            "Networking",
            "AudioInput",
            "VideoInput",
            "PrinterRedirection",
            "ClipboardRedirection",
        ] {
            assert!(config.contains(&format!("<{tag}>Disable</{tag}>")));
        }
        assert!(config.contains("<ReadOnly>true</ReadOnly>"));
        assert!(config.contains("a&amp;b\\&lt;input&gt;"));
        assert!(!config.contains("LogonCommand"));
        assert!(configuration(Path::new(r"C:\%userprofile%\input")).is_err());
        Ok(())
    }
    #[test]
    fn preparation_has_no_effect_and_confirmation_is_single_use() -> io::Result<()> {
        let (root, exe) = fixture()?;
        let store = root.join("sessions");
        let mut controller = SandboxController::default();
        let plan = controller.prepare(exe.to_str().ok_or_else(|| invalid("test"))?)?;
        assert!(!store.exists());
        let session = controller.create(&store, plan.id)?;
        assert_eq!(
            fs::read(store.join(session.id.to_string()).join("input/payload.exe"))?,
            fs::read(&exe)?
        );
        assert_eq!(sessions(&store)?.len(), 1);
        assert!(controller.create(&store, plan.id).is_err());
        remove(&store, session.id)?;
        assert!(sessions(&store)?.is_empty());
        fs::remove_dir_all(root)?;
        Ok(())
    }
    #[test]
    fn changed_source_and_expired_plans_are_rejected() -> io::Result<()> {
        let (root, exe) = fixture()?;
        let store = root.join("sessions");
        let mut controller = SandboxController::default();
        let path = exe.to_str().ok_or_else(|| invalid("test"))?;
        let plan = controller.prepare(path)?;
        let mut changed = fs::read(&exe)?;
        changed[2] = 42;
        fs::write(&exe, changed)?;
        assert!(controller.create(&store, plan.id).is_err());
        assert!(!store.exists());
        let plan = controller.prepare(path)?;
        if let Some(p) = controller.plans.get_mut(&plan.id) {
            p.expires_at = 0;
        }
        assert!(controller.create(&store, plan.id).is_err());
        fs::remove_dir_all(root)?;
        Ok(())
    }
    #[test]
    fn tampered_profile_never_reaches_launcher() -> io::Result<()> {
        let (root, exe) = fixture()?;
        let store = root.join("sessions");
        let mut controller = SandboxController::default();
        let plan = controller.prepare(exe.to_str().ok_or_else(|| invalid("test"))?)?;
        let s = controller.create(&store, plan.id)?;
        fs::write(&s.configuration, "<Configuration/>")?;
        assert!(launch(&store, s.id).is_err());
        remove(&store, s.id)?;
        fs::remove_dir_all(root)?;
        Ok(())
    }
}
