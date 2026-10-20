//! Read-only discovery; metadata is a hint, never executable identity or authorization.
use serde::Serialize;
use std::{
    collections::BTreeSet,
    fs, io,
    os::windows::fs::MetadataExt,
    path::{Path, PathBuf},
    time::{Duration, Instant},
};

#[derive(Debug, Serialize)]
pub struct ExecutableCandidates {
    pub app_id: String,
    pub paths: Vec<String>,
    pub complete: bool,
    pub warnings: Vec<String>,
}

fn icon_path(value: &str) -> Option<String> {
    let value = value.trim();
    let path = if let Some(rest) = value.strip_prefix('"') {
        let end = rest.find('"')?;
        let tail = rest[end + 1..].trim();
        if !tail.is_empty()
            && tail
                .strip_prefix(',')
                .is_none_or(|n| n.trim().parse::<i32>().is_err())
        {
            return None;
        }
        &rest[..end]
    } else if let Some((path, index)) = value.rsplit_once(',') {
        if index.trim().parse::<i32>().is_ok() {
            path.trim()
        } else {
            value
        }
    } else {
        value
    };
    super::validate_path(path).ok()?;
    Some(path.to_string())
}

fn scoped_folder(value: &str) -> Option<PathBuf> {
    let value = value.trim().trim_end_matches('\\');
    super::validate_path(&format!("{value}\\piko-discovery-probe.exe")).ok()?;
    let path = PathBuf::from(value);
    if path.components().count() < 3 {
        return None;
    }
    for key in [
        "ProgramFiles",
        "ProgramFiles(x86)",
        "ProgramData",
        "USERPROFILE",
        "LOCALAPPDATA",
        "APPDATA",
        "PUBLIC",
    ] {
        if std::env::var(key).is_ok_and(|p| p.eq_ignore_ascii_case(value)) {
            return None;
        }
    }
    let windows = piko_win_platform::network_elevation::windows_directory().ok()?;
    if Path::new(&value.to_lowercase()).starts_with(windows.to_string_lossy().to_lowercase()) {
        return None;
    }
    Some(path)
}

pub fn application_executables(app_id: &str) -> io::Result<ExecutableCandidates> {
    if app_id.len() > 8192 {
        return Err(super::invalid("Identificativo applicazione non valido."));
    }
    let snapshot = piko_win_platform::software_inventory::inventory(true)?;
    let app = snapshot
        .entries
        .into_iter()
        .find(|a| a.id == app_id)
        .ok_or_else(|| super::invalid("Applicazione non più presente nell’inventario."))?;
    let mut result = ExecutableCandidates {
        app_id: app_id.into(),
        paths: vec![],
        complete: true,
        warnings: vec![],
    };
    let mut paths = BTreeSet::new();
    if let Some(path) = app.display_icon.as_deref().and_then(icon_path) {
        if fs::symlink_metadata(&path)
            .is_ok_and(|m| m.is_file() && m.file_attributes() & super::REPARSE_POINT == 0)
        {
            paths.insert(path);
        }
    }
    if let Some(folder) = app.install_location.as_deref().and_then(scoped_folder) {
        // Parent locks prevent traversal through pre-existing reparse points. No executable is run.
        match piko_win_platform::network_elevation::lock_path_parents(
            &folder.join("piko-discovery-probe.exe"),
        ) {
            Ok(_locks) => scan(&folder, &mut paths, &mut result),
            Err(_) => {
                result.complete = false;
                result.warnings.push(
                    "Cartella non accessibile o contenente collegamenti: ricerca limitata.".into(),
                );
            }
        }
    } else {
        result.complete = false;
        result.warnings.push("Cartella di installazione assente o troppo generica. Il percorso icona, se presente, è solo un candidato.".into());
    }
    let mut seen = BTreeSet::new();
    result.paths = paths
        .into_iter()
        .filter(|p| seen.insert(p.to_lowercase()))
        .take(32)
        .collect();
    if result.paths.is_empty() {
        result.warnings.push(
            "Nessun eseguibile trovato: usa il percorso manuale o Attività applicazioni.".into(),
        );
    }
    Ok(result)
}

fn scan(root: &Path, paths: &mut BTreeSet<String>, result: &mut ExecutableCandidates) {
    let deadline = Instant::now() + Duration::from_secs(2);
    let mut pending = vec![(root.to_path_buf(), 0)];
    let mut visited = 0;
    while let Some((folder, depth)) = pending.pop() {
        let Ok(_locks) = piko_win_platform::network_elevation::lock_path_parents(
            &folder.join("piko-discovery-probe.exe"),
        ) else {
            result.complete = false;
            continue;
        };
        let Ok(items) = fs::read_dir(folder) else {
            result.complete = false;
            continue;
        };
        for item in items {
            visited += 1;
            if visited > 1024 || paths.len() >= 32 || Instant::now() >= deadline {
                result.complete = false;
                result
                    .warnings
                    .push("Ricerca limitata a 1024 voci, 32 eseguibili e due secondi.".into());
                return;
            }
            let Ok(item) = item else {
                result.complete = false;
                continue;
            };
            let Ok(meta) = fs::symlink_metadata(item.path()) else {
                result.complete = false;
                continue;
            };
            if meta.file_attributes() & super::REPARSE_POINT != 0 {
                result.complete = false;
                continue;
            }
            let path = item.path();
            if meta.is_dir() {
                if depth < 3 {
                    pending.push((path, depth + 1));
                } else {
                    result.complete = false;
                }
            } else if meta.is_file() {
                if let Some(path) = path.to_str().filter(|p| super::validate_path(p).is_ok()) {
                    paths.insert(path.to_string());
                }
            }
        }
    }
    if !result.complete {
        result.warnings.push(
            "Alcune cartelle non sono state lette; copertura degli eseguibili parziale.".into(),
        );
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn discovery_is_bounded_and_does_not_read_or_execute_file_contents() -> io::Result<()> {
        let root =
            std::env::temp_dir().join(format!("piko-discovery-test-{}", uuid::Uuid::new_v4()));
        fs::create_dir(&root)?;
        for i in 0..40 {
            fs::write(root.join(format!("candidate-{i}.exe")), b"not a program")?;
        }
        fs::write(root.join("ignore.txt"), b"ignored")?;
        let mut result = ExecutableCandidates {
            app_id: "test".into(),
            paths: vec![],
            complete: true,
            warnings: vec![],
        };
        let mut paths = BTreeSet::new();
        scan(&root, &mut paths, &mut result);
        assert_eq!(paths.len(), 32);
        assert!(!result.complete);
        assert!(!result.warnings.is_empty());
        assert!(paths
            .iter()
            .all(|p| p.ends_with(".exe") && Path::new(p).starts_with(&root)));
        // Remove only the exact files created by this test, never recurse.
        for i in 0..40 {
            fs::remove_file(root.join(format!("candidate-{i}.exe")))?;
        }
        fs::remove_file(root.join("ignore.txt"))?;
        fs::remove_dir(root)?;
        Ok(())
    }
    #[test]
    fn icon_metadata_never_becomes_a_command() {
        assert_eq!(
            icon_path(r#""C:\Example\app.exe",-2"#),
            Some(r"C:\Example\app.exe".into())
        );
        assert_eq!(
            icon_path(r"C:\Example\app.exe,0"),
            Some(r"C:\Example\app.exe".into())
        );
        for value in [
            r#""C:\Example\app.exe" --run"#,
            r"C:\Example\app.ico",
            r"%TEMP%\app.exe",
            r"\\server\app.exe",
            r"C:\Example\..\app.exe",
        ] {
            assert!(icon_path(value).is_none());
        }
    }
    #[test]
    fn broad_scan_roots_are_rejected() {
        assert!(scoped_folder(r"C:\").is_none());
        if let Ok(root) = std::env::var("ProgramFiles") {
            assert!(scoped_folder(&root).is_none());
        }
        assert!(scoped_folder(r"C:\Example\..\").is_none());
    }
}
