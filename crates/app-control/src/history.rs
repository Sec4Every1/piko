//! Bounded, per-viewer installer-metadata history. Not verified product genealogy.
use piko_win_platform::software_inventory::InventorySnapshot;
use rusqlite::{params, Connection};
use serde::{Deserialize, Serialize};
use std::{
    collections::{BTreeMap, BTreeSet},
    io,
    path::Path,
    time::Duration,
};
const HISTORY_LIMIT: i64 = 2000;
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct SoftwareMetadata {
    pub id: String,
    pub name: String,
    pub publisher: Option<String>,
    pub version: Option<String>,
    pub install_location: Option<String>,
}
#[derive(Serialize)]
pub struct SoftwareChange {
    pub sequence: i64,
    pub observed_at: u64,
    pub kind: String,
    pub before: Option<SoftwareMetadata>,
    pub after: Option<SoftwareMetadata>,
}
#[derive(Serialize)]
pub struct SoftwareHistory {
    pub entries: Vec<SoftwareChange>,
    pub observed_at: u64,
    pub first_observed_at: u64,
    pub inventory_complete: bool,
    pub has_more: bool,
    pub retained_limit: i64,
}
fn err(e: impl std::fmt::Display) -> io::Error {
    io::Error::other(e.to_string())
}
fn open(path: &Path) -> io::Result<Connection> {
    let parent = path
        .parent()
        .ok_or_else(|| err("Missing history directory"))?;
    std::fs::create_dir_all(parent)?;
    let _locks = piko_win_platform::network_elevation::lock_path_parents(path)?;
    if path.exists() {
        use std::os::windows::fs::MetadataExt;
        let m = std::fs::symlink_metadata(path)?;
        if !m.is_file() || m.file_attributes() & 0x400 != 0 || m.len() > 16 * 1024 * 1024 {
            return Err(err("Archivio storico non valido o oltre 16 MiB"));
        }
    }
    let db = Connection::open(path).map_err(err)?;
    let page_size: i64 = db
        .query_row("PRAGMA page_size", [], |r| r.get(0))
        .map_err(err)?;
    if page_size != 4096 {
        return Err(err("Formato pagine storico non supportato"));
    }
    db.busy_timeout(Duration::from_millis(500)).map_err(err)?;
    db.execute_batch("PRAGMA journal_mode=DELETE; PRAGMA synchronous=FULL; PRAGMA max_page_count=4096;
      CREATE TABLE IF NOT EXISTS state(id TEXT PRIMARY KEY, metadata TEXT NOT NULL, present INTEGER NOT NULL);
      CREATE TABLE IF NOT EXISTS history(seq INTEGER PRIMARY KEY AUTOINCREMENT, observed INTEGER NOT NULL, kind TEXT NOT NULL, old TEXT, new TEXT);
      CREATE TABLE IF NOT EXISTS scan(id INTEGER PRIMARY KEY CHECK(id=1), first INTEGER NOT NULL, observed INTEGER NOT NULL, complete INTEGER NOT NULL);").map_err(err)?;
    Ok(db)
}
pub fn observe(
    path: &Path,
    snapshot: &InventorySnapshot,
    time: u64,
    before_sequence: Option<i64>,
) -> io::Result<SoftwareHistory> {
    if time == 0
        || time > 8_640_000_000_000
        || before_sequence.is_some_and(|v| v <= 0)
        || snapshot.entries.len() > 4096
    {
        return Err(err("Richiesta storico non valida"));
    }
    let mut current = BTreeMap::new();
    for app in &snapshot.entries {
        let item = SoftwareMetadata {
            id: app.id.clone(),
            name: app.display_name.clone(),
            publisher: app.publisher.clone(),
            version: app.version.clone(),
            install_location: app.install_location.clone(),
        };
        let json = serde_json::to_string(&item).map_err(err)?;
        if json.len() > 16384
            || app.id.is_empty()
            || current.insert(app.id.clone(), (item, json)).is_some()
        {
            return Err(err("Metadati duplicati o oltre limite"));
        }
    }
    let mut db = open(path)?;
    let tx = db.transaction().map_err(err)?;
    let initialized = tx
        .query_row("SELECT COUNT(*) FROM scan", [], |r| r.get::<_, i64>(0))
        .map_err(err)?
        > 0;
    let mut previous = BTreeMap::new();
    {
        let mut statement = tx
            .prepare("SELECT id,metadata,present FROM state LIMIT 4097")
            .map_err(err)?;
        let rows = statement
            .query_map([], |r| {
                Ok((
                    r.get::<_, String>(0)?,
                    r.get::<_, String>(1)?,
                    r.get::<_, bool>(2)?,
                ))
            })
            .map_err(err)?;
        for row in rows {
            let (id, json, present) = row.map_err(err)?;
            if json.len() > 16384 {
                return Err(err("Metadati storici oltre limite"));
            }
            let item: SoftwareMetadata = serde_json::from_str(&json).map_err(err)?;
            previous.insert(id, (item, json, present));
        }
    }
    let identities = previous
        .keys()
        .chain(current.keys())
        .collect::<BTreeSet<_>>();
    if identities.len() > 4096 {
        return Err(err("Limite di 4096 identità osservate raggiunto"));
    }
    for (id, (item, json)) in &current {
        let old = previous.get(id);
        let kind = match old {
            None if initialized => Some("appeared"),
            Some((_, _, false)) => Some("reappeared"),
            Some((p, _, true)) if p != item => Some(
                if p.version.is_some() && item.version.is_some() && p.version != item.version {
                    "version_changed"
                } else {
                    "metadata_changed"
                },
            ),
            _ => None,
        };
        if let Some(kind) = kind {
            tx.execute(
                "INSERT INTO history(observed,kind,old,new) VALUES(?1,?2,?3,?4)",
                params![time, kind, old.map(|(_, j, _)| j), json],
            )
            .map_err(err)?;
        }
        tx.execute("INSERT INTO state(id,metadata,present) VALUES(?1,?2,1) ON CONFLICT(id) DO UPDATE SET metadata=excluded.metadata,present=1", params![id,json]).map_err(err)?;
    }
    let complete = snapshot.complete && !snapshot.truncated;
    if complete {
        for (id, (_, json, present)) in &previous {
            if *present && !current.contains_key(id) {
                tx.execute(
                    "INSERT INTO history(observed,kind,old,new) VALUES(?1,'disappeared',?2,NULL)",
                    params![time, json],
                )
                .map_err(err)?;
                tx.execute("UPDATE state SET present=0 WHERE id=?1", params![id])
                    .map_err(err)?;
            }
        }
    }
    tx.execute("INSERT INTO scan(id,first,observed,complete) VALUES(1,?1,?1,?2) ON CONFLICT(id) DO UPDATE SET observed=excluded.observed,complete=excluded.complete",params![time,complete]).map_err(err)?;
    tx.execute(
        "DELETE FROM history WHERE seq NOT IN (SELECT seq FROM history ORDER BY seq DESC LIMIT ?1)",
        params![HISTORY_LIMIT],
    )
    .map_err(err)?;
    tx.commit().map_err(err)?;
    let first_observed_at = db
        .query_row("SELECT first FROM scan WHERE id=1", [], |r| r.get(0))
        .map_err(err)?;
    let mut query = db.prepare("SELECT seq,observed,kind,old,new FROM history WHERE (?1 IS NULL OR seq < ?1) ORDER BY seq DESC LIMIT 51").map_err(err)?;
    let rows = query
        .query_map(params![before_sequence], |r| {
            Ok((
                r.get::<_, i64>(0)?,
                r.get::<_, u64>(1)?,
                r.get::<_, String>(2)?,
                r.get::<_, Option<String>>(3)?,
                r.get::<_, Option<String>>(4)?,
            ))
        })
        .map_err(err)?;
    let mut entries = Vec::new();
    for row in rows {
        let (seq, observed_at, kind, old, new) = row.map_err(err)?;
        let parse = |s: Option<String>| -> io::Result<Option<SoftwareMetadata>> {
            s.map(|v| {
                if v.len() > 16384 {
                    return Err(err("Record storico oltre limite"));
                }
                serde_json::from_str(&v).map_err(err)
            })
            .transpose()
        };
        entries.push(SoftwareChange {
            sequence: seq,
            observed_at,
            kind,
            before: parse(old)?,
            after: parse(new)?,
        });
    }
    let has_more = entries.len() > 50;
    entries.truncate(50);
    Ok(SoftwareHistory {
        entries,
        observed_at: time,
        first_observed_at,
        inventory_complete: complete,
        has_more,
        retained_limit: HISTORY_LIMIT,
    })
}
#[cfg(test)]
mod tests {
    use super::*;
    use piko_win_platform::software_inventory::InstalledSoftware;
    fn snapshot(version: Option<&str>) -> InventorySnapshot {
        InventorySnapshot {
            entries: vec![InstalledSoftware {
                id: "test".into(),
                display_name: "Example".into(),
                publisher: None,
                version: version.map(str::to_owned),
                install_location: None,
                install_date: None,
                display_icon: None,
                scope: "user".into(),
                registry_view: "64".into(),
                source: "windows_uninstall_registry".into(),
                uninstall_key: "test".into(),
            }],
            complete: true,
            truncated: false,
            warnings: vec![],
        }
    }
    fn path() -> io::Result<std::path::PathBuf> {
        let root = std::env::temp_dir().join(format!("piko-history-{}", uuid::Uuid::new_v4()));
        std::fs::create_dir(&root)?;
        Ok(root.join("history.sqlite"))
    }
    #[test]
    fn baseline_and_repeated_reads_are_quiet_and_version_changes_survive_reopen() -> io::Result<()>
    {
        let p = path()?;
        assert!(observe(&p, &snapshot(Some("1")), 100, None)?
            .entries
            .is_empty());
        assert!(observe(&p, &snapshot(Some("1")), 101, None)?
            .entries
            .is_empty());
        let changed = observe(&p, &snapshot(Some("2")), 102, None)?;
        assert_eq!(changed.entries[0].kind, "version_changed");
        assert_eq!(changed.first_observed_at, 100);
        assert_eq!(
            observe(&p, &snapshot(Some("2")), 103, None)?.entries.len(),
            1
        );
        std::fs::remove_dir_all(p.parent().ok_or_else(|| err("test"))?)?;
        Ok(())
    }
    #[test]
    fn partial_missing_entries_do_not_imply_removal_and_unknown_version_is_metadata(
    ) -> io::Result<()> {
        let p = path()?;
        observe(&p, &snapshot(Some("1")), 100, None)?;
        let mut missing = snapshot(None);
        missing.entries.clear();
        missing.complete = false;
        assert!(observe(&p, &missing, 101, None)?.entries.is_empty());
        missing.complete = true;
        missing.truncated = true;
        assert!(observe(&p, &missing, 102, None)?.entries.is_empty());
        missing.truncated = false;
        assert_eq!(
            observe(&p, &missing, 103, None)?.entries[0].kind,
            "disappeared"
        );
        assert_eq!(
            observe(&p, &snapshot(None), 104, None)?.entries[0].kind,
            "reappeared"
        );
        assert_eq!(
            observe(&p, &snapshot(Some("3")), 105, None)?.entries[0].kind,
            "metadata_changed"
        );
        std::fs::remove_dir_all(p.parent().ok_or_else(|| err("test"))?)?;
        Ok(())
    }
    #[test]
    fn invalid_duplicate_snapshot_does_not_change_history() -> io::Result<()> {
        let p = path()?;
        observe(&p, &snapshot(Some("1")), 100, None)?;
        let mut bad = snapshot(Some("2"));
        bad.entries.push(bad.entries[0].clone());
        assert!(observe(&p, &bad, 101, None).is_err());
        assert!(observe(&p, &snapshot(Some("1")), 102, None)?
            .entries
            .is_empty());
        std::fs::remove_dir_all(p.parent().ok_or_else(|| err("test"))?)?;
        Ok(())
    }
    #[test]
    fn retention_and_cursor_are_bounded_and_unknown_gaps_are_not_backfilled() -> io::Result<()> {
        let p = path()?;
        let mut scan = snapshot(Some("1"));
        let template = scan.entries[0].clone();
        scan.entries = (0..2060)
            .map(|i| {
                let mut a = template.clone();
                a.id = format!("app-{i}");
                a
            })
            .collect();
        observe(&p, &scan, 100, None)?;
        for app in &mut scan.entries {
            app.version = Some("2".into());
        }
        let first = observe(&p, &scan, 101, None)?;
        assert_eq!(first.entries.len(), 50);
        assert!(first.has_more);
        let last = first.entries.last().ok_or_else(|| err("test"))?.sequence;
        let older = observe(&p, &scan, 102, Some(last))?;
        assert_eq!(older.entries.len(), 50);
        assert!(older.entries.iter().all(|e| e.sequence < last));
        let db = Connection::open(&p).map_err(err)?;
        let count: i64 = db
            .query_row("SELECT COUNT(*) FROM history", [], |r| r.get(0))
            .map_err(err)?;
        assert_eq!(count, 2000);
        drop(db);
        assert!(observe(&p, &scan, 103, Some(0)).is_err());
        std::fs::remove_dir_all(p.parent().ok_or_else(|| err("test"))?)?;
        Ok(())
    }
}
