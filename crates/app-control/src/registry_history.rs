//! Per-viewer history of observed startup values; no author/process attribution or registry writes.
use piko_win_platform::registry_history::{
    scope_ids, RegistryScope, RegistrySnapshot, RegistryValue,
};
use rusqlite::{params, Connection};
use serde::{Deserialize, Serialize};
use std::{
    collections::{BTreeMap, BTreeSet},
    io,
    path::Path,
    time::Duration,
};
#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct RegistryChange {
    pub sequence: i64,
    pub observed_at: u64,
    pub kind: String,
    pub before: Option<RegistryValue>,
    pub after: Option<RegistryValue>,
}
#[derive(Serialize)]
pub struct RegistryHistory {
    pub entries: Vec<RegistryChange>,
    pub scopes: Vec<RegistryScope>,
    pub observed_at: u64,
    pub first_observed_at: u64,
    pub has_more: bool,
    pub retained_limit: u32,
}
fn err(e: impl std::fmt::Display) -> io::Error {
    io::Error::other(e.to_string())
}
fn open(path: &Path) -> io::Result<Connection> {
    std::fs::create_dir_all(
        path.parent()
            .ok_or_else(|| err("Missing history directory"))?,
    )?;
    let _locks = piko_win_platform::network_elevation::lock_path_parents(path)?;
    if path.exists() {
        use std::os::windows::fs::MetadataExt;
        let m = std::fs::symlink_metadata(path)?;
        if !m.is_file() || m.file_attributes() & 0x400 != 0 || m.len() > 16 * 1024 * 1024 {
            return Err(err("Invalid registry history archive"));
        }
    }
    let db = Connection::open(path).map_err(err)?;
    let pages: i64 = db
        .query_row("PRAGMA page_size", [], |r| r.get(0))
        .map_err(err)?;
    if pages != 4096 {
        return Err(err("Unsupported archive pages"));
    }
    db.busy_timeout(Duration::from_millis(500)).map_err(err)?;
    db.execute_batch("PRAGMA journal_mode=DELETE; PRAGMA synchronous=FULL; PRAGMA max_page_count=4096; CREATE TABLE IF NOT EXISTS state(scope TEXT NOT NULL,name TEXT NOT NULL,payload TEXT NOT NULL,present INTEGER NOT NULL,PRIMARY KEY(scope,name)); CREATE TABLE IF NOT EXISTS changes(seq INTEGER PRIMARY KEY AUTOINCREMENT,observed INTEGER NOT NULL,kind TEXT NOT NULL,old TEXT,new TEXT); CREATE TABLE IF NOT EXISTS scan(id INTEGER PRIMARY KEY CHECK(id=1),first INTEGER NOT NULL,observed INTEGER NOT NULL);").map_err(err)?;
    Ok(db)
}
pub fn observe(
    path: &Path,
    snapshot: &RegistrySnapshot,
    time: u64,
    before_sequence: Option<i64>,
) -> io::Result<RegistryHistory> {
    if time == 0
        || time > 8640000000000
        || before_sequence.is_some_and(|v| v <= 0)
        || snapshot.scopes.len() != 8
        || snapshot.values.len() > 1024
    {
        return Err(err("Invalid registry snapshot bounds"));
    }
    let expected = scope_ids().into_iter().collect::<BTreeSet<_>>();
    let scopes = snapshot
        .scopes
        .iter()
        .map(|s| s.id.clone())
        .collect::<BTreeSet<_>>();
    if scopes != expected
        || snapshot
            .scopes
            .iter()
            .any(|s| s.warnings.len() > 8 || s.warnings.iter().any(|w| w.len() > 4096))
    {
        return Err(err("Invalid registry scopes"));
    }
    let mut current = BTreeMap::new();
    let mut total = 0;
    for v in &snapshot.values {
        if !scopes.contains(&v.scope_id)
            || v.value_name.len() > 2048
            || v.data_hex.len() > 4096
            || !v.data_hex.len().is_multiple_of(2)
            || !v.data_hex.bytes().all(|b| b.is_ascii_hexdigit())
            || v.text.as_ref().is_some_and(|s| s.len() > 4096)
        {
            return Err(err("Invalid registry value"));
        }
        let json = serde_json::to_string(v).map_err(err)?;
        total += json.len();
        if total > 512 * 1024
            || current
                .insert(
                    (v.scope_id.clone(), v.value_name.clone()),
                    (v.clone(), json),
                )
                .is_some()
        {
            return Err(err("Duplicate or oversized snapshot"));
        }
    }
    let mut db = open(path)?;
    let tx = db.transaction().map_err(err)?;
    let initialized: bool = tx
        .query_row("SELECT COUNT(*)>0 FROM scan", [], |r| r.get(0))
        .map_err(err)?;
    let mut previous = BTreeMap::new();
    {
        let mut q = tx
            .prepare("SELECT scope,name,payload,present FROM state LIMIT 1025")
            .map_err(err)?;
        for row in q
            .query_map([], |r| {
                Ok((
                    r.get::<_, String>(0)?,
                    r.get::<_, String>(1)?,
                    r.get::<_, String>(2)?,
                    r.get::<_, bool>(3)?,
                ))
            })
            .map_err(err)?
        {
            let (scope, name, json, present) = row.map_err(err)?;
            if json.len() > 16384 {
                return Err(err("Stored payload exceeds bound"));
            }
            let value: RegistryValue = serde_json::from_str(&json).map_err(err)?;
            if value.scope_id != scope
                || value.value_name != name
                || !expected.contains(&scope)
                || value.data_hex.len() > 4096
                || !value.data_hex.len().is_multiple_of(2)
                || !value.data_hex.bytes().all(|b| b.is_ascii_hexdigit())
                || name.len() > 2048
                || value.text.as_ref().is_some_and(|s| s.len() > 4096)
            {
                return Err(err("Invalid stored registry identity"));
            }
            previous.insert((scope, name), (value, json, present));
        }
    }
    if previous.len() > 1024
        || previous
            .keys()
            .chain(current.keys())
            .collect::<BTreeSet<_>>()
            .len()
            > 1024
    {
        return Err(err("Registry identity budget exhausted"));
    }
    for ((scope, name), (value, json)) in &current {
        let old = previous.get(&(scope.clone(), name.clone()));
        let changed = old.is_some_and(|(v, _, present)| v != value || !*present);
        if initialized && (old.is_none() || changed) {
            let kind = if old.is_none() {
                "appeared"
            } else if old.is_some_and(|(_, _, p)| !*p) {
                "reappeared"
            } else {
                "changed"
            };
            tx.execute(
                "INSERT INTO changes(observed,kind,old,new) VALUES(?1,?2,?3,?4)",
                params![time, kind, old.map(|(_, j, _)| j), json],
            )
            .map_err(err)?;
        }
        tx.execute("INSERT INTO state(scope,name,payload,present) VALUES(?1,?2,?3,1) ON CONFLICT(scope,name) DO UPDATE SET payload=excluded.payload,present=1",params![scope,name,json]).map_err(err)?;
    }
    let complete = snapshot
        .scopes
        .iter()
        .filter(|s| s.complete)
        .map(|s| &s.id)
        .collect::<BTreeSet<_>>();
    if initialized {
        for ((scope, name), (_, json, present)) in &previous {
            if *present
                && complete.contains(scope)
                && !current.contains_key(&(scope.clone(), name.clone()))
            {
                tx.execute(
                    "INSERT INTO changes(observed,kind,old,new) VALUES(?1,'not_observed',?2,NULL)",
                    params![time, json],
                )
                .map_err(err)?;
                tx.execute(
                    "UPDATE state SET present=0 WHERE scope=?1 AND name=?2",
                    params![scope, name],
                )
                .map_err(err)?;
            }
        }
    }
    tx.execute("INSERT INTO scan(id,first,observed) VALUES(1,?1,?1) ON CONFLICT(id) DO UPDATE SET observed=excluded.observed",[time]).map_err(err)?;
    tx.execute("DELETE FROM changes WHERE seq IN (SELECT seq FROM changes ORDER BY seq DESC LIMIT -1 OFFSET 500)",[]).map_err(err)?;
    tx.commit().map_err(err)?;
    let first = db
        .query_row("SELECT first FROM scan WHERE id=1", [], |r| r.get(0))
        .map_err(err)?;
    let mut q=db.prepare("SELECT seq,observed,kind,old,new FROM changes WHERE (?1 IS NULL OR seq<?1) ORDER BY seq DESC LIMIT 51").map_err(err)?;
    let mut entries = Vec::new();
    for row in q
        .query_map([before_sequence], |r| {
            Ok((
                r.get(0)?,
                r.get(1)?,
                r.get(2)?,
                r.get::<_, Option<String>>(3)?,
                r.get::<_, Option<String>>(4)?,
            ))
        })
        .map_err(err)?
    {
        let (seq, observed_at, kind, old, new) = row.map_err(err)?;
        let parse = |j: Option<String>| -> io::Result<Option<RegistryValue>> {
            j.map(|s| {
                if s.len() > 16384 {
                    return Err(err("History payload exceeds bound"));
                }
                serde_json::from_str(&s).map_err(err)
            })
            .transpose()
        };
        entries.push(RegistryChange {
            sequence: seq,
            observed_at,
            kind,
            before: parse(old)?,
            after: parse(new)?,
        });
    }
    let has_more = entries.len() > 50;
    entries.truncate(50);
    Ok(RegistryHistory {
        entries,
        scopes: snapshot.scopes.clone(),
        observed_at: time,
        first_observed_at: first,
        has_more,
        retained_limit: 500,
    })
}
#[cfg(test)]
mod tests {
    use super::*;
    use uuid::Uuid;
    fn sample(text: &str) -> RegistrySnapshot {
        RegistrySnapshot {
            scopes: scope_ids()
                .into_iter()
                .map(|id| RegistryScope {
                    id,
                    complete: true,
                    warnings: Vec::new(),
                })
                .collect(),
            values: vec![RegistryValue {
                scope_id: scope_ids()[0].clone(),
                value_name: "Test".into(),
                value_type: 1,
                data_hex: text.as_bytes().iter().map(|b| format!("{b:02x}")).collect(),
                text: Some(text.into()),
            }],
        }
    }
    #[test]
    fn observed_a_b_a_and_partial_absence_preserve_history() -> io::Result<()> {
        let dir = std::env::temp_dir().join(format!("piko-registry-{}", Uuid::new_v4()));
        let p = dir.join("history.sqlite");
        assert!(observe(&p, &sample("A"), 1, None)?.entries.is_empty());
        assert_eq!(observe(&p, &sample("B"), 2, None)?.entries.len(), 1);
        let result = observe(&p, &sample("A"), 3, None)?;
        assert_eq!(
            result.entries[0].before.as_ref().map(|x| x.text.as_deref()),
            Some(Some("B"))
        );
        assert_eq!(
            result.entries[0].after.as_ref().map(|x| x.text.as_deref()),
            Some(Some("A"))
        );
        let mut partial = sample("A");
        partial.values.clear();
        partial.scopes[0].complete = false;
        assert_eq!(observe(&p, &partial, 4, None)?.entries.len(), 2);
        partial.scopes[0].complete = true;
        assert_eq!(
            observe(&p, &partial, 5, None)?.entries[0].kind,
            "not_observed"
        );
        assert_eq!(
            observe(&p, &sample("A"), 6, None)?.entries[0].kind,
            "reappeared"
        );
        std::fs::remove_file(p)?;
        std::fs::remove_dir(dir)?;
        Ok(())
    }
    #[test]
    fn invalid_duplicate_and_changed_types_are_explicit() -> io::Result<()> {
        let dir = std::env::temp_dir().join(format!("piko-registry-{}", Uuid::new_v4()));
        let p = dir.join("history.sqlite");
        let mut a = sample("A");
        observe(&p, &a, 1, None)?;
        a.values[0].value_type = 2;
        assert_eq!(observe(&p, &a, 2, None)?.entries[0].kind, "changed");
        a.values.push(a.values[0].clone());
        assert!(observe(&p, &a, 3, None).is_err());
        std::fs::remove_file(p)?;
        std::fs::remove_dir(dir)?;
        Ok(())
    }
}
