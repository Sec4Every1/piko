//! Expiring process response plans and an independent per-viewer action journal.
use piko_win_platform::process_control::ProcessTarget;
use rusqlite::{params, Connection};
use serde::{Deserialize, Serialize};
use std::{
    collections::HashMap,
    io,
    path::Path,
    time::{Duration, SystemTime, UNIX_EPOCH},
};
use uuid::Uuid;
#[derive(Clone, Serialize)]
pub struct ProcessPlan {
    pub id: Uuid,
    pub target: ProcessTarget,
    pub expires_at: u64,
}
#[derive(Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ProcessAction {
    pub id: Uuid,
    pub target: ProcessTarget,
    pub requested_at: u64,
    pub completed_at: Option<u64>,
    pub status: String,
    pub detail: String,
}
#[derive(Default)]
pub struct ProcessController {
    plans: HashMap<Uuid, ProcessPlan>,
}
fn now() -> io::Result<u64> {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map_err(io::Error::other)
        .map(|v| v.as_secs())
}
fn err(e: impl std::fmt::Display) -> io::Error {
    io::Error::other(e.to_string())
}
impl ProcessController {
    pub fn prepare(&mut self, pid: u32, creation_filetime: &str) -> io::Result<ProcessPlan> {
        let time = now()?;
        self.plans.retain(|_, p| p.expires_at > time);
        if self.plans.len() >= 8 {
            return Err(err("Too many process previews"));
        }
        if creation_filetime.len() > 20
            || creation_filetime
                .parse::<u64>()
                .ok()
                .filter(|v| *v > 0)
                .is_none()
        {
            return Err(err("Invalid creation identity"));
        }
        let target = piko_win_platform::process_control::preview(pid, creation_filetime)?;
        let plan = ProcessPlan {
            id: Uuid::new_v4(),
            target,
            expires_at: time + 60,
        };
        self.plans.insert(plan.id, plan.clone());
        Ok(plan)
    }
    pub fn discard(&mut self, id: Uuid) {
        self.plans.remove(&id);
    }
    pub fn execute(&mut self, path: &Path, id: Uuid) -> io::Result<ProcessAction> {
        let plan = self
            .plans
            .remove(&id)
            .ok_or_else(|| err("Process preview missing or already consumed"))?;
        let time = now()?;
        if plan.expires_at <= time {
            return Err(err("Process preview expired"));
        }
        let mut action = ProcessAction {
            id,
            target: plan.target,
            requested_at: time,
            completed_at: None,
            status: "executing".into(),
            detail: "Intent committed; termination outcome not yet known".into(),
        };
        save(path, &action)?;
        match piko_win_platform::process_control::terminate(&action.target) {
            Ok(true) => {
                action.status = "terminated".into();
                action.detail = "Windows confirmed exit of the selected instance".into();
            }
            Ok(false) => {
                action.status = "uncertain".into();
                action.detail =
                    "Termination submitted; exit not confirmed within two seconds".into();
            }
            Err(error) => {
                action.status = "failed_or_uncertain".into();
                action.detail = error.to_string().chars().take(1000).collect();
            }
        }
        action.completed_at = Some(now()?);
        save(path, &action)?;
        Ok(action)
    }
}
fn open(path: &Path) -> io::Result<Connection> {
    std::fs::create_dir_all(
        path.parent()
            .ok_or_else(|| err("Missing response directory"))?,
    )?;
    let _locks = piko_win_platform::network_elevation::lock_path_parents(path)?;
    if path.exists() {
        use std::os::windows::fs::MetadataExt;
        let m = std::fs::symlink_metadata(path)?;
        if !m.is_file() || m.file_attributes() & 0x400 != 0 || m.len() > 16 * 1024 * 1024 {
            return Err(err("Invalid process action archive"));
        }
    }
    let db = Connection::open(path).map_err(err)?;
    let page: i64 = db
        .query_row("PRAGMA page_size", [], |r| r.get(0))
        .map_err(err)?;
    if page != 4096 {
        return Err(err("Unsupported action archive page size"));
    }
    db.busy_timeout(Duration::from_millis(500)).map_err(err)?;
    db.execute_batch("PRAGMA journal_mode=DELETE; PRAGMA synchronous=FULL; PRAGMA max_page_count=4096; CREATE TABLE IF NOT EXISTS actions(id TEXT PRIMARY KEY,payload TEXT NOT NULL,requested INTEGER NOT NULL);").map_err(err)?;
    Ok(db)
}
fn save(path: &Path, item: &ProcessAction) -> io::Result<()> {
    let json = serde_json::to_string(item).map_err(err)?;
    if json.len() > 16384 {
        return Err(err("Process action exceeds limit"));
    }
    let mut db = open(path)?;
    let tx = db.transaction().map_err(err)?;
    tx.execute("INSERT INTO actions(id,payload,requested) VALUES(?1,?2,?3) ON CONFLICT(id) DO UPDATE SET payload=excluded.payload",params![item.id.to_string(),json,item.requested_at]).map_err(err)?;
    tx.execute("DELETE FROM actions WHERE id IN (SELECT id FROM actions ORDER BY requested DESC,id LIMIT -1 OFFSET 1000)",[]).map_err(err)?;
    tx.commit().map_err(err)
}
pub fn actions(path: &Path) -> io::Result<Vec<ProcessAction>> {
    let db = open(path)?;
    let mut q = db
        .prepare("SELECT payload FROM actions ORDER BY requested DESC,id LIMIT 50")
        .map_err(err)?;
    let mut out = Vec::new();
    for row in q.query_map([], |r| r.get::<_, String>(0)).map_err(err)? {
        let payload = row.map_err(err)?;
        if payload.len() > 16384 {
            return Err(err("Action payload exceeds limit"));
        }
        let mut value: ProcessAction = serde_json::from_str(&payload).map_err(err)?;
        if value.status == "executing" {
            value.status = "uncertain".into();
            value.detail =
                "Interruption after intent; outcome unknown, never automatically retried".into();
        }
        out.push(value);
    }
    Ok(out)
}
#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn persisted_intent_is_uncertain_after_interruption() -> io::Result<()> {
        let dir = std::env::temp_dir().join(format!("piko-process-actions-{}", Uuid::new_v4()));
        let path = dir.join("actions.sqlite");
        let item = ProcessAction {
            id: Uuid::new_v4(),
            target: ProcessTarget {
                pid: 99,
                creation_filetime: "123".into(),
                executable: r"C:\example\example.exe".into(),
                name: "example.exe".into(),
                sid: "S-1-5-21-1-2-3-1000".into(),
                session_id: 1,
            },
            requested_at: 100,
            completed_at: None,
            status: "executing".into(),
            detail: "intent".into(),
        };
        save(&path, &item)?;
        assert_eq!(actions(&path)?[0].status, "uncertain");
        std::fs::remove_file(path)?;
        std::fs::remove_dir(dir)?;
        Ok(())
    }
}
