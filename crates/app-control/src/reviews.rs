//! Per-user manual dispositions. Never changes evidence, detection or score.
use rusqlite::{params, Connection};
use serde::{Deserialize, Serialize};
use std::{io, path::Path, time::Duration};
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ReviewState {
    Open,
    Investigating,
    Expected,
    Handled,
}
#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct AlertReview {
    pub alert_id: String,
    pub state: ReviewState,
    pub note: String,
    pub updated_at: u64,
    pub reviewer_sid: String,
}
fn err(e: impl std::fmt::Display) -> io::Error {
    io::Error::other(e.to_string())
}
fn valid(item: &AlertReview) -> io::Result<()> {
    let Some((rule, id)) = item.alert_id.split_once(':') else {
        return Err(err("Invalid alert ID"));
    };
    if rule.is_empty()
        || rule.len() > 80
        || !rule.bytes().all(|c| c.is_ascii_lowercase() || c == b'-')
        || uuid::Uuid::parse_str(id).is_err()
        || item.note.len() > 1000
        || item
            .note
            .chars()
            .any(|c| c.is_control() && c != '\n' && c != '\t')
        || item.updated_at == 0
        || item.updated_at > 8_640_000_000_000
        || !piko_win_platform::valid_sid_text(&item.reviewer_sid)
    {
        return Err(err("Invalid alert review"));
    }
    Ok(())
}
fn open(path: &Path) -> io::Result<Connection> {
    std::fs::create_dir_all(
        path.parent()
            .ok_or_else(|| err("Missing review directory"))?,
    )?;
    let _locks = piko_win_platform::network_elevation::lock_path_parents(path)?;
    if path.exists() {
        use std::os::windows::fs::MetadataExt;
        let m = std::fs::symlink_metadata(path)?;
        if !m.is_file() || m.file_attributes() & 0x400 != 0 || m.len() > 16 * 1024 * 1024 {
            return Err(err("Invalid review archive"));
        }
    }
    let db = Connection::open(path).map_err(err)?;
    let size: i64 = db
        .query_row("PRAGMA page_size", [], |r| r.get(0))
        .map_err(err)?;
    if size != 4096 {
        return Err(err("Unsupported review page size"));
    }
    db.busy_timeout(Duration::from_millis(500)).map_err(err)?;
    db.execute_batch("PRAGMA journal_mode=DELETE; PRAGMA synchronous=FULL; PRAGMA max_page_count=4096;
CREATE TABLE IF NOT EXISTS reviews(id TEXT PRIMARY KEY,payload TEXT NOT NULL,updated INTEGER NOT NULL);
CREATE INDEX IF NOT EXISTS reviews_updated ON reviews(updated);").map_err(err)?;
    Ok(db)
}
pub fn list(path: &Path) -> io::Result<Vec<AlertReview>> {
    let db = open(path)?;
    let mut query = db
        .prepare("SELECT payload FROM reviews ORDER BY updated DESC,id LIMIT 2000")
        .map_err(err)?;
    let mut out = Vec::new();
    let mut bytes = 0;
    for row in query
        .query_map([], |r| r.get::<_, String>(0))
        .map_err(err)?
    {
        let json = row.map_err(err)?;
        bytes += json.len();
        if bytes > 3 * 1024 * 1024 || json.len() > 4096 {
            return Err(err("Review archive exceeds read limit"));
        }
        let review: AlertReview = serde_json::from_str(&json).map_err(err)?;
        valid(&review)?;
        out.push(review);
    }
    Ok(out)
}
pub fn save(path: &Path, item: AlertReview) -> io::Result<AlertReview> {
    valid(&item)?;
    let mut db = open(path)?;
    let tx = db.transaction().map_err(err)?;
    tx.execute("INSERT INTO reviews(id,payload,updated) VALUES(?1,?2,?3) ON CONFLICT(id) DO UPDATE SET payload=excluded.payload,updated=excluded.updated",params![item.alert_id,serde_json::to_string(&item).map_err(err)?,item.updated_at]).map_err(err)?;
    tx.execute("DELETE FROM reviews WHERE id IN (SELECT id FROM reviews ORDER BY updated DESC,id LIMIT -1 OFFSET 2000)",[]).map_err(err)?;
    tx.commit().map_err(err)?;
    Ok(item)
}
#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn disposition_survives_reopen_and_rejects_invalid_input() -> io::Result<()> {
        let dir = std::env::temp_dir().join(format!("piko-review-test-{}", uuid::Uuid::new_v4()));
        let path = dir.join("reviews.sqlite");
        let mut item = AlertReview {
            alert_id: format!("service-installed:{}", uuid::Uuid::new_v4()),
            state: ReviewState::Expected,
            note: "Aggiornamento autorizzato".into(),
            updated_at: 100,
            reviewer_sid: "S-1-5-21-1-2-3-1000".into(),
        };
        save(&path, item.clone())?;
        assert_eq!(list(&path)?[0].state, ReviewState::Expected);
        item.state = ReviewState::Open;
        item.note.clear();
        item.updated_at = 101;
        save(&path, item.clone())?;
        assert_eq!(list(&path)?.len(), 1);
        assert_eq!(list(&path)?[0].state, ReviewState::Open);
        item.note = "x".repeat(1001);
        assert!(save(&path, item.clone()).is_err());
        assert_eq!(list(&path)?[0].note, "");
        item.note.clear();
        item.alert_id = "invalid".into();
        assert!(save(&path, item).is_err());
        std::fs::remove_file(path)?;
        std::fs::remove_dir(dir)?;
        Ok(())
    }
}
