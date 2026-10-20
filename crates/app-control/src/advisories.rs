//! Offline advisory matching. Product/version bindings are manual declarations, never name guesses.
use piko_win_platform::software_inventory::{InstalledSoftware, InventorySnapshot};
use rusqlite::{params, Connection};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use std::{
    collections::HashSet,
    fs::File,
    io,
    os::windows::fs::{MetadataExt, OpenOptionsExt},
    path::Path,
    time::Duration,
};

pub const MAX_FEED_BYTES: usize = 1024 * 1024;
const MAX_BINDINGS: usize = 512;
const MAX_ARCHIVE_BYTES: u64 = 16 * 1024 * 1024;
#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Product {
    pub product_id: String,
    pub display_name: String,
    pub covered_versions: Vec<String>,
}
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum AdvisoryKind {
    Vulnerability,
    EndOfSupport,
}
#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Advisory {
    pub id: String,
    pub product_id: String,
    pub affected_versions: Vec<String>,
    pub kind: AdvisoryKind,
    pub title: String,
    pub summary: String,
    /// Source-declared CVSS score * 100 (0..1000), not an exploit probability.
    pub cvss_x100: Option<u16>,
    pub cvss_version: Option<String>,
    pub cvss_vector: Option<String>,
    pub source_url: String,
    pub published_at: u64,
    pub remediation: Vec<String>,
}
#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct AdvisoryFeed {
    pub schema_version: u32,
    pub source_name: String,
    pub source_url: String,
    pub generated_at: u64,
    pub expires_at: u64,
    pub products: Vec<Product>,
    pub advisories: Vec<Advisory>,
}
#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ProductBinding {
    pub application_id: String,
    pub application_name: String,
    pub publisher: Option<String>,
    pub installer_version: Option<String>,
    pub product_id: String,
    pub exact_version: String,
    pub bound_at: u64,
}
#[derive(Clone, Debug, Serialize)]
pub struct FeedStatus {
    pub source_name: String,
    pub source_url: String,
    pub generated_at: u64,
    pub expires_at: u64,
    pub imported_at: u64,
    pub sha256: String,
    pub advisory_count: usize,
    pub product_count: usize,
    pub products: Vec<Product>,
    pub stale: bool,
    pub authenticity: &'static str,
}
#[derive(Clone, Debug, PartialEq, Eq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum MatchState {
    Matched,
    NoKnownAdvisory,
    ProductNotCovered,
    VersionNotCovered,
    MetadataChanged,
    NotObserved,
    NoFeed,
}
#[derive(Clone, Debug, Serialize)]
pub struct ApplicationAssessment {
    pub binding: ProductBinding,
    pub state: MatchState,
    pub advisory_count: usize,
}
#[derive(Clone, Debug, Serialize)]
pub struct AdvisorySnapshot {
    pub checked_at: u64,
    pub inventory_complete: bool,
    pub unbound_count: usize,
    pub feed: Option<FeedStatus>,
    pub entries: Vec<ApplicationAssessment>,
    pub advisories: Vec<Advisory>,
}
fn err(message: impl std::fmt::Display) -> io::Error {
    io::Error::new(io::ErrorKind::InvalidData, message.to_string())
}
fn text(value: &str, max: usize) -> bool {
    !value.is_empty()
        && value.len() <= max
        && value.trim() == value
        && !value.chars().any(|c| {
            c.is_control() || matches!(c, '\u{202a}'..='\u{202e}' | '\u{2066}'..='\u{2069}')
        })
}
fn identifier(value: &str) -> bool {
    text(value, 120)
        && value
            .bytes()
            .all(|c| c.is_ascii_alphanumeric() || b"-_.:".contains(&c))
}
fn version(value: &str) -> bool {
    text(value, 80)
        && value
            .bytes()
            .all(|c| c.is_ascii_alphanumeric() || b"-_.+".contains(&c))
}
fn timestamp(value: u64) -> bool {
    value > 0 && value <= 8_640_000_000
}
/// Narrow HTTPS syntax: no credentials, IPs, ports, fragments, escapes or ambiguous authorities.
pub fn valid_source_url(value: &str) -> bool {
    if !text(value, 2048)
        || !value.is_ascii()
        || value.contains(['\\', '%', '#', '"', '<', '>', '`'])
    {
        return false;
    }
    let Some(tail) = value.strip_prefix("https://") else {
        return false;
    };
    let host = tail.split('/').next().unwrap_or("");
    if host.len() > 253
        || !host.contains('.')
        || host.bytes().all(|c| c.is_ascii_digit() || c == b'.')
    {
        return false;
    }
    host.split('.').all(|part| {
        !part.is_empty()
            && part.len() <= 63
            && !part.starts_with('-')
            && !part.ends_with('-')
            && part.bytes().all(|c| c.is_ascii_alphanumeric() || c == b'-')
    }) && tail.bytes().all(|c| (0x21..=0x7e).contains(&c))
}
pub fn parse_feed(json: &str, current: u64) -> io::Result<AdvisoryFeed> {
    if json.is_empty() || json.len() > MAX_FEED_BYTES || !timestamp(current) {
        return Err(err("Feed oltre 1 MiB o data non valida."));
    }
    let feed: AdvisoryFeed = serde_json::from_str(json).map_err(err)?;
    validate_feed(&feed, current)?;
    Ok(feed)
}
fn validate_feed(feed: &AdvisoryFeed, current: u64) -> io::Result<()> {
    if feed.schema_version != 1
        || !text(&feed.source_name, 120)
        || !valid_source_url(&feed.source_url)
        || !timestamp(feed.generated_at)
        || !timestamp(feed.expires_at)
        || feed.generated_at > current.saturating_add(300)
        || feed.expires_at <= feed.generated_at
        || feed.expires_at - feed.generated_at > 90 * 86400
        || feed.products.is_empty()
        || feed.products.len() > 256
        || feed.advisories.len() > 1000
    {
        return Err(err("Schema, fonte, scadenza o limiti del feed non validi."));
    }
    let mut products = HashSet::new();
    for p in &feed.products {
        if !identifier(&p.product_id)
            || !text(&p.display_name, 160)
            || !products.insert(&p.product_id)
            || p.covered_versions.is_empty()
            || p.covered_versions.len() > 100
        {
            return Err(err("Prodotto del feed non valido o duplicato."));
        }
        let mut versions = HashSet::new();
        if p.covered_versions
            .iter()
            .any(|v| !version(v) || !versions.insert(v))
        {
            return Err(err("Versioni esatte non valide o duplicate."));
        }
    }
    let mut ids = HashSet::new();
    for a in &feed.advisories {
        let product = feed
            .products
            .iter()
            .find(|p| p.product_id == a.product_id)
            .ok_or_else(|| err("Advisory riferito a un prodotto non dichiarato."))?;
        let mut versions = HashSet::new();
        if !identifier(&a.id)
            || !ids.insert(&a.id)
            || !text(&a.title, 160)
            || !text(&a.summary, 1000)
            || !valid_source_url(&a.source_url)
            || !timestamp(a.published_at)
            || a.published_at > feed.generated_at
            || !valid_cvss(a)
            || (a.kind == AdvisoryKind::EndOfSupport && a.cvss_x100.is_some())
            || a.affected_versions.is_empty()
            || a.affected_versions.len() > 100
            || a.affected_versions.iter().any(|v| {
                !version(v) || !versions.insert(v) || !product.covered_versions.contains(v)
            })
            || a.remediation.is_empty()
            || a.remediation.len() > 8
            || a.remediation.iter().any(|v| !text(v, 512))
        {
            return Err(err("Advisory non valido, duplicato o fuori copertura."));
        }
    }
    Ok(())
}
fn valid_cvss(a: &Advisory) -> bool {
    match (&a.cvss_x100, &a.cvss_version, &a.cvss_vector) {
        (None, None, None) => true,
        (Some(score), Some(version), Some(vector)) => {
            *score <= 1000
                && score.is_multiple_of(10)
                && matches!(version.as_str(), "3.0" | "3.1" | "4.0")
                && text(vector, 512)
                && vector.starts_with(&format!("CVSS:{version}/"))
                && vector.split('/').skip(1).count() <= 32
                && vector.split('/').skip(1).all(|metric| {
                    metric.split_once(':').is_some_and(|(name, value)| {
                        !name.is_empty()
                            && !value.is_empty()
                            && name.bytes().all(|c| c.is_ascii_alphanumeric())
                            && value.bytes().all(|c| c.is_ascii_alphanumeric())
                    })
                })
        }
        _ => false,
    }
}
fn validate_binding(item: &ProductBinding) -> io::Result<()> {
    if !text(&item.application_id, 2048)
        || !text(&item.application_name, 2048)
        || item.publisher.as_ref().is_some_and(|v| !text(v, 2048))
        || item
            .installer_version
            .as_ref()
            .is_some_and(|v| !text(v, 2048))
        || !identifier(&item.product_id)
        || !version(&item.exact_version)
        || !timestamp(item.bound_at)
    {
        return Err(err("Associazione prodotto/versione non valida."));
    }
    Ok(())
}
struct Store {
    db: Connection,
    _parents: Vec<File>,
    _file: File,
}
fn validate_archive(path: &Path) -> io::Result<()> {
    match std::fs::symlink_metadata(path) {
        Ok(m)
            if !m.is_file() || m.file_attributes() & 0x400 != 0 || m.len() > MAX_ARCHIVE_BYTES =>
        {
            Err(err("Archivio advisory non regolare o oltre 16 MiB."))
        }
        Ok(_) => Ok(()),
        Err(e) if e.kind() == io::ErrorKind::NotFound => Ok(()),
        Err(e) => Err(e),
    }
}
fn open(path: &Path) -> io::Result<Store> {
    let parent = path
        .parent()
        .ok_or_else(|| err("Cartella advisory assente."))?;
    // Reject existing redirected ancestors before creating a missing per-user directory.
    for ancestor in parent.ancestors() {
        if let Ok(m) = std::fs::symlink_metadata(ancestor) {
            if !m.is_dir() || m.file_attributes() & 0x400 != 0 {
                return Err(err("Cartella advisory reindirizzata."));
            }
        }
    }
    std::fs::create_dir_all(parent)?;
    let parents = piko_win_platform::network_elevation::lock_path_parents(path)?;
    validate_archive(path)?;
    let journal = path.with_file_name(format!(
        "{}-journal",
        path.file_name()
            .ok_or_else(|| err("Nome archivio assente."))?
            .to_string_lossy()
    ));
    validate_archive(&journal)?;
    // Lock the file before SQLite resolves its name. Reject a redirected or oversized
    // file using handle metadata as well as the earlier name check.
    let file = match std::fs::OpenOptions::new()
        .write(true)
        .create_new(true)
        .share_mode(3)
        .custom_flags(0x00200000)
        .open(path)
    {
        Ok(file) => file,
        Err(e) if e.kind() == io::ErrorKind::AlreadyExists => std::fs::OpenOptions::new()
            .access_mode(0x80)
            .share_mode(3)
            .custom_flags(0x00200000)
            .open(path)?,
        Err(e) => return Err(e),
    };
    let metadata = file.metadata()?;
    if !metadata.is_file()
        || metadata.file_attributes() & 0x400 != 0
        || metadata.len() > MAX_ARCHIVE_BYTES
    {
        return Err(err("Archivio advisory reindirizzato o oltre il limite."));
    }
    for suffix in ["-wal", "-shm"] {
        let sidecar = path.with_file_name(format!(
            "{}{suffix}",
            path.file_name()
                .ok_or_else(|| err("Nome archivio assente."))?
                .to_string_lossy()
        ));
        match std::fs::symlink_metadata(sidecar) {
            Ok(_) => return Err(err("Archivio advisory con sidecar WAL inatteso.")),
            Err(e) if e.kind() == io::ErrorKind::NotFound => {}
            Err(e) => return Err(e),
        }
    }
    let db = Connection::open(path).map_err(err)?;
    let page_size: i64 = db
        .query_row("PRAGMA page_size", [], |r| r.get(0))
        .map_err(err)?;
    if page_size != 4096 {
        return Err(err("Dimensione pagina advisory non supportata."));
    }
    db.busy_timeout(Duration::from_millis(500)).map_err(err)?;
    db.execute_batch("PRAGMA journal_mode=DELETE; PRAGMA synchronous=FULL; PRAGMA max_page_count=4096;
CREATE TABLE IF NOT EXISTS advisory_feed(singleton INTEGER PRIMARY KEY CHECK(singleton=1),payload TEXT NOT NULL,sha256 TEXT NOT NULL,imported INTEGER NOT NULL);
CREATE TABLE IF NOT EXISTS advisory_bindings(id TEXT PRIMARY KEY,payload TEXT NOT NULL);").map_err(err)?;
    Ok(Store {
        db,
        _parents: parents,
        _file: file,
    })
}
pub fn import_feed(path: &Path, json: &str, current: u64) -> io::Result<()> {
    let feed = parse_feed(json, current)?;
    let canonical = serde_json::to_string(&feed).map_err(err)?;
    let mut store = open(path)?;
    let tx = store.db.transaction().map_err(err)?;
    tx.execute("INSERT INTO advisory_feed VALUES(1,?1,?2,?3) ON CONFLICT(singleton) DO UPDATE SET payload=excluded.payload,sha256=excluded.sha256,imported=excluded.imported", params![canonical, format!("{:x}", Sha256::digest(canonical.as_bytes())), current]).map_err(err)?;
    tx.commit().map_err(err)?;
    Ok(())
}
pub fn bind(
    path: &Path,
    application: &InstalledSoftware,
    product_id: &str,
    exact_version: &str,
    current: u64,
) -> io::Result<()> {
    let item = ProductBinding {
        application_id: application.id.clone(),
        application_name: application.display_name.clone(),
        publisher: application.publisher.clone(),
        installer_version: application.version.clone(),
        product_id: product_id.into(),
        exact_version: exact_version.into(),
        bound_at: current,
    };
    validate_binding(&item)?;
    let mut store = open(path)?;
    let tx = store.db.transaction().map_err(err)?;
    let count: i64 = tx
        .query_row(
            "SELECT count(*) FROM advisory_bindings WHERE id != ?1",
            [&item.application_id],
            |r| r.get(0),
        )
        .map_err(err)?;
    if count >= MAX_BINDINGS as i64 {
        return Err(err("Limite di 512 associazioni raggiunto."));
    }
    tx.execute("INSERT INTO advisory_bindings VALUES(?1,?2) ON CONFLICT(id) DO UPDATE SET payload=excluded.payload", params![item.application_id, serde_json::to_string(&item).map_err(err)?]).map_err(err)?;
    tx.commit().map_err(err)?;
    Ok(())
}
pub fn unbind(path: &Path, application_id: &str) -> io::Result<()> {
    if !text(application_id, 2048) {
        return Err(err("Identità applicazione non valida."));
    }
    open(path)?
        .db
        .execute(
            "DELETE FROM advisory_bindings WHERE id=?1",
            [application_id],
        )
        .map_err(err)?;
    Ok(())
}
fn assess(
    binding: ProductBinding,
    feed: Option<&AdvisoryFeed>,
    inventory: &InventorySnapshot,
) -> ApplicationAssessment {
    let state = match inventory
        .entries
        .iter()
        .find(|a| a.id == binding.application_id)
    {
        None => MatchState::NotObserved,
        Some(a)
            if a.version != binding.installer_version
                || a.display_name != binding.application_name
                || a.publisher != binding.publisher =>
        {
            MatchState::MetadataChanged
        }
        Some(_) => match feed {
            None => MatchState::NoFeed,
            Some(f) => match f
                .products
                .iter()
                .find(|p| p.product_id == binding.product_id)
            {
                None => MatchState::ProductNotCovered,
                Some(p) if !p.covered_versions.contains(&binding.exact_version) => {
                    MatchState::VersionNotCovered
                }
                Some(_) => MatchState::NoKnownAdvisory,
            },
        },
    };
    let advisory_count = if state == MatchState::NoKnownAdvisory {
        feed.into_iter()
            .flat_map(|f| &f.advisories)
            .filter(|a| {
                a.product_id == binding.product_id
                    && a.affected_versions.contains(&binding.exact_version)
            })
            .count()
    } else {
        0
    };
    ApplicationAssessment {
        binding,
        state: if advisory_count == 0 {
            state
        } else {
            MatchState::Matched
        },
        advisory_count,
    }
}
pub fn snapshot(
    path: &Path,
    inventory: &InventorySnapshot,
    current: u64,
) -> io::Result<AdvisorySnapshot> {
    if !timestamp(current) {
        return Err(err("Data advisory non valida."));
    }
    let store = open(path)?;
    let mut feed_query = store
        .db
        .prepare("SELECT payload,sha256,imported FROM advisory_feed WHERE singleton=1")
        .map_err(err)?;
    let mut rows = feed_query.query([]).map_err(err)?;
    let (feed, status) = if let Some(row) = rows.next().map_err(err)? {
        let bytes: i64 = store
            .db
            .query_row(
                "SELECT length(CAST(payload AS BLOB)) FROM advisory_feed WHERE singleton=1",
                [],
                |r| r.get(0),
            )
            .map_err(err)?;
        if bytes < 0 || bytes > MAX_FEED_BYTES as i64 {
            return Err(err("Feed archiviato oltre il limite."));
        }
        let json: String = row.get(0).map_err(err)?;
        let hash: String = row.get(1).map_err(err)?;
        if hash != format!("{:x}", Sha256::digest(json.as_bytes())) {
            return Err(err("Feed archiviato alterato rispetto al digest locale."));
        }
        let feed = parse_feed(&json, current)?;
        let imported_at: u64 = row.get(2).map_err(err)?;
        if !timestamp(imported_at) {
            return Err(err("Data importazione non valida."));
        }
        let status = FeedStatus {
            source_name: feed.source_name.clone(),
            source_url: feed.source_url.clone(),
            generated_at: feed.generated_at,
            expires_at: feed.expires_at,
            imported_at,
            sha256: hash,
            advisory_count: feed.advisories.len(),
            product_count: feed.products.len(),
            products: feed.products.clone(),
            stale: current >= feed.expires_at,
            authenticity: "not_verified",
        };
        (Some(feed), Some(status))
    } else {
        (None, None)
    };
    let mut query = store.db.prepare("SELECT id,length(CAST(payload AS BLOB)),payload FROM advisory_bindings ORDER BY id LIMIT 513").map_err(err)?;
    let mut rows = query.query([]).map_err(err)?;
    let mut entries = Vec::new();
    while let Some(row) = rows.next().map_err(err)? {
        let size: i64 = row.get(1).map_err(err)?;
        if entries.len() >= MAX_BINDINGS || !(1..=16384).contains(&size) {
            return Err(err("Associazioni archiviate oltre il limite."));
        }
        let binding: ProductBinding =
            serde_json::from_str(&row.get::<_, String>(2).map_err(err)?).map_err(err)?;
        validate_binding(&binding)?;
        if binding.application_id != row.get::<_, String>(0).map_err(err)? {
            return Err(err("Identità associazione incoerente."));
        }
        entries.push(assess(binding, feed.as_ref(), inventory));
    }
    let unbound_count = inventory
        .entries
        .iter()
        .filter(|a| !entries.iter().any(|e| e.binding.application_id == a.id))
        .count();
    entries.sort_by(|a, b| {
        b.advisory_count.cmp(&a.advisory_count).then_with(|| {
            a.binding
                .application_name
                .to_lowercase()
                .cmp(&b.binding.application_name.to_lowercase())
        })
    });
    Ok(AdvisorySnapshot {
        checked_at: current,
        inventory_complete: inventory.complete && !inventory.truncated,
        unbound_count,
        feed: status,
        entries,
        advisories: feed.map(|f| f.advisories).unwrap_or_default(),
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    fn feed() -> AdvisoryFeed {
        AdvisoryFeed {
            schema_version: 1,
            source_name: "Test fixture only".into(),
            source_url: "https://example.org/advisories".into(),
            generated_at: 100,
            expires_at: 200,
            products: vec![Product {
                product_id: "test:editor".into(),
                display_name: "Test editor".into(),
                covered_versions: vec!["1.0".into(), "2.0".into()],
            }],
            advisories: vec![Advisory {
                id: "TEST-1".into(),
                product_id: "test:editor".into(),
                affected_versions: vec!["1.0".into()],
                kind: AdvisoryKind::Vulnerability,
                title: "Test vulnerability".into(),
                summary: "Synthetic test data only".into(),
                cvss_x100: Some(750),
                cvss_version: Some("3.1".into()),
                cvss_vector: Some("CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:N/A:N".into()),
                source_url: "https://example.org/TEST-1".into(),
                published_at: 99,
                remediation: vec!["Test-only remediation".into()],
            }],
        }
    }
    fn app() -> InstalledSoftware {
        InstalledSoftware {
            id: "test-registry-id".into(),
            display_name: "Test editor".into(),
            publisher: Some("Test vendor".into()),
            version: Some("1.0".into()),
            install_location: None,
            install_date: None,
            display_icon: None,
            scope: "user".into(),
            registry_view: "native".into(),
            source: "test".into(),
            uninstall_key: "test".into(),
        }
    }
    #[test]
    fn parser_rejects_unknown_duplicate_invalid_and_unbounded_feed() -> io::Result<()> {
        let json = serde_json::to_string(&feed()).map_err(err)?;
        assert!(parse_feed(&json, 150).is_ok());
        assert!(parse_feed(
            &json.replace("\"schema_version\":1", "\"schema_version\":1,\"unknown\":1"),
            150
        )
        .is_err());
        assert!(parse_feed(
            &json.replace(
                "\"schema_version\":1",
                "\"schema_version\":1,\"schema_version\":1"
            ),
            150
        )
        .is_err());
        for url in [
            "http://example.org",
            "https://example.org@evil.org",
            "https://127.0.0.1/",
            "https://example.org:443/",
            "https://example.org\\bad",
            "https://example.org/%0a",
        ] {
            assert!(!valid_source_url(url), "{url}");
        }
        assert!(parse_feed(&" ".repeat(MAX_FEED_BYTES + 1), 150).is_err());
        let mut f = feed();
        f.advisories[0].affected_versions = vec!["1.1".into()];
        assert!(parse_feed(&serde_json::to_string(&f).map_err(err)?, 150).is_err());
        f = feed();
        f.advisories[0].kind = AdvisoryKind::EndOfSupport;
        assert!(parse_feed(&serde_json::to_string(&f).map_err(err)?, 150).is_err());
        f = feed();
        f.products.push(f.products[0].clone());
        assert!(parse_feed(&serde_json::to_string(&f).map_err(err)?, 150).is_err());
        Ok(())
    }
    #[test]
    fn exact_manual_binding_survives_reopen_and_staleness_never_clears_matches() -> io::Result<()> {
        let root = std::env::temp_dir().join(format!("piko-advisory-{}", uuid::Uuid::new_v4()));
        let path = root.join("advisories.sqlite");
        let mut inventory = InventorySnapshot {
            entries: vec![app()],
            complete: true,
            truncated: false,
            warnings: vec![],
        };
        bind(&path, &inventory.entries[0], "test:editor", "1.0", 150)?;
        assert_eq!(
            snapshot(&path, &inventory, 150)?.entries[0].state,
            MatchState::NoFeed
        );
        import_feed(&path, &serde_json::to_string(&feed()).map_err(err)?, 150)?;
        let result = snapshot(&path, &inventory, 201)?;
        assert!(result.feed.is_some_and(|f| f.stale));
        assert_eq!(result.entries[0].state, MatchState::Matched);
        assert_eq!(result.advisories[0].cvss_x100, Some(750));
        assert!(import_feed(&path, "{}", 150).is_err());
        assert_eq!(
            snapshot(&path, &inventory, 150)?.entries[0].advisory_count,
            1
        );
        inventory.entries[0].version = Some("2.0".into());
        assert_eq!(
            snapshot(&path, &inventory, 150)?.entries[0].state,
            MatchState::MetadataChanged
        );
        bind(&path, &inventory.entries[0], "test:editor", "2.0", 150)?;
        assert_eq!(
            snapshot(&path, &inventory, 150)?.entries[0].state,
            MatchState::NoKnownAdvisory
        );
        bind(&path, &inventory.entries[0], "other:editor", "2.0", 150)?;
        assert_eq!(
            snapshot(&path, &inventory, 150)?.entries[0].state,
            MatchState::ProductNotCovered
        );
        bind(&path, &inventory.entries[0], "test:editor", "2.1", 150)?;
        assert_eq!(
            snapshot(&path, &inventory, 150)?.entries[0].state,
            MatchState::VersionNotCovered
        );
        inventory.entries.clear();
        inventory.complete = false;
        assert_eq!(
            snapshot(&path, &inventory, 150)?.entries[0].state,
            MatchState::NotObserved
        );
        unbind(&path, "test-registry-id")?;
        assert!(snapshot(&path, &inventory, 150)?.entries.is_empty());
        std::fs::remove_file(path)?;
        std::fs::remove_dir(root)?;
        Ok(())
    }
    #[test]
    fn stored_hash_corruption_and_oversized_archive_fail_closed() -> io::Result<()> {
        let root =
            std::env::temp_dir().join(format!("piko-advisory-corrupt-{}", uuid::Uuid::new_v4()));
        let path = root.join("advisories.sqlite");
        import_feed(&path, &serde_json::to_string(&feed()).map_err(err)?, 150)?;
        {
            let db = Connection::open(&path).map_err(err)?;
            db.execute("UPDATE advisory_feed SET sha256='changed'", [])
                .map_err(err)?;
        }
        let inventory = InventorySnapshot {
            entries: vec![],
            complete: true,
            truncated: false,
            warnings: vec![],
        };
        assert!(snapshot(&path, &inventory, 150).is_err());
        File::options()
            .write(true)
            .open(&path)?
            .set_len(MAX_ARCHIVE_BYTES + 1)?;
        assert!(snapshot(&path, &inventory, 150).is_err());
        std::fs::remove_file(path)?;
        std::fs::remove_dir(root)?;
        Ok(())
    }
    #[test]
    fn binding_limit_prevents_silent_eviction_and_database_replacement() -> io::Result<()> {
        let root =
            std::env::temp_dir().join(format!("piko-advisory-bound-{}", uuid::Uuid::new_v4()));
        let path = root.join("advisories.sqlite");
        let mut store = open(&path)?;
        assert!(std::fs::rename(&path, root.join("moved.sqlite")).is_err());
        let tx = store.db.transaction().map_err(err)?;
        for n in 0..MAX_BINDINGS {
            let item = ProductBinding {
                application_id: format!("test-{n}"),
                application_name: "Test app".into(),
                publisher: None,
                installer_version: None,
                product_id: "test:app".into(),
                exact_version: "1.0".into(),
                bound_at: 150,
            };
            tx.execute(
                "INSERT INTO advisory_bindings VALUES(?1,?2)",
                params![
                    item.application_id,
                    serde_json::to_string(&item).map_err(err)?
                ],
            )
            .map_err(err)?;
        }
        tx.commit().map_err(err)?;
        drop(store);
        assert!(bind(&path, &app(), "test:editor", "1.0", 150).is_err());
        let inventory = InventorySnapshot {
            entries: vec![],
            complete: false,
            truncated: false,
            warnings: vec![],
        };
        assert_eq!(
            snapshot(&path, &inventory, 150)?.entries.len(),
            MAX_BINDINGS
        );
        let sidecar = root.join("advisories.sqlite-wal");
        std::fs::write(&sidecar, b"unexpected")?;
        assert!(snapshot(&path, &inventory, 150).is_err());
        std::fs::remove_file(sidecar)?;
        std::fs::remove_file(path)?;
        std::fs::remove_dir(root)?;
        Ok(())
    }
}
