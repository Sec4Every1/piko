//! Machine-wide registration candidates. Registry reads never run on the async
//! request thread, and a stuck read cannot create an unbounded worker backlog.
use std::sync::atomic::{AtomicBool, Ordering};

use piko_ipc::{ApiData, ApiError};
use piko_security_core::browser_inventory::{
    from_registrations, BrowserInventory, Registration, RegistrationScope,
};
use piko_win_platform::software_inventory::InventorySnapshot;

use super::storage_worker::api_error;

static RUNNING: AtomicBool = AtomicBool::new(false);

struct Reservation(&'static AtomicBool);

impl Reservation {
    fn try_acquire(flag: &'static AtomicBool) -> Option<Self> {
        flag.compare_exchange(false, true, Ordering::Acquire, Ordering::Relaxed)
            .ok()
            .map(|_| Self(flag))
    }
}

impl Drop for Reservation {
    fn drop(&mut self) {
        self.0.store(false, Ordering::Release);
    }
}

fn interpret(snapshot: &InventorySnapshot) -> Result<BrowserInventory, ApiError> {
    // A service's HKCU is not the interactive viewer's HKCU. Reject unexpected
    // scopes rather than mislabeling them or exposing service-account metadata.
    if snapshot
        .entries
        .iter()
        .any(|entry| entry.scope != "machine")
    {
        return Err(api_error(
            "browser_inventory_scope",
            "Unexpected registration scope",
        ));
    }
    let registrations = snapshot.entries.iter().map(|entry| Registration {
        id: &entry.id,
        display_name: &entry.display_name,
        publisher: entry.publisher.as_deref(),
        version: entry.version.as_deref(),
        scope: RegistrationScope::Machine,
    });
    let mut result = from_registrations(registrations, snapshot.complete && !snapshot.truncated);
    // Preserve the registry collector's truncation independently of classifier bounds.
    result.truncated |= snapshot.truncated;
    Ok(result)
}

pub async fn collect() -> Result<ApiData, ApiError> {
    let reservation = Reservation::try_acquire(&RUNNING).ok_or_else(|| {
        api_error(
            "browser_inventory_busy",
            "Browser inventory scan is already in progress",
        )
    })?;
    tokio::task::spawn_blocking(move || {
        // The guard stays owned by the worker even if the requesting future times
        // out, so another request cannot start while the registry call is stuck.
        let _reservation = reservation;
        let snapshot = piko_win_platform::software_inventory::inventory(false)
            .map_err(|error| api_error("browser_inventory_unavailable", &error.to_string()))?;
        interpret(&snapshot).map(ApiData::BrowserInventory)
    })
    .await
    .map_err(|_| {
        api_error(
            "browser_inventory_unavailable",
            "Browser inventory worker failed",
        )
    })?
}

#[cfg(test)]
mod tests {
    use super::*;
    use piko_win_platform::software_inventory::InstalledSoftware;

    fn snapshot(scope: &str) -> InventorySnapshot {
        InventorySnapshot {
            entries: vec![InstalledSoftware {
                id: "registry:machine:64:key".into(),
                display_name: "Google Chrome".into(),
                publisher: Some("unverified publisher".into()),
                version: None,
                install_location: None,
                install_date: None,
                display_icon: None,
                scope: scope.into(),
                registry_view: "64".into(),
                source: "synthetic".into(),
                uninstall_key: "key".into(),
            }],
            complete: true,
            truncated: false,
            warnings: vec![],
        }
    }

    #[test]
    fn machine_candidates_stay_unverified_and_partial_is_visible() -> Result<(), &'static str> {
        let mut source = snapshot("machine");
        source.complete = false;
        source.truncated = true;
        let result = interpret(&source).map_err(|_| "machine registry snapshot")?;
        assert_eq!(result.candidates.len(), 1);
        assert_eq!(result.candidates[0].scope, RegistrationScope::Machine);
        assert!(result.truncated && !result.registration_scan_complete);
        assert!(!result.browser_discovery_complete && !result.profiles_known);
        assert!(!result.executable_identity_verified && !result.protection_status_known);
        Ok(())
    }

    #[test]
    fn service_or_user_scope_is_never_labeled_as_machine() {
        for scope in ["user", "service", "unknown", ""] {
            assert!(interpret(&snapshot(scope)).is_err());
        }
    }

    #[test]
    fn reservation_refuses_overlap_until_worker_drops_it() -> Result<(), &'static str> {
        static FLAG: AtomicBool = AtomicBool::new(false);
        let guard = Reservation::try_acquire(&FLAG).ok_or("first scan")?;
        assert!(Reservation::try_acquire(&FLAG).is_none());
        drop(guard);
        assert!(Reservation::try_acquire(&FLAG).is_some());
        Ok(())
    }

    #[tokio::test]
    async fn abandoned_request_cannot_start_another_scan() -> Result<(), Box<dyn std::error::Error>>
    {
        use std::{sync::mpsc, time::Duration};
        static FLAG: AtomicBool = AtomicBool::new(false);
        let reservation = Reservation::try_acquire(&FLAG).ok_or("first scan")?;
        let (started_tx, started_rx) = mpsc::channel();
        let (release_tx, release_rx) = mpsc::channel();
        let (done_tx, done_rx) = mpsc::channel();
        let handle = tokio::task::spawn_blocking(move || {
            let _ = started_tx.send(());
            let _ = release_rx.recv();
            drop(reservation);
            let _ = done_tx.send(());
        });
        started_rx.recv_timeout(Duration::from_secs(5))?;
        // Dropping a timed-out request's join handle does not cancel blocking work.
        drop(handle);
        assert!(Reservation::try_acquire(&FLAG).is_none());
        release_tx.send(())?;
        done_rx.recv_timeout(Duration::from_secs(5))?;
        assert!(Reservation::try_acquire(&FLAG).is_some());
        Ok(())
    }
}
