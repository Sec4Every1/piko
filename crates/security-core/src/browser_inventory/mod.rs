//! Bounded interpretation of untrusted installed-software registrations.
//!
//! This module does not discover executables or profiles and performs no I/O.
//! A registration is a candidate, not verified installation or protection.

use serde::{Deserialize, Serialize};

pub const MAX_REGISTRATIONS_SCANNED: usize = 3072;
pub const MAX_BROWSER_CANDIDATES: usize = 128;
const MAX_FIELD_BYTES: usize = 4096;

/// The caller must report which account's registration data was actually read.
/// In particular, a service's HKCU is not the interactive viewer's HKCU.
#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum RegistrationScope {
    Machine,
    Viewer,
    ServiceAccount,
    Unknown,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum BrowserFamily {
    Edge,
    Chrome,
    Firefox,
}

/// One bounded claim from Windows uninstall registry metadata. None of these
/// fields is authenticated; callers must not use them to authorize a process.
#[derive(Clone, Debug)]
pub struct Registration<'a> {
    pub id: &'a str,
    pub display_name: &'a str,
    pub publisher: Option<&'a str>,
    pub version: Option<&'a str>,
    pub scope: RegistrationScope,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
pub struct BrowserCandidate {
    pub family: BrowserFamily,
    pub registration_id: String,
    pub registered_name: String,
    pub registered_publisher: Option<String>,
    pub registered_version: Option<String>,
    pub scope: RegistrationScope,
}

/// Overall discovery is always incomplete: registry metadata cannot enumerate
/// all browsers, profiles or portable installations, and user scope may be absent.
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
pub struct BrowserInventory {
    pub candidates: Vec<BrowserCandidate>,
    pub registration_scan_complete: bool,
    pub truncated: bool,
    pub oversized_metadata: bool,
    pub browser_discovery_complete: bool,
    pub profiles_known: bool,
    pub executable_identity_verified: bool,
    pub protection_status_known: bool,
}

fn family(name: &str) -> Option<BrowserFamily> {
    let name = name.trim();
    if name.eq_ignore_ascii_case("Microsoft Edge") {
        Some(BrowserFamily::Edge)
    } else if name.eq_ignore_ascii_case("Google Chrome") {
        Some(BrowserFamily::Chrome)
    } else if name.eq_ignore_ascii_case("Mozilla Firefox") {
        Some(BrowserFamily::Firefox)
    } else {
        None
    }
}

fn bounded(value: Option<&str>) -> bool {
    value.is_none_or(|s| s.len() <= MAX_FIELD_BYTES && !s.contains('\0'))
}

/// Interprets only exact names as unverified candidate registrations. Scan and
/// output are capped; omitted/ambiguous registrations do not establish absence.
pub fn from_registrations<'a>(
    registrations: impl IntoIterator<Item = Registration<'a>>,
    source_complete: bool,
) -> BrowserInventory {
    let mut result = BrowserInventory {
        candidates: Vec::new(),
        registration_scan_complete: source_complete,
        truncated: false,
        oversized_metadata: false,
        browser_discovery_complete: false,
        profiles_known: false,
        executable_identity_verified: false,
        protection_status_known: false,
    };
    for (position, item) in registrations.into_iter().enumerate() {
        if position >= MAX_REGISTRATIONS_SCANNED {
            result.truncated = true;
            result.registration_scan_complete = false;
            break;
        }
        // Names outside the input bound cannot safely be classified or ignored.
        if !bounded(Some(item.display_name)) {
            result.oversized_metadata = true;
            result.registration_scan_complete = false;
            continue;
        }
        let Some(family) = family(item.display_name) else {
            continue;
        };
        if !bounded(Some(item.id))
            || item.id.is_empty()
            || !bounded(item.publisher)
            || !bounded(item.version)
        {
            result.oversized_metadata = true;
            result.registration_scan_complete = false;
            continue;
        }
        if result.candidates.len() == MAX_BROWSER_CANDIDATES {
            result.truncated = true;
            result.registration_scan_complete = false;
            break;
        }
        result.candidates.push(BrowserCandidate {
            family,
            registration_id: item.id.into(),
            registered_name: item.display_name.into(),
            registered_publisher: item.publisher.map(str::to_owned),
            registered_version: item.version.map(str::to_owned),
            scope: item.scope,
        });
    }
    result
}

#[cfg(test)]
mod tests {
    use super::*;

    fn entry(name: &str) -> Registration<'_> {
        Registration {
            id: "machine/64/key",
            display_name: name,
            publisher: None,
            version: None,
            scope: RegistrationScope::Machine,
        }
    }

    #[test]
    fn claims_are_candidates_not_verified_browsers_or_protection() {
        let result = from_registrations(
            [
                entry("google chrome"),
                entry("Microsoft Edge"),
                entry("Mozilla Firefox"),
                entry("Google Chrome Helper"),
            ],
            true,
        );
        assert_eq!(result.candidates.len(), 3);
        assert_eq!(result.candidates[0].family, BrowserFamily::Chrome);
        assert!(!result.browser_discovery_complete && !result.profiles_known);
        assert!(!result.executable_identity_verified && !result.protection_status_known);
        assert!(result.registration_scan_complete);
    }

    #[test]
    fn incomplete_source_and_service_scope_do_not_imply_viewer_coverage() {
        let mut r = entry("Google Chrome");
        r.scope = RegistrationScope::ServiceAccount;
        let result = from_registrations([r], false);
        assert!(!result.registration_scan_complete && !result.browser_discovery_complete);
        assert_eq!(
            result.candidates[0].scope,
            RegistrationScope::ServiceAccount
        );
    }

    #[test]
    fn oversized_and_nul_metadata_refuse_candidate_without_claiming_completeness() {
        let long = "x".repeat(MAX_FIELD_BYTES + 1);
        let mut r = entry("Google Chrome");
        r.version = Some(&long);
        let mut bad = entry("Microsoft Edge");
        bad.id = "bad\0id";
        let result = from_registrations([r, bad], true);
        assert!(result.candidates.is_empty() && result.oversized_metadata);
        assert!(!result.registration_scan_complete);
        let unknown = from_registrations([entry(&long)], true);
        assert!(unknown.oversized_metadata && !unknown.registration_scan_complete);
    }

    #[test]
    fn scan_and_output_bounds_are_visible() {
        let results = from_registrations(
            (0..MAX_BROWSER_CANDIDATES + 1).map(|_| entry("Google Chrome")),
            true,
        );
        assert_eq!(results.candidates.len(), MAX_BROWSER_CANDIDATES);
        assert!(results.truncated && !results.registration_scan_complete);
        let results = from_registrations(
            (0..MAX_REGISTRATIONS_SCANNED + 1).map(|_| entry("unrelated")),
            true,
        );
        assert!(results.candidates.is_empty() && results.truncated);
        assert!(!results.browser_discovery_complete);
    }
}
