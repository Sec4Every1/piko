use serde::{Deserialize, Serialize};
use uuid::Uuid;

pub struct SecretText(zeroize::Zeroizing<String>);
impl std::fmt::Debug for SecretText {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str("[REDACTED]")
    }
}
impl SecretText {
    pub fn new(value: String) -> Result<Self, &'static str> {
        let value = zeroize::Zeroizing::new(value);
        if value.is_empty() || value.len() > 128 || !value.is_ascii() {
            return Err("invalid recovery code input");
        }
        Ok(Self(value))
    }
    pub fn expose(&self) -> &str {
        &self.0
    }
}
impl Serialize for SecretText {
    fn serialize<S: serde::Serializer>(&self, s: S) -> Result<S::Ok, S::Error> {
        s.serialize_str(self.expose())
    }
}
impl<'de> Deserialize<'de> for SecretText {
    fn deserialize<D: serde::Deserializer<'de>>(d: D) -> Result<Self, D::Error> {
        Self::new(String::deserialize(d)?).map_err(serde::de::Error::custom)
    }
}
#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct EvidenceKeyStatus {
    pub state: String,
    pub backup_confirmed: bool,
    pub new_raw_enabled: bool,
    pub recoverable_mode: bool,
    #[serde(default)]
    pub activation_pending: bool,
}
#[derive(Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct KeyBackupTicket {
    pub id: Uuid,
    pub expires_at_unix_ms: u64,
}
#[derive(Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct EvidenceProtectionTicket {
    pub id: Uuid,
    pub expires_at_unix_ms: u64,
}
#[derive(Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct KeyBackupReply {
    pub ticket_id: Uuid,
    pub archive_id: Uuid,
    pub recipient: String,
    pub recovery_code: SecretText,
}
#[cfg(windows)]
#[derive(Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct KeyBackupAuthorization {
    pub purpose: String,
    pub ticket_id: Uuid,
    pub origin: piko_win_platform::network_elevation::NetworkPlanOrigin,
    pub expires_at_unix_ms: u64,
}
#[cfg(windows)]
#[derive(Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct EvidenceProtectionAuthorization {
    pub purpose: String,
    pub ticket_id: Uuid,
    pub origin: piko_win_platform::network_elevation::NetworkPlanOrigin,
    pub expires_at_unix_ms: u64,
}
#[cfg(windows)]
#[derive(Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct EvidenceProtectionResumeAuthorization {
    pub purpose: String,
    pub origin: piko_win_platform::network_elevation::NetworkPlanOrigin,
    pub expires_at_unix_ms: u64,
}
