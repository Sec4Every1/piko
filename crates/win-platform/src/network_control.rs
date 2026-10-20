//! Bounded Windows Firewall COM boundary. Rules restrict an executable PATH,
//! including future files at that path; they are not executable hash policies.
//! Call mutations only after application identity and user intent are verified.
use std::{collections::HashSet, io, marker::PhantomData, rc::Rc};
use windows::{
    core::{IUnknown, Interface, BSTR},
    Win32::{
        Foundation::{RPC_E_CHANGED_MODE, VARIANT_FALSE, VARIANT_TRUE},
        NetworkManagement::WindowsFirewall::*,
        System::{
            Com::{
                CoCreateInstance, CoInitializeEx, CoUninitialize, IDispatch, CLSCTX_INPROC_SERVER,
                COINIT_MULTITHREADED,
            },
            Ole::IEnumVARIANT,
            Variant::{VARIANT, VT_DISPATCH, VT_UNKNOWN},
        },
    },
};

pub const RULE_GROUP: &str = "piko network control";
const RULE_PREFIX: &str = "piko:block-outbound:";
const RULE_DESCRIPTION: &str =
    "piko outbound path block v1; all protocols, destinations and profiles";
const INBOUND_PREFIX: &str = "piko:block-inbound:";
const INBOUND_DESCRIPTION: &str = "piko inbound path block v1; all protocols, sources and profiles";
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum NetworkDirection {
    #[default]
    Outbound,
    Inbound,
}
impl NetworkDirection {
    fn prefix(self) -> &'static str {
        match self {
            Self::Outbound => RULE_PREFIX,
            Self::Inbound => INBOUND_PREFIX,
        }
    }
    fn description(self) -> &'static str {
        match self {
            Self::Outbound => RULE_DESCRIPTION,
            Self::Inbound => INBOUND_DESCRIPTION,
        }
    }
}
fn named_direction(name: &str) -> Option<NetworkDirection> {
    [NetworkDirection::Outbound, NetworkDirection::Inbound]
        .into_iter()
        .find(|d| {
            name.get(..d.prefix().len())
                .is_some_and(|prefix| prefix.eq_ignore_ascii_case(d.prefix()))
        })
}
const MAX_RULES: usize = 16_384;
const MAX_MANAGED_RULES: usize = 512;
const MAX_STRING_UNITS: usize = 4096;

#[derive(Clone, Debug, serde::Serialize)]
pub struct NetworkProfile {
    pub id: i32,
    pub name: String,
    pub active: bool,
    /// Local configuration, not proof of packet filtering under domain policy.
    pub firewall_enabled: bool,
    pub block_all_inbound: bool,
    pub excluded_interfaces: bool,
}

#[derive(Clone, Debug, serde::Serialize)]
pub struct ManagedNetworkRule {
    pub direction: NetworkDirection,
    pub id: String,
    pub executable: String,
    pub enabled: bool,
    /// The entire supported rule shape matches piko's template. This does not
    /// assert packets are blocked or authenticate the administrator who added it.
    pub verified: bool,
}

#[derive(Clone, Debug, serde::Serialize)]
pub struct NetworkSnapshot {
    pub active_profiles: i32,
    pub profiles: Vec<NetworkProfile>,
    /// ok, group_policy_override, inbound_blocked, or unknown.
    pub local_policy_modify_state: String,
    pub rules: Vec<ManagedNetworkRule>,
    pub complete: bool,
    pub warnings: Vec<String>,
}

struct Apartment {
    owns_initialization: bool,
    _thread_bound: PhantomData<Rc<()>>,
}
impl Apartment {
    fn new() -> io::Result<Self> {
        // SAFETY: no reserved pointer; ownership is balanced on this same thread.
        let result = unsafe { CoInitializeEx(None, COINIT_MULTITHREADED) };
        if result.is_err() && result != RPC_E_CHANGED_MODE {
            return Err(com_error(result.into()));
        }
        Ok(Self {
            owns_initialization: result.is_ok(),
            _thread_bound: PhantomData,
        })
    }
}
impl Drop for Apartment {
    fn drop(&mut self) {
        if self.owns_initialization {
            // SAFETY: exactly balances this wrapper's successful CoInitializeEx.
            unsafe { CoUninitialize() };
        }
    }
}

fn com_error(error: windows::core::Error) -> io::Error {
    io::Error::other(format!("Windows Firewall: {error}"))
}
fn policy() -> io::Result<INetFwPolicy2> {
    // SAFETY: callers hold an initialized apartment, returned COM pointer owns a reference.
    unsafe { CoCreateInstance(&NetFwPolicy2, None, CLSCTX_INPROC_SERVER) }.map_err(com_error)
}
fn text(value: BSTR) -> io::Result<String> {
    if value.len() > MAX_STRING_UNITS {
        return Err(io::Error::other(
            "Windows Firewall string exceeds metadata bound",
        ));
    }
    let value = String::from_utf16(&value).map_err(io::Error::other)?;
    if value
        .chars()
        .any(|c| c.is_control() || matches!(c, '\u{202a}'..='\u{202e}' | '\u{2066}'..='\u{2069}'))
    {
        return Err(io::Error::other(
            "Windows Firewall string contains control characters",
        ));
    }
    Ok(value)
}
fn validate_id(id: &str) -> io::Result<()> {
    if id.len() != 64
        || !id
            .bytes()
            .all(|c| c.is_ascii_digit() || (b'a'..=b'f').contains(&c))
    {
        return Err(io::Error::new(
            io::ErrorKind::InvalidInput,
            "Invalid piko rule identity",
        ));
    }
    Ok(())
}
fn validate_target(id: &str, executable: &str) -> io::Result<String> {
    validate_id(id)?;
    let bytes = executable.as_bytes();
    if executable.encode_utf16().count() > MAX_STRING_UNITS
        || bytes.len() < 7
        || !bytes[0].is_ascii_alphabetic()
        || &bytes[1..3] != b":\\"
        || executable[3..].contains([':', '/', '"', '*', '?', '%'])
        || executable.chars().any(char::is_control)
        || !executable.to_ascii_lowercase().ends_with(".exe")
        || executable[3..].split('\\').any(|part| {
            part.is_empty() || part == "." || part == ".." || part.ends_with(['.', ' '])
        })
    {
        return Err(io::Error::new(
            io::ErrorKind::InvalidInput,
            "Expected a canonical local executable path",
        ));
    }
    Ok(format!("{RULE_PREFIX}{id}"))
}

fn read_profiles(policy: &INetFwPolicy2) -> io::Result<(i32, Vec<NetworkProfile>, String)> {
    // SAFETY: live interfaces in this apartment; no mutation, all returned values owned.
    unsafe {
        let active = policy.CurrentProfileTypes().map_err(com_error)?;
        let mut profiles = Vec::new();
        for (id, name) in [
            (NET_FW_PROFILE2_DOMAIN, "domain"),
            (NET_FW_PROFILE2_PRIVATE, "private"),
            (NET_FW_PROFILE2_PUBLIC, "public"),
        ] {
            profiles.push(NetworkProfile {
                id: id.0,
                name: name.into(),
                active: active & id.0 != 0,
                firewall_enabled: policy.get_FirewallEnabled(id).map_err(com_error)?.as_bool(),
                block_all_inbound: policy
                    .get_BlockAllInboundTraffic(id)
                    .map_err(com_error)?
                    .as_bool(),
                excluded_interfaces: !policy
                    .get_ExcludedInterfaces(id)
                    .map_err(com_error)?
                    .is_empty(),
            });
        }
        let state = match policy.LocalPolicyModifyState().map_err(com_error)? {
            NET_FW_MODIFY_STATE_OK => "ok",
            NET_FW_MODIFY_STATE_GP_OVERRIDE => "group_policy_override",
            NET_FW_MODIFY_STATE_INBOUND_BLOCKED => "inbound_blocked",
            _ => "unknown",
        };
        Ok((active, profiles, state.into()))
    }
}

#[derive(Clone, Debug)]
struct RuleShape {
    name: String,
    executable: String,
    grouping: String,
    description: String,
    enabled: bool,
    exact_scope: bool,
}
impl RuleShape {
    fn matches(&self, name: &str, executable: &str) -> bool {
        self.name == name
            && self.executable == executable
            && self.grouping == RULE_GROUP
            && named_direction(name).is_some_and(|d| self.description == d.description())
            && self.enabled
            && self.exact_scope
    }
}
fn read_rule(rule: &INetFwRule) -> io::Result<RuleShape> {
    // SAFETY: live interface in the initialized apartment; getters return owned
    // BSTR/VARIANT values whose generated wrappers release them on drop.
    unsafe {
        let rule3: INetFwRule3 = rule.cast().map_err(com_error)?;
        let name = text(rule.Name().map_err(com_error)?)?;
        let expected = if named_direction(&name) == Some(NetworkDirection::Inbound) {
            NET_FW_RULE_DIR_IN
        } else {
            NET_FW_RULE_DIR_OUT
        };
        let exact_scope = rule.Direction().map_err(com_error)? == expected
            && rule.Action().map_err(com_error)? == NET_FW_ACTION_BLOCK
            && rule.Profiles().map_err(com_error)? == NET_FW_PROFILE2_ALL.0
            && rule.Protocol().map_err(com_error)? == NET_FW_IP_PROTOCOL_ANY.0
            && text(rule.ServiceName().map_err(com_error)?)?.is_empty()
            && text(rule.LocalAddresses().map_err(com_error)?)? == "*"
            && text(rule.RemoteAddresses().map_err(com_error)?)? == "*"
            && text(rule.InterfaceTypes().map_err(com_error)?)? == "All"
            && rule.Interfaces().map_err(com_error)?.is_empty()
            && !rule.EdgeTraversal().map_err(com_error)?.as_bool()
            && rule3.EdgeTraversalOptions().map_err(com_error)? == 0
            && text(rule3.LocalAppPackageId().map_err(com_error)?)?.is_empty()
            && text(rule3.LocalUserOwner().map_err(com_error)?)?.is_empty()
            && text(rule3.LocalUserAuthorizedList().map_err(com_error)?)?.is_empty()
            && text(rule3.RemoteUserAuthorizedList().map_err(com_error)?)?.is_empty()
            && text(rule3.RemoteMachineAuthorizedList().map_err(com_error)?)?.is_empty()
            && rule3.SecureFlags().map_err(com_error)? == 0;
        Ok(RuleShape {
            name,
            executable: text(rule.ApplicationName().map_err(com_error)?)?,
            grouping: text(rule.Grouping().map_err(com_error)?)?,
            description: text(rule.Description().map_err(com_error)?)?,
            enabled: rule.Enabled().map_err(com_error)?.as_bool(),
            exact_scope,
        })
    }
}

/// Enumerate the full bounded collection to reject duplicate names, which a
/// single Item(name) lookup cannot establish. Unrelated rule bodies are unread.
fn variant_rule(value: &VARIANT) -> io::Result<INetFwRule> {
    // Windows Firewall's enumerator normally yields VT_DISPATCH. The generated
    // IUnknown conversion accepts only VT_UNKNOWN, not its IDispatch subtype.
    match value.vt() {
        VT_DISPATCH => IDispatch::try_from(value)
            .map_err(com_error)?
            .cast()
            .map_err(com_error),
        VT_UNKNOWN => IUnknown::try_from(value)
            .map_err(com_error)?
            .cast()
            .map_err(com_error),
        _ => Err(io::Error::other(
            "Unexpected Firewall enumeration value type",
        )),
    }
}

fn read_managed(rules: &INetFwRules) -> io::Result<Vec<RuleShape>> {
    // SAFETY: all COM objects and variants are owned in the current apartment.
    unsafe {
        let count = rules.Count().map_err(com_error)?;
        if count < 0 || count as usize > MAX_RULES {
            return Err(io::Error::other(
                "Firewall collection exceeds the bounded rule inventory",
            ));
        }
        let enumerator: IEnumVARIANT = rules
            ._NewEnum()
            .map_err(com_error)?
            .cast()
            .map_err(com_error)?;
        let mut managed = Vec::new();
        for index in 0..=MAX_RULES {
            let mut values = [VARIANT::default()];
            let mut fetched = 0;
            enumerator
                .Next(&mut values, &mut fetched)
                .ok()
                .map_err(com_error)?;
            if fetched == 0 {
                return Ok(managed);
            }
            if fetched != 1 || index == MAX_RULES {
                return Err(io::Error::other("Firewall enumeration exceeded its bound"));
            }
            let rule = variant_rule(&values[0])?;
            let name = text(rule.Name().map_err(com_error)?)?;
            if named_direction(&name).is_some() {
                if managed.len() >= MAX_MANAGED_RULES {
                    return Err(io::Error::other(
                        "Too many piko Firewall rules to inspect safely",
                    ));
                }
                managed.push(read_rule(&rule)?);
            }
        }
        Err(io::Error::other("Firewall enumeration did not finish"))
    }
}

pub fn network_snapshot() -> io::Result<NetworkSnapshot> {
    let _apartment = Apartment::new()?;
    let policy = policy()?;
    let (active_profiles, profiles, local_policy_modify_state) = read_profiles(&policy)?;
    // SAFETY: live COM interface and same apartment.
    let rules = unsafe { policy.Rules() }.map_err(com_error)?;
    let mut snapshot = NetworkSnapshot {
        active_profiles,
        profiles,
        local_policy_modify_state,
        rules: Vec::new(),
        complete: true,
        warnings: Vec::new(),
    };
    let managed = match read_managed(&rules) {
        Ok(rules) => rules,
        Err(error) => {
            snapshot.complete = false;
            snapshot.warnings.push(error.to_string());
            return Ok(snapshot);
        }
    };
    let mut names = HashSet::new();
    let mut duplicates = HashSet::new();
    for rule in &managed {
        if !names.insert(rule.name.to_ascii_lowercase()) {
            duplicates.insert(rule.name.to_ascii_lowercase());
        }
    }
    for rule in &managed {
        let Some(direction) = named_direction(&rule.name) else {
            continue;
        };
        let Some(id) = rule.name.get(direction.prefix().len()..) else {
            continue;
        };
        if validate_id(id).is_err() {
            snapshot.complete = false;
            if snapshot.warnings.len() < 32 {
                snapshot
                    .warnings
                    .push("Malformed piko rule identity; manual Firewall review required".into());
            }
            continue;
        }
        let verified = !duplicates.contains(&rule.name.to_ascii_lowercase())
            && validate_target(id, &rule.executable).is_ok()
            && rule.matches(&format!("{}{id}", direction.prefix()), &rule.executable);
        // Duplicate COM names are exposed once, always unverified, so callers
        // cannot mistake the first matching entry for a unique owned rule.
        if snapshot
            .rules
            .iter()
            .any(|existing| existing.id == id && existing.direction == direction)
        {
            continue;
        }
        snapshot.rules.push(ManagedNetworkRule {
            direction,
            id: id.into(),
            executable: rule.executable.clone(),
            enabled: rule.enabled,
            verified,
        });
    }
    snapshot.rules.sort_by(|a, b| a.id.cmp(&b.id));
    Ok(snapshot)
}

fn matching_rule<'a>(
    managed: &'a [RuleShape],
    name: &str,
    executable: &str,
) -> io::Result<Option<&'a RuleShape>> {
    let mut matches = managed
        .iter()
        .filter(|rule| rule.name.eq_ignore_ascii_case(name));
    let existing = matches.next();
    if matches.next().is_some() || existing.is_some_and(|rule| !rule.matches(name, executable)) {
        return Err(io::Error::new(
            io::ErrorKind::PermissionDenied,
            "Rule identity collision or externally modified piko rule; no change made",
        ));
    }
    Ok(existing)
}

/// Builds an in-memory COM object only. Persistence occurs exclusively at Add.
fn block_template(name: &str, executable: &str) -> io::Result<INetFwRule> {
    // SAFETY: called in an initialized apartment; returned COM object owns its reference.
    unsafe {
        let rule: INetFwRule =
            CoCreateInstance(&NetFwRule, None, CLSCTX_INPROC_SERVER).map_err(com_error)?;
        rule.SetName(&BSTR::from(name)).map_err(com_error)?;
        let direction =
            named_direction(name).ok_or_else(|| io::Error::other("Unsupported rule direction"))?;
        rule.SetDescription(&BSTR::from(direction.description()))
            .map_err(com_error)?;
        rule.SetApplicationName(&BSTR::from(executable))
            .map_err(com_error)?;
        rule.SetServiceName(&BSTR::new()).map_err(com_error)?;
        rule.SetProtocol(NET_FW_IP_PROTOCOL_ANY.0)
            .map_err(com_error)?;
        rule.SetLocalAddresses(&BSTR::from("*"))
            .map_err(com_error)?;
        rule.SetRemoteAddresses(&BSTR::from("*"))
            .map_err(com_error)?;
        rule.SetInterfaceTypes(&BSTR::from("All"))
            .map_err(com_error)?;
        rule.SetDirection(if direction == NetworkDirection::Inbound {
            NET_FW_RULE_DIR_IN
        } else {
            NET_FW_RULE_DIR_OUT
        })
        .map_err(com_error)?;
        rule.SetProfiles(NET_FW_PROFILE2_ALL.0).map_err(com_error)?;
        rule.SetGrouping(&BSTR::from(RULE_GROUP))
            .map_err(com_error)?;
        rule.SetEdgeTraversal(VARIANT_FALSE).map_err(com_error)?;
        rule.SetAction(NET_FW_ACTION_BLOCK).map_err(com_error)?;
        rule.SetEnabled(VARIANT_TRUE).map_err(com_error)?;
        if !read_rule(&rule)?.matches(name, executable) {
            return Err(io::Error::other(
                "Windows Firewall rejected the piko rule template before insertion",
            ));
        }
        Ok(rule)
    }
}

/// Add one outbound BLOCK rule. Never modifies a global setting or an existing
/// rule. Caller must retain its verified executable handle until this returns.
pub fn apply_network_block(rule_id: &str, executable: &str) -> io::Result<()> {
    apply_direction_block(rule_id, executable, NetworkDirection::Outbound)
}
pub fn apply_direction_block(
    rule_id: &str,
    executable: &str,
    direction: NetworkDirection,
) -> io::Result<()> {
    validate_target(rule_id, executable)?;
    let name = format!("{}{rule_id}", direction.prefix());
    let _apartment = Apartment::new()?;
    let policy = policy()?;
    let (active, profiles, state) = read_profiles(&policy)?;
    if active == 0
        || !matches!(state.as_str(), "ok" | "inbound_blocked")
        || profiles.iter().any(|profile| {
            profile.active && (!profile.firewall_enabled || profile.excluded_interfaces)
        })
    {
        return Err(io::Error::new(io::ErrorKind::PermissionDenied,
            "The active Firewall configuration cannot confirm that a local executable block will apply"));
    }
    // SAFETY: live COM objects in the initialized apartment; only a new rule
    // with the fixed piko template is submitted. No command shell is involved.
    unsafe {
        let rules = policy.Rules().map_err(com_error)?;
        if matching_rule(&read_managed(&rules)?, &name, executable)?.is_some() {
            return Ok(());
        }
        let rule = block_template(&name, executable)?;
        // Re-read immediately before mutation; COM has no atomic compare/add API.
        if matching_rule(&read_managed(&rules)?, &name, executable)?.is_some() {
            return Ok(());
        }
        rules.Add(&rule).map_err(com_error)?;
        if matching_rule(&read_managed(&rules)?, &name, executable)?.is_none() {
            return Err(io::Error::other(
                "Firewall rule was submitted but could not be verified; refresh before retrying",
            ));
        }
    }
    Ok(())
}

/// Remove only a matching piko block. This never installs an allow rule, and
/// other Windows/domain Firewall rules continue to apply.
pub fn remove_network_block(rule_id: &str, executable: &str) -> io::Result<()> {
    remove_direction_block(rule_id, executable, NetworkDirection::Outbound)
}
pub fn remove_direction_block(
    rule_id: &str,
    executable: &str,
    direction: NetworkDirection,
) -> io::Result<()> {
    validate_target(rule_id, executable)?;
    let name = format!("{}{rule_id}", direction.prefix());
    let _apartment = Apartment::new()?;
    let policy = policy()?;
    // SAFETY: only an exact, unique piko rule name inspected above is removed.
    // Elevated administrators can still race COM's non-transactional API.
    unsafe {
        let rules = policy.Rules().map_err(com_error)?;
        if matching_rule(&read_managed(&rules)?, &name, executable)?.is_none() {
            return Ok(());
        }
        rules
            .Remove(&BSTR::from(name.as_str()))
            .map_err(com_error)?;
        if read_managed(&rules)?
            .iter()
            .any(|rule| rule.name.eq_ignore_ascii_case(&name))
        {
            return Err(io::Error::other(
                "Firewall removal could not be verified; refresh before retrying",
            ));
        }
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    fn template() -> RuleShape {
        RuleShape {
            name: format!("{RULE_PREFIX}{}", "a".repeat(64)),
            executable: r"C:\Apps\example.exe".into(),
            grouping: RULE_GROUP.into(),
            description: RULE_DESCRIPTION.into(),
            enabled: true,
            exact_scope: true,
        }
    }

    #[test]
    fn rejects_nonlocal_ambiguous_or_injected_paths_before_com() {
        let id = "a".repeat(64);
        for path in [
            r"\\server\share\app.exe",
            r"\\?\C:\app.exe",
            r"C:app.exe",
            r"C:\app.exe:stream",
            r"C:\a\..\app.exe",
            r"C:\a.\app.exe",
            r"C:\%APP%\app.exe",
            "C:\\app.exe\0",
            "C:\\app.exe\"",
            r"C:\app.cmd",
        ] {
            assert!(validate_target(&id, path).is_err(), "{path}");
        }
        assert!(validate_target(&id, r"C:\Program Files\Example\example.exe").is_ok());
        assert!(validate_target(&"A".repeat(64), r"C:\app.exe").is_err());
        assert!(validate_target(&"a".repeat(63), r"C:\app.exe").is_err());
    }

    #[test]
    fn collisions_duplicates_and_modified_rules_are_rejected() -> io::Result<()> {
        let valid = template();
        assert!(matching_rule(&[], &valid.name, &valid.executable)?.is_none());
        assert!(
            matching_rule(std::slice::from_ref(&valid), &valid.name, &valid.executable)?.is_some()
        );
        assert!(matching_rule(
            &[valid.clone(), valid.clone()],
            &valid.name,
            &valid.executable
        )
        .is_err());
        for field in 0..6 {
            let mut modified = valid.clone();
            match field {
                0 => modified.grouping = "foreign".into(),
                1 => modified.executable = r"C:\other.exe".into(),
                2 => modified.description.clear(),
                3 => modified.enabled = false,
                4 => modified.exact_scope = false,
                _ => modified.name = valid.name.to_ascii_uppercase(),
            }
            assert!(matching_rule(&[modified], &valid.name, &valid.executable).is_err());
        }
        Ok(())
    }

    #[test]
    fn real_com_template_round_trips_without_persisting_a_rule() -> io::Result<()> {
        let _apartment = Apartment::new()?;
        let expected = template();
        let inbound_name = format!("{INBOUND_PREFIX}{}", "a".repeat(64));
        let inbound = block_template(&inbound_name, &expected.executable)?;
        assert!(read_rule(&inbound)?.matches(&inbound_name, &expected.executable));
        // SAFETY: unregistered in-memory object only; test never persists rules.
        unsafe { inbound.SetDirection(NET_FW_RULE_DIR_OUT) }.map_err(com_error)?;
        assert!(!read_rule(&inbound)?.matches(&inbound_name, &expected.executable));
        let rule = block_template(&expected.name, &expected.executable)?;
        assert!(read_rule(&rule)?.matches(&expected.name, &expected.executable));
        // SAFETY: mutate only an unregistered COM object in this apartment;
        // no INetFwRules::Add call, so the host Firewall is never changed.
        unsafe { rule.SetLocalAddresses(&BSTR::from("127.0.0.1")) }.map_err(com_error)?;
        assert!(!read_rule(&rule)?.matches(&expected.name, &expected.executable));
        Ok(())
    }

    #[test]
    fn windows_firewall_read_only_snapshot_is_bounded() -> io::Result<()> {
        let snapshot = network_snapshot()?;
        assert!(
            snapshot.complete,
            "Firewall read failed: {:?}",
            snapshot.warnings
        );
        assert_eq!(snapshot.profiles.len(), 3);
        assert!(snapshot.rules.len() <= MAX_MANAGED_RULES);
        assert!(snapshot.warnings.len() <= 32);
        for profile in snapshot.profiles {
            assert_eq!(profile.active, snapshot.active_profiles & profile.id != 0);
        }
        Ok(())
    }
}
