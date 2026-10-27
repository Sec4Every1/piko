//! Negative decoding only: every recognized fixture fails before Windows calls.
use super::try_authorize;

fn encoded(value: &serde_json::Value) -> String {
    value
        .to_string()
        .bytes()
        .map(|byte| format!("{byte:02x}"))
        .collect()
}

fn request(purpose: &str) -> serde_json::Value {
    let mut value = serde_json::json!({
        "purpose": purpose,
        "origin": { "pid": 8, "creation_filetime": "1" },
        "expires_at_unix_ms": 0
    });
    if purpose != "evidence-protection-resume-v1" {
        value["ticket_id"] = "11111111-1111-4111-8111-111111111111".into();
    }
    value
}

fn refused(value: &serde_json::Value) {
    let Some(Err(error)) = try_authorize(&encoded(value)) else {
        panic!("recognized fixture must be refused before Windows actions");
    };
    assert_eq!(error.to_string(), "evidence key operation was refused");
}

#[test]
fn malformed_encoding_and_unknown_purposes_are_not_key_operations() {
    for value in [
        "".to_owned(),
        "0".into(),
        "zz".into(),
        "00".into(),
        "61".repeat(12_289),
    ] {
        assert!(try_authorize(&value).is_none());
    }
    for value in [
        serde_json::json!({}),
        serde_json::json!({"purpose": 1}),
        serde_json::json!({"purpose": "network-operation"}),
        serde_json::json!({"purpose": "evidence-key-backup-v2"}),
    ] {
        assert!(try_authorize(&encoded(&value)).is_none());
    }
}

#[test]
fn recognized_but_incomplete_requests_are_refused_before_authorization() {
    for purpose in [
        "evidence-key-backup-v1",
        "evidence-protection-activation-v1",
        "evidence-protection-resume-v1",
    ] {
        refused(&serde_json::json!({"purpose": purpose}));
        let mut malformed = request(purpose);
        malformed["origin"] = serde_json::json!({"pid": "invalid", "creation_filetime": "1"});
        refused(&malformed);
    }
}

#[test]
fn expired_backup_activation_and_resume_fail_before_windows_operations() {
    for purpose in [
        "evidence-key-backup-v1",
        "evidence-protection-activation-v1",
        "evidence-protection-resume-v1",
    ] {
        refused(&request(purpose));
    }
}

#[test]
fn nil_or_malformed_ticket_is_refused_without_privilege_or_ipc_calls() {
    for purpose in [
        "evidence-key-backup-v1",
        "evidence-protection-activation-v1",
    ] {
        for ticket in ["00000000-0000-0000-0000-000000000000", "invalid"] {
            let mut value = request(purpose);
            value["ticket_id"] = ticket.into();
            refused(&value);
        }
    }
}

#[test]
fn recognized_requests_reject_injected_authorization_fields() {
    for purpose in [
        "evidence-key-backup-v1",
        "evidence-protection-activation-v1",
        "evidence-protection-resume-v1",
    ] {
        let mut value = request(purpose);
        value["authorized"] = true.into();
        refused(&value);
        let mut value = request(purpose);
        value["origin"]["elevated"] = true.into();
        refused(&value);
    }
}
