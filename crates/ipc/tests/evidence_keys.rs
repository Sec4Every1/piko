//! Wire/input boundaries only; these tests do not authorize real key access.
use piko_ipc::{Command, SecretText};
use std::error::Error;
use uuid::Uuid;

#[test]
fn secret_input_has_explicit_bounds_and_redacted_debug() -> Result<(), Box<dyn Error>> {
    for invalid in [String::new(), "x".repeat(129), "é".into()] {
        assert!(SecretText::new(invalid).is_err());
    }
    let text = "synthetic-secret-input";
    let secret = SecretText::new(text.into())?;
    assert!(!format!("{secret:?}").contains(text));
    let wire = serde_json::to_vec(&secret)?;
    let decoded: SecretText = serde_json::from_slice(&wire)?;
    assert!(decoded.expose() == text);
    assert!(SecretText::new("x".repeat(128)).is_ok());
    Ok(())
}

#[test]
fn backup_and_activation_authorizations_remain_distinct_mutations() -> Result<(), Box<dyn Error>> {
    let ticket_id = Uuid::from_u128(1);
    for command in [
        Command::AuthorizeKeyBackup { ticket_id },
        Command::AuthorizeEvidenceProtection { ticket_id },
    ] {
        assert!(command.is_key_command());
        assert!(command.is_response_mutation());
        let encoded = serde_json::to_vec(&command)?;
        let decoded: Command = serde_json::from_slice(&encoded)?;
        assert!(decoded.is_key_command() && decoded.is_response_mutation());
    }
    for command in [
        Command::GetEvidenceKeyStatus,
        Command::BeginKeyBackup,
        Command::BeginEvidenceProtection,
    ] {
        assert!(command.is_key_command());
        assert!(!command.is_response_mutation());
    }
    Ok(())
}

#[test]
fn invalid_secret_and_injected_command_fields_are_refused_without_secret_echo() {
    let oversized = "synthetic-secret-".repeat(10);
    let encoded = format!("\"{oversized}\"");
    let result = serde_json::from_str::<SecretText>(&encoded);
    let Err(error) = result else {
        panic!("oversized secret was accepted")
    };
    assert!(!error.to_string().contains(&oversized));
    for command in [
        r#"{"action":"begin_key_backup","activate":true}"#,
        r#"{"action":"authorize_evidence_protection","filter":{"ticket_id":"00000000-0000-0000-0000-000000000001","activate":true}}"#,
        r#"{"action":"confirm_key_backup","filter":{"ticket_id":"00000000-0000-0000-0000-000000000001","code":""}}"#,
    ] {
        assert!(serde_json::from_str::<Command>(command).is_err());
    }
}
