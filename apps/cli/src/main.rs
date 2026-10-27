#![forbid(unsafe_code)]

use piko_event_storage::EventQuery;
use piko_ipc::{ApiData, Command};

#[tokio::main(flavor = "current_thread")]
async fn main() -> std::process::ExitCode {
    match run().await {
        Ok(()) => std::process::ExitCode::SUCCESS,
        Err(error) => {
            eprintln!("piko: {error}");
            std::process::ExitCode::FAILURE
        }
    }
}

async fn run() -> Result<(), Box<dyn std::error::Error>> {
    let args: Vec<String> = std::env::args().skip(1).collect();
    if args.first().map(String::as_str) == Some("signature") && args.len() == 2 {
        let result = piko_app_control::executable_signature(&args[1])?;
        println!("{}", serde_json::to_string(&result)?);
        return Ok(());
    }
    let command = match args.first().map(String::as_str) {
        Some("alerts") if args.len() == 1 => Command::ListAlerts,
        Some("actions") if args.len() == 1 => Command::GetResponseStatus,
        Some("quarantine-plan") if args.len() == 2 => Command::PrepareQuarantine {
            path: args[1].clone(),
        },
        Some("restore-plan") if args.len() == 2 => Command::PrepareRestore {
            action_id: args[1].parse()?,
        },
        Some("confirm") if args.len() == 3 => Command::ExecuteAction {
            action_id: args[1].parse()?,
            expected_sha256: args[2].clone(),
        },
        Some("health") if args.len() == 1 => Command::GetHealth,
        Some("maintenance") if args.len() == 1 => Command::GetArchiveMaintenance,
        Some("evidence-key-status") if args.len() == 1 => Command::GetEvidenceKeyStatus,
        Some("observations") if args.len() == 1 => Command::GetObservations,
        Some("investigate") if args.len() == 2 => Command::GetInvestigation {
            process_instance: args[1].parse()?,
        },
        Some("verify") if args.len() == 1 => Command::VerifyStore,
        Some("evidence") if args.len() == 2 => Command::GetEvidence {
            evidence_id: args[1].parse()?,
        },
        Some("query") if args.len() == 2 => Command::ListEvents(EventQuery {
            expression: Some(args[1].clone()),
            ..EventQuery::default()
        }),
        Some("events") if args.len() <= 2 => {
            let mut query = EventQuery::default();
            if let Some(search) = args.get(1) {
                query.search = Some(search.clone());
            }
            Command::ListEvents(query)
        }
        Some("identity") if args.len() == 1 => {
            Command::GetAuthenticationActivity(Default::default())
        }
        None | Some("--help") | Some("help") => {
            println!("piko — local security\n\n  piko health\n  piko signature <absolute-exe-path>\n  piko observations\n  piko identity\n  piko events [search]\n  piko query <expression>\n  piko investigate <process-instance-UUID>\n  piko evidence <UUID>\n  piko verify\n  piko alerts\n  piko actions\n  piko quarantine-plan <absolute-file-path>\n  piko restore-plan <quarantine-UUID>\n  piko confirm <plan-UUID> <preview-SHA256>\n\nPlans expire after 5 minutes. Confirmation executes the precise previewed action.\nService mutations require an elevated administrator and configured response_roots.");
            println!(
                "  piko maintenance    Last automatic archive-maintenance outcome (read-only)"
            );
            println!("  piko evidence-key-status    Recovery-key and activation status (read-only; no secrets)");
            return Ok(());
        }
        _ => return Err("invalid arguments; use piko --help".into()),
    };
    let data = piko_ipc::call(command).await?;
    let json = match data {
        ApiData::Alerts(value) => serde_json::to_string_pretty(&value)?,
        ApiData::Action(value) => serde_json::to_string_pretty(&value)?,
        ApiData::ResponseStatus(value) => serde_json::to_string_pretty(&value)?,
        ApiData::Health(value) => serde_json::to_string_pretty(&value)?,
        ApiData::ArchiveMaintenance(value) => serde_json::to_string_pretty(&value)?,
        ApiData::EvidenceKeyStatus(value) => serde_json::to_string_pretty(&value)?,
        ApiData::KeyBackupTicket(_)
        | ApiData::KeyBackup(_)
        | ApiData::EvidenceProtectionTicket(_) => {
            return Err("evidence-key mutations are restricted to the guided desktop flow".into())
        }
        ApiData::Observations(value) => serde_json::to_string_pretty(&value)?,
        ApiData::Investigation(value) => serde_json::to_string_pretty(&value)?,
        ApiData::Events(value) => serde_json::to_string_pretty(&value)?,
        ApiData::AuthenticationActivity(value) => serde_json::to_string_pretty(&value)?,
        ApiData::Integrity(value) => serde_json::to_string_pretty(&value)?,
        ApiData::Evidence(value) => serde_json::to_string_pretty(&value)?,
    };
    println!("{json}");
    Ok(())
}
