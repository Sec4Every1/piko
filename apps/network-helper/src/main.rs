#![forbid(unsafe_code)]
#![cfg_attr(not(debug_assertions), windows_subsystem = "windows")]
#[cfg(windows)]
mod evidence_keys;

fn main() -> std::process::ExitCode {
    let mut args = std::env::args().skip(1);
    let Some(payload) = args.next() else {
        return std::process::ExitCode::from(2);
    };
    if args.next().is_some() {
        return std::process::ExitCode::from(2);
    }
    #[cfg(windows)]
    let key_result = if payload == "--resume-evidence-protection" {
        Some(evidence_keys::resume_activation())
    } else {
        evidence_keys::try_authorize(&payload)
    };
    #[cfg(not(windows))]
    let key_result: Option<std::io::Result<()>> = None;
    let (operation, result) = match key_result {
        Some(result) => ("evidence key operation", result),
        None => ("network action", piko_app_control::execute_helper(&payload)),
    };
    match result {
        Ok(()) => std::process::ExitCode::SUCCESS,
        Err(error) => {
            let _ = piko_win_platform::event_log::report_diagnostic(
                &format!(
                    "piko {operation} failed: {}",
                    error.to_string().chars().take(2000).collect::<String>()
                ),
                true,
            );
            std::process::ExitCode::from(1)
        }
    }
}
