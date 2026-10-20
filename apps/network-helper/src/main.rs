#![forbid(unsafe_code)]
#![cfg_attr(not(debug_assertions), windows_subsystem = "windows")]

fn main() -> std::process::ExitCode {
    let mut args = std::env::args().skip(1);
    let Some(payload) = args.next() else {
        return std::process::ExitCode::from(2);
    };
    if args.next().is_some() {
        return std::process::ExitCode::from(2);
    }
    match piko_app_control::execute_helper(&payload) {
        Ok(()) => std::process::ExitCode::SUCCESS,
        Err(error) => {
            let _ = piko_win_platform::event_log::report_diagnostic(
                &format!(
                    "piko network action failed: {}",
                    error.to_string().chars().take(2000).collect::<String>()
                ),
                true,
            );
            std::process::ExitCode::from(1)
        }
    }
}
