#![forbid(unsafe_code)]

#[cfg(windows)]
mod runtime;

#[cfg(windows)]
fn main() -> std::process::ExitCode {
    let result = if std::env::args().skip(1).eq(["--configure-recovery"]) {
        piko_win_platform::service::configure_recovery_policy()
            .map_err(|e| Box::new(e) as Box<dyn std::error::Error>)
    } else if std::env::args().nth(1).as_deref() == Some("--verify-evidence") {
        runtime::verify_evidence()
    } else if std::env::args().nth(1).as_deref() == Some("--compact-evidence") {
        runtime::compact_evidence()
    } else if std::env::args().nth(1).as_deref() == Some("--remove-noise") {
        runtime::remove_noise()
    } else if std::env::args().any(|arg| arg == "--service") {
        piko_win_platform::service::dispatch(service_entry)
            .map_err(|e| Box::new(e) as Box<dyn std::error::Error>)
    } else {
        run(None)
    };
    match result {
        Ok(()) => std::process::ExitCode::SUCCESS,
        Err(error) => {
            eprintln!(
                "{}",
                serde_json::json!({"level":"error","component":"piko.runtime","message":error.to_string()})
            );
            std::process::ExitCode::FAILURE
        }
    }
}

#[cfg(windows)]
fn run(
    context: Option<piko_win_platform::service::ServiceContext>,
) -> Result<(), Box<dyn std::error::Error>> {
    tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()?
        .block_on(runtime::run(context))
}

#[cfg(windows)]
fn service_entry(context: piko_win_platform::service::ServiceContext) -> u32 {
    match run(Some(context)) {
        Ok(()) => 0,
        Err(error) => {
            let message = format!("piko service failed: {error}");
            let _ = piko_win_platform::event_log::report_diagnostic(&message, true);
            eprintln!("{message}");
            1
        }
    }
}

#[cfg(not(windows))]
fn main() -> std::process::ExitCode {
    eprintln!("piko-service requires Windows x86-64");
    std::process::ExitCode::FAILURE
}
