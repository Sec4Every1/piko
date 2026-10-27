#![forbid(unsafe_code)]

#[cfg(windows)]
mod runtime;

#[cfg(windows)]
fn main() -> std::process::ExitCode {
    let result = if std::env::args().skip(1).eq(["--configure-recovery"]) {
        piko_win_platform::service::configure_recovery_policy()
            .map_err(|e| Box::new(e) as Box<dyn std::error::Error>)
    } else if std::env::args().skip(1).eq(["--key-recovery-capabilities"]) {
        println!(
            "{}",
            serde_json::json!({"protocol":1,"service_key_recovery":true,"report_version":1,"normal_start_guard":true})
        );
        Ok(())
    } else if std::env::args().skip(1).eq(["--archive-capabilities"]) {
        runtime::archive_capabilities();
        Ok(())
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
    let maintenance = context.start_arguments.len() > 1;
    let result = if maintenance
        && context
            .start_arguments
            .get(1)
            .is_some_and(|arg| arg == "--recover-evidence-key")
    {
        runtime::recover_service_keys(context)
    } else if maintenance {
        runtime::verify_service_archive(context)
    } else if context
        .start_arguments
        .first()
        .and_then(|name| name.to_str())
        .is_some_and(|name| name.eq_ignore_ascii_case(piko_win_platform::service::SERVICE_NAME))
    {
        run(Some(context))
    } else {
        Err("missing or invalid SCM service identity argument".into())
    };
    match result {
        Ok(()) => 0,
        Err(error) => {
            let message = format!("piko service failed: {error}");
            let _ = piko_win_platform::event_log::report_diagnostic(&message, true);
            eprintln!("{message}");
            // Do not auto-restart a completed/refused maintenance diagnostic as
            // a normal collector. A durable guard also covers process crashes.
            if maintenance {
                0
            } else {
                1
            }
        }
    }
}

#[cfg(not(windows))]
fn main() -> std::process::ExitCode {
    eprintln!("piko-service requires Windows x86-64");
    std::process::ExitCode::FAILURE
}
