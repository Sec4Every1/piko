#![forbid(unsafe_code)]
fn main() -> Result<(), Box<dyn std::error::Error>> {
    let token = std::env::args().nth(1).ok_or("missing test token")?;
    if token.len() > 128 || !token.chars().all(|c| c.is_ascii_alphanumeric() || c == '-') {
        return Err("invalid test token".into());
    }
    piko_win_platform::event_log::report_diagnostic(
        &format!("piko harmless telemetry self-test {token}"),
        false,
    )?;
    Ok(())
}
