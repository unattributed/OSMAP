//! Fixed Rust account-service entry. No config or credential arguments.
fn main() -> std::process::ExitCode {
    let result = if std::env::args_os().len() == 1 {
        osmap::openbsd::AccountAdmissionSignals::install()
            .map_err(|_| osmap::account_admission::Error::Unavailable)
            .and_then(|signals| {
                osmap::account_password_server::run_operator_service(signals.stop_flag())
            })
    } else {
        Err(osmap::account_admission::Error::Invalid)
    };
    if result.is_ok() {
        std::process::ExitCode::SUCCESS
    } else {
        eprintln!("Account password service unavailable.");
        std::process::ExitCode::FAILURE
    }
}
