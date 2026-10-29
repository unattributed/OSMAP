//! Operator recovery entrypoint; no browser credentials or selected paths.
fn main() -> std::process::ExitCode {
    match osmap::account_recovery_operator::run_cli() {
        Ok(()) => std::process::ExitCode::SUCCESS,
        Err(error) => {
            // Fixed enum only: never print arbitrary OS/native diagnostics.
            eprintln!("account_recovery outcome={error:?} automatic_retry=false");
            std::process::ExitCode::FAILURE
        }
    }
}
