//! Binary entrypoint for the OSMAP proof-of-concept skeleton.
//!
//! The executable currently performs only bootstrap validation and startup
//! reporting. Later work packages will replace this with a real runtime while
//! preserving the same conservative configuration discipline.

use std::process::ExitCode;

fn main() -> ExitCode {
    match osmap::bootstrap::bootstrap() {
        Ok(report) => {
            eprintln!("{}", report.as_log_line());
            ExitCode::SUCCESS
        }
        Err(error) => {
            eprintln!("osmap bootstrap failed: {error}");
            ExitCode::FAILURE
        }
    }
}
