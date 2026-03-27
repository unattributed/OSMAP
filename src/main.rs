//! Binary entrypoint for the OSMAP proof-of-concept skeleton.
//!
//! The executable now supports two modes:
//! - `bootstrap`, which validates startup configuration and exits
//! - `serve`, which starts the current bounded HTTP/browser slice

use std::process::ExitCode;

fn main() -> ExitCode {
    match osmap::bootstrap::bootstrap() {
        Ok(context) => {
            context.logger.emit(&context.report.to_log_event());
            match context.config.run_mode {
                osmap::config::AppRunMode::Bootstrap => ExitCode::SUCCESS,
                osmap::config::AppRunMode::Serve => {
                    match osmap::http::run_http_server(&context.config, &context.logger) {
                        Ok(()) => ExitCode::SUCCESS,
                        Err(error) => {
                            eprintln!("osmap http server failed: {error}");
                            ExitCode::FAILURE
                        }
                    }
                }
            }
        }
        Err(error) => {
            eprintln!("osmap bootstrap failed: {error}");
            ExitCode::FAILURE
        }
    }
}
