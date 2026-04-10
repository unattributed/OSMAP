//! Binary entrypoint for the OSMAP proof-of-concept skeleton.
//!
//! The executable now supports three modes:
//! - `bootstrap`, which validates startup configuration and exits
//! - `serve`, which starts the current bounded HTTP/browser slice
//! - `mailbox-helper`, which serves the first local mailbox-read helper slice

use std::env;
use std::process::ExitCode;

fn main() -> ExitCode {
    if let Err(message) = apply_cli_run_mode_override() {
        eprintln!("{message}");
        return ExitCode::FAILURE;
    }

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
                osmap::config::AppRunMode::MailboxHelper => {
                    match osmap::mailbox_helper::run_mailbox_helper_server(
                        &context.config,
                        &context.logger,
                    ) {
                        Ok(()) => ExitCode::SUCCESS,
                        Err(error) => {
                            eprintln!("osmap mailbox helper failed: {error}");
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

fn apply_cli_run_mode_override() -> Result<(), String> {
    let mut args = env::args();
    let program = args.next().unwrap_or_else(|| "osmap".to_string());
    let Some(run_mode) = args.next() else {
        return Ok(());
    };

    if matches!(run_mode.as_str(), "-h" | "--help") {
        return Err(usage_message(&program));
    }

    if args.next().is_some() {
        return Err(usage_message(&program));
    }

    if !matches!(run_mode.as_str(), "bootstrap" | "serve" | "mailbox-helper") {
        return Err(format!(
            "unsupported run mode argument: {run_mode}\n{}",
            usage_message(&program)
        ));
    }

    env::set_var("OSMAP_RUN_MODE", run_mode);
    Ok(())
}

fn usage_message(program: &str) -> String {
    format!("usage: {program} [bootstrap|serve|mailbox-helper]")
}

#[cfg(test)]
mod tests {
    use super::usage_message;

    #[test]
    fn usage_message_lists_supported_run_modes() {
        assert_eq!(
            usage_message("osmap"),
            "usage: osmap [bootstrap|serve|mailbox-helper]"
        );
    }
}
