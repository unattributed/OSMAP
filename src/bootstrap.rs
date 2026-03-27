//! Early bootstrap logic for the OSMAP executable.
//!
//! The goal here is not to implement the mail service yet. The goal is to make
//! the repository executable, testable, and ready for later vertical slices.

use crate::config::AppConfig;
use crate::error::BootstrapError;

/// A non-secret summary of the runtime state that can be emitted at startup.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct BootstrapReport {
    pub environment: String,
    pub listen_addr: String,
    pub state_dir: String,
    pub log_level: String,
}

impl BootstrapReport {
    /// Formats the startup summary as a single operator-readable line.
    pub fn as_log_line(&self) -> String {
        format!(
            "osmap bootstrap ready env={} listen_addr={} state_dir={} log_level={}",
            self.environment, self.listen_addr, self.state_dir, self.log_level
        )
    }
}

/// Loads configuration and returns a report describing the runtime shape.
pub fn bootstrap() -> Result<BootstrapReport, BootstrapError> {
    let config = AppConfig::from_process_env()?;
    Ok(report_from_config(&config))
}

/// Converts validated configuration into the startup report used by the binary.
fn report_from_config(config: &AppConfig) -> BootstrapReport {
    BootstrapReport {
        environment: config.environment.clone(),
        listen_addr: config.listen_addr.clone(),
        state_dir: config.state_dir.clone(),
        log_level: config.log_level.clone(),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn startup_report_is_operator_readable() {
        let config = AppConfig {
            environment: "development".to_string(),
            listen_addr: "127.0.0.1:8080".to_string(),
            state_dir: "/var/lib/osmap".to_string(),
            log_level: "info".to_string(),
        };

        let report = report_from_config(&config);

        assert_eq!(
            report.as_log_line(),
            "osmap bootstrap ready env=development listen_addr=127.0.0.1:8080 state_dir=/var/lib/osmap log_level=info"
        );
    }
}
