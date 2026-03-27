//! Early bootstrap logic for the OSMAP executable.
//!
//! The goal here is not to implement the mail service yet. The goal is to make
//! the repository executable, testable, and ready for later vertical slices.

use crate::config::AppConfig;
use crate::error::BootstrapError;
use crate::logging::{EventCategory, LogEvent, Logger};

/// A non-secret summary of the runtime state that can be emitted at startup.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct BootstrapReport {
    pub environment: String,
    pub listen_addr: String,
    pub state_root: String,
    pub runtime_dir: String,
    pub session_dir: String,
    pub audit_dir: String,
    pub cache_dir: String,
    pub totp_secret_dir: String,
    pub log_level: String,
    pub log_format: String,
    pub totp_allowed_skew_steps: String,
}

impl BootstrapReport {
    /// Builds a structured startup event that excludes secret-bearing values.
    pub fn to_log_event(&self) -> LogEvent {
        LogEvent::new(
            crate::config::LogLevel::Info,
            EventCategory::Bootstrap,
            "startup_ready",
            "bootstrap completed",
        )
        .with_field("env", self.environment.clone())
        .with_field("listen_addr", self.listen_addr.clone())
        .with_field("state_root", self.state_root.clone())
        .with_field("runtime_dir", self.runtime_dir.clone())
        .with_field("session_dir", self.session_dir.clone())
        .with_field("audit_dir", self.audit_dir.clone())
        .with_field("cache_dir", self.cache_dir.clone())
        .with_field("totp_secret_dir", self.totp_secret_dir.clone())
        .with_field("log_level", self.log_level.clone())
        .with_field("log_format", self.log_format.clone())
        .with_field("totp_allowed_skew_steps", self.totp_allowed_skew_steps.clone())
    }
}

/// Holds the early runtime objects created during bootstrap.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct BootstrapContext {
    pub config: AppConfig,
    pub logger: Logger,
    pub report: BootstrapReport,
}

/// Loads configuration and runtime helpers for the current process.
pub fn bootstrap() -> Result<BootstrapContext, BootstrapError> {
    let config = AppConfig::from_process_env()?;
    let logger = Logger::new(config.log_format, config.log_level);
    let report = report_from_config(&config);

    Ok(BootstrapContext {
        config,
        logger,
        report,
    })
}

/// Converts validated configuration into the startup report used by the binary.
fn report_from_config(config: &AppConfig) -> BootstrapReport {
    BootstrapReport {
        environment: config.environment.as_str().to_string(),
        listen_addr: config.listen_addr.clone(),
        state_root: config.state_root.display().to_string(),
        runtime_dir: config.state_layout.runtime_dir.display().to_string(),
        session_dir: config.state_layout.session_dir.display().to_string(),
        audit_dir: config.state_layout.audit_dir.display().to_string(),
        cache_dir: config.state_layout.cache_dir.display().to_string(),
        totp_secret_dir: config.state_layout.totp_secret_dir.display().to_string(),
        log_level: config.log_level.as_str().to_string(),
        log_format: config.log_format.as_str().to_string(),
        totp_allowed_skew_steps: config.totp_allowed_skew_steps.to_string(),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::config::{LogFormat, LogLevel, RuntimeEnvironment};
    use crate::state::StateLayout;
    use std::path::PathBuf;

    #[test]
    fn startup_report_is_operator_readable() {
        let config = AppConfig {
            environment: RuntimeEnvironment::Development,
            listen_addr: "127.0.0.1:8080".to_string(),
            state_root: PathBuf::from("/var/lib/osmap"),
            log_level: LogLevel::Info,
            log_format: LogFormat::Text,
            state_layout: StateLayout::new(
                PathBuf::from("/var/lib/osmap"),
                PathBuf::from("/var/lib/osmap/run"),
                PathBuf::from("/var/lib/osmap/sessions"),
                PathBuf::from("/var/lib/osmap/audit"),
                PathBuf::from("/var/lib/osmap/cache"),
                PathBuf::from("/var/lib/osmap/secrets/totp"),
            )
            .expect("layout should be valid"),
            totp_allowed_skew_steps: 1,
        };

        let report = report_from_config(&config);

        assert_eq!(
            report.to_log_event().fields,
            vec![
                crate::logging::LogField {
                    key: "env",
                    value: "development".to_string(),
                },
                crate::logging::LogField {
                    key: "listen_addr",
                    value: "127.0.0.1:8080".to_string(),
                },
                crate::logging::LogField {
                    key: "state_root",
                    value: "/var/lib/osmap".to_string(),
                },
                crate::logging::LogField {
                    key: "runtime_dir",
                    value: "/var/lib/osmap/run".to_string(),
                },
                crate::logging::LogField {
                    key: "session_dir",
                    value: "/var/lib/osmap/sessions".to_string(),
                },
                crate::logging::LogField {
                    key: "audit_dir",
                    value: "/var/lib/osmap/audit".to_string(),
                },
                crate::logging::LogField {
                    key: "cache_dir",
                    value: "/var/lib/osmap/cache".to_string(),
                },
                crate::logging::LogField {
                    key: "totp_secret_dir",
                    value: "/var/lib/osmap/secrets/totp".to_string(),
                },
                crate::logging::LogField {
                    key: "log_level",
                    value: "info".to_string(),
                },
                crate::logging::LogField {
                    key: "log_format",
                    value: "text".to_string(),
                },
                crate::logging::LogField {
                    key: "totp_allowed_skew_steps",
                    value: "1".to_string(),
                },
            ]
        );
    }
}
