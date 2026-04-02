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
    pub run_mode: String,
    pub environment: String,
    pub listen_addr: String,
    pub doveadm_auth_socket_path: String,
    pub doveadm_userdb_socket_path: String,
    pub mailbox_helper_socket_path: String,
    pub openbsd_confinement_mode: String,
    pub state_root: String,
    pub runtime_dir: String,
    pub session_dir: String,
    pub audit_dir: String,
    pub cache_dir: String,
    pub totp_secret_dir: String,
    pub log_level: String,
    pub log_format: String,
    pub session_lifetime_seconds: String,
    pub totp_allowed_skew_steps: String,
    pub login_throttle_max_failures: String,
    pub login_throttle_window_seconds: String,
    pub login_throttle_lockout_seconds: String,
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
        .with_field("run_mode", self.run_mode.clone())
        .with_field("env", self.environment.clone())
        .with_field("listen_addr", self.listen_addr.clone())
        .with_field(
            "doveadm_auth_socket_path",
            self.doveadm_auth_socket_path.clone(),
        )
        .with_field(
            "doveadm_userdb_socket_path",
            self.doveadm_userdb_socket_path.clone(),
        )
        .with_field(
            "mailbox_helper_socket_path",
            self.mailbox_helper_socket_path.clone(),
        )
        .with_field(
            "openbsd_confinement_mode",
            self.openbsd_confinement_mode.clone(),
        )
        .with_field("state_root", self.state_root.clone())
        .with_field("runtime_dir", self.runtime_dir.clone())
        .with_field("session_dir", self.session_dir.clone())
        .with_field("audit_dir", self.audit_dir.clone())
        .with_field("cache_dir", self.cache_dir.clone())
        .with_field("totp_secret_dir", self.totp_secret_dir.clone())
        .with_field("log_level", self.log_level.clone())
        .with_field("log_format", self.log_format.clone())
        .with_field(
            "session_lifetime_seconds",
            self.session_lifetime_seconds.clone(),
        )
        .with_field(
            "totp_allowed_skew_steps",
            self.totp_allowed_skew_steps.clone(),
        )
        .with_field(
            "login_throttle_max_failures",
            self.login_throttle_max_failures.clone(),
        )
        .with_field(
            "login_throttle_window_seconds",
            self.login_throttle_window_seconds.clone(),
        )
        .with_field(
            "login_throttle_lockout_seconds",
            self.login_throttle_lockout_seconds.clone(),
        )
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
        run_mode: config.run_mode.as_str().to_string(),
        environment: config.environment.as_str().to_string(),
        listen_addr: config.listen_addr.clone(),
        doveadm_auth_socket_path: config
            .doveadm_auth_socket_path
            .as_ref()
            .map(|path| path.display().to_string())
            .unwrap_or_default(),
        doveadm_userdb_socket_path: config
            .doveadm_userdb_socket_path
            .as_ref()
            .map(|path| path.display().to_string())
            .unwrap_or_default(),
        mailbox_helper_socket_path: config
            .mailbox_helper_socket_path
            .as_ref()
            .map(|path| path.display().to_string())
            .unwrap_or_default(),
        openbsd_confinement_mode: config.openbsd_confinement_mode.as_str().to_string(),
        state_root: config.state_root.display().to_string(),
        runtime_dir: config.state_layout.runtime_dir.display().to_string(),
        session_dir: config.state_layout.session_dir.display().to_string(),
        audit_dir: config.state_layout.audit_dir.display().to_string(),
        cache_dir: config.state_layout.cache_dir.display().to_string(),
        totp_secret_dir: config.state_layout.totp_secret_dir.display().to_string(),
        log_level: config.log_level.as_str().to_string(),
        log_format: config.log_format.as_str().to_string(),
        session_lifetime_seconds: config.session_lifetime_seconds.to_string(),
        totp_allowed_skew_steps: config.totp_allowed_skew_steps.to_string(),
        login_throttle_max_failures: config.login_throttle_max_failures.to_string(),
        login_throttle_window_seconds: config.login_throttle_window_seconds.to_string(),
        login_throttle_lockout_seconds: config.login_throttle_lockout_seconds.to_string(),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::config::{AppRunMode, LogFormat, LogLevel, RuntimeEnvironment};
    use crate::state::StateLayout;
    use std::path::PathBuf;

    #[test]
    fn startup_report_is_operator_readable() {
        let config = AppConfig {
            run_mode: AppRunMode::Bootstrap,
            environment: RuntimeEnvironment::Development,
            listen_addr: "127.0.0.1:8080".to_string(),
            doveadm_auth_socket_path: Some(PathBuf::from("/var/run/osmap/dovecot-auth")),
            doveadm_userdb_socket_path: Some(PathBuf::from("/var/run/osmap/dovecot-userdb")),
            mailbox_helper_socket_path: Some(PathBuf::from(
                "/var/lib/osmap/run/mailbox-helper.sock",
            )),
            openbsd_confinement_mode: crate::config::OpenbsdConfinementMode::Disabled,
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
            session_lifetime_seconds: 43200,
            totp_allowed_skew_steps: 1,
            login_throttle_max_failures: 5,
            login_throttle_window_seconds: 300,
            login_throttle_lockout_seconds: 900,
        };

        let report = report_from_config(&config);

        assert_eq!(
            report.to_log_event().fields,
            vec![
                crate::logging::LogField {
                    key: "run_mode",
                    value: "bootstrap".to_string(),
                },
                crate::logging::LogField {
                    key: "env",
                    value: "development".to_string(),
                },
                crate::logging::LogField {
                    key: "listen_addr",
                    value: "127.0.0.1:8080".to_string(),
                },
                crate::logging::LogField {
                    key: "doveadm_auth_socket_path",
                    value: "/var/run/osmap/dovecot-auth".to_string(),
                },
                crate::logging::LogField {
                    key: "doveadm_userdb_socket_path",
                    value: "/var/run/osmap/dovecot-userdb".to_string(),
                },
                crate::logging::LogField {
                    key: "mailbox_helper_socket_path",
                    value: "/var/lib/osmap/run/mailbox-helper.sock".to_string(),
                },
                crate::logging::LogField {
                    key: "openbsd_confinement_mode",
                    value: "disabled".to_string(),
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
                    key: "session_lifetime_seconds",
                    value: "43200".to_string(),
                },
                crate::logging::LogField {
                    key: "totp_allowed_skew_steps",
                    value: "1".to_string(),
                },
                crate::logging::LogField {
                    key: "login_throttle_max_failures",
                    value: "5".to_string(),
                },
                crate::logging::LogField {
                    key: "login_throttle_window_seconds",
                    value: "300".to_string(),
                },
                crate::logging::LogField {
                    key: "login_throttle_lockout_seconds",
                    value: "900".to_string(),
                },
            ]
        );
    }
}
