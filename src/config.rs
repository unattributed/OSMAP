//! Configuration loading for the early OSMAP skeleton.
//!
//! The bootstrap keeps configuration intentionally small:
//! - values come from the environment
//! - defaults are conservative and loopback-bound
//! - secrets are expected to be supplied out-of-band by operators later

use std::collections::BTreeMap;
use std::env;
use std::path::{Path, PathBuf};

use crate::error::BootstrapError;
use crate::state::StateLayout;
use crate::throttle::{
    DEFAULT_LOGIN_THROTTLE_LOCKOUT_SECONDS, DEFAULT_LOGIN_THROTTLE_MAX_FAILURES,
    DEFAULT_LOGIN_THROTTLE_REMOTE_MAX_FAILURES, DEFAULT_LOGIN_THROTTLE_WINDOW_SECONDS,
    DEFAULT_MESSAGE_MOVE_THROTTLE_LOCKOUT_SECONDS, DEFAULT_MESSAGE_MOVE_THROTTLE_MAX_MOVES,
    DEFAULT_MESSAGE_MOVE_THROTTLE_REMOTE_MAX_MOVES, DEFAULT_MESSAGE_MOVE_THROTTLE_WINDOW_SECONDS,
    DEFAULT_SUBMISSION_THROTTLE_LOCKOUT_SECONDS, DEFAULT_SUBMISSION_THROTTLE_MAX_SUBMISSIONS,
    DEFAULT_SUBMISSION_THROTTLE_REMOTE_MAX_SUBMISSIONS, DEFAULT_SUBMISSION_THROTTLE_WINDOW_SECONDS,
};

/// Runtime configuration that is safe to print in operator-facing startup
/// output because it excludes secret-bearing fields.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct AppConfig {
    pub run_mode: AppRunMode,
    pub environment: RuntimeEnvironment,
    pub listen_addr: String,
    pub doveadm_auth_socket_path: Option<PathBuf>,
    pub doveadm_userdb_socket_path: Option<PathBuf>,
    pub mailbox_helper_socket_path: Option<PathBuf>,
    pub state_root: PathBuf,
    pub log_level: LogLevel,
    pub log_format: LogFormat,
    pub state_layout: StateLayout,
    pub session_lifetime_seconds: u64,
    pub totp_allowed_skew_steps: i64,
    pub login_throttle_max_failures: u64,
    pub login_throttle_remote_max_failures: u64,
    pub login_throttle_window_seconds: u64,
    pub login_throttle_lockout_seconds: u64,
    pub submission_throttle_max_submissions: u64,
    pub submission_throttle_remote_max_submissions: u64,
    pub submission_throttle_window_seconds: u64,
    pub submission_throttle_lockout_seconds: u64,
    pub message_move_throttle_max_moves: u64,
    pub message_move_throttle_remote_max_moves: u64,
    pub message_move_throttle_window_seconds: u64,
    pub message_move_throttle_lockout_seconds: u64,
    pub openbsd_confinement_mode: OpenbsdConfinementMode,
}

/// Controls whether the binary only validates startup or actually serves HTTP.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum AppRunMode {
    Bootstrap,
    Serve,
    MailboxHelper,
}

impl AppRunMode {
    /// Parses the run-mode string from configuration.
    fn parse(value: &str) -> Result<Self, BootstrapError> {
        match value {
            "bootstrap" => Ok(Self::Bootstrap),
            "serve" => Ok(Self::Serve),
            "mailbox-helper" => Ok(Self::MailboxHelper),
            _ => Err(BootstrapError::UnsupportedValue {
                field: "OSMAP_RUN_MODE",
                value: value.to_string(),
                expected: "bootstrap, serve, or mailbox-helper",
            }),
        }
    }

    /// Returns the canonical string representation used in logs and docs.
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Bootstrap => "bootstrap",
            Self::Serve => "serve",
            Self::MailboxHelper => "mailbox-helper",
        }
    }
}

/// Enumerates the supported runtime environments for the early prototype.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum RuntimeEnvironment {
    Development,
    Staging,
    Production,
}

impl RuntimeEnvironment {
    /// Parses the environment string from configuration.
    fn parse(value: &str) -> Result<Self, BootstrapError> {
        match value {
            "development" => Ok(Self::Development),
            "staging" => Ok(Self::Staging),
            "production" => Ok(Self::Production),
            _ => Err(BootstrapError::UnsupportedValue {
                field: "OSMAP_ENV",
                value: value.to_string(),
                expected: "development, staging, or production",
            }),
        }
    }

    /// Returns the canonical string representation used in logs and docs.
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Development => "development",
            Self::Staging => "staging",
            Self::Production => "production",
        }
    }
}

/// Controls the minimum event severity emitted by the application logger.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
pub enum LogLevel {
    Debug,
    Info,
    Warn,
    Error,
}

impl LogLevel {
    /// Parses the log level string from configuration.
    fn parse(value: &str) -> Result<Self, BootstrapError> {
        match value {
            "debug" => Ok(Self::Debug),
            "info" => Ok(Self::Info),
            "warn" => Ok(Self::Warn),
            "error" => Ok(Self::Error),
            _ => Err(BootstrapError::UnsupportedValue {
                field: "OSMAP_LOG_LEVEL",
                value: value.to_string(),
                expected: "debug, info, warn, or error",
            }),
        }
    }

    /// Returns the canonical string representation used in logs.
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Debug => "debug",
            Self::Info => "info",
            Self::Warn => "warn",
            Self::Error => "error",
        }
    }
}

/// Describes the operator-facing log line encoding.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum LogFormat {
    Text,
}

impl LogFormat {
    /// Parses the log format string from configuration.
    fn parse(value: &str) -> Result<Self, BootstrapError> {
        match value {
            "text" => Ok(Self::Text),
            _ => Err(BootstrapError::UnsupportedValue {
                field: "OSMAP_LOG_FORMAT",
                value: value.to_string(),
                expected: "text",
            }),
        }
    }

    /// Returns the canonical string representation used in logs and docs.
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Text => "text",
        }
    }
}

/// Controls whether OpenBSD-native runtime confinement is disabled, only
/// described in logs, or actively enforced.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum OpenbsdConfinementMode {
    Disabled,
    LogOnly,
    Enforce,
}

impl OpenbsdConfinementMode {
    /// Parses the confinement-mode string from configuration.
    fn parse(value: &str) -> Result<Self, BootstrapError> {
        match value {
            "disabled" => Ok(Self::Disabled),
            "log-only" => Ok(Self::LogOnly),
            "enforce" => Ok(Self::Enforce),
            _ => Err(BootstrapError::UnsupportedValue {
                field: "OSMAP_OPENBSD_CONFINEMENT_MODE",
                value: value.to_string(),
                expected: "disabled, log-only, or enforce",
            }),
        }
    }

    /// Returns the canonical string representation used in logs and docs.
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Disabled => "disabled",
            Self::LogOnly => "log-only",
            Self::Enforce => "enforce",
        }
    }
}

impl AppConfig {
    /// Loads configuration from the current process environment.
    pub fn from_process_env() -> Result<Self, BootstrapError> {
        let env_map = env::vars().collect::<BTreeMap<String, String>>();
        Self::from_env_map(&env_map)
    }

    /// Loads configuration from a caller-supplied key/value map.
    ///
    /// This shape keeps the parser easy to unit test without mutating global
    /// process state.
    pub fn from_env_map(env_map: &BTreeMap<String, String>) -> Result<Self, BootstrapError> {
        let run_mode_value = read_value(env_map, "OSMAP_RUN_MODE", "bootstrap");
        let environment_value = read_value(env_map, "OSMAP_ENV", "development");
        let listen_addr = read_value(env_map, "OSMAP_LISTEN_ADDR", "127.0.0.1:8080");
        let state_root_value = read_value(env_map, "OSMAP_STATE_DIR", "/var/lib/osmap");
        let log_level_value = read_value(env_map, "OSMAP_LOG_LEVEL", "info");
        let log_format_value = read_value(env_map, "OSMAP_LOG_FORMAT", "text");
        let session_lifetime_value = read_value(env_map, "OSMAP_SESSION_LIFETIME_SECS", "43200");
        let totp_skew_steps_value = read_value(env_map, "OSMAP_TOTP_ALLOWED_SKEW_STEPS", "1");
        let login_throttle_max_failures_value = read_value(
            env_map,
            "OSMAP_LOGIN_THROTTLE_MAX_FAILURES",
            &DEFAULT_LOGIN_THROTTLE_MAX_FAILURES.to_string(),
        );
        let login_throttle_window_value = read_value(
            env_map,
            "OSMAP_LOGIN_THROTTLE_WINDOW_SECS",
            &DEFAULT_LOGIN_THROTTLE_WINDOW_SECONDS.to_string(),
        );
        let login_throttle_remote_max_failures_value = read_value(
            env_map,
            "OSMAP_LOGIN_THROTTLE_REMOTE_MAX_FAILURES",
            &DEFAULT_LOGIN_THROTTLE_REMOTE_MAX_FAILURES.to_string(),
        );
        let login_throttle_lockout_value = read_value(
            env_map,
            "OSMAP_LOGIN_THROTTLE_LOCKOUT_SECS",
            &DEFAULT_LOGIN_THROTTLE_LOCKOUT_SECONDS.to_string(),
        );
        let submission_throttle_max_submissions_value = read_value(
            env_map,
            "OSMAP_SUBMISSION_THROTTLE_MAX_SUBMISSIONS",
            &DEFAULT_SUBMISSION_THROTTLE_MAX_SUBMISSIONS.to_string(),
        );
        let submission_throttle_remote_max_submissions_value = read_value(
            env_map,
            "OSMAP_SUBMISSION_THROTTLE_REMOTE_MAX_SUBMISSIONS",
            &DEFAULT_SUBMISSION_THROTTLE_REMOTE_MAX_SUBMISSIONS.to_string(),
        );
        let submission_throttle_window_value = read_value(
            env_map,
            "OSMAP_SUBMISSION_THROTTLE_WINDOW_SECS",
            &DEFAULT_SUBMISSION_THROTTLE_WINDOW_SECONDS.to_string(),
        );
        let submission_throttle_lockout_value = read_value(
            env_map,
            "OSMAP_SUBMISSION_THROTTLE_LOCKOUT_SECS",
            &DEFAULT_SUBMISSION_THROTTLE_LOCKOUT_SECONDS.to_string(),
        );
        let message_move_throttle_max_moves_value = read_value(
            env_map,
            "OSMAP_MESSAGE_MOVE_THROTTLE_MAX_MOVES",
            &DEFAULT_MESSAGE_MOVE_THROTTLE_MAX_MOVES.to_string(),
        );
        let message_move_throttle_remote_max_moves_value = read_value(
            env_map,
            "OSMAP_MESSAGE_MOVE_THROTTLE_REMOTE_MAX_MOVES",
            &DEFAULT_MESSAGE_MOVE_THROTTLE_REMOTE_MAX_MOVES.to_string(),
        );
        let message_move_throttle_window_value = read_value(
            env_map,
            "OSMAP_MESSAGE_MOVE_THROTTLE_WINDOW_SECS",
            &DEFAULT_MESSAGE_MOVE_THROTTLE_WINDOW_SECONDS.to_string(),
        );
        let message_move_throttle_lockout_value = read_value(
            env_map,
            "OSMAP_MESSAGE_MOVE_THROTTLE_LOCKOUT_SECS",
            &DEFAULT_MESSAGE_MOVE_THROTTLE_LOCKOUT_SECONDS.to_string(),
        );
        let openbsd_confinement_mode_value =
            read_value(env_map, "OSMAP_OPENBSD_CONFINEMENT_MODE", "disabled");
        let doveadm_auth_socket_path =
            parse_optional_absolute_optional_path(env_map, "OSMAP_DOVEADM_AUTH_SOCKET_PATH")?;
        let doveadm_userdb_socket_path =
            parse_optional_absolute_optional_path(env_map, "OSMAP_DOVEADM_USERDB_SOCKET_PATH")?;

        validate_non_empty("OSMAP_RUN_MODE", &run_mode_value)?;
        validate_non_empty("OSMAP_ENV", &environment_value)?;
        let runtime_dir = parse_optional_absolute_path(
            env_map,
            "OSMAP_RUNTIME_DIR",
            PathBuf::from(&state_root_value).join("run"),
        )?;
        let session_dir = parse_optional_absolute_path(
            env_map,
            "OSMAP_SESSION_DIR",
            PathBuf::from(&state_root_value).join("sessions"),
        )?;
        let settings_dir = parse_optional_absolute_path(
            env_map,
            "OSMAP_SETTINGS_DIR",
            PathBuf::from(&state_root_value).join("settings"),
        )?;
        let audit_dir = parse_optional_absolute_path(
            env_map,
            "OSMAP_AUDIT_DIR",
            PathBuf::from(&state_root_value).join("audit"),
        )?;
        let cache_dir = parse_optional_absolute_path(
            env_map,
            "OSMAP_CACHE_DIR",
            PathBuf::from(&state_root_value).join("cache"),
        )?;
        let totp_secret_dir = parse_optional_absolute_path(
            env_map,
            "OSMAP_TOTP_SECRET_DIR",
            PathBuf::from(&state_root_value)
                .join("secrets")
                .join("totp"),
        )?;
        validate_non_empty("OSMAP_LOG_LEVEL", &log_level_value)?;
        validate_non_empty("OSMAP_LOG_FORMAT", &log_format_value)?;
        validate_non_empty("OSMAP_LISTEN_ADDR", &listen_addr)?;
        validate_non_empty("OSMAP_SESSION_LIFETIME_SECS", &session_lifetime_value)?;
        validate_non_empty("OSMAP_TOTP_ALLOWED_SKEW_STEPS", &totp_skew_steps_value)?;
        validate_non_empty(
            "OSMAP_LOGIN_THROTTLE_MAX_FAILURES",
            &login_throttle_max_failures_value,
        )?;
        validate_non_empty(
            "OSMAP_LOGIN_THROTTLE_REMOTE_MAX_FAILURES",
            &login_throttle_remote_max_failures_value,
        )?;
        validate_non_empty(
            "OSMAP_LOGIN_THROTTLE_WINDOW_SECS",
            &login_throttle_window_value,
        )?;
        validate_non_empty(
            "OSMAP_LOGIN_THROTTLE_LOCKOUT_SECS",
            &login_throttle_lockout_value,
        )?;
        validate_non_empty(
            "OSMAP_SUBMISSION_THROTTLE_MAX_SUBMISSIONS",
            &submission_throttle_max_submissions_value,
        )?;
        validate_non_empty(
            "OSMAP_SUBMISSION_THROTTLE_REMOTE_MAX_SUBMISSIONS",
            &submission_throttle_remote_max_submissions_value,
        )?;
        validate_non_empty(
            "OSMAP_SUBMISSION_THROTTLE_WINDOW_SECS",
            &submission_throttle_window_value,
        )?;
        validate_non_empty(
            "OSMAP_SUBMISSION_THROTTLE_LOCKOUT_SECS",
            &submission_throttle_lockout_value,
        )?;
        validate_non_empty(
            "OSMAP_MESSAGE_MOVE_THROTTLE_MAX_MOVES",
            &message_move_throttle_max_moves_value,
        )?;
        validate_non_empty(
            "OSMAP_MESSAGE_MOVE_THROTTLE_REMOTE_MAX_MOVES",
            &message_move_throttle_remote_max_moves_value,
        )?;
        validate_non_empty(
            "OSMAP_MESSAGE_MOVE_THROTTLE_WINDOW_SECS",
            &message_move_throttle_window_value,
        )?;
        validate_non_empty(
            "OSMAP_MESSAGE_MOVE_THROTTLE_LOCKOUT_SECS",
            &message_move_throttle_lockout_value,
        )?;
        validate_non_empty(
            "OSMAP_OPENBSD_CONFINEMENT_MODE",
            &openbsd_confinement_mode_value,
        )?;

        let run_mode = AppRunMode::parse(&run_mode_value)?;
        let environment = RuntimeEnvironment::parse(&environment_value)?;
        let state_root = parse_absolute_path("OSMAP_STATE_DIR", &state_root_value)?;
        let log_level = LogLevel::parse(&log_level_value)?;
        let log_format = LogFormat::parse(&log_format_value)?;
        let openbsd_confinement_mode =
            OpenbsdConfinementMode::parse(&openbsd_confinement_mode_value)?;
        let session_lifetime_seconds =
            parse_u64("OSMAP_SESSION_LIFETIME_SECS", &session_lifetime_value)?;
        let totp_allowed_skew_steps =
            parse_i64("OSMAP_TOTP_ALLOWED_SKEW_STEPS", &totp_skew_steps_value)?;
        let login_throttle_max_failures = parse_u64(
            "OSMAP_LOGIN_THROTTLE_MAX_FAILURES",
            &login_throttle_max_failures_value,
        )?;
        let login_throttle_remote_max_failures = parse_u64(
            "OSMAP_LOGIN_THROTTLE_REMOTE_MAX_FAILURES",
            &login_throttle_remote_max_failures_value,
        )?;
        let login_throttle_window_seconds = parse_u64(
            "OSMAP_LOGIN_THROTTLE_WINDOW_SECS",
            &login_throttle_window_value,
        )?;
        let login_throttle_lockout_seconds = parse_u64(
            "OSMAP_LOGIN_THROTTLE_LOCKOUT_SECS",
            &login_throttle_lockout_value,
        )?;
        let submission_throttle_max_submissions = parse_u64(
            "OSMAP_SUBMISSION_THROTTLE_MAX_SUBMISSIONS",
            &submission_throttle_max_submissions_value,
        )?;
        let submission_throttle_remote_max_submissions = parse_u64(
            "OSMAP_SUBMISSION_THROTTLE_REMOTE_MAX_SUBMISSIONS",
            &submission_throttle_remote_max_submissions_value,
        )?;
        let submission_throttle_window_seconds = parse_u64(
            "OSMAP_SUBMISSION_THROTTLE_WINDOW_SECS",
            &submission_throttle_window_value,
        )?;
        let submission_throttle_lockout_seconds = parse_u64(
            "OSMAP_SUBMISSION_THROTTLE_LOCKOUT_SECS",
            &submission_throttle_lockout_value,
        )?;
        let message_move_throttle_max_moves = parse_u64(
            "OSMAP_MESSAGE_MOVE_THROTTLE_MAX_MOVES",
            &message_move_throttle_max_moves_value,
        )?;
        let message_move_throttle_remote_max_moves = parse_u64(
            "OSMAP_MESSAGE_MOVE_THROTTLE_REMOTE_MAX_MOVES",
            &message_move_throttle_remote_max_moves_value,
        )?;
        let message_move_throttle_window_seconds = parse_u64(
            "OSMAP_MESSAGE_MOVE_THROTTLE_WINDOW_SECS",
            &message_move_throttle_window_value,
        )?;
        let message_move_throttle_lockout_seconds = parse_u64(
            "OSMAP_MESSAGE_MOVE_THROTTLE_LOCKOUT_SECS",
            &message_move_throttle_lockout_value,
        )?;
        validate_positive_u64("OSMAP_SESSION_LIFETIME_SECS", session_lifetime_seconds)?;
        validate_positive_u64(
            "OSMAP_LOGIN_THROTTLE_MAX_FAILURES",
            login_throttle_max_failures,
        )?;
        validate_positive_u64(
            "OSMAP_LOGIN_THROTTLE_REMOTE_MAX_FAILURES",
            login_throttle_remote_max_failures,
        )?;
        validate_positive_u64(
            "OSMAP_LOGIN_THROTTLE_WINDOW_SECS",
            login_throttle_window_seconds,
        )?;
        validate_positive_u64(
            "OSMAP_LOGIN_THROTTLE_LOCKOUT_SECS",
            login_throttle_lockout_seconds,
        )?;
        validate_positive_u64(
            "OSMAP_SUBMISSION_THROTTLE_MAX_SUBMISSIONS",
            submission_throttle_max_submissions,
        )?;
        validate_positive_u64(
            "OSMAP_SUBMISSION_THROTTLE_REMOTE_MAX_SUBMISSIONS",
            submission_throttle_remote_max_submissions,
        )?;
        validate_positive_u64(
            "OSMAP_SUBMISSION_THROTTLE_WINDOW_SECS",
            submission_throttle_window_seconds,
        )?;
        validate_positive_u64(
            "OSMAP_SUBMISSION_THROTTLE_LOCKOUT_SECS",
            submission_throttle_lockout_seconds,
        )?;
        validate_positive_u64(
            "OSMAP_MESSAGE_MOVE_THROTTLE_MAX_MOVES",
            message_move_throttle_max_moves,
        )?;
        validate_positive_u64(
            "OSMAP_MESSAGE_MOVE_THROTTLE_REMOTE_MAX_MOVES",
            message_move_throttle_remote_max_moves,
        )?;
        validate_positive_u64(
            "OSMAP_MESSAGE_MOVE_THROTTLE_WINDOW_SECS",
            message_move_throttle_window_seconds,
        )?;
        validate_positive_u64(
            "OSMAP_MESSAGE_MOVE_THROTTLE_LOCKOUT_SECS",
            message_move_throttle_lockout_seconds,
        )?;

        let state_layout = StateLayout::new(
            state_root.clone(),
            runtime_dir,
            session_dir,
            settings_dir,
            audit_dir,
            cache_dir,
            totp_secret_dir,
        )?;
        validate_development_bindings(environment, &listen_addr)?;
        let mailbox_helper_socket_path =
            parse_mailbox_helper_socket_path(env_map, run_mode, &state_layout.runtime_dir)?;

        Ok(Self {
            run_mode,
            environment,
            listen_addr,
            doveadm_auth_socket_path,
            doveadm_userdb_socket_path,
            mailbox_helper_socket_path,
            log_level,
            log_format,
            state_root,
            state_layout,
            session_lifetime_seconds,
            totp_allowed_skew_steps,
            login_throttle_max_failures,
            login_throttle_remote_max_failures,
            login_throttle_window_seconds,
            login_throttle_lockout_seconds,
            submission_throttle_max_submissions,
            submission_throttle_remote_max_submissions,
            submission_throttle_window_seconds,
            submission_throttle_lockout_seconds,
            message_move_throttle_max_moves,
            message_move_throttle_remote_max_moves,
            message_move_throttle_window_seconds,
            message_move_throttle_lockout_seconds,
            openbsd_confinement_mode,
        })
    }
}

/// Reads a value from the environment map and falls back to a conservative
/// default when the variable is absent.
fn read_value(env_map: &BTreeMap<String, String>, key: &str, default: &str) -> String {
    env_map
        .get(key)
        .cloned()
        .unwrap_or_else(|| default.to_string())
}

/// Parses a required absolute filesystem path from configuration.
fn parse_absolute_path(field: &'static str, value: &str) -> Result<PathBuf, BootstrapError> {
    validate_non_empty(field, value)?;
    let path = PathBuf::from(value);

    if !path.is_absolute() {
        return Err(BootstrapError::PathMustBeAbsolute {
            field,
            value: value.to_string(),
        });
    }

    Ok(path)
}

/// Parses an optional absolute filesystem path, falling back to the supplied
/// default when the environment variable is absent.
fn parse_optional_absolute_path(
    env_map: &BTreeMap<String, String>,
    field: &'static str,
    default: PathBuf,
) -> Result<PathBuf, BootstrapError> {
    match env_map.get(field) {
        Some(value) => parse_absolute_path(field, value),
        None => Ok(default),
    }
}

/// Parses an optional absolute path that may be omitted entirely.
fn parse_optional_absolute_optional_path(
    env_map: &BTreeMap<String, String>,
    field: &'static str,
) -> Result<Option<PathBuf>, BootstrapError> {
    match env_map.get(field) {
        Some(value) => Ok(Some(parse_absolute_path(field, value)?)),
        None => Ok(None),
    }
}

/// Parses the mailbox-helper socket path and supplies a conservative default
/// only when the helper itself is the selected run mode.
fn parse_mailbox_helper_socket_path(
    env_map: &BTreeMap<String, String>,
    run_mode: AppRunMode,
    runtime_dir: &Path,
) -> Result<Option<PathBuf>, BootstrapError> {
    match env_map.get("OSMAP_MAILBOX_HELPER_SOCKET_PATH") {
        Some(value) => Ok(Some(parse_absolute_path(
            "OSMAP_MAILBOX_HELPER_SOCKET_PATH",
            value,
        )?)),
        None if run_mode == AppRunMode::MailboxHelper => {
            Ok(Some(runtime_dir.join("mailbox-helper.sock")))
        }
        None => Ok(None),
    }
}

/// Parses a signed integer from configuration.
fn parse_i64(field: &'static str, value: &str) -> Result<i64, BootstrapError> {
    value
        .parse::<i64>()
        .map_err(|error| BootstrapError::InvalidConfig {
            field,
            reason: format!("value must be a signed integer: {error}"),
        })
}

/// Parses an unsigned integer from configuration.
fn parse_u64(field: &'static str, value: &str) -> Result<u64, BootstrapError> {
    value
        .parse::<u64>()
        .map_err(|error| BootstrapError::InvalidConfig {
            field,
            reason: format!("value must be an unsigned integer: {error}"),
        })
}

/// Rejects zero-valued unsigned integers for settings that must remain active.
fn validate_positive_u64(field: &'static str, value: u64) -> Result<(), BootstrapError> {
    if value == 0 {
        return Err(BootstrapError::InvalidConfig {
            field,
            reason: "value must be greater than zero".to_string(),
        });
    }

    Ok(())
}

/// Rejects empty configuration values so later phases do not inherit silent
/// fallback behavior around important runtime paths.
fn validate_non_empty(field: &'static str, value: &str) -> Result<(), BootstrapError> {
    if value.trim().is_empty() {
        return Err(BootstrapError::InvalidConfig {
            field,
            reason: "value must not be empty".to_string(),
        });
    }

    Ok(())
}

/// Keeps development builds loopback-bound by default so local bootstrap work
/// does not accidentally normalize broad listener exposure.
fn validate_development_bindings(
    environment: RuntimeEnvironment,
    listen_addr: &str,
) -> Result<(), BootstrapError> {
    if environment == RuntimeEnvironment::Development && !is_loopback_listener(listen_addr) {
        return Err(BootstrapError::InvalidConfig {
            field: "OSMAP_LISTEN_ADDR",
            reason: "development listeners must stay on loopback".to_string(),
        });
    }

    Ok(())
}

/// Applies a conservative loopback test for the early prototype listener.
fn is_loopback_listener(listen_addr: &str) -> bool {
    listen_addr.starts_with("127.0.0.1:")
        || listen_addr.starts_with("[::1]:")
        || listen_addr.starts_with("localhost:")
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn uses_conservative_defaults_when_environment_is_empty() {
        let env_map = BTreeMap::new();
        let config = AppConfig::from_env_map(&env_map).expect("defaults should be valid");

        assert_eq!(config.run_mode, AppRunMode::Bootstrap);
        assert_eq!(config.environment, RuntimeEnvironment::Development);
        assert_eq!(config.listen_addr, "127.0.0.1:8080");
        assert_eq!(config.doveadm_auth_socket_path, None);
        assert_eq!(config.doveadm_userdb_socket_path, None);
        assert_eq!(config.mailbox_helper_socket_path, None);
        assert_eq!(config.state_root, std::path::Path::new("/var/lib/osmap"));
        assert_eq!(
            config.state_layout.runtime_dir,
            std::path::Path::new("/var/lib/osmap/run")
        );
        assert_eq!(
            config.state_layout.session_dir,
            std::path::Path::new("/var/lib/osmap/sessions")
        );
        assert_eq!(
            config.state_layout.audit_dir,
            std::path::Path::new("/var/lib/osmap/audit")
        );
        assert_eq!(
            config.state_layout.cache_dir,
            std::path::Path::new("/var/lib/osmap/cache")
        );
        assert_eq!(
            config.state_layout.totp_secret_dir,
            std::path::Path::new("/var/lib/osmap/secrets/totp")
        );
        assert_eq!(config.log_level, LogLevel::Info);
        assert_eq!(config.log_format, LogFormat::Text);
        assert_eq!(config.session_lifetime_seconds, 43200);
        assert_eq!(config.totp_allowed_skew_steps, 1);
        assert_eq!(config.login_throttle_max_failures, 5);
        assert_eq!(config.login_throttle_remote_max_failures, 12);
        assert_eq!(config.login_throttle_window_seconds, 300);
        assert_eq!(config.login_throttle_lockout_seconds, 900);
        assert_eq!(config.submission_throttle_max_submissions, 10);
        assert_eq!(config.submission_throttle_remote_max_submissions, 25);
        assert_eq!(config.submission_throttle_window_seconds, 300);
        assert_eq!(config.submission_throttle_lockout_seconds, 900);
        assert_eq!(config.message_move_throttle_max_moves, 20);
        assert_eq!(config.message_move_throttle_remote_max_moves, 60);
        assert_eq!(config.message_move_throttle_window_seconds, 300);
        assert_eq!(config.message_move_throttle_lockout_seconds, 900);
        assert_eq!(
            config.openbsd_confinement_mode,
            OpenbsdConfinementMode::Disabled
        );
    }

    #[test]
    fn accepts_explicit_environment_values() {
        let env_map = BTreeMap::from([
            ("OSMAP_RUN_MODE".to_string(), "serve".to_string()),
            ("OSMAP_ENV".to_string(), "staging".to_string()),
            (
                "OSMAP_LISTEN_ADDR".to_string(),
                "127.0.0.1:8443".to_string(),
            ),
            (
                "OSMAP_STATE_DIR".to_string(),
                "/var/lib/osmap-staging".to_string(),
            ),
            (
                "OSMAP_RUNTIME_DIR".to_string(),
                "/var/lib/osmap-staging/run".to_string(),
            ),
            (
                "OSMAP_SESSION_DIR".to_string(),
                "/var/lib/osmap-staging/session-store".to_string(),
            ),
            (
                "OSMAP_TOTP_SECRET_DIR".to_string(),
                "/var/lib/osmap-staging/secure/totp".to_string(),
            ),
            ("OSMAP_LOG_LEVEL".to_string(), "debug".to_string()),
            ("OSMAP_LOG_FORMAT".to_string(), "text".to_string()),
            (
                "OSMAP_SESSION_LIFETIME_SECS".to_string(),
                "3600".to_string(),
            ),
            ("OSMAP_TOTP_ALLOWED_SKEW_STEPS".to_string(), "2".to_string()),
            (
                "OSMAP_OPENBSD_CONFINEMENT_MODE".to_string(),
                "log-only".to_string(),
            ),
            (
                "OSMAP_LOGIN_THROTTLE_MAX_FAILURES".to_string(),
                "4".to_string(),
            ),
            (
                "OSMAP_LOGIN_THROTTLE_WINDOW_SECS".to_string(),
                "120".to_string(),
            ),
            (
                "OSMAP_LOGIN_THROTTLE_REMOTE_MAX_FAILURES".to_string(),
                "9".to_string(),
            ),
            (
                "OSMAP_LOGIN_THROTTLE_LOCKOUT_SECS".to_string(),
                "600".to_string(),
            ),
            (
                "OSMAP_SUBMISSION_THROTTLE_MAX_SUBMISSIONS".to_string(),
                "6".to_string(),
            ),
            (
                "OSMAP_SUBMISSION_THROTTLE_REMOTE_MAX_SUBMISSIONS".to_string(),
                "18".to_string(),
            ),
            (
                "OSMAP_SUBMISSION_THROTTLE_WINDOW_SECS".to_string(),
                "180".to_string(),
            ),
            (
                "OSMAP_SUBMISSION_THROTTLE_LOCKOUT_SECS".to_string(),
                "1200".to_string(),
            ),
            (
                "OSMAP_MESSAGE_MOVE_THROTTLE_MAX_MOVES".to_string(),
                "8".to_string(),
            ),
            (
                "OSMAP_MESSAGE_MOVE_THROTTLE_REMOTE_MAX_MOVES".to_string(),
                "24".to_string(),
            ),
            (
                "OSMAP_MESSAGE_MOVE_THROTTLE_WINDOW_SECS".to_string(),
                "240".to_string(),
            ),
            (
                "OSMAP_MESSAGE_MOVE_THROTTLE_LOCKOUT_SECS".to_string(),
                "1500".to_string(),
            ),
            (
                "OSMAP_DOVEADM_AUTH_SOCKET_PATH".to_string(),
                "/var/run/osmap/dovecot-auth".to_string(),
            ),
            (
                "OSMAP_DOVEADM_USERDB_SOCKET_PATH".to_string(),
                "/var/run/osmap/dovecot-userdb".to_string(),
            ),
            (
                "OSMAP_MAILBOX_HELPER_SOCKET_PATH".to_string(),
                "/var/lib/osmap-staging/run/mailbox-helper.sock".to_string(),
            ),
        ]);

        let config = AppConfig::from_env_map(&env_map).expect("explicit values should be valid");

        assert_eq!(config.run_mode, AppRunMode::Serve);
        assert_eq!(config.environment, RuntimeEnvironment::Staging);
        assert_eq!(config.listen_addr, "127.0.0.1:8443");
        assert_eq!(
            config.doveadm_auth_socket_path,
            Some(std::path::Path::new("/var/run/osmap/dovecot-auth").to_path_buf())
        );
        assert_eq!(
            config.doveadm_userdb_socket_path,
            Some(std::path::Path::new("/var/run/osmap/dovecot-userdb").to_path_buf())
        );
        assert_eq!(
            config.mailbox_helper_socket_path,
            Some(
                std::path::Path::new("/var/lib/osmap-staging/run/mailbox-helper.sock")
                    .to_path_buf()
            )
        );
        assert_eq!(
            config.state_root,
            std::path::Path::new("/var/lib/osmap-staging")
        );
        assert_eq!(
            config.state_layout.runtime_dir,
            std::path::Path::new("/var/lib/osmap-staging/run")
        );
        assert_eq!(
            config.state_layout.session_dir,
            std::path::Path::new("/var/lib/osmap-staging/session-store")
        );
        assert_eq!(
            config.state_layout.totp_secret_dir,
            std::path::Path::new("/var/lib/osmap-staging/secure/totp")
        );
        assert_eq!(config.log_level, LogLevel::Debug);
        assert_eq!(config.log_format, LogFormat::Text);
        assert_eq!(config.session_lifetime_seconds, 3600);
        assert_eq!(config.totp_allowed_skew_steps, 2);
        assert_eq!(config.login_throttle_max_failures, 4);
        assert_eq!(config.login_throttle_remote_max_failures, 9);
        assert_eq!(config.login_throttle_window_seconds, 120);
        assert_eq!(config.login_throttle_lockout_seconds, 600);
        assert_eq!(config.submission_throttle_max_submissions, 6);
        assert_eq!(config.submission_throttle_remote_max_submissions, 18);
        assert_eq!(config.submission_throttle_window_seconds, 180);
        assert_eq!(config.submission_throttle_lockout_seconds, 1200);
        assert_eq!(config.message_move_throttle_max_moves, 8);
        assert_eq!(config.message_move_throttle_remote_max_moves, 24);
        assert_eq!(config.message_move_throttle_window_seconds, 240);
        assert_eq!(config.message_move_throttle_lockout_seconds, 1500);
        assert_eq!(
            config.openbsd_confinement_mode,
            OpenbsdConfinementMode::LogOnly
        );
    }

    #[test]
    fn rejects_empty_values() {
        let env_map = BTreeMap::from([("OSMAP_LOG_LEVEL".to_string(), "".to_string())]);

        let error = AppConfig::from_env_map(&env_map).expect_err("empty values must fail");

        assert_eq!(
            error,
            BootstrapError::InvalidConfig {
                field: "OSMAP_LOG_LEVEL",
                reason: "value must not be empty".to_string(),
            }
        );
    }

    #[test]
    fn rejects_empty_run_mode() {
        let env_map = BTreeMap::from([("OSMAP_RUN_MODE".to_string(), "".to_string())]);

        let error = AppConfig::from_env_map(&env_map).expect_err("empty values must fail");

        assert_eq!(
            error,
            BootstrapError::InvalidConfig {
                field: "OSMAP_RUN_MODE",
                reason: "value must not be empty".to_string(),
            }
        );
    }

    #[test]
    fn rejects_unsupported_run_mode() {
        let env_map = BTreeMap::from([("OSMAP_RUN_MODE".to_string(), "daemon".to_string())]);

        let error = AppConfig::from_env_map(&env_map).expect_err("unsupported run modes must fail");

        assert_eq!(
            error,
            BootstrapError::UnsupportedValue {
                field: "OSMAP_RUN_MODE",
                value: "daemon".to_string(),
                expected: "bootstrap, serve, or mailbox-helper",
            }
        );
    }

    #[test]
    fn rejects_zero_session_lifetime() {
        let env_map =
            BTreeMap::from([("OSMAP_SESSION_LIFETIME_SECS".to_string(), "0".to_string())]);

        let error =
            AppConfig::from_env_map(&env_map).expect_err("zero-valued session lifetime must fail");

        assert_eq!(
            error,
            BootstrapError::InvalidConfig {
                field: "OSMAP_SESSION_LIFETIME_SECS",
                reason: "value must be greater than zero".to_string(),
            }
        );
    }

    #[test]
    fn rejects_zero_login_throttle_threshold() {
        let env_map = BTreeMap::from([(
            "OSMAP_LOGIN_THROTTLE_MAX_FAILURES".to_string(),
            "0".to_string(),
        )]);

        let error = AppConfig::from_env_map(&env_map)
            .expect_err("zero-valued login throttle threshold must fail");

        assert_eq!(
            error,
            BootstrapError::InvalidConfig {
                field: "OSMAP_LOGIN_THROTTLE_MAX_FAILURES",
                reason: "value must be greater than zero".to_string(),
            }
        );
    }

    #[test]
    fn rejects_zero_remote_login_throttle_threshold() {
        let env_map = BTreeMap::from([(
            "OSMAP_LOGIN_THROTTLE_REMOTE_MAX_FAILURES".to_string(),
            "0".to_string(),
        )]);

        let error = AppConfig::from_env_map(&env_map)
            .expect_err("zero-valued remote login throttle threshold must fail");

        assert_eq!(
            error,
            BootstrapError::InvalidConfig {
                field: "OSMAP_LOGIN_THROTTLE_REMOTE_MAX_FAILURES",
                reason: "value must be greater than zero".to_string(),
            }
        );
    }

    #[test]
    fn rejects_zero_submission_throttle_threshold() {
        let env_map = BTreeMap::from([(
            "OSMAP_SUBMISSION_THROTTLE_MAX_SUBMISSIONS".to_string(),
            "0".to_string(),
        )]);

        let error = AppConfig::from_env_map(&env_map)
            .expect_err("zero-valued submission throttle threshold must fail");

        assert_eq!(
            error,
            BootstrapError::InvalidConfig {
                field: "OSMAP_SUBMISSION_THROTTLE_MAX_SUBMISSIONS",
                reason: "value must be greater than zero".to_string(),
            }
        );
    }

    #[test]
    fn rejects_zero_remote_submission_throttle_threshold() {
        let env_map = BTreeMap::from([(
            "OSMAP_SUBMISSION_THROTTLE_REMOTE_MAX_SUBMISSIONS".to_string(),
            "0".to_string(),
        )]);

        let error = AppConfig::from_env_map(&env_map)
            .expect_err("zero-valued remote submission throttle threshold must fail");

        assert_eq!(
            error,
            BootstrapError::InvalidConfig {
                field: "OSMAP_SUBMISSION_THROTTLE_REMOTE_MAX_SUBMISSIONS",
                reason: "value must be greater than zero".to_string(),
            }
        );
    }

    #[test]
    fn rejects_zero_message_move_throttle_threshold() {
        let env_map = BTreeMap::from([(
            "OSMAP_MESSAGE_MOVE_THROTTLE_MAX_MOVES".to_string(),
            "0".to_string(),
        )]);

        let error = AppConfig::from_env_map(&env_map)
            .expect_err("zero-valued message move throttle threshold must fail");

        assert_eq!(
            error,
            BootstrapError::InvalidConfig {
                field: "OSMAP_MESSAGE_MOVE_THROTTLE_MAX_MOVES",
                reason: "value must be greater than zero".to_string(),
            }
        );
    }

    #[test]
    fn rejects_zero_remote_message_move_throttle_threshold() {
        let env_map = BTreeMap::from([(
            "OSMAP_MESSAGE_MOVE_THROTTLE_REMOTE_MAX_MOVES".to_string(),
            "0".to_string(),
        )]);

        let error = AppConfig::from_env_map(&env_map)
            .expect_err("zero-valued remote message move throttle threshold must fail");

        assert_eq!(
            error,
            BootstrapError::InvalidConfig {
                field: "OSMAP_MESSAGE_MOVE_THROTTLE_REMOTE_MAX_MOVES",
                reason: "value must be greater than zero".to_string(),
            }
        );
    }

    #[test]
    fn rejects_relative_state_root() {
        let env_map =
            BTreeMap::from([("OSMAP_STATE_DIR".to_string(), "var/lib/osmap".to_string())]);

        let error = AppConfig::from_env_map(&env_map).expect_err("relative paths must fail");

        assert_eq!(
            error,
            BootstrapError::PathMustBeAbsolute {
                field: "OSMAP_STATE_DIR",
                value: "var/lib/osmap".to_string(),
            }
        );
    }

    #[test]
    fn rejects_relative_doveadm_auth_socket_path() {
        let env_map = BTreeMap::from([(
            "OSMAP_DOVEADM_AUTH_SOCKET_PATH".to_string(),
            "var/run/osmap-auth".to_string(),
        )]);

        let error =
            AppConfig::from_env_map(&env_map).expect_err("relative auth socket path must fail");

        assert_eq!(
            error,
            BootstrapError::PathMustBeAbsolute {
                field: "OSMAP_DOVEADM_AUTH_SOCKET_PATH",
                value: "var/run/osmap-auth".to_string(),
            }
        );
    }

    #[test]
    fn rejects_relative_doveadm_userdb_socket_path() {
        let env_map = BTreeMap::from([(
            "OSMAP_DOVEADM_USERDB_SOCKET_PATH".to_string(),
            "var/run/osmap-userdb".to_string(),
        )]);

        let error =
            AppConfig::from_env_map(&env_map).expect_err("relative userdb socket path must fail");

        assert_eq!(
            error,
            BootstrapError::PathMustBeAbsolute {
                field: "OSMAP_DOVEADM_USERDB_SOCKET_PATH",
                value: "var/run/osmap-userdb".to_string(),
            }
        );
    }

    #[test]
    fn helper_mode_defaults_mailbox_helper_socket_under_runtime_dir() {
        let env_map =
            BTreeMap::from([("OSMAP_RUN_MODE".to_string(), "mailbox-helper".to_string())]);

        let config = AppConfig::from_env_map(&env_map).expect("helper mode should parse");

        assert_eq!(config.run_mode, AppRunMode::MailboxHelper);
        assert_eq!(
            config.mailbox_helper_socket_path,
            Some(std::path::Path::new("/var/lib/osmap/run/mailbox-helper.sock").to_path_buf())
        );
    }

    #[test]
    fn rejects_relative_mailbox_helper_socket_path() {
        let env_map = BTreeMap::from([(
            "OSMAP_MAILBOX_HELPER_SOCKET_PATH".to_string(),
            "var/run/mailbox-helper.sock".to_string(),
        )]);

        let error = AppConfig::from_env_map(&env_map)
            .expect_err("relative mailbox helper socket path must fail");

        assert_eq!(
            error,
            BootstrapError::PathMustBeAbsolute {
                field: "OSMAP_MAILBOX_HELPER_SOCKET_PATH",
                value: "var/run/mailbox-helper.sock".to_string(),
            }
        );
    }

    #[test]
    fn rejects_non_loopback_development_listener() {
        let env_map =
            BTreeMap::from([("OSMAP_LISTEN_ADDR".to_string(), "0.0.0.0:8080".to_string())]);

        let error = AppConfig::from_env_map(&env_map)
            .expect_err("development listeners must remain loopback-bound");

        assert_eq!(
            error,
            BootstrapError::InvalidConfig {
                field: "OSMAP_LISTEN_ADDR",
                reason: "development listeners must stay on loopback".to_string(),
            }
        );
    }

    #[test]
    fn accepts_non_loopback_listener_outside_development() {
        let env_map = BTreeMap::from([
            ("OSMAP_ENV".to_string(), "staging".to_string()),
            ("OSMAP_LISTEN_ADDR".to_string(), "0.0.0.0:8080".to_string()),
        ]);

        let config = AppConfig::from_env_map(&env_map).expect("staging listeners may be broader");

        assert_eq!(config.environment, RuntimeEnvironment::Staging);
        assert_eq!(config.listen_addr, "0.0.0.0:8080");
    }

    #[test]
    fn rejects_unsupported_openbsd_confinement_mode() {
        let env_map = BTreeMap::from([(
            "OSMAP_OPENBSD_CONFINEMENT_MODE".to_string(),
            "strict".to_string(),
        )]);

        let error = AppConfig::from_env_map(&env_map).expect_err("mode should be rejected");

        assert_eq!(
            error,
            BootstrapError::UnsupportedValue {
                field: "OSMAP_OPENBSD_CONFINEMENT_MODE",
                value: "strict".to_string(),
                expected: "disabled, log-only, or enforce",
            }
        );
    }
}
