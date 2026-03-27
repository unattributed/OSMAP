//! Configuration loading for the early OSMAP skeleton.
//!
//! The bootstrap keeps configuration intentionally small:
//! - values come from the environment
//! - defaults are conservative and loopback-bound
//! - secrets are expected to be supplied out-of-band by operators later

use std::collections::BTreeMap;
use std::env;
use std::path::PathBuf;

use crate::error::BootstrapError;
use crate::state::StateLayout;

/// Runtime configuration that is safe to print in operator-facing startup
/// output because it excludes secret-bearing fields.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct AppConfig {
    pub environment: RuntimeEnvironment,
    pub listen_addr: String,
    pub state_root: PathBuf,
    pub log_level: LogLevel,
    pub log_format: LogFormat,
    pub state_layout: StateLayout,
    pub session_lifetime_seconds: u64,
    pub totp_allowed_skew_steps: i64,
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
    pub fn from_env_map(
        env_map: &BTreeMap<String, String>,
    ) -> Result<Self, BootstrapError> {
        let environment_value = read_value(env_map, "OSMAP_ENV", "development");
        let listen_addr = read_value(env_map, "OSMAP_LISTEN_ADDR", "127.0.0.1:8080");
        let state_root_value = read_value(env_map, "OSMAP_STATE_DIR", "/var/lib/osmap");
        let log_level_value = read_value(env_map, "OSMAP_LOG_LEVEL", "info");
        let log_format_value = read_value(env_map, "OSMAP_LOG_FORMAT", "text");
        let session_lifetime_value = read_value(env_map, "OSMAP_SESSION_LIFETIME_SECS", "43200");
        let totp_skew_steps_value = read_value(env_map, "OSMAP_TOTP_ALLOWED_SKEW_STEPS", "1");

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
            PathBuf::from(&state_root_value).join("secrets").join("totp"),
        )?;
        validate_non_empty("OSMAP_LOG_LEVEL", &log_level_value)?;
        validate_non_empty("OSMAP_LOG_FORMAT", &log_format_value)?;
        validate_non_empty("OSMAP_LISTEN_ADDR", &listen_addr)?;
        validate_non_empty("OSMAP_SESSION_LIFETIME_SECS", &session_lifetime_value)?;
        validate_non_empty("OSMAP_TOTP_ALLOWED_SKEW_STEPS", &totp_skew_steps_value)?;

        let environment = RuntimeEnvironment::parse(&environment_value)?;
        let state_root = parse_absolute_path("OSMAP_STATE_DIR", &state_root_value)?;
        let log_level = LogLevel::parse(&log_level_value)?;
        let log_format = LogFormat::parse(&log_format_value)?;
        let session_lifetime_seconds =
            parse_u64("OSMAP_SESSION_LIFETIME_SECS", &session_lifetime_value)?;
        let totp_allowed_skew_steps =
            parse_i64("OSMAP_TOTP_ALLOWED_SKEW_STEPS", &totp_skew_steps_value)?;
        validate_positive_u64("OSMAP_SESSION_LIFETIME_SECS", session_lifetime_seconds)?;

        let state_layout =
            StateLayout::new(
                state_root.clone(),
                runtime_dir,
                session_dir,
                audit_dir,
                cache_dir,
                totp_secret_dir,
            )?;
        validate_development_bindings(environment, &listen_addr)?;

        Ok(Self {
            environment,
            listen_addr,
            log_level,
            log_format,
            state_root,
            state_layout,
            session_lifetime_seconds,
            totp_allowed_skew_steps,
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
fn parse_absolute_path(
    field: &'static str,
    value: &str,
) -> Result<PathBuf, BootstrapError> {
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

        assert_eq!(config.environment, RuntimeEnvironment::Development);
        assert_eq!(config.listen_addr, "127.0.0.1:8080");
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
    }

    #[test]
    fn accepts_explicit_environment_values() {
        let env_map = BTreeMap::from([
            ("OSMAP_ENV".to_string(), "staging".to_string()),
            ("OSMAP_LISTEN_ADDR".to_string(), "127.0.0.1:8443".to_string()),
            ("OSMAP_STATE_DIR".to_string(), "/var/lib/osmap-staging".to_string()),
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
            ("OSMAP_SESSION_LIFETIME_SECS".to_string(), "3600".to_string()),
            ("OSMAP_TOTP_ALLOWED_SKEW_STEPS".to_string(), "2".to_string()),
        ]);

        let config = AppConfig::from_env_map(&env_map).expect("explicit values should be valid");

        assert_eq!(config.environment, RuntimeEnvironment::Staging);
        assert_eq!(config.listen_addr, "127.0.0.1:8443");
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
    fn rejects_zero_session_lifetime() {
        let env_map = BTreeMap::from([
            ("OSMAP_SESSION_LIFETIME_SECS".to_string(), "0".to_string()),
        ]);

        let error = AppConfig::from_env_map(&env_map)
            .expect_err("zero-valued session lifetime must fail");

        assert_eq!(
            error,
            BootstrapError::InvalidConfig {
                field: "OSMAP_SESSION_LIFETIME_SECS",
                reason: "value must be greater than zero".to_string(),
            }
        );
    }

    #[test]
    fn rejects_relative_state_root() {
        let env_map = BTreeMap::from([(
            "OSMAP_STATE_DIR".to_string(),
            "var/lib/osmap".to_string(),
        )]);

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
    fn rejects_non_loopback_development_listener() {
        let env_map = BTreeMap::from([(
            "OSMAP_LISTEN_ADDR".to_string(),
            "0.0.0.0:8080".to_string(),
        )]);

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

        let config =
            AppConfig::from_env_map(&env_map).expect("staging listeners may be broader");

        assert_eq!(config.environment, RuntimeEnvironment::Staging);
        assert_eq!(config.listen_addr, "0.0.0.0:8080");
    }
}
