//! Configuration loading for the early OSMAP skeleton.
//!
//! The bootstrap keeps configuration intentionally small:
//! - values come from the environment
//! - defaults are conservative and loopback-bound
//! - secrets are expected to be supplied out-of-band by operators later

use std::collections::BTreeMap;
use std::env;

use crate::error::BootstrapError;

/// Runtime configuration that is safe to print in operator-facing startup
/// output because it excludes secret-bearing fields.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct AppConfig {
    pub environment: String,
    pub listen_addr: String,
    pub state_dir: String,
    pub log_level: String,
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
        let environment = read_value(env_map, "OSMAP_ENV", "development");
        let listen_addr = read_value(env_map, "OSMAP_LISTEN_ADDR", "127.0.0.1:8080");
        let state_dir = read_value(env_map, "OSMAP_STATE_DIR", "/var/lib/osmap");
        let log_level = read_value(env_map, "OSMAP_LOG_LEVEL", "info");

        validate_non_empty("OSMAP_ENV", &environment)?;
        validate_non_empty("OSMAP_LISTEN_ADDR", &listen_addr)?;
        validate_non_empty("OSMAP_STATE_DIR", &state_dir)?;
        validate_non_empty("OSMAP_LOG_LEVEL", &log_level)?;

        Ok(Self {
            environment,
            listen_addr,
            state_dir,
            log_level,
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

/// Rejects empty configuration values so later phases do not inherit silent
/// fallback behavior around important runtime paths.
fn validate_non_empty(field: &'static str, value: &str) -> Result<(), BootstrapError> {
    if value.trim().is_empty() {
        return Err(BootstrapError::InvalidConfig {
            field,
            reason: "value must not be empty",
        });
    }

    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn uses_conservative_defaults_when_environment_is_empty() {
        let env_map = BTreeMap::new();
        let config = AppConfig::from_env_map(&env_map).expect("defaults should be valid");

        assert_eq!(config.environment, "development");
        assert_eq!(config.listen_addr, "127.0.0.1:8080");
        assert_eq!(config.state_dir, "/var/lib/osmap");
        assert_eq!(config.log_level, "info");
    }

    #[test]
    fn accepts_explicit_environment_values() {
        let env_map = BTreeMap::from([
            ("OSMAP_ENV".to_string(), "staging".to_string()),
            ("OSMAP_LISTEN_ADDR".to_string(), "127.0.0.1:8443".to_string()),
            ("OSMAP_STATE_DIR".to_string(), "/tmp/osmap-state".to_string()),
            ("OSMAP_LOG_LEVEL".to_string(), "debug".to_string()),
        ]);

        let config = AppConfig::from_env_map(&env_map).expect("explicit values should be valid");

        assert_eq!(config.environment, "staging");
        assert_eq!(config.listen_addr, "127.0.0.1:8443");
        assert_eq!(config.state_dir, "/tmp/osmap-state");
        assert_eq!(config.log_level, "debug");
    }

    #[test]
    fn rejects_empty_values() {
        let env_map = BTreeMap::from([("OSMAP_LOG_LEVEL".to_string(), "".to_string())]);

        let error = AppConfig::from_env_map(&env_map).expect_err("empty values must fail");

        assert_eq!(
            error,
            BootstrapError::InvalidConfig {
                field: "OSMAP_LOG_LEVEL",
                reason: "value must not be empty",
            }
        );
    }
}
