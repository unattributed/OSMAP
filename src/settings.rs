//! Bounded end-user settings for the first OSMAP browser release.
//!
//! This module intentionally stays small. The first settings surface exists to
//! expose one meaningful preference without turning OSMAP into a broad
//! preference platform.

use std::fs;
use std::io::Write as _;
use std::path::PathBuf;

use sha2::{Digest, Sha256};

use crate::auth::AuthenticationContext;
use crate::config::LogLevel;
use crate::logging::{EventCategory, LogEvent};
use crate::rendering::HtmlDisplayPreference;
use crate::session::ValidatedSession;

/// The current bounded end-user settings record.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct UserSettings {
    pub html_display_preference: HtmlDisplayPreference,
}

impl Default for UserSettings {
    fn default() -> Self {
        Self {
            html_display_preference: HtmlDisplayPreference::PreferSanitizedHtml,
        }
    }
}

/// Errors raised while loading or saving end-user settings.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct UserSettingsError {
    pub reason: String,
}

/// Persists and retrieves bounded end-user settings.
pub trait UserSettingsStore {
    fn load(&self, canonical_username: &str) -> Result<Option<UserSettings>, UserSettingsError>;
    fn save(
        &self,
        canonical_username: &str,
        settings: &UserSettings,
    ) -> Result<(), UserSettingsError>;
}

/// File-backed user-settings store rooted under the configured state tree.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct FileUserSettingsStore {
    settings_dir: PathBuf,
}

impl FileUserSettingsStore {
    /// Creates a file-backed settings store rooted at the supplied directory.
    pub fn new(settings_dir: impl Into<PathBuf>) -> Self {
        Self {
            settings_dir: settings_dir.into(),
        }
    }

    /// Returns the filesystem path for one user's settings file.
    pub fn settings_path_for_username(&self, canonical_username: &str) -> PathBuf {
        let mut digest = Sha256::new();
        digest.update(b"osmap-user-settings-v1");
        digest.update([0]);
        digest.update(canonical_username.as_bytes());

        self.settings_dir
            .join(format!("{}.settings", hex_lower(&digest.finalize())))
    }
}

impl UserSettingsStore for FileUserSettingsStore {
    fn load(&self, canonical_username: &str) -> Result<Option<UserSettings>, UserSettingsError> {
        let path = self.settings_path_for_username(canonical_username);

        if !path.exists() {
            return Ok(None);
        }

        let content = fs::read_to_string(&path).map_err(|error| UserSettingsError {
            reason: format!("failed to read user settings file {:?}: {error}", path),
        })?;

        parse_user_settings(&content).map(Some)
    }

    fn save(
        &self,
        canonical_username: &str,
        settings: &UserSettings,
    ) -> Result<(), UserSettingsError> {
        fs::create_dir_all(&self.settings_dir).map_err(|error| UserSettingsError {
            reason: format!(
                "failed to create user settings directory {:?}: {error}",
                self.settings_dir
            ),
        })?;

        let path = self.settings_path_for_username(canonical_username);
        let tmp_path = self.settings_dir.join("settings.tmp");
        let content = serialize_user_settings(settings);

        let mut file = fs::File::create(&tmp_path).map_err(|error| UserSettingsError {
            reason: format!(
                "failed to create user settings temp file {:?}: {error}",
                tmp_path
            ),
        })?;
        file.write_all(content.as_bytes())
            .map_err(|error| UserSettingsError {
                reason: format!(
                    "failed to write user settings temp file {:?}: {error}",
                    tmp_path
                ),
            })?;

        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            fs::set_permissions(&tmp_path, fs::Permissions::from_mode(0o600)).map_err(|error| {
                UserSettingsError {
                    reason: format!(
                        "failed to set user settings temp permissions {:?}: {error}",
                        tmp_path
                    ),
                }
            })?;
        }

        fs::rename(&tmp_path, &path).map_err(|error| UserSettingsError {
            reason: format!("failed to finalize user settings file {:?}: {error}", path),
        })?;

        Ok(())
    }
}

/// Loaded settings plus the emitted audit event.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct LoadedUserSettings {
    pub settings: UserSettings,
    pub audit_event: LogEvent,
}

/// Updated settings plus the emitted audit event.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct UpdatedUserSettings {
    pub settings: UserSettings,
    pub audit_event: LogEvent,
}

/// Small service over the file-backed settings store.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct UserSettingsService<S> {
    store: S,
}

impl<S> UserSettingsService<S> {
    /// Builds the current settings service around the supplied store.
    pub fn new(store: S) -> Self {
        Self { store }
    }
}

impl<S> UserSettingsService<S>
where
    S: UserSettingsStore,
{
    /// Loads settings for the current validated browser user.
    pub fn load_for_validated_session(
        &self,
        context: &AuthenticationContext,
        validated_session: &ValidatedSession,
    ) -> Result<LoadedUserSettings, UserSettingsError> {
        let settings = self
            .store
            .load(&validated_session.record.canonical_username)?
            .unwrap_or_default();

        Ok(LoadedUserSettings {
            audit_event: LogEvent::new(
                LogLevel::Info,
                EventCategory::Session,
                "user_settings_loaded",
                "user settings loaded",
            )
            .with_field(
                "canonical_username",
                validated_session.record.canonical_username.clone(),
            )
            .with_field(
                "html_display_preference",
                settings.html_display_preference.as_str(),
            )
            .with_field("request_id", context.request_id.clone())
            .with_field("remote_addr", context.remote_addr.clone())
            .with_field("user_agent", context.user_agent.clone()),
            settings,
        })
    }

    /// Persists a new HTML-display preference for the current validated user.
    pub fn update_html_display_preference(
        &self,
        context: &AuthenticationContext,
        validated_session: &ValidatedSession,
        html_display_preference: HtmlDisplayPreference,
    ) -> Result<UpdatedUserSettings, UserSettingsError> {
        let settings = UserSettings {
            html_display_preference,
        };
        self.store
            .save(&validated_session.record.canonical_username, &settings)?;

        Ok(UpdatedUserSettings {
            audit_event: LogEvent::new(
                LogLevel::Info,
                EventCategory::Session,
                "user_settings_updated",
                "user settings updated",
            )
            .with_field(
                "canonical_username",
                validated_session.record.canonical_username.clone(),
            )
            .with_field(
                "html_display_preference",
                settings.html_display_preference.as_str(),
            )
            .with_field("request_id", context.request_id.clone())
            .with_field("remote_addr", context.remote_addr.clone())
            .with_field("user_agent", context.user_agent.clone()),
            settings,
        })
    }
}

fn serialize_user_settings(settings: &UserSettings) -> String {
    format!(
        "html_display_preference={}\n",
        settings.html_display_preference.as_str()
    )
}

fn parse_user_settings(content: &str) -> Result<UserSettings, UserSettingsError> {
    let mut html_display_preference = None;

    for line in content.lines() {
        if line.trim().is_empty() {
            continue;
        }

        let Some((key, value)) = line.split_once('=') else {
            return Err(UserSettingsError {
                reason: "user settings line did not contain '='".to_string(),
            });
        };

        match key {
            "html_display_preference" => {
                html_display_preference =
                    Some(HtmlDisplayPreference::parse(value).map_err(|error| {
                        UserSettingsError {
                            reason: error.reason,
                        }
                    })?)
            }
            _ => {
                return Err(UserSettingsError {
                    reason: format!("unsupported user settings key {key}"),
                })
            }
        }
    }

    Ok(UserSettings {
        html_display_preference: html_display_preference.unwrap_or_default(),
    })
}

fn hex_lower(bytes: &[u8]) -> String {
    let mut encoded = String::with_capacity(bytes.len() * 2);
    for byte in bytes {
        encoded.push_str(&format!("{:02x}", byte));
    }
    encoded
}

#[cfg(test)]
mod tests {
    use super::*;

    fn temp_dir(label: &str) -> PathBuf {
        let mut path = std::env::temp_dir();
        path.push(format!("{label}-{}", std::process::id()));
        let _ = fs::remove_dir_all(&path);
        path
    }

    fn validated_session_fixture() -> ValidatedSession {
        ValidatedSession {
            record: crate::session::SessionRecord {
                session_id: "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef"
                    .to_string(),
                csrf_token: "fedcba9876543210fedcba9876543210fedcba9876543210fedcba9876543210"
                    .to_string(),
                canonical_username: "alice@example.com".to_string(),
                issued_at: 10,
                expires_at: 100,
                last_seen_at: 20,
                revoked_at: None,
                remote_addr: "127.0.0.1".to_string(),
                user_agent: "Firefox/Test".to_string(),
                factor: crate::auth::RequiredSecondFactor::Totp,
            },
            audit_event: LogEvent::new(
                LogLevel::Info,
                EventCategory::Session,
                "session_validated",
                "browser session validated",
            ),
        }
    }

    fn context_fixture() -> AuthenticationContext {
        AuthenticationContext::new(
            crate::auth::AuthenticationPolicy::default(),
            "req-settings",
            "127.0.0.1",
            "Firefox/Test",
        )
        .expect("context should be valid")
    }

    #[test]
    fn file_settings_store_round_trips_settings() {
        let dir = temp_dir("osmap-user-settings");
        let store = FileUserSettingsStore::new(&dir);
        let settings = UserSettings {
            html_display_preference: HtmlDisplayPreference::PreferPlainText,
        };

        store
            .save("alice@example.com", &settings)
            .expect("save should succeed");
        let loaded = store
            .load("alice@example.com")
            .expect("load should succeed")
            .expect("settings should exist");

        assert_eq!(loaded, settings);
    }

    #[test]
    fn service_defaults_to_sanitized_html_preference() {
        let dir = temp_dir("osmap-user-settings-default");
        let service = UserSettingsService::new(FileUserSettingsStore::new(&dir));
        let loaded = service
            .load_for_validated_session(&context_fixture(), &validated_session_fixture())
            .expect("load should succeed");

        assert_eq!(
            loaded.settings.html_display_preference,
            HtmlDisplayPreference::PreferSanitizedHtml
        );
    }

    #[test]
    fn service_updates_html_preference() {
        let dir = temp_dir("osmap-user-settings-update");
        let service = UserSettingsService::new(FileUserSettingsStore::new(&dir));
        let updated = service
            .update_html_display_preference(
                &context_fixture(),
                &validated_session_fixture(),
                HtmlDisplayPreference::PreferPlainText,
            )
            .expect("update should succeed");

        assert_eq!(
            updated.settings.html_display_preference,
            HtmlDisplayPreference::PreferPlainText
        );
    }
}
