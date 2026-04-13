//! Bounded end-user settings for the first OSMAP browser release.
//!
//! This module intentionally stays small. The first settings surface exists to
//! expose a small set of meaningful preferences without turning OSMAP into a
//! broad preference platform.

use std::fs;
use std::io::Write as _;
use std::path::PathBuf;
use std::sync::atomic::{AtomicU64, Ordering};

use sha2::{Digest, Sha256};

use crate::auth::AuthenticationContext;
use crate::config::LogLevel;
use crate::logging::{EventCategory, LogEvent};
use crate::mailbox::{
    MailboxEntry, MailboxListingPolicy, DEFAULT_MAILBOX_NAME_MAX_LEN, DEFAULT_MAX_MAILBOXES,
};
use crate::rendering::HtmlDisplayPreference;
use crate::session::ValidatedSession;

/// The current bounded end-user settings record.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct UserSettings {
    pub html_display_preference: HtmlDisplayPreference,
    pub archive_mailbox_name: Option<String>,
}

impl Default for UserSettings {
    fn default() -> Self {
        Self {
            html_display_preference: HtmlDisplayPreference::PreferSanitizedHtml,
            archive_mailbox_name: None,
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

    fn temporary_settings_path(&self, path: &std::path::Path) -> PathBuf {
        let final_name = path
            .file_name()
            .and_then(|name| name.to_str())
            .unwrap_or("settings");
        let unique_suffix = NEXT_SETTINGS_TEMP_FILE_ID.fetch_add(1, Ordering::Relaxed);
        self.settings_dir.join(format!(
            ".{final_name}.{}.{}.tmp",
            std::process::id(),
            unique_suffix
        ))
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
        let tmp_path = self.temporary_settings_path(&path);
        let content = serialize_user_settings(settings);

        let mut file = fs::OpenOptions::new()
            .write(true)
            .create_new(true)
            .open(&tmp_path)
            .map_err(|error| UserSettingsError {
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

static NEXT_SETTINGS_TEMP_FILE_ID: AtomicU64 = AtomicU64::new(0);

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
            .with_field(
                "archive_mailbox_name",
                settings
                    .archive_mailbox_name
                    .clone()
                    .unwrap_or_else(|| "<unset>".to_string()),
            )
            .with_field("request_id", context.request_id.clone())
            .with_field("remote_addr", context.remote_addr.clone())
            .with_field("user_agent", context.user_agent.clone()),
            settings,
        })
    }

    /// Persists new browser-visible settings for the current validated user.
    pub fn update_browser_preferences(
        &self,
        context: &AuthenticationContext,
        validated_session: &ValidatedSession,
        html_display_preference: HtmlDisplayPreference,
        archive_mailbox_name: Option<&str>,
    ) -> Result<UpdatedUserSettings, UserSettingsError> {
        let archive_mailbox_name = parse_archive_mailbox_name(archive_mailbox_name)?;
        let settings = UserSettings {
            html_display_preference,
            archive_mailbox_name,
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
            .with_field(
                "archive_mailbox_name",
                settings
                    .archive_mailbox_name
                    .clone()
                    .unwrap_or_else(|| "<unset>".to_string()),
            )
            .with_field("request_id", context.request_id.clone())
            .with_field("remote_addr", context.remote_addr.clone())
            .with_field("user_agent", context.user_agent.clone()),
            settings,
        })
    }
}

fn serialize_user_settings(settings: &UserSettings) -> String {
    let mut content = format!(
        "html_display_preference={}\n",
        settings.html_display_preference.as_str()
    );
    if let Some(archive_mailbox_name) = &settings.archive_mailbox_name {
        content.push_str(&format!("archive_mailbox_name={archive_mailbox_name}\n"));
    }
    content
}

fn parse_user_settings(content: &str) -> Result<UserSettings, UserSettingsError> {
    let mut html_display_preference = None;
    let mut archive_mailbox_name = None;

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
            "archive_mailbox_name" => {
                archive_mailbox_name = Some(parse_archive_mailbox_name(Some(value))?)
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
        archive_mailbox_name: archive_mailbox_name.unwrap_or(None),
    })
}

pub fn parse_archive_mailbox_name(
    archive_mailbox_name: Option<&str>,
) -> Result<Option<String>, UserSettingsError> {
    let Some(archive_mailbox_name) = archive_mailbox_name else {
        return Ok(None);
    };
    let archive_mailbox_name = archive_mailbox_name.trim();
    if archive_mailbox_name.is_empty() {
        return Ok(None);
    }

    MailboxEntry::new(
        MailboxListingPolicy {
            mailbox_name_max_len: DEFAULT_MAILBOX_NAME_MAX_LEN,
            max_mailboxes: DEFAULT_MAX_MAILBOXES,
        },
        archive_mailbox_name.to_string(),
    )
    .map(|entry| Some(entry.name))
    .map_err(|error| UserSettingsError {
        reason: error.reason,
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
            archive_mailbox_name: Some("Archive/2026".to_string()),
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
    fn file_settings_store_saves_do_not_collide_across_users() {
        use std::sync::{Arc, Barrier};
        use std::thread;

        let dir = temp_dir("osmap-user-settings-concurrent");
        let store = Arc::new(FileUserSettingsStore::new(&dir));
        let alice_settings = UserSettings {
            html_display_preference: HtmlDisplayPreference::PreferPlainText,
            archive_mailbox_name: Some("Archive/Alice".to_string()),
        };
        let bob_settings = UserSettings {
            html_display_preference: HtmlDisplayPreference::PreferSanitizedHtml,
            archive_mailbox_name: Some("Archive/Bob".to_string()),
        };

        for _ in 0..200 {
            let barrier = Arc::new(Barrier::new(2));

            let alice_store = Arc::clone(&store);
            let alice_barrier = Arc::clone(&barrier);
            let alice_expected = alice_settings.clone();
            let alice_handle = thread::spawn(move || {
                alice_barrier.wait();
                alice_store
                    .save("alice@example.com", &alice_expected)
                    .expect("alice save should succeed");
            });

            let bob_store = Arc::clone(&store);
            let bob_barrier = Arc::clone(&barrier);
            let bob_expected = bob_settings.clone();
            let bob_handle = thread::spawn(move || {
                bob_barrier.wait();
                bob_store
                    .save("bob@example.com", &bob_expected)
                    .expect("bob save should succeed");
            });

            alice_handle.join().expect("alice writer should join");
            bob_handle.join().expect("bob writer should join");

            assert_eq!(
                store
                    .load("alice@example.com")
                    .expect("alice load should succeed")
                    .expect("alice settings should exist"),
                alice_settings
            );
            assert_eq!(
                store
                    .load("bob@example.com")
                    .expect("bob load should succeed")
                    .expect("bob settings should exist"),
                bob_settings
            );
        }
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
        assert_eq!(loaded.settings.archive_mailbox_name, None);
    }

    #[test]
    fn service_updates_browser_preferences() {
        let dir = temp_dir("osmap-user-settings-update");
        let service = UserSettingsService::new(FileUserSettingsStore::new(&dir));
        let updated = service
            .update_browser_preferences(
                &context_fixture(),
                &validated_session_fixture(),
                HtmlDisplayPreference::PreferPlainText,
                Some("Archive/2026"),
            )
            .expect("update should succeed");

        assert_eq!(
            updated.settings.html_display_preference,
            HtmlDisplayPreference::PreferPlainText
        );
        assert_eq!(
            updated.settings.archive_mailbox_name,
            Some("Archive/2026".to_string())
        );
    }

    #[test]
    fn archive_mailbox_name_treats_blank_values_as_unset() {
        assert_eq!(
            parse_archive_mailbox_name(Some("   ")).expect("blank archive name should be accepted"),
            None
        );
    }

    #[test]
    fn archive_mailbox_name_reuses_mailbox_name_validation() {
        let error = parse_archive_mailbox_name(Some("Archive\n2026"))
            .expect_err("control characters should be rejected");
        assert!(error.reason.contains("control characters"));
    }
}
