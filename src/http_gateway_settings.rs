use super::*;
use crate::settings::{FileUserSettingsStore, UserSettingsError, UserSettingsService};

impl RuntimeBrowserGateway {
    /// Builds the current file-backed end-user settings service.
    pub(super) fn build_user_settings_service(&self) -> UserSettingsService<FileUserSettingsStore> {
        UserSettingsService::new(FileUserSettingsStore::new(self.settings_dir.clone()))
    }

    /// Projects persisted settings into the current browser-safe shape.
    pub(super) fn visible_settings(
        settings: crate::settings::UserSettings,
    ) -> BrowserVisibleSettings {
        BrowserVisibleSettings {
            html_display_preference: settings.html_display_preference,
        }
    }

    /// Builds a renderer policy for the current user-visible settings.
    pub(super) fn render_policy_for_html_preference(
        &self,
        html_display_preference: HtmlDisplayPreference,
    ) -> RenderingPolicy {
        let mut render_policy = self.render_policy;
        render_policy.html_display_preference = html_display_preference;
        render_policy
    }

    /// Records a non-fatal user-settings-store error so settings failures can
    /// be diagnosed without silently widening browser trust.
    pub(super) fn build_user_settings_store_error_event(
        &self,
        action: &'static str,
        message: &'static str,
        context: &AuthenticationContext,
        error: &UserSettingsError,
    ) -> LogEvent {
        build_http_warning_event(action, message, context)
            .with_field("reason", error.reason.clone())
    }

    pub(super) fn load_settings_impl(
        &self,
        context: &AuthenticationContext,
        validated_session: &ValidatedSession,
    ) -> BrowserSettingsOutcome {
        match self
            .build_user_settings_service()
            .load_for_validated_session(context, validated_session)
        {
            Ok(loaded) => BrowserSettingsOutcome {
                decision: BrowserSettingsDecision::Loaded {
                    canonical_username: validated_session.record.canonical_username.clone(),
                    settings: Self::visible_settings(loaded.settings),
                },
                audit_events: vec![loaded.audit_event],
            },
            Err(error) => BrowserSettingsOutcome {
                decision: BrowserSettingsDecision::Denied {
                    public_reason: "temporarily_unavailable".to_string(),
                },
                audit_events: vec![self.build_user_settings_store_error_event(
                    "user_settings_load_failed",
                    "user settings load failed",
                    context,
                    &error,
                )],
            },
        }
    }

    pub(super) fn update_settings_impl(
        &self,
        context: &AuthenticationContext,
        validated_session: &ValidatedSession,
        html_display_preference: HtmlDisplayPreference,
    ) -> BrowserSettingsUpdateOutcome {
        match self
            .build_user_settings_service()
            .update_html_display_preference(context, validated_session, html_display_preference)
        {
            Ok(updated) => BrowserSettingsUpdateOutcome {
                decision: BrowserSettingsUpdateDecision::Updated,
                audit_events: vec![updated.audit_event],
            },
            Err(error) => BrowserSettingsUpdateOutcome {
                decision: BrowserSettingsUpdateDecision::Denied {
                    public_reason: "temporarily_unavailable".to_string(),
                },
                audit_events: vec![self.build_user_settings_store_error_event(
                    "user_settings_update_failed",
                    "user settings update failed",
                    context,
                    &error,
                )],
            },
        }
    }
}
