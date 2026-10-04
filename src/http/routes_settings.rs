//! End-user settings route handlers for the bounded browser runtime.
//!
//! This settings slice stays intentionally small and CSRF-bound so OSMAP can
//! expose a few useful preferences without becoming a broad preference UI.

use super::*;
use crate::settings::parse_archive_mailbox_name;

fn mailbox_name_exists(mailboxes: &[MailboxEntry], mailbox_name: &str) -> bool {
    mailboxes.iter().any(|mailbox| mailbox.name == mailbox_name)
}

impl<G> BrowserApp<G>
where
    G: BrowserGateway,
{
    /// Serves the current bounded settings page.
    pub(super) fn handle_settings_page(
        &self,
        request: &HttpRequest,
        context: &AuthenticationContext,
    ) -> HandledHttpResponse {
        let (validated_session, mut audit_events) =
            match self.require_validated_session(request, context) {
                Ok(result) => result,
                Err(response) => return response,
            };
        if request.query_params.contains_key("folder") && request.query_params.contains_key("q") {
            return HandledHttpResponse {
                response: html_response(
                    400,
                    "Bad Request",
                    "Invalid Folder Selection",
                    "<p>Select a folder from Copies &amp; Folders.</p>",
                ),
                audit_events,
            };
        }
        if let Some(query) = request.query_params.get("q") {
            if query.chars().count() > 128 || query.chars().any(char::is_control) {
                return HandledHttpResponse {
                    response: html_response(
                        400,
                        "Bad Request",
                        "Invalid Settings Search",
                        "<p>Use at most 128 characters to search Settings.</p>",
                    ),
                    audit_events,
                };
            }
            return HandledHttpResponse {
                response: html_response(
                    200,
                    "OK",
                    "Search Settings",
                    crate::http_ui::render_settings_search_page(
                        &validated_session.record.canonical_username,
                        &validated_session.record.csrf_token,
                        query.trim(),
                    ),
                ),
                audit_events,
            };
        }
        let success_message = if ["appearance_updated", "updated"]
            .iter()
            .any(|key| request.query_params.get(*key).map(String::as_str) == Some("1"))
        {
            Some("Current saved settings are shown below. Review your values.")
        } else {
            None
        };

        let section = request
            .query_params
            .get("section")
            .map(String::as_str)
            .unwrap_or("general");
        if !matches!(
            section,
            "general"
                | "appearance"
                | "reading"
                | "composition"
                | "copies"
                | "privacy"
                | "security"
                | "authentication"
                | "identity"
                | "notifications"
                | "openpgp"
        ) {
            return HandledHttpResponse {
                response: html_response(
                    400,
                    "Bad Request",
                    "Unknown Settings Section",
                    "<p>Choose a section from Settings.</p>",
                ),
                audit_events,
            };
        }
        if request.query_params.get("folder").is_some_and(|name| {
            section != "copies"
                || MailboxEntry::new(
                    crate::mailbox::MailboxListingPolicy::default(),
                    name.clone(),
                )
                .is_err()
        }) {
            return HandledHttpResponse {
                response: html_response(
                    400,
                    "Bad Request",
                    "Invalid Folder Selection",
                    "<p>Select a folder from Copies &amp; Folders.</p>",
                ),
                audit_events,
            };
        }
        if section == "openpgp" {
            let inventory =
                self.public_inventory_view(context, &validated_session, &mut audit_events);
            let capability = self.gateway.compose_protection(
                &validated_session,
                "",
                "",
                "",
                crate::send::ProtectionIntent::default(),
            );
            return HandledHttpResponse {
                response: html_response(
                    200,
                    "OK",
                    "OpenPGP Settings",
                    crate::http_ui::render_openpgp_settings(
                        &validated_session.record.canonical_username,
                        &validated_session.record.csrf_token,
                        &inventory,
                        capability.as_ref(),
                    ),
                ),
                audit_events,
            };
        }

        if section == "notifications" {
            return HandledHttpResponse {
                response: html_response(
                    200,
                    "OK",
                    "Notification Settings",
                    crate::http_ui::render_notifications_page(
                        &validated_session.record.canonical_username,
                        &validated_session.record.csrf_token,
                    ),
                ),
                audit_events,
            };
        }
        if section == "identity" {
            let signature = self.gateway.load_signature(&validated_session).ok();
            let loaded = self
                .gateway
                .load_identity_preferences(context, &validated_session);
            return HandledHttpResponse {
                response: match loaded {
                    Ok(record) => html_response(200, "OK", "Identity Settings", crate::http_ui::render_identity_page_with_signature(&crate::http_ui::IdentityPageModel {
                        canonical_username: &validated_session.record.canonical_username,
                        csrf_token: &validated_session.record.csrf_token,
                        revision: record.revision,
                        display_name: record.preferences.display_name(),
                        reply_to: record.preferences.reply_to().unwrap_or(""),
                        error_message: None,
                        available: true,
                    },signature.as_ref())),
                    Err(_) => html_response(503, "Service Unavailable", "Identity Settings Unavailable", crate::http_ui::render_identity_page_with_signature(&crate::http_ui::IdentityPageModel {
                        canonical_username: &validated_session.record.canonical_username,
                        csrf_token: &validated_session.record.csrf_token,
                        revision: 0,
                        display_name: "",
                        reply_to: "",
                        error_message: Some("Your saved identity preferences could not be loaded. No preference was changed. Reload this page before editing."),
                        available: false,
                    },signature.as_ref())),
                },
                audit_events,
            };
        }
        if matches!(section, "security" | "authentication") {
            let outcome = self.gateway.list_sessions(context, &validated_session);
            audit_events.extend(outcome.audit_events);
            let mut key_state = if section == "security" {
                Some(self.gateway.key_management(context, &validated_session))
            } else {
                None
            };
            if let Some(keys) = key_state.as_mut() {
                audit_events.append(&mut keys.audit_events);
            }
            return HandledHttpResponse {
                response: html_response(
                    200,
                    "OK",
                    "Settings",
                    crate::http_ui::render_security_page(
                        &validated_session.record.canonical_username,
                        &validated_session.record.csrf_token,
                        &outcome.decision,
                        key_state.as_ref().map(|keys| &keys.state),
                        section == "authentication",
                    ),
                ),
                audit_events,
            };
        }
        let (presentation, appearance_error) = match self
            .gateway
            .load_display(context, &validated_session)
        {
            Ok(value) => (value, None),
            Err(_) => {
                audit_events.push(build_http_warning_event(
                    "appearance_load_failed",
                    "appearance preference unavailable",
                    context,
                ));
                (AppearanceSettings::default(), Some("Your saved appearance could not be loaded. System colours are being used. If this continues, ask your administrator to check preference storage."))
            }
        };
        let outcome = self.gateway.load_settings(context, &validated_session);
        audit_events.extend(outcome.audit_events);

        match outcome.decision {
            BrowserSettingsDecision::Loaded { ref canonical_username, .. }
                if canonical_username != &validated_session.record.canonical_username =>
            {
                HandledHttpResponse {
                    response: html_response(
                        503,
                        "Service Unavailable",
                        "Settings Unavailable",
                        "<p>The saved settings could not be confirmed for this account. No preference was changed.</p>",
                    ),
                    audit_events,
                }
            }
            BrowserSettingsDecision::Loaded {
                canonical_username,
                settings,
            } => HandledHttpResponse {
                response: html_response(200, "OK", "Settings", {
                    let model = SettingsPageModel {
                        canonical_username: &canonical_username,
                        csrf_token: &validated_session.record.csrf_token,
                        success_message,
                        error_message: appearance_error,
                        html_display_preference: settings.html_display_preference,
                        archive_mailbox_name: settings.archive_mailbox_name.as_deref(),
                    };
                    if section == "privacy" {
                        crate::http_ui::render_privacy_page(&model)
                    } else if section == "copies" {
                        let owned_mailboxes = self.reading_mailbox_choices(context, &validated_session, &mut audit_events).filter(|entries| valid_folder_listing(entries));
                        let mailboxes = owned_mailboxes.as_ref().map(|entries| super::routes_mail::filter_user_visible_mailboxes(entries));
                        let hierarchy = owned_mailboxes.as_ref().and_then(|entries| self.folder_hierarchy(context, &validated_session, entries, &mut audit_events));
                        let chosen = request.query_params.get("folder").map(String::as_str)
                            .or(model.archive_mailbox_name).filter(|name| hierarchy.as_ref().is_none_or(|tree| tree.selectable(name))).filter(|name| mailboxes.as_ref().is_some_and(|entries| entries.iter().any(|v| v.name == *name)))
                            .or_else(|| if request.query_params.contains_key("folder") { None } else { mailboxes.as_ref().and_then(|v| v.iter().find(|m| hierarchy.as_ref().is_none_or(|tree| tree.selectable(&m.name)))).map(|v| v.name.as_str()) });
                        if request.query_params.contains_key("folder") && mailboxes.is_some() && chosen.is_none() {
                            return HandledHttpResponse { response: html_response(400, "Bad Request", "Folder Unavailable", "<p>Select a folder from Copies &amp; Folders.</p>"), audit_events };
                        }
                        let counts = chosen.and_then(|name| self.folder_counts(context, &validated_session, name, &mut audit_events));
                        {
                            let status=chosen.and_then(|folder| self.folder_status(context,&validated_session,folder,&mut audit_events));
                            let creation = chosen.zip(status.as_ref()).zip(hierarchy.as_ref()).is_some_and(|((name, status), tree)| tree.can_create(&canonical_username, name, status));
                            {
                                let bin = self.gateway.load_bin_preference(&validated_session).ok();
                                let sent_copy = self.gateway.load_sent_copy_preference(&validated_session).ok();
                                let bin_choices = self.bin_folder_choices(context, &validated_session, &mut audit_events);
                                crate::http_ui::render_copies_page_with_state(&model, crate::http_ui::CopiesPageState { mailboxes: mailboxes.as_deref(), chosen, counts, status: status.as_ref(), hierarchy: hierarchy.as_ref(), creation, bin: bin.as_ref(), bin_choices: bin_choices.as_deref(), sent_copy: sent_copy.as_ref() })
                            }
                        }
                    } else if section == "appearance" {
                        crate::http_ui::render_appearance_page(&model, &presentation)
                    } else if section == "composition" {
                        crate::http_ui::render_composition_page_with_signature(
                            &model,
                            self.gateway.load_composition_preferences(context, &validated_session).ok(),
                            self.gateway.load_signature(&validated_session).ok().as_ref(),
                            self.gateway.load_autosave(&validated_session).ok().as_ref(),
                        )
                    } else if section == "general" {
                        let mark_read = self.load_settings_mark_read_policy(context, &validated_session, &mut audit_events);
                        crate::http_ui::render_general_page_with_mark_read(
                            &model,
                            &presentation,
                            self.gateway
                                .load_composition_preferences(context, &validated_session)
                                .ok(),
                            self.gateway
                                .load_identity_preferences(context, &validated_session)
                                .ok(),
                            self.gateway.load_reading_preferences(context, &validated_session).ok(),
                            self.gateway.load_signature(&validated_session).ok().as_ref(),
                            mark_read.as_ref(),
                        )
                    } else {
                        let preferences = match self.gateway.load_reading_preferences(context, &validated_session) {
                            Ok(value) => value,
                            Err(_) => {
                                audit_events.push(build_http_warning_event("reading_preferences_load_failed", "stored reading preferences could not be loaded", context));
                                return HandledHttpResponse {
                                    response: html_response(503, "Service Unavailable", "Reading Settings Unavailable", "<p>Your saved reading preferences could not be loaded. No defaults were saved. <a href=\"/settings?section=reading\">Try loading Reading settings again</a>.</p>"),
                                    audit_events,
                                };
                            }
                        };
                        let mailboxes = self.reading_mailbox_choices(context, &validated_session, &mut audit_events);
                        let mark_read = self.load_settings_mark_read_policy(context, &validated_session, &mut audit_events);
                        {
                            let bin = self.gateway.load_bin_preference(&validated_session).ok();
                            let bin_choices = self.bin_folder_choices(context, &validated_session, &mut audit_events);
                            crate::http_ui::render_reading_page_with_folders(&model, &preferences, mailboxes.as_deref(),self.gateway.load_after_archive(&validated_session).ok().as_ref(),mark_read.as_ref(), bin.as_ref(), bin_choices.as_deref())
                        }
                    }
                })
                .with_header(
                    "Set-Cookie",
                    presentation.theme.cookie(self.policy.secure_session_cookie),
                )
                .with_header(
                    "Set-Cookie",
                    presentation.cookie(self.policy.secure_session_cookie),
                ),
                audit_events,
            },
            BrowserSettingsDecision::Denied { public_reason } => HandledHttpResponse {
                response: html_response(
                    503,
                    "Service Unavailable",
                    "Settings Unavailable",
                    TrustedHtml::from_template(format!(
                        "<p>{}</p>",
                        escape_html(public_reason_message(&public_reason))
                    )),
                ),
                audit_events,
            },
        }
    }

    fn load_settings_mark_read_policy(
        &self,
        context: &AuthenticationContext,
        session: &ValidatedSession,
        audit_events: &mut Vec<LogEvent>,
    ) -> Option<crate::mark_read::Preference> {
        match self.gateway.load_mark_read_policy(session) {
            Ok(value) => Some(value),
            Err(_) => {
                audit_events.push(build_http_warning_event(
                    "mark_read_preference_load_failed",
                    "stored mark-read preference could not be loaded",
                    context,
                ));
                None
            }
        }
    }

    /// Handles CSRF-bound end-user settings updates.
    pub(super) fn handle_settings_update(
        &self,
        request: &HttpRequest,
        context: &AuthenticationContext,
    ) -> HandledHttpResponse {
        if !allows_urlencoded_request_body(request.headers.get("content-type").map(String::as_str))
        {
            return HandledHttpResponse {
                response: html_response(
                    400,
                    "Bad Request",
                    "Invalid Settings Request",
                    "<p>The settings form content type was not supported.</p>",
                ),
                audit_events: vec![build_http_warning_event(
                    "http_settings_content_type_rejected",
                    "settings form content type was not supported",
                    context,
                )],
            };
        }

        let form = match parse_urlencoded_form(
            &request.body,
            self.policy.max_form_fields,
            self.policy.max_body_bytes,
        ) {
            Ok(form) => form,
            Err(error) => {
                return HandledHttpResponse {
                    response: html_response(
                        400,
                        "Bad Request",
                        "Invalid Settings Request",
                        "<p>The settings form could not be parsed.</p>",
                    ),
                    audit_events: vec![build_http_warning_event(
                        "http_settings_parse_failed",
                        "settings form parsing failed",
                        context,
                    )
                    .with_field("reason", error.reason)],
                };
            }
        };

        let (validated_session, mut audit_events) =
            match self.require_validated_session(request, context) {
                Ok(result) => result,
                Err(response) => return response,
            };
        if let Some(response) = self.require_valid_csrf(
            request,
            form.get("csrf_token").map(String::as_str),
            &validated_session,
            context,
        ) {
            return response;
        }

        let destination = match form.get("return_section").map(String::as_str) {
            None | Some("general") => "/settings?updated=1",
            Some("reading") => "/settings?section=reading&updated=1",
            Some("copies") => "/settings?section=copies&updated=1",
            Some("privacy") => "/settings?section=privacy&updated=1",
            Some(_) => return HandledHttpResponse {
                response: html_response(
                    400,
                    "Bad Request",
                    "Invalid Settings Request",
                    "<p>The settings return section was invalid. No preference was changed.</p>",
                ),
                audit_events,
            },
        };
        let content_only = form.get("settings_action").map(String::as_str) == Some("content");
        let archive_only = form.get("settings_action").map(String::as_str) == Some("archive");
        if form
            .get("settings_action")
            .is_some_and(|value| value != "archive" && value != "content")
            || content_only
                && (!form.contains_key("html_display_preference")
                    || form.keys().any(|key| {
                        ![
                            "csrf_token",
                            "settings_action",
                            "html_display_preference",
                            "return_section",
                        ]
                        .contains(&key.as_str())
                    }))
            || archive_only
                && (!form.contains_key("archive_mailbox_name")
                    || form.keys().any(|key| {
                        ![
                            "csrf_token",
                            "settings_action",
                            "archive_mailbox_name",
                            "return_section",
                        ]
                        .contains(&key.as_str())
                    }))
        {
            return HandledHttpResponse {
                response: html_response(
                    400,
                    "Bad Request",
                    "Invalid Settings Request",
                    "<p>The settings action was invalid. No preference was changed.</p>",
                ),
                audit_events,
            };
        }
        let html_display_preference = if archive_only {
            None
        } else {
            let Some(html_display_preference) = form.get("html_display_preference") else {
                return HandledHttpResponse {
                    response: html_response(
                        400,
                        "Bad Request",
                        "Invalid Settings Request",
                        "<p>An HTML display preference is required.</p>",
                    ),
                    audit_events: vec![build_http_warning_event(
                        "http_settings_missing_preference",
                        "settings update missing html display preference",
                        context,
                    )],
                };
            };

            let html_display_preference =
                match HtmlDisplayPreference::parse(html_display_preference) {
                    Ok(html_display_preference) => html_display_preference,
                    Err(error) => {
                        return HandledHttpResponse {
                            response: html_response(
                                400,
                                "Bad Request",
                                "Invalid Settings Request",
                                "<p>The submitted HTML display preference was not valid.</p>",
                            ),
                            audit_events: vec![build_http_warning_event(
                                "http_settings_preference_rejected",
                                "settings update preference validation failed",
                                context,
                            )
                            .with_field("reason", error.reason)],
                        };
                    }
                };
            Some(html_display_preference)
        };
        let archive_mailbox_name = match parse_archive_mailbox_name(
            form.get("archive_mailbox_name").map(String::as_str),
        ) {
            Ok(archive_mailbox_name) => archive_mailbox_name,
            Err(error) => {
                return HandledHttpResponse {
                    response: html_response(
                        400,
                        "Bad Request",
                        "Invalid Settings Request",
                        "<p>The submitted archive mailbox name was not valid.</p>",
                    ),
                    audit_events: vec![build_http_warning_event(
                        "http_settings_archive_mailbox_rejected",
                        "settings update archive mailbox validation failed",
                        context,
                    )
                    .with_field("reason", error.reason)],
                };
            }
        };

        if let Some(archive_mailbox_name) = archive_mailbox_name.as_deref() {
            let mailbox_outcome = self.gateway.list_mailboxes(context, &validated_session);
            audit_events.extend(mailbox_outcome.audit_events);

            match mailbox_outcome.decision {
                BrowserMailboxDecision::Listed {
                    canonical_username,
                    mailboxes,
                } => {
                    if canonical_username != validated_session.record.canonical_username {
                        return HandledHttpResponse { response: html_response(503,"Service Unavailable","Settings Update Failed","<p>The mailbox list could not be confirmed for this account. No preference was changed.</p>"), audit_events };
                    }
                    let mailboxes =
                        if form.get("return_section").map(String::as_str) == Some("copies") {
                            super::routes_mail::filter_user_visible_mailboxes(&mailboxes)
                        } else {
                            mailboxes
                        };
                    if !mailbox_name_exists(&mailboxes, archive_mailbox_name) {
                        return HandledHttpResponse {
                            response: html_response(
                                400,
                                "Bad Request",
                                "Invalid Settings Request",
                                "<p>The selected archive mailbox does not exist for this account.</p>",
                            ),
                            audit_events: {
                                audit_events.push(
                                    build_http_warning_event(
                                        "http_settings_archive_mailbox_missing",
                                        "settings update archive mailbox did not match mailbox listing",
                                        context,
                                    )
                                    .with_field(
                                        "archive_mailbox_name",
                                        archive_mailbox_name.to_string(),
                                    ),
                                );
                                audit_events
                            },
                        };
                    }
                }
                BrowserMailboxDecision::Denied { public_reason } => {
                    return HandledHttpResponse {
                        response: html_response(
                            503,
                            "Service Unavailable",
                            "Settings Update Failed",
                            TrustedHtml::from_template(format!(
                                "<p>{}</p>",
                                escape_html(public_reason_message(&public_reason))
                            )),
                        ),
                        audit_events,
                    };
                }
            }
        }

        let outcome = if archive_only {
            self.gateway.update_archive_setting(
                context,
                &validated_session,
                archive_mailbox_name.as_deref(),
            )
        } else {
            let Some(content) = html_display_preference else {
                return HandledHttpResponse {
                    response: html_response(
                        400,
                        "Bad Request",
                        "Invalid Settings Request",
                        "<p>A content preference is required.</p>",
                    ),
                    audit_events,
                };
            };
            if content_only {
                self.gateway
                    .update_content_setting(context, &validated_session, content)
            } else {
                self.gateway.update_settings(
                    context,
                    &validated_session,
                    content,
                    archive_mailbox_name.as_deref(),
                )
            }
        };
        audit_events.extend(outcome.audit_events);

        match outcome.decision {
            BrowserSettingsUpdateDecision::Updated => HandledHttpResponse {
                response: redirect_response(303, "See Other", destination),
                audit_events,
            },
            BrowserSettingsUpdateDecision::Denied { public_reason } => {
                let (status_code, reason_phrase, title) = if public_reason == "invalid_request" {
                    (400, "Bad Request", "Invalid Settings Request")
                } else {
                    (503, "Service Unavailable", "Settings Update Failed")
                };
                HandledHttpResponse {
                    response: html_response(
                        status_code,
                        reason_phrase,
                        title,
                        TrustedHtml::from_template(format!(
                            "<p>{}</p>",
                            escape_html(if public_reason == "invalid_request" {
                                public_reason_message(&public_reason)
                            } else {
                                "The settings save could not be confirmed. Review your saved values before retrying."
                            })
                        )),
                    ),
                    audit_events,
                }
            }
        }
    }
}

pub(super) fn valid_folder_listing(entries: &[MailboxEntry]) -> bool {
    let mut names = std::collections::BTreeSet::new();
    entries.len() <= crate::mailbox::DEFAULT_MAX_MAILBOXES
        && entries.iter().all(|v| {
            MailboxEntry::new(
                crate::mailbox::MailboxListingPolicy::default(),
                v.name.clone(),
            )
            .is_ok()
                && names.insert(v.name.as_str())
        })
}

fn verified_folder_counts(
    account: &str,
    folder: &str,
    decision: BrowserMessageListDecision,
) -> Option<(usize, usize)> {
    let BrowserMessageListDecision::Listed {
        canonical_username,
        mailbox_name,
        messages,
    } = decision
    else {
        return None;
    };
    let mut uids = std::collections::BTreeSet::new();
    if canonical_username != account
        || mailbox_name != folder
        || messages.len() > crate::mailbox::DEFAULT_MAX_MESSAGES
        || messages.iter().any(|row| {
            row.mailbox_name != folder
                || row.uid == 0
                || row.uid > u64::from(u32::MAX)
                || !uids.insert(row.uid)
                || row.flags.len() > 256
                || row.flags.iter().map(String::len).sum::<usize>() > 256
                || row.flags.iter().any(|flag| {
                    flag.is_empty() || flag.chars().any(|ch| ch.is_control() || ch.is_whitespace())
                })
        })
    {
        return None;
    }
    Some((
        messages.len(),
        messages
            .iter()
            .filter(|row| {
                !row.flags
                    .iter()
                    .any(|flag| flag.eq_ignore_ascii_case("\\Seen"))
            })
            .count(),
    ))
}

impl<G: BrowserGateway> BrowserApp<G> {
    fn folder_hierarchy(
        &self,
        context: &AuthenticationContext,
        session: &ValidatedSession,
        entries: &[MailboxEntry],
        audit: &mut Vec<LogEvent>,
    ) -> Option<crate::http::FolderTree> {
        let (guard, event) =
            match self.acquire_mailbox_budget(context, session, "settings_folder_hierarchy") {
                Ok(v) => v,
                Err(r) => {
                    audit.extend(r.audit_events);
                    return None;
                }
            };
        audit.push(event);
        let outcome = self.gateway.folder_metadata(context, session);
        audit.extend(outcome.audit_events);
        audit.push(self.release_request_budget(
            guard,
            "settings_folder_hierarchy",
            context,
            session,
        ));
        if outcome.canonical_username != session.record.canonical_username {
            return None;
        }
        crate::http::FolderTree::build(
            &session.record.canonical_username,
            outcome.snapshot.as_ref()?,
            entries,
        )
    }
    fn folder_status(
        &self,
        context: &AuthenticationContext,
        session: &ValidatedSession,
        folder: &str,
        audit: &mut Vec<LogEvent>,
    ) -> Option<crate::mailbox_status::MailboxStatus> {
        crate::mailbox_status::validate_name(folder).ok()?;
        let (guard, event) =
            match self.acquire_mailbox_budget(context, session, "settings_folder_status") {
                Ok(v) => v,
                Err(r) => {
                    audit.extend(r.audit_events);
                    return None;
                }
            };
        audit.push(event);
        let outcome = self.gateway.mailbox_status(context, session, folder);
        audit.extend(outcome.audit_events);
        audit.push(self.release_request_budget(guard, "settings_folder_status", context, session));
        if outcome.canonical_username != session.record.canonical_username {
            return None;
        }
        outcome.status.filter(|v| v.validate(folder).is_ok())
    }
    fn folder_counts(
        &self,
        context: &AuthenticationContext,
        session: &ValidatedSession,
        folder: &str,
        audit: &mut Vec<LogEvent>,
    ) -> Option<(usize, usize)> {
        let (guard, event) =
            match self.acquire_mailbox_budget(context, session, "settings_folder_summaries") {
                Ok(value) => value,
                Err(response) => {
                    audit.extend(response.audit_events);
                    return None;
                }
            };
        audit.push(event);
        let outcome = self.gateway.list_messages(context, session, folder);
        audit.extend(outcome.audit_events);
        audit.push(self.release_request_budget(
            guard,
            "settings_folder_summaries",
            context,
            session,
        ));
        verified_folder_counts(&session.record.canonical_username, folder, outcome.decision)
    }
}

impl<G: BrowserGateway> BrowserApp<G> {
    fn public_inventory_view(
        &self,
        context: &AuthenticationContext,
        session: &ValidatedSession,
        audit: &mut Vec<LogEvent>,
    ) -> crate::http_ui::key_inventory_ui::PublicInventoryView {
        let outcome = self.gateway.public_key_inventory(context, session);
        audit.extend(outcome.audit_events);
        crate::http_ui::key_inventory_ui::map_public_inventory(
            &session.record.canonical_username,
            &outcome.canonical_username,
            outcome.inventory.as_ref(),
        )
    }
}

#[cfg(test)]
mod folder_count_tests {
    use super::*;
    #[test]
    fn counts_refuse_overbound_malformed_flags_and_ambiguous_folders() {
        let row = MessageSummary {
            to: None,
            metadata: None,
            mailbox_name: "INBOX".into(),
            uid: 1,
            flags: vec![],
            date_received: String::new(),
            size_virtual: 0,
            subject: None,
            from: None,
        };
        let project = |rows| {
            verified_folder_counts(
                "a@example.test",
                "INBOX",
                BrowserMessageListDecision::Listed {
                    canonical_username: "a@example.test".into(),
                    mailbox_name: "INBOX".into(),
                    messages: rows,
                },
            )
        };
        assert_eq!(project(vec![row.clone()]), Some((1, 1)));
        let mut read = row.clone();
        read.flags = vec!["\\seen".into()];
        assert_eq!(project(vec![read]), Some((1, 0)));
        let mut oversized_uid = row.clone();
        oversized_uid.uid = u64::from(u32::MAX) + 1;
        assert_eq!(project(vec![oversized_uid]), None);
        assert_eq!(project(vec![row.clone(); 2001]), None);
        let mut bad = row;
        bad.flags = vec!["\\Seen\n".into()];
        assert_eq!(project(vec![bad]), None);
        assert!(!valid_folder_listing(&[
            MailboxEntry {
                name: "INBOX".into()
            },
            MailboxEntry {
                name: "INBOX".into()
            }
        ]));
        assert!(!valid_folder_listing(&[MailboxEntry {
            name: "bad\n".into()
        }]));
    }
}
