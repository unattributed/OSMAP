//! Account-owned selectable Bin preference. This route never moves mail.
use super::*;
use crate::bin_folder::Error;

impl<G: BrowserGateway> BrowserApp<G> {
    pub(super) fn bin_folder_choices(
        &self,
        context: &AuthenticationContext,
        session: &ValidatedSession,
        audit: &mut Vec<LogEvent>,
    ) -> Option<Vec<MailboxEntry>> {
        let (guard, event) =
            match self.acquire_mailbox_budget(context, session, "bin_folder_choices") {
                Ok(value) => value,
                Err(response) => {
                    audit.extend(response.audit_events);
                    return None;
                }
            };
        audit.push(event);
        let deadline = std::time::Instant::now()
            + std::time::Duration::from_secs(
                self.policy.expensive_request_timeout_secs.clamp(1, 30),
            );
        let listing = self.gateway.list_mailboxes(context, session);
        audit.extend(listing.audit_events);
        let result = match listing.decision {
            BrowserMailboxDecision::Listed {
                canonical_username,
                mailboxes,
            } if canonical_username == session.record.canonical_username
                && super::routes_settings::valid_folder_listing(&mailboxes)
                && std::time::Instant::now() < deadline =>
            {
                let metadata = self.gateway.folder_metadata(context, session);
                audit.extend(metadata.audit_events);
                if metadata.canonical_username == canonical_username
                    && std::time::Instant::now() < deadline
                {
                    metadata
                        .snapshot
                        .as_ref()
                        .filter(|snapshot| snapshot.validate_for(&canonical_username).is_ok())
                        .map(|snapshot| {
                            mailboxes
                                .into_iter()
                                .filter(|entry| {
                                    crate::bin_folder::selectable(
                                        snapshot,
                                        &canonical_username,
                                        &entry.name,
                                    )
                                })
                                .collect()
                        })
                } else {
                    None
                }
            }
            _ => None,
        };
        audit.push(self.release_request_budget(guard, "bin_folder_choices", context, session));
        result
    }

    pub(super) fn handle_bin_folder_settings(
        &self,
        request: &HttpRequest,
        context: &AuthenticationContext,
    ) -> HandledHttpResponse {
        let (session, mut audit_events) = match self.require_validated_session(request, context) {
            Ok(value) => value,
            Err(response) => return response,
        };
        let form =
            allows_urlencoded_request_body(request.headers.get("content-type").map(String::as_str))
                .then(|| parse_urlencoded_form(&request.body, 4, 2048).ok())
                .flatten();
        let Some(form) = form else {
            return HandledHttpResponse {
                response: html_response(
                    400,
                    "Bad Request",
                    "Invalid Bin Folder",
                    "<p>Reload Reading or Copies settings before saving Bin.</p>",
                ),
                audit_events,
            };
        };
        if let Some(response) = self.require_valid_csrf(
            request,
            form.get("csrf_token").map(String::as_str),
            &session,
            context,
        ) {
            return response;
        }
        let revision = form.get("expected_revision").and_then(|value| {
            value
                .parse::<u64>()
                .ok()
                .filter(|n| n.to_string() == *value)
        });
        let folder = form
            .get("mailbox_name")
            .and_then(|v| crate::bin_folder::parse_mailbox_name(v).ok());
        let section = form
            .get("section")
            .map(String::as_str)
            .filter(|v| matches!(*v, "reading" | "copies"));
        let result = if form.keys().any(|key| {
            !matches!(
                key.as_str(),
                "csrf_token" | "expected_revision" | "mailbox_name" | "section"
            )
        }) {
            Err(Error::Invalid)
        } else {
            match (revision, folder.as_deref(), section) {
                (Some(revision), Some(name), Some(_)) => {
                    match self.bin_folder_choices(context, &session, &mut audit_events) {
                        Some(choices) if choices.iter().any(|entry| entry.name == name) => revision
                            .checked_add(1)
                            .ok_or(Error::Invalid)
                            .and_then(|next| {
                                self.gateway
                                    .update_bin_preference(&session, revision, name)
                                    .and_then(|saved| {
                                        if saved.revision == next && saved.mailbox_name == name {
                                            Ok(saved)
                                        } else {
                                            Err(Error::Unconfirmed)
                                        }
                                    })
                            }),
                        Some(_) => Err(Error::Invalid),
                        None => Err(Error::Unavailable),
                    }
                }
                _ => Err(Error::Invalid),
            }
        };
        audit_events.push(build_http_info_event(
            if result.is_ok() {
                "bin_folder_preference_saved"
            } else {
                "bin_folder_preference_unconfirmed"
            },
            "Bin preference evaluated",
            context,
        ));
        let destination = format!("/settings?section={}", section.unwrap_or("reading"));
        let response = match result {
            Ok(_) => redirect_response(303, "See Other", &format!("{destination}&updated=1")),
            Err(error) => html_response(match error { Error::Invalid => 400, Error::Stale => 409, Error::Unavailable | Error::Unconfirmed => 503 }, "Preference Not Confirmed", "Bin Folder Not Confirmed", TrustedHtml::from_template(format!(
                "{}<main id=\"main-content\" class=\"page-shell standalone-notice\" tabindex=\"-1\"><section class=\"panel\"><h1>Bin folder not confirmed</h1><p>Your submitted folder is shown below. Reload saved settings before another change. No message was moved.</p><fieldset disabled><label>Bin folder<input value=\"{}\"></label><label>Revision<input value=\"{}\"></label></fieldset><a href=\"{destination}\">Load saved settings</a></section></main>",
                crate::http_ui::app_header(&session.record.canonical_username, &session.record.csrf_token, if section == Some("copies") { "settings-copies" } else { "settings-reading" }),
                escape_html(form.get("mailbox_name").map(String::as_str).unwrap_or("")), escape_html(form.get("expected_revision").map(String::as_str).unwrap_or("")),
            ))),
        };
        HandledHttpResponse {
            response,
            audit_events,
        }
    }
}
