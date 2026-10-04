//! Native account-bound Identity updates; aliases and canonical From are not writable.
use super::*;
use crate::identity_preferences::{IdentityPreferences, IdentityPreferencesError};
impl<G: BrowserGateway> BrowserApp<G> {
    pub(super) fn handle_identity_preferences_update(
        &self,
        request: &HttpRequest,
        context: &AuthenticationContext,
    ) -> HandledHttpResponse {
        let (session, mut audit_events) = match self.require_validated_session(request, context) {
            Ok(v) => v,
            Err(response) => return response,
        };
        let invalid = || {
            HandledHttpResponse {response:html_response(400,"Bad Request","Identity Not Saved","<p>The Identity form could not be read. Reload Identity settings before editing.</p>"),audit_events:vec![]}
        };
        if !allows_urlencoded_request_body(request.headers.get("content-type").map(String::as_str))
        {
            return invalid();
        }
        let form = match parse_urlencoded_form(&request.body, 4, 4096) {
            Ok(form) => form,
            Err(_) => return invalid(),
        };
        if let Some(response) = self.require_valid_csrf(
            request,
            form.get("csrf_token").map(String::as_str),
            &session,
            context,
        ) {
            return response;
        }
        let name = form.get("display_name").map(String::as_str).unwrap_or("");
        let reply = form.get("reply_to").map(String::as_str).unwrap_or("");
        let revision = form
            .get("identity_revision")
            .and_then(|v| v.parse::<u64>().ok().filter(|n| n.to_string() == *v));
        let result = if form.keys().any(|key| {
            ![
                "csrf_token",
                "identity_revision",
                "display_name",
                "reply_to",
            ]
            .contains(&key.as_str())
        }) || !form.contains_key("display_name")
            || !form.contains_key("reply_to")
            || revision.is_none()
        {
            Err(IdentityPreferencesError::InvalidInput)
        } else {
            IdentityPreferences::new(name, Some(reply)).and_then(|value| {
                self.gateway.update_identity_preferences(
                    context,
                    &session,
                    revision.unwrap_or(0),
                    &value,
                )
            })
        };
        let failed = result.is_err();
        audit_events.push(
            if failed {
                build_http_warning_event(
                    "identity_preferences_update_failed",
                    "identity preference save not confirmed",
                    context,
                )
            } else {
                build_http_info_event(
                    "identity_preferences_updated",
                    "identity preferences saved",
                    context,
                )
            }
            .with_field(
                "session_ref",
                crate::logging::audit_session_ref(&session.record.session_id),
            ),
        );
        match result {
            Ok(_) => HandledHttpResponse {
                response: redirect_response(
                    303,
                    "See Other",
                    "/settings?section=identity&updated=1",
                ),
                audit_events,
            },
            Err(error) => {
                let (status,reason,message,available)=match error {
                    IdentityPreferencesError::InvalidInput=>(400,"Bad Request","Use a display name of at most 128 characters and 256 UTF-8 bytes, without controls or surrounding spaces. Reply-To must be one bare email address, or empty.",revision.is_some()),
                    IdentityPreferencesError::Stale=>(409,"Conflict","Identity changed in another view. Your entered values are shown below. Reload Identity settings and reconcile the saved values before saving again.",true),
                    _=>(503,"Service Unavailable","The Identity save could not be confirmed. Your entered values are shown below. Reload Identity settings to review the saved record before trying again.",false),
                };
                HandledHttpResponse {
                    response: html_response(
                        status,
                        reason,
                        "Identity Not Saved",
                        crate::http_ui::render_identity_page(&crate::http_ui::IdentityPageModel {
                            canonical_username: &session.record.canonical_username,
                            csrf_token: &session.record.csrf_token,
                            revision: revision.unwrap_or(0),
                            display_name: name,
                            reply_to: reply,
                            error_message: Some(message),
                            available,
                            sender_inventory: None,
                            sender_record: None,
                        }),
                    ),
                    audit_events,
                }
            }
        }
    }
}
