//! Native account-bound selection of existing server-authorized identities.
use super::*;
use crate::identity_preferences::{
    IdentityAction, IdentityPreferences, IdentityPreferencesError, SenderIdentityUpdate,
};
impl<G: BrowserGateway> BrowserApp<G> {
    pub(super) fn handle_sender_identity_update(
        &self,
        request: &HttpRequest,
        context: &AuthenticationContext,
    ) -> HandledHttpResponse {
        let (session, mut audit_events) = match self.require_validated_session(request, context) {
            Ok(value) => value,
            Err(response) => return response,
        };
        let invalid = || {
            HandledHttpResponse { response: html_response(400, "Bad Request", "Sender Identity Not Saved", "<p>The sender identity form was refused. Reload Identity settings before editing.</p>"), audit_events: vec![] }
        };
        if !request.query_params.is_empty()
            || request.body.len() > 4096
            || !allows_urlencoded_request_body(
                request.headers.get("content-type").map(String::as_str),
            )
        {
            return invalid();
        }
        let form = match parse_urlencoded_form(&request.body, 7, 4096) {
            Ok(value) => value,
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
        let Some(revision) = form
            .get("sender_revision")
            .and_then(|v| v.parse::<u64>().ok().filter(|n| n.to_string() == *v))
        else {
            return invalid();
        };
        let Some(id) = form
            .get("identity_id")
            .filter(|id| crate::sender_authority::valid_id(id))
        else {
            return invalid();
        };
        let action = match form.get("action").map(String::as_str) {
            Some("add") => IdentityAction::Add,
            Some("edit") => IdentityAction::Edit,
            Some("primary") => IdentityAction::Primary,
            _ => return invalid(),
        };
        let allowed = if action == IdentityAction::Edit {
            &[
                "csrf_token",
                "sender_revision",
                "identity_id",
                "action",
                "display_name",
                "reply_to",
                "use_for_new",
            ][..]
        } else {
            &["csrf_token", "sender_revision", "identity_id", "action"][..]
        };
        if form.keys().any(|key| !allowed.contains(&key.as_str()))
            || (action != IdentityAction::Edit && form.len() != 4)
            || (action == IdentityAction::Edit
                && (!form.contains_key("display_name") || !form.contains_key("reply_to")))
        {
            return invalid();
        }
        let use_for_new = match form.get("use_for_new").map(String::as_str) {
            Some("on") => true,
            None | Some("off") => false,
            _ => return invalid(),
        };
        let presentation = match IdentityPreferences::new(
            form.get("display_name").map(String::as_str).unwrap_or(""),
            form.get("reply_to").map(String::as_str),
        ) {
            Ok(value) => value,
            Err(_) => return invalid(),
        };
        let update = SenderIdentityUpdate {
            identity_id: id.clone(),
            action,
            presentation,
            use_for_new,
        };
        let result = self
            .gateway
            .update_sender_identity(&session, revision, &update);
        audit_events.push(
            build_http_info_event(
                if result.is_ok() {
                    "sender_identity_updated"
                } else {
                    "sender_identity_update_refused"
                },
                "sender identity preference update completed",
                context,
            )
            .with_field(
                "session_ref",
                crate::logging::audit_session_ref(&session.record.session_id),
            ),
        );
        let response = match result {
            Ok(_) => redirect_response(303, "See Other", "/settings?section=identity&updated=1"),
            Err(IdentityPreferencesError::InvalidInput) => html_response(400, "Bad Request", "Sender Identity Not Saved", "<p>The selected identity or presentation was refused. No server alias was created. <a href=\"/settings?section=identity\">Review current authorized identities</a>.</p>"),
            Err(IdentityPreferencesError::Stale) => html_response(409, "Conflict", "Sender Identity Changed", "<p>Identity settings changed in another view. No change from this form was applied. <a href=\"/settings?section=identity\">Review saved identities</a>.</p>"),
            Err(_) => html_response(503, "Service Unavailable", "Sender Identity Save Not Confirmed", "<p>The saved choice could not be confirmed. No server alias was created. <a href=\"/settings?section=identity\">Review saved identities</a> before retrying.</p>"),
        };
        HandledHttpResponse {
            response,
            audit_events,
        }
    }
}
