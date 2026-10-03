use super::*;
impl<G: BrowserGateway> BrowserApp<G> {
    pub(super) fn handle_composition_preferences_update(
        &self,
        request: &HttpRequest,
        context: &AuthenticationContext,
    ) -> HandledHttpResponse {
        let (session, mut audit_events) = match self.require_validated_session(request, context) {
            Ok(value) => value,
            Err(response) => return response,
        };
        let rejected = |status, reason, message| HandledHttpResponse {
            response: html_response(status, reason, "Composition Preference Not Saved", message),
            audit_events: vec![build_http_warning_event(
                "composition_preference_rejected",
                "composition preference was not confirmed",
                context,
            )],
        };
        if !allows_urlencoded_request_body(request.headers.get("content-type").map(String::as_str))
        {
            return rejected(
                400,
                "Bad Request",
                "<p>The form content type was not supported.</p>",
            );
        }
        let form = match parse_urlencoded_form(&request.body, 7, 512) {
            Ok(value) => value,
            Err(_) => {
                return rejected(
                    400,
                    "Bad Request",
                    "<p>The preference form was invalid.</p>",
                )
            }
        };
        if let Some(response) = self.require_valid_csrf(
            request,
            form.get("csrf_token").map(String::as_str),
            &session,
            context,
        ) {
            return response;
        }
        if form.keys().any(|key| {
            ![
                "csrf_token",
                "default_body_format",
                "reply_placement",
                "return_section",
                "pgp_sign",
                "pgp_encrypt",
                "pgp_self",
            ]
            .contains(&key.as_str())
        }) {
            return rejected(
                400,
                "Bad Request",
                "<p>The preference form contained an unsupported field.</p>",
            );
        }
        let Some(value) = form.get("default_body_format").and_then(|value| {
            crate::composition_preferences::CompositionPreferences::parse_default_format(value)
        }) else {
            return rejected(
                400,
                "Bad Request",
                "<p>Choose Plain text or Formatted text.</p>",
            );
        };
        let destination = match form.get("return_section").map(String::as_str) {
            None | Some("general") => "/settings?section=general&updated=1",
            Some("composition") => "/settings?section=composition&updated=1",
            _ => {
                return rejected(
                    400,
                    "Bad Request",
                    "<p>The settings destination was invalid.</p>",
                )
            }
        };
        let placement = if let Some(placement) = form.get("reply_placement") {
            let Some(placement) = crate::composition_preferences::ReplyPlacement::parse(placement)
            else {
                return rejected(
                    400,
                    "Bad Request",
                    "<p>Choose Above quoted text or Below quoted text.</p>",
                );
            };
            Some(placement)
        } else {
            None
        };
        let parse_choice = |name| match form.get(name).map(String::as_str) {
            Some("on") => Some(true),
            Some("off") => Some(false),
            _ => None,
        };
        let openpgp = if ["pgp_sign", "pgp_encrypt", "pgp_self"]
            .iter()
            .any(|name| form.contains_key(*name))
        {
            let (Some(sign), Some(encrypt), Some(encrypt_to_self)) = (
                parse_choice("pgp_sign"),
                parse_choice("pgp_encrypt"),
                parse_choice("pgp_self"),
            ) else {
                return rejected(
                    400,
                    "Bad Request",
                    "<p>Choose On or Off for all three OpenPGP defaults.</p>",
                );
            };
            if encrypt_to_self && !encrypt {
                return rejected(
                    400,
                    "Bad Request",
                    "<p>Encrypt to self requires Encryption On.</p>",
                );
            }
            Some(crate::composition_preferences::OpenPgpDefaults {
                sign,
                encrypt,
                encrypt_to_self,
            })
        } else {
            None
        };
        let saved = self.gateway.update_composition_preferences(
            context,
            &session,
            crate::composition_preferences::CompositionPreferencesUpdate {
                default_body_format: value.default_body_format,
                reply_placement: placement,
                openpgp,
            },
        );
        if saved.is_err() {
            return rejected(503, "Service Unavailable", "<p>The preference save could not be confirmed. Review your saved setting before retrying.</p>");
        }
        audit_events.push(build_http_info_event(
            "composition_preference_saved",
            "composition defaults saved",
            context,
        ));
        HandledHttpResponse {
            response: redirect_response(303, "See Other", destination),
            audit_events,
        }
    }
}
