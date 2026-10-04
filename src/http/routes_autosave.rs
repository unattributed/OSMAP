//! Finite configuration and confirmation responses for compose-only automatic saves.
use super::*;
pub(super) fn json(status: u16, value: serde_json::Value) -> HttpResponse {
    HttpResponse::text(
        status,
        if status == 200 {
            "OK"
        } else if status == 409 {
            "Conflict"
        } else {
            "Service Unavailable"
        },
        value.to_string(),
    )
    .with_header("Content-Type", "application/json")
    .with_header("Cache-Control", "no-store")
    .with_header("X-Content-Type-Options", "nosniff")
    .with_header(
        "Content-Security-Policy",
        crate::http_support::browser_csp(),
    )
}
impl<G: BrowserGateway> BrowserApp<G> {
    pub(super) fn handle_autosave_config(
        &self,
        r: &HttpRequest,
        c: &AuthenticationContext,
    ) -> HandledHttpResponse {
        let (s, audit_events) = match self.require_validated_session(r, c) {
            Ok(v) => v,
            Err(e) => return e,
        };
        let response = match self.gateway.load_autosave(&s) {
            Ok(v) => json(
                200,
                serde_json::json!({"version":1,"enabled":v.enabled,"interval":v.interval}),
            ),
            Err(_) => json(503, serde_json::json!({"version":1,"state":"unavailable"})),
        };
        HandledHttpResponse {
            response,
            audit_events,
        }
    }
    pub(super) fn handle_autosave_settings(
        &self,
        r: &HttpRequest,
        c: &AuthenticationContext,
    ) -> HandledHttpResponse {
        let (s, mut audit_events) = match self.require_validated_session(r, c) {
            Ok(v) => v,
            Err(e) => return e,
        };
        let f = if allows_urlencoded_request_body(r.headers.get("content-type").map(String::as_str))
        {
            parse_urlencoded_form(&r.body, 4, 1024).ok()
        } else {
            None
        };
        let Some(f) = f else {
            return HandledHttpResponse {
                response: html_response(
                    400,
                    "Bad Request",
                    "Invalid auto-save preference",
                    "<p>Reload Composition settings before saving.</p>",
                ),
                audit_events,
            };
        };
        if let Some(e) = self.require_valid_csrf(r, f.get("csrf_token").map(String::as_str), &s, c)
        {
            return e;
        }
        let rev = f
            .get("revision")
            .and_then(|v| v.parse::<u64>().ok().filter(|n| n.to_string() == *v));
        let interval = f.get("interval").and_then(|v| {
            v.parse::<u16>()
                .ok()
                .filter(|n| n.to_string() == *v && matches!(n, 30 | 60 | 120))
        });
        let enabled = f.get("enabled").map(String::as_str) == Some("1");
        let result = if f.keys().any(|k| {
            !matches!(
                k.as_str(),
                "csrf_token" | "revision" | "interval" | "enabled"
            )
        }) || f.get("enabled").is_some_and(|v| v != "1")
        {
            Err(crate::autosave::Error::Invalid)
        } else {
            match (rev, interval) {
                (Some(rev), Some(interval)) => {
                    self.gateway.save_autosave(&s, rev, enabled, interval)
                }
                _ => Err(crate::autosave::Error::Invalid),
            }
        };
        audit_events.push(build_http_info_event(
            if result.is_ok() {
                "autosave_preference_saved"
            } else {
                "autosave_preference_unconfirmed"
            },
            "automatic saving preference evaluated",
            c,
        ));
        let response = match result {
            Ok(_) => redirect_response(303, "See Other", "/settings?section=composition"),
            Err(e) => {
                let status = match e {
                    crate::autosave::Error::Invalid => 400,
                    crate::autosave::Error::Stale => 409,
                    _ => 503,
                };
                html_response(status,if status==409{"Conflict"}else{"Save Not Confirmed"},"Auto-save preference not confirmed",TrustedHtml::from_template(format!("<h1>Auto-save preference not confirmed</h1><p>Your submitted choice is retained. Load saved settings before another change.</p><fieldset disabled><label>Auto-save drafts<input type=\"checkbox\"{}></label><label>Interval<input value=\"{}\"></label><label>Revision<input value=\"{}\"></label></fieldset><a href=\"/settings?section=composition\">Load saved Composition settings</a>",if enabled{" checked"}else{""},escape_html(f.get("interval").map(String::as_str).unwrap_or("")),escape_html(f.get("revision").map(String::as_str).unwrap_or("")))))
            }
        };
        HandledHttpResponse {
            response,
            audit_events,
        }
    }
    pub(super) fn autosave_confirmation(
        &self,
        c: &AuthenticationContext,
        s: &ValidatedSession,
        id: &str,
        form: &BTreeMap<String, String>,
        audit: &mut Vec<LogEvent>,
    ) -> HttpResponse {
        let loaded = self.gateway.load_draft(c, s, id);
        audit.extend(loaded.audit_events);
        let expected = super::routes_draft::submitted_draft_revision(form)
            .ok()
            .flatten()
            .unwrap_or(0)
            .checked_add(1);
        if let BrowserDraftLoadDecision::Loaded {
            canonical_username,
            draft,
        } = loaded.decision
        {
            let req = &draft.request;
            let equal =
                |key: &str, value: &str| form.get(key).map(String::as_str).unwrap_or("") == value;
            if canonical_username == s.record.canonical_username
                && draft.canonical_username == canonical_username
                && draft.draft_id == id
                && expected.is_some()
                && draft.revision == expected
                && equal("to", &req.recipients_text)
                && equal("cc", &req.cc_text)
                && equal("bcc", &req.bcc_text)
                && equal("subject", &req.subject)
                && equal("body", &req.body)
                && Some(req.body_format) == super::compose_actions::body_format(form)
            {
                if let Ok(intent) = crate::send_journal::intent_for_draft(
                    &canonical_username,
                    id,
                    expected.unwrap_or(0),
                    draft.updated_at,
                ) {
                    return json(
                        200,
                        serde_json::json!({"version":1,"state":"saved","draft_id":id,"revision":draft.revision,"send_intent":intent,"display_name":req.sender_identity.display_name(),"reply_to":req.sender_identity.reply_to(),"sender_address":req.sender_identity.sender().map(|s|s.address()).unwrap_or(&s.record.canonical_username)}),
                    );
                }
            }
        }
        json(503, serde_json::json!({"version":1,"state":"unconfirmed"}))
    }
}
