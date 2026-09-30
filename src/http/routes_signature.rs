use super::*;
use crate::signature::{SignatureChange, SignatureError, SignatureSelection};
impl<G: BrowserGateway> BrowserApp<G> {
    pub(super) fn handle_signature_update(
        &self,
        request: &HttpRequest,
        context: &AuthenticationContext,
    ) -> HandledHttpResponse {
        let (session, mut audit_events) = match self.require_validated_session(request, context) {
            Ok(v) => v,
            Err(r) => return r,
        };
        let form = if allows_urlencoded_request_body(
            request.headers.get("content-type").map(String::as_str),
        ) {
            parse_urlencoded_form(&request.body, 6, 32768).ok()
        } else {
            None
        };
        let Some(form) = form else {
            return HandledHttpResponse {
                response: html_response(
                    400,
                    "Bad Request",
                    "Signature not saved",
                    "<p>The signature form could not be read. Reload settings before editing.</p>",
                ),
                audit_events,
            };
        };
        if let Some(r) = self.require_valid_csrf(
            request,
            form.get("csrf_token").map(String::as_str),
            &session,
            context,
        ) {
            return r;
        }
        let text = form.get("text").map(String::as_str).unwrap_or("");
        let selection = form.get("selection").map(String::as_str).unwrap_or("");
        let operation = form.get("operation").map(String::as_str).unwrap_or("");
        let revision = form
            .get("signature_revision")
            .and_then(|v| v.parse::<u64>().ok().filter(|n| n.to_string() == *v));
        let section = form.get("return_section").map(String::as_str).unwrap_or("");
        let result = (|| {
            if form.keys().any(|k| {
                ![
                    "csrf_token",
                    "text",
                    "selection",
                    "operation",
                    "signature_revision",
                    "return_section",
                ]
                .contains(&k.as_str())
            }) || !matches!(section, "identity" | "composition")
            {
                return Err(SignatureError::Invalid);
            }
            let selection = if !form.contains_key("selection")
                && operation == "selection"
                && section == "composition"
            {
                SignatureSelection::None
            } else {
                SignatureSelection::parse(selection).ok_or(SignatureError::Invalid)?
            };
            let revision = revision.ok_or(SignatureError::Invalid)?;
            let normalized = text.replace("\r\n", "\n");
            let change = match operation {
                "definition" if form.contains_key("text") => SignatureChange::Definition {
                    selection,
                    text: &normalized,
                },
                "selection" if !form.contains_key("text") => SignatureChange::Selection(selection),
                _ => return Err(SignatureError::Invalid),
            };
            self.gateway.change_signature(&session, revision, change)
        })();
        audit_events.push(build_http_info_event(
            if result.is_ok() {
                "signature_preference_saved"
            } else {
                "signature_preference_refused"
            },
            "ordinary signature preference evaluated",
            context,
        ));
        match result {
            Ok(_) => HandledHttpResponse {
                response: redirect_response(
                    303,
                    "See Other",
                    if section == "composition" {
                        "/settings?section=composition"
                    } else {
                        "/settings?section=identity"
                    },
                ),
                audit_events,
            },
            Err(e) => {
                let(status,reason,notice,editable)=match e{SignatureError::Invalid=>(400,"Bad Request","Use at most 2,000 Unicode characters and 8,000 UTF-8 bytes of plain text, with only line breaks and tabs as controls. Default requires nonempty text.",revision.is_some()),SignatureError::Stale=>(409,"Conflict","The saved signature changed. Your submitted values are retained. Reload saved settings before editing again.",false),_=>(503,"Service Unavailable","The signature save could not be confirmed. Your submitted values are retained. Reload saved settings before another save.",false)};
                HandledHttpResponse {
                    response: html_response(
                        status,
                        reason,
                        "Signature not saved",
                        crate::signature_ui::render_signature_error(
                            &crate::signature_ui::SignatureEditorModel {
                                account: &session.record.canonical_username,
                                csrf: &session.record.csrf_token,
                                revision: revision.unwrap_or(0),
                                selection,
                                text,
                                operation,
                                return_section: if section == "composition" {
                                    "composition"
                                } else {
                                    "identity"
                                },
                                notice,
                                editable,
                            },
                        ),
                    ),
                    audit_events,
                }
            }
        }
    }
}
