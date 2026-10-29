//! Authenticated own-account metadata and an untrusted recovery request only.
use super::*;
impl<G: BrowserGateway> BrowserApp<G> {
    pub(super) fn handle_authenticator(
        &self,
        request: &HttpRequest,
        context: &AuthenticationContext,
    ) -> HandledHttpResponse {
        let (session, audit_events) = match self.require_validated_session(request, context) {
            Ok(value) => value,
            Err(response) => return response,
        };
        let account = &session.record.canonical_username;
        let mut state = self
            .gateway
            .authenticator(&session)
            .ok()
            .filter(|v| v.account == *account);
        let mut notice = None;
        let mut code = if state.is_some() { 200 } else { 503 };
        if !request.query_params.is_empty() {
            code = 400;
            notice = Some("Open authenticator management without query parameters.");
        } else if request.method == HttpMethod::Post {
            if !allows_urlencoded_request_body(
                request.headers.get("content-type").map(String::as_str),
            ) {
                code = 400;
                notice = Some("The request form could not be read. No recovery was started.");
            } else {
                match parse_urlencoded_form(&request.body, 3, 4096) {
                    Ok(form) => {
                        if let Some(response) = self.require_valid_csrf(
                            request,
                            form.get("csrf_token").map(String::as_str),
                            &session,
                            context,
                        ) {
                            return response;
                        }
                        let revision = form.get("revision").and_then(|v| v.parse::<u64>().ok());
                        if form.len() != 3
                            || form.get("action").map(String::as_str) != Some("request")
                            || revision.is_none()
                        {
                            code = 400;
                            notice = Some("The request was refused. No recovery was started.");
                        } else if state.is_none() {
                            code = 503;
                            notice = Some("Authenticator state is unavailable. No recovery request was saved.");
                        } else {
                            match self
                                .gateway
                                .request_account_recovery(&session, revision.unwrap_or_default())
                            {
                                Ok(record)
                                    if record.account == *account
                                        && record.state == "requested" =>
                                {
                                    if let Some(state) = state.as_mut() {
                                        state.request = Some(record);
                                    }
                                    notice = Some("Recovery request saved. An operator must independently verify identity before any account or factor change.");
                                }
                                Err(crate::authenticator::Error::Refused) => {
                                    code = 409;
                                    notice = Some("The request state changed. Reload before submitting again.");
                                }
                                _ => {
                                    code = 503;
                                    notice = Some("The request result could not be confirmed. Reload to inspect its state before another submission.");
                                }
                            }
                        }
                    }
                    Err(_) => {
                        code = 400;
                        notice =
                            Some("The request form could not be read. No recovery was started.");
                    }
                }
            }
        }
        HandledHttpResponse {
            response: html_response(
                code,
                match code {
                    200 => "OK",
                    400 => "Bad Request",
                    409 => "Conflict",
                    _ => "Service Unavailable",
                },
                "Authenticator Management",
                crate::http_ui::render_authenticator_page(
                    account,
                    &session.record.csrf_token,
                    state.as_ref(),
                    notice,
                ),
            ),
            audit_events,
        }
    }
}
