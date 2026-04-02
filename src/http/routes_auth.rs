//! Auth and session route handlers for the bounded browser runtime.
//!
//! Keeping these handlers separate from mail and compose routes reduces the
//! concentration of authentication, session, and CSRF behavior in `http.rs`
//! without widening visibility or changing the current route surface.

use super::*;

impl<G> BrowserApp<G>
where
    G: BrowserGateway,
{
    /// Serves the current login form.
    pub(super) fn handle_login_form(
        &self,
        context: &AuthenticationContext,
    ) -> HandledHttpResponse {
        HandledHttpResponse {
            response: html_response(200, "OK", "OSMAP Login", &render_login_page(None)),
            audit_events: vec![build_http_info_event(
                "http_login_form_served",
                "login form served",
                context,
            )],
        }
    }

    /// Handles login form submission using the existing auth/session layers.
    pub(super) fn handle_login(
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
                    "Invalid Login Request",
                    "<p>The login form content type was not supported.</p>",
                ),
                audit_events: vec![build_http_warning_event(
                    "http_login_content_type_rejected",
                    "login form content type was not supported",
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
                        "Invalid Login Request",
                        "<p>The login form could not be parsed.</p>",
                    ),
                    audit_events: vec![build_http_warning_event(
                        "http_login_parse_failed",
                        "login form parsing failed",
                        context,
                    )
                    .with_field("reason", error.reason)],
                };
            }
        };

        let username = form.get("username").cloned().unwrap_or_default();
        let password = form.get("password").cloned().unwrap_or_default();
        let totp_code = form.get("totp_code").cloned().unwrap_or_default();

        let outcome = self
            .gateway
            .login(context, &username, &password, &totp_code);

        match outcome.decision {
            BrowserLoginDecision::Authenticated { session_token, .. } => HandledHttpResponse {
                response: redirect_response(303, "See Other", "/mailboxes").with_header(
                    "Set-Cookie",
                    build_session_cookie(
                        self.policy.session_cookie_name,
                        session_token.as_str(),
                        self.policy.secure_session_cookie,
                    ),
                ),
                audit_events: outcome.audit_events,
            },
            BrowserLoginDecision::Denied { public_reason } => HandledHttpResponse {
                response: html_response(
                    401,
                    "Unauthorized",
                    "Login Failed",
                    &render_login_page(Some(public_reason_message(&public_reason))),
                ),
                audit_events: outcome.audit_events,
            },
        }
    }

    /// Redirects the root path toward either the login page or mailbox home.
    pub(super) fn handle_root_redirect(
        &self,
        request: &HttpRequest,
        context: &AuthenticationContext,
    ) -> HandledHttpResponse {
        if let Some(session_token) = session_cookie_value(request, self.policy.session_cookie_name)
        {
            let outcome = self.gateway.validate_session(context, &session_token);
            if matches!(outcome.decision, BrowserSessionDecision::Valid { .. }) {
                return HandledHttpResponse {
                    response: redirect_response(303, "See Other", "/mailboxes"),
                    audit_events: outcome.audit_events,
                };
            }
        }

        HandledHttpResponse {
            response: redirect_response(303, "See Other", "/login"),
            audit_events: vec![build_http_info_event(
                "http_root_redirected",
                "root path redirected to login",
                context,
            )],
        }
    }

    /// Handles the browser-visible session-management page.
    pub(super) fn handle_sessions_page(
        &self,
        request: &HttpRequest,
        context: &AuthenticationContext,
    ) -> HandledHttpResponse {
        let (validated_session, mut audit_events) =
            match self.require_validated_session(request, context) {
                Ok(result) => result,
                Err(response) => return response,
            };

        let success_message =
            if request.query_params.get("revoked").map(String::as_str) == Some("1") {
                Some("The selected session was revoked.")
            } else {
                None
            };

        let outcome = self.gateway.list_sessions(context, &validated_session);
        audit_events.extend(outcome.audit_events);

        match outcome.decision {
            BrowserSessionListDecision::Listed {
                canonical_username,
                sessions,
            } => HandledHttpResponse {
                response: html_response(
                    200,
                    "OK",
                    "Sessions",
                    &render_sessions_page(
                        &canonical_username,
                        &validated_session.record.session_id,
                        &validated_session.record.csrf_token,
                        &sessions,
                        success_message,
                    ),
                ),
                audit_events,
            },
            BrowserSessionListDecision::Denied { public_reason } => HandledHttpResponse {
                response: html_response(
                    503,
                    "Service Unavailable",
                    "Sessions Unavailable",
                    &format!(
                        "<p>{}</p>",
                        escape_html(public_reason_message(&public_reason))
                    ),
                ),
                audit_events,
            },
        }
    }

    /// Handles CSRF-bound self-service session revocation.
    pub(super) fn handle_session_revoke(
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
                    "Invalid Session Request",
                    "<p>The session form content type was not supported.</p>",
                ),
                audit_events: vec![build_http_warning_event(
                    "http_session_revoke_content_type_rejected",
                    "session revoke form content type was not supported",
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
                        "Invalid Session Request",
                        "<p>The session revoke request could not be parsed.</p>",
                    ),
                    audit_events: vec![build_http_warning_event(
                        "http_session_revoke_parse_failed",
                        "session revoke form parsing failed",
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
            form.get("csrf_token").map(String::as_str),
            &validated_session,
            context,
        ) {
            return response;
        }

        let Some(session_id) = form.get("session_id").cloned() else {
            return HandledHttpResponse {
                response: html_response(
                    400,
                    "Bad Request",
                    "Invalid Session Request",
                    "<p>A session identifier is required.</p>",
                ),
                audit_events: vec![build_http_warning_event(
                    "http_session_revoke_missing_target",
                    "session revoke target missing",
                    context,
                )],
            };
        };

        let outcome = self
            .gateway
            .revoke_session(context, &validated_session, &session_id);
        audit_events.extend(outcome.audit_events);

        match outcome.decision {
            BrowserSessionRevokeDecision::Revoked {
                revoked_current_session,
                ..
            } => {
                let mut response = redirect_response(
                    303,
                    "See Other",
                    if revoked_current_session {
                        "/login"
                    } else {
                        "/sessions?revoked=1"
                    },
                );
                if revoked_current_session {
                    response = response.with_header(
                        "Set-Cookie",
                        clear_session_cookie(
                            self.policy.session_cookie_name,
                            self.policy.secure_session_cookie,
                        ),
                    );
                }

                HandledHttpResponse {
                    response,
                    audit_events,
                }
            }
            BrowserSessionRevokeDecision::Denied { public_reason } => {
                let status_code = if public_reason == "invalid_request" {
                    400
                } else if public_reason == "not_found" {
                    404
                } else {
                    503
                };
                let reason_phrase = if public_reason == "invalid_request" {
                    "Bad Request"
                } else if public_reason == "not_found" {
                    "Not Found"
                } else {
                    "Service Unavailable"
                };
                HandledHttpResponse {
                    response: html_response(
                        status_code,
                        reason_phrase,
                        "Session Revocation Failed",
                        &format!(
                            "<p>{}</p>",
                            escape_html(public_reason_message(&public_reason))
                        ),
                    ),
                    audit_events,
                }
            }
        }
    }

    /// Handles logout and clears the browser session cookie regardless of outcome.
    pub(super) fn handle_logout(
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
                    "Invalid Logout Request",
                    "<p>The logout form content type was not supported.</p>",
                ),
                audit_events: vec![build_http_warning_event(
                    "http_logout_content_type_rejected",
                    "logout form content type was not supported",
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
                        "Invalid Logout Request",
                        "<p>The logout request could not be parsed.</p>",
                    ),
                    audit_events: vec![build_http_warning_event(
                        "http_logout_parse_failed",
                        "logout form parsing failed",
                        context,
                    )
                    .with_field("reason", error.reason)],
                };
            }
        };

        let mut audit_events = Vec::new();
        if let Some(session_token) = session_cookie_value(request, self.policy.session_cookie_name)
        {
            let validation = self.gateway.validate_session(context, &session_token);
            audit_events.extend(validation.audit_events.clone());
            if let BrowserSessionDecision::Valid { validated_session } = validation.decision {
                if let Some(response) = self.require_valid_csrf(
                    form.get("csrf_token").map(String::as_str),
                    validated_session.as_ref(),
                    context,
                ) {
                    return response;
                }
            }

            let outcome = self.gateway.logout(context, &session_token);
            audit_events.extend(outcome.audit_events);
        }

        HandledHttpResponse {
            response: redirect_response(303, "See Other", "/login").with_header(
                "Set-Cookie",
                clear_session_cookie(
                    self.policy.session_cookie_name,
                    self.policy.secure_session_cookie,
                ),
            ),
            audit_events,
        }
    }

    /// Validates the presented session cookie or redirects back to login.
    pub(super) fn require_validated_session(
        &self,
        request: &HttpRequest,
        context: &AuthenticationContext,
    ) -> Result<(ValidatedSession, Vec<LogEvent>), HandledHttpResponse> {
        let Some(session_token) = session_cookie_value(request, self.policy.session_cookie_name)
        else {
            return Err(HandledHttpResponse {
                response: redirect_response(303, "See Other", "/login"),
                audit_events: vec![build_http_info_event(
                    "http_session_missing",
                    "browser session cookie missing",
                    context,
                )],
            });
        };

        let outcome = self.gateway.validate_session(context, &session_token);
        match outcome.decision {
            BrowserSessionDecision::Valid { validated_session } => {
                Ok((*validated_session, outcome.audit_events))
            }
            BrowserSessionDecision::Invalid => Err(HandledHttpResponse {
                response: redirect_response(303, "See Other", "/login").with_header(
                    "Set-Cookie",
                    clear_session_cookie(
                        self.policy.session_cookie_name,
                        self.policy.secure_session_cookie,
                    ),
                ),
                audit_events: outcome.audit_events,
            }),
        }
    }

    /// Validates the CSRF token for authenticated state-changing routes.
    pub(super) fn require_valid_csrf(
        &self,
        submitted_token: Option<&str>,
        validated_session: &ValidatedSession,
        context: &AuthenticationContext,
    ) -> Option<HandledHttpResponse> {
        let Some(submitted_token) = submitted_token else {
            return Some(HandledHttpResponse {
                response: html_response(
                    403,
                    "Forbidden",
                    "CSRF Validation Failed",
                    "<p>The request did not include a valid CSRF token.</p>",
                ),
                audit_events: vec![build_http_warning_event(
                    "http_csrf_missing",
                    "csrf token missing from state-changing request",
                    context,
                )
                .with_field("session_id", validated_session.record.session_id.clone())],
            });
        };

        if !constant_time_eq(
            submitted_token.as_bytes(),
            validated_session.record.csrf_token.as_bytes(),
        ) {
            return Some(HandledHttpResponse {
                response: html_response(
                    403,
                    "Forbidden",
                    "CSRF Validation Failed",
                    "<p>The request did not include a valid CSRF token.</p>",
                ),
                audit_events: vec![build_http_warning_event(
                    "http_csrf_invalid",
                    "csrf token validation failed",
                    context,
                )
                .with_field("session_id", validated_session.record.session_id.clone())],
            });
        }

        None
    }
}
