//! One own-account request, one original deadline; no automatic mutation retry.
use super::*;

const PASSWORD_RESULT_COOKIE: &str = "osmap_password_result";
const PASSWORD_RESULT_PATH: &str = "/settings/password/result";
fn result_cookie(capability: &str, secure: bool) -> String {
    format!("{PASSWORD_RESULT_COOKIE}={capability}; Path=/settings/password; Max-Age=900; HttpOnly; SameSite=Strict{}", if secure { "; Secure" } else { "" })
}
fn write_timing(stamp: Option<&str>, confirmed: bool) -> String {
    stamp
        .filter(|v| crate::account_mutation::changed_at_valid(v))
        .map(|v| {
            let state = if confirmed {
                "Password change and required OSMAP session cleanup were confirmed."
            } else {
                "Required containment remains incomplete; this is not a completed password change."
            };
            format!(
                "<p>The credential write was verified at {}-{}-{} {}:{}:{} UTC. {state}</p>",
                &v[0..4],
                &v[4..6],
                &v[6..8],
                &v[8..10],
                &v[10..12],
                &v[12..14]
            )
        })
        .unwrap_or_default()
}
fn result_response(result: BrowserPasswordResult) -> HttpResponse {
    let message = if result.confirmed {
        "Your password was changed and your existing browser sessions were revoked. Sign in again with your new password. Mail clients already authenticated through IMAP or SMTP may remain connected."
    } else {
        "A completed password change has not been confirmed. If you submitted a change, do not repeat it; contact support to reconcile the account state. This result does not grant access to your account."
    };
    let timing = write_timing(result.changed_at.as_deref(), result.confirmed);
    html_response(200, "OK", "Password Change", TrustedHtml::from_template(format!(
        "<main id=\"main-content\" class=\"page-shell\"><section class=\"panel\"><h1>Password change</h1><p role=\"status\">{message}</p>{timing}<a href=\"/login\">Sign in</a></section></main>"
    )))
}

const PASSWORD_SCRIPT: &str = include_str!("password_local.js");
const PASSWORD_SCRIPT_HASH: &str = "sha256-yy1xyn6PfDKkPhGgl2wE49oKPcIjrGhGJYi3trYVTPI=";

fn password_response(
    status: u16,
    reason: &'static str,
    account: &str,
    csrf: &str,
    available: bool,
    notice: Option<&str>,
) -> HttpResponse {
    let body = crate::http_ui::render_password_page(account, csrf, available, notice);
    let body = TrustedHtml::from_template(format!(
        "{body}<script id=\"osmap-password-local\">{PASSWORD_SCRIPT}</script>"
    ));
    let mut response = html_response(status, reason, "Change Password", body);
    for (name, value) in &mut response.headers {
        if name.eq_ignore_ascii_case("Content-Security-Policy") {
            *value = format!(
                "{}; script-src '{}'; script-src-attr 'none'; connect-src 'none'",
                crate::http_support::browser_csp(),
                PASSWORD_SCRIPT_HASH
            );
        }
    }
    response
}

impl<G: BrowserGateway> BrowserApp<G> {
    /// This capability discloses only this request's bounded result. It never
    /// validates an old browser session or enters authenticated Settings.
    pub(super) fn handle_password_result(&self, request: &HttpRequest) -> HandledHttpResponse {
        let result = request
            .query_params
            .is_empty()
            .then(|| {
                session_cookie_value(request, PASSWORD_RESULT_COOKIE)
                    .and_then(|capability| self.gateway.password_result(&capability))
            })
            .flatten();
        HandledHttpResponse {
            response: result.map(result_response).unwrap_or_else(|| html_response(
                404, "Not Found", "Password result unavailable",
                TrustedHtml::from_template("<main id=\"main-content\"><h1>Password result unavailable</h1><p>This result is unavailable or has expired. Sign in if your account is available, or contact support. Do not repeat an unconfirmed password change.</p><a href=\"/login\">Sign in</a></main>".into()),
            )),
            audit_events: Vec::new(),
        }
    }
    pub(super) fn handle_password_change(
        &self,
        request: &HttpRequest,
        context: &AuthenticationContext,
    ) -> HandledHttpResponse {
        let deadline = std::time::Instant::now() + std::time::Duration::from_secs(60);
        let (session, mut audit_events) = match self.require_validated_session(request, context) {
            Ok(value) => value,
            Err(mut response) => {
                // A lost terminal HTTP reply can leave the old session cookie
                // in the browser after its authority was revoked. The separate
                // pre-dispatch capability reveals only the fixed result view;
                // it never restores this session or reaches form submission.
                if request.query_params.is_empty()
                    && session_cookie_value(request, PASSWORD_RESULT_COOKIE)
                        .and_then(|capability| self.gateway.password_result(&capability))
                        .is_some()
                {
                    response.response = redirect_response(303, "See Other", PASSWORD_RESULT_PATH)
                        .with_header(
                            "Set-Cookie",
                            clear_session_cookie(
                                self.policy.session_cookie_name,
                                self.policy.secure_session_cookie,
                            ),
                        );
                }
                return response;
            }
        };
        let account = &session.record.canonical_username;
        let csrf = &session.record.csrf_token;
        let available = self.gateway.password_change_available(&session);
        let reply = |status, reason, notice| {
            password_response(status, reason, account, csrf, available, Some(notice))
        };
        if !request.query_params.is_empty() {
            return HandledHttpResponse {
                response: reply(
                    400,
                    "Bad Request",
                    "Use the password form without query parameters.",
                ),
                audit_events,
            };
        }
        if request.method == HttpMethod::Get {
            let capability = if available {
                match self.gateway.begin_password_result(
                    &session,
                    session_cookie_value(request, PASSWORD_RESULT_COOKIE).as_deref(),
                ) {
                    Ok(value) => value,
                    Err(_) => return HandledHttpResponse {
                        response: password_response(
                            503,
                            "Service Unavailable",
                            account,
                            csrf,
                            false,
                            Some(
                                "Password result storage is unavailable. No change was submitted.",
                            ),
                        ),
                        audit_events,
                    },
                }
            } else {
                None
            };
            let mut response = password_response(
                if available { 200 } else { 503 },
                if available {
                    "OK"
                } else {
                    "Service Unavailable"
                },
                account,
                csrf,
                available,
                None,
            );
            if let Some(capability) = capability {
                response = response.with_header(
                    "Set-Cookie",
                    result_cookie(&capability, self.policy.secure_session_cookie),
                );
            }
            return HandledHttpResponse {
                response,
                audit_events,
            };
        }
        if !allows_urlencoded_request_body(request.headers.get("content-type").map(String::as_str))
        {
            return HandledHttpResponse {
                response: reply(
                    400,
                    "Bad Request",
                    "The password form could not be read. No change was submitted.",
                ),
                audit_events,
            };
        }
        let form = match parse_urlencoded_form(&request.body, 5, 8192) {
            Ok(value) => value,
            Err(_) => {
                return HandledHttpResponse {
                    response: reply(
                        400,
                        "Bad Request",
                        "The password form could not be read. No change was submitted.",
                    ),
                    audit_events,
                }
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
        if form.len() != 5
            || form.keys().any(|key| {
                ![
                    "csrf_token",
                    "current_password",
                    "new_password",
                    "confirmation",
                    "totp_code",
                ]
                .contains(&key.as_str())
            })
        {
            return HandledHttpResponse { response: reply(400, "Bad Request", "The password form contained unsupported or missing fields. No change was submitted."), audit_events };
        }
        let field = |key: &str| form.get(key).map(String::as_str).unwrap_or_default();
        let action = match crate::password_change::Request::new(field("current_password"), field("new_password"), field("confirmation"), field("totp_code")) {
            Ok(value) => value,
            Err(_) => return HandledHttpResponse { response: reply(400, "Bad Request", "Check the password requirements, confirmation and six-digit authenticator code. No change was submitted."), audit_events },
        };
        if !available {
            return HandledHttpResponse {
                response: reply(
                    503,
                    "Service Unavailable",
                    "Password change is unavailable. No change was submitted.",
                ),
                audit_events,
            };
        }
        let token = match session_cookie_value(request, self.policy.session_cookie_name)
            .and_then(|value| SessionToken::new(value).ok())
        {
            Some(value) => value,
            None => {
                return HandledHttpResponse {
                    response: reply(
                        401,
                        "Unauthorized",
                        "Your session is unavailable. Sign in again.",
                    ),
                    audit_events,
                }
            }
        };
        let result_capability = match self.gateway.begin_password_result(
            &session,
            session_cookie_value(request, PASSWORD_RESULT_COOKIE).as_deref(),
        ) {
            Ok(value) => value,
            Err(_) => {
                return HandledHttpResponse {
                    response: password_response(
                        503,
                        "Service Unavailable",
                        account,
                        csrf,
                        false,
                        Some("Password result storage is unavailable. No change was submitted."),
                    ),
                    audit_events,
                }
            }
        };
        let (guard, acquired) = match self.acquire_auth_budget(context) {
            Ok(value) => value,
            Err(response) => return response,
        };
        audit_events.push(acquired);
        let mut outcome = self
            .gateway
            .change_own_password(context, &session, &token, action, deadline);
        if outcome.decision == BrowserPasswordDecision::Changed
            && !outcome
                .changed_at
                .as_deref()
                .is_some_and(crate::account_mutation::changed_at_valid)
        {
            outcome.decision = BrowserPasswordDecision::Unconfirmed;
        }
        let saved_result = result_capability.as_deref().filter(|capability| {
            self.gateway
                .finish_password_result(&session, capability, &outcome)
        });
        audit_events.extend(outcome.audit_events);
        audit_events.push(self.release_auth_budget(guard, context));
        audit_events.push(
            build_http_info_event(
                "http_password_change_result",
                "own-account password request completed with a bounded outcome",
                context,
            )
            .with_field(
                "outcome",
                match outcome.decision {
                    BrowserPasswordDecision::Changed => "changed",
                    BrowserPasswordDecision::KnownRefused => "known_refused",
                    BrowserPasswordDecision::Unconfirmed => "unconfirmed",
                    BrowserPasswordDecision::PrewriteRefused(_) => "prewrite_refused",
                },
            )
            .with_field("session_revocation_scope", "osmap_browser_sessions")
            .with_field("external_mail_session_termination", "not_requested"),
        );
        let (status, reason, message, clear) = match outcome.decision {
            BrowserPasswordDecision::Changed => (200, "OK", "Your password was changed and your existing browser sessions were revoked. Sign in again with your new password. Mail clients already authenticated through IMAP or SMTP may remain connected.", true),
            BrowserPasswordDecision::KnownRefused => (409, "Conflict", "The account service refused this change. No password change was made.", false),
            BrowserPasswordDecision::Unconfirmed => (503, "Service Unavailable", "The password change or session cleanup could not be confirmed. Your session is cleared. Do not repeat this request; contact support to reconcile the account state.", true),
            BrowserPasswordDecision::PrewriteRefused(error) => match error {
                crate::password_change::Error::Unavailable => (503, "Service Unavailable", "Password change is unavailable. No change was submitted.", false),
                crate::password_change::Error::Throttled => (429, "Too Many Requests", "Password verification is temporarily limited. No change was submitted.", false),
                _ => (403, "Forbidden", "Current-password, authenticator or session verification failed. No change was submitted.", false),
            },
        };
        // Completed/uncertain results do not expose a second submission form.
        let timing = write_timing(
            outcome.changed_at.as_deref(),
            outcome.decision == BrowserPasswordDecision::Changed,
        );
        let response = if let (true, Some(capability)) = (clear, saved_result) {
            redirect_response(303, "See Other", PASSWORD_RESULT_PATH)
                .with_header(
                    "Set-Cookie",
                    clear_session_cookie(
                        self.policy.session_cookie_name,
                        self.policy.secure_session_cookie,
                    ),
                )
                .with_header(
                    "Set-Cookie",
                    result_cookie(capability, self.policy.secure_session_cookie),
                )
        } else if clear {
            html_response(status, reason, "Password Change", TrustedHtml::from_template(format!("<main id=\"main-content\" class=\"page-shell\"><section class=\"panel\"><h1>Password change</h1><p role=\"status\">{message}</p>{timing}<a href=\"/login\">Sign in</a></section></main>")))
                .with_header("Set-Cookie", clear_session_cookie(self.policy.session_cookie_name, self.policy.secure_session_cookie))
        } else {
            reply(status, reason, message)
        };
        HandledHttpResponse {
            response,
            audit_events,
        }
    }
}
