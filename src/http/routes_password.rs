//! One own-account request, one original deadline; no automatic mutation retry.
use super::*;

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
    pub(super) fn handle_password_change(
        &self,
        request: &HttpRequest,
        context: &AuthenticationContext,
    ) -> HandledHttpResponse {
        let deadline = std::time::Instant::now() + std::time::Duration::from_secs(60);
        let (session, mut audit_events) = match self.require_validated_session(request, context) {
            Ok(value) => value,
            Err(response) => return response,
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
            return HandledHttpResponse {
                response: password_response(
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
                ),
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
            ),
        );
        let (status, reason, message, clear) = match outcome.decision {
            BrowserPasswordDecision::Changed => (200, "OK", "Your password was changed and your existing browser sessions were revoked. Sign in again with your new password.", true),
            BrowserPasswordDecision::KnownRefused => (409, "Conflict", "The account service refused this change. No password change was made.", false),
            BrowserPasswordDecision::Unconfirmed => (503, "Service Unavailable", "The password change or session cleanup could not be confirmed. Your session is cleared. Do not repeat this request; contact support to reconcile the account state.", true),
            BrowserPasswordDecision::PrewriteRefused(error) => match error {
                crate::password_change::Error::Unavailable => (503, "Service Unavailable", "Password change is unavailable. No change was submitted.", false),
                crate::password_change::Error::Throttled => (429, "Too Many Requests", "Password verification is temporarily limited. No change was submitted.", false),
                _ => (403, "Forbidden", "Current-password, authenticator or session verification failed. No change was submitted.", false),
            },
        };
        // Completed/uncertain results do not expose a second submission form.
        let timing = outcome.changed_at.as_deref()
            .filter(|v| crate::account_mutation::changed_at_valid(v))
            .map(|v| {
                let state = if outcome.decision == BrowserPasswordDecision::Changed {
                    "Password change and required containment were confirmed."
                } else {
                    "Required containment remains incomplete; this is not a completed password change."
                };
                format!("<p>The credential write was verified at {}-{}-{} {}:{}:{} UTC. {state}</p>",
                    &v[0..4], &v[4..6], &v[6..8], &v[8..10], &v[10..12], &v[12..14])
            })
            .unwrap_or_default();
        let response = if clear {
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
