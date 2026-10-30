//! Narrow browser recovery routes. Restricted cookies never become mail sessions.
use super::*;
use crate::browser_access::{
    AccessAction, AccessAuthority, AccessCookie, AccessError, AccessOutcome, AccessView,
    RECOVERY_COOKIE, RECOVERY_CSRF_COOKIE,
};
use crate::session::{RandomSource, SystemRandomSource};

fn hex_token(value: &str) -> bool {
    value.len() == 64
        && value
            .bytes()
            .all(|v| v.is_ascii_digit() || (b'a'..=b'f').contains(&v))
}
fn cookie(name: &str, value: &str, clear: bool) -> String {
    format!(
        "{name}={value}; Path=/; Max-Age={}; HttpOnly; Secure; SameSite=Strict",
        if clear { 0 } else { 600 }
    )
}
fn failure(error: AccessError) -> HttpResponse {
    let (status, reason, message) = match error {
        AccessError::Refused => (403, "Forbidden", "The details could not be verified. Check the latest code before trying again."),
        AccessError::Expired => (410, "Gone", "This recovery step expired. Start again from the sign-in page."),
        AccessError::Conflict => (409, "Conflict", "This step changed. Reload to inspect its current state before another submission."),
        AccessError::Throttled => (429, "Too Many Requests", "Verification is temporarily limited. Wait before trying again."),
        AccessError::Unavailable => (503, "Service Unavailable", "Recovery is unavailable. No completed update has been confirmed."),
        AccessError::Unconfirmed => (503, "Service Unavailable", "The update could not be confirmed. Do not submit it again. Sign in if access is available, or contact support to reconcile the account."),
    };
    html_response(
        status,
        reason,
        "Recovery unavailable",
        crate::access_recovery_ui::render_access_failure(message),
    )
}
fn nonce() -> Result<String, AccessError> {
    let mut bytes = [0; 32];
    SystemRandomSource
        .fill_bytes(&mut bytes)
        .map_err(|_| AccessError::Unavailable)?;
    Ok(bytes.iter().map(|v| format!("{v:02x}")).collect())
}
fn same_origin(request: &HttpRequest, allowed: &[String]) -> bool {
    let Some(host) = request.headers.get("host") else {
        return false;
    };
    let Some(origin) = request
        .headers
        .get("origin")
        .and_then(|v| v.strip_prefix("https://"))
    else {
        return false;
    };
    !origin.is_empty()
        && !origin
            .chars()
            .any(|v| v.is_whitespace() || matches!(v, '/' | '?' | '#' | '@' | '\\'))
        && host.eq_ignore_ascii_case(origin)
        && allowed.iter().any(|v| v.eq_ignore_ascii_case(host))
}
fn parse_action<'a>(path: &str, form: &'a BTreeMap<String, String>) -> Option<AccessAction<'a>> {
    let get = |key: &str| form.get(key).map(String::as_str);
    let exact =
        |names: &[&str]| form.len() == names.len() && names.iter().all(|v| form.contains_key(*v));
    let code =
        |name: &str| get(name).filter(|v| v.len() == 6 && v.bytes().all(|x| x.is_ascii_digit()));
    let enrollment = || {
        let id = get("enrollment_id").filter(|v| hex_token(v))?;
        let revision = get("revision")?.parse::<u64>().ok().filter(|v| *v > 0)?;
        Some((id, revision))
    };
    match (path, get("action")?) {
        ("/recover", "send_code") if exact(&["csrf_token", "action", "email"]) => {
            let email = get("email")?;
            (email.len() <= 254 && !email.is_empty() && !email.chars().any(char::is_control))
                .then_some(AccessAction::SendRecoveryCode { email })
        }
        ("/recover", "verify_code") if exact(&["csrf_token", "action", "challenge_id", "code"]) => {
            Some(AccessAction::VerifyRecoveryCode {
                challenge_id: get("challenge_id").filter(|v| hex_token(v))?,
                code: code("code")?,
            })
        }
        ("/recover/setup", "confirm_recovery")
            if exact(&[
                "csrf_token",
                "action",
                "enrollment_id",
                "revision",
                "new_password",
                "confirmation",
                "new_totp_code",
            ]) =>
        {
            let (enrollment_id, revision) = enrollment()?;
            Some(AccessAction::ConfirmRecovery {
                enrollment_id,
                revision,
                new_password: get("new_password")?,
                confirmation: get("confirmation")?,
                new_totp_code: code("new_totp_code")?,
            })
        }
        ("/settings/authenticator", "begin_reset")
            if exact(&[
                "csrf_token",
                "action",
                "current_password",
                "current_totp_code",
            ]) =>
        {
            Some(AccessAction::BeginTotpReset {
                current_password: get("current_password")?,
                current_totp_code: code("current_totp_code")?,
            })
        }
        ("/settings/authenticator", "confirm_reset")
            if exact(&[
                "csrf_token",
                "action",
                "enrollment_id",
                "revision",
                "new_totp_code",
            ]) =>
        {
            let (enrollment_id, revision) = enrollment()?;
            Some(AccessAction::ConfirmTotpReset {
                enrollment_id,
                revision,
                new_totp_code: code("new_totp_code")?,
            })
        }
        _ => None,
    }
}
fn view_matches(view: &AccessView, path: &str, account: Option<&str>, grant_issued: bool) -> bool {
    match (path, view) {
        ("/recover", AccessView::RecoveryEmail { .. } | AccessView::RecoveryCode { .. }) => true,
        ("/recover", AccessView::RecoverySetup { .. }) => grant_issued,
        ("/recover/setup", AccessView::RecoverySetup { .. } | AccessView::Complete) => true,
        (
            "/settings/authenticator",
            AccessView::TotpResetStart { account: shown, .. }
            | AccessView::TotpReplacement { account: shown, .. },
        ) => account == Some(shown.as_str()),
        ("/settings/authenticator", AccessView::Complete) => true,
        _ => false,
    }
}

impl<G: BrowserGateway> BrowserApp<G> {
    pub(super) fn handle_access_recovery(
        &self,
        request: &HttpRequest,
        context: &AuthenticationContext,
    ) -> HandledHttpResponse {
        let mut audit_events = Vec::new();
        let reply = |response, audit_events| HandledHttpResponse {
            response,
            audit_events,
        };
        if !request.query_params.is_empty() {
            return reply(
                html_response(
                    400,
                    "Bad Request",
                    "Invalid recovery request",
                    crate::access_recovery_ui::render_access_failure(
                        "Open recovery without query parameters.",
                    ),
                ),
                audit_events,
            );
        }
        let session = if request.path == "/settings/authenticator" {
            match self.require_validated_session(request, context) {
                Ok((session, events)) => {
                    audit_events.extend(events);
                    Some(session)
                }
                Err(response) => return response,
            }
        } else {
            None
        };
        let grant = session_cookie_value(request, RECOVERY_COOKIE).filter(|v| hex_token(v));
        if request.path == "/recover/setup" && grant.is_none() {
            return reply(
                redirect_response(303, "See Other", "/recover")
                    .with_header("Set-Cookie", cookie(RECOVERY_COOKIE, "", true)),
                audit_events,
            );
        }
        let authority = || match session.as_ref() {
            Some(session) => AccessAuthority::Session(session),
            None if request.path == "/recover/setup" => {
                AccessAuthority::Grant(grant.as_deref().unwrap_or_default())
            }
            None => AccessAuthority::Unauthenticated,
        };
        let submitted_cookie =
            session_cookie_value(request, RECOVERY_CSRF_COOKIE).filter(|v| hex_token(v));
        let csrf = if let Some(session) = &session {
            session.record.csrf_token.clone()
        } else if let Some(value) = &submitted_cookie {
            value.clone()
        } else if request.method == HttpMethod::Get {
            match nonce() {
                Ok(value) => value,
                Err(error) => return reply(failure(error), audit_events),
            }
        } else {
            return reply(failure(AccessError::Refused), audit_events);
        };
        let outcome = if request.method == HttpMethod::Get {
            self.gateway
                .access_view(context, authority(), &csrf)
                .map(|view| AccessOutcome {
                    view,
                    grant_cookie: AccessCookie::Unchanged,
                })
        } else {
            if !same_origin(request, &self.policy.allowed_hosts)
                || !allows_urlencoded_request_body(
                    request.headers.get("content-type").map(String::as_str),
                )
            {
                return reply(failure(AccessError::Refused), audit_events);
            }
            let form = match parse_urlencoded_form(&request.body, 7, 8192) {
                Ok(form) => form,
                Err(_) => {
                    return reply(
                        html_response(
                            400,
                            "Bad Request",
                            "Invalid recovery request",
                            crate::access_recovery_ui::render_access_failure(
                                "The form could not be read. No update was submitted.",
                            ),
                        ),
                        audit_events,
                    )
                }
            };
            if !submitted_cookie
                .as_deref()
                .is_some_and(|v| constant_time_eq(v.as_bytes(), csrf.as_bytes()))
                || !form
                    .get("csrf_token")
                    .is_some_and(|v| constant_time_eq(v.as_bytes(), csrf.as_bytes()))
            {
                return reply(failure(AccessError::Refused), audit_events);
            }
            let Some(action) = parse_action(&request.path, &form) else {
                return reply(html_response(400, "Bad Request", "Invalid recovery request", crate::access_recovery_ui::render_access_failure("The form contained invalid or unsupported fields. No update was submitted.")), audit_events);
            };
            // Known pre-effect refusal may show the same code form again. Never
            // repopulate a submitted password/code, or retry an uncertain effect.
            let retry_view = match &action {
                AccessAction::VerifyRecoveryCode { challenge_id, .. } => {
                    Some(AccessView::RecoveryCode {
                        csrf: csrf.clone(),
                        challenge_id: (*challenge_id).into(),
                    })
                }
                AccessAction::BeginTotpReset { .. } => {
                    session.as_ref().map(|session| AccessView::TotpResetStart {
                        account: session.record.canonical_username.clone(),
                        csrf: csrf.clone(),
                    })
                }
                _ => None,
            };
            let (guard, acquired) = match self.acquire_auth_budget(context) {
                Ok(value) => value,
                Err(response) => return response,
            };
            audit_events.push(acquired);
            let outcome = self.gateway.access_action(
                context,
                authority(),
                &csrf,
                action,
                std::time::Instant::now() + std::time::Duration::from_secs(60),
            );
            audit_events.push(self.release_auth_budget(guard, context));
            if matches!(outcome, Err(AccessError::Refused)) {
                let view = retry_view
                    .map(Ok)
                    .unwrap_or_else(|| self.gateway.access_view(context, authority(), &csrf));
                if let Ok(mut view) = view {
                    if view_matches(
                        &view,
                        &request.path,
                        session
                            .as_ref()
                            .map(|v| v.record.canonical_username.as_str()),
                        false,
                    ) && view.bind_csrf(&csrf)
                    {
                        if let Ok(body) = crate::access_recovery_ui::render_access_page(&view, Some("The details could not be verified. Check the latest code and try again.")) {
                            return reply(html_response(403, "Forbidden", "Verification failed", body), audit_events);
                        }
                    }
                }
            }
            outcome
        };
        let mut outcome = match outcome {
            Ok(value) => value,
            Err(error) => return reply(failure(error), audit_events),
        };
        let issued = matches!(&outcome.grant_cookie, AccessCookie::Set(token) if hex_token(token));
        if matches!(&outcome.grant_cookie, AccessCookie::Set(token) if !hex_token(token))
            || !view_matches(
                &outcome.view,
                &request.path,
                session
                    .as_ref()
                    .map(|v| v.record.canonical_username.as_str()),
                issued,
            )
            || !outcome.view.bind_csrf(&csrf)
        {
            return reply(failure(AccessError::Unavailable), audit_events);
        }
        let body = match crate::access_recovery_ui::render_access_page(&outcome.view, None) {
            Ok(body) => body,
            Err(error) => return reply(failure(error), audit_events),
        };
        let mut response = html_response(200, "OK", "Account recovery", body)
            .with_header("Set-Cookie", cookie(RECOVERY_CSRF_COOKIE, &csrf, false));
        match outcome.grant_cookie {
            AccessCookie::Unchanged => {}
            AccessCookie::Set(token) => {
                response =
                    response.with_header("Set-Cookie", cookie(RECOVERY_COOKIE, &token, false))
            }
            AccessCookie::Clear => {
                response = response.with_header("Set-Cookie", cookie(RECOVERY_COOKIE, "", true))
            }
        }
        if matches!(outcome.view, AccessView::Complete) {
            response = response
                .with_header(
                    "Set-Cookie",
                    clear_session_cookie(
                        self.policy.session_cookie_name,
                        self.policy.secure_session_cookie,
                    ),
                )
                .with_header("Set-Cookie", cookie(RECOVERY_COOKIE, "", true))
                .with_header("Set-Cookie", cookie(RECOVERY_CSRF_COOKIE, "", true));
        }
        reply(response, audit_events)
    }
}
