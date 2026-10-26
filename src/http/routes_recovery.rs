//! Authenticated recovery-contact metadata and explicit POST-only proof.
use super::*;
use crate::logging::EventCategory;
use crate::recovery_contact::{
    RecoveryContactAction as Action, RecoveryContactDelivery as Delivery,
    RecoveryContactError as Error,
};

fn page(
    status: u16,
    reason: &'static str,
    session: &ValidatedSession,
    state: Option<&crate::recovery_contact::RecoveryContactSnapshot>,
    notice: Option<&str>,
) -> HttpResponse {
    html_response(
        status,
        reason,
        "Recovery Contact",
        crate::http_ui::render_recovery_contact_page(
            &session.record.canonical_username,
            &session.record.csrf_token,
            state,
            notice,
        ),
    )
}

impl<G: BrowserGateway> BrowserApp<G> {
    pub(super) fn handle_recovery_contact(
        &self,
        request: &HttpRequest,
        context: &AuthenticationContext,
    ) -> HandledHttpResponse {
        let deadline = std::time::Instant::now() + std::time::Duration::from_secs(60);
        let (session, mut audit_events) = match self.require_validated_session(request, context) {
            Ok(value) => value,
            Err(response) => return response,
        };
        let state = self.gateway.recovery_contact(&session).ok();
        let reply =
            |status, reason, text| page(status, reason, &session, state.as_ref(), Some(text));
        if !request.query_params.is_empty() {
            return HandledHttpResponse { response: reply(400, "Bad Request", "Open the recovery contact page without query parameters. No contact change was submitted."), audit_events };
        }
        if request.method == HttpMethod::Get {
            return HandledHttpResponse {
                response: page(
                    if state.is_some() { 200 } else { 503 },
                    if state.is_some() {
                        "OK"
                    } else {
                        "Service Unavailable"
                    },
                    &session,
                    state.as_ref(),
                    state.is_none().then_some(
                        "Recovery-contact storage is unavailable. No change was submitted.",
                    ),
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
                    "The recovery form could not be read. No change was submitted.",
                ),
                audit_events,
            };
        }
        let form = match parse_urlencoded_form(&request.body, 6, 8192) {
            Ok(value) => value,
            Err(_) => {
                return HandledHttpResponse {
                    response: reply(
                        400,
                        "Bad Request",
                        "The recovery form could not be read. No change was submitted.",
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
        let get = |key: &str| form.get(key).map(String::as_str).unwrap_or_default();
        let revision = get("revision").parse::<u64>().ok();
        let (action, expected) = match get("action") {
            "begin" => (
                Some(Action::Begin {
                    email: get("email").into(),
                }),
                &[
                    "csrf_token",
                    "revision",
                    "action",
                    "email",
                    "current_password",
                    "totp_code",
                ][..],
            ),
            "resend" => (
                Some(Action::Resend),
                &[
                    "csrf_token",
                    "revision",
                    "action",
                    "current_password",
                    "totp_code",
                ][..],
            ),
            "remove" => (
                Some(Action::Remove),
                &[
                    "csrf_token",
                    "revision",
                    "action",
                    "current_password",
                    "totp_code",
                ][..],
            ),
            "verify" => (
                Some(Action::Verify {
                    token: get("token").into(),
                }),
                &["csrf_token", "revision", "action", "token"][..],
            ),
            _ => (None, &[][..]),
        };
        if form.len() != expected.len() || form.keys().any(|key| !expected.contains(&key.as_str()))
        {
            return HandledHttpResponse { response: reply(400, "Bad Request", "The recovery form contained unsupported or missing fields. Reload the page before submitting."), audit_events };
        }
        let (Some(revision), Some(action)) = (revision, action) else {
            return HandledHttpResponse { response: reply(400, "Bad Request", "The recovery form contained unsupported or missing fields. Reload the page before submitting."), audit_events };
        };
        let Some(token) = session_cookie_value(request, self.policy.session_cookie_name)
            .and_then(|v| SessionToken::new(v).ok())
        else {
            return HandledHttpResponse {
                response: reply(
                    401,
                    "Unauthorized",
                    "Sign in again before managing your contact.",
                ),
                audit_events,
            };
        };
        let (guard, acquired) = match self.acquire_auth_budget(context) {
            Ok(value) => value,
            Err(response) => return response,
        };
        audit_events.push(acquired);
        let result = self.gateway.recovery_contact_action(
            context,
            &session,
            &token,
            revision,
            action,
            get("current_password"),
            get("totp_code"),
            deadline,
        );
        drop(guard);
        let response = match result {
            Ok(result) => {
                let notice = match result.delivery {
                    Some(Delivery::Refused) => "Message submission was refused. Review the current contact state below; no message delivery is claimed.",
                    Some(Delivery::Unconfirmed) => "Message submission is unconfirmed. Review the current contact state and contact support before repeating this action.",
                    _ => match result.effect {
                        crate::recovery_contact::RecoveryContactEffect::Pending => "Verification was accepted by the mail service. Enter the code from that message below; the address is not yet verified.",
                        crate::recovery_contact::RecoveryContactEffect::Verified => "Your recovery contact was verified. This does not grant account access or bypass TOTP.",
                        crate::recovery_contact::RecoveryContactEffect::Removed => "Your recovery contact and pending verification were removed.",
                    },
                };
                audit_events.push(LogEvent::new(LogLevel::Info, EventCategory::Auth, "recovery_contact_action", "Recovery contact action recorded; delivery and verification are separate outcomes").with_field("request_id", context.request_id.clone()));
                page(200, "OK", &session, Some(&result.snapshot), Some(notice))
            }
            Err(error) => {
                let (status, reason, notice) = match error {
                    Error::Authentication => (403, "Forbidden", "Your current password or fresh authenticator code was not accepted. No contact change was made."),
                    Error::Throttled | Error::RateLimited { .. } => (429, "Too Many Requests", "Too many attempts or verification messages. Wait before trying again."),
                    Error::Stale | Error::Busy => (409, "Conflict", "The contact state changed or another operation is active. Reload the page before submitting."),
                    Error::Invalid | Error::InvalidToken | Error::Expired | Error::NoPending => (400, "Bad Request", "The address or verification code is invalid, expired or no longer pending. Review the current state below."),
                    Error::DeliveryUnconfirmed => (409, "Conflict", "A prior message submission is unconfirmed. Contact support to reconcile it; do not repeat the send."),
                    Error::Unavailable => (503, "Service Unavailable", "The operation could not be confirmed. Reload to inspect the stored contact state; do not automatically repeat the action."),
                };
                audit_events.push(
                    LogEvent::new(
                        LogLevel::Warn,
                        EventCategory::Auth,
                        "recovery_contact_refused",
                        "Recovery contact action did not report completion",
                    )
                    .with_field("request_id", context.request_id.clone()),
                );
                let refreshed = self.gateway.recovery_contact(&session).ok();
                page(status, reason, &session, refreshed.as_ref(), Some(notice))
            }
        };
        HandledHttpResponse {
            response,
            audit_events,
        }
    }
}
