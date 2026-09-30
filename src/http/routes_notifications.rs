//! Native owner-bound notification reads and revision-checked read state.
use super::*;
use crate::logging::EventCategory;
use crate::notifications::{NotificationError, NotificationKind};
impl<G: BrowserGateway> BrowserApp<G> {
    pub(super) fn record_session_notice(
        &self,
        context: &AuthenticationContext,
        account: &str,
        kind: NotificationKind,
        events: &mut Vec<LogEvent>,
    ) -> bool {
        if self
            .gateway
            .record_session_notification(account, kind)
            .is_ok()
        {
            true
        } else {
            events.push(
                LogEvent::new(
                    LogLevel::Warn,
                    EventCategory::Session,
                    "notification_recording_unconfirmed",
                    "session action succeeded but notification recording was not confirmed",
                )
                .with_field("request_id", context.request_id.clone()),
            );
            false
        }
    }
    pub(super) fn handle_notifications(
        &self,
        request: &HttpRequest,
        context: &AuthenticationContext,
    ) -> HandledHttpResponse {
        let (session, audit_events) = match self.require_validated_session(request, context) {
            Ok(value) => value,
            Err(response) => return response,
        };
        let inbox = self.gateway.notification_inbox(&session);
        request.notification_context.borrow_mut().count =
            Some(super::notification_badge::unread(inbox.as_ref().ok()));
        HandledHttpResponse {
            response: html_response(
                if inbox.is_ok() { 200 } else { 503 },
                if inbox.is_ok() {
                    "OK"
                } else {
                    "Service Unavailable"
                },
                "Notifications",
                crate::http_ui::render_notification_inbox(
                    &session.record.canonical_username,
                    &session.record.csrf_token,
                    inbox.as_ref().ok(),
                    None,
                ),
            ),
            audit_events,
        }
    }
    pub(super) fn handle_notification_read(
        &self,
        request: &HttpRequest,
        context: &AuthenticationContext,
    ) -> HandledHttpResponse {
        let (session, mut audit_events) = match self.require_validated_session(request, context) {
            Ok(value) => value,
            Err(response) => return response,
        };
        let form = if allows_urlencoded_request_body(
            request.headers.get("content-type").map(String::as_str),
        ) {
            parse_urlencoded_form(&request.body, 4, 512).ok()
        } else {
            None
        };
        let Some(form) = form else {
            return HandledHttpResponse {
                response: html_response(
                    400,
                    "Bad Request",
                    "Invalid Notification Request",
                    "<p>Reload Notifications before changing read state.</p>",
                ),
                audit_events,
            };
        };
        if let Some(response) = self.require_valid_csrf(
            request,
            form.get("csrf_token").map(String::as_str),
            &session,
            context,
        ) {
            return response;
        }
        let result = (|| {
            if form.len() != 4
                || form.keys().any(|key| {
                    !["csrf_token", "event_id", "revision", "read"].contains(&key.as_str())
                })
            {
                return Err(NotificationError::Invalid);
            }
            let revision = form
                .get("revision")
                .and_then(|v| v.parse::<u64>().ok().filter(|n| n.to_string() == *v))
                .ok_or(NotificationError::Invalid)?;
            let read = match form.get("read").map(String::as_str) {
                Some("1") => true,
                Some("0") => false,
                _ => return Err(NotificationError::Invalid),
            };
            self.gateway.set_notification_read(
                &session,
                form.get("event_id").ok_or(NotificationError::Invalid)?,
                revision,
                read,
            )
        })();
        match result {
            Ok(_) => HandledHttpResponse {
                response: redirect_response(303, "See Other", "/notifications"),
                audit_events,
            },
            Err(error) => {
                let (status,reason,text)=match error {NotificationError::Stale=>(409,"Conflict","Notifications changed. Review the current list before changing read state."),NotificationError::Invalid|NotificationError::Missing=>(400,"Bad Request","The notification request was not valid for this account. Reload Notifications."),_=>(503,"Service Unavailable","The read-state update could not be confirmed. Reload Notifications to check the stored state.")};
                audit_events.push(build_http_warning_event(
                    "notification_read_refused",
                    "notification read update was not confirmed",
                    context,
                ));
                let inbox = self.gateway.notification_inbox(&session).ok();
                request.notification_context.borrow_mut().count =
                    Some(super::notification_badge::unread(inbox.as_ref()));
                HandledHttpResponse {
                    response: html_response(
                        status,
                        reason,
                        "Notifications",
                        crate::http_ui::render_notification_inbox(
                            &session.record.canonical_username,
                            &session.record.csrf_token,
                            inbox.as_ref(),
                            Some(text),
                        ),
                    ),
                    audit_events,
                }
            }
        }
    }
}
