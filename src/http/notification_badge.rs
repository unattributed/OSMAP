//! Response-scoped notification projection from the route's validated session.
use super::*;
use crate::notifications::{NotificationInbox, MAX_EVENTS};

#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub(crate) struct RenderContext {
    pub session: Option<ValidatedSession>,
    pub authentication_context: Option<AuthenticationContext>,
    pub count: Option<Option<usize>>,
}

/// Clears response-only state before use and on every return or unwind.
pub(super) struct RenderScope<'a>(&'a HttpRequest);
impl<'a> RenderScope<'a> {
    pub(super) fn new(request: &'a HttpRequest) -> Self {
        *request.notification_context.borrow_mut() = RenderContext::default();
        Self(request)
    }
}
impl Drop for RenderScope<'_> {
    fn drop(&mut self) {
        *self.0.notification_context.borrow_mut() = RenderContext::default();
    }
}

pub(super) fn unread(inbox: Option<&NotificationInbox>) -> Option<usize> {
    let inbox = inbox?;
    if inbox.events.len() > MAX_EVENTS {
        return None;
    }
    let mut ids = std::collections::BTreeSet::new();
    if inbox
        .events
        .iter()
        .any(|event| !ids.insert(&event.event_id))
    {
        return None;
    }
    Some(inbox.events.iter().filter(|event| !event.read).count())
}

impl<G: BrowserGateway> BrowserApp<G> {
    pub(super) fn apply_notification_badge(
        &self,
        response: &mut HttpResponse,
        request: &HttpRequest,
    ) {
        if !response
            .headers
            .iter()
            .any(|(k, v)| k.eq_ignore_ascii_case("Content-Type") && v == "text/html; charset=utf-8")
            || response
                .headers
                .iter()
                .any(|(k, _)| k.eq_ignore_ascii_case("Content-Disposition"))
        {
            return;
        }
        let context = request.notification_context.borrow();
        let Some(session) = &context.session else {
            return;
        };
        let Ok(html) = std::str::from_utf8(&response.body) else {
            return;
        };
        let slot =
            crate::http_ui::notification_header_link(&session.record.canonical_username, None);
        if !html.starts_with("<!doctype html><html lang=\"en\"") || !html.contains(&slot) {
            return;
        }
        let count = context
            .count
            .unwrap_or_else(|| unread(self.gateway.notification_inbox(session).as_ref().ok()));
        response.body = html
            .replacen(
                &slot,
                &crate::http_ui::notification_header_link(
                    &session.record.canonical_username,
                    count,
                ),
                1,
            )
            .into_bytes();
    }
}
