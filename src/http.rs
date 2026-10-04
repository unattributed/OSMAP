//! Minimal HTTP and browser handling for the first OSMAP web slice.
//!
//! This module deliberately avoids a framework while the project is still
//! proving its security and operational shape. The goal is not feature breadth;
//! the goal is an explicit, reviewable request path that consumes the existing
//! auth, session, mailbox, and rendering layers.

pub(crate) mod compose_actions;
pub(crate) mod compose_delivery_ui;
mod compose_enhancement;
pub(crate) mod compose_preflight;
pub(crate) mod compose_protection;
pub use compose_protection::ComposeProtectionView;
#[path = "http/folder_tree.rs"]
mod folder_tree;
mod header_theme;
#[path = "http_browser.rs"]
mod http_browser;
#[path = "http_gateway.rs"]
mod http_gateway;
#[path = "http_runtime.rs"]
mod http_runtime;
mod notification_badge;
mod routes_after_archive;
mod routes_appearance;
mod routes_auth;
mod routes_autosave;
mod routes_bin_folder;
mod routes_compose;
mod routes_composition_preferences;
mod routes_contacts;
mod routes_content;
mod routes_display;
mod routes_draft;
mod routes_draft_selection;
mod routes_flags;
mod routes_identity_preferences;
#[path = "http/routes_keys.rs"]
mod routes_keys;
mod routes_label_selection;
mod routes_labels;
mod routes_mail;
mod routes_mark_read;
mod routes_message_open;
pub(crate) use folder_tree::FolderTree;
mod routes_all_search;
mod routes_bulk_delete;
mod routes_delete;
mod routes_folder_create;
mod routes_moves;
mod routes_notifications;
#[path = "http/routes_people.rs"]
mod routes_people;
mod routes_reading_preferences;
mod routes_reply;
#[path = "http/routes_send_receipt.rs"]
mod routes_send_receipt;
mod routes_settings;

mod routes_signature;
mod routes_snooze;
mod routes_source_attachments;
#[path = "http/welcome_data.rs"]
mod welcome_data;

use std::collections::BTreeMap;
use std::path::PathBuf;
use std::sync::atomic::{AtomicUsize, Ordering};

use crate::appearance::{AppearancePreference, AppearanceSettings, AppearanceStore};
use crate::attachment::{
    AttachmentDownloadDecision, AttachmentDownloadPolicy, AttachmentDownloadPublicFailureReason,
    AttachmentDownloadService, DownloadedAttachment,
};
use crate::auth::{
    AuthenticationContext, AuthenticationDecision, AuthenticationPolicy, AuthenticationService,
    DoveadmAuthTestBackend, PublicFailureReason, RequiredSecondFactor, SecondFactorService,
    SystemCommandExecutor,
};
use crate::config::{AppConfig, LogLevel, RuntimeEnvironment};
use crate::draft::{
    DraftPolicy, DraftRecord, DraftRecordInput, DraftSourceAttachments, DraftStore, DraftSummary,
    FileDraftStore,
};
use crate::html::TrustedHtml;
use crate::http_form::{parse_compose_form, parse_urlencoded_form};
use crate::http_parse::{
    allows_urlencoded_request_body, build_session_cookie, clear_session_cookie,
    compose_source_from_request, session_cookie_value,
};
use crate::http_support::{
    attachment_download_response, build_auth_warning_event, build_http_info_event,
    build_http_warning_event, constant_time_eq, escape_html, html_response, public_reason_message,
    redirect_response, session_error_label, throttle_store_error_label, url_encode,
};
use crate::http_ui::{
    render_compose_page, render_draft_list_page, render_login_page,
    render_mailboxes_page_with_policy, render_message_list_page, render_message_search_page,
    render_navigation_notice, render_sessions_page, ComposePageModel, DraftListPageModel,
    MailReaderContext, MessageListBulkActions, MessageListSortLinks, MessageSearchContext,
    SelectedMessagePane, SettingsPageModel,
};
use crate::logging::LogEvent;
#[cfg(test)]
use crate::logging::{EventCategory, Logger};
use crate::mailbox::MessageView;
use crate::mailbox::{
    DoveadmMailboxListBackend, DoveadmMessageAppendBackend, DoveadmMessageListBackend,
    DoveadmMessageMoveBackend, DoveadmMessageSearchBackend, DoveadmMessageViewBackend,
    MailboxEntry, MailboxListingDecision, MailboxListingPolicy, MailboxListingService,
    MessageAppendBackend, MessageAppendRequest, MessageListDecision, MessageListPolicy,
    MessageListRequest, MessageListService, MessageMovePolicy, MessageMoveRequest,
    MessageSearchDecision, MessageSearchField, MessageSearchPolicy, MessageSearchRequest,
    MessageSearchResult, MessageSearchService, MessageSummary, MessageViewDecision,
    MessageViewPolicy, MessageViewRequest, MessageViewService,
};
use crate::mailbox_helper::{
    MailboxHelperMailboxListBackend, MailboxHelperMessageAppendBackend,
    MailboxHelperMessageListBackend, MailboxHelperMessageMoveBackend,
    MailboxHelperMessageSearchBackend, MailboxHelperMessageViewBackend, MailboxHelperPolicy,
};
use crate::rendering::{
    HtmlDisplayPreference, PlainTextMessageRenderer, RenderedMessageView, RenderingPolicy,
};
#[cfg(test)]
use crate::send::build_submission_message;
use crate::send::{
    ComposeDraft, ComposeIntent, ComposePolicy, ComposeRequest, SendmailSubmissionBackend,
    SubmissionDecision, SubmissionOutcome, SubmissionPublicFailureReason, SubmissionService,
    UploadedAttachment, DEFAULT_ATTACHMENT_MAX_BYTES, DEFAULT_TOTAL_ATTACHMENT_MAX_BYTES,
};
use crate::session::{
    FileSessionStore, SessionService, SessionToken, SystemRandomSource, ValidatedSession,
    SESSION_ID_HEX_LEN,
};
use crate::throttle::{
    FileLoginThrottleStore, LoginThrottleDecision, LoginThrottleError, LoginThrottlePolicy,
    LoginThrottleService, MessageMoveThrottleDecision, MessageMoveThrottlePolicy,
    MessageMoveThrottleService, SubmissionThrottleDecision, SubmissionThrottlePolicy,
    SubmissionThrottleService, TOO_MANY_ATTEMPTS_PUBLIC_REASON,
    TOO_MANY_MESSAGE_MOVES_PUBLIC_REASON, TOO_MANY_SUBMISSIONS_PUBLIC_REASON,
};
use crate::totp::{FileTotpSecretStore, SystemTimeProvider, TotpPolicy, TotpVerifier};

pub use crate::http_parse::{parse_http_request, parse_http_request_bytes};

/// Conservative upper bound for the full header section of an inbound request.
pub const DEFAULT_HTTP_MAX_HEADER_BYTES: usize = 16 * 1024;

/// Conservative upper bound for one request target.
pub const DEFAULT_HTTP_MAX_REQUEST_TARGET_BYTES: usize = 2048;

/// Conservative upper bound for a small HTML form request body.
pub const DEFAULT_HTTP_MAX_BODY_BYTES: usize = 8 * 1024;

/// Conservative upper bound for query fields in one request target.
pub const DEFAULT_HTTP_MAX_QUERY_FIELDS: usize = 16;

/// Conservative upper bound for a multipart upload request body.
pub const DEFAULT_HTTP_MAX_UPLOAD_BODY_BYTES: usize = 32 * 1024 * 1024;

/// Conservative upper bound for parsed HTML form fields.
pub const DEFAULT_HTTP_MAX_FORM_FIELDS: usize = 16;

/// Conservative upper bound for header count in one request.
pub const DEFAULT_HTTP_MAX_HEADER_COUNT: usize = 64;

/// Conservative upper bound for any individual request-header value.
pub const DEFAULT_HTTP_MAX_HEADER_VALUE_BYTES: usize = 8 * 1024;

/// Conservative upper bound for the `Host` header value.
pub const DEFAULT_HTTP_MAX_HOST_HEADER_BYTES: usize = 512;

/// Conservative upper bound for one browser `Cookie` header value.
pub const DEFAULT_HTTP_MAX_COOKIE_HEADER_BYTES: usize = 4096;

/// Conservative upper bound for one `Content-Type` header value.
pub const DEFAULT_HTTP_MAX_CONTENT_TYPE_HEADER_BYTES: usize = 256;

/// Conservative upper bound for one response header name.
pub const DEFAULT_RESPONSE_HEADER_NAME_MAX_LEN: usize = 128;

/// Conservative upper bound for one response header value.
pub const DEFAULT_RESPONSE_HEADER_VALUE_MAX_LEN: usize = 4096;

/// Conservative per-connection read timeout for the sequential HTTP listener.
pub const DEFAULT_HTTP_READ_TIMEOUT_SECS: u64 = 5;

/// Conservative per-connection write timeout for the sequential HTTP listener.
pub const DEFAULT_HTTP_WRITE_TIMEOUT_SECS: u64 = 5;

/// Conservative bound for concurrently handled HTTP connections.
pub const DEFAULT_HTTP_MAX_CONCURRENT_CONNECTIONS: usize = 16;

/// Conservative bound for expensive authenticated mailbox worker occupancy.
pub const DEFAULT_MAILBOX_WORKER_BUDGET: usize = 8;

/// Conservative bound for expensive authenticated search worker occupancy.
pub const DEFAULT_SEARCH_WORKER_BUDGET: usize = 4;

/// Conservative bound for expensive outbound send worker occupancy.
pub const DEFAULT_SEND_WORKER_BUDGET: usize = 2;

/// Conservative bound for expensive external-auth worker occupancy.
pub const DEFAULT_AUTH_WORKER_BUDGET: usize = 4;

/// Short retry hint for fail-fast route-class budget exhaustion.
pub const DEFAULT_REQUEST_BUDGET_RETRY_AFTER_SECS: u64 = 1;

/// Conservative route-level cap for admitted expensive browser work.
pub const DEFAULT_EXPENSIVE_REQUEST_TIMEOUT_SECS: u64 =
    crate::config::DEFAULT_EXPENSIVE_REQUEST_TIMEOUT_SECONDS;

/// The fixed cookie name used by the current browser session slice.
pub const DEFAULT_SESSION_COOKIE_NAME: &str = "osmap_session";

/// Policy controlling the first bounded HTTP/browser slice.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct HttpPolicy {
    pub max_header_bytes: usize,
    pub max_request_target_bytes: usize,
    pub max_header_count: usize,
    pub max_header_value_bytes: usize,
    pub max_query_fields: usize,
    pub max_body_bytes: usize,
    pub max_upload_body_bytes: usize,
    pub max_form_fields: usize,
    pub allowed_hosts: Vec<String>,
    pub session_cookie_name: &'static str,
    pub secure_session_cookie: bool,
    pub read_timeout_secs: u64,
    pub write_timeout_secs: u64,
    pub max_concurrent_connections: usize,
    pub mailbox_worker_budget: usize,
    pub search_worker_budget: usize,
    pub send_worker_budget: usize,
    pub auth_worker_budget: usize,
    pub expensive_request_timeout_secs: u64,
    pub request_budget_retry_after_secs: u64,
    pub authentication_policy: AuthenticationPolicy,
}

impl HttpPolicy {
    /// Builds the browser policy from validated application configuration.
    pub fn from_config(config: &AppConfig) -> Self {
        Self {
            max_header_bytes: DEFAULT_HTTP_MAX_HEADER_BYTES,
            max_request_target_bytes: DEFAULT_HTTP_MAX_REQUEST_TARGET_BYTES,
            max_header_count: DEFAULT_HTTP_MAX_HEADER_COUNT,
            max_header_value_bytes: DEFAULT_HTTP_MAX_HEADER_VALUE_BYTES,
            max_query_fields: DEFAULT_HTTP_MAX_QUERY_FIELDS,
            max_body_bytes: DEFAULT_HTTP_MAX_BODY_BYTES,
            max_upload_body_bytes: DEFAULT_HTTP_MAX_UPLOAD_BODY_BYTES,
            max_form_fields: DEFAULT_HTTP_MAX_FORM_FIELDS,
            allowed_hosts: config.allowed_hosts.clone(),
            session_cookie_name: DEFAULT_SESSION_COOKIE_NAME,
            secure_session_cookie: config.environment != RuntimeEnvironment::Development,
            read_timeout_secs: DEFAULT_HTTP_READ_TIMEOUT_SECS,
            write_timeout_secs: DEFAULT_HTTP_WRITE_TIMEOUT_SECS,
            max_concurrent_connections: config.http_max_concurrent_connections as usize,
            mailbox_worker_budget: config.mailbox_worker_budget as usize,
            search_worker_budget: config.search_worker_budget as usize,
            send_worker_budget: config.send_worker_budget as usize,
            auth_worker_budget: config.auth_worker_budget as usize,
            expensive_request_timeout_secs: config.expensive_request_timeout_seconds,
            request_budget_retry_after_secs: DEFAULT_REQUEST_BUDGET_RETRY_AFTER_SECS,
            authentication_policy: AuthenticationPolicy {
                required_second_factor: RequiredSecondFactor::Totp,
                ..AuthenticationPolicy::default()
            },
        }
    }
}

impl Default for HttpPolicy {
    fn default() -> Self {
        Self {
            max_header_bytes: DEFAULT_HTTP_MAX_HEADER_BYTES,
            max_request_target_bytes: DEFAULT_HTTP_MAX_REQUEST_TARGET_BYTES,
            max_header_count: DEFAULT_HTTP_MAX_HEADER_COUNT,
            max_header_value_bytes: DEFAULT_HTTP_MAX_HEADER_VALUE_BYTES,
            max_query_fields: DEFAULT_HTTP_MAX_QUERY_FIELDS,
            max_body_bytes: DEFAULT_HTTP_MAX_BODY_BYTES,
            max_upload_body_bytes: DEFAULT_HTTP_MAX_UPLOAD_BODY_BYTES,
            max_form_fields: DEFAULT_HTTP_MAX_FORM_FIELDS,
            allowed_hosts: vec![
                "localhost".to_string(),
                "localhost:8080".to_string(),
                "127.0.0.1".to_string(),
                "127.0.0.1:8080".to_string(),
            ],
            session_cookie_name: DEFAULT_SESSION_COOKIE_NAME,
            secure_session_cookie: false,
            read_timeout_secs: DEFAULT_HTTP_READ_TIMEOUT_SECS,
            write_timeout_secs: DEFAULT_HTTP_WRITE_TIMEOUT_SECS,
            max_concurrent_connections: DEFAULT_HTTP_MAX_CONCURRENT_CONNECTIONS,
            mailbox_worker_budget: DEFAULT_MAILBOX_WORKER_BUDGET,
            search_worker_budget: DEFAULT_SEARCH_WORKER_BUDGET,
            send_worker_budget: DEFAULT_SEND_WORKER_BUDGET,
            auth_worker_budget: DEFAULT_AUTH_WORKER_BUDGET,
            expensive_request_timeout_secs: DEFAULT_EXPENSIVE_REQUEST_TIMEOUT_SECS,
            request_budget_retry_after_secs: DEFAULT_REQUEST_BUDGET_RETRY_AFTER_SECS,
            authentication_policy: AuthenticationPolicy::default(),
        }
    }
}

/// The supported HTTP methods for the current browser slice.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum HttpMethod {
    Get,
    Post,
}

impl HttpMethod {
    /// Returns the canonical method token used in logs and diagnostics.
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Get => "GET",
            Self::Post => "POST",
        }
    }
}

/// A small parsed HTTP request.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct HttpRequest {
    pub(crate) notification_context: std::cell::RefCell<notification_badge::RenderContext>,
    pub method: HttpMethod,
    pub path: String,
    pub query_params: BTreeMap<String, String>,
    pub headers: BTreeMap<String, String>,
    pub body: Vec<u8>,
}

/// A small HTTP response that can be written directly to a socket.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct HttpResponse {
    pub status_code: u16,
    pub reason_phrase: &'static str,
    pub headers: Vec<(String, String)>,
    pub body: Vec<u8>,
}

impl HttpResponse {
    /// Creates a text response with the supplied status and body.
    pub fn text(status_code: u16, reason_phrase: &'static str, body: impl Into<String>) -> Self {
        Self {
            status_code,
            reason_phrase,
            headers: Vec::new(),
            body: body.into().into_bytes(),
        }
    }

    /// Creates a binary response with the supplied status and body.
    pub fn binary(status_code: u16, reason_phrase: &'static str, body: Vec<u8>) -> Self {
        Self {
            status_code,
            reason_phrase,
            headers: Vec::new(),
            body,
        }
    }

    /// Adds one header in insertion order.
    pub fn with_header(mut self, name: impl Into<String>, value: impl Into<String>) -> Self {
        let name = name.into();
        let value = value.into();
        if validate_response_header(&name, &value).is_err() {
            return invalid_response_header();
        }

        self.headers.push((name, value));
        self
    }

    /// Encodes the response into a connection-close HTTP/1.1 payload.
    pub fn to_http_bytes(&self) -> Vec<u8> {
        if self
            .headers
            .iter()
            .any(|(name, value)| validate_response_header(name, value).is_err())
        {
            return invalid_response_header().to_http_bytes();
        }

        let mut output = String::new();
        output.push_str(&format!(
            "HTTP/1.1 {} {}\r\n",
            self.status_code, self.reason_phrase
        ));

        let mut has_content_type = false;
        let mut has_content_length = false;
        let mut has_connection = false;
        for (name, value) in &self.headers {
            if name.eq_ignore_ascii_case("content-type") {
                has_content_type = true;
            }
            if name.eq_ignore_ascii_case("content-length") {
                has_content_length = true;
            }
            if name.eq_ignore_ascii_case("connection") {
                has_connection = true;
            }
            output.push_str(&format!("{name}: {value}\r\n"));
        }

        if !has_content_type {
            output.push_str("Content-Type: text/html; charset=utf-8\r\n");
        }
        if !has_content_length {
            output.push_str(&format!("Content-Length: {}\r\n", self.body.len()));
        }
        if !has_connection {
            output.push_str("Connection: close\r\n");
        }

        output.push_str("\r\n");
        let mut bytes = output.into_bytes();
        bytes.extend_from_slice(&self.body);
        bytes
    }
}

fn invalid_response_header() -> HttpResponse {
    HttpResponse {
        status_code: 500,
        reason_phrase: "Internal Server Error",
        headers: vec![
            (
                "Content-Type".to_string(),
                "text/plain; charset=utf-8".to_string(),
            ),
            ("Cache-Control".to_string(), "no-store".to_string()),
            ("X-Content-Type-Options".to_string(), "nosniff".to_string()),
        ],
        body: b"invalid response header\n".to_vec(),
    }
}

fn validate_response_header(name: &str, value: &str) -> Result<(), ()> {
    if name.is_empty() || name.len() > DEFAULT_RESPONSE_HEADER_NAME_MAX_LEN {
        return Err(());
    }

    if !name.bytes().all(is_http_header_name_byte) {
        return Err(());
    }

    if value.len() > DEFAULT_RESPONSE_HEADER_VALUE_MAX_LEN {
        return Err(());
    }

    if value.chars().any(char::is_control) {
        return Err(());
    }

    Ok(())
}

fn is_http_header_name_byte(byte: u8) -> bool {
    byte.is_ascii_alphanumeric()
        || matches!(
            byte,
            b'!' | b'#'
                | b'$'
                | b'%'
                | b'&'
                | b'\''
                | b'*'
                | b'+'
                | b'-'
                | b'.'
                | b'^'
                | b'_'
                | b'`'
                | b'|'
                | b'~'
        )
}

/// A response plus the log events emitted while building it.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct HandledHttpResponse {
    pub response: HttpResponse,
    pub audit_events: Vec<LogEvent>,
}

/// Shared fail-fast budgets for expensive authenticated route classes.
#[derive(Debug)]
struct RequestBudgets {
    mailbox_workers: RequestBudget,
    search_workers: RequestBudget,
    send_workers: RequestBudget,
    auth_workers: RequestBudget,
}

impl RequestBudgets {
    fn from_policy(policy: &HttpPolicy) -> Self {
        Self {
            mailbox_workers: RequestBudget::new("mailbox_workers", policy.mailbox_worker_budget),
            search_workers: RequestBudget::new("search_workers", policy.search_worker_budget),
            send_workers: RequestBudget::new("send_workers", policy.send_worker_budget),
            auth_workers: RequestBudget::new("auth_workers", policy.auth_worker_budget),
        }
    }
}

/// One atomic route-class budget.
#[derive(Debug)]
struct RequestBudget {
    name: &'static str,
    limit: usize,
    active: AtomicUsize,
}

impl RequestBudget {
    fn new(name: &'static str, limit: usize) -> Self {
        Self {
            name,
            limit,
            active: AtomicUsize::new(0),
        }
    }

    fn try_acquire(&self) -> Option<RequestBudgetGuard<'_>> {
        let mut active = self.active.load(Ordering::SeqCst);
        loop {
            if active >= self.limit {
                return None;
            }
            match self.active.compare_exchange(
                active,
                active + 1,
                Ordering::SeqCst,
                Ordering::SeqCst,
            ) {
                Ok(_) => {
                    return Some(RequestBudgetGuard {
                        budget: self,
                        released: false,
                    });
                }
                Err(observed) => active = observed,
            }
        }
    }

    fn active_count(&self) -> usize {
        self.active.load(Ordering::SeqCst)
    }
}

/// RAII guard that releases a budget slot on normal return or unwind.
#[derive(Debug)]
struct RequestBudgetGuard<'a> {
    budget: &'a RequestBudget,
    released: bool,
}

impl RequestBudgetGuard<'_> {
    fn active_count(&self) -> usize {
        self.budget.active_count()
    }

    fn limit(&self) -> usize {
        self.budget.limit
    }

    fn release(mut self) -> usize {
        self.released = true;
        self.budget
            .active
            .fetch_sub(1, Ordering::SeqCst)
            .saturating_sub(1)
    }
}

impl Drop for RequestBudgetGuard<'_> {
    fn drop(&mut self) {
        if !self.released {
            self.budget.active.fetch_sub(1, Ordering::SeqCst);
        }
    }
}

/// Errors raised while parsing or reading an inbound HTTP request.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum HttpRequestErrorKind {
    Parse,
    Timeout,
    Truncated,
    Empty,
}

/// Errors raised while parsing or reading an inbound HTTP request.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct HttpRequestError {
    pub kind: HttpRequestErrorKind,
    pub reason: String,
}

/// The browser application/router for the current HTTP slice.
pub struct BrowserApp<G> {
    policy: HttpPolicy,
    gateway: G,
    request_budgets: RequestBudgets,
}

impl<G> BrowserApp<G> {
    /// Creates a browser app from the supplied policy and gateway.
    pub fn new(policy: HttpPolicy, gateway: G) -> Self {
        let request_budgets = RequestBudgets::from_policy(&policy);
        Self {
            policy,
            gateway,
            request_budgets,
        }
    }

    /// Returns the current request-reading limits.
    pub fn policy(&self) -> &HttpPolicy {
        &self.policy
    }

    fn acquire_search_budget(
        &self,
        context: &AuthenticationContext,
        validated_session: &ValidatedSession,
    ) -> Result<(RequestBudgetGuard<'_>, LogEvent), HandledHttpResponse> {
        self.acquire_request_budget(
            &self.request_budgets.search_workers,
            "message_search",
            context,
            Some(validated_session),
        )
    }

    fn acquire_mailbox_budget(
        &self,
        context: &AuthenticationContext,
        validated_session: &ValidatedSession,
        route_class: &'static str,
    ) -> Result<(RequestBudgetGuard<'_>, LogEvent), HandledHttpResponse> {
        self.acquire_request_budget(
            &self.request_budgets.mailbox_workers,
            route_class,
            context,
            Some(validated_session),
        )
    }

    fn acquire_send_budget(
        &self,
        context: &AuthenticationContext,
        validated_session: &ValidatedSession,
    ) -> Result<(RequestBudgetGuard<'_>, LogEvent), HandledHttpResponse> {
        self.acquire_request_budget(
            &self.request_budgets.send_workers,
            "message_send",
            context,
            Some(validated_session),
        )
    }

    fn acquire_auth_budget(
        &self,
        context: &AuthenticationContext,
    ) -> Result<(RequestBudgetGuard<'_>, LogEvent), HandledHttpResponse> {
        self.acquire_request_budget(&self.request_budgets.auth_workers, "login", context, None)
    }

    fn acquire_request_budget<'a>(
        &self,
        budget: &'a RequestBudget,
        route_class: &'static str,
        context: &AuthenticationContext,
        validated_session: Option<&ValidatedSession>,
    ) -> Result<(RequestBudgetGuard<'a>, LogEvent), HandledHttpResponse> {
        match budget.try_acquire() {
            Some(guard) => {
                let active = guard.active_count();
                let limit = guard.limit();
                Ok((
                    guard,
                    request_budget_event(
                        LogLevel::Info,
                        "request_budget_acquired",
                        "request worker budget slot acquired",
                        RequestBudgetEventContext {
                            budget_name: budget.name,
                            route_class,
                            active,
                            limit,
                            context,
                            validated_session,
                        },
                    ),
                ))
            }
            None => {
                let active = budget.active_count();
                let limit = budget.limit;
                let response = html_response(
                    503,
                    "Service Unavailable",
                    "Request Capacity Reached",
                    "<p>This request class is temporarily busy. Please retry shortly.</p>",
                )
                .with_header(
                    "Retry-After",
                    self.policy.request_budget_retry_after_secs.to_string(),
                );
                Err(HandledHttpResponse {
                    response,
                    audit_events: vec![request_budget_event(
                        LogLevel::Warn,
                        "request_budget_exhausted",
                        "request worker budget exhausted",
                        RequestBudgetEventContext {
                            budget_name: budget.name,
                            route_class,
                            active,
                            limit,
                            context,
                            validated_session,
                        },
                    )],
                })
            }
        }
    }

    fn release_request_budget(
        &self,
        guard: RequestBudgetGuard<'_>,
        route_class: &'static str,
        context: &AuthenticationContext,
        validated_session: &ValidatedSession,
    ) -> LogEvent {
        let budget_name = guard.budget.name;
        let limit = guard.limit();
        let active = guard.release();
        request_budget_event(
            LogLevel::Info,
            "request_budget_released",
            "request worker budget slot released",
            RequestBudgetEventContext {
                budget_name,
                route_class,
                active,
                limit,
                context,
                validated_session: Some(validated_session),
            },
        )
    }

    fn release_auth_budget(
        &self,
        guard: RequestBudgetGuard<'_>,
        context: &AuthenticationContext,
    ) -> LogEvent {
        let budget_name = guard.budget.name;
        let limit = guard.limit();
        let active = guard.release();
        request_budget_event(
            LogLevel::Info,
            "request_budget_released",
            "request worker budget slot released",
            RequestBudgetEventContext {
                budget_name,
                route_class: "login",
                active,
                limit,
                context,
                validated_session: None,
            },
        )
    }
}

struct RequestBudgetEventContext<'a> {
    budget_name: &'static str,
    route_class: &'static str,
    active: usize,
    limit: usize,
    context: &'a AuthenticationContext,
    validated_session: Option<&'a ValidatedSession>,
}

fn request_budget_event(
    level: LogLevel,
    action: &'static str,
    message: &'static str,
    budget_context: RequestBudgetEventContext<'_>,
) -> LogEvent {
    let mut event = LogEvent::new(level, crate::logging::EventCategory::Http, action, message)
        .with_field("budget_name", budget_context.budget_name)
        .with_field("route_class", budget_context.route_class)
        .with_field("active", budget_context.active.to_string())
        .with_field("limit", budget_context.limit.to_string())
        .with_field("request_id", budget_context.context.request_id.clone())
        .with_field("remote_addr", budget_context.context.remote_addr.clone())
        .with_field("user_agent", budget_context.context.user_agent.clone());
    if let Some(validated_session) = budget_context.validated_session {
        event = event.with_field(
            "canonical_username",
            validated_session.record.canonical_username.clone(),
        );
    }
    event
}

pub use self::http_browser::{
    BrowserAttachmentDownloadDecision, BrowserAttachmentDownloadOutcome,
    BrowserDraftDeleteDecision, BrowserDraftDeleteOutcome, BrowserDraftEditState,
    BrowserDraftListDecision, BrowserDraftListOutcome, BrowserDraftLoadDecision,
    BrowserDraftLoadOutcome, BrowserDraftSaveDecision, BrowserDraftSaveOutcome,
    BrowserDraftSaveRequest, BrowserDraftState, BrowserDraftStorageUsage,
    BrowserFolderCreateOutcome, BrowserFolderMetadataOutcome, BrowserGateway, BrowserLoginDecision,
    BrowserLoginOutcome, BrowserLogoutOutcome, BrowserMailboxDecision, BrowserMailboxOutcome,
    BrowserMailboxStatusOutcome, BrowserMessageDeleteOutcome, BrowserMessageFlagFailure,
    BrowserMessageFlagOutcome, BrowserMessageListDecision, BrowserMessageListOutcome,
    BrowserMessageMoveDecision, BrowserMessageMoveOutcome, BrowserMessageSearchDecision,
    BrowserMessageSearchOutcome, BrowserMessageViewDecision, BrowserMessageViewOutcome,
    BrowserPublicInventoryOutcome, BrowserSendDecision, BrowserSendOutcome,
    BrowserSendRecoveryDecision, BrowserSendRecoverySnapshot, BrowserSendRequest,
    BrowserSessionDecision, BrowserSessionListDecision, BrowserSessionListOutcome,
    BrowserSessionRevokeDecision, BrowserSessionRevokeOutcome, BrowserSessionRevokeScope,
    BrowserSessionValidationOutcome, BrowserSettingsDecision, BrowserSettingsOutcome,
    BrowserSettingsUpdateDecision, BrowserSettingsUpdateOutcome, BrowserVisibleSession,
    BrowserVisibleSettings,
};
pub use self::http_gateway::RuntimeBrowserGateway;
pub use self::http_runtime::run_http_server;

#[cfg(test)]
mod tests {
    mod inventory_route_tests {
        include!("http_inventory_tests.rs");
    }
    mod key_inventory_fixture {
        use super::*;
        include!("http/key_inventory_fixture.rs");
    }
    mod folder_create_fixture {
        include!("http/folder_create_fixture.rs");
    }
    mod folder_create_tests {
        include!("http/folder_create_tests.rs");
    }
    use super::*;
    mod welcome_data_tests {
        include!("http/welcome_data_tests.rs");
    }
    mod compose_enhancement_tests {
        include!("http/compose_enhancement_tests.rs");
    }
    mod fixture_sessions {
        include!("http/fixture_sessions.rs");
    }
    mod compose_format_tests {
        include!("http/compose_format_tests.rs");
    }
    mod send_recovery_ui_tests {
        include!("http/send_recovery_ui_tests.rs");
    }
    mod send_journal_routes_tests {
        include!("http/send_journal_routes_tests.rs");
    }
    mod send_result_tests {
        include!("http/send_result_tests.rs");
    }
    mod security_settings_tests {
        include!("http/security_settings_tests.rs");
    }
    mod snooze_tests {
        include!("http/snooze_tests.rs");
    }
    mod notification_tests {
        include!("http/notification_tests.rs");
    }
    mod identity_preference_tests {
        include!("http/identity_preference_tests.rs");
    }
    mod archive_event_route_tests {
        include!("http/archive_event_route_tests.rs");
    }
    mod after_archive_tests {
        include!("http/after_archive_tests.rs");
    }
    mod message_delete_tests {
        include!("http_message_delete_tests.rs");
    }
    mod bulk_delete_tests {
        include!("http_bulk_delete_tests.rs");
    }
    mod bin_folder_tests {
        include!("http/bin_folder_tests.rs");
    }
    mod copies_tests {
        include!("http/copies_tests.rs");
    }
    mod composition_preference_tests {
        include!("http/composition_preference_tests.rs");
    }
    mod reading_preferences_tests {
        include!("http/reading_preferences_tests.rs");
    }
    mod conversation_tests {
        include!("http/conversation_tests.rs");
    }
    mod ux_fixtures {
        include!("http/ux_fixtures.rs");
    }
    mod header_theme_tests {
        include!("http/header_theme_tests.rs");
    }
    mod appearance_tests {
        include!("http/appearance_tests.rs");
    }
    mod shell_tests {
        include!("http/shell_tests.rs");
    }
    mod component_tests {
        include!("http_component_tests.rs");
    }
    mod ux_browser_server {
        include!("http/ux_browser_server.rs");
    }
    mod mail_list_tests {
        include!("http/mail_list_tests.rs");
    }
    mod move_fixtures {
        include!("http/move_fixtures.rs");
    }
    use move_fixtures::{move_form, SyntheticMessageMoves};
    mod move_tests {
        include!("http/move_tests.rs");
    }
    mod content_tests {
        include!("http/content_tests.rs");
    }
    mod protected_route_tests {
        include!("http/protected_route_tests.rs");
    }
    mod key_management_route_tests {
        include!("http/key_management_route_tests.rs");
    }
    mod reply_tests {
        include!("http/reply_tests.rs");
    }
    mod autosave_tests {
        include!("http/autosave_tests.rs");
    }
    mod general_preferences_tests {
        include!("http/general_preferences_tests.rs");
    }

    mod signature_tests {
        include!("http/signature_tests.rs");
    }
    mod label_selection_tests {
        include!("http/label_selection_tests.rs");
    }
    mod label_tests {
        include!("http/label_tests.rs");
    }
    mod people_tests {
        include!("http/people_tests.rs");
    }
    mod all_search_tests {
        include!("http/all_search_tests.rs");
    }
    mod contact_tests {
        include!("http/contact_tests.rs");
    }
    mod draft_preservation_tests {
        include!("http/draft_preservation_tests.rs");
    }
    mod stale_binding_recovery_tests {
        include!("http/stale_binding_recovery_tests.rs");
    }
    mod source_attachment_tests {
        include!("http/source_attachment_tests.rs");
    }
    mod flag_fixtures {
        include!("http/flag_fixtures.rs");
    }
    mod flag_tests {
        include!("http/flag_tests.rs");
    }
    mod mark_read_tests {
        include!("http/mark_read_tests.rs");
    }
    use crate::auth::RequiredSecondFactor;
    use crate::mailbox::MessageView;
    use crate::mime::{AttachmentDisposition, MimeBodySource};
    use crate::rendering::RenderingMode;
    use crate::session::SessionRecord;
    use crate::throttle::LoginThrottleStore;
    use std::fs;
    use std::io::{Read as _, Write as _};
    use std::net::{Shutdown, TcpListener};
    use std::path::PathBuf;
    use std::sync::atomic::{AtomicUsize, Ordering};
    use std::sync::{Arc, Mutex};
    use std::thread;
    use std::time::Duration;

    type SyntheticFlagStates = BTreeMap<(String, String, u64), Vec<String>>;

    #[derive(Debug, Clone)]
    struct FixtureOpenPgpSnapshot {
        revision: u64,
        preflight_revision: Option<u64>,
        available: bool,
    }

    #[derive(Debug, Clone)]
    struct StubGateway {
        created_folders: Arc<Mutex<BTreeMap<String, Vec<String>>>>,
        send_journal: crate::send_journal::SendJournal,
        recovery_root: PathBuf,
        recovery_now: Option<u64>,
        labels_store: Option<crate::labels::LabelStore>,
        signature_store: Option<crate::signature::SignatureStore>,
        autosave_store: Option<crate::autosave::Store>,
        after_archive_store: Option<crate::after_archive::Store>,
        archive_event_store: Option<crate::archive_event::Store>,
        archive_event_records: Arc<std::sync::atomic::AtomicUsize>,
        archive_event_post_list_fault: Arc<Mutex<Option<archive_event_route_tests::PostListFault>>>,
        bin_store: Option<crate::bin_folder::BinPreferencesStore>,
        delete_decision: Arc<Mutex<crate::mailbox::RetentionDecision>>,
        delete_result: Arc<
            Mutex<Result<crate::mailbox::MessageDeleteResult, crate::mailbox::MessageDeleteError>>,
        >,
        delete_calls: Arc<Mutex<Vec<crate::mailbox::MessageDeleteRequest>>>,
        delete_results: Arc<
            Mutex<
                std::collections::VecDeque<
                    Result<crate::mailbox::MessageDeleteResult, crate::mailbox::MessageDeleteError>,
                >,
            >,
        >,
        delete_list_decision: Arc<Mutex<Option<BrowserMessageListDecision>>>,
        mark_read_store: Option<crate::mark_read::Store>,
        contacts_store: Option<crate::contacts::ContactStore>,
        draft_store: Option<crate::draft::FileDraftStore>,
        fail_draft_delete: Option<String>,
        drafts: Arc<Mutex<BTreeMap<String, DraftRecord>>>,
        submitted: Arc<Mutex<Vec<ComposeRequest>>>,
        message_flags: Arc<Mutex<SyntheticFlagStates>>,
        message_moves: Arc<Mutex<SyntheticMessageMoves>>,
        appearance_store: Option<AppearanceStore>,
        settings_store: Option<crate::settings::FileUserSettingsStore>,
        notification_store: Option<crate::notifications::NotificationStore>,
        notification_loads: std::sync::Arc<std::sync::atomic::AtomicUsize>,
        snooze_store: Option<crate::snooze::SnoozeStore>,
        identity_preferences_store: Option<crate::identity_preferences::IdentityPreferencesStore>,
        composition_preferences_store:
            Option<crate::composition_preferences::CompositionPreferencesStore>,
        reading_preferences_store: Option<crate::reading_preferences::ReadingPreferencesStore>,
        message_list_override: Option<Vec<MessageSummary>>,
        all_search_override: Option<BrowserMessageSearchDecision>,
        browser_fixture_accounts: bool,
        browser_fixture_openpgp: bool,
        browser_fixture_openpgp_denials: bool,
        fixture_openpgp_snapshot: Option<Arc<Mutex<FixtureOpenPgpSnapshot>>>,
        preview_mailbox_tree: bool,
        fixture_sessions: Option<fixture_sessions::FixtureSessions>,
    }

    impl Default for StubGateway {
        fn default() -> Self {
            Self {
                created_folders: Arc::new(Mutex::new(BTreeMap::new())),
                labels_store: None,
                signature_store: None,
                autosave_store: None,
                after_archive_store: None,
                archive_event_store: None,
                archive_event_records: Default::default(),
                archive_event_post_list_fault: Default::default(),
                bin_store: None,
                delete_decision: Arc::new(Mutex::new(
                    crate::mailbox::RetentionDecision::Unavailable,
                )),
                delete_result: Arc::new(Mutex::new(Err(
                    crate::mailbox::MessageDeleteError::PolicyUnavailable,
                ))),
                delete_calls: Arc::new(Mutex::new(Vec::new())),
                delete_results: Arc::new(Mutex::new(std::collections::VecDeque::new())),
                delete_list_decision: Arc::new(Mutex::new(None)),
                mark_read_store: None,
                contacts_store: None,
                draft_store: None,
                send_journal: fixture_send_journal(),
                recovery_now: None,
                recovery_root: temp_dir(&format!(
                    "recovery-fixture-{}",
                    crate::draft::generate_draft_id().unwrap()
                )),
                fail_draft_delete: None,
                drafts: Arc::new(Mutex::new(BTreeMap::new())),
                submitted: Arc::new(Mutex::new(Vec::new())),
                message_flags: Arc::new(Mutex::new(BTreeMap::new())),
                message_moves: Arc::new(Mutex::new(SyntheticMessageMoves::default())),
                appearance_store: None,
                settings_store: None,
                identity_preferences_store: None,
                notification_store: None,
                notification_loads: Default::default(),
                snooze_store: None,
                composition_preferences_store: None,
                reading_preferences_store: None,
                message_list_override: None,
                all_search_override: None,
                browser_fixture_accounts: false,
                browser_fixture_openpgp: false,
                browser_fixture_openpgp_denials: false,
                fixture_openpgp_snapshot: None,
                preview_mailbox_tree: false,
                fixture_sessions: None,
            }
        }
    }

    impl StubGateway {
        fn created_folder_guid(&self, account: &str, name: &str) -> Option<String> {
            use sha2::Digest;
            self.created_folders
                .lock()
                .unwrap()
                .get(account)
                .filter(|folders| folders.iter().any(|folder| folder == name))
                .map(|_| {
                    format!("{:x}", sha2::Sha256::digest(format!("{account}\0{name}")))[..32]
                        .to_owned()
                })
        }

        fn validated_session() -> ValidatedSession {
            ValidatedSession {
                record: SessionRecord {
                    session_id: "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef"
                        .to_string(),
                    csrf_token: "fedcba9876543210fedcba9876543210fedcba9876543210fedcba9876543210"
                        .to_string(),
                    canonical_username: "alice@example.com".to_string(),
                    issued_at: 10,
                    expires_at: 100,
                    last_seen_at: 20,
                    revoked_at: None,
                    remote_addr: "127.0.0.1".to_string(),
                    user_agent: "Firefox/Test".to_string(),
                    factor: RequiredSecondFactor::Totp,
                },
                audit_event: LogEvent::new(
                    LogLevel::Info,
                    EventCategory::Session,
                    "session_validated",
                    "browser session validated",
                ),
            }
        }

        fn next_draft_id(&self) -> String {
            if self.draft_store.is_some() {
                return crate::draft::generate_draft_id().expect("synthetic draft id");
            }
            let next = self.drafts.lock().expect("stub drafts should lock").len() + 1;
            format!("{next:032x}")
        }
    }

    impl BrowserGateway for StubGateway {
        fn retention_status(
            &self,
            _session: &ValidatedSession,
            _mailbox: &str,
        ) -> crate::mailbox::RetentionDecision {
            *self.delete_decision.lock().unwrap()
        }
        fn delete_message(
            &self,
            _context: &AuthenticationContext,
            session: &ValidatedSession,
            request: &crate::mailbox::MessageDeleteRequest,
        ) -> BrowserMessageDeleteOutcome {
            assert_eq!(
                request.canonical_username,
                session.record.canonical_username
            );
            self.delete_calls.lock().unwrap().push(request.clone());
            let result = self
                .delete_results
                .lock()
                .unwrap()
                .pop_front()
                .unwrap_or_else(|| *self.delete_result.lock().unwrap());
            BrowserMessageDeleteOutcome {
                result,
                retry_after_seconds: None,
                audit_events: Vec::new(),
            }
        }
        fn compose_protection(
            &self,
            _session: &ValidatedSession,
            to: &str,
            _cc: &str,
            _bcc: &str,
            intent: crate::send::ProtectionIntent,
        ) -> Option<ComposeProtectionView> {
            if let Some(snapshot) = &self.fixture_openpgp_snapshot {
                let snapshot = snapshot.lock().unwrap();
                if !snapshot.available {
                    return None;
                }
                return Some(ComposeProtectionView {
                    runtime_configured: true,
                    revision: Some(snapshot.revision),
                    preflight: snapshot.preflight_revision.map(|revision| {
                        crate::openpgp_bindings::Preflight {
                            revision,
                            state: if intent.sign && intent.encrypt {
                                crate::openpgp_bindings::PreflightState::Green
                            } else {
                                crate::openpgp_bindings::PreflightState::Orange
                            },
                            signing: crate::openpgp_bindings::KeyStatus::Ready,
                            self_encryption: crate::openpgp_bindings::KeyStatus::Ready,
                            recipients: vec![crate::openpgp_bindings::RecipientReadiness {
                                address: to.into(),
                                state: crate::openpgp_bindings::KeyStatus::Ready,
                                requirement: crate::openpgp_bindings::Requirement::Optional,
                            }],
                            reasons: Vec::new(),
                            plan: Some(crate::openpgp_bindings::OperationPlan {
                                signer_fingerprint: intent.sign.then(|| "A".repeat(40)),
                                recipient_fingerprints: if intent.encrypt {
                                    vec!["B".repeat(40)]
                                } else {
                                    Vec::new()
                                },
                                encrypt_to_self: intent.encrypt_to_self,
                            }),
                        }
                    }),
                    account_binding: None,
                    policy: crate::openpgp_bindings::ProtectionPolicy::default(),
                    recipient_binding_count: 1,
                });
            }
            self.browser_fixture_openpgp
                .then_some(ComposeProtectionView {
                    runtime_configured: false,
                    revision: Some(2),
                    preflight: None,
                    account_binding: None,
                    policy: crate::openpgp_bindings::ProtectionPolicy::default(),
                    recipient_binding_count: 0,
                })
        }
        fn load_bin_preference(
            &self,
            session: &ValidatedSession,
        ) -> Result<crate::bin_folder::BinPreference, crate::bin_folder::Error> {
            match &self.bin_store {
                Some(store) => store.load(&session.record.canonical_username),
                None => Ok(crate::bin_folder::BinPreference::default()),
            }
        }
        fn update_bin_preference(
            &self,
            session: &ValidatedSession,
            revision: u64,
            mailbox_name: &str,
        ) -> Result<crate::bin_folder::BinPreference, crate::bin_folder::Error> {
            self.bin_store
                .as_ref()
                .ok_or(crate::bin_folder::Error::Unavailable)?
                .save(&session.record.canonical_username, revision, mailbox_name)
        }

        fn load_after_archive(
            &self,
            s: &ValidatedSession,
        ) -> Result<crate::after_archive::Preference, crate::after_archive::Error> {
            self.after_archive_store
                .as_ref()
                .ok_or(crate::after_archive::Error::Unavailable)?
                .load(&s.record.canonical_username)
        }
        fn save_after_archive(
            &self,
            s: &ValidatedSession,
            revision: u64,
            choice: crate::after_archive::Choice,
        ) -> Result<crate::after_archive::Preference, crate::after_archive::Error> {
            self.after_archive_store
                .as_ref()
                .ok_or(crate::after_archive::Error::Unavailable)?
                .save(&s.record.canonical_username, revision, choice)
        }
        fn load_mark_read_policy(
            &self,
            session: &ValidatedSession,
        ) -> Result<crate::mark_read::Preference, crate::mark_read::Error> {
            self.mark_read_store
                .as_ref()
                .ok_or(crate::mark_read::Error::Unavailable)?
                .load(&session.record.canonical_username)
        }
        fn save_mark_read_policy(
            &self,
            session: &ValidatedSession,
            revision: u64,
            policy: crate::mark_read::Policy,
        ) -> Result<crate::mark_read::Preference, crate::mark_read::Error> {
            self.mark_read_store
                .as_ref()
                .ok_or(crate::mark_read::Error::Unavailable)?
                .save(&session.record.canonical_username, revision, policy)
        }
        fn load_autosave(
            &self,
            session: &ValidatedSession,
        ) -> Result<crate::autosave::Preference, crate::autosave::Error> {
            self.autosave_store
                .as_ref()
                .ok_or(crate::autosave::Error::Unavailable)?
                .load(&session.record.canonical_username)
        }
        fn save_autosave(
            &self,
            session: &ValidatedSession,
            revision: u64,
            enabled: bool,
            interval: u16,
        ) -> Result<crate::autosave::Preference, crate::autosave::Error> {
            self.autosave_store
                .as_ref()
                .ok_or(crate::autosave::Error::Unavailable)?
                .save(
                    &session.record.canonical_username,
                    revision,
                    enabled,
                    interval,
                )
        }
        fn load_signature(
            &self,
            session: &ValidatedSession,
        ) -> Result<crate::signature::SignatureRecord, crate::signature::SignatureError> {
            self.signature_store
                .as_ref()
                .ok_or(crate::signature::SignatureError::Unavailable)?
                .load(&session.record.canonical_username)
        }
        fn change_signature(
            &self,
            session: &ValidatedSession,
            revision: u64,
            change: crate::signature::SignatureChange<'_>,
        ) -> Result<crate::signature::SignatureRecord, crate::signature::SignatureError> {
            self.signature_store
                .as_ref()
                .ok_or(crate::signature::SignatureError::Unavailable)?
                .change(&session.record.canonical_username, revision, change)
        }

        fn snooze_load(
            &self,
            session: &ValidatedSession,
        ) -> Result<crate::snooze::SnoozeRecord, crate::snooze::SnoozeError> {
            self.snooze_store
                .as_ref()
                .ok_or(crate::snooze::SnoozeError::Unavailable)?
                .load(&session.record.canonical_username, self.snooze_clock())
        }
        fn snooze_change(
            &self,
            session: &ValidatedSession,
            identity: &crate::snooze::MessageIdentity,
            revision: u64,
            until: Option<u64>,
        ) -> Result<crate::snooze::SnoozeRecord, crate::snooze::SnoozeError> {
            let store = self
                .snooze_store
                .as_ref()
                .ok_or(crate::snooze::SnoozeError::Unavailable)?;
            match until {
                Some(until) => store.set(
                    &session.record.canonical_username,
                    identity,
                    revision,
                    until,
                    self.snooze_clock(),
                ),
                None => store.cancel(
                    &session.record.canonical_username,
                    identity,
                    revision,
                    self.snooze_clock(),
                ),
            }
        }
        fn snooze_project(
            &self,
            session: &ValidatedSession,
            owner: &str,
            folder: &str,
            rows: &[MessageSummary],
        ) -> crate::snooze::SnoozeProjection {
            let store = match self.snooze_store.as_ref() {
                Some(store) => store,
                None => {
                    return crate::snooze::SnoozeProjection {
                        hidden: vec![],
                        revision: None,
                        unavailable: Some(crate::snooze::SnoozeError::Unavailable),
                    }
                }
            };
            store.project(
                &session.record.canonical_username,
                owner,
                folder,
                rows,
                self.snooze_clock(),
            )
        }

        fn read_send_recovery(
            &self,
            session: &ValidatedSession,
            intent: &str,
        ) -> BrowserSendRecoveryDecision {
            use crate::send_recovery::{RecoveryRead, SendRecovery};
            match SendRecovery::new(self.recovery_root.clone()).lookup(
                &self.send_journal,
                &session.record.canonical_username,
                intent,
                self.recovery_now.unwrap_or(100),
            ) {
                Ok(RecoveryRead::Available(value)) => {
                    BrowserSendRecoveryDecision::Available(BrowserSendRecoverySnapshot {
                        request: value.request,
                        created_at: value.created_at,
                        expires_at: value.expires_at,
                    })
                }
                Ok(RecoveryRead::Missing) => BrowserSendRecoveryDecision::Missing,
                Ok(RecoveryRead::Expired) => BrowserSendRecoveryDecision::Expired,
                Ok(RecoveryRead::Unconfirmed) => BrowserSendRecoveryDecision::Unconfirmed,
                Err(_) => BrowserSendRecoveryDecision::Unavailable,
            }
        }
        fn send_clock(&self) -> u64 {
            100
        }
        fn send_receipt(
            &self,
            session: &ValidatedSession,
            intent: &str,
        ) -> Result<Option<BrowserSendDecision>, String> {
            self.send_journal
                .receipt(&session.record.canonical_username, intent, 100)
                .map(|value| {
                    value.map(|outcome| {
                        fixture_send_decision(Ok(crate::send_journal::JournalResult {
                            outcome,
                            replayed: true,
                            receipt_persisted: true,
                        }))
                    })
                })
                .map_err(|_| "send_attempt_paused".into())
        }
        fn cleanup_sent_draft(
            &self,
            session: &ValidatedSession,
            id: &str,
            revision: u64,
            intent: &str,
        ) -> Result<bool, String> {
            if self.fail_draft_delete.as_deref() == Some(id) {
                return Err("cleanup_unconfirmed".into());
            }
            let guard = self
                .send_journal
                .account_guard(&session.record.canonical_username, 100)
                .map_err(|_| "paused")?;
            guard
                .require_accepted_with_sent(intent)
                .map_err(|_| "paused")?;
            let mut drafts = self.drafts.lock().map_err(|_| "paused")?;
            if let Some(store) = &self.draft_store {
                let draft = store
                    .load(&session.record.canonical_username, id, 100)
                    .map_err(|_| "paused")?
                    .ok_or("missing")?;
                if draft.revision != Some(revision)
                    || guard.draft_intent(&draft).map_err(|_| "paused")? != intent
                {
                    return Err("paused".into());
                }
                return store
                    .delete(&session.record.canonical_username, id, revision)
                    .map_err(|_| "paused".into());
            }
            let draft = drafts.get(id).ok_or("missing")?;
            if draft.revision != Some(revision)
                || guard.draft_intent(draft).map_err(|_| "paused")? != intent
            {
                return Err("paused".into());
            }
            Ok(drafts.remove(id).is_some())
        }

        fn archive_events_available(&self) -> bool {
            self.archive_event_store.is_some()
        }
        fn archive_event_clock(&self) -> u64 {
            archive_event_route_tests::CONFIRMED_AT
        }
        fn load_archive_events(
            &self,
            session: &ValidatedSession,
        ) -> Result<crate::archive_event::Snapshot, crate::archive_event::Error> {
            self.archive_event_store
                .as_ref()
                .ok_or(crate::archive_event::Error::Unavailable)?
                .load(&session.record.canonical_username)
        }
        fn record_archive_event(
            &self,
            session: &ValidatedSession,
            confirmation: &crate::archive_event::ConfirmedArchive,
            confirmed_at: u64,
        ) -> Result<crate::archive_event::Snapshot, crate::archive_event::Error> {
            self.archive_event_records
                .fetch_add(1, std::sync::atomic::Ordering::SeqCst);
            self.archive_event_store
                .as_ref()
                .ok_or(crate::archive_event::Error::Unavailable)?
                .record_confirmed_archive(
                    &session.record.canonical_username,
                    confirmation,
                    confirmed_at,
                )
        }
        fn labels_available(&self) -> bool {
            self.labels_store.is_some()
        }
        fn load_labels(
            &self,
            s: &ValidatedSession,
        ) -> Result<crate::labels::LabelRecord, crate::labels::LabelError> {
            self.labels_store
                .as_ref()
                .ok_or(crate::labels::LabelError::Unavailable)?
                .load(&s.record.canonical_username)
        }
        fn change_labels(
            &self,
            s: &ValidatedSession,
            r: u64,
            c: crate::labels::LabelChange<'_>,
        ) -> Result<crate::labels::LabelRecord, crate::labels::LabelError> {
            self.labels_store
                .as_ref()
                .ok_or(crate::labels::LabelError::Unavailable)?
                .change(&s.record.canonical_username, r, c)
        }
        fn reconcile_labels(
            &self,
            s: &ValidatedSession,
            r: u64,
            a: &crate::labels::MessageIdentity,
            b: &crate::labels::MessageIdentity,
        ) -> Result<crate::labels::LabelRecord, crate::labels::LabelError> {
            self.labels_store
                .as_ref()
                .ok_or(crate::labels::LabelError::Unavailable)?
                .reconcile_confirmed_move(&s.record.canonical_username, r, a, b)
        }
        fn load_contacts(
            &self,
            session: &ValidatedSession,
        ) -> Result<crate::contacts::ContactBook, crate::contacts::ContactError> {
            self.contacts_store
                .as_ref()
                .map(|store| store.load(&session.record.canonical_username))
                .unwrap_or_else(|| {
                    Ok(crate::contacts::ContactBook::empty(
                        &session.record.canonical_username,
                    ))
                })
        }
        fn change_contact(
            &self,
            session: &ValidatedSession,
            revision: u64,
            change: crate::contacts::ContactChange,
        ) -> Result<crate::contacts::ContactBook, crate::contacts::ContactError> {
            self.contacts_store
                .as_ref()
                .ok_or(crate::contacts::ContactError::Unavailable)?
                .change(&session.record.canonical_username, revision, change)
        }

        fn set_message_flag(
            &self,
            context: &AuthenticationContext,
            session: &ValidatedSession,
            request: &crate::mailbox::MessageFlagRequest,
        ) -> BrowserMessageFlagOutcome {
            self.set_fixture_message_flag(context, session, request)
        }
        fn login(
            &self,
            context: &AuthenticationContext,
            username: &str,
            password: &str,
            totp_code: &str,
        ) -> BrowserLoginOutcome {
            let account_allowed = username == "alice@example.com"
                || self.browser_fixture_accounts && username == "bob@example.com";
            if !account_allowed || password != "correct horse battery staple" {
                return BrowserLoginOutcome {
                    decision: BrowserLoginDecision::Denied {
                        public_reason: "invalid_credentials".to_string(),
                    },
                    audit_events: vec![LogEvent::new(
                        LogLevel::Warn,
                        EventCategory::Auth,
                        "stub_login_denied",
                        "stub login denied",
                    )],
                };
            }

            if totp_code != "123456" {
                return BrowserLoginOutcome {
                    decision: BrowserLoginDecision::Denied {
                        public_reason: "invalid_credentials".to_string(),
                    },
                    audit_events: vec![LogEvent::new(
                        LogLevel::Warn,
                        EventCategory::Auth,
                        "stub_second_factor_denied",
                        "stub second factor denied",
                    )],
                };
            }

            if let Some(sessions) = &self.fixture_sessions {
                let presentation = self
                    .appearance_store
                    .as_ref()
                    .map(|store| {
                        store
                            .load_settings(username)
                            .expect("synthetic preference store")
                    })
                    .unwrap_or_default();
                let mut outcome = sessions.login(context, username, presentation.theme);
                if let BrowserLoginDecision::Authenticated {
                    presentation: saved,
                    reading,
                    ..
                } = &mut outcome.decision
                {
                    *saved = presentation;
                    *reading = self
                        .reading_preferences_store
                        .as_ref()
                        .and_then(|store| store.load(username).ok())
                        .unwrap_or_default();
                }
                return outcome;
            }
            BrowserLoginOutcome {
                decision: BrowserLoginDecision::Authenticated {
                    canonical_username: username.to_string(),
                    reading: self
                        .reading_preferences_store
                        .as_ref()
                        .and_then(|store| store.load(username).ok())
                        .unwrap_or_default(),
                    presentation: self
                        .appearance_store
                        .as_ref()
                        .map(|store| {
                            store
                                .load_settings(username)
                                .expect("synthetic preference store")
                        })
                        .unwrap_or_default(),
                    appearance: self
                        .appearance_store
                        .as_ref()
                        .map(|store| store.load(username).expect("synthetic preference store"))
                        .unwrap_or_default(),
                    session_token: SessionToken::new(if username == "bob@example.com" {
                        "bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb"
                    } else {
                        "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"
                    })
                    .expect("token should be valid"),
                },
                audit_events: vec![LogEvent::new(
                    LogLevel::Info,
                    EventCategory::Auth,
                    "stub_login_ok",
                    "stub login accepted",
                )],
            }
        }

        fn validate_session(
            &self,
            context: &AuthenticationContext,
            presented_token: &str,
        ) -> BrowserSessionValidationOutcome {
            if let Some(sessions) = &self.fixture_sessions {
                return sessions.validate(context, presented_token);
            }
            let bob = self.browser_fixture_accounts
                && presented_token
                    == "bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb";
            if bob
                || presented_token
                    == "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"
            {
                let mut validated_session = Self::validated_session();
                if bob {
                    validated_session.record.canonical_username = "bob@example.com".to_string();
                    validated_session.record.session_id = "b".repeat(64);
                    validated_session.record.csrf_token = "c".repeat(64);
                }
                if context.user_agent.contains("LongIdentity") {
                    validated_session.record.canonical_username =
                        format!("{}@example.test", "long-account-name-".repeat(16));
                }
                BrowserSessionValidationOutcome {
                    decision: BrowserSessionDecision::Valid {
                        validated_session: Box::new(validated_session),
                    },
                    audit_events: vec![LogEvent::new(
                        LogLevel::Info,
                        EventCategory::Session,
                        "stub_session_ok",
                        "stub session accepted",
                    )],
                }
            } else {
                BrowserSessionValidationOutcome {
                    decision: BrowserSessionDecision::Invalid,
                    audit_events: vec![LogEvent::new(
                        LogLevel::Warn,
                        EventCategory::Session,
                        "stub_session_denied",
                        "stub session denied",
                    )],
                }
            }
        }

        fn logout(
            &self,
            context: &AuthenticationContext,
            presented_token: &str,
        ) -> BrowserLogoutOutcome {
            if let Some(sessions) = &self.fixture_sessions {
                return sessions.logout(context, presented_token);
            }
            BrowserLogoutOutcome {
                session_was_revoked: true,
                audit_events: vec![LogEvent::new(
                    LogLevel::Info,
                    EventCategory::Session,
                    "stub_logout",
                    "stub logout completed",
                )],
            }
        }

        fn list_sessions(
            &self,
            context: &AuthenticationContext,
            validated_session: &ValidatedSession,
        ) -> BrowserSessionListOutcome {
            if let Some(sessions) = &self.fixture_sessions {
                return sessions.list(context, validated_session);
            }
            BrowserSessionListOutcome {
                decision: BrowserSessionListDecision::Listed {
                    canonical_username: validated_session.record.canonical_username.clone(),
                    session_lifetime_seconds: 3600,
                    session_idle_timeout_seconds: 1800,
                    sessions: vec![
                        BrowserVisibleSession {
                            session_id: validated_session.record.session_id.clone(),
                            issued_at: validated_session.record.issued_at,
                            expires_at: validated_session.record.expires_at,
                            last_seen_at: validated_session.record.last_seen_at,
                            revoked_at: None,
                            device_label: "Firefox".to_string(),
                            remote_addr: validated_session.record.remote_addr.clone(),
                            user_agent: validated_session.record.user_agent.clone(),
                            factor: validated_session.record.factor,
                        },
                        BrowserVisibleSession {
                            session_id:
                                "bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb"
                                    .to_string(),
                            issued_at: 5,
                            expires_at: 95,
                            last_seen_at: 15,
                            revoked_at: None,
                            device_label: "Firefox".to_string(),
                            remote_addr: "203.0.113.9".to_string(),
                            user_agent: "Firefox/Secondary".to_string(),
                            factor: RequiredSecondFactor::Totp,
                        },
                    ],
                },
                audit_events: vec![LogEvent::new(
                    LogLevel::Info,
                    EventCategory::Session,
                    "stub_session_list",
                    "stub session list returned",
                )],
            }
        }

        fn revoke_session(
            &self,
            context: &AuthenticationContext,
            validated_session: &ValidatedSession,
            session_id: &str,
        ) -> BrowserSessionRevokeOutcome {
            if let Some(sessions) = &self.fixture_sessions {
                return sessions.revoke(context, validated_session, session_id);
            }
            if session_id == validated_session.record.session_id {
                BrowserSessionRevokeOutcome {
                    decision: BrowserSessionRevokeDecision::Revoked {
                        newly_revoked: true,
                        revoked_session_id: session_id.to_string(),
                        revoked_current_session: true,
                    },
                    audit_events: vec![LogEvent::new(
                        LogLevel::Info,
                        EventCategory::Session,
                        "stub_session_revoke_current",
                        "stub current session revoked",
                    )],
                }
            } else if session_id
                == "bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb"
            {
                BrowserSessionRevokeOutcome {
                    decision: BrowserSessionRevokeDecision::Revoked {
                        newly_revoked: true,
                        revoked_session_id: session_id.to_string(),
                        revoked_current_session: false,
                    },
                    audit_events: vec![LogEvent::new(
                        LogLevel::Info,
                        EventCategory::Session,
                        "stub_session_revoke_other",
                        "stub non-current session revoked",
                    )],
                }
            } else {
                BrowserSessionRevokeOutcome {
                    decision: BrowserSessionRevokeDecision::Denied {
                        public_reason: "not_found".to_string(),
                    },
                    audit_events: vec![LogEvent::new(
                        LogLevel::Warn,
                        EventCategory::Session,
                        "stub_session_revoke_denied",
                        "stub session revoke denied",
                    )],
                }
            }
        }

        fn revoke_sessions(
            &self,
            context: &AuthenticationContext,
            validated_session: &ValidatedSession,
            scope: BrowserSessionRevokeScope,
        ) -> BrowserSessionRevokeOutcome {
            if let Some(sessions) = &self.fixture_sessions {
                return sessions.revoke_many(context, validated_session, scope);
            }
            match scope {
                BrowserSessionRevokeScope::OtherSessions => BrowserSessionRevokeOutcome {
                    decision: BrowserSessionRevokeDecision::RevokedMany {
                        revoked_count: 1,
                        revoked_current_session: false,
                    },
                    audit_events: vec![LogEvent::new(
                        LogLevel::Info,
                        EventCategory::Session,
                        "stub_session_revoke_others",
                        "stub other sessions revoked",
                    )],
                },
                BrowserSessionRevokeScope::AllSessions => BrowserSessionRevokeOutcome {
                    decision: BrowserSessionRevokeDecision::RevokedMany {
                        revoked_count: 2,
                        revoked_current_session: true,
                    },
                    audit_events: vec![LogEvent::new(
                        LogLevel::Info,
                        EventCategory::Session,
                        "stub_session_revoke_all",
                        "stub all sessions revoked",
                    )],
                },
            }
        }

        fn load_appearance(
            &self,
            context: &AuthenticationContext,
            session: &ValidatedSession,
        ) -> std::io::Result<AppearancePreference> {
            if let Some(store) = &self.appearance_store {
                return store.load(&session.record.canonical_username);
            }
            if context.user_agent.contains("AppearanceUnavailable") {
                return Err(std::io::Error::other("synthetic store unavailable"));
            }
            Ok(if context.user_agent.contains("AppearanceDark") {
                AppearancePreference::Dark
            } else if context.user_agent.contains("AppearanceLight") {
                AppearancePreference::Light
            } else {
                AppearancePreference::System
            })
        }

        fn update_appearance(
            &self,
            context: &AuthenticationContext,
            session: &ValidatedSession,
            appearance: AppearancePreference,
        ) -> std::io::Result<()> {
            if let Some(store) = &self.appearance_store {
                return store.save(&session.record.canonical_username, appearance);
            }
            if context.user_agent.contains("AppearanceUnavailable") {
                Err(std::io::Error::other("synthetic store unavailable"))
            } else {
                Ok(())
            }
        }

        fn load_display(
            &self,
            context: &AuthenticationContext,
            session: &ValidatedSession,
        ) -> std::io::Result<AppearanceSettings> {
            if let Some(store) = &self.appearance_store {
                return store.load_settings(&session.record.canonical_username);
            }
            self.load_appearance(context, session)
                .map(|theme| AppearanceSettings {
                    theme,
                    ..AppearanceSettings::default()
                })
        }

        fn update_display(
            &self,
            context: &AuthenticationContext,
            session: &ValidatedSession,
            preferences: AppearanceSettings,
        ) -> std::io::Result<()> {
            if let Some(store) = &self.appearance_store {
                return store.save_settings(&session.record.canonical_username, preferences);
            }
            self.update_appearance(context, session, preferences.theme)
        }

        fn load_reading_preferences(
            &self,
            context: &AuthenticationContext,
            session: &ValidatedSession,
        ) -> std::io::Result<crate::reading_preferences::ReadingPreferences> {
            if context.user_agent.contains("ReadingUnavailable") {
                return Err(std::io::Error::other(
                    "synthetic reading preference load failure",
                ));
            }
            self.reading_preferences_store.as_ref().map_or_else(
                || Ok(crate::reading_preferences::ReadingPreferences::default()),
                |store| store.load(&session.record.canonical_username),
            )
        }

        fn update_reading_start_page(
            &self,
            _context: &AuthenticationContext,
            session: &ValidatedSession,
            start_page: crate::reading_preferences::StartPage,
        ) -> std::io::Result<crate::reading_preferences::ReadingPreferences> {
            self.reading_preferences_store
                .as_ref()
                .ok_or_else(|| std::io::Error::other("reading preferences unavailable"))?
                .save_start_page(&session.record.canonical_username, start_page)
        }

        fn update_reading_preferences(
            &self,
            _context: &AuthenticationContext,
            session: &ValidatedSession,
            value: crate::reading_preferences::ReadingPreferences,
        ) -> std::io::Result<()> {
            self.reading_preferences_store
                .as_ref()
                .ok_or_else(|| {
                    std::io::Error::other("synthetic reading preference store unavailable")
                })?
                .save(&session.record.canonical_username, value)
        }

        fn record_session_notification(
            &self,
            account: &str,
            kind: crate::notifications::NotificationKind,
        ) -> Result<(), crate::notifications::NotificationError> {
            self.notification_store.as_ref().map_or(Ok(()), |store| {
                store.record(
                    account,
                    kind,
                    crate::totp::TimeProvider::unix_timestamp(&crate::totp::SystemTimeProvider),
                )
            })
        }
        fn notification_inbox(
            &self,
            session: &ValidatedSession,
        ) -> Result<crate::notifications::NotificationInbox, crate::notifications::NotificationError>
        {
            self.notification_loads
                .fetch_add(1, std::sync::atomic::Ordering::SeqCst);
            self.notification_store
                .as_ref()
                .ok_or(crate::notifications::NotificationError::Unavailable)?
                .load(
                    &session.record.canonical_username,
                    crate::totp::TimeProvider::unix_timestamp(&crate::totp::SystemTimeProvider),
                )
        }
        fn set_notification_read(
            &self,
            session: &ValidatedSession,
            id: &str,
            revision: u64,
            read: bool,
        ) -> Result<crate::notifications::NotificationInbox, crate::notifications::NotificationError>
        {
            self.notification_store
                .as_ref()
                .ok_or(crate::notifications::NotificationError::Unavailable)?
                .set_read(
                    &session.record.canonical_username,
                    id,
                    revision,
                    read,
                    crate::totp::TimeProvider::unix_timestamp(&crate::totp::SystemTimeProvider),
                )
        }
        fn load_identity_preferences(
            &self,
            _context: &AuthenticationContext,
            session: &ValidatedSession,
        ) -> Result<
            crate::identity_preferences::IdentityPreferencesRecord,
            crate::identity_preferences::IdentityPreferencesError,
        > {
            self.identity_preferences_store
                .as_ref()
                .ok_or(crate::identity_preferences::IdentityPreferencesError::Unavailable)?
                .load(&session.record.canonical_username)
        }
        fn update_identity_preferences(
            &self,
            _context: &AuthenticationContext,
            session: &ValidatedSession,
            expected_revision: u64,
            value: &crate::identity_preferences::IdentityPreferences,
        ) -> Result<
            crate::identity_preferences::IdentityPreferencesRecord,
            crate::identity_preferences::IdentityPreferencesError,
        > {
            self.identity_preferences_store
                .as_ref()
                .ok_or(crate::identity_preferences::IdentityPreferencesError::Unavailable)?
                .save(&session.record.canonical_username, expected_revision, value)
        }

        fn load_composition_preferences(
            &self,
            context: &AuthenticationContext,
            session: &ValidatedSession,
        ) -> std::io::Result<crate::composition_preferences::CompositionPreferences> {
            if context.user_agent.contains("CompositionUnavailable") {
                return Err(std::io::Error::other("synthetic preference load failure"));
            }
            self.composition_preferences_store.as_ref().map_or_else(
                || Ok(crate::composition_preferences::CompositionPreferences::default()),
                |store| store.load(&session.record.canonical_username),
            )
        }

        fn update_composition_format(
            &self,
            _context: &AuthenticationContext,
            session: &ValidatedSession,
            value: crate::compose_format::BodyFormat,
        ) -> std::io::Result<()> {
            self.composition_preferences_store
                .as_ref()
                .ok_or_else(|| std::io::Error::other("synthetic preference store unavailable"))?
                .save_format(&session.record.canonical_username, value)
        }

        fn update_composition_preferences(
            &self,
            _context: &AuthenticationContext,
            session: &ValidatedSession,
            value: crate::composition_preferences::CompositionPreferencesUpdate,
        ) -> std::io::Result<()> {
            self.composition_preferences_store
                .as_ref()
                .ok_or_else(|| std::io::Error::other("synthetic preference store unavailable"))?
                .update(&session.record.canonical_username, value)
        }

        fn load_settings(
            &self,
            context: &AuthenticationContext,
            validated_session: &ValidatedSession,
        ) -> BrowserSettingsOutcome {
            if matches!(
                context.user_agent.as_str(),
                "SettingsWrongOwner" | "ReaderSettingsWrongOwner"
            ) {
                return BrowserSettingsOutcome {
                    decision: BrowserSettingsDecision::Loaded {
                        canonical_username: "foreign-settings-owner@example.test".into(),
                        settings: BrowserVisibleSettings {
                            html_display_preference: HtmlDisplayPreference::PreferSanitizedHtml,
                            archive_mailbox_name: Some(
                                if context.user_agent == "ReaderSettingsWrongOwner" {
                                    "INBOX"
                                } else {
                                    "foreign-private-archive"
                                }
                                .into(),
                            ),
                        },
                    },
                    audit_events: Vec::new(),
                };
            }
            if let Some(store) = &self.settings_store {
                return BrowserSettingsOutcome {
                    decision: match crate::settings::UserSettingsStore::load(
                        store,
                        &validated_session.record.canonical_username,
                    ) {
                        Ok(settings) => {
                            let settings = settings.unwrap_or_default();
                            BrowserSettingsDecision::Loaded {
                                canonical_username: validated_session
                                    .record
                                    .canonical_username
                                    .clone(),
                                settings: BrowserVisibleSettings {
                                    html_display_preference: settings.html_display_preference,
                                    archive_mailbox_name: settings.archive_mailbox_name,
                                },
                            }
                        }
                        Err(_) => BrowserSettingsDecision::Denied {
                            public_reason: "temporarily_unavailable".into(),
                        },
                    },
                    audit_events: vec![],
                };
            }
            if context.user_agent.contains("SettingsUnavailable") {
                return BrowserSettingsOutcome {
                    decision: BrowserSettingsDecision::Denied {
                        public_reason: "temporarily_unavailable".into(),
                    },
                    audit_events: Vec::new(),
                };
            }
            BrowserSettingsOutcome {
                decision: BrowserSettingsDecision::Loaded {
                    canonical_username: validated_session.record.canonical_username.clone(),
                    settings: BrowserVisibleSettings {
                        html_display_preference: HtmlDisplayPreference::PreferSanitizedHtml,
                        archive_mailbox_name: if context.user_agent.contains("NoArchiveTest") {
                            None
                        } else {
                            Some(
                                if context.user_agent.contains("InvalidArchiveTest") {
                                    "MissingArchive"
                                } else {
                                    "Archive/2026"
                                }
                                .to_string(),
                            )
                        },
                    },
                },
                audit_events: vec![LogEvent::new(
                    LogLevel::Info,
                    EventCategory::Session,
                    "stub_settings_load",
                    "stub settings loaded",
                )],
            }
        }

        fn update_content_setting(
            &self,
            _context: &AuthenticationContext,
            session: &ValidatedSession,
            content: HtmlDisplayPreference,
        ) -> BrowserSettingsUpdateOutcome {
            let Some(store) = &self.settings_store else {
                return BrowserSettingsUpdateOutcome {
                    decision: BrowserSettingsUpdateDecision::Denied {
                        public_reason: "temporarily_unavailable".into(),
                    },
                    audit_events: vec![],
                };
            };
            let result = store.save_content(&session.record.canonical_username, content);
            BrowserSettingsUpdateOutcome {
                decision: if result.is_ok() {
                    BrowserSettingsUpdateDecision::Updated
                } else {
                    BrowserSettingsUpdateDecision::Denied {
                        public_reason: "temporarily_unavailable".into(),
                    }
                },
                audit_events: vec![],
            }
        }

        fn update_archive_setting(
            &self,
            context: &AuthenticationContext,
            session: &ValidatedSession,
            archive: Option<&str>,
        ) -> BrowserSettingsUpdateOutcome {
            if self.settings_store.is_none() {
                return BrowserSettingsUpdateOutcome {
                    decision: BrowserSettingsUpdateDecision::Denied {
                        public_reason: "temporarily_unavailable".into(),
                    },
                    audit_events: vec![],
                };
            }
            let result = self
                .settings_store
                .as_ref()
                .expect("store checked above")
                .save_archive(&session.record.canonical_username, archive);
            BrowserSettingsUpdateOutcome {
                decision: if result.is_ok() {
                    BrowserSettingsUpdateDecision::Updated
                } else {
                    BrowserSettingsUpdateDecision::Denied {
                        public_reason: "temporarily_unavailable".into(),
                    }
                },
                audit_events: vec![LogEvent::new(
                    if result.is_ok() {
                        LogLevel::Info
                    } else {
                        LogLevel::Warn
                    },
                    EventCategory::Session,
                    "archive_settings_update",
                    "archive preference update processed",
                )
                .with_field("request_id", context.request_id.clone())],
            }
        }

        fn update_settings(
            &self,
            _context: &AuthenticationContext,
            validated_session: &ValidatedSession,
            html_display_preference: HtmlDisplayPreference,
            archive_mailbox_name: Option<&str>,
        ) -> BrowserSettingsUpdateOutcome {
            if let Some(store) = &self.settings_store {
                let settings = crate::settings::UserSettings {
                    html_display_preference,
                    archive_mailbox_name: archive_mailbox_name.map(str::to_owned),
                };
                return BrowserSettingsUpdateOutcome {
                    decision: match crate::settings::UserSettingsStore::save(
                        store,
                        &validated_session.record.canonical_username,
                        &settings,
                    ) {
                        Ok(()) => BrowserSettingsUpdateDecision::Updated,
                        Err(_) => BrowserSettingsUpdateDecision::Denied {
                            public_reason: "temporarily_unavailable".into(),
                        },
                    },
                    audit_events: vec![],
                };
            }
            match (html_display_preference, archive_mailbox_name) {
                (
                    HtmlDisplayPreference::PreferSanitizedHtml
                    | HtmlDisplayPreference::PreferPlainText,
                    None | Some("Archive/2026"),
                ) => BrowserSettingsUpdateOutcome {
                    decision: BrowserSettingsUpdateDecision::Updated,
                    audit_events: vec![LogEvent::new(
                        LogLevel::Info,
                        EventCategory::Session,
                        "stub_settings_update",
                        "stub settings updated",
                    )],
                },
                _ => BrowserSettingsUpdateOutcome {
                    decision: BrowserSettingsUpdateDecision::Denied {
                        public_reason: "invalid_request".to_string(),
                    },
                    audit_events: vec![LogEvent::new(
                        LogLevel::Warn,
                        EventCategory::Session,
                        "stub_settings_update_denied",
                        "stub settings update denied",
                    )],
                },
            }
        }

        fn create_folder(
            &self,
            context: &AuthenticationContext,
            session: &ValidatedSession,
            request: &crate::folder_create::CreateFolderRequest,
        ) -> BrowserFolderCreateOutcome {
            use crate::folder_create::{Outcome, Refusal};
            let metadata = self.folder_metadata(context, session);
            let status = self.mailbox_status(context, session, request.parent());
            let outcome = if request.account() != session.record.canonical_username {
                Outcome::Refused(Refusal::Invalid)
            } else if let (Some(snapshot), Some(status)) = (metadata.snapshot, status.status) {
                if let Err(e) = request.validate_parent(&snapshot, &status) {
                    Outcome::Refused(e)
                } else if snapshot.folder(request.account(), &request.child()).is_ok() {
                    Outcome::Conflict
                } else if context.user_agent.contains("CreateUnknown") {
                    Outcome::Unknown
                } else {
                    self.created_folders
                        .lock()
                        .unwrap()
                        .entry(request.account().into())
                        .or_default()
                        .push(request.child());
                    Outcome::Created {
                        guid: self
                            .created_folder_guid(request.account(), &request.child())
                            .unwrap(),
                    }
                }
            } else {
                Outcome::Refused(Refusal::Unavailable)
            };
            BrowserFolderCreateOutcome {
                outcome,
                audit_events: vec![],
            }
        }
        fn key_management(
            &self,
            context: &AuthenticationContext,
            session: &ValidatedSession,
        ) -> crate::key_management::StateOutcome {
            let inventory = key_inventory_fixture::outcome(
                &context.user_agent,
                &session.record.canonical_username,
            );
            let interactive = context.user_agent == "KeyInventoryInteractive";
            crate::key_management::StateOutcome {
                state: crate::key_management::State {
                    canonical_username: inventory.canonical_username,
                    inventory: inventory.inventory,
                    bindings: interactive.then(|| {
                        crate::openpgp_bindings::BindingRecord::empty(
                            &session.record.canonical_username,
                        )
                        .unwrap()
                    }),
                    binding_changes_available: interactive,
                    public_key_changes_available: interactive,
                    public_inventory_revision: interactive.then(|| "a".repeat(64)),
                },
                audit_events: vec![],
            }
        }
        fn public_key_inventory(
            &self,
            context: &AuthenticationContext,
            session: &ValidatedSession,
        ) -> BrowserPublicInventoryOutcome {
            key_inventory_fixture::outcome(&context.user_agent, &session.record.canonical_username)
        }
        fn folder_metadata(
            &self,
            context: &AuthenticationContext,
            session: &ValidatedSession,
        ) -> BrowserFolderMetadataOutcome {
            let account = if context.user_agent == "FolderTreeWrongOwner" {
                "bob@example.com"
            } else {
                &session.record.canonical_username
            };
            let bytes=b"* PREAUTH fixture\r\n* NAMESPACE ((\"\" \".\")) ((\"Shared/\" \"/\")) ((\"Public/\" \"/\"))\r\nN1 OK done\r\n* LIST (\\HasChildren) \".\" \"INBOX\"\r\n* LIST (\\HasNoChildren) \".\" \"INBOX.Projects\"\r\n* LIST (\\Drafts) \".\" \"Drafts\"\r\n* LIST (\\Junk) \".\" \"Junk\"\r\n* LIST (\\Trash) \".\" \"Trash\"\r\n* LIST (\\Sent) \".\" \"Sent\"\r\n* LIST (\\Noselect) \"/\" \"Shared/Team\"\r\n* LIST () \"/\" \"Shared/Team/Review\"\r\n* LIST (\\NonExistent) \"/\" \"Public/Old\"\r\n* LIST () \"/\" \"Public/Old/News\"\r\nL1 OK done\r\n* BYE done\r\nZ1 OK done\r\n";
            BrowserFolderMetadataOutcome {
                canonical_username: account.into(),
                snapshot: if context.user_agent == "FolderTreeMalformed" {
                    None
                } else {
                    {
                        let mut text = String::from_utf8(bytes.to_vec()).unwrap();
                        let extra = self
                            .created_folders
                            .lock()
                            .unwrap()
                            .get(account)
                            .cloned()
                            .unwrap_or_default()
                            .iter()
                            .map(|name| {
                                let flags = match context.user_agent.as_str() {
                                    "FolderTreeBinNoselect" if name == "Deleted" => "\\Noselect",
                                    "FolderTreeBinAbsent" if name == "Deleted" => "\\NonExistent",
                                    _ => "",
                                };
                                format!(
                                    "* LIST ({flags}) \".\" {}\r\n",
                                    folder_create_fixture::wire_name(name)
                                )
                            })
                            .collect::<String>();
                        text = text.replace("L1 OK done", &(extra + "L1 OK done"));
                        crate::folder_metadata::FolderSnapshot::parse(account, text.as_bytes()).ok()
                    }
                },
                audit_events: vec![],
            }
        }
        fn mailbox_status(
            &self,
            context: &AuthenticationContext,
            session: &ValidatedSession,
            folder: &str,
        ) -> BrowserMailboxStatusOutcome {
            let created_guid = self.created_folder_guid(&session.record.canonical_username, folder);
            let native = crate::auth::CommandExecution {
                status_code: 0,
                stdout: format!(
                    "[{{\"mailbox\":{},\"guid\":{},\"messages\":\"{}\",\"vsize\":\"{}\"}}]",
                    serde_json::to_string(folder).unwrap(),
                    serde_json::to_string(
                        created_guid
                            .as_deref()
                            .unwrap_or("1234567890abcdef1234567890abcdef")
                    )
                    .unwrap(),
                    if created_guid.is_some() { 0 } else { 42 },
                    if created_guid.is_some() { 0 } else { 8192 }
                ),
                stderr: String::new(),
            };
            BrowserMailboxStatusOutcome {
                canonical_username: if context.user_agent.contains("StatusWrongOwner") {
                    "other@example.test".into()
                } else {
                    session.record.canonical_username.clone()
                },
                status: if context.user_agent.contains("StatusUnavailable") {
                    None
                } else {
                    crate::mailbox_status::parse_native(folder, &native).ok()
                },
                audit_events: vec![LogEvent::new(
                    LogLevel::Info,
                    EventCategory::Mailbox,
                    "status_fixture",
                    "one status lookup",
                )],
            }
        }
        fn list_mailboxes(
            &self,
            context: &AuthenticationContext,
            validated_session: &ValidatedSession,
        ) -> BrowserMailboxOutcome {
            if context.user_agent == "CopiesWrongOwner" {
                return BrowserMailboxOutcome {
                    decision: BrowserMailboxDecision::Listed {
                        canonical_username: "bob@example.com".into(),
                        mailboxes: vec![MailboxEntry {
                            name: "Archive/2026".into(),
                        }],
                    },
                    audit_events: vec![],
                };
            }
            if matches!(
                context.user_agent.as_str(),
                "WelcomeWrongAccount" | "ReaderMailboxWrongOwner"
            ) {
                return BrowserMailboxOutcome {
                    decision: BrowserMailboxDecision::Listed {
                        canonical_username: "foreign@example.test".into(),
                        mailboxes: vec![MailboxEntry {
                            name: if context.user_agent == "ReaderMailboxWrongOwner" {
                                "Archive/2026"
                            } else {
                                "INBOX"
                            }
                            .into(),
                        }],
                    },
                    audit_events: vec![],
                };
            }
            if context.user_agent.starts_with("FolderCreate") {
                let mut names = vec!["INBOX".to_owned(), "INBOX.Projects".to_owned()];
                names.extend(
                    self.created_folders
                        .lock()
                        .unwrap()
                        .get(&validated_session.record.canonical_username)
                        .cloned()
                        .unwrap_or_default(),
                );
                return BrowserMailboxOutcome {
                    decision: BrowserMailboxDecision::Listed {
                        canonical_username: validated_session.record.canonical_username.clone(),
                        mailboxes: names
                            .into_iter()
                            .map(|name| MailboxEntry { name })
                            .collect(),
                    },
                    audit_events: vec![],
                };
            }
            if context.user_agent.starts_with("FolderTree") || self.preview_mailbox_tree {
                return BrowserMailboxOutcome {
                    decision: BrowserMailboxDecision::Listed {
                        canonical_username: validated_session.record.canonical_username.clone(),
                        mailboxes: [
                            "INBOX",
                            "INBOX.Projects",
                            "Drafts",
                            "Junk",
                            "Trash",
                            "Sent",
                            "Shared/Team/Review",
                            "Public/Old/News",
                        ]
                        .iter()
                        .map(|n| MailboxEntry { name: (*n).into() })
                        .chain(
                            self.created_folders
                                .lock()
                                .unwrap()
                                .get(&validated_session.record.canonical_username)
                                .cloned()
                                .unwrap_or_default()
                                .into_iter()
                                .map(|name| MailboxEntry { name }),
                        )
                        .collect(),
                    },
                    audit_events: vec![],
                };
            }
            if context.user_agent == "WelcomeMissing" {
                return BrowserMailboxOutcome {
                    decision: BrowserMailboxDecision::Listed {
                        canonical_username: validated_session.record.canonical_username.clone(),
                        mailboxes: vec![MailboxEntry {
                            name: format!(
                                "INBOX.{}<img src=x> & synthetic",
                                "long-folder-".repeat(16)
                            ),
                        }],
                    },
                    audit_events: vec![],
                };
            }
            if context.user_agent == "Firefox/ManyMailboxes" {
                let mut mailboxes = vec![MailboxEntry {
                    name: "INBOX".to_string(),
                }];
                mailboxes.extend((0..=crate::mailbox::DEFAULT_MAX_MAILBOXES).map(|index| {
                    MailboxEntry {
                        name: format!("INBOX.overflow-{index}"),
                    }
                }));

                return BrowserMailboxOutcome {
                    decision: BrowserMailboxDecision::Listed {
                        canonical_username: validated_session.record.canonical_username.clone(),
                        mailboxes,
                    },
                    audit_events: vec![LogEvent::new(
                        LogLevel::Info,
                        EventCategory::Mailbox,
                        "stub_many_mailboxes",
                        "stub many mailboxes returned",
                    )],
                };
            }

            BrowserMailboxOutcome {
                decision: BrowserMailboxDecision::Listed {
                    canonical_username: validated_session.record.canonical_username.clone(),
                    mailboxes: vec![
                        MailboxEntry {
                            name: "dovecot".to_string(),
                        },
                        MailboxEntry {
                            name: "dovecot.sieve".to_string(),
                        },
                        MailboxEntry {
                            name: "INBOX".to_string(),
                        },
                        MailboxEntry {
                            name: "INBOX.Projects".to_string(),
                        },
                        MailboxEntry {
                            name: "Drafts".to_string(),
                        },
                        MailboxEntry {
                            name: "Archive/2026".to_string(),
                        },
                        MailboxEntry {
                            name: "Junk".to_string(),
                        },
                        MailboxEntry {
                            name: "Trash".to_string(),
                        },
                    ]
                    .into_iter()
                    .chain(
                        context
                            .user_agent
                            .starts_with("Welcome")
                            .then(|| MailboxEntry {
                                name: "Sent".into(),
                            }),
                    )
                    .collect(),
                },
                audit_events: vec![LogEvent::new(
                    LogLevel::Info,
                    EventCategory::Mailbox,
                    "stub_mailboxes",
                    "stub mailboxes returned",
                )],
            }
        }

        fn list_messages(
            &self,
            context: &AuthenticationContext,
            validated_session: &ValidatedSession,
            mailbox_name: &str,
        ) -> BrowserMessageListOutcome {
            if self.archive_event_store.is_some() && mailbox_name == "INBOX.Projects" {
                let mut rows = self.fixture_reconcile_messages(
                    &validated_session.record.canonical_username,
                    mailbox_name,
                    Vec::new(),
                );
                let mut returned_account = validated_session.record.canonical_username.clone();
                match *self.archive_event_post_list_fault.lock().unwrap() {
                    Some(archive_event_route_tests::PostListFault::Missing) => rows.clear(),
                    Some(archive_event_route_tests::PostListFault::Foreign) => {
                        returned_account = "bob@example.com".into()
                    }
                    Some(archive_event_route_tests::PostListFault::Duplicate) => {
                        if let Some(row) = rows.first().cloned() {
                            rows.push(row);
                        }
                    }
                    Some(archive_event_route_tests::PostListFault::WrongGeneration) => {
                        if let Some(mut row) = rows.first().cloned() {
                            row.uid += 1;
                            let version = &mut row.metadata.as_mut().unwrap().version;
                            version.mailbox_guid = "c".repeat(32);
                            version.message_guid = "different-native-guid".into();
                            rows.push(row);
                        }
                    }
                    None => {}
                }
                return BrowserMessageListOutcome {
                    decision: BrowserMessageListDecision::Listed {
                        canonical_username: returned_account,
                        mailbox_name: mailbox_name.into(),
                        messages: rows,
                    },
                    audit_events: vec![],
                };
            }
            if let Some(decision) = self.delete_list_decision.lock().unwrap().clone() {
                return BrowserMessageListOutcome {
                    decision,
                    audit_events: Vec::new(),
                };
            }
            if let Some(outcome) =
                ux_browser_server::back_focus_list(validated_session, mailbox_name)
            {
                return outcome;
            }
            if mailbox_name == "INBOX"
                && validated_session.record.canonical_username == "alice@example.com"
            {
                if let Some(messages) = &self.message_list_override {
                    return BrowserMessageListOutcome {
                        decision: BrowserMessageListDecision::Listed {
                            canonical_username: validated_session.record.canonical_username.clone(),
                            mailbox_name: mailbox_name.into(),
                            messages: messages.clone(),
                        },
                        audit_events: vec![],
                    };
                }
            }
            if self
                .created_folder_guid(&validated_session.record.canonical_username, mailbox_name)
                .is_some()
            {
                return BrowserMessageListOutcome {
                    decision: BrowserMessageListDecision::Listed {
                        canonical_username: validated_session.record.canonical_username.clone(),
                        mailbox_name: mailbox_name.into(),
                        messages: self.fixture_reconcile_messages(
                            &validated_session.record.canonical_username,
                            mailbox_name,
                            Vec::new(),
                        ),
                    },
                    audit_events: vec![],
                };
            }
            if (mailbox_name == "INBOX" && context.user_agent.starts_with("WelcomeData/"))
                || (mailbox_name == "Sent" && context.user_agent.starts_with("WelcomeSent/"))
            {
                let marker = context.user_agent.split_once('/').unwrap().1;
                let mut rows: Vec<_> = (1..=8)
                    .map(|uid| MessageSummary {
                        to: None,
                        metadata: None,
                        mailbox_name: mailbox_name.into(),
                        uid,
                        flags: if uid % 2 == 0 {
                            vec!["\\Seen".into(), "\\Flagged".into()]
                        } else {
                            vec![]
                        },
                        date_received: format!("2026-09-{:02} 00:00:00 +0000", uid),
                        size_virtual: 1,
                        subject: Some(format!("Actual {uid} <inert>")),
                        from: Some("Sender & <sender@example.test>".into()),
                    })
                    .collect();
                if marker == "wrong-row" {
                    rows[0].mailbox_name = "Foreign".into();
                }
                if marker == "zero" {
                    rows[0].uid = 0;
                }
                if marker == "duplicate" {
                    rows[0].uid = rows[1].uid;
                }
                if marker == "empty" {
                    rows.clear();
                }
                return BrowserMessageListOutcome {
                    decision: if marker == "failure" {
                        BrowserMessageListDecision::Denied {
                            public_reason: "unavailable".into(),
                        }
                    } else {
                        BrowserMessageListDecision::Listed {
                            canonical_username: if marker == "wrong-owner" {
                                "foreign@example.test".into()
                            } else {
                                validated_session.record.canonical_username.clone()
                            },
                            mailbox_name: if marker == "wrong-mailbox" {
                                "Foreign".into()
                            } else {
                                mailbox_name.into()
                            },
                            messages: rows,
                        }
                    },
                    audit_events: vec![LogEvent::new(
                        LogLevel::Info,
                        EventCategory::Mailbox,
                        "welcome_fixture_summary_list",
                        "one summary lookup",
                    )],
                };
            }
            BrowserMessageListOutcome {
                decision: BrowserMessageListDecision::Listed {
                    canonical_username: validated_session.record.canonical_username.clone(),
                    mailbox_name: mailbox_name.to_string(),
                    messages: self.fixture_reconcile_messages(
                        &validated_session.record.canonical_username,
                        mailbox_name,
                        if context.user_agent.starts_with("OSMAP/EmptyMailbox") {
                            Vec::new()
                        } else if context.user_agent.starts_with("OSMAP/ManyMessages") {
                            (1..=125)
                                .map(|uid| MessageSummary {
                                    to: if context.user_agent.contains("SentRecipients") { match uid % 4 { 0 => None, 1 => Some("<img src=x> & recipient@example.test".into()), 2 => Some("Élodie <elodie@example.test>, Bob <bob@example.test>".into()), _ => Some(format!("Recipient {uid:03} <recipient{uid}@example.test>")) } } else { None },
                                    metadata: Self::fixture_attachment_metadata(
                                        context,
                                        &validated_session.record.canonical_username,
                                        mailbox_name,
                                        uid,
                                    ),
                                    mailbox_name: mailbox_name.to_string(),
                                    uid,
                                    flags: self.fixture_message_flags(
                                        &validated_session.record.canonical_username,
                                        mailbox_name,
                                        uid,
                                    ),
                                    date_received: "2026-09-30 00:00:00 +0000".to_string(),
                                    size_virtual: 1024,
                                    subject: Some(
                                        if context.user_agent.contains("LongHeaders") && uid == 125
                                        {
                                            format!("<b>Synthetic header</b> {}", "W".repeat(256))
                                        } else {
                                            format!("Message {uid:03}")
                                        },
                                    ),
                                    from: Some(
                                        if context.user_agent.contains("LongHeaders") && uid == 125
                                        {
                                            format!(
                                                "Synthetic long sender {} <sender@example.test>",
                                                "Y".repeat(256)
                                            )
                                        } else {
                                            "Synthetic Sender <sender@example.test>".to_string()
                                        },
                                    ),
                                })
                                .collect()
                        } else {
                            vec![
                                MessageSummary {
                                    to: None,
                                    metadata: (!context.user_agent.contains("LegacyMetadata"))
                                        .then(|| {
                                            Self::fixture_metadata(
                                                &validated_session.record.canonical_username,
                                                mailbox_name,
                                                9,
                                            )
                                        }),
                                    mailbox_name: mailbox_name.to_string(),
                                    uid: 9,
                                    flags: vec!["\\Seen".to_string()],
                                    date_received: "2026-03-27 11:00:00 +0000".to_string(),
                                    size_virtual: 512,
                                    subject: Some("Quarterly report".to_string()),
                                    from: Some("Alice <alice@example.com>".to_string()),
                                },
                                MessageSummary {
                                    to: None,
                                    metadata: (!context.user_agent.contains("LegacyMetadata"))
                                        .then(|| {
                                            Self::fixture_metadata(
                                                &validated_session.record.canonical_username,
                                                mailbox_name,
                                                10,
                                            )
                                        }),
                                    mailbox_name: mailbox_name.to_string(),
                                    uid: 10,
                                    flags: Vec::new(),
                                    date_received: "2026-03-28 12:00:00 +0000".to_string(),
                                    size_virtual: 768,
                                    subject: Some("Follow-up".to_string()),
                                    from: Some("Bob <bob@example.com>".to_string()),
                                },
                            ]
                        },
                    ),
                },
                audit_events: vec![LogEvent::new(
                    LogLevel::Info,
                    EventCategory::Mailbox,
                    "stub_message_list",
                    "stub message list returned",
                )],
            }
        }

        fn search_messages(
            &self,
            context: &AuthenticationContext,
            validated_session: &ValidatedSession,
            mailbox_name: Option<&str>,
            query: &str,
            field: MessageSearchField,
        ) -> BrowserMessageSearchOutcome {
            if let Some(decision) = &self.all_search_override {
                return BrowserMessageSearchOutcome {
                    decision: decision.clone(),
                    audit_events: vec![build_http_info_event(
                        "stub_all_search",
                        "controlled search returned",
                        context,
                    )
                    .with_field("all_scope", mailbox_name.is_none().to_string())
                    .with_field("field", field.query_value())],
                };
            }
            if let Some(outcome) =
                ux_browser_server::back_focus_search(validated_session, mailbox_name, query, field)
            {
                return outcome;
            }
            if validated_session.record.canonical_username == "alice@example.com"
                && mailbox_name.is_none_or(|name| name == "INBOX")
                && query == "Shared public subject"
                && field == MessageSearchField::Subject
            {
                if let Some(messages) = &self.message_list_override {
                    return BrowserMessageSearchOutcome {
                        decision: BrowserMessageSearchDecision::Listed {
                            canonical_username: validated_session.record.canonical_username.clone(),
                            mailbox_name: mailbox_name.map(str::to_string),
                            query: query.into(),
                            results: messages
                                .iter()
                                .map(|message| MessageSearchResult {
                                    mailbox_name: message.mailbox_name.clone(),
                                    uid: message.uid,
                                    flags: message.flags.clone(),
                                    date_received: message.date_received.clone(),
                                    size_virtual: message.size_virtual,
                                    subject: message.subject.clone(),
                                    from: message.from.clone(),
                                    metadata: message.metadata.clone(),
                                })
                                .collect(),
                        },
                        audit_events: Vec::new(),
                    };
                }
            }
            if context.user_agent == "OSMAP/StateFailure" {
                return BrowserMessageSearchOutcome {
                    decision: BrowserMessageSearchDecision::Denied {
                        public_reason: "unavailable".into(),
                    },
                    audit_events: Vec::new(),
                };
            }
            if context.user_agent == "OSMAP/SearchWrongOwner" {
                return BrowserMessageSearchOutcome {
                    decision: BrowserMessageSearchDecision::Listed {
                        canonical_username: "foreign@example.test".into(),
                        mailbox_name: Some("ForeignFolder".into()),
                        query: "foreign-secret".into(),
                        results: Vec::new(),
                    },
                    audit_events: Vec::new(),
                };
            }
            let mailbox_name = mailbox_name.map(str::to_string);
            if context.user_agent.starts_with("OSMAP/ManyMessages")
                && matches!(query, "reader-fixture" | "reader-miss")
            {
                let mut results = Vec::new();
                if query == "reader-fixture" {
                    let names = mailbox_name
                        .as_deref()
                        .map(|name| vec![name])
                        .unwrap_or_else(|| vec!["INBOX", "Sent"]);
                    for name in names {
                        for uid in 1..=125 {
                            if self.fixture_message_removed(
                                &validated_session.record.canonical_username,
                                name,
                                uid,
                            ) {
                                continue;
                            }
                            results.push(MessageSearchResult {
                                metadata: Self::fixture_attachment_metadata(
                                    context,
                                    &validated_session.record.canonical_username,
                                    name,
                                    uid,
                                ),
                                mailbox_name: name.into(),
                                uid,
                                flags: self.fixture_message_flags(
                                    &validated_session.record.canonical_username,
                                    name,
                                    uid,
                                ),
                                date_received: "2026-09-30 00:00:00 +0000".into(),
                                size_virtual: 1024,
                                subject: Some(format!("Message {uid:03}")),
                                from: Some("Synthetic Sender <sender@example.test>".into()),
                            });
                        }
                        results.extend(
                            self.fixture_reconcile_messages(
                                &validated_session.record.canonical_username,
                                name,
                                Vec::new(),
                            )
                            .into_iter()
                            .map(|message| MessageSearchResult {
                                metadata: message.metadata,
                                mailbox_name: message.mailbox_name,
                                uid: message.uid,
                                flags: message.flags,
                                date_received: message.date_received,
                                size_virtual: message.size_virtual,
                                subject: message.subject,
                                from: message.from,
                            }),
                        );
                    }
                }
                return BrowserMessageSearchOutcome {
                    decision: BrowserMessageSearchDecision::Listed {
                        canonical_username: validated_session.record.canonical_username.clone(),
                        mailbox_name,
                        query: query.into(),
                        results,
                    },
                    audit_events: Vec::new(),
                };
            }
            if query == "ux-empty-fixture" {
                return BrowserMessageSearchOutcome {
                    decision: BrowserMessageSearchDecision::Listed {
                        canonical_username: validated_session.record.canonical_username.clone(),
                        mailbox_name,
                        query: query.to_string(),
                        results: Vec::new(),
                    },
                    audit_events: Vec::new(),
                };
            }
            if mailbox_name.as_deref() == Some("MissingArchive") {
                return BrowserMessageSearchOutcome {
                    decision: BrowserMessageSearchDecision::Denied {
                        public_reason: "invalid_mailbox".to_string(),
                    },
                    audit_events: vec![LogEvent::new(
                        LogLevel::Warn,
                        EventCategory::Mailbox,
                        "stub_message_search_denied",
                        "stub message search denied",
                    )],
                };
            }
            if query.trim() == "manyresults" {
                let results = (0..crate::mailbox::DEFAULT_MAX_SEARCH_RESULTS + 25)
                    .map(|index| MessageSearchResult {
                        metadata: None,
                        mailbox_name: "INBOX".to_string(),
                        uid: 10_000 + index as u64,
                        flags: Vec::new(),
                        date_received: "2026-03-29 09:00:00 +0000".to_string(),
                        size_virtual: 512,
                        subject: Some(format!("Result {index}")),
                        from: Some("Load Test <load@example.com>".to_string()),
                    })
                    .collect();

                return BrowserMessageSearchOutcome {
                    decision: BrowserMessageSearchDecision::Listed {
                        canonical_username: validated_session.record.canonical_username.clone(),
                        mailbox_name,
                        query: query.trim().to_string(),
                        results,
                    },
                    audit_events: vec![LogEvent::new(
                        LogLevel::Info,
                        EventCategory::Mailbox,
                        "stub_many_search_results",
                        "stub many message search results returned",
                    )],
                };
            }
            if query.trim() == "searchsort" {
                let results = vec![
                    MessageSearchResult {
                        metadata: None,
                        mailbox_name: "INBOX".to_string(),
                        uid: 30,
                        flags: vec!["\\Seen".to_string()],
                        date_received: "2026-03-29 09:00:00 +0000".to_string(),
                        size_virtual: 2048,
                        subject: Some("Search Middle".to_string()),
                        from: Some("Carol <carol@example.com>".to_string()),
                    },
                    MessageSearchResult {
                        metadata: None,
                        mailbox_name: "Archive/2026".to_string(),
                        uid: 10,
                        flags: vec!["\\Answered".to_string()],
                        date_received: "2026-03-27 07:00:00 +0000".to_string(),
                        size_virtual: 512,
                        subject: Some("Search Alpha".to_string()),
                        from: Some("Bob <bob@example.com>".to_string()),
                    },
                    MessageSearchResult {
                        metadata: None,
                        mailbox_name: "Sent".to_string(),
                        uid: 20,
                        flags: vec!["\\Flagged".to_string()],
                        date_received: "2026-03-28 08:00:00 +0000".to_string(),
                        size_virtual: 1024,
                        subject: Some("Search Zulu".to_string()),
                        from: Some("Alice <alice@example.com>".to_string()),
                    },
                ];

                return BrowserMessageSearchOutcome {
                    decision: BrowserMessageSearchDecision::Listed {
                        canonical_username: validated_session.record.canonical_username.clone(),
                        mailbox_name,
                        query: query.trim().to_string(),
                        results,
                    },
                    audit_events: vec![LogEvent::new(
                        LogLevel::Info,
                        EventCategory::Mailbox,
                        "stub_search_sort_results",
                        "stub sortable message search results returned",
                    )],
                };
            }
            if query.trim() == "fieldfilter" {
                let subject = match field {
                    MessageSearchField::All => "All field selected",
                    MessageSearchField::Subject => "Subject field selected",
                    MessageSearchField::From => "From field selected",
                };

                return BrowserMessageSearchOutcome {
                    decision: BrowserMessageSearchDecision::Listed {
                        canonical_username: validated_session.record.canonical_username.clone(),
                        mailbox_name,
                        query: query.trim().to_string(),
                        results: vec![MessageSearchResult {
                            metadata: None,
                            mailbox_name: "INBOX".to_string(),
                            uid: 19,
                            flags: Vec::new(),
                            date_received: "2026-03-29 10:00:00 +0000".to_string(),
                            size_virtual: 333,
                            subject: Some(subject.to_string()),
                            from: Some("Field Test <field@example.com>".to_string()),
                        }],
                    },
                    audit_events: vec![LogEvent::new(
                        LogLevel::Info,
                        EventCategory::Mailbox,
                        "stub_search_field_results",
                        "stub search field result returned",
                    )],
                };
            }
            let results = match mailbox_name.as_deref() {
                Some(mailbox_name) => vec![MessageSearchResult {
                    metadata: None,
                    mailbox_name: mailbox_name.to_string(),
                    uid: 17,
                    flags: vec!["\\Seen".to_string()],
                    date_received: "2026-03-27 17:00:00 +0000".to_string(),
                    size_virtual: 2048,
                    subject: Some("Quarterly report".to_string()),
                    from: Some("Alice <alice@example.com>".to_string()),
                }],
                None => vec![
                    MessageSearchResult {
                        metadata: None,
                        mailbox_name: "INBOX".to_string(),
                        uid: 17,
                        flags: vec!["\\Seen".to_string()],
                        date_received: "2026-03-27 17:00:00 +0000".to_string(),
                        size_virtual: 2048,
                        subject: Some("Quarterly report".to_string()),
                        from: Some("Alice <alice@example.com>".to_string()),
                    },
                    MessageSearchResult {
                        metadata: None,
                        mailbox_name: "Archive/2026".to_string(),
                        uid: 23,
                        flags: Vec::new(),
                        date_received: "2026-03-28 08:30:00 +0000".to_string(),
                        size_virtual: 1536,
                        subject: Some("Archived follow-up".to_string()),
                        from: Some("Bob <bob@example.com>".to_string()),
                    },
                ],
            };

            BrowserMessageSearchOutcome {
                decision: BrowserMessageSearchDecision::Listed {
                    canonical_username: validated_session.record.canonical_username.clone(),
                    mailbox_name,
                    query: query.trim().to_string(),
                    results,
                },
                audit_events: vec![LogEvent::new(
                    LogLevel::Info,
                    EventCategory::Mailbox,
                    "stub_message_search",
                    "stub message search returned",
                )],
            }
        }

        fn view_message(
            &self,
            context: &AuthenticationContext,
            validated_session: &ValidatedSession,
            mailbox_name: &str,
            uid: u64,
        ) -> BrowserMessageViewOutcome {
            if let Some(outcome) =
                ux_browser_server::back_focus_view(validated_session, mailbox_name, uid)
            {
                return outcome;
            }
            if mailbox_name == "INBOX"
                && validated_session.record.canonical_username == "alice@example.com"
            {
                if let Some(message) = self
                    .message_list_override
                    .as_ref()
                    .and_then(|messages| messages.iter().find(|message| message.uid == uid))
                {
                    let body = format!("Synthetic message {uid} in INBOX for alice@example.com.");
                    return BrowserMessageViewOutcome {
                        decision: BrowserMessageViewDecision::Rendered {
                            canonical_username: validated_session.record.canonical_username.clone(),
                            rendered: Box::new(RenderedMessageView {
                                openpgp: None,
                                metadata: message.metadata.clone(),
                                to: Some(validated_session.record.canonical_username.clone()),
                                cc: None,
                                reply_metadata: None,
                                flags: message.flags.clone(),
                                mailbox_name: message.mailbox_name.clone(),
                                uid,
                                subject: message.subject.clone(),
                                from: message.from.clone(),
                                date_received: message.date_received.clone(),
                                mime_top_level_content_type: "text/plain".into(),
                                body_source: MimeBodySource::SinglePartPlainText,
                                contains_html_body: false,
                                body_html: TrustedHtml::from_template(format!(
                                    "<pre>{}</pre>",
                                    escape_html(&body)
                                )),
                                body_text_for_compose: body,
                                attachments: Vec::new(),
                                rendering_mode: RenderingMode::PlainTextPreformatted,
                            }),
                        },
                        audit_events: Vec::new(),
                    };
                }
            }
            if uid == 900 || context.user_agent.contains("ReaderUnavailable") {
                return BrowserMessageViewOutcome {
                    decision: BrowserMessageViewDecision::Denied {
                        public_reason: "temporarily_unavailable".to_string(),
                    },
                    audit_events: vec![LogEvent::new(
                        LogLevel::Warn,
                        EventCategory::Mailbox,
                        "stub_oversized_mime_rejected",
                        "stub oversized mime body rejected",
                    )],
                };
            }

            if self.fixture_message_removed(
                &validated_session.record.canonical_username,
                mailbox_name,
                uid,
            ) {
                return BrowserMessageViewOutcome {
                    decision: BrowserMessageViewDecision::Denied {
                        public_reason: "not_found".into(),
                    },
                    audit_events: Vec::new(),
                };
            }
            if context.user_agent == "PrivacyBrowser" {
                let content = self
                    .settings_store
                    .as_ref()
                    .and_then(|store| {
                        crate::settings::UserSettingsStore::load(
                            store,
                            &validated_session.record.canonical_username,
                        )
                        .ok()
                        .flatten()
                    })
                    .unwrap_or_default()
                    .html_display_preference;
                let message = MessageView { metadata: None, mailbox_name: mailbox_name.into(), uid, flags: vec![], date_received: "2026-09-30 00:00:00 +0000".into(), size_virtual: 512, header_block: "Subject: Privacy sample\nContent-Type: multipart/alternative; boundary=privacy\n".into(), body_text: "--privacy\nContent-Type: text/plain; charset=utf-8\n\nSynthetic plain part\n--privacy\nContent-Type: text/html; charset=utf-8\n\n<p>Synthetic <strong>protected part</strong></p><img src=\"https://external.invalid/pixel\"><script>unsafe()</script>\n--privacy--\n".into() };
                let rendered = PlainTextMessageRenderer::new(RenderingPolicy {
                    html_display_preference: content,
                    ..RenderingPolicy::default()
                })
                .render_for_validated_session(context, validated_session, &message)
                .unwrap();
                return BrowserMessageViewOutcome {
                    decision: BrowserMessageViewDecision::Rendered {
                        canonical_username: validated_session.record.canonical_username.clone(),
                        rendered: Box::new(rendered.rendered),
                    },
                    audit_events: vec![rendered.audit_event],
                };
            }
            let moved_fixture = self.fixture_added_message(
                &validated_session.record.canonical_username,
                mailbox_name,
                uid,
            );
            let _unused_fixture = MessageView {
                metadata: None,
                mailbox_name: mailbox_name.to_string(),
                uid,
                flags: vec!["\\Seen".to_string()],
                date_received: "2026-03-27 11:00:00 +0000".to_string(),
                size_virtual: 512,
                header_block: "Subject: Example\n".to_string(),
                body_text: "Hello world\n".to_string(),
            };
            let attachments = if context.user_agent.starts_with("OSMAP/ManyMessages") {
                if uid % 5 == 0 {
                    vec![crate::mime::AttachmentMetadata {
                        part_path: "1.2".into(),
                        filename: Some("fixture.txt".into()),
                        content_type: "application/octet-stream".into(),
                        disposition: AttachmentDisposition::Attachment,
                        content_id: None,
                        size_hint_bytes: 24,
                    }]
                } else {
                    Vec::new()
                }
            } else if uid == 901 {
                (0..crate::mime::DEFAULT_MIME_PARTS_MAX + 12)
                    .map(|index| crate::mime::AttachmentMetadata {
                        part_path: format!("1.{}", index + 2),
                        filename: Some(format!("overflow-{index}.bin")),
                        content_type: "application/octet-stream".to_string(),
                        disposition: AttachmentDisposition::Attachment,
                        content_id: None,
                        size_hint_bytes: 128,
                    })
                    .collect()
            } else {
                vec![
                    crate::mime::AttachmentMetadata {
                        part_path: "1.2".to_string(),
                        filename: Some("report.pdf".to_string()),
                        content_type: "application/pdf".to_string(),
                        disposition: AttachmentDisposition::Attachment,
                        content_id: None,
                        size_hint_bytes: 128,
                    },
                    crate::mime::AttachmentMetadata {
                        part_path: "1.3".to_string(),
                        filename: Some("chart.png".to_string()),
                        content_type: "image/png".to_string(),
                        disposition: AttachmentDisposition::Inline,
                        content_id: Some("chart@example.com".to_string()),
                        size_hint_bytes: 64,
                    },
                ]
            };

            let many = context.user_agent.starts_with("OSMAP/ManyMessages");
            let body_text = if context.user_agent.contains("CompositionLiteralSource") {
                composition_preference_tests::LITERAL_SOURCE.into()
            } else if many {
                format!(
                    "Synthetic message {uid} in {mailbox_name} for {}.",
                    validated_session.record.canonical_username
                )
            } else {
                "Hello world".into()
            };
            let mut metadata = if context.user_agent.contains("LegacyMetadata") {
                None
            } else {
                self.fixture_current_metadata(
                    &validated_session.record.canonical_username,
                    mailbox_name,
                    uid,
                )
            };
            if context.user_agent.contains("ReaderStale") {
                if let Some(metadata) = &mut metadata {
                    metadata.version.message_guid = "changed-synthetic-message".into();
                }
            }
            BrowserMessageViewOutcome {
                decision: BrowserMessageViewDecision::Rendered {
                    canonical_username: if context.user_agent.contains("ReaderWrongAccount") {
                        "other@example.test".into()
                    } else {
                        validated_session.record.canonical_username.clone()
                    },
                    rendered: Box::new(RenderedMessageView {
                        openpgp: None,
                        metadata,
                        to: Some(validated_session.record.canonical_username.clone()),
                        cc: None,
                        reply_metadata: crate::reply_thread::ReplyMetadata::from_original(
                            &reply_tests::source_headers(context, validated_session, uid),
                        )
                        .ok(),
                        flags: self.fixture_message_flags(
                            &validated_session.record.canonical_username,
                            mailbox_name,
                            uid,
                        ),
                        mailbox_name: if context.user_agent.contains("ReaderWrongMailbox") {
                            "Other".into()
                        } else {
                            mailbox_name.to_string()
                        },
                        uid: if context.user_agent.contains("ReaderWrongUid") {
                            uid + 1
                        } else {
                            uid
                        },
                        subject: Some(
                            if let Some(subject) = moved_fixture
                                .as_ref()
                                .and_then(|message| message.subject.as_ref())
                            {
                                subject.clone()
                            } else if many
                                && context.user_agent.contains("LongHeaders")
                                && uid == 125
                            {
                                format!("<b>Synthetic header</b> {}", "W".repeat(256))
                            } else if many {
                                format!("Message {uid:03}")
                            } else {
                                "Example".into()
                            },
                        ),
                        from: Some(if many {
                            "Synthetic Sender <sender@example.test>".into()
                        } else {
                            "Alice <alice@example.com>".into()
                        }),
                        date_received: if many {
                            "2026-09-30 00:00:00 +0000".into()
                        } else {
                            "2026-03-27 11:00:00 +0000".into()
                        },
                        mime_top_level_content_type: "multipart/mixed".to_string(),
                        body_source: MimeBodySource::MultipartPlainTextPart,
                        contains_html_body: !many,
                        body_html: TrustedHtml::from_template(format!(
                            "<pre>{}</pre>",
                            escape_html(&body_text)
                        )),
                        body_text_for_compose: body_text,
                        attachments,
                        rendering_mode: RenderingMode::PlainTextPreformatted,
                    }),
                },
                audit_events: vec![LogEvent::new(
                    LogLevel::Info,
                    EventCategory::Mailbox,
                    "stub_message_view",
                    "stub message view returned",
                )],
            }
        }

        fn send_message(
            &self,
            context: &AuthenticationContext,
            _validated_session: &ValidatedSession,
            request: BrowserSendRequest<'_>,
        ) -> BrowserSendOutcome {
            if let Some(snapshot) = &self.fixture_openpgp_snapshot {
                if request.protection.binding_revision != Some(snapshot.lock().unwrap().revision) {
                    return BrowserSendOutcome {
                        decision: BrowserSendDecision::Denied {
                            public_reason: "openpgp_binding_changed".into(),
                            retry_after_seconds: None,
                        },
                        audit_events: vec![],
                    };
                }
            }
            if self.browser_fixture_openpgp_denials {
                let reason = match request.recipients {
                    "pgp-locked@example.test" => Some("openpgp_key_locked"),
                    "pgp-blocked@example.test" => Some("openpgp_protection_blocked"),
                    _ => None,
                };
                if let Some(public_reason) = reason {
                    return BrowserSendOutcome {
                        decision: BrowserSendDecision::Denied {
                            public_reason: public_reason.into(),
                            retry_after_seconds: None,
                        },
                        audit_events: vec![],
                    };
                }
            }
            use crate::send_journal::{AttemptOutcome, PreparedResult};
            let result = self.send_journal.execute_prepared(
                &_validated_session.record.canonical_username,
                request.send_intent,
                100,
                |consumed| {
                    if !consumed && request.recipients == "locked@example.com" {
                        return Err(BrowserSendDecision::Denied {
                            public_reason: TOO_MANY_SUBMISSIONS_PUBLIC_REASON.into(),
                            retry_after_seconds: Some(120),
                        });
                    }
                    let mut parsed = ComposeRequest::new_with_routing(
                        ComposePolicy::default(),
                        request.recipients,
                        request.cc_recipients,
                        request.bcc_recipients,
                        request.subject,
                        request.body,
                        request.attachments.to_vec(),
                    )
                    .and_then(|value| value.with_body_format(request.body_format))
                    .map_err(|_| BrowserSendDecision::Denied {
                        public_reason: "invalid_request".into(),
                        retry_after_seconds: None,
                    })?;
                    parsed.sender_identity = if consumed {
                        match crate::send_recovery::SendRecovery::new(self.recovery_root.clone())
                            .lookup(
                                &self.send_journal,
                                &_validated_session.record.canonical_username,
                                request.send_intent,
                                100,
                            ) {
                            Ok(crate::send_recovery::RecoveryRead::Available(snapshot)) => {
                                snapshot.request.sender_identity.clone()
                            }
                            _ => {
                                return Err(BrowserSendDecision::Unconfirmed {
                                    public_reason: "send_attempt_paused".into(),
                                })
                            }
                        }
                    } else if let Some(id) = request.draft_id {
                        let record = if let Some(store) = &self.draft_store {
                            store
                                .load(&_validated_session.record.canonical_username, id, 100)
                                .ok()
                                .flatten()
                        } else {
                            self.drafts.lock().unwrap().get(id).cloned()
                        };
                        record
                            .ok_or_else(|| BrowserSendDecision::Unconfirmed {
                                public_reason: "send_attempt_paused".into(),
                            })?
                            .request
                            .sender_identity
                    } else if self.identity_preferences_store.is_some() {
                        self.load_identity_preferences(context, _validated_session)
                            .map_err(|_| BrowserSendDecision::Unconfirmed {
                                public_reason: "send_attempt_paused".into(),
                            })?
                            .preferences
                    } else {
                        crate::identity_preferences::IdentityPreferences::default()
                    };
                    parsed.reply_thread = request.reply_thread.cloned();
                    Ok(parsed)
                },
                |compose| {
                    let normal = self.draft_store.clone().unwrap_or_else(|| {
                        FileDraftStore::new(
                            self.recovery_root.join("ordinary-fixture"),
                            DraftPolicy::default(),
                        )
                    });
                    let compose =
                        match crate::send_recovery::SendRecovery::new(self.recovery_root.clone())
                            .capture(
                                &self.send_journal,
                                &normal,
                                &_validated_session.record.canonical_username,
                                request.send_intent,
                                compose,
                                100,
                            ) {
                            Ok(value) => value,
                            Err(error) => {
                                return AttemptOutcome::RecoveryRefused {
                                    capacity: error
                                        == crate::send_recovery::RecoveryError::Capacity,
                                }
                            }
                        };
                    self.submitted
                        .lock()
                        .expect("synthetic submissions")
                        .push(compose.clone());
                    if context.user_agent.contains("SendUnconfirmed") {
                        AttemptOutcome::Unconfirmed
                    } else {
                        AttemptOutcome::Accepted {
                            sent_copy_stored: !context.user_agent.contains("SentCopyUnconfirmed"),
                        }
                    }
                },
            );
            BrowserSendOutcome {
                decision: match result {
                    Ok(PreparedResult::Outcome(recorded)) => fixture_send_decision(Ok(recorded)),
                    Ok(PreparedResult::NotDispatched(decision)) => decision,
                    Err(error) => fixture_send_decision(Err(error)),
                },
                audit_events: vec![],
            }
        }

        fn read_message_source(
            &self,
            context: &AuthenticationContext,
            session: &ValidatedSession,
            request: &MessageViewRequest,
        ) -> crate::mailbox::MessageViewOutcome {
            protected_route_tests::source_fixture(context, session, request)
                .unwrap_or_else(|| content_tests::fixture_source(self, context, session, request))
        }

        fn download_stored_attachment(
            &self,
            context: &AuthenticationContext,
            session: &ValidatedSession,
            message: &MessageView,
            part: &str,
        ) -> BrowserAttachmentDownloadOutcome {
            protected_route_tests::stored_attachment_fixture(context, session, message, part)
        }

        fn download_attachment(
            &self,
            _context: &AuthenticationContext,
            validated_session: &ValidatedSession,
            mailbox_name: &str,
            uid: u64,
            part_path: &str,
        ) -> BrowserAttachmentDownloadOutcome {
            if mailbox_name == "INBOX" && uid == 9 && part_path == "1.2" {
                BrowserAttachmentDownloadOutcome {
                    decision: BrowserAttachmentDownloadDecision::Downloaded {
                        canonical_username: validated_session.record.canonical_username.clone(),
                        attachment: DownloadedAttachment {
                            mailbox_name: mailbox_name.to_string(),
                            uid,
                            part_path: part_path.to_string(),
                            filename: "report.pdf".to_string(),
                            content_type: "application/pdf".to_string(),
                            body: b"%PDF-stub%".to_vec(),
                        },
                    },
                    audit_events: vec![LogEvent::new(
                        LogLevel::Info,
                        EventCategory::Mailbox,
                        "stub_attachment_download",
                        "stub attachment download returned",
                    )],
                }
            } else {
                BrowserAttachmentDownloadOutcome {
                    decision: BrowserAttachmentDownloadDecision::Denied {
                        public_reason: "not_found".to_string(),
                    },
                    audit_events: vec![LogEvent::new(
                        LogLevel::Warn,
                        EventCategory::Mailbox,
                        "stub_attachment_missing",
                        "stub attachment missing",
                    )],
                }
            }
        }

        fn move_message(
            &self,
            context: &AuthenticationContext,
            session: &ValidatedSession,
            request: &MessageMoveRequest,
        ) -> BrowserMessageMoveOutcome {
            self.set_fixture_message_move(context, session, request)
        }

        fn list_drafts(
            &self,
            _context: &AuthenticationContext,
            validated_session: &ValidatedSession,
        ) -> BrowserDraftListOutcome {
            if matches!(
                _context.user_agent.as_str(),
                "WelcomeDraftFailure" | "WelcomeDraftWrongOwner"
            ) {
                return BrowserDraftListOutcome {
                    decision: if _context.user_agent == "WelcomeDraftFailure" {
                        BrowserDraftListDecision::Denied {
                            public_reason: "unavailable".into(),
                        }
                    } else {
                        BrowserDraftListDecision::Listed {
                            canonical_username: "foreign@example.test".into(),
                            drafts: vec![],
                            states: vec![],
                            usage: BrowserDraftStorageUsage::Unknown,
                        }
                    },
                    audit_events: vec![],
                };
            }
            let guard = match self.send_journal.account_guard(
                &validated_session.record.canonical_username,
                self.send_clock(),
            ) {
                Ok(guard) => guard,
                Err(_) => {
                    return BrowserDraftListOutcome {
                        decision: BrowserDraftListDecision::Denied {
                            public_reason: "temporarily_unavailable".into(),
                        },
                        audit_events: vec![],
                    }
                }
            };
            let drafts = if let Some(store) = &self.draft_store {
                match store.list(&validated_session.record.canonical_username, 100) {
                    Ok(drafts) => drafts,
                    Err(error) => {
                        return BrowserDraftListOutcome {
                            decision: BrowserDraftListDecision::Denied {
                                public_reason: fixture_draft_error(&error),
                            },
                            audit_events: vec![],
                        }
                    }
                }
            } else {
                self.drafts
                    .lock()
                    .expect("stub drafts should lock")
                    .values()
                    .filter(|draft| {
                        draft.canonical_username == validated_session.record.canonical_username
                    })
                    .map(DraftRecord::summary)
                    .collect()
            };
            let recovery = crate::send_recovery::SendRecovery::new(self.recovery_root.clone())
                .storage_usage(
                    &validated_session.record.canonical_username,
                    self.send_clock(),
                );
            let (states, usage) = super::http_browser::project_drafts(&guard, &drafts, recovery);
            BrowserDraftListOutcome {
                decision: BrowserDraftListDecision::Listed {
                    canonical_username: validated_session.record.canonical_username.clone(),
                    drafts,
                    states,
                    usage,
                },
                audit_events: vec![LogEvent::new(
                    LogLevel::Info,
                    EventCategory::Http,
                    "stub_draft_list",
                    "stub draft list returned",
                )],
            }
        }

        fn load_draft(
            &self,
            _context: &AuthenticationContext,
            validated_session: &ValidatedSession,
            draft_id: &str,
        ) -> BrowserDraftLoadOutcome {
            let _guard = match self
                .send_journal
                .account_guard(&validated_session.record.canonical_username, 100)
            {
                Ok(guard) => guard,
                Err(_) => {
                    return BrowserDraftLoadOutcome {
                        decision: BrowserDraftLoadDecision::Denied {
                            public_reason: "send_attempt_paused".into(),
                        },
                        audit_events: vec![],
                    }
                }
            };
            let draft = if let Some(store) = &self.draft_store {
                match store.load(&validated_session.record.canonical_username, draft_id, 100) {
                    Ok(draft) => draft,
                    Err(error) => {
                        return BrowserDraftLoadOutcome {
                            decision: BrowserDraftLoadDecision::Denied {
                                public_reason: fixture_draft_error(&error),
                            },
                            audit_events: vec![],
                        }
                    }
                }
            } else {
                self.drafts
                    .lock()
                    .expect("stub drafts should lock")
                    .get(draft_id)
                    .filter(|draft| {
                        draft.canonical_username == validated_session.record.canonical_username
                    })
                    .cloned()
            };
            match draft {
                Some(draft) => BrowserDraftLoadOutcome {
                    decision: BrowserDraftLoadDecision::Loaded {
                        canonical_username: validated_session.record.canonical_username.clone(),
                        draft: Box::new(draft),
                    },
                    audit_events: vec![LogEvent::new(
                        LogLevel::Info,
                        EventCategory::Http,
                        "stub_draft_load",
                        "stub draft loaded",
                    )],
                },
                None => BrowserDraftLoadOutcome {
                    decision: BrowserDraftLoadDecision::NotFound,
                    audit_events: vec![LogEvent::new(
                        LogLevel::Warn,
                        EventCategory::Http,
                        "stub_draft_missing",
                        "stub draft missing",
                    )],
                },
            }
        }

        fn save_draft(
            &self,
            context: &AuthenticationContext,
            validated_session: &ValidatedSession,
            request: BrowserDraftSaveRequest<'_>,
        ) -> BrowserDraftSaveOutcome {
            let mut guard = match self
                .send_journal
                .account_guard(&validated_session.record.canonical_username, 100)
            {
                Ok(value) => value,
                Err(_) => return fixture_paused_save(),
            };
            if guard.require_unconsumed(request.send_intent).is_err() {
                return fixture_paused_save();
            }
            let draft_id = request
                .draft_id
                .filter(|value| !value.trim().is_empty())
                .map(str::to_string)
                .unwrap_or_else(|| self.next_draft_id());
            let mut drafts = self.drafts.lock().expect("stub drafts should lock");
            let existing = if let Some(store) = &self.draft_store {
                match store.load(&validated_session.record.canonical_username, &draft_id, 100) {
                    Ok(draft) => draft,
                    Err(error) => {
                        return BrowserDraftSaveOutcome {
                            decision: BrowserDraftSaveDecision::Denied {
                                public_reason: fixture_draft_error(&error),
                            },
                            audit_events: vec![],
                        }
                    }
                }
            } else {
                drafts.get(&draft_id).cloned()
            };
            if existing.as_ref().is_some_and(|draft| {
                draft.canonical_username != validated_session.record.canonical_username
            }) {
                return BrowserDraftSaveOutcome {
                    decision: BrowserDraftSaveDecision::Denied {
                        public_reason: "invalid_request".into(),
                    },
                    audit_events: vec![],
                };
            }
            if existing.as_ref().and_then(|draft| draft.revision) != request.expected_revision
                || request.draft_id.is_some() != existing.is_some()
            {
                return BrowserDraftSaveOutcome {
                    decision: BrowserDraftSaveDecision::Denied {
                        public_reason: "draft_conflict".into(),
                    },
                    audit_events: vec![],
                };
            }
            let mut attachments = match crate::draft_content::retain_saved_attachments(
                existing
                    .as_ref()
                    .map(|draft| draft.request.attachments.as_slice())
                    .unwrap_or_default(),
                request.removed_attachment_indices,
            ) {
                Ok(attachments) => attachments,
                Err(_) => {
                    return BrowserDraftSaveOutcome {
                        decision: BrowserDraftSaveDecision::Denied {
                            public_reason: "invalid_request".into(),
                        },
                        audit_events: vec![],
                    }
                }
            };
            attachments.extend_from_slice(request.attachments);
            if let Some(existing) = &existing {
                if guard.draft_intent(existing).ok().as_deref() != Some(request.send_intent) {
                    return fixture_paused_save();
                }
            }
            if request.draft_id.is_none()
                && guard
                    .begin_draft_save(request.send_intent, &draft_id)
                    .is_err()
            {
                return fixture_paused_save();
            }
            let mut record = match DraftRecord::new(
                DraftPolicy::default(),
                DraftRecordInput {
                    draft_id: draft_id.clone(),
                    canonical_username: validated_session.record.canonical_username.clone(),
                    now: 100,
                    recipients_text: request.recipients.to_string(),
                    cc_text: request.cc_recipients.to_string(),
                    bcc_text: request.bcc_recipients.to_string(),
                    subject: request.subject.to_string(),
                    body: request.body.to_string(),
                    attachments,
                    source_attachments: request.source_attachments.cloned(),
                },
            ) {
                Ok(record) => record,
                Err(_) => {
                    return BrowserDraftSaveOutcome {
                        decision: BrowserDraftSaveDecision::Denied {
                            public_reason: "invalid_request".to_string(),
                        },
                        audit_events: vec![LogEvent::new(
                            LogLevel::Warn,
                            EventCategory::Http,
                            "stub_draft_save_denied",
                            "stub draft save denied",
                        )],
                    }
                }
            };
            record.request.sender_identity = if let Some(saved) = existing.as_ref() {
                saved.request.sender_identity.clone()
            } else if let Some(store) = &self.identity_preferences_store {
                match store.load(&validated_session.record.canonical_username) {
                    Ok(value) => value.preferences,
                    Err(_) => return fixture_paused_save(),
                }
            } else {
                crate::identity_preferences::IdentityPreferences::default()
            };
            record.request.body_format = request.body_format;
            record.request.protection = request.protection;
            record.request.reply_thread = request.reply_thread.cloned();
            record.revision = request.expected_revision;
            if let Some(existing) = existing {
                record.created_at = existing.created_at;
                record.starred = existing.starred;
                record.request.reply_thread = existing.request.reply_thread;
            }
            if let Some(store) = &self.draft_store {
                if let Err(error) = store.save(&record, 100) {
                    return BrowserDraftSaveOutcome {
                        decision: if error.save_unconfirmed() {
                            BrowserDraftSaveDecision::Unconfirmed { draft_id }
                        } else {
                            BrowserDraftSaveDecision::Denied {
                                public_reason: fixture_draft_error(&error),
                            }
                        },
                        audit_events: vec![],
                    };
                }
            } else {
                record.revision = Some(request.expected_revision.unwrap_or(0) + 1);
                drafts.insert(draft_id.clone(), record);
            }
            if request.draft_id.is_none()
                && guard
                    .finish_draft_save(request.send_intent, &draft_id)
                    .is_err()
            {
                return fixture_paused_save();
            }
            BrowserDraftSaveOutcome {
                decision: if context.user_agent.contains("DraftSaveUnconfirmed") {
                    BrowserDraftSaveDecision::Unconfirmed { draft_id }
                } else {
                    BrowserDraftSaveDecision::Saved { draft_id }
                },
                audit_events: vec![LogEvent::new(
                    LogLevel::Info,
                    EventCategory::Http,
                    "stub_draft_save",
                    "stub draft saved",
                )],
            }
        }

        fn delete_draft(
            &self,
            _context: &AuthenticationContext,
            validated_session: &ValidatedSession,
            draft_id: &str,
            expected_revision: u64,
        ) -> BrowserDraftDeleteOutcome {
            if self.fail_draft_delete.as_deref() == Some(draft_id) {
                return BrowserDraftDeleteOutcome {
                    decision: BrowserDraftDeleteDecision::Denied {
                        public_reason: "temporarily_unavailable".into(),
                    },
                    audit_events: vec![],
                };
            }
            if let Some(store) = &self.draft_store {
                return BrowserDraftDeleteOutcome {
                    decision: match store.delete(
                        &validated_session.record.canonical_username,
                        draft_id,
                        expected_revision,
                    ) {
                        Ok(true) => BrowserDraftDeleteDecision::Deleted,
                        Ok(false) => BrowserDraftDeleteDecision::NotFound,
                        Err(error) => BrowserDraftDeleteDecision::Denied {
                            public_reason: fixture_draft_error(&error),
                        },
                    },
                    audit_events: vec![],
                };
            }
            let mut drafts = self.drafts.lock().expect("stub drafts should lock");
            let decision = match drafts.get(draft_id) {
                Some(draft)
                    if draft.canonical_username != validated_session.record.canonical_username =>
                {
                    BrowserDraftDeleteDecision::NotFound
                }
                Some(draft) if draft.revision != Some(expected_revision) => {
                    BrowserDraftDeleteDecision::Denied {
                        public_reason: "draft_conflict".into(),
                    }
                }
                Some(_) => {
                    drafts.remove(draft_id);
                    BrowserDraftDeleteDecision::Deleted
                }
                None => BrowserDraftDeleteDecision::NotFound,
            };
            BrowserDraftDeleteOutcome {
                decision,
                audit_events: vec![LogEvent::new(
                    LogLevel::Info,
                    EventCategory::Http,
                    "stub_draft_delete",
                    "stub draft delete completed",
                )],
            }
        }

        fn set_draft_star(
            &self,
            _context: &AuthenticationContext,
            session: &ValidatedSession,
            draft_id: &str,
            expected_revision: u64,
            starred: bool,
        ) -> BrowserDraftSaveOutcome {
            let mut drafts = self.drafts.lock().unwrap();
            let result = (|| {
                let draft = if let Some(store) = &self.draft_store {
                    store.load(&session.record.canonical_username, draft_id, 100)?
                } else {
                    drafts
                        .get(draft_id)
                        .filter(|draft| {
                            draft.canonical_username == session.record.canonical_username
                        })
                        .cloned()
                };
                let mut draft = draft.ok_or_else(|| crate::draft::DraftError {
                    reason: "draft revision is stale".into(),
                })?;
                if draft.revision != Some(expected_revision) {
                    return Err(crate::draft::DraftError {
                        reason: "draft revision is stale".into(),
                    });
                }
                draft.starred = starred;
                if let Some(store) = &self.draft_store {
                    store.save(&draft, 100)?;
                } else {
                    draft.revision = Some(expected_revision + 1);
                    drafts.insert(draft_id.into(), draft);
                }
                Ok(())
            })();
            BrowserDraftSaveOutcome {
                decision: match result {
                    Ok(()) => BrowserDraftSaveDecision::Saved {
                        draft_id: draft_id.into(),
                    },
                    Err(error) if error.save_unconfirmed() => {
                        BrowserDraftSaveDecision::Unconfirmed {
                            draft_id: draft_id.into(),
                        }
                    }
                    Err(error) => BrowserDraftSaveDecision::Denied {
                        public_reason: fixture_draft_error(&error),
                    },
                },
                audit_events: vec![],
            }
        }
    }

    fn app() -> BrowserApp<StubGateway> {
        BrowserApp::new(HttpPolicy::default(), StubGateway::default())
    }

    fn fixture_send_journal() -> crate::send_journal::SendJournal {
        static NEXT: AtomicUsize = AtomicUsize::new(0);
        let serial = NEXT.fetch_add(1, Ordering::Relaxed);
        crate::send_journal::SendJournal::new(
            temp_dir(&format!("send-journal-fixture-{serial}")).join("records"),
        )
    }
    fn fixture_paused_save() -> BrowserDraftSaveOutcome {
        BrowserDraftSaveOutcome {
            decision: BrowserDraftSaveDecision::Denied {
                public_reason: "send_attempt_paused".into(),
            },
            audit_events: vec![],
        }
    }
    fn fixture_send_decision(
        result: Result<crate::send_journal::JournalResult, crate::send_journal::JournalError>,
    ) -> BrowserSendDecision {
        match result {
            Ok(crate::send_journal::JournalResult {
                outcome: crate::send_journal::AttemptOutcome::RecoveryRefused { capacity },
                ..
            }) => BrowserSendDecision::RecoveryRefused { capacity },
            Ok(crate::send_journal::JournalResult {
                outcome: crate::send_journal::AttemptOutcome::Accepted { sent_copy_stored },
                receipt_persisted,
                ..
            }) => BrowserSendDecision::Submitted {
                sent_copy_stored,
                receipt_persisted,
            },
            Ok(crate::send_journal::JournalResult {
                outcome:
                    crate::send_journal::AttemptOutcome::DraftSaved {
                        draft_id,
                        save_confirmed,
                    },
                ..
            }) => BrowserSendDecision::DraftSaved {
                draft_id: crate::send_journal::draft_id_text(&draft_id),
                save_confirmed,
            },
            _ => BrowserSendDecision::Unconfirmed {
                public_reason: "send_attempt_paused".into(),
            },
        }
    }
    fn fixture_draft_error(error: &crate::draft::DraftError) -> String {
        if error.reason.contains("revision") {
            "draft_conflict"
        } else if error.reason.contains("quota") {
            "draft_quota_exceeded"
        } else if error.reason == "draft store busy" {
            "draft_busy"
        } else {
            "temporarily_unavailable"
        }
        .into()
    }

    fn app_with_policy(policy: HttpPolicy) -> BrowserApp<StubGateway> {
        BrowserApp::new(policy, StubGateway::default())
    }

    // Explicit opt-in for existing valid compose fixtures. Generic request()
    // deliberately stays raw, so missing-intent and duplicate tests stay real.
    fn native_compose_request_bytes(
        app: &BrowserApp<StubGateway>,
        method: &str,
        path: &str,
        headers: &[(&str, &str)],
        body: &[u8],
    ) -> HttpRequest {
        let mut req = request_bytes(method, path, headers, body);
        add_native_compose_intent(app, &mut req);
        req
    }
    fn native_compose_request(
        app: &BrowserApp<StubGateway>,
        method: &str,
        path: &str,
        headers: &[(&str, &str)],
        body: &str,
    ) -> HttpRequest {
        let mut req = request(method, path, headers, body);
        add_native_compose_intent(app, &mut req);
        req
    }
    fn add_native_compose_intent(app: &BrowserApp<StubGateway>, req: &mut HttpRequest) {
        assert_eq!(req.method, HttpMethod::Post);
        assert!(matches!(
            req.path.as_str(),
            "/send" | "/drafts/save" | "/drafts/autosave"
        ));
        let kind = req.headers.get("content-type").cloned();
        let Ok(parsed) = parse_compose_form(
            &req.body,
            kind.as_deref(),
            128,
            32 * 1024 * 1024,
            ComposePolicy::default(),
        ) else {
            return;
        };
        if parsed.fields.contains_key("send_intent") {
            return;
        }
        let account = "alice@example.com";
        let draft = parsed.fields.get("draft_id").and_then(|id| {
            if let Some(store) = &app.gateway.draft_store {
                store.load(account, id, 100).ok().flatten()
            } else {
                app.gateway.drafts.lock().unwrap().get(id).cloned()
            }
        });
        let intent = if let Some(draft) = draft {
            crate::send_journal::intent_for_draft(
                account,
                &draft.draft_id,
                draft.revision.unwrap_or(0),
                draft.updated_at,
            )
            .unwrap()
        } else {
            crate::send_journal::mint_intent(app.gateway.send_clock()).unwrap()
        };
        if let Some(boundary) = kind
            .as_deref()
            .and_then(|value| value.split("boundary=").nth(1))
        {
            let mut body = format!("--{boundary}\r\nContent-Disposition: form-data; name=\"send_intent\"\r\n\r\n{intent}\r\n").into_bytes();
            body.extend_from_slice(&req.body);
            req.body = body;
        } else {
            req.body
                .extend_from_slice(format!("&send_intent={intent}").as_bytes());
        }
        req.headers
            .insert("content-length".into(), req.body.len().to_string());
    }

    fn request(method: &str, path: &str, headers: &[(&str, &str)], body: &str) -> HttpRequest {
        request_bytes(method, path, headers, body.as_bytes())
    }

    fn request_bytes(
        method: &str,
        path: &str,
        headers: &[(&str, &str)],
        body: &[u8],
    ) -> HttpRequest {
        let mut raw = format!("{method} {path} HTTP/1.1\r\nHost: localhost\r\n");
        for (name, value) in headers {
            raw.push_str(&format!("{name}: {value}\r\n"));
        }
        raw.push_str(&format!("Content-Length: {}\r\n\r\n", body.len()));

        let mut raw_bytes = raw.into_bytes();
        raw_bytes.extend_from_slice(body);

        parse_http_request_bytes(&raw_bytes, &HttpPolicy::default()).expect("request should parse")
    }

    fn request_with_host(
        method: &str,
        path: &str,
        host: Option<&str>,
        headers: &[(&str, &str)],
        body: &str,
    ) -> HttpRequest {
        let version = if host.is_some() {
            "HTTP/1.1"
        } else {
            "HTTP/1.0"
        };
        let mut raw = format!("{method} {path} {version}\r\n");
        if let Some(host) = host {
            raw.push_str(&format!("Host: {host}\r\n"));
        }
        for (name, value) in headers {
            raw.push_str(&format!("{name}: {value}\r\n"));
        }
        raw.push_str(&format!("Content-Length: {}\r\n\r\n{body}", body.len()));

        parse_http_request_bytes(raw.as_bytes(), &HttpPolicy::default())
            .expect("request should parse")
    }

    fn body_text(response: &HandledHttpResponse) -> String {
        String::from_utf8_lossy(&response.response.body).into_owned()
    }

    fn authenticated_get(path: &str) -> HandledHttpResponse {
        app().handle_request(
            &request("GET", path, &authenticated_headers(), ""),
            "127.0.0.1",
        )
    }

    fn assert_body_order(body: &str, before: &str, after: &str) {
        let before_index = body
            .find(before)
            .unwrap_or_else(|| panic!("body should contain {before}"));
        let after_index = body
            .find(after)
            .unwrap_or_else(|| panic!("body should contain {after}"));

        assert!(
            before_index < after_index,
            "expected {before} to appear before {after}"
        );
    }

    fn location_header(response: &HandledHttpResponse) -> String {
        response
            .response
            .headers
            .iter()
            .find_map(|(name, value)| (name == "Location").then_some(value.clone()))
            .expect("response should include Location header")
    }

    fn authenticated_headers() -> [(&'static str, &'static str); 2] {
        [
            ("User-Agent", "Firefox/Test"),
            (
                "Cookie",
                "osmap_session=aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
            ),
        ]
    }

    fn authenticated_same_origin_headers() -> [(&'static str, &'static str); 3] {
        [
            ("User-Agent", "Firefox/Test"),
            (
                "Cookie",
                "osmap_session=aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
            ),
            ("Origin", "https://localhost"),
        ]
    }

    fn authenticated_same_origin_referer_headers() -> [(&'static str, &'static str); 3] {
        [
            ("User-Agent", "Firefox/Test"),
            (
                "Cookie",
                "osmap_session=aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
            ),
            ("Referer", "https://localhost/settings"),
        ]
    }

    fn app_for_allowed_host(host: &str) -> BrowserApp<StubGateway> {
        BrowserApp::new(
            HttpPolicy {
                allowed_hosts: vec![host.to_string()],
                ..HttpPolicy::default()
            },
            StubGateway::default(),
        )
    }

    #[test]
    fn response_header_helper_rejects_invalid_header_names() {
        for name in ["", "Bad:Name", "Bad Name", "Bad\tName", "Bad\r\nName"] {
            let response = HttpResponse::text(200, "OK", "body").with_header(name, "value");

            assert_eq!(response.status_code, 500, "{name:?}");
            let bytes = String::from_utf8(response.to_http_bytes()).expect("response is utf-8");
            assert!(!bytes.contains("value\r\n"));
            assert!(bytes.contains("invalid response header"));
        }
    }

    #[test]
    fn response_header_helper_rejects_crlf_header_value_splitting() {
        let injected_cookie_header = ["Set-Cookie", ": injected=1"].concat();
        for (name, value) in [
            ("Location", format!("/x\r\n{injected_cookie_header}")),
            ("Content-Type", "text/html\r\nX-Injected: yes".to_string()),
            (
                "Content-Disposition",
                "attachment; filename=\"report.txt\"\r\nX-Injected: yes".to_string(),
            ),
        ] {
            let response = HttpResponse::text(303, "See Other", "body").with_header(name, &value);

            assert_eq!(response.status_code, 500, "{name}: {value:?}");
            let bytes = String::from_utf8(response.to_http_bytes()).expect("response is utf-8");
            assert!(!bytes.contains(&injected_cookie_header));
            assert!(!bytes.contains("X-Injected: yes"));
            assert!(!bytes.contains(&value));
            assert!(bytes.contains("Cache-Control: no-store\r\n"));
        }
    }

    #[test]
    fn response_header_helper_accepts_expected_safe_headers() {
        let response = HttpResponse::text(303, "See Other", "body")
            .with_header("Location", "/mailboxes")
            .with_header("Content-Type", "text/plain; charset=utf-8")
            .with_header(
                "Set-Cookie",
                "osmap_session=abc; HttpOnly; Secure; SameSite=Strict",
            );

        let bytes = String::from_utf8(response.to_http_bytes()).expect("response is utf-8");

        assert!(bytes.contains("Location: /mailboxes\r\n"));
        assert!(bytes.contains("Content-Type: text/plain; charset=utf-8\r\n"));
        let expected_cookie_header = [
            "Set-Cookie",
            ": osmap_session=abc; HttpOnly; Secure; SameSite=Strict\r\n",
        ]
        .concat();
        assert!(bytes.contains(&expected_cookie_header));
    }

    #[test]
    fn response_serialization_rejects_directly_constructed_invalid_headers() {
        let response = HttpResponse {
            status_code: 200,
            reason_phrase: "OK",
            headers: vec![("X-Test".to_string(), "ok\r\nX-Injected: yes".to_string())],
            body: b"body".to_vec(),
        };

        let bytes = String::from_utf8(response.to_http_bytes()).expect("response is utf-8");

        assert!(bytes.starts_with("HTTP/1.1 500 Internal Server Error\r\n"));
        assert!(!bytes.contains("X-Injected: yes"));
        assert!(!bytes.contains("X-Test: ok"));
        assert!(bytes.contains("invalid response header"));
    }

    #[test]
    fn rejects_requests_with_unconfigured_host() {
        let response = app_for_allowed_host("mail.example.test").handle_request(
            &request_with_host("GET", "/login", Some("attacker.example.test"), &[], ""),
            "127.0.0.1",
        );

        assert_eq!(response.response.status_code, 421);
        assert!(body_text(&response).contains("Host Rejected"));
    }

    #[test]
    fn rejects_routed_requests_without_host() {
        let response = app_for_allowed_host("mail.example.test").handle_request(
            &request_with_host("GET", "/login", None, &[], ""),
            "127.0.0.1",
        );

        assert_eq!(response.response.status_code, 421);
        assert!(body_text(&response).contains("Host Rejected"));
    }

    #[test]
    fn accepts_requests_with_configured_host() {
        let response = app_for_allowed_host("mail.example.test").handle_request(
            &request_with_host("GET", "/login", Some("mail.example.test"), &[], ""),
            "127.0.0.1",
        );

        assert_eq!(response.response.status_code, 200);
        assert!(body_text(&response).contains("OSMAP Login"));
    }

    #[test]
    fn accepts_default_loopback_host_with_default_port() {
        let response = app().handle_request(
            &request_with_host("GET", "/login", Some("localhost:8080"), &[], ""),
            "127.0.0.1",
        );

        assert_eq!(response.response.status_code, 200);
        assert!(body_text(&response).contains("OSMAP Login"));
    }

    #[test]
    fn state_changing_routes_require_origin_matching_configured_host() {
        let response = app_for_allowed_host("mail.example.test").handle_request(
            &request_with_host(
                "POST",
                "/settings",
                Some("mail.example.test"),
                &[
                    ("User-Agent", "Firefox/Test"),
                    (
                        "Cookie",
                        "osmap_session=aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
                    ),
                    ("Origin", "https://mail.example.test"),
                ],
                "csrf_token=fedcba9876543210fedcba9876543210fedcba9876543210fedcba9876543210&archive_mailbox=Archive",
            ),
            "127.0.0.1",
        );

        assert_ne!(response.response.status_code, 403);
    }

    #[test]
    fn rejects_origin_matching_attacker_host_but_not_configured_host() {
        let response = app_for_allowed_host("mail.example.test").handle_request(
            &request_with_host(
                "POST",
                "/settings",
                Some("attacker.example.test"),
                &[
                    ("User-Agent", "Firefox/Test"),
                    (
                        "Cookie",
                        "osmap_session=aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
                    ),
                    ("Origin", "https://attacker.example.test"),
                ],
                "csrf_token=fedcba9876543210fedcba9876543210fedcba9876543210fedcba9876543210&archive_mailbox=Archive",
            ),
            "127.0.0.1",
        );

        assert_eq!(response.response.status_code, 421);
        assert!(body_text(&response).contains("Host Rejected"));
    }

    #[test]
    fn rejects_referer_matching_attacker_host_but_not_configured_host() {
        let response = app_for_allowed_host("mail.example.test").handle_request(
            &request_with_host(
                "POST",
                "/settings",
                Some("mail.example.test"),
                &[
                    ("User-Agent", "Firefox/Test"),
                    (
                        "Cookie",
                        "osmap_session=aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
                    ),
                    ("Referer", "https://attacker.example.test/settings"),
                ],
                "csrf_token=fedcba9876543210fedcba9876543210fedcba9876543210fedcba9876543210&archive_mailbox=Archive",
            ),
            "127.0.0.1",
        );

        assert_eq!(response.response.status_code, 403);
        assert!(body_text(&response).contains("Request Origin Rejected"));
    }

    #[test]
    fn accepts_referer_matching_configured_host() {
        let response = app_for_allowed_host("mail.example.test").handle_request(
            &request_with_host(
                "POST",
                "/settings",
                Some("mail.example.test"),
                &[
                    ("User-Agent", "Firefox/Test"),
                    (
                        "Cookie",
                        "osmap_session=aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
                    ),
                    ("Referer", "https://mail.example.test/settings"),
                ],
                "csrf_token=fedcba9876543210fedcba9876543210fedcba9876543210fedcba9876543210&archive_mailbox=Archive",
            ),
            "127.0.0.1",
        );

        assert_ne!(response.response.status_code, 403);
    }

    #[test]
    fn rejects_http_origin_for_non_loopback_configured_host() {
        let response = app_for_allowed_host("mail.example.test").handle_request(
            &request_with_host(
                "POST",
                "/settings",
                Some("mail.example.test"),
                &[
                    ("User-Agent", "Firefox/Test"),
                    (
                        "Cookie",
                        "osmap_session=aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
                    ),
                    ("Origin", "http://mail.example.test"),
                ],
                "csrf_token=fedcba9876543210fedcba9876543210fedcba9876543210fedcba9876543210&archive_mailbox=Archive",
            ),
            "127.0.0.1",
        );

        assert_eq!(response.response.status_code, 403);
        assert!(body_text(&response).contains("Request Origin Rejected"));
    }

    #[test]
    fn accepts_http_origin_for_loopback_development_host() {
        let response = app_for_allowed_host("localhost:8080").handle_request(
            &request_with_host(
                "POST",
                "/settings",
                Some("localhost:8080"),
                &[
                    ("User-Agent", "Firefox/Test"),
                    (
                        "Cookie",
                        "osmap_session=aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
                    ),
                    ("Origin", "http://localhost:8080"),
                ],
                "csrf_token=fedcba9876543210fedcba9876543210fedcba9876543210fedcba9876543210&archive_mailbox=Archive",
            ),
            "127.0.0.1",
        );

        assert_ne!(response.response.status_code, 403);
    }

    #[test]
    fn healthz_response_includes_plain_text_security_headers() {
        let response = app().handle_request(
            &request_with_host("GET", "/healthz", Some("localhost"), &[], ""),
            "127.0.0.1",
        );

        assert_eq!(response.response.status_code, 200);
        assert_eq!(response.response.body, b"ok\n".to_vec());
        for (name, value) in [
            ("Content-Type", "text/plain; charset=utf-8"),
            ("Cache-Control", "no-store"),
            ("X-Content-Type-Options", "nosniff"),
            ("Cross-Origin-Resource-Policy", "same-origin"),
            ("Referrer-Policy", "no-referrer"),
        ] {
            assert!(
                response
                    .response
                    .headers
                    .iter()
                    .any(|(header_name, header_value)| header_name == name && header_value == value),
                "missing {name}: {value}"
            );
        }
    }

    #[test]
    fn parses_basic_http_requests() {
        let request = parse_http_request(
            "GET /mailbox?name=INBOX HTTP/1.1\r\nHost: localhost\r\nUser-Agent: Firefox/Test\r\nCookie: osmap_session=abc\r\n\r\n",
            &HttpPolicy::default(),
        )
        .expect("request should parse even with an unusable session cookie");

        assert_eq!(
            session_cookie_value(&request, DEFAULT_SESSION_COOKIE_NAME),
            None
        );

        let request = parse_http_request(
            "GET /mailbox?name=INBOX HTTP/1.1\r\nHost: localhost\r\nUser-Agent: Firefox/Test\r\nCookie: osmap_session=aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa\r\n\r\n",
            &HttpPolicy::default(),
        )
        .expect("request should parse");

        assert_eq!(request.method, HttpMethod::Get);
        assert_eq!(request.path, "/mailbox");
        assert_eq!(
            request.query_params.get("name").map(String::as_str),
            Some("INBOX")
        );
        assert_eq!(
            session_cookie_value(&request, DEFAULT_SESSION_COOKIE_NAME).as_deref(),
            Some("aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa")
        );
    }

    #[test]
    fn serves_login_form() {
        let response = app().handle_request(
            &request("GET", "/login", &[("User-Agent", "Firefox/Test")], ""),
            "127.0.0.1",
        );

        assert_eq!(response.response.status_code, 200);
        let body = body_text(&response);
        assert!(body.contains("OSMAP Login"));
        assert!(body.contains("Secure Webmail"));
        assert!(body.contains("2FA Required"));
        assert!(body.contains("Session Secured"));
        assert!(body.contains("totp_code"));
        assert!(!body.contains("Remember this device"));
        assert!(!body.contains("Forgot password"));
    }

    #[test]
    fn login_sets_session_cookie_and_redirects() {
        let response = app().handle_request(
            &request(
                "POST",
                "/login",
                &[("User-Agent", "Firefox/Test")],
                "username=alice%40example.com&password=correct+horse+battery+staple&totp_code=123456",
            ),
            "127.0.0.1",
        );

        assert_eq!(response.response.status_code, 303);
        assert!(response
            .response
            .headers
            .iter()
            .any(|(name, value)| name == "Set-Cookie"
                && value.contains("osmap_session=aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa")));
    }

    #[test]
    fn login_failure_banner_is_identical_for_wrong_password_and_wrong_totp() {
        let app = app();
        let wrong_password_request = request(
            "POST",
            "/login",
            &[("content-type", "application/x-www-form-urlencoded")],
            "username=alice%40example.com&password=wrong&totp_code=123456",
        );
        let wrong_totp_request = request(
            "POST",
            "/login",
            &[("content-type", "application/x-www-form-urlencoded")],
            "username=alice%40example.com&password=correct+horse+battery+staple&totp_code=000000",
        );

        let wrong_password = app.handle_request(&wrong_password_request, "127.0.0.1");
        let wrong_totp = app.handle_request(&wrong_totp_request, "127.0.0.1");
        let wrong_password_body =
            String::from_utf8(wrong_password.response.body).expect("body should be utf-8");
        let wrong_totp_body =
            String::from_utf8(wrong_totp.response.body).expect("body should be utf-8");

        assert_eq!(wrong_password.response.status_code, 401);
        assert_eq!(wrong_totp.response.status_code, 401);
        assert!(wrong_password_body.contains("The supplied credentials were not accepted."));
        assert!(wrong_totp_body.contains("The supplied credentials were not accepted."));
        assert!(!wrong_totp_body.contains("second-factor code was not accepted"));
    }

    #[test]
    fn runtime_gateway_denies_prelocked_login_attempts() {
        let temp_root = temp_dir("osmap-http-login-throttle");
        let context = AuthenticationContext::new(
            AuthenticationPolicy::default(),
            "req-throttle",
            "127.0.0.1",
            "Firefox/Test",
        )
        .expect("context should be valid");
        let throttle_store =
            FileLoginThrottleStore::new(temp_root.join("cache").join("login-throttle"));
        let throttle_key =
            crate::throttle::LoginThrottleKey::new("alice@example.com", &context.remote_addr);
        throttle_store
            .save(
                &throttle_key.key_id,
                &crate::throttle::LoginThrottleRecord {
                    failure_count: 5,
                    window_started_at: 100,
                    last_failure_at: 120,
                    locked_until: Some(10_000_000_000),
                },
            )
            .expect("prelocked throttle record should save");
        let gateway = RuntimeBrowserGateway::for_test(&temp_root);

        let outcome = gateway.login(&context, "alice@example.com", "wrong password", "123456");
        assert_eq!(
            outcome.decision,
            BrowserLoginDecision::Denied {
                public_reason: TOO_MANY_ATTEMPTS_PUBLIC_REASON.to_string(),
            }
        );
        assert!(outcome
            .audit_events
            .iter()
            .any(|event| event.action == "login_throttled"));
    }

    #[test]
    fn runtime_gateway_denies_prelocked_submission_attempts() {
        let temp_root = temp_dir("osmap-http-submission-throttle");
        let context = AuthenticationContext::new(
            AuthenticationPolicy::default(),
            "req-send-throttle",
            "127.0.0.1",
            "Firefox/Test",
        )
        .expect("context should be valid");
        let throttle_store =
            FileLoginThrottleStore::new(temp_root.join("cache").join("submission-throttle"));
        let throttle_key =
            crate::throttle::SubmissionThrottleKey::for_canonical_user_and_remote_addr(
                "alice@example.com",
                &context.remote_addr,
            );
        throttle_store
            .save(
                &throttle_key.key_id,
                &crate::throttle::LoginThrottleRecord {
                    failure_count: 10,
                    window_started_at: 100,
                    last_failure_at: 120,
                    locked_until: Some(10_000_000_000),
                },
            )
            .expect("prelocked submission throttle record should save");
        let gateway = RuntimeBrowserGateway::for_test(&temp_root);
        let validated_session = ValidatedSession {
            record: crate::session::SessionRecord {
                session_id: "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef"
                    .to_string(),
                csrf_token: "fedcba9876543210fedcba9876543210fedcba9876543210fedcba9876543210"
                    .to_string(),
                canonical_username: "alice@example.com".to_string(),
                issued_at: 100,
                expires_at: 200,
                last_seen_at: 100,
                revoked_at: None,
                remote_addr: "127.0.0.1".to_string(),
                user_agent: "Firefox/Test".to_string(),
                factor: RequiredSecondFactor::Totp,
            },
            audit_event: LogEvent::new(
                LogLevel::Info,
                EventCategory::Session,
                "stub_session_validated",
                "stub session validated",
            ),
        };

        let outcome = gateway.send_message(
            &context,
            &validated_session,
            BrowserSendRequest {
                protection: crate::send::ProtectionIntent::default(),
                send_intent: &crate::send_journal::mint_intent(gateway.send_clock()).unwrap(),
                draft_id: None,
                draft_revision: None,
                reply_thread: None,
                recipients: "bob@example.com",
                cc_recipients: "",
                bcc_recipients: "",
                subject: "Test",
                body: "Hello",
                body_format: crate::compose_format::BodyFormat::Plain,
                attachments: &[],
            },
        );
        match outcome.decision {
            BrowserSendDecision::Denied {
                public_reason,
                retry_after_seconds: Some(retry_after_seconds),
            } => {
                assert_eq!(public_reason, TOO_MANY_SUBMISSIONS_PUBLIC_REASON);
                assert!(retry_after_seconds > 0);
            }
            other => panic!("unexpected send decision: {other:?}"),
        }
        assert!(outcome
            .audit_events
            .iter()
            .any(|event| event.action == "submission_throttled"));
    }

    #[test]
    fn runtime_gateway_denies_prelocked_message_move_attempts() {
        let temp_root = temp_dir("osmap-http-message-move-throttle");
        let context = AuthenticationContext::new(
            AuthenticationPolicy::default(),
            "req-move-throttle",
            "127.0.0.1",
            "Firefox/Test",
        )
        .expect("context should be valid");
        let throttle_store =
            FileLoginThrottleStore::new(temp_root.join("cache").join("message-move-throttle"));
        let throttle_key =
            crate::throttle::MessageMoveThrottleKey::for_canonical_user_and_remote_addr(
                "alice@example.com",
                &context.remote_addr,
            );
        throttle_store
            .save(
                &throttle_key.key_id,
                &crate::throttle::LoginThrottleRecord {
                    failure_count: 20,
                    window_started_at: 100,
                    last_failure_at: 120,
                    locked_until: Some(10_000_000_000),
                },
            )
            .expect("prelocked move throttle record should save");
        let gateway = RuntimeBrowserGateway::for_test(&temp_root);
        let validated_session = ValidatedSession {
            record: crate::session::SessionRecord {
                session_id: "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef"
                    .to_string(),
                csrf_token: "fedcba9876543210fedcba9876543210fedcba9876543210fedcba9876543210"
                    .to_string(),
                canonical_username: "alice@example.com".to_string(),
                issued_at: 100,
                expires_at: 200,
                last_seen_at: 100,
                revoked_at: None,
                remote_addr: "127.0.0.1".to_string(),
                user_agent: "Firefox/Test".to_string(),
                factor: RequiredSecondFactor::Totp,
            },
            audit_event: LogEvent::new(
                LogLevel::Info,
                EventCategory::Session,
                "stub_session_validated",
                "stub session validated",
            ),
        };

        let outcome = gateway.move_message(
            &context,
            &validated_session,
            &MessageMoveRequest::new(
                MessageMovePolicy::default(),
                "INBOX",
                "Archive",
                9,
                crate::message_metadata::MessageVersion::new("a".repeat(32), "fixture-9".into())
                    .unwrap(),
            )
            .unwrap(),
        );
        match outcome.decision {
            BrowserMessageMoveDecision::Denied {
                public_reason,
                retry_after_seconds: Some(retry_after_seconds),
            } => {
                assert_eq!(public_reason, TOO_MANY_MESSAGE_MOVES_PUBLIC_REASON);
                assert!(retry_after_seconds > 0);
            }
            other => panic!("unexpected move decision: {other:?}"),
        }
        assert!(outcome
            .audit_events
            .iter()
            .any(|event| event.action == "message_move_throttled"));
    }

    #[test]
    fn login_rejects_unsupported_form_content_type() {
        let response = app().handle_request(
            &request(
                "POST",
                "/login",
                &[
                    ("User-Agent", "Firefox/Test"),
                    ("Content-Type", "application/json"),
                ],
                "{\"username\":\"alice@example.com\"}",
            ),
            "127.0.0.1",
        );

        assert_eq!(response.response.status_code, 400);
        assert!(body_text(&response).contains("content type was not supported"));
    }

    #[test]
    fn mailbox_page_requires_valid_session() {
        let response = app().handle_request(
            &request("GET", "/mailboxes", &[("User-Agent", "Firefox/Test")], ""),
            "127.0.0.1",
        );

        assert_eq!(response.response.status_code, 303);
        assert!(response
            .response
            .headers
            .iter()
            .any(|(name, value)| name == "Location" && value == "/login"));
    }

    #[test]
    fn mailbox_page_renders_for_valid_session() {
        let response = app().handle_request(
            &request(
                "GET",
                "/mailboxes",
                &[
                    ("User-Agent", "Firefox/Test"),
                    (
                        "Cookie",
                        "osmap_session=aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
                    ),
                ],
                "",
            ),
            "127.0.0.1",
        );

        assert_eq!(response.response.status_code, 200);
        let body = body_text(&response);
        assert!(body.contains("alice@example.com"));
        for name in ["INBOX", "INBOX.Projects", "Drafts"] {
            assert!(body.contains(&format!("<strong>{name}</strong>")));
            assert!(body.contains(&format!("href=\"/mailbox?name={name}\"")));
        }
        for name in ["dovecot", "dovecot.sieve"] {
            assert!(!body.contains(&format!("href=\"/mailbox?name={name}\"")));
            assert!(!body.contains(&format!("<strong>{name}</strong>")));
            assert!(!body.contains(&format!("value=\"{name}\"")));
        }
    }

    #[test]
    fn mailbox_message_list_renders_search_form() {
        let response = app().handle_request(
            &request(
                "GET",
                "/mailbox?name=INBOX",
                &[
                    ("User-Agent", "Firefox/Test"),
                    (
                        "Cookie",
                        "osmap_session=aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
                    ),
                ],
                "",
            ),
            "127.0.0.1",
        );

        assert_eq!(response.response.status_code, 200);
        let body = body_text(&response);
        assert!(body.contains("Search all mailboxes"));
        assert!(body.contains("action=\"/search\""));
        assert!(body.contains("name=\"mailbox\" value=\"INBOX\""));
        assert!(body.contains("name=\"scope\" value=\"all\""));
        assert!(body.contains("Archive shortcut sends messages"));
        assert!(body.contains("name=\"action\" value=\"archive\""));
        assert!(body.contains(">Archive</button>"));
        assert!(body.contains("aria-label=\"Sort by Subject ascending\""));
        assert!(body.contains("aria-label=\"Sort by From ascending\""));
        assert!(body.contains("Quarterly report"));
        assert!(body.contains("Alice &lt;alice@example.com&gt;"));
    }

    #[test]
    fn mailbox_message_list_defaults_to_newest_received_first() {
        let response = authenticated_get("/mailbox?name=INBOX");
        assert_eq!(response.response.status_code, 200);
        assert_body_order(&body_text(&response), "Follow-up", "Quarterly report");
    }

    #[test]
    fn mailbox_message_list_sorts_by_uid() {
        let ascending = authenticated_get("/mailbox?name=INBOX&sort=uid&dir=asc");
        assert_eq!(ascending.response.status_code, 200);
        assert_body_order(&body_text(&ascending), "Quarterly report", "Follow-up");

        let descending = authenticated_get("/mailbox?name=INBOX&sort=uid&dir=desc");
        assert_eq!(descending.response.status_code, 200);
        assert_body_order(&body_text(&descending), "Follow-up", "Quarterly report");
    }

    #[test]
    fn mailbox_message_list_sorts_by_subject() {
        let ascending = authenticated_get("/mailbox?name=INBOX&sort=subject&dir=asc");
        assert_eq!(ascending.response.status_code, 200);
        assert_body_order(&body_text(&ascending), "Follow-up", "Quarterly report");

        let descending = authenticated_get("/mailbox?name=INBOX&sort=subject&dir=desc");
        assert_eq!(descending.response.status_code, 200);
        assert_body_order(&body_text(&descending), "Quarterly report", "Follow-up");
    }

    #[test]
    fn mailbox_message_list_sorts_by_from() {
        let ascending = authenticated_get("/mailbox?name=INBOX&sort=from&dir=asc");
        assert_eq!(ascending.response.status_code, 200);
        assert_body_order(&body_text(&ascending), "Quarterly report", "Follow-up");

        let descending = authenticated_get("/mailbox?name=INBOX&sort=from&dir=desc");
        assert_eq!(descending.response.status_code, 200);
        assert_body_order(&body_text(&descending), "Follow-up", "Quarterly report");
    }

    #[test]
    fn mailbox_message_list_sorts_by_received() {
        let ascending = authenticated_get("/mailbox?name=INBOX&sort=received&dir=asc");
        assert_eq!(ascending.response.status_code, 200);
        assert_body_order(&body_text(&ascending), "Quarterly report", "Follow-up");

        let descending = authenticated_get("/mailbox?name=INBOX&sort=received&dir=desc");
        assert_eq!(descending.response.status_code, 200);
        assert_body_order(&body_text(&descending), "Follow-up", "Quarterly report");
    }

    #[test]
    fn mailbox_message_list_sorts_by_flags() {
        let ascending = authenticated_get("/mailbox?name=INBOX&sort=flags&dir=asc");
        assert_eq!(ascending.response.status_code, 200);
        assert_body_order(&body_text(&ascending), "Follow-up", "Quarterly report");

        let descending = authenticated_get("/mailbox?name=INBOX&sort=flags&dir=desc");
        assert_eq!(descending.response.status_code, 200);
        assert_body_order(&body_text(&descending), "Quarterly report", "Follow-up");
    }

    #[test]
    fn mailbox_message_list_sorts_by_size() {
        let ascending = authenticated_get("/mailbox?name=INBOX&sort=size&dir=asc");
        assert_eq!(ascending.response.status_code, 200);
        assert_body_order(&body_text(&ascending), "Quarterly report", "Follow-up");

        let descending = authenticated_get("/mailbox?name=INBOX&sort=size&dir=desc");
        assert_eq!(descending.response.status_code, 200);
        assert_body_order(&body_text(&descending), "Follow-up", "Quarterly report");
    }

    #[test]
    fn mailbox_message_list_ignores_invalid_sort_values() {
        let response = authenticated_get("/mailbox?name=INBOX&sort=mailbox_name&dir=desc");
        assert_eq!(response.response.status_code, 200);
        let body = body_text(&response);
        assert_body_order(&body, "Follow-up", "Quarterly report");
        assert!(!body.contains("UID ↓"));
        assert!(!body.contains("Subject ↓"));
        assert!(!body.contains("From ↓"));
        assert!(body.contains("Received ↓"));
        assert!(!body.contains("Flags ↓"));
        assert!(!body.contains("Size ↓"));
    }

    #[test]
    fn mailbox_message_list_defaults_invalid_sort_direction() {
        let response = authenticated_get("/mailbox?name=INBOX&sort=subject&dir=sideways");
        assert_eq!(response.response.status_code, 200);
        let body = body_text(&response);
        assert_body_order(&body, "Follow-up", "Quarterly report");
        assert!(body.contains("Subject ↑"));
    }

    #[test]
    fn mailbox_sort_links_preserve_mailbox_name_and_search_parameters() {
        let response = authenticated_get(
            "/mailbox?name=Archive%2F2026&q=quarterly+report&scope=all&sort=subject&dir=asc",
        );
        assert_eq!(response.response.status_code, 200);
        let body = body_text(&response);

        assert!(body.contains(
            "/mailbox?name=Archive%2F2026&amp;q=quarterly+report&amp;scope=all&amp;sort=subject&amp;dir=desc"
        ));
        assert!(body.contains(
            "/mailbox?name=Archive%2F2026&amp;q=quarterly+report&amp;scope=all&amp;sort=received&amp;dir=desc"
        ));
        assert!(body.contains("Subject ↑"));
    }

    #[test]
    fn search_sort_links_preserve_mailbox_name_and_query() {
        let response = authenticated_get(
            "/search?mailbox=INBOX&q=quarterly+report&field=subject&sort=uid&dir=asc",
        );
        assert_eq!(response.response.status_code, 200);
        let body = body_text(&response);

        assert!(body.contains(
            "/search?mailbox=INBOX&amp;q=quarterly+report&amp;field=subject&amp;sort=uid&amp;dir=desc"
        ));
        assert!(body.contains(
            "/search?mailbox=INBOX&amp;q=quarterly+report&amp;field=subject&amp;sort=received&amp;dir=desc"
        ));
        assert!(body.contains("UID ↑"));
        assert!(body.contains("<option value=\"subject\" selected>Subject</option>"));
    }

    #[test]
    fn search_page_sorts_results_by_supported_columns() {
        for (column, asc_order, desc_order) in [
            (
                "uid",
                ["Search Alpha", "Search Zulu", "Search Middle"],
                ["Search Middle", "Search Zulu", "Search Alpha"],
            ),
            (
                "subject",
                ["Search Alpha", "Search Middle", "Search Zulu"],
                ["Search Zulu", "Search Middle", "Search Alpha"],
            ),
            (
                "from",
                ["Search Zulu", "Search Alpha", "Search Middle"],
                ["Search Middle", "Search Alpha", "Search Zulu"],
            ),
            (
                "received",
                ["Search Alpha", "Search Zulu", "Search Middle"],
                ["Search Middle", "Search Zulu", "Search Alpha"],
            ),
            (
                "flags",
                ["Search Alpha", "Search Zulu", "Search Middle"],
                ["Search Middle", "Search Zulu", "Search Alpha"],
            ),
            (
                "size",
                ["Search Alpha", "Search Zulu", "Search Middle"],
                ["Search Middle", "Search Zulu", "Search Alpha"],
            ),
        ] {
            let ascending =
                authenticated_get(&format!("/search?q=searchsort&sort={column}&dir=asc"));
            assert_eq!(ascending.response.status_code, 200);
            let ascending_body = body_text(&ascending);
            assert_body_order(&ascending_body, asc_order[0], asc_order[1]);
            assert_body_order(&ascending_body, asc_order[1], asc_order[2]);

            let descending =
                authenticated_get(&format!("/search?q=searchsort&sort={column}&dir=desc"));
            assert_eq!(descending.response.status_code, 200);
            let descending_body = body_text(&descending);
            assert_body_order(&descending_body, desc_order[0], desc_order[1]);
            assert_body_order(&descending_body, desc_order[1], desc_order[2]);
        }
    }

    #[test]
    fn search_page_ignores_invalid_sort_values_and_defaults_invalid_direction() {
        let invalid_sort = authenticated_get("/search?q=searchsort&sort=mailbox_name&dir=desc");
        assert_eq!(invalid_sort.response.status_code, 200);
        let invalid_sort_body = body_text(&invalid_sort);
        assert_body_order(&invalid_sort_body, "Search Middle", "Search Zulu");
        assert_body_order(&invalid_sort_body, "Search Zulu", "Search Alpha");
        assert!(invalid_sort_body.contains("Received ↓"));

        let invalid_dir = authenticated_get("/search?q=searchsort&sort=subject&dir=sideways");
        assert_eq!(invalid_dir.response.status_code, 200);
        let invalid_dir_body = body_text(&invalid_dir);
        assert_body_order(&invalid_dir_body, "Search Alpha", "Search Middle");
        assert_body_order(&invalid_dir_body, "Search Middle", "Search Zulu");
        assert!(invalid_dir_body.contains("Subject ↑"));
    }

    #[test]
    fn search_page_applies_whitelisted_field_refinements() {
        let all = authenticated_get("/search?q=fieldfilter");
        assert_eq!(all.response.status_code, 200);
        let all_body = body_text(&all);
        assert!(all_body.contains("All field selected"));
        assert!(all_body.contains("<option value=\"all\" selected>All message text</option>"));
        assert!(all_body.contains(
            "/search?scope=all&amp;q=fieldfilter&amp;field=all&amp;sort=uid&amp;dir=asc"
        ));

        let subject = authenticated_get("/search?q=fieldfilter&field=subject");
        assert_eq!(subject.response.status_code, 200);
        let subject_body = body_text(&subject);
        assert!(subject_body.contains("Subject field selected"));
        assert!(subject_body.contains("<option value=\"subject\" selected>Subject</option>"));

        let from = authenticated_get("/search?q=fieldfilter&field=from");
        assert_eq!(from.response.status_code, 200);
        let from_body = body_text(&from);
        assert!(from_body.contains("From field selected"));
        assert!(from_body.contains("<option value=\"from\" selected>From</option>"));
    }

    #[test]
    fn search_page_rejects_invalid_field_values() {
        let response = authenticated_get("/search?q=fieldfilter&field=to");
        assert_eq!(response.response.status_code, 400);
        let body = body_text(&response);
        assert!(body.contains("selected search field is not supported"));
        assert!(response
            .audit_events
            .iter()
            .any(|event| event.action == "http_search_field_rejected"));
    }

    #[test]
    fn search_page_renders_backend_results_for_valid_session() {
        let response = app().handle_request(
            &request(
                "GET",
                "/search?mailbox=INBOX&q=quarterly+report",
                &[
                    ("User-Agent", "Firefox/Test"),
                    (
                        "Cookie",
                        "osmap_session=aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
                    ),
                ],
                "",
            ),
            "127.0.0.1",
        );

        assert_eq!(response.response.status_code, 200);
        let body = body_text(&response);
        assert!(body.contains("<h1>Search</h1>"));
        assert!(body.contains("<h2 class=\"section-title sr-only\">Search Results</h2>"));
        assert_eq!(body.matches("<h1").count(), 1);
        assert!(body.contains("Quarterly report"));
        assert!(body.contains("Alice &lt;alice@example.com&gt;"));
        assert!(body.contains("/message?mailbox=INBOX&amp;uid=17"));
        assert!(body.contains("class=\"search-scope\">INBOX"));
    }

    #[test]
    fn search_budget_exhaustion_returns_retry_after_without_blocking_login() {
        let policy = HttpPolicy {
            search_worker_budget: 1,
            ..HttpPolicy::default()
        };
        let app = app_with_policy(policy);
        let held_budget = app
            .request_budgets
            .search_workers
            .try_acquire()
            .expect("test should hold the only search slot");

        let response = app.handle_request(
            &request(
                "GET",
                "/search?mailbox=INBOX&q=quarterly+report",
                &authenticated_headers(),
                "",
            ),
            "127.0.0.1",
        );

        assert_eq!(response.response.status_code, 503);
        assert!(response
            .response
            .headers
            .iter()
            .any(|(name, value)| name == "Retry-After" && value == "1"));
        assert!(response.audit_events.iter().any(|event| event.action
            == "request_budget_exhausted"
            && event
                .fields
                .iter()
                .any(|field| field.key == "budget_name" && field.value == "search_workers")));

        let login_response = app.handle_request(
            &request("GET", "/login", &[("User-Agent", "Firefox/Test")], ""),
            "127.0.0.1",
        );
        assert_eq!(login_response.response.status_code, 200);

        drop(held_budget);
        let response_after_release = app.handle_request(
            &request(
                "GET",
                "/search?mailbox=INBOX&q=quarterly+report",
                &authenticated_headers(),
                "",
            ),
            "127.0.0.1",
        );
        assert_eq!(response_after_release.response.status_code, 200);
    }

    #[test]
    fn batch_search_backend_refusal_releases_browser_worker_and_keeps_login_available() {
        let app = app_with_policy(HttpPolicy {
            search_worker_budget: 1,
            ..HttpPolicy::default()
        });
        let mut headers = authenticated_headers();
        for (name, value) in &mut headers {
            if *name == "User-Agent" {
                *value = "OSMAP/StateFailure";
            }
        }
        let response = app.handle_request(
            &request("GET", "/search?q=needle", &headers, ""),
            "127.0.0.1",
        );
        assert_eq!(response.response.status_code, 503);
        assert!(!response
            .audit_events
            .iter()
            .any(|event| event.action == "request_budget_exhausted"));
        let released = app
            .request_budgets
            .search_workers
            .try_acquire()
            .expect("backend refusal must release its only worker slot");
        let login = app.handle_request(
            &request("GET", "/login", &[("User-Agent", "Firefox/Test")], ""),
            "127.0.0.1",
        );
        assert_eq!(login.response.status_code, 200);
        drop(released);
        let success = app.handle_request(
            &request(
                "GET",
                "/search?q=quarterly+report",
                &authenticated_headers(),
                "",
            ),
            "127.0.0.1",
        );
        assert_eq!(success.response.status_code, 200);
        assert!(body_text(&success).contains("Quarterly report"));
    }

    #[test]
    fn all_mailbox_search_fanout_uses_search_budget() {
        let policy = HttpPolicy {
            search_worker_budget: 1,
            ..HttpPolicy::default()
        };
        let app = app_with_policy(policy);
        let held_budget = app
            .request_budgets
            .search_workers
            .try_acquire()
            .expect("test should hold the only search slot");

        let response = app.handle_request(
            &request(
                "GET",
                "/search?q=quarterly+report",
                &authenticated_headers(),
                "",
            ),
            "127.0.0.1",
        );

        assert_eq!(response.response.status_code, 503);
        assert!(response.audit_events.iter().any(|event| {
            event.action == "request_budget_exhausted"
                && event
                    .fields
                    .iter()
                    .any(|field| field.key == "budget_name" && field.value == "search_workers")
                && event
                    .fields
                    .iter()
                    .any(|field| field.key == "route_class" && field.value == "message_search")
        }));

        drop(held_budget);
        let response_after_release = app.handle_request(
            &request(
                "GET",
                "/search?q=quarterly+report",
                &authenticated_headers(),
                "",
            ),
            "127.0.0.1",
        );
        assert_eq!(response_after_release.response.status_code, 200);
    }

    #[test]
    fn compose_source_loading_uses_mailbox_budget() {
        let policy = HttpPolicy {
            mailbox_worker_budget: 1,
            ..HttpPolicy::default()
        };
        let app = app_with_policy(policy);
        let held_budget = app
            .request_budgets
            .mailbox_workers
            .try_acquire()
            .expect("test should hold the only mailbox slot");

        let response = app.handle_request(
            &request(
                "GET",
                "/compose?mode=reply&mailbox=INBOX&uid=9",
                &authenticated_headers(),
                "",
            ),
            "127.0.0.1",
        );

        assert_eq!(response.response.status_code, 503);
        assert!(response.audit_events.iter().any(|event| {
            event.action == "request_budget_exhausted"
                && event
                    .fields
                    .iter()
                    .any(|field| field.key == "budget_name" && field.value == "mailbox_workers")
                && event
                    .fields
                    .iter()
                    .any(|field| field.key == "route_class" && field.value == "compose_source")
        }));

        drop(held_budget);
        let response_after_release = app.handle_request(
            &request(
                "GET",
                "/compose?mode=reply&mailbox=INBOX&uid=9",
                &authenticated_headers(),
                "",
            ),
            "127.0.0.1",
        );
        assert_eq!(response_after_release.response.status_code, 200);
    }

    #[test]
    fn message_move_uses_mailbox_budget() {
        let policy = HttpPolicy {
            mailbox_worker_budget: 1,
            ..HttpPolicy::default()
        };
        let app = app_with_policy(policy);
        let held_budget = app
            .request_budgets
            .mailbox_workers
            .try_acquire()
            .expect("test should hold the only mailbox slot");

        let response = app.handle_request(
            &request(
                "POST",
                "/message/move",
                &authenticated_same_origin_headers(),
                &move_form("csrf_token=fedcba9876543210fedcba9876543210fedcba9876543210fedcba9876543210&mailbox=INBOX&uid=9&destination_mailbox=Archive%2F2026", "move"),
            ),
            "127.0.0.1",
        );

        assert_eq!(response.response.status_code, 503);
        assert!(response.audit_events.iter().any(|event| {
            event.action == "request_budget_exhausted"
                && event
                    .fields
                    .iter()
                    .any(|field| field.key == "budget_name" && field.value == "mailbox_workers")
                && event
                    .fields
                    .iter()
                    .any(|field| field.key == "route_class" && field.value == "message_move")
        }));

        drop(held_budget);
        let response_after_release = app.handle_request(
            &request(
                "POST",
                "/message/move",
                &authenticated_same_origin_headers(),
                &move_form("csrf_token=fedcba9876543210fedcba9876543210fedcba9876543210fedcba9876543210&mailbox=INBOX&uid=9&destination_mailbox=Archive%2F2026", "move"),
            ),
            "127.0.0.1",
        );
        assert_eq!(response_after_release.response.status_code, 303);
    }

    #[test]
    fn bulk_message_move_uses_mailbox_budget() {
        let policy = HttpPolicy {
            mailbox_worker_budget: 1,
            ..HttpPolicy::default()
        };
        let app = app_with_policy(policy);
        let held_budget = app
            .request_budgets
            .mailbox_workers
            .try_acquire()
            .expect("test should hold the only mailbox slot");

        let response = app.handle_request(
            &request(
                "POST",
                "/messages/move",
                &authenticated_same_origin_headers(),
                &move_form("csrf_token=fedcba9876543210fedcba9876543210fedcba9876543210fedcba9876543210&mailbox=INBOX&destination_mailbox=INBOX.Projects&uid_9=9", "move"),
            ),
            "127.0.0.1",
        );

        assert_eq!(response.response.status_code, 503);
        assert!(response.audit_events.iter().any(|event| {
            event.action == "request_budget_exhausted"
                && event
                    .fields
                    .iter()
                    .any(|field| field.key == "budget_name" && field.value == "mailbox_workers")
                && event
                    .fields
                    .iter()
                    .any(|field| field.key == "route_class" && field.value == "bulk_message_move")
        }));

        drop(held_budget);
        let response_after_release = app.handle_request(
            &request(
                "POST",
                "/messages/move",
                &authenticated_same_origin_headers(),
                &move_form("csrf_token=fedcba9876543210fedcba9876543210fedcba9876543210fedcba9876543210&mailbox=INBOX&destination_mailbox=INBOX.Projects&uid_9=9", "move"),
            ),
            "127.0.0.1",
        );
        assert_eq!(response_after_release.response.status_code, 303);
    }

    #[test]
    fn bulk_archive_uses_mailbox_budget() {
        let policy = HttpPolicy {
            mailbox_worker_budget: 1,
            ..HttpPolicy::default()
        };
        let app = app_with_policy(policy);
        let held_budget = app
            .request_budgets
            .mailbox_workers
            .try_acquire()
            .expect("test should hold the only mailbox slot");

        let response = app.handle_request(
            &request(
                "POST",
                "/messages/archive",
                &authenticated_same_origin_headers(),
                &move_form("csrf_token=fedcba9876543210fedcba9876543210fedcba9876543210fedcba9876543210&mailbox=INBOX&destination_mailbox=Archive%2F2026&uid_9=9", "archive"),
            ),
            "127.0.0.1",
        );

        assert_eq!(response.response.status_code, 503);
        assert!(response.audit_events.iter().any(|event| {
            event.action == "request_budget_exhausted"
                && event
                    .fields
                    .iter()
                    .any(|field| field.key == "budget_name" && field.value == "mailbox_workers")
                && event.fields.iter().any(|field| {
                    field.key == "route_class" && field.value == "bulk_message_archive"
                })
        }));

        drop(held_budget);
        let response_after_release = app.handle_request(
            &request(
                "POST",
                "/messages/archive",
                &authenticated_same_origin_headers(),
                &move_form("csrf_token=fedcba9876543210fedcba9876543210fedcba9876543210fedcba9876543210&mailbox=INBOX&destination_mailbox=Archive%2F2026&uid_9=9", "archive"),
            ),
            "127.0.0.1",
        );
        assert_eq!(response_after_release.response.status_code, 303);
    }

    #[test]
    fn attachment_download_uses_mailbox_budget() {
        let policy = HttpPolicy {
            mailbox_worker_budget: 1,
            ..HttpPolicy::default()
        };
        let app = app_with_policy(policy);
        let held_budget = app
            .request_budgets
            .mailbox_workers
            .try_acquire()
            .expect("test should hold the only mailbox slot");

        let response = app.handle_request(
            &request(
                "GET",
                "/attachment?mailbox=INBOX&uid=9&part=1.2",
                &authenticated_headers(),
                "",
            ),
            "127.0.0.1",
        );

        assert_eq!(response.response.status_code, 503);
        assert!(response.audit_events.iter().any(|event| {
            event.action == "request_budget_exhausted"
                && event
                    .fields
                    .iter()
                    .any(|field| field.key == "budget_name" && field.value == "mailbox_workers")
                && event
                    .fields
                    .iter()
                    .any(|field| field.key == "route_class" && field.value == "attachment_download")
        }));

        drop(held_budget);
        let response_after_release = app.handle_request(
            &request(
                "GET",
                "/attachment?mailbox=INBOX&uid=9&part=1.2",
                &authenticated_headers(),
                "",
            ),
            "127.0.0.1",
        );
        assert_eq!(response_after_release.response.status_code, 200);
    }

    #[test]
    fn auth_budget_exhaustion_returns_retry_after_without_running_login() {
        let policy = HttpPolicy {
            auth_worker_budget: 1,
            ..HttpPolicy::default()
        };
        let app = app_with_policy(policy);
        let held_budget = app
            .request_budgets
            .auth_workers
            .try_acquire()
            .expect("test should hold the only auth slot");

        let response = app.handle_request(
            &request(
                "POST",
                "/login",
                &[("content-type", "application/x-www-form-urlencoded")],
                "username=alice%40example.com&password=correct+horse+battery+staple&totp_code=123456",
            ),
            "127.0.0.1",
        );

        assert_eq!(response.response.status_code, 503);
        assert!(response
            .response
            .headers
            .iter()
            .any(|(name, value)| name == "Retry-After" && value == "1"));
        assert!(response.audit_events.iter().any(|event| {
            event.action == "request_budget_exhausted"
                && event
                    .fields
                    .iter()
                    .any(|field| field.key == "budget_name" && field.value == "auth_workers")
                && !event
                    .fields
                    .iter()
                    .any(|field| field.key == "canonical_username")
        }));

        drop(held_budget);
        let response_after_release = app.handle_request(
            &request(
                "POST",
                "/login",
                &[("content-type", "application/x-www-form-urlencoded")],
                "username=alice%40example.com&password=correct+horse+battery+staple&totp_code=123456",
            ),
            "127.0.0.1",
        );
        assert_eq!(response_after_release.response.status_code, 303);
    }

    #[test]
    fn send_budget_exhaustion_returns_retry_after_after_session_validation() {
        let policy = HttpPolicy {
            send_worker_budget: 1,
            ..HttpPolicy::default()
        };
        let app = app_with_policy(policy);
        let held_budget = app
            .request_budgets
            .send_workers
            .try_acquire()
            .expect("test should hold the only send slot");

        let response = app.handle_request(
            &native_compose_request(&app,
                "POST",
                "/send",
                &authenticated_same_origin_headers(),
                "csrf_token=fedcba9876543210fedcba9876543210fedcba9876543210fedcba9876543210&to=bob%40example.com&subject=Test&body=Hello",
            ),
            "127.0.0.1",
        );

        assert_eq!(response.response.status_code, 503);
        assert!(response
            .response
            .headers
            .iter()
            .any(|(name, value)| name == "Retry-After" && value == "1"));
        assert!(response.audit_events.iter().any(|event| {
            event.action == "request_budget_exhausted"
                && event
                    .fields
                    .iter()
                    .any(|field| field.key == "budget_name" && field.value == "send_workers")
                && event.fields.iter().any(|field| {
                    field.key == "canonical_username" && field.value == "alice@example.com"
                })
        }));

        drop(held_budget);
        let response_after_release = app.handle_request(
            &native_compose_request(&app,
                "POST",
                "/send",
                &authenticated_same_origin_headers(),
                "csrf_token=fedcba9876543210fedcba9876543210fedcba9876543210fedcba9876543210&to=bob%40example.com&subject=Test&body=Hello",
            ),
            "127.0.0.1",
        );
        assert_eq!(response_after_release.response.status_code, 303);
    }

    #[test]
    fn search_budget_events_do_not_log_bearer_or_csrf_tokens() {
        let policy = HttpPolicy {
            search_worker_budget: 1,
            ..HttpPolicy::default()
        };
        let app = app_with_policy(policy);
        let _held_budget = app
            .request_budgets
            .search_workers
            .try_acquire()
            .expect("test should hold the only search slot");

        let response = app.handle_request(
            &request(
                "GET",
                "/search?mailbox=INBOX&q=quarterly+report",
                &authenticated_headers(),
                "",
            ),
            "127.0.0.1",
        );
        let logger = Logger::new(crate::config::LogFormat::Text, LogLevel::Debug);
        let rendered_events = response
            .audit_events
            .iter()
            .map(|event| logger.render_with_timestamp(event, 1000))
            .collect::<Vec<_>>()
            .join("\n");

        assert!(!rendered_events
            .contains("aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"));
        assert!(!rendered_events
            .contains("fedcba9876543210fedcba9876543210fedcba9876543210fedcba9876543210"));
        assert!(rendered_events.contains("request_budget_exhausted"));
        assert!(rendered_events.contains("canonical_username=\"alice@example.com\""));
    }

    #[test]
    fn search_page_missing_query_renders_native_landing_without_backend_call() {
        let response = app().handle_request(
            &request(
                "GET",
                "/search?mailbox=INBOX",
                &[
                    ("User-Agent", "Firefox/Test"),
                    (
                        "Cookie",
                        "osmap_session=aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
                    ),
                ],
                "",
            ),
            "127.0.0.1",
        );

        assert_eq!(response.response.status_code, 200);
        assert!(body_text(&response).contains("Enter keywords to search your mail."));
        assert!(body_text(&response).contains("id=\"search-query\""));
        assert!(!format!("{:?}", response.audit_events).contains("stub_message_search"));
    }

    #[test]
    fn search_page_rejects_wrong_owner_without_foreign_values() {
        let response = app().handle_request(&request("GET", "/search?q=quarterly", &[
            ("User-Agent", "OSMAP/SearchWrongOwner"),
            ("Cookie", "osmap_session=aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"),
        ], ""), "127.0.0.1");
        assert_eq!(response.response.status_code, 503);
        for value in ["foreign@example.test", "ForeignFolder", "foreign-secret"] {
            assert!(!body_text(&response).contains(value));
        }
        assert_eq!(
            response
                .audit_events
                .iter()
                .filter(|event| event.action == "request_budget_released")
                .count(),
            1
        );
    }

    #[test]
    fn search_page_blank_query_authenticates_and_validates_before_landing() {
        let unauthenticated =
            app().handle_request(&request("GET", "/search", &[], ""), "127.0.0.1");
        assert_ne!(unauthenticated.response.status_code, 200);
        for (path, status) in [
            ("/search?q=+++", 200),
            ("/search?q=&field=unsupported", 400),
            ("/search?q=&after=invalid", 400),
            ("/search?q=%0A", 400),
        ] {
            let response = app().handle_request(&request("GET", path, &[("Cookie", "osmap_session=aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa")], ""), "127.0.0.1");
            assert_eq!(response.response.status_code, status, "{path}");
            assert!(!format!("{:?}", response.audit_events).contains("stub_message_search"));
        }
    }

    #[test]
    fn search_page_rejects_unknown_mailbox_cleanly() {
        let response = app().handle_request(
            &request(
                "GET",
                "/search?mailbox=MissingArchive&q=quarterly+report",
                &[
                    ("User-Agent", "Firefox/Test"),
                    (
                        "Cookie",
                        "osmap_session=aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
                    ),
                ],
                "",
            ),
            "127.0.0.1",
        );

        assert_eq!(response.response.status_code, 400);
        assert!(body_text(&response).contains("selected mailbox does not exist"));
    }

    #[test]
    fn mailboxes_page_renders_global_search_form() {
        let response = app().handle_request(
            &request(
                "GET",
                "/mailboxes",
                &[
                    ("User-Agent", "Firefox/Test"),
                    (
                        "Cookie",
                        "osmap_session=aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
                    ),
                ],
                "",
            ),
            "127.0.0.1",
        );

        assert_eq!(response.response.status_code, 200);
        let body = body_text(&response);
        assert!(body.contains("Search all mailboxes"));
        assert!(body.contains("action=\"/search\""));
        assert!(body.contains("name=\"field\""));
        assert!(!body.contains("name=\"mailbox\""));
    }

    #[test]
    fn search_page_renders_cross_mailbox_results_when_mailbox_not_supplied() {
        let response = app().handle_request(
            &request(
                "GET",
                "/search?q=quarterly+report",
                &[
                    ("User-Agent", "Firefox/Test"),
                    (
                        "Cookie",
                        "osmap_session=aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
                    ),
                ],
                "",
            ),
            "127.0.0.1",
        );

        assert_eq!(response.response.status_code, 200);
        let body = body_text(&response);
        assert!(body.contains("class=\"search-scope\">All mailboxes"));
        assert!(body.contains("name=\"scope\" value=\"all\" checked"));
        assert!(body.contains("/message?mailbox=INBOX&amp;uid=17"));
        assert!(body.contains("/message?mailbox=Archive%2F2026&amp;uid=23"));
        assert!(body.contains("Archive/2026"));
    }

    #[test]
    fn search_page_caps_excessive_all_mailbox_results() {
        let response = app().handle_request(
            &request(
                "GET",
                "/search?q=manyresults",
                &[
                    ("User-Agent", "Firefox/Test"),
                    (
                        "Cookie",
                        "osmap_session=aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
                    ),
                ],
                "",
            ),
            "127.0.0.1",
        );

        assert_eq!(response.response.status_code, 200);
        let body = body_text(&response);
        assert!(body.contains("Result limit reached."));
        assert!(body.contains(&format!(
            "Showing up to {} backend results.",
            crate::mailbox::DEFAULT_MAX_SEARCH_RESULTS,
        )));
        assert!(body.contains(&format!(
            "Messages ({})",
            crate::mailbox::DEFAULT_MAX_SEARCH_RESULTS
        )));
        assert!(body.contains("Result 249"));
        assert!(!body.contains("Result 250"));
        assert_eq!(body.matches("class=\"message-row").count(), 50);
        assert!(body.contains("Page 1 of 5"));
    }

    #[test]
    fn mailboxes_page_caps_pathological_mailbox_lists() {
        let response = app().handle_request(
            &request(
                "GET",
                "/mailboxes",
                &[
                    ("User-Agent", "Firefox/ManyMailboxes"),
                    (
                        "Cookie",
                        "osmap_session=aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
                    ),
                ],
                "",
            ),
            "127.0.0.1",
        );

        assert_eq!(response.response.status_code, 200);
        let body = body_text(&response);
        assert!(body.contains(&format!(
            "Mailbox list display limit reached: showing first {} of {} visible mailboxes.",
            crate::mailbox::DEFAULT_MAX_MAILBOXES,
            crate::mailbox::DEFAULT_MAX_MAILBOXES + 2
        )));
        assert!(body.contains("INBOX.overflow-1022"));
        assert!(!body.contains("INBOX.overflow-1023"));
    }

    #[test]
    fn message_view_renders_safe_body_and_attachments() {
        let response = app().handle_request(
            &request(
                "GET",
                "/message?mailbox=INBOX&uid=9",
                &[
                    ("User-Agent", "Firefox/Test"),
                    (
                        "Cookie",
                        "osmap_session=aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
                    ),
                ],
                "",
            ),
            "127.0.0.1",
        );

        assert_eq!(response.response.status_code, 200);
        let body = body_text(&response);
        assert!(body.contains("multipart/mixed"));
        assert!(body.contains("standalone-reader"));
        assert!(
            body.find("<section class=\"body-panel\">")
                .expect("body panel")
                < body
                    .find("<section class=\"panel reader-attachments\">")
                    .expect("attachments")
        );
        assert!(body.contains("Reading Pane"));
        assert!(body.contains("Remote content blocked by policy"));
        assert!(body.contains("report.pdf"));
        assert!(body.contains("<pre>Hello world</pre>"));
        assert!(body.contains("mode=reply"));
        assert!(body.contains("mode=forward"));
        assert!(body.contains("Archive Message"));
        assert!(body.contains("name=\"action\" value=\"archive\""));
        assert!(body.contains("Move to Bin"));
        assert!(body.contains("name=\"action\" value=\"bin\""));
        assert!(body.contains("action=\"/message/move\""));
        assert!(body.contains("<select name=\"destination_mailbox\">"));
        assert!(body.contains("<option value=\"Trash\">Trash</option>"));
        assert!(body.contains("<option value=\"Junk\">Junk</option>"));
        assert!(body.contains("/attachment?mailbox=INBOX&amp;uid=9&amp;part=1.2"));
        assert!(body.contains("chart.png"));
        assert!(body.contains("Content-ID <strong>cid:chart@example.com</strong>"));
        assert!(body.contains(
            "including <strong>1</strong> with Content-ID metadata used by `cid:` HTML references"
        ));
    }

    #[test]
    fn mailbox_budget_releases_after_message_view_timeout_like_failure() {
        let policy = HttpPolicy {
            mailbox_worker_budget: 1,
            ..HttpPolicy::default()
        };
        let app = app_with_policy(policy);

        let response = app.handle_request(
            &request(
                "GET",
                "/message?mailbox=INBOX&uid=900",
                &authenticated_headers(),
                "",
            ),
            "127.0.0.1",
        );

        assert_eq!(response.response.status_code, 503);
        assert_eq!(app.request_budgets.mailbox_workers.active_count(), 0);
        assert!(response
            .audit_events
            .iter()
            .any(|event| event.action == "request_budget_released"));

        let response_after_failure = app.handle_request(
            &request(
                "GET",
                "/message?mailbox=INBOX&uid=9",
                &authenticated_headers(),
                "",
            ),
            "127.0.0.1",
        );
        assert_eq!(response_after_failure.response.status_code, 200);
    }

    #[test]
    fn request_budget_guard_releases_on_panic() {
        let budget = RequestBudget::new("panic_test_workers", 1);
        let result = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
            let _guard = budget
                .try_acquire()
                .expect("test should acquire the budget slot");
            panic!("simulated route panic");
        }));

        assert!(result.is_err());
        assert_eq!(budget.active_count(), 0);
        assert!(budget.try_acquire().is_some());
    }

    #[test]
    fn message_view_route_maps_oversized_mime_body_to_safe_failure() {
        let response = app().handle_request(
            &request(
                "GET",
                "/message?mailbox=INBOX&uid=900",
                &[
                    ("User-Agent", "Firefox/Test"),
                    (
                        "Cookie",
                        "osmap_session=aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
                    ),
                ],
                "",
            ),
            "127.0.0.1",
        );

        assert_eq!(response.response.status_code, 503);
        let body = body_text(&response);
        assert!(body.contains("The service could not complete the request at this time."));
        assert!(!body.contains("oversized"));
        assert!(!body.contains("mime body"));
    }

    #[test]
    fn message_view_caps_excessive_attachment_metadata() {
        let response = app().handle_request(
            &request(
                "GET",
                "/message?mailbox=INBOX&uid=901",
                &[
                    ("User-Agent", "Firefox/Test"),
                    (
                        "Cookie",
                        "osmap_session=aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
                    ),
                ],
                "",
            ),
            "127.0.0.1",
        );

        assert_eq!(response.response.status_code, 200);
        let body = body_text(&response);
        assert!(body.contains(&format!(
            "Displaying the first {} of {} surfaced parts.",
            crate::mime::DEFAULT_MIME_PARTS_MAX,
            crate::mime::DEFAULT_MIME_PARTS_MAX + 12
        )));
        assert!(body.contains("overflow-63.bin"));
        assert!(!body.contains("overflow-64.bin"));
        assert!(body.contains("/attachment?mailbox=INBOX&amp;uid=901&amp;part=1.65"));
        assert!(!body.contains("/attachment?mailbox=INBOX&amp;uid=901&amp;part=1.66"));
    }

    #[test]
    fn archive_shortcut_is_hidden_when_viewing_the_archive_mailbox() {
        let response = app().handle_request(
            &request(
                "GET",
                "/mailbox?name=Archive%2F2026",
                &[
                    ("User-Agent", "Firefox/Test"),
                    (
                        "Cookie",
                        "osmap_session=aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
                    ),
                ],
                "",
            ),
            "127.0.0.1",
        );

        assert_eq!(response.response.status_code, 200);
        let body = body_text(&response);
        assert!(body.contains("<h1>Archive / Bin</h1>"));
        assert!(body
            .contains("href=\"/mailbox?name=Archive%2F2026\" aria-current=\"page\">Archive</a>"));
        assert!(!body.contains(">Archive</button>"));
    }

    #[test]
    fn mailbox_page_renders_bounded_bulk_archive_controls() {
        let response = app().handle_request(
            &request(
                "GET",
                "/mailbox?name=INBOX",
                &[
                    ("User-Agent", "Firefox/Test"),
                    (
                        "Cookie",
                        "osmap_session=aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
                    ),
                ],
                "",
            ),
            "127.0.0.1",
        );

        assert_eq!(response.response.status_code, 200);
        let body = body_text(&response);
        assert!(body.contains("id=\"bulk-move-form\""));
        assert!(body.contains("action=\"/messages/move\""));
        assert!(!body.contains("id=\"bulk-archive-form\""));
        assert!(body.contains("name=\"action\" value=\"archive\""));
        assert!(body.contains("name=\"action\" value=\"archive\""));
        assert!(body.contains("<option value=\"Archive/2026\">Archive/2026</option>"));
        assert!(body.contains("<option value=\"INBOX.Projects\">INBOX.Projects</option>"));
        assert!(body.contains("form=\"bulk-move-form\" type=\"checkbox\" name=\"message_9\""));
        assert!(body.contains("form=\"bulk-move-form\" type=\"checkbox\" name=\"message_10\""));
        assert_eq!(
            body.matches("type=\"checkbox\" name=\"message_9\"").count(),
            1
        );
        assert_eq!(
            body.matches("type=\"checkbox\" name=\"message_10\"")
                .count(),
            1
        );
        assert!(body.contains(">Move Selected</button>"));
        assert!(body.contains(">Archive Selected</button>"));
    }

    #[test]
    fn message_move_redirects_back_to_mailbox_after_success() {
        let response = app().handle_request(
            &request(
                "POST",
                "/message/move",
                &authenticated_same_origin_headers(),
                &move_form("csrf_token=fedcba9876543210fedcba9876543210fedcba9876543210fedcba9876543210&mailbox=INBOX&uid=9&destination_mailbox=Archive%2F2026", "move"),
            ),
            "127.0.0.1",
        );

        assert_eq!(response.response.status_code, 303);
        assert!(response
            .response
            .headers
            .iter()
            .any(|(name, value)| { name == "Location" && value == "/mailbox?name=INBOX" }));
    }

    #[test]
    fn message_move_rejects_tampered_invalid_uid_without_success_redirect() {
        let response = app().handle_request(
            &request(
                "POST",
                "/message/move",
                &authenticated_same_origin_headers(),
                &move_form("csrf_token=fedcba9876543210fedcba9876543210fedcba9876543210fedcba9876543210&mailbox=INBOX&uid=100156&destination_mailbox=Junk", "move"),
            ),
            "127.0.0.1",
        );

        assert_eq!(response.response.status_code, 409);
        assert!(body_text(&response).contains("current message was moved, removed or replaced"));
        assert!(!response
            .response
            .headers
            .iter()
            .any(|(name, value)| name == "Location" && value.contains("moved_to")));
    }

    #[test]
    fn message_move_rejects_mismatched_mailbox_uid_tuple() {
        let response = app().handle_request(
            &request(
                "POST",
                "/message/move",
                &authenticated_same_origin_headers(),
                &move_form("csrf_token=fedcba9876543210fedcba9876543210fedcba9876543210fedcba9876543210&mailbox=Junk&uid=9&destination_mailbox=INBOX", "move"),
            ),
            "127.0.0.1",
        );

        assert_eq!(response.response.status_code, 409);
        assert!(body_text(&response).contains("current message was moved, removed or replaced"));
    }

    #[test]
    fn message_move_rejects_non_numeric_uid() {
        let response = app().handle_request(
            &request(
                "POST",
                "/message/move",
                &authenticated_same_origin_headers(),
                &move_form("csrf_token=fedcba9876543210fedcba9876543210fedcba9876543210fedcba9876543210&mailbox=INBOX&uid=abc&destination_mailbox=Junk", "move"),
            ),
            "127.0.0.1",
        );

        assert_eq!(response.response.status_code, 400);
        assert!(
            body_text(&response).contains("Select current messages and an available destination")
        );
    }

    #[test]
    fn message_move_rejects_empty_destination() {
        let response = app().handle_request(
            &request(
                "POST",
                "/message/move",
                &authenticated_same_origin_headers(),
                &move_form("csrf_token=fedcba9876543210fedcba9876543210fedcba9876543210fedcba9876543210&mailbox=INBOX&uid=9&destination_mailbox=", "move"),
            ),
            "127.0.0.1",
        );

        assert_eq!(response.response.status_code, 400);
        assert!(
            body_text(&response).contains("Select current messages and an available destination")
        );
    }

    #[test]
    fn bulk_archive_redirects_back_to_mailbox_after_success() {
        let response = app().handle_request(
            &request(
                "POST",
                "/messages/archive",
                &authenticated_same_origin_headers(),
                &move_form("csrf_token=fedcba9876543210fedcba9876543210fedcba9876543210fedcba9876543210&mailbox=INBOX&destination_mailbox=Archive%2F2026&uid_9=9&uid_10=10", "archive"),
            ),
            "127.0.0.1",
        );

        assert_eq!(response.response.status_code, 303);
        assert!(response
            .response
            .headers
            .iter()
            .any(|(name, value)| { name == "Location" && value == "/mailbox?name=INBOX" }));
    }

    #[test]
    fn bulk_move_redirects_back_to_mailbox_after_success() {
        let response = app().handle_request(
            &request(
                "POST",
                "/messages/move",
                &authenticated_same_origin_headers(),
                &move_form("csrf_token=fedcba9876543210fedcba9876543210fedcba9876543210fedcba9876543210&mailbox=INBOX&destination_mailbox=INBOX.Projects&uid_9=9&uid_10=10", "move"),
            ),
            "127.0.0.1",
        );

        assert_eq!(response.response.status_code, 303);
        assert!(response
            .response
            .headers
            .iter()
            .any(|(name, value)| { name == "Location" && value == "/mailbox?name=INBOX" }));
    }

    #[test]
    fn bulk_archive_requires_at_least_one_selected_message() {
        let response = app().handle_request(
            &request(
                "POST",
                "/messages/archive",
                &authenticated_same_origin_headers(),
                &move_form("csrf_token=fedcba9876543210fedcba9876543210fedcba9876543210fedcba9876543210&mailbox=INBOX&destination_mailbox=Archive%2F2026", "archive"),
            ),
            "127.0.0.1",
        );

        assert_eq!(response.response.status_code, 400);
        assert!(
            body_text(&response).contains("Select current messages and an available destination")
        );
    }

    #[test]
    fn bulk_move_rejects_empty_selection() {
        let response = app().handle_request(
            &request(
                "POST",
                "/messages/move",
                &authenticated_same_origin_headers(),
                &move_form("csrf_token=fedcba9876543210fedcba9876543210fedcba9876543210fedcba9876543210&mailbox=INBOX&destination_mailbox=INBOX.Projects", "move"),
            ),
            "127.0.0.1",
        );

        assert_eq!(response.response.status_code, 400);
        assert!(
            body_text(&response).contains("Select current messages and an available destination")
        );
    }

    #[test]
    fn bulk_archive_rejects_oversized_selection_before_moving() {
        let response = app().handle_request(
            &request(
                "POST",
                "/messages/archive",
                &authenticated_same_origin_headers(),
                &move_form("csrf_token=fedcba9876543210fedcba9876543210fedcba9876543210fedcba9876543210&mailbox=INBOX&destination_mailbox=Archive%2F2026&uid_1=1&uid_2=2&uid_3=3&uid_4=4&uid_5=5&uid_6=6&uid_7=7&uid_8=8&uid_9=9&uid_10=10&uid_11=11", "archive"),
            ),
            "127.0.0.1",
        );

        assert_eq!(response.response.status_code, 400);
        assert!(
            body_text(&response).contains("Select current messages and an available destination")
        );
    }

    #[test]
    fn bulk_move_rejects_oversized_selection_before_moving() {
        let response = app().handle_request(
            &request(
                "POST",
                "/messages/move",
                &authenticated_same_origin_headers(),
                &move_form("csrf_token=fedcba9876543210fedcba9876543210fedcba9876543210fedcba9876543210&mailbox=INBOX&destination_mailbox=INBOX.Projects&uid_1=1&uid_2=2&uid_3=3&uid_4=4&uid_5=5&uid_6=6&uid_7=7&uid_8=8&uid_9=9&uid_10=10&uid_11=11", "move"),
            ),
            "127.0.0.1",
        );

        assert_eq!(response.response.status_code, 400);
        assert!(
            body_text(&response).contains("Select current messages and an available destination")
        );
    }

    #[test]
    fn bulk_move_rejects_unapproved_destination_before_moving() {
        let response = app().handle_request(
            &request(
                "POST",
                "/messages/move",
                &authenticated_same_origin_headers(),
                &move_form("csrf_token=fedcba9876543210fedcba9876543210fedcba9876543210fedcba9876543210&mailbox=INBOX&destination_mailbox=dovecot&uid_9=9", "move"),
            ),
            "127.0.0.1",
        );

        assert_eq!(response.response.status_code, 400);
        assert!(
            body_text(&response).contains("Select current messages and an available destination")
        );
    }

    #[test]
    fn bulk_move_reports_partial_success_when_later_uid_is_stale() {
        let response = app().handle_request(
            &request(
                "POST",
                "/messages/move",
                &authenticated_same_origin_headers(),
                &move_form("csrf_token=fedcba9876543210fedcba9876543210fedcba9876543210fedcba9876543210&mailbox=INBOX&destination_mailbox=INBOX.Projects&uid_9=9&uid_100156=100156", "move"),
            ),
            "127.0.0.1",
        );

        assert_eq!(response.response.status_code, 409);
        assert!(body_text(&response)
            .contains("1 confirmed moved; 0 uncertain; 0 remaining messages were not attempted."));
    }

    #[test]
    fn mailbox_page_does_not_trust_caller_supplied_move_success() {
        let response = app().handle_request(
            &request(
                "GET",
                "/mailbox?name=INBOX&moved_to=Archive%2F2026",
                &[
                    ("User-Agent", "Firefox/Test"),
                    (
                        "Cookie",
                        "osmap_session=aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
                    ),
                ],
                "",
            ),
            "127.0.0.1",
        );

        assert_eq!(response.response.status_code, 200);
        assert!(!body_text(&response).contains("Update complete:"));
    }

    #[test]
    fn mailbox_page_does_not_trust_caller_supplied_bulk_count() {
        let response = app().handle_request(
            &request(
                "GET",
                "/mailbox?name=INBOX&moved_to=Archive%2F2026&moved_count=2",
                &[
                    ("User-Agent", "Firefox/Test"),
                    (
                        "Cookie",
                        "osmap_session=aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
                    ),
                ],
                "",
            ),
            "127.0.0.1",
        );

        assert_eq!(response.response.status_code, 200);
        assert!(!body_text(&response).contains("Update complete:"));
    }

    #[test]
    fn compose_page_renders_csrf_bound_form() {
        let response = app().handle_request(
            &request(
                "GET",
                "/compose",
                &[
                    ("User-Agent", "Firefox/Test"),
                    (
                        "Cookie",
                        "osmap_session=aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
                    ),
                ],
                "",
            ),
            "127.0.0.1",
        );

        assert_eq!(response.response.status_code, 200);
        let body = body_text(&response);
        assert!(body.contains("name=\"csrf_token\""));
        assert!(body.contains("action=\"/send\""));
        assert!(body.contains("name=\"to\""));
        assert!(body.contains("name=\"cc\""));
        assert!(body.contains("name=\"bcc\""));
        assert!(body.contains("formaction=\"/drafts/save\""));
        assert!(body.contains("href=\"/drafts\""));
    }

    #[test]
    fn draft_save_resume_and_list_are_authenticated_and_redacted() {
        let app = app();
        let save_response = app.handle_request(
            &native_compose_request(&app,
                "POST",
                "/drafts/save",
                &authenticated_same_origin_headers(),
                "csrf_token=fedcba9876543210fedcba9876543210fedcba9876543210fedcba9876543210&to=bob%40example.com&cc=carol%40example.net&bcc=dana%40example.org&subject=Draft%20Subject&body=Private%20draft%20body",
            ),
            "127.0.0.1",
        );

        assert_eq!(save_response.response.status_code, 303);
        let location = location_header(&save_response);
        assert!(location.starts_with("/draft?id="));

        let resume_response = app.handle_request(
            &request("GET", &location, &authenticated_headers(), ""),
            "127.0.0.1",
        );
        assert_eq!(resume_response.response.status_code, 200);
        let resume_body = body_text(&resume_response);
        assert!(resume_body.contains("Resume Draft"));
        assert!(resume_body.contains("Draft Subject"));
        assert!(resume_body.contains("carol@example.net"));
        assert!(resume_body.contains("dana@example.org"));
        assert!(resume_body.contains("Private draft body"));
        assert!(resume_body.contains("name=\"draft_id\""));

        let list_response = app.handle_request(
            &request("GET", "/drafts", &authenticated_headers(), ""),
            "127.0.0.1",
        );
        assert_eq!(list_response.response.status_code, 200);
        let list_body = body_text(&list_response);
        assert!(list_body.contains("Resume"));
        assert!(list_body.contains("Draft Subject"));
        assert!(list_body.contains("Recipient"));
        assert!(!list_body.contains("Body Bytes"));
        assert!(!list_body.contains("Private draft body"));
        assert!(!list_body.contains("dana@example.org"));
        let summaries = app
            .gateway
            .drafts
            .lock()
            .unwrap()
            .values()
            .map(DraftRecord::summary)
            .collect::<Vec<_>>();
        let debug = format!("{summaries:?}");
        assert!(!debug.contains("Draft Subject") && !debug.contains("bob@example.com"));
    }

    #[test]
    fn draft_save_resume_and_send_revalidate_explicit_source_attachment_references() {
        let app = app();
        let save_response = app.handle_request(
            &native_compose_request(&app,
                "POST",
                "/drafts/save",
                &authenticated_same_origin_headers(),
                concat!(
                    "csrf_token=fedcba9876543210fedcba9876543210fedcba9876543210fedcba9876543210",
                    "&to=bob%40example.com&subject=Source%20Draft&body=Body",
                    "&source_mailbox=INBOX&source_uid=9&source_mailbox_guid=bdb0b520cd1ca1698f6409144e01c408&source_message_guid=synthetic-bdb0b520-9",
                    "&include_original_attachment_1=1.2"
                ),
            ),
            "127.0.0.1",
        );
        assert_eq!(save_response.response.status_code, 303);
        assert!(save_response
            .audit_events
            .iter()
            .any(|event| event.action == "stub_source_read"));

        let location = location_header(&save_response);
        let draft_id = location.trim_start_matches("/draft?id=");
        let resume_response = app.handle_request(
            &request("GET", &location, &authenticated_headers(), ""),
            "127.0.0.1",
        );
        assert_eq!(resume_response.response.status_code, 200);
        let resume_body = body_text(&resume_response);
        assert!(resume_body.contains("name=\"source_mailbox\" value=\"INBOX\""));
        assert!(resume_body.contains("name=\"source_uid\" value=\"9\""));
        assert!(resume_body.contains("value=\"1.2\" checked"));
        assert!(resume_body.contains("value=\"1.3\""));
        assert!(!resume_body.contains("value=\"1.3\" checked"));

        let send_response = app.handle_request(
            &native_compose_request(&app,
                "POST",
                "/send",
                &authenticated_same_origin_headers(),
                &format!(
                    "csrf_token=fedcba9876543210fedcba9876543210fedcba9876543210fedcba9876543210&draft_id={draft_id}&draft_revision=1&to=bob%40example.com&subject=Source%20Draft&body=Body&source_mailbox=INBOX&source_uid=9&source_mailbox_guid=bdb0b520cd1ca1698f6409144e01c408&source_message_guid=synthetic-bdb0b520-9&include_original_attachment_1=1.2"
                ),
            ),
            "127.0.0.1",
        );
        assert_eq!(send_response.response.status_code, 303);
        assert!(send_response
            .audit_events
            .iter()
            .any(|event| event.action == "stub_source_read"));
    }

    #[test]
    fn draft_save_rejects_unsurfaced_source_attachment_reference() {
        let response = app().handle_request(
            &native_compose_request(&app(),
                "POST",
                "/drafts/save",
                &authenticated_same_origin_headers(),
                concat!(
                    "csrf_token=fedcba9876543210fedcba9876543210fedcba9876543210fedcba9876543210",
                    "&to=bob%40example.com&subject=Stale&body=Body",
                    "&source_mailbox=INBOX&source_uid=9&source_mailbox_guid=bdb0b520cd1ca1698f6409144e01c408&source_message_guid=synthetic-bdb0b520-9",
                    "&include_original_attachment_1=1.99"
                ),
            ),
            "127.0.0.1",
        );

        assert_eq!(response.response.status_code, 409);
        assert!(body_text(&response).contains("could not be revalidated"));
        assert!(!response
            .audit_events
            .iter()
            .any(|event| event.action == "stub_draft_save"));
    }

    #[test]
    fn draft_delete_removes_saved_draft() {
        let app = app();
        let save_response = app.handle_request(
            &native_compose_request(&app,
                "POST",
                "/drafts/save",
                &authenticated_same_origin_headers(),
                "csrf_token=fedcba9876543210fedcba9876543210fedcba9876543210fedcba9876543210&to=bob%40example.com&subject=Delete%20Me&body=Body",
            ),
            "127.0.0.1",
        );
        let location = location_header(&save_response);
        let draft_id = location.trim_start_matches("/draft?id=");

        let delete_response = app.handle_request(
            &request(
                "POST",
                "/drafts/delete",
                &authenticated_same_origin_headers(),
                &format!(
                    "csrf_token=fedcba9876543210fedcba9876543210fedcba9876543210fedcba9876543210&draft_id={draft_id}&draft_revision=1&confirm=1"
                ),
            ),
            "127.0.0.1",
        );
        assert_eq!(delete_response.response.status_code, 303);

        let resume_response = app.handle_request(
            &request("GET", &location, &authenticated_headers(), ""),
            "127.0.0.1",
        );
        assert_eq!(resume_response.response.status_code, 404);
    }

    #[test]
    fn send_success_deletes_draft_after_accepted_handoff() {
        let app = app();
        let save_response = app.handle_request(
            &native_compose_request(&app,
                "POST",
                "/drafts/save",
                &authenticated_same_origin_headers(),
                "csrf_token=fedcba9876543210fedcba9876543210fedcba9876543210fedcba9876543210&to=bob%40example.com&subject=Send%20Me&body=Body",
            ),
            "127.0.0.1",
        );
        let location = location_header(&save_response);
        let draft_id = location.trim_start_matches("/draft?id=");

        let send_response = app.handle_request(
            &native_compose_request(&app,
                "POST",
                "/send",
                &authenticated_same_origin_headers(),
                &format!(
                    "csrf_token=fedcba9876543210fedcba9876543210fedcba9876543210fedcba9876543210&draft_id={draft_id}&draft_revision=1&to=bob%40example.com&subject=Send%20Me&body=Body"
                ),
            ),
            "127.0.0.1",
        );
        assert_eq!(send_response.response.status_code, 303);
        assert!(location_header(&send_response).starts_with("/compose?receipt="));

        let resume_response = app.handle_request(
            &request("GET", &location, &authenticated_headers(), ""),
            "127.0.0.1",
        );
        assert_eq!(resume_response.response.status_code, 404);
    }

    #[test]
    fn send_failure_preserves_draft() {
        let app = app();
        let save_response = app.handle_request(
            &native_compose_request(&app,
                "POST",
                "/drafts/save",
                &authenticated_same_origin_headers(),
                "csrf_token=fedcba9876543210fedcba9876543210fedcba9876543210fedcba9876543210&to=locked%40example.com&subject=Retry%20Later&body=Body",
            ),
            "127.0.0.1",
        );
        let location = location_header(&save_response);
        let draft_id = location.trim_start_matches("/draft?id=");

        let send_response = app.handle_request(
            &native_compose_request(&app,
                "POST",
                "/send",
                &authenticated_same_origin_headers(),
                &format!(
                    "csrf_token=fedcba9876543210fedcba9876543210fedcba9876543210fedcba9876543210&draft_id={draft_id}&draft_revision=1&to=locked%40example.com&subject=Retry%20Later&body=Body"
                ),
            ),
            "127.0.0.1",
        );
        assert_eq!(send_response.response.status_code, 429);

        let resume_response = app.handle_request(
            &request("GET", &location, &authenticated_headers(), ""),
            "127.0.0.1",
        );
        assert_eq!(resume_response.response.status_code, 200);
        assert!(body_text(&resume_response).contains("Retry Later"));
    }

    #[test]
    fn draft_save_preserves_stored_attachments_until_send() {
        let app = app();
        let mut multipart_body = String::new();
        multipart_body.push_str("--draft-boundary\r\n");
        multipart_body.push_str("Content-Disposition: form-data; name=\"csrf_token\"\r\n\r\n");
        multipart_body
            .push_str("fedcba9876543210fedcba9876543210fedcba9876543210fedcba9876543210\r\n");
        multipart_body.push_str("--draft-boundary\r\n");
        multipart_body.push_str("Content-Disposition: form-data; name=\"to\"\r\n\r\n");
        multipart_body.push_str("bob@example.com\r\n");
        multipart_body.push_str("--draft-boundary\r\n");
        multipart_body.push_str("Content-Disposition: form-data; name=\"subject\"\r\n\r\n");
        multipart_body.push_str("Attachment Draft\r\n");
        multipart_body.push_str("--draft-boundary\r\n");
        multipart_body.push_str("Content-Disposition: form-data; name=\"body\"\r\n\r\n");
        multipart_body.push_str("Body\r\n");
        multipart_body.push_str("--draft-boundary\r\n");
        multipart_body.push_str(
            "Content-Disposition: form-data; name=\"attachment\"; filename=\"report.txt\"\r\n",
        );
        multipart_body.push_str("Content-Type: text/plain\r\n\r\n");
        multipart_body.push_str("draft attachment\r\n");
        multipart_body.push_str("--draft-boundary--\r\n");

        let save_response = app.handle_request(
            &native_compose_request(&app,
                "POST",
                "/drafts/save",
                &[
                    ("User-Agent", "Firefox/Test"),
                    (
                        "Cookie",
                        "osmap_session=aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
                    ),
                    ("Origin", "https://localhost"),
                    ("Content-Type", "multipart/form-data; boundary=draft-boundary"),
                ],
                &multipart_body,
            ),
            "127.0.0.1",
        );
        assert_eq!(save_response.response.status_code, 303);
        let location = location_header(&save_response);
        let draft_id = location.trim_start_matches("/draft?id=");

        let resume_response = app.handle_request(
            &request("GET", &location, &authenticated_headers(), ""),
            "127.0.0.1",
        );
        assert!(body_text(&resume_response).contains("1 stored attachment"));

        let send_response = app.handle_request(
            &native_compose_request(&app,
                "POST",
                "/send",
                &authenticated_same_origin_headers(),
                &format!(
                    "csrf_token=fedcba9876543210fedcba9876543210fedcba9876543210fedcba9876543210&draft_id={draft_id}&draft_revision=1&to=bob%40example.com&subject=Attachment%20Draft&body=Body"
                ),
            ),
            "127.0.0.1",
        );
        assert_eq!(send_response.response.status_code, 303);
    }

    #[test]
    fn draft_save_requires_valid_csrf_token() {
        let response = app().handle_request(
            &native_compose_request(
                &app(),
                "POST",
                "/drafts/save",
                &authenticated_same_origin_headers(),
                "csrf_token=wrong&to=bob%40example.com&subject=Draft&body=Body",
            ),
            "127.0.0.1",
        );

        assert_eq!(response.response.status_code, 403);
        assert!(body_text(&response).contains("CSRF Validation Failed"));
    }

    #[test]
    fn draft_delete_requires_same_origin_request_metadata() {
        let response = app().handle_request(
            &request(
                "POST",
                "/drafts/delete",
                &authenticated_headers(),
                "csrf_token=fedcba9876543210fedcba9876543210fedcba9876543210fedcba9876543210&draft_id=00000000000000000000000000000001",
            ),
            "127.0.0.1",
        );

        assert_eq!(response.response.status_code, 403);
        assert!(body_text(&response).contains("Request Origin Rejected"));
    }

    #[test]
    fn sessions_page_renders_for_valid_session() {
        let response = app().handle_request(
            &request(
                "GET",
                "/sessions",
                &[
                    ("User-Agent", "Firefox/Test"),
                    (
                        "Cookie",
                        "osmap_session=aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
                    ),
                ],
                "",
            ),
            "127.0.0.1",
        );

        assert_eq!(response.response.status_code, 200);
        let body = body_text(&response);
        assert!(body.contains("<h1>Active Sessions</h1>"));
        assert!(body.contains("Concurrent browser sessions are allowed."));
        assert!(body.contains("<th scope=\"col\">Device</th>"));
        assert!(body.contains(">Firefox<"));
        assert!(body.contains("203.0.113.9"));
        assert!(body.contains("Revoke This Session"));
        assert!(body.contains("Sign out all other sessions"));
        assert!(body.contains("Revoke All Sessions"));
        assert!(body.contains("Idle timeout:</strong> 1800 seconds"));
    }

    #[test]
    fn settings_page_renders_for_valid_session() {
        let response = app().handle_request(
            &request(
                "GET",
                "/settings",
                &[
                    ("User-Agent", "Firefox/Test"),
                    (
                        "Cookie",
                        "osmap_session=aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
                    ),
                ],
                "",
            ),
            "127.0.0.1",
        );

        assert_eq!(response.response.status_code, 200);
        let body = body_text(&response);
        assert!(body.contains("<h1>Settings</h1>"));
        assert!(body.contains("<h2 id=\"general-profile-title\">Account Profile</h2>"));
        assert!(body.contains("name=\"settings_action\" value=\"archive\""));
        assert!(!body.contains("name=\"html_display_preference\""));
        assert!(body.contains("name=\"archive_mailbox_name\""));
        assert!(body.contains("id=\"general-archive\""));
        assert!(body.contains("for=\"general-archive\""));
        assert!(body.contains("value=\"Archive/2026\""));
        assert!(body.contains("Save archive folder"));
        assert!(body.contains("Save appearance"));
        assert!(body.contains("action=\"/settings/display\""));
        assert!(body.contains("href=\"/settings?section=reading\""));
    }

    #[test]
    fn compose_reply_prefills_recipient_and_subject() {
        let response = app().handle_request(
            &request(
                "GET",
                "/compose?mode=reply&mailbox=INBOX&uid=9",
                &[
                    ("User-Agent", "Firefox/Test"),
                    (
                        "Cookie",
                        "osmap_session=aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
                    ),
                ],
                "",
            ),
            "127.0.0.1",
        );

        assert_eq!(response.response.status_code, 200);
        let body = body_text(&response);
        assert!(body.contains("<h1>Reply</h1>"));
        assert!(body.contains("alice@example.com"));
        assert!(body.contains("Re: Example"));
        assert!(body.contains("source attachments are not selected automatically"));
        assert!(body.contains("Source Attachments"));
        assert!(body.contains("include_original_attachment_1"));
        assert!(body.contains("source_mailbox"));
        assert!(body.contains("source_uid"));
    }

    #[test]
    fn compose_forward_prefills_attachment_aware_context() {
        let response = app().handle_request(
            &request(
                "GET",
                "/compose?mode=forward&mailbox=INBOX&uid=9",
                &[
                    ("User-Agent", "Firefox/Test"),
                    (
                        "Cookie",
                        "osmap_session=aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
                    ),
                ],
                "",
            ),
            "127.0.0.1",
        );

        assert_eq!(response.response.status_code, 200);
        let body = body_text(&response);
        assert!(body.contains("<h1>Forward</h1>"));
        assert!(body.contains("Fwd: Example"));
        assert!(body.contains("report.pdf"));
        assert!(body.contains("source attachments are not selected automatically"));
        assert!(body.contains("Source Attachments"));
        assert!(body.contains("include_original_attachment_1"));
    }

    #[test]
    fn send_route_refetches_selected_original_attachment() {
        let body = concat!(
            "--test-boundary\r\n",
            "Content-Disposition: form-data; name=\"csrf_token\"\r\n\r\n",
            "fedcba9876543210fedcba9876543210fedcba9876543210fedcba9876543210\r\n",
            "--test-boundary\r\n",
            "Content-Disposition: form-data; name=\"to\"\r\n\r\n",
            "bob@example.com\r\n",
            "--test-boundary\r\n",
            "Content-Disposition: form-data; name=\"subject\"\r\n\r\n",
            "Forwarded report\r\n",
            "--test-boundary\r\n",
            "Content-Disposition: form-data; name=\"body\"\r\n\r\n",
            "See selected source attachment.\r\n",
            "--test-boundary\r\n",
            "Content-Disposition: form-data; name=\"source_mailbox\"\r\n\r\n",
            "INBOX\r\n",
            "--test-boundary\r\n",
            "Content-Disposition: form-data; name=\"source_uid\"\r\n\r\n",
            "9\r\n",
            "--test-boundary\r\n",
            "Content-Disposition: form-data; name=\"source_mailbox_guid\"\r\n\r\n",
            "bdb0b520cd1ca1698f6409144e01c408\r\n",
            "--test-boundary\r\n",
            "Content-Disposition: form-data; name=\"source_message_guid\"\r\n\r\n",
            "synthetic-bdb0b520-9\r\n",
            "--test-boundary\r\n",
            "Content-Disposition: form-data; name=\"include_original_attachment_1\"\r\n\r\n",
            "1.2\r\n",
            "--test-boundary--\r\n",
        );

        let response = app().handle_request(
            &native_compose_request_bytes(&app(),
                "POST",
                "/send",
                &[
                    ("User-Agent", "Firefox/Test"),
                    (
                        "Cookie",
                        "osmap_session=aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
                    ),
                    ("Origin", "https://localhost"),
                    ("Content-Type", "multipart/form-data; boundary=test-boundary"),
                ],
                body.as_bytes(),
            ),
            "127.0.0.1",
        );

        assert_eq!(response.response.status_code, 303);
        assert!(response
            .audit_events
            .iter()
            .any(|event| event.action == "stub_source_read"));
    }

    #[test]
    fn send_route_rejects_duplicate_original_attachment_selection() {
        let body = concat!(
            "--test-boundary\r\n",
            "Content-Disposition: form-data; name=\"csrf_token\"\r\n\r\n",
            "fedcba9876543210fedcba9876543210fedcba9876543210fedcba9876543210\r\n",
            "--test-boundary\r\n",
            "Content-Disposition: form-data; name=\"to\"\r\n\r\n",
            "bob@example.com\r\n",
            "--test-boundary\r\n",
            "Content-Disposition: form-data; name=\"subject\"\r\n\r\n",
            "Forwarded report\r\n",
            "--test-boundary\r\n",
            "Content-Disposition: form-data; name=\"body\"\r\n\r\n",
            "Duplicate selection should fail.\r\n",
            "--test-boundary\r\n",
            "Content-Disposition: form-data; name=\"source_mailbox\"\r\n\r\n",
            "INBOX\r\n",
            "--test-boundary\r\n",
            "Content-Disposition: form-data; name=\"source_uid\"\r\n\r\n",
            "9\r\n",
            "--test-boundary\r\n",
            "Content-Disposition: form-data; name=\"source_mailbox_guid\"\r\n\r\n",
            "bdb0b520cd1ca1698f6409144e01c408\r\n",
            "--test-boundary\r\n",
            "Content-Disposition: form-data; name=\"source_message_guid\"\r\n\r\n",
            "synthetic-bdb0b520-9\r\n",
            "--test-boundary\r\n",
            "Content-Disposition: form-data; name=\"include_original_attachment_1\"\r\n\r\n",
            "1.2\r\n",
            "--test-boundary\r\n",
            "Content-Disposition: form-data; name=\"include_original_attachment_2\"\r\n\r\n",
            "1.2\r\n",
            "--test-boundary--\r\n",
        );

        let response = app().handle_request(
            &native_compose_request_bytes(&app(),
                "POST",
                "/send",
                &[
                    ("User-Agent", "Firefox/Test"),
                    (
                        "Cookie",
                        "osmap_session=aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
                    ),
                    ("Origin", "https://localhost"),
                    ("Content-Type", "multipart/form-data; boundary=test-boundary"),
                ],
                body.as_bytes(),
            ),
            "127.0.0.1",
        );

        assert_eq!(response.response.status_code, 400);
        assert!(response
            .audit_events
            .iter()
            .any(|event| event.action == "http_send_original_attachment_selection_rejected"));
        assert!(!response
            .audit_events
            .iter()
            .any(|event| event.action == "stub_attachment_download"));
    }

    #[test]
    fn send_route_rejects_original_attachment_without_source_mailbox() {
        let body = concat!(
            "--test-boundary\r\n",
            "Content-Disposition: form-data; name=\"csrf_token\"\r\n\r\n",
            "fedcba9876543210fedcba9876543210fedcba9876543210fedcba9876543210\r\n",
            "--test-boundary\r\n",
            "Content-Disposition: form-data; name=\"to\"\r\n\r\n",
            "bob@example.com\r\n",
            "--test-boundary\r\n",
            "Content-Disposition: form-data; name=\"subject\"\r\n\r\n",
            "Forwarded report\r\n",
            "--test-boundary\r\n",
            "Content-Disposition: form-data; name=\"body\"\r\n\r\n",
            "Missing source should fail.\r\n",
            "--test-boundary\r\n",
            "Content-Disposition: form-data; name=\"source_uid\"\r\n\r\n",
            "9\r\n",
            "--test-boundary\r\n",
            "Content-Disposition: form-data; name=\"source_mailbox_guid\"\r\n\r\n",
            "bdb0b520cd1ca1698f6409144e01c408\r\n",
            "--test-boundary\r\n",
            "Content-Disposition: form-data; name=\"source_message_guid\"\r\n\r\n",
            "synthetic-bdb0b520-9\r\n",
            "--test-boundary\r\n",
            "Content-Disposition: form-data; name=\"include_original_attachment_1\"\r\n\r\n",
            "1.2\r\n",
            "--test-boundary--\r\n",
        );

        let response = app().handle_request(
            &native_compose_request_bytes(&app(),
                "POST",
                "/send",
                &[
                    ("User-Agent", "Firefox/Test"),
                    (
                        "Cookie",
                        "osmap_session=aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
                    ),
                    ("Origin", "https://localhost"),
                    ("Content-Type", "multipart/form-data; boundary=test-boundary"),
                ],
                body.as_bytes(),
            ),
            "127.0.0.1",
        );

        assert_eq!(response.response.status_code, 400);
        assert!(body_text(&response).contains("missing a source mailbox"));
        assert!(!response
            .audit_events
            .iter()
            .any(|event| event.action == "stub_attachment_download"));
    }

    #[test]
    fn send_route_fails_visibly_for_stale_original_attachment_selection() {
        let body = concat!(
            "--test-boundary\r\n",
            "Content-Disposition: form-data; name=\"csrf_token\"\r\n\r\n",
            "fedcba9876543210fedcba9876543210fedcba9876543210fedcba9876543210\r\n",
            "--test-boundary\r\n",
            "Content-Disposition: form-data; name=\"to\"\r\n\r\n",
            "bob@example.com\r\n",
            "--test-boundary\r\n",
            "Content-Disposition: form-data; name=\"subject\"\r\n\r\n",
            "Forwarded report\r\n",
            "--test-boundary\r\n",
            "Content-Disposition: form-data; name=\"body\"\r\n\r\n",
            "Stale source should fail.\r\n",
            "--test-boundary\r\n",
            "Content-Disposition: form-data; name=\"source_mailbox\"\r\n\r\n",
            "INBOX\r\n",
            "--test-boundary\r\n",
            "Content-Disposition: form-data; name=\"source_uid\"\r\n\r\n",
            "9\r\n",
            "--test-boundary\r\n",
            "Content-Disposition: form-data; name=\"source_mailbox_guid\"\r\n\r\n",
            "bdb0b520cd1ca1698f6409144e01c408\r\n",
            "--test-boundary\r\n",
            "Content-Disposition: form-data; name=\"source_message_guid\"\r\n\r\n",
            "synthetic-bdb0b520-9\r\n",
            "--test-boundary\r\n",
            "Content-Disposition: form-data; name=\"include_original_attachment_1\"\r\n\r\n",
            "1.99\r\n",
            "--test-boundary--\r\n",
        );

        let response = app().handle_request(
            &native_compose_request_bytes(&app(),
                "POST",
                "/send",
                &[
                    ("User-Agent", "Firefox/Test"),
                    (
                        "Cookie",
                        "osmap_session=aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
                    ),
                    ("Origin", "https://localhost"),
                    ("Content-Type", "multipart/form-data; boundary=test-boundary"),
                ],
                body.as_bytes(),
            ),
            "127.0.0.1",
        );

        assert_eq!(response.response.status_code, 409);
        assert!(body_text(&response).contains("could not be revalidated"));
        assert!(response
            .audit_events
            .iter()
            .any(|event| event.action == "stub_source_read"));
        assert!(!response
            .audit_events
            .iter()
            .any(|event| event.action == "stub_send_ok"));
    }

    #[test]
    fn send_route_counts_original_attachments_against_upload_limit() {
        let body_prefix = concat!(
            "--test-boundary\r\n",
            "Content-Disposition: form-data; name=\"csrf_token\"\r\n\r\n",
            "fedcba9876543210fedcba9876543210fedcba9876543210fedcba9876543210\r\n",
            "--test-boundary\r\n",
            "Content-Disposition: form-data; name=\"to\"\r\n\r\n",
            "bob@example.com\r\n",
            "--test-boundary\r\n",
            "Content-Disposition: form-data; name=\"subject\"\r\n\r\n",
            "Forwarded report\r\n",
            "--test-boundary\r\n",
            "Content-Disposition: form-data; name=\"body\"\r\n\r\n",
            "Aggregate attachment limit should fail.\r\n",
            "--test-boundary\r\n",
            "Content-Disposition: form-data; name=\"source_mailbox\"\r\n\r\n",
            "INBOX\r\n",
            "--test-boundary\r\n",
            "Content-Disposition: form-data; name=\"source_uid\"\r\n\r\n",
            "9\r\n",
            "--test-boundary\r\n",
            "Content-Disposition: form-data; name=\"source_mailbox_guid\"\r\n\r\n",
            "bdb0b520cd1ca1698f6409144e01c408\r\n",
            "--test-boundary\r\n",
            "Content-Disposition: form-data; name=\"source_message_guid\"\r\n\r\n",
            "synthetic-bdb0b520-9\r\n",
            "--test-boundary\r\n",
            "Content-Disposition: form-data; name=\"include_original_attachment_1\"\r\n\r\n",
            "1.2\r\n",
        );
        let uploads = concat!(
            "--test-boundary\r\n",
            "Content-Disposition: form-data; name=\"attachment\"; filename=\"one.txt\"\r\n",
            "Content-Type: text/plain\r\n\r\n",
            "one\r\n",
            "--test-boundary\r\n",
            "Content-Disposition: form-data; name=\"attachment\"; filename=\"two.txt\"\r\n",
            "Content-Type: text/plain\r\n\r\n",
            "two\r\n",
            "--test-boundary\r\n",
            "Content-Disposition: form-data; name=\"attachment\"; filename=\"three.txt\"\r\n",
            "Content-Type: text/plain\r\n\r\n",
            "three\r\n",
            "--test-boundary--\r\n",
        );
        let body = format!("{body_prefix}{uploads}");

        let response = app().handle_request(
            &native_compose_request_bytes(&app(),
                "POST",
                "/send",
                &[
                    ("User-Agent", "Firefox/Test"),
                    (
                        "Cookie",
                        "osmap_session=aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
                    ),
                    ("Origin", "https://localhost"),
                    ("Content-Type", "multipart/form-data; boundary=test-boundary"),
                ],
                body.as_bytes(),
            ),
            "127.0.0.1",
        );

        assert_eq!(response.response.status_code, 400);
        assert!(body_text(&response).contains("attachment count limit"));
        assert!(!response
            .audit_events
            .iter()
            .any(|event| event.action == "stub_attachment_download"));
    }

    #[test]
    fn attachment_download_returns_forced_download_headers() {
        let response = app().handle_request(
            &request(
                "GET",
                "/attachment?mailbox=INBOX&uid=9&part=1.2",
                &[
                    ("User-Agent", "Firefox/Test"),
                    (
                        "Cookie",
                        "osmap_session=aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
                    ),
                ],
                "",
            ),
            "127.0.0.1",
        );

        assert_eq!(response.response.status_code, 200);
        assert_eq!(response.response.body, b"%PDF-stub%".to_vec());
        assert!(response
            .response
            .headers
            .iter()
            .any(|(name, value)| name == "Content-Disposition"
                && value == "attachment; filename=\"report.pdf\""));
        assert!(response
            .response
            .headers
            .iter()
            .any(|(name, value)| name == "X-Content-Type-Options" && value == "nosniff"));
        assert!(response
            .response
            .headers
            .iter()
            .any(|(name, value)| name == "Cross-Origin-Resource-Policy" && value == "same-origin"));
    }

    #[test]
    fn send_route_requires_valid_csrf_token() {
        let response = app().handle_request(
            &native_compose_request(
                &app(),
                "POST",
                "/send",
                &authenticated_headers(),
                "to=bob%40example.com&subject=Test&body=Hello",
            ),
            "127.0.0.1",
        );

        assert_eq!(response.response.status_code, 403);
        assert!(body_text(&response).contains("CSRF Validation Failed"));
    }

    #[test]
    fn send_route_redirects_after_successful_submission() {
        let response = app().handle_request(
            &native_compose_request(&app(),
                "POST",
                "/send",
                &authenticated_same_origin_headers(),
                "csrf_token=fedcba9876543210fedcba9876543210fedcba9876543210fedcba9876543210&to=bob%40example.com&subject=Test&body=Hello",
            ),
            "127.0.0.1",
        );

        assert_eq!(response.response.status_code, 303);
        assert!(response
            .response
            .headers
            .iter()
            .any(|(name, value)| name == "Location" && value.starts_with("/compose?receipt=")));
    }

    #[test]
    fn send_route_returns_retry_after_when_submission_is_throttled() {
        let response = app().handle_request(
            &native_compose_request(&app(),
                "POST",
                "/send",
                &authenticated_same_origin_headers(),
                "csrf_token=fedcba9876543210fedcba9876543210fedcba9876543210fedcba9876543210&to=locked%40example.com&subject=Test&body=Hello",
            ),
            "127.0.0.1",
        );

        assert_eq!(response.response.status_code, 429);
        assert!(body_text(&response).contains("Too many outbound submissions were observed."));
        assert!(response
            .response
            .headers
            .iter()
            .any(|(name, value)| name == "Retry-After" && value == "120"));
    }

    #[test]
    fn message_move_route_returns_retry_after_when_throttled() {
        let mut headers = authenticated_same_origin_headers().to_vec();
        headers.retain(|(name, _)| !name.eq_ignore_ascii_case("user-agent"));
        headers.push(("User-Agent", "OSMAP/ManyMessages;MoveThrottled"));
        let response = app().handle_request(
            &request(
                "POST",
                "/message/move",
                &headers,
                &move_form("csrf_token=fedcba9876543210fedcba9876543210fedcba9876543210fedcba9876543210&mailbox=INBOX&uid=9&destination_mailbox=Junk", "move"),
            ),
            "127.0.0.1",
        );

        assert_eq!(response.response.status_code, 429);
        assert!(body_text(&response).contains("mail action limit has been reached"));
        assert!(response
            .response
            .headers
            .iter()
            .any(|(name, value)| name == "Retry-After" && value == "180"));
    }

    #[test]
    fn session_revoke_redirects_back_to_sessions_for_non_current_target() {
        let response = app().handle_request(
            &request(
                "POST",
                "/sessions/revoke",
                &authenticated_same_origin_headers(),
                "csrf_token=fedcba9876543210fedcba9876543210fedcba9876543210fedcba9876543210&session_id=bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb",
            ),
            "127.0.0.1",
        );

        assert_eq!(response.response.status_code, 303);
        assert!(response
            .response
            .headers
            .iter()
            .any(|(name, value)| name == "Location" && value == "/sessions?revoked=1"));
    }

    #[test]
    fn session_revoke_requires_valid_csrf_token() {
        let response = app().handle_request(
            &request(
                "POST",
                "/sessions/revoke",
                &authenticated_same_origin_headers(),
                "session_id=bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb",
            ),
            "127.0.0.1",
        );

        assert_eq!(response.response.status_code, 403);
        assert!(body_text(&response).contains("CSRF Validation Failed"));
        assert!(!response
            .audit_events
            .iter()
            .any(|event| event.action == "stub_session_revoke_other"));
    }

    #[test]
    fn session_revoke_rejects_unsupported_form_content_type() {
        let response = app().handle_request(
            &request(
                "POST",
                "/sessions/revoke",
                &[
                    ("User-Agent", "Firefox/Test"),
                    (
                        "Cookie",
                        "osmap_session=aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
                    ),
                    ("Origin", "https://localhost"),
                    ("Content-Type", "application/json"),
                ],
                concat!(
                    "{\"session_id\":\"",
                    "bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb",
                    "\"}",
                ),
            ),
            "127.0.0.1",
        );

        assert_eq!(response.response.status_code, 400);
        assert!(body_text(&response).contains("Invalid Session Request"));
        assert!(response
            .audit_events
            .iter()
            .any(|event| event.action == "http_session_revoke_content_type_rejected"));
    }

    #[test]
    fn session_revoke_rejects_unknown_session_for_user() {
        let response = app().handle_request(
            &request(
                "POST",
                "/sessions/revoke",
                &authenticated_same_origin_headers(),
                "csrf_token=fedcba9876543210fedcba9876543210fedcba9876543210fedcba9876543210&session_id=cccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccc",
            ),
            "127.0.0.1",
        );

        assert_eq!(response.response.status_code, 404);
        assert!(body_text(&response).contains("Session Revocation Failed"));
        assert!(response
            .audit_events
            .iter()
            .any(|event| event.action == "stub_session_revoke_denied"));
    }

    #[test]
    fn session_revoke_clears_cookie_when_current_session_is_revoked() {
        let response = app().handle_request(
            &request(
                "POST",
                "/sessions/revoke",
                &authenticated_same_origin_headers(),
                "csrf_token=fedcba9876543210fedcba9876543210fedcba9876543210fedcba9876543210&session_id=0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef",
            ),
            "127.0.0.1",
        );

        assert_eq!(response.response.status_code, 303);
        assert!(response
            .response
            .headers
            .iter()
            .any(|(name, value)| name == "Location" && value == "/login"));
        assert!(response
            .response
            .headers
            .iter()
            .any(|(name, value)| name == "Set-Cookie" && value.contains("Max-Age=0")));
    }

    #[test]
    fn session_revoke_other_sessions_redirects_back_to_sessions() {
        let response = app().handle_request(
            &request(
                "POST",
                "/sessions/revoke",
                &authenticated_same_origin_headers(),
                "csrf_token=fedcba9876543210fedcba9876543210fedcba9876543210fedcba9876543210&scope=others",
            ),
            "127.0.0.1",
        );

        assert_eq!(response.response.status_code, 303);
        assert!(response
            .response
            .headers
            .iter()
            .any(|(name, value)| name == "Location" && value == "/sessions?revoked=1"));
    }

    #[test]
    fn session_revoke_all_sessions_clears_current_cookie() {
        let response = app().handle_request(
            &request(
                "POST",
                "/sessions/revoke",
                &authenticated_same_origin_headers(),
                "csrf_token=fedcba9876543210fedcba9876543210fedcba9876543210fedcba9876543210&scope=all",
            ),
            "127.0.0.1",
        );

        assert_eq!(response.response.status_code, 303);
        assert!(response
            .response
            .headers
            .iter()
            .any(|(name, value)| name == "Location" && value == "/login"));
        assert!(response
            .response
            .headers
            .iter()
            .any(|(name, value)| name == "Set-Cookie" && value.contains("Max-Age=0")));
    }

    #[test]
    fn settings_update_redirects_after_successful_save() {
        let response = app().handle_request(
            &request(
                "POST",
                "/settings",
                &authenticated_same_origin_headers(),
                "csrf_token=fedcba9876543210fedcba9876543210fedcba9876543210fedcba9876543210&html_display_preference=prefer_plain_text&archive_mailbox_name=Archive%2F2026",
            ),
            "127.0.0.1",
        );

        assert_eq!(response.response.status_code, 303);
        assert!(response
            .response
            .headers
            .iter()
            .any(|(name, value)| name == "Location" && value == "/settings?updated=1"));
    }

    #[test]
    fn settings_update_rejects_invalid_archive_mailbox_name() {
        let response = app().handle_request(
            &request(
                "POST",
                "/settings",
                &authenticated_same_origin_headers(),
                "csrf_token=fedcba9876543210fedcba9876543210fedcba9876543210fedcba9876543210&html_display_preference=prefer_plain_text&archive_mailbox_name=Archive%0A2026",
            ),
            "127.0.0.1",
        );

        assert_eq!(response.response.status_code, 400);
        assert!(body_text(&response).contains("archive mailbox name was not valid"));
    }

    #[test]
    fn settings_update_rejects_nonexistent_archive_mailbox_name() {
        let response = app().handle_request(
            &request(
                "POST",
                "/settings",
                &authenticated_same_origin_headers(),
                "csrf_token=fedcba9876543210fedcba9876543210fedcba9876543210fedcba9876543210&html_display_preference=prefer_plain_text&archive_mailbox_name=MissingArchive",
            ),
            "127.0.0.1",
        );

        assert_eq!(response.response.status_code, 400);
        assert!(body_text(&response)
            .contains("The selected archive mailbox does not exist for this account."));
        assert!(!response
            .response
            .headers
            .iter()
            .any(|(name, value)| name == "Location" && value == "/settings?updated=1"));
    }

    #[test]
    fn message_view_hides_archive_shortcut_when_setting_target_is_missing() {
        let response = app().handle_request(
            &request(
                "GET",
                "/message?mailbox=INBOX&uid=9",
                &[
                    ("User-Agent", "Firefox/InvalidArchiveTest"),
                    (
                        "Cookie",
                        "osmap_session=aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
                    ),
                ],
                "",
            ),
            "127.0.0.1",
        );

        assert_eq!(response.response.status_code, 200);
        let body = body_text(&response);
        assert!(!body.contains("name=\"destination_mailbox\" value=\"MissingArchive\""));
        assert!(body.contains("Set an archive mailbox in Settings"));
    }

    #[test]
    fn send_route_accepts_bounded_multipart_attachment_upload() {
        let body = concat!(
            "--test-boundary\r\n",
            "Content-Disposition: form-data; name=\"csrf_token\"\r\n\r\n",
            "fedcba9876543210fedcba9876543210fedcba9876543210fedcba9876543210\r\n",
            "--test-boundary\r\n",
            "Content-Disposition: form-data; name=\"to\"\r\n\r\n",
            "bob@example.com\r\n",
            "--test-boundary\r\n",
            "Content-Disposition: form-data; name=\"subject\"\r\n\r\n",
            "Quarterly report\r\n",
            "--test-boundary\r\n",
            "Content-Disposition: form-data; name=\"body\"\r\n\r\n",
            "See attachment.\r\n",
            "--test-boundary\r\n",
            "Content-Disposition: form-data; name=\"attachment\"; filename=\"report.bin\"\r\n",
            "Content-Type: application/octet-stream\r\n\r\n",
        );
        let mut multipart_body = body.as_bytes().to_vec();
        multipart_body.extend_from_slice(&[0x00, 0xff, 0x10, 0x41]);
        multipart_body.extend_from_slice(b"\r\n--test-boundary--\r\n");

        let response = app().handle_request(
            &native_compose_request_bytes(&app(),
                "POST",
                "/send",
                &[
                    ("User-Agent", "Firefox/Test"),
                    (
                        "Cookie",
                        "osmap_session=aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
                    ),
                    ("Origin", "https://localhost"),
                    ("Content-Type", "multipart/form-data; boundary=test-boundary"),
                ],
                &multipart_body,
            ),
            "127.0.0.1",
        );

        assert_eq!(response.response.status_code, 303);
        assert!(response
            .response
            .headers
            .iter()
            .any(|(name, value)| name == "Location" && value.starts_with("/compose?receipt=")));
    }

    #[test]
    fn send_route_accepts_attachment_larger_than_legacy_tiny_limit() {
        let body = concat!(
            "--test-boundary\r\n",
            "Content-Disposition: form-data; name=\"csrf_token\"\r\n\r\n",
            "fedcba9876543210fedcba9876543210fedcba9876543210fedcba9876543210\r\n",
            "--test-boundary\r\n",
            "Content-Disposition: form-data; name=\"to\"\r\n\r\n",
            "bob@example.com\r\n",
            "--test-boundary\r\n",
            "Content-Disposition: form-data; name=\"subject\"\r\n\r\n",
            "Policy sized attachment\r\n",
            "--test-boundary\r\n",
            "Content-Disposition: form-data; name=\"body\"\r\n\r\n",
            "See attachment.\r\n",
            "--test-boundary\r\n",
            "Content-Disposition: form-data; name=\"attachment\"; filename=\"report.pdf\"\r\n",
            "Content-Type: application/pdf\r\n\r\n",
        );
        let mut multipart_body = body.as_bytes().to_vec();
        multipart_body.extend(std::iter::repeat_n(b'A', 300 * 1024));
        multipart_body.extend_from_slice(b"\r\n--test-boundary--\r\n");

        let response = app().handle_request(
            &native_compose_request_bytes(&app(),
                "POST",
                "/send",
                &[
                    ("User-Agent", "Firefox/Test"),
                    (
                        "Cookie",
                        "osmap_session=aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
                    ),
                    ("Origin", "https://localhost"),
                    ("Content-Type", "multipart/form-data; boundary=test-boundary"),
                ],
                &multipart_body,
            ),
            "127.0.0.1",
        );

        assert_eq!(response.response.status_code, 303);
        assert!(!response
            .audit_events
            .iter()
            .any(|event| event.action == "http_send_parse_failed"));
    }

    #[test]
    fn send_route_reports_oversized_attachment_limit() {
        let body = concat!(
            "--test-boundary\r\n",
            "Content-Disposition: form-data; name=\"csrf_token\"\r\n\r\n",
            "fedcba9876543210fedcba9876543210fedcba9876543210fedcba9876543210\r\n",
            "--test-boundary\r\n",
            "Content-Disposition: form-data; name=\"to\"\r\n\r\n",
            "bob@example.com\r\n",
            "--test-boundary\r\n",
            "Content-Disposition: form-data; name=\"subject\"\r\n\r\n",
            "Oversized attachment\r\n",
            "--test-boundary\r\n",
            "Content-Disposition: form-data; name=\"body\"\r\n\r\n",
            "See attachment.\r\n",
            "--test-boundary\r\n",
            "Content-Disposition: form-data; name=\"attachment\"; filename=\"large.pdf\"\r\n",
            "Content-Type: application/pdf\r\n\r\n",
        );
        let mut multipart_body = body.as_bytes().to_vec();
        multipart_body.extend(std::iter::repeat_n(b'A', DEFAULT_ATTACHMENT_MAX_BYTES + 1));
        multipart_body.extend_from_slice(b"\r\n--test-boundary--\r\n");

        let response = app().handle_request(
            &native_compose_request_bytes(&app(),
                "POST",
                "/send",
                &[
                    ("User-Agent", "Firefox/Test"),
                    (
                        "Cookie",
                        "osmap_session=aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
                    ),
                    ("Origin", "https://localhost"),
                    ("Content-Type", "multipart/form-data; boundary=test-boundary"),
                ],
                &multipart_body,
            ),
            "127.0.0.1",
        );

        assert_eq!(response.response.status_code, 400);
        assert!(body_text(&response).contains("10 MiB per-file compose limit"));
        assert!(response.audit_events.iter().any(|event| {
            event.action == "http_send_parse_failed"
                && event.fields.iter().any(|field| {
                    field.key == "reason"
                        && field
                            .value
                            .starts_with("attachment body exceeded maximum length")
                })
        }));
    }

    #[test]
    fn logout_clears_session_cookie() {
        let response = app().handle_request(
            &request(
                "POST",
                "/logout",
                &authenticated_same_origin_headers(),
                "csrf_token=fedcba9876543210fedcba9876543210fedcba9876543210fedcba9876543210",
            ),
            "127.0.0.1",
        );

        assert_eq!(response.response.status_code, 303);
        assert!(response
            .response
            .headers
            .iter()
            .any(|(name, value)| name == "Set-Cookie" && value.contains("Max-Age=0")));
    }

    #[test]
    fn logout_rejects_unsupported_form_content_type() {
        let response = app().handle_request(
            &request(
                "POST",
                "/logout",
                &[
                    ("User-Agent", "Firefox/Test"),
                    (
                        "Cookie",
                        "osmap_session=aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
                    ),
                    ("Origin", "https://localhost"),
                    ("Content-Type", "multipart/form-data; boundary=test-boundary"),
                ],
                "--test-boundary--\r\n",
            ),
            "127.0.0.1",
        );

        assert_eq!(response.response.status_code, 400);
        assert!(body_text(&response).contains("content type was not supported"));
    }

    #[test]
    fn settings_update_requires_same_origin_request_metadata() {
        let response = app().handle_request(
            &request(
                "POST",
                "/settings",
                &authenticated_headers(),
                "csrf_token=fedcba9876543210fedcba9876543210fedcba9876543210fedcba9876543210&html_display_preference=prefer_plain_text",
            ),
            "127.0.0.1",
        );

        assert_eq!(response.response.status_code, 403);
        assert!(body_text(&response).contains("Request Origin Rejected"));
    }

    #[test]
    fn settings_update_accepts_same_origin_referer_when_origin_is_absent() {
        let response = app().handle_request(
            &request(
                "POST",
                "/settings",
                &authenticated_same_origin_referer_headers(),
                "csrf_token=fedcba9876543210fedcba9876543210fedcba9876543210fedcba9876543210&html_display_preference=prefer_plain_text&archive_mailbox_name=Archive%2F2026",
            ),
            "127.0.0.1",
        );

        assert_eq!(response.response.status_code, 303);
        assert!(response
            .response
            .headers
            .iter()
            .any(|(name, value)| name == "Location" && value == "/settings?updated=1"));
    }

    #[test]
    fn send_route_accepts_opaque_origin_when_same_origin_referer_is_present() {
        let response = app().handle_request(
            &native_compose_request(&app(),
                "POST",
                "/send",
                &[
                    ("User-Agent", "Firefox/Test"),
                    (
                        "Cookie",
                        "osmap_session=aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
                    ),
                    ("Origin", "null"),
                    ("Referer", "https://localhost/compose"),
                ],
                "csrf_token=fedcba9876543210fedcba9876543210fedcba9876543210fedcba9876543210&to=bob%40example.com&subject=Test&body=Hello",
            ),
            "127.0.0.1",
        );

        assert_eq!(response.response.status_code, 303);
        assert!(response
            .response
            .headers
            .iter()
            .any(|(name, value)| name == "Location" && value.starts_with("/compose?receipt=")));
    }

    #[test]
    fn send_route_accepts_same_origin_fetch_metadata_when_origin_is_opaque() {
        let response = app().handle_request(
            &native_compose_request(&app(),
                "POST",
                "/send",
                &[
                    ("User-Agent", "Firefox/Test"),
                    (
                        "Cookie",
                        "osmap_session=aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
                    ),
                    ("Origin", "null"),
                    ("Sec-Fetch-Site", "same-origin"),
                ],
                "csrf_token=fedcba9876543210fedcba9876543210fedcba9876543210fedcba9876543210&to=bob%40example.com&subject=Test&body=Hello",
            ),
            "127.0.0.1",
        );

        assert_eq!(response.response.status_code, 303);
        assert!(response
            .response
            .headers
            .iter()
            .any(|(name, value)| name == "Location" && value.starts_with("/compose?receipt=")));
    }

    #[test]
    fn settings_update_accepts_same_origin_fetch_metadata_when_origin_and_referer_are_absent() {
        let response = app().handle_request(
            &request(
                "POST",
                "/settings",
                &[
                    ("User-Agent", "Firefox/Test"),
                    (
                        "Cookie",
                        "osmap_session=aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
                    ),
                    ("Sec-Fetch-Site", "same-origin"),
                ],
                "csrf_token=fedcba9876543210fedcba9876543210fedcba9876543210fedcba9876543210&html_display_preference=prefer_plain_text",
            ),
            "127.0.0.1",
        );

        assert_eq!(response.response.status_code, 303);
        assert!(response
            .response
            .headers
            .iter()
            .any(|(name, value)| name == "Location" && value == "/settings?updated=1"));
    }

    #[test]
    fn authenticated_post_routes_reject_opaque_origin_without_same_origin_referer() {
        let response = app().handle_request(
            &request(
                "POST",
                "/logout",
                &[
                    ("User-Agent", "Firefox/Test"),
                    (
                        "Cookie",
                        "osmap_session=aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
                    ),
                    ("Origin", "null"),
                ],
                "csrf_token=fedcba9876543210fedcba9876543210fedcba9876543210fedcba9876543210",
            ),
            "127.0.0.1",
        );

        assert_eq!(response.response.status_code, 403);
        assert!(body_text(&response).contains("Request Origin Rejected"));
    }

    #[test]
    fn authenticated_post_routes_reject_cross_site_fetch_metadata_without_origin_or_referer() {
        let response = app().handle_request(
            &request(
                "POST",
                "/logout",
                &[
                    ("User-Agent", "Firefox/Test"),
                    (
                        "Cookie",
                        "osmap_session=aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
                    ),
                    ("Sec-Fetch-Site", "cross-site"),
                ],
                "csrf_token=fedcba9876543210fedcba9876543210fedcba9876543210fedcba9876543210",
            ),
            "127.0.0.1",
        );

        assert_eq!(response.response.status_code, 403);
        assert!(body_text(&response).contains("Request Origin Rejected"));
    }

    #[test]
    fn authenticated_post_routes_reject_cross_origin_headers() {
        for (path, body) in [
            (
                "/send",
                "csrf_token=fedcba9876543210fedcba9876543210fedcba9876543210fedcba9876543210&to=bob%40example.com&subject=Test&body=Hello",
            ),
            (
                "/message/move",
                "csrf_token=fedcba9876543210fedcba9876543210fedcba9876543210fedcba9876543210&mailbox=INBOX&uid=9&destination_mailbox=Archive%2F2026",
            ),
            (
                "/messages/archive",
                "csrf_token=fedcba9876543210fedcba9876543210fedcba9876543210fedcba9876543210&mailbox=INBOX&destination_mailbox=Archive%2F2026&uid_9=9",
            ),
            (
                "/drafts/save",
                "csrf_token=fedcba9876543210fedcba9876543210fedcba9876543210fedcba9876543210&to=bob%40example.com&subject=Draft&body=Body",
            ),
            (
                "/drafts/delete",
                "csrf_token=fedcba9876543210fedcba9876543210fedcba9876543210fedcba9876543210&draft_id=00000000000000000000000000000001",
            ),
            (
                "/drafts/star",
                "csrf_token=fedcba9876543210fedcba9876543210fedcba9876543210fedcba9876543210",
            ),
            (
                "/drafts/discard",
                "csrf_token=fedcba9876543210fedcba9876543210fedcba9876543210fedcba9876543210",
            ),
            (
                "/sessions/revoke",
                "csrf_token=fedcba9876543210fedcba9876543210fedcba9876543210fedcba9876543210&session_id=bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb",
            ),
            (
                "/settings",
                "csrf_token=fedcba9876543210fedcba9876543210fedcba9876543210fedcba9876543210&html_display_preference=prefer_plain_text",
            ),
            (
                "/logout",
                "csrf_token=fedcba9876543210fedcba9876543210fedcba9876543210fedcba9876543210",
            ),
        ] {
            let response = app().handle_request(
                &request(
                    "POST",
                    path,
                    &[
                        ("User-Agent", "Firefox/Test"),
                        (
                            "Cookie",
                            "osmap_session=aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
                        ),
                        ("Origin", "https://evil.example"),
                    ],
                    body,
                ),
                "127.0.0.1",
            );

            assert_eq!(response.response.status_code, 403, "route {path} should reject");
            assert!(body_text(&response).contains("Request Origin Rejected"));
        }
    }

    #[test]
    fn logger_renders_http_events_stably() {
        let logger = Logger::new(crate::config::LogFormat::Text, LogLevel::Debug);
        let rendered = logger.render_with_timestamp(
            &build_http_info_event(
                "http_login_form_served",
                "login form served",
                &AuthenticationContext::new(
                    AuthenticationPolicy::default(),
                    "http-1",
                    "127.0.0.1",
                    "Firefox/Test",
                )
                .expect("context should be valid"),
            ),
            4242,
        );

        assert_eq!(
            rendered,
            "ts=\"1970-01-01T01:10:42Z\" ts_unix=4242 level=info category=http action=http_login_form_served msg=\"login form served\" request_id=\"http-1\" remote_addr=\"127.0.0.1\" user_agent=\"Firefox/Test\""
        );
    }

    #[test]
    fn rejects_duplicate_http_headers() {
        let error = parse_http_request(
            "GET /mailboxes HTTP/1.1\r\nHost: localhost\r\nHost: duplicate\r\n\r\n",
            &HttpPolicy::default(),
        )
        .expect_err("duplicate headers must be rejected");

        assert_eq!(error.reason, "duplicate http header: host");
    }

    #[test]
    fn rejects_empty_host_headers() {
        let error = parse_http_request(
            "GET /mailboxes HTTP/1.1\r\nHost: \r\n\r\n",
            &HttpPolicy::default(),
        )
        .expect_err("empty host headers must be rejected");

        assert_eq!(error.reason, "host header must not be empty");
    }

    #[test]
    fn rejects_host_headers_with_path_characters() {
        let error = parse_http_request(
            "GET /mailboxes HTTP/1.1\r\nHost: localhost/example\r\n\r\n",
            &HttpPolicy::default(),
        )
        .expect_err("host headers with path characters must be rejected");

        assert_eq!(error.reason, "host header contained unsupported characters");
    }

    #[test]
    fn rejects_oversized_cookie_headers() {
        let oversized_cookie = format!(
            "Cookie: {}\r\n",
            "a".repeat(DEFAULT_HTTP_MAX_COOKIE_HEADER_BYTES + 1)
        );
        let raw = format!("GET /mailboxes HTTP/1.1\r\nHost: localhost\r\n{oversized_cookie}\r\n");

        let error = parse_http_request(&raw, &HttpPolicy::default())
            .expect_err("oversized cookie headers must be rejected");

        assert_eq!(error.reason, "cookie header exceeded maximum length");
    }

    #[test]
    fn rejects_http11_requests_without_host() {
        let error = parse_http_request(
            "GET /mailboxes HTTP/1.1\r\nUser-Agent: curl/8\r\n\r\n",
            &HttpPolicy::default(),
        )
        .expect_err("hostless http/1.1 requests must be rejected");

        assert_eq!(error.reason, "http/1.1 requests must include host");
    }

    #[test]
    fn rejects_request_targets_with_fragments() {
        let error = parse_http_request(
            "GET /mailboxes#fragment HTTP/1.1\r\nHost: localhost\r\n\r\n",
            &HttpPolicy::default(),
        )
        .expect_err("fragment targets must be rejected");

        assert_eq!(error.reason, "request target fragments are not supported");
    }

    #[test]
    fn rejects_request_targets_that_are_too_large() {
        let oversized_target = format!("/{}", "a".repeat(DEFAULT_HTTP_MAX_REQUEST_TARGET_BYTES));
        let raw = format!("GET {oversized_target} HTTP/1.1\r\nHost: localhost\r\n\r\n");

        let error = parse_http_request(&raw, &HttpPolicy::default())
            .expect_err("oversized targets must be rejected");

        assert_eq!(error.reason, "request target exceeded maximum length");
    }

    #[test]
    fn rejects_request_targets_with_non_normalized_slashes() {
        let error = parse_http_request(
            "GET //mailboxes HTTP/1.1\r\nHost: localhost\r\n\r\n",
            &HttpPolicy::default(),
        )
        .expect_err("non-normalized request paths must be rejected");

        assert_eq!(error.reason, "request target path must be normalized");
    }

    #[test]
    fn rejects_request_targets_with_dot_segments() {
        let error = parse_http_request(
            "GET /mailboxes/../login HTTP/1.1\r\nHost: localhost\r\n\r\n",
            &HttpPolicy::default(),
        )
        .expect_err("dot-segment request paths must be rejected");

        assert_eq!(
            error.reason,
            "request target path must not contain dot segments"
        );
    }

    #[test]
    fn rejects_duplicate_query_parameters() {
        let error = parse_http_request(
            "GET /mailbox?name=INBOX&name=Archive HTTP/1.1\r\nHost: localhost\r\n\r\n",
            &HttpPolicy::default(),
        )
        .expect_err("duplicate query fields must be rejected");

        assert_eq!(error.reason, "duplicate form field: name");
    }

    #[test]
    fn rejects_unsupported_transfer_encoding_headers() {
        let error = parse_http_request(
            "POST /login HTTP/1.1\r\nHost: localhost\r\nTransfer-Encoding: chunked\r\n\r\n",
            &HttpPolicy::default(),
        )
        .expect_err("unsupported transfer-encoding must be rejected");

        assert_eq!(error.reason, "unsupported transfer-encoding header");
    }

    #[test]
    fn rejects_extra_bytes_after_declared_body_length() {
        let error = parse_http_request(
            "POST /login HTTP/1.1\r\nHost: localhost\r\nContent-Length: 4\r\n\r\nuser=alice",
            &HttpPolicy::default(),
        )
        .expect_err("extra bytes after content-length must be rejected");

        assert_eq!(
            error.reason,
            "http body length did not match content-length"
        );
    }

    #[test]
    fn rejects_pipelined_second_request_bytes() {
        let error = parse_http_request(
            "POST /login HTTP/1.1\r\nHost: localhost\r\nContent-Length: 0\r\n\r\nGET /mailboxes HTTP/1.1\r\nHost: localhost\r\n\r\n",
            &HttpPolicy::default(),
        )
        .expect_err("pipelined second request bytes must be rejected");

        assert_eq!(
            error.reason,
            "http body length did not match content-length"
        );
    }

    #[test]
    fn rejects_duplicate_content_length_body_framing() {
        let error = parse_http_request(
            "POST /login HTTP/1.1\r\nHost: localhost\r\nContent-Length: 0\r\nContent-Length: 4\r\n\r\nbody",
            &HttpPolicy::default(),
        )
        .expect_err("duplicate content-length must be rejected");

        assert_eq!(error.reason, "duplicate http header: content-length");
    }

    #[test]
    fn rejects_get_requests_with_bodies() {
        let error = parse_http_request(
            "GET /mailboxes HTTP/1.1\r\nHost: localhost\r\nContent-Length: 5\r\n\r\nhello",
            &HttpPolicy::default(),
        )
        .expect_err("get requests with bodies must be rejected");

        assert_eq!(error.reason, "get requests must not send a request body");
    }

    #[test]
    fn rejects_post_requests_without_content_length_even_when_empty() {
        let error = parse_http_request(
            "POST /logout HTTP/1.1\r\nHost: localhost\r\n\r\n",
            &HttpPolicy::default(),
        )
        .expect_err("post requests without content-length must be rejected");

        assert_eq!(error.reason, "post requests must send content-length");
    }

    #[test]
    fn rejects_duplicate_session_cookies() {
        let request = parse_http_request(
            "GET /mailboxes HTTP/1.1\r\nHost: localhost\r\nCookie: osmap_session=aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa; osmap_session=bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb\r\n\r\n",
            &HttpPolicy::default(),
        )
        .expect("request should parse");

        assert_eq!(
            session_cookie_value(&request, DEFAULT_SESSION_COOKIE_NAME),
            None
        );
    }

    #[test]
    fn rejects_invalid_session_cookie_values() {
        let request = parse_http_request(
            "GET /mailboxes HTTP/1.1\r\nHost: localhost\r\nCookie: osmap_session=\"quoted\"\r\n\r\n",
            &HttpPolicy::default(),
        )
        .expect("request should parse");

        assert_eq!(
            session_cookie_value(&request, DEFAULT_SESSION_COOKIE_NAME),
            None
        );
    }

    fn temp_dir(prefix: &str) -> PathBuf {
        let dir = std::env::temp_dir().join(format!("{prefix}-{}", std::process::id()));
        let _ = fs::remove_dir_all(&dir);
        fs::create_dir_all(&dir).expect("temp dir should be created");
        dir
    }

    fn with_connected_streams<F>(handler: F) -> Vec<u8>
    where
        F: FnOnce(std::net::TcpStream) + Send + 'static,
    {
        let listener = TcpListener::bind("127.0.0.1:0").expect("listener should bind");
        let addr = listener.local_addr().expect("listener addr should exist");
        let server = thread::spawn(move || {
            let (stream, _) = listener.accept().expect("server should accept client");
            handler(stream);
        });

        let mut client = std::net::TcpStream::connect(addr).expect("client should connect");
        let mut response = Vec::new();
        client
            .read_to_end(&mut response)
            .expect("client should read response");
        server.join().expect("server thread should finish");
        response
    }

    #[test]
    fn read_http_request_reports_truncated_headers_when_peer_closes_early() {
        let listener = TcpListener::bind("127.0.0.1:0").expect("listener should bind");
        let addr = listener.local_addr().expect("listener addr should exist");
        let server = thread::spawn(move || {
            let (mut stream, _) = listener.accept().expect("server should accept client");
            let error = crate::http_parse::read_http_request(&mut stream, &HttpPolicy::default())
                .expect_err("truncated headers must be rejected");
            assert_eq!(error.kind, HttpRequestErrorKind::Truncated);
            assert_eq!(
                error.reason,
                "connection closed before complete http headers were received"
            );
        });

        let mut client = std::net::TcpStream::connect(addr).expect("client should connect");
        client
            .write_all(b"GET /mailboxes HTTP/1.1\r\nHost: localhost\r\n")
            .expect("client should write partial header");
        client
            .shutdown(Shutdown::Write)
            .expect("client should close write side");

        server.join().expect("server thread should finish");
    }

    #[test]
    fn login_form_uses_trusted_loopback_proxy_client_ip_for_audit_context() {
        let response = app().handle_request(
            &request(
                "GET",
                "/login",
                &[
                    ("User-Agent", "Firefox/Test"),
                    ("X-Real-IP", "198.51.100.24"),
                ],
                "",
            ),
            "127.0.0.1",
        );

        assert_eq!(response.response.status_code, 200);
        let event = response
            .audit_events
            .first()
            .expect("login form should emit one audit event");
        assert!(event
            .fields
            .iter()
            .any(|field| field.key == "remote_addr" && field.value == "198.51.100.24"));
    }

    #[test]
    fn login_form_ignores_proxy_client_ip_headers_from_non_loopback_peers() {
        let response = app().handle_request(
            &request(
                "GET",
                "/login",
                &[
                    ("User-Agent", "Firefox/Test"),
                    ("X-Real-IP", "198.51.100.24"),
                ],
                "",
            ),
            "203.0.113.9",
        );

        assert_eq!(response.response.status_code, 200);
        let event = response
            .audit_events
            .first()
            .expect("login form should emit one audit event");
        assert!(event
            .fields
            .iter()
            .any(|field| field.key == "remote_addr" && field.value == "203.0.113.9"));
    }

    #[test]
    fn read_http_request_reports_truncated_bodies_when_peer_closes_early() {
        let listener = TcpListener::bind("127.0.0.1:0").expect("listener should bind");
        let addr = listener.local_addr().expect("listener addr should exist");
        let server = thread::spawn(move || {
            let (mut stream, _) = listener.accept().expect("server should accept client");
            let error = crate::http_parse::read_http_request(&mut stream, &HttpPolicy::default())
                .expect_err("truncated body must be rejected");
            assert_eq!(error.kind, HttpRequestErrorKind::Truncated);
            assert_eq!(
                error.reason,
                "connection closed before complete http body was received"
            );
        });

        let mut client = std::net::TcpStream::connect(addr).expect("client should connect");
        client
            .write_all(b"POST /logout HTTP/1.1\r\nHost: localhost\r\nContent-Length: 4\r\n\r\nx")
            .expect("client should write partial body");
        client
            .shutdown(Shutdown::Write)
            .expect("client should close write side");

        server.join().expect("server thread should finish");
    }

    #[test]
    fn connection_timeout_returns_request_timeout_response() {
        let response = with_connected_streams(|mut stream| {
            let policy = HttpPolicy {
                read_timeout_secs: 1,
                ..HttpPolicy::default()
            };
            let app = BrowserApp::new(policy, StubGateway::default());
            let logger = Logger::new(crate::config::LogFormat::Text, LogLevel::Debug);
            super::http_runtime::handle_client_stream(&app, &logger, &mut stream);
        });

        let text = String::from_utf8(response).expect("response should be utf-8");
        assert!(text.starts_with("HTTP/1.1 408 Request Timeout\r\n"));
        assert!(text.contains("\r\nConnection: close\r\n"));
        assert!(text.contains("The request was not completed before the connection timed out."));
    }

    #[test]
    fn empty_connection_closes_without_emitting_http_response() {
        let listener = TcpListener::bind("127.0.0.1:0").expect("listener should bind");
        let addr = listener.local_addr().expect("listener addr should exist");
        let server = thread::spawn(move || {
            let (mut stream, _) = listener.accept().expect("server should accept client");
            let app = BrowserApp::new(HttpPolicy::default(), StubGateway::default());
            let logger = Logger::new(crate::config::LogFormat::Text, LogLevel::Debug);
            super::http_runtime::handle_client_stream(&app, &logger, &mut stream);
        });

        let mut client = std::net::TcpStream::connect(addr).expect("client should connect");
        client
            .shutdown(Shutdown::Write)
            .expect("client should close write side");
        let mut response = Vec::new();
        client
            .read_to_end(&mut response)
            .expect("client should read response");

        server.join().expect("server thread should finish");
        assert!(response.is_empty());
    }

    #[test]
    fn truncated_connection_closes_without_emitting_http_response() {
        let listener = TcpListener::bind("127.0.0.1:0").expect("listener should bind");
        let addr = listener.local_addr().expect("listener addr should exist");
        let server = thread::spawn(move || {
            let (mut stream, _) = listener.accept().expect("server should accept client");
            let app = BrowserApp::new(HttpPolicy::default(), StubGateway::default());
            let logger = Logger::new(crate::config::LogFormat::Text, LogLevel::Debug);
            super::http_runtime::handle_client_stream(&app, &logger, &mut stream);
        });

        let mut client = std::net::TcpStream::connect(addr).expect("client should connect");
        client
            .write_all(b"GET /mailboxes HTTP/1.1\r\nHost: localhost\r\n")
            .expect("client should write partial request");
        client
            .shutdown(Shutdown::Write)
            .expect("client should close write side");
        let mut response = Vec::new();
        client
            .read_to_end(&mut response)
            .expect("client should read response");

        server.join().expect("server thread should finish");
        assert!(response.is_empty());
    }

    #[test]
    fn accept_failure_backoff_caps_at_one_second() {
        assert_eq!(super::http_runtime::accept_failure_backoff_millis(0), 0);
        assert_eq!(super::http_runtime::accept_failure_backoff_millis(1), 50);
        assert_eq!(super::http_runtime::accept_failure_backoff_millis(2), 100);
        assert_eq!(super::http_runtime::accept_failure_backoff_millis(3), 200);
        assert_eq!(super::http_runtime::accept_failure_backoff_millis(4), 400);
        assert_eq!(super::http_runtime::accept_failure_backoff_millis(5), 800);
        assert_eq!(super::http_runtime::accept_failure_backoff_millis(6), 1000);
        assert_eq!(super::http_runtime::accept_failure_backoff_millis(12), 1000);
    }

    #[test]
    fn accept_failure_event_escalates_after_threshold() {
        let warn_event =
            super::http_runtime::build_accept_failure_event("temporary".to_string(), 2, 100);
        assert_eq!(warn_event.level, LogLevel::Warn);
        assert_eq!(warn_event.action, "http_accept_failed");
        assert!(warn_event
            .fields
            .iter()
            .any(|field| field.key == "consecutive_failures" && field.value == "2"));

        let error_event =
            super::http_runtime::build_accept_failure_event("persistent".to_string(), 5, 800);
        assert_eq!(error_event.level, LogLevel::Error);
        assert_eq!(error_event.action, "http_accept_failed_sustained");
        assert!(error_event
            .fields
            .iter()
            .any(|field| field.key == "consecutive_failures" && field.value == "5"));
        assert!(error_event
            .fields
            .iter()
            .any(|field| field.key == "backoff_millis" && field.value == "800"));
    }

    #[test]
    fn accept_recovery_event_reports_previous_failure_streak() {
        let event = super::http_runtime::build_accept_recovery_event(7);

        assert_eq!(event.level, LogLevel::Info);
        assert_eq!(event.category, EventCategory::Http);
        assert_eq!(event.action, "http_accept_recovered");
        assert!(event
            .fields
            .iter()
            .any(|field| { field.key == "previous_consecutive_failures" && field.value == "7" }));
    }

    #[test]
    fn response_write_failure_event_escalates_after_threshold() {
        let warn_event = super::http_runtime::build_response_write_failure_event(
            super::http_runtime::ResponseWriteFailureContext {
                remote_addr: "127.0.0.1".to_string(),
                reason: "temporary".to_string(),
                consecutive_failures: 2,
                status_code: Some(200),
                request_context: Some(("GET", "/mailboxes", 512)),
                response_bytes: 512,
                active_connections: None,
                over_capacity_response: false,
            },
        );
        assert_eq!(warn_event.level, LogLevel::Warn);
        assert_eq!(warn_event.action, "http_response_write_failed");

        let error_event = super::http_runtime::build_response_write_failure_event(
            super::http_runtime::ResponseWriteFailureContext {
                remote_addr: "127.0.0.1".to_string(),
                reason: "persistent".to_string(),
                consecutive_failures: 5,
                status_code: Some(503),
                request_context: None,
                response_bytes: 128,
                active_connections: Some(16),
                over_capacity_response: true,
            },
        );
        assert_eq!(error_event.level, LogLevel::Error);
        assert_eq!(
            error_event.action,
            "http_over_capacity_response_write_failed_sustained"
        );
        assert!(error_event
            .fields
            .iter()
            .any(|field| field.key == "consecutive_failures" && field.value == "5"));
    }

    #[test]
    fn request_completion_event_is_warn_for_slow_requests() {
        let event = super::http_runtime::build_request_completion_event(
            "127.0.0.1",
            HttpMethod::Get,
            "/mailboxes",
            200,
            512,
            Duration::from_millis(1500),
        );

        assert_eq!(event.level, LogLevel::Warn);
        assert_eq!(event.category, EventCategory::Http);
        assert_eq!(event.action, "http_request_slow");
        assert!(event
            .fields
            .iter()
            .any(|field| field.key == "method" && field.value == "GET"));
        assert!(event
            .fields
            .iter()
            .any(|field| field.key == "path" && field.value == "/mailboxes"));
        assert!(event
            .fields
            .iter()
            .any(|field| field.key == "status_code" && field.value == "200"));
        assert!(event
            .fields
            .iter()
            .any(|field| field.key == "response_bytes" && field.value == "512"));
        assert!(event
            .fields
            .iter()
            .any(|field| field.key == "duration_ms" && field.value == "1500"));
    }

    #[test]
    fn connection_slots_are_capped_by_policy_limit() {
        let active_connections = AtomicUsize::new(0);
        let policy = HttpPolicy {
            max_concurrent_connections: 2,
            ..HttpPolicy::default()
        };

        assert_eq!(
            super::http_runtime::try_acquire_connection_slot(&active_connections, &policy),
            Some(1)
        );
        assert_eq!(
            super::http_runtime::try_acquire_connection_slot(&active_connections, &policy),
            Some(2)
        );
        assert_eq!(
            super::http_runtime::try_acquire_connection_slot(&active_connections, &policy),
            None
        );
    }

    #[test]
    fn connection_high_watermark_event_warns_at_capacity() {
        let policy = HttpPolicy {
            max_concurrent_connections: 4,
            ..HttpPolicy::default()
        };

        let event = super::http_runtime::build_connection_high_watermark_event(&policy, 4);

        assert_eq!(event.level, LogLevel::Warn);
        assert_eq!(event.category, EventCategory::Http);
        assert_eq!(event.action, "http_connection_capacity_reached");
        assert!(event
            .fields
            .iter()
            .any(|field| { field.key == "active_connections" && field.value == "4" }));
        assert!(event
            .fields
            .iter()
            .any(|field| { field.key == "max_concurrent_connections" && field.value == "4" }));
        assert!(event
            .fields
            .iter()
            .any(|field| { field.key == "utilization_percent" && field.value == "100" }));
    }

    #[test]
    fn connection_worker_spawn_failure_releases_slot_and_reports_error() {
        let listener = TcpListener::bind("127.0.0.1:0").expect("listener should bind");
        let addr = listener.local_addr().expect("listener addr should exist");
        let _client = std::net::TcpStream::connect(addr).expect("client should connect");
        let (stream, _) = listener.accept().expect("server should accept client");
        let active_connections = Arc::new(AtomicUsize::new(1));
        let app = Arc::new(BrowserApp::new(
            HttpPolicy::default(),
            StubGateway::default(),
        ));
        let logger = Logger::new(crate::config::LogFormat::Text, LogLevel::Debug);
        let write_failures = Arc::new(AtomicUsize::new(0));

        let event = super::http_runtime::spawn_connection_worker(
            app,
            logger,
            stream,
            Arc::clone(&active_connections),
            write_failures,
            |_app, _logger, _stream, _active_connections, _write_failures| {
                Err(std::io::Error::other("simulated spawn failure"))
            },
        )
        .expect_err("spawn failure should be surfaced as a log event");

        assert_eq!(
            active_connections.load(std::sync::atomic::Ordering::Acquire),
            0
        );
        assert_eq!(event.level, LogLevel::Error);
        assert_eq!(event.category, EventCategory::Http);
        assert_eq!(event.action, "http_connection_worker_spawn_failed");
        assert!(event
            .fields
            .iter()
            .any(|field| field.key == "reason" && field.value == "simulated spawn failure"));
        assert!(event.fields.iter().any(|field| {
            field.key == "active_connections_before_release" && field.value == "1"
        }));
        assert!(event.fields.iter().any(|field| {
            field.key == "active_connections_after_release" && field.value == "0"
        }));
    }

    #[test]
    fn connection_slot_release_saturates_at_zero() {
        let active_connections = AtomicUsize::new(0);

        assert_eq!(
            super::http_runtime::release_connection_slot(&active_connections),
            0
        );
        assert_eq!(active_connections.load(Ordering::Acquire), 0);
    }

    #[test]
    fn connection_worker_panic_releases_slot_and_reports_error() {
        let listener = TcpListener::bind("127.0.0.1:0").expect("listener should bind");
        let addr = listener.local_addr().expect("listener addr should exist");
        let _client = std::net::TcpStream::connect(addr).expect("client should connect");
        let (mut stream, _) = listener.accept().expect("server should accept client");
        let active_connections = Arc::new(AtomicUsize::new(1));
        let app = BrowserApp::new(HttpPolicy::default(), StubGateway::default());
        let logger = Logger::new(crate::config::LogFormat::Text, LogLevel::Debug);
        let write_failures = AtomicUsize::new(0);

        let event = super::http_runtime::run_connection_worker(
            &app,
            &logger,
            &mut stream,
            &active_connections,
            &write_failures,
            |_app, _logger, _stream, _write_failures| panic!("simulated worker panic"),
        )
        .expect("worker panic should be surfaced as a log event");

        assert_eq!(active_connections.load(Ordering::Acquire), 0);
        assert_eq!(event.level, LogLevel::Error);
        assert_eq!(event.category, EventCategory::Http);
        assert_eq!(event.action, "http_connection_worker_panicked");
        assert!(event
            .fields
            .iter()
            .any(|field| field.key == "reason" && field.value == "simulated worker panic"));
        assert!(event
            .fields
            .iter()
            .any(|field| field.key == "thread_name" && field.value == "osmap-http-conn"));
        assert!(event
            .fields
            .iter()
            .any(|field| field.key == "active_connections_after_release" && field.value == "0"));
    }

    #[test]
    fn successful_response_events_only_emit_completion_for_written_requests() {
        let completion = super::http_runtime::RequestCompletionContext {
            remote_addr: "127.0.0.1".to_string(),
            method: HttpMethod::Get,
            path: "/mailboxes".to_string(),
            status_code: 200,
            response_bytes: 512,
        };
        let no_failures = AtomicUsize::new(0);

        let completion_events = super::http_runtime::build_successful_response_events(
            Some(&completion),
            &no_failures,
            Duration::from_millis(25),
            "127.0.0.1",
        );
        assert!(completion_events
            .iter()
            .any(|event| event.action == "http_request_completed"));

        let recovery_only_events = super::http_runtime::build_successful_response_events(
            None,
            &AtomicUsize::new(5),
            Duration::from_millis(25),
            "127.0.0.1",
        );
        assert!(!recovery_only_events
            .iter()
            .any(|event| event.action == "http_request_completed"));
        assert!(recovery_only_events
            .iter()
            .any(|event| event.action == "http_response_write_recovered"));
    }

    #[test]
    fn successful_response_events_use_effective_remote_addr_for_recovery_after_parsed_requests() {
        let completion = super::http_runtime::RequestCompletionContext {
            remote_addr: "198.51.100.24".to_string(),
            method: HttpMethod::Get,
            path: "/login".to_string(),
            status_code: 200,
            response_bytes: 512,
        };
        let prior_failures = AtomicUsize::new(5);

        let events = super::http_runtime::build_successful_response_events(
            Some(&completion),
            &prior_failures,
            Duration::from_millis(25),
            "127.0.0.1",
        );

        let completion_event = events
            .iter()
            .find(|event| event.action == "http_request_completed")
            .expect("completion event should be present");
        assert!(completion_event
            .fields
            .iter()
            .any(|field| { field.key == "remote_addr" && field.value == "198.51.100.24" }));

        let recovery_event = events
            .iter()
            .find(|event| event.action == "http_response_write_recovered")
            .expect("recovery event should be present");
        assert!(recovery_event
            .fields
            .iter()
            .any(|field| { field.key == "remote_addr" && field.value == "198.51.100.24" }));
    }

    #[test]
    fn over_capacity_connections_receive_service_unavailable() {
        let response = with_connected_streams(|mut stream| {
            let policy = HttpPolicy {
                max_concurrent_connections: 1,
                ..HttpPolicy::default()
            };
            let logger = Logger::new(crate::config::LogFormat::Text, LogLevel::Debug);
            let write_failures = AtomicUsize::new(0);
            super::http_runtime::handle_over_capacity_stream(
                &logger,
                &mut stream,
                &policy,
                1,
                &write_failures,
            );
        });

        let text = String::from_utf8(response).expect("response should be utf-8");
        assert!(text.starts_with("HTTP/1.1 503 Service Unavailable\r\n"));
        assert!(text.contains("\r\nRetry-After: 1\r\n"));
        assert!(text.contains("\r\nConnection: close\r\n"));
        assert!(text.contains("The service is temporarily busy. Please retry shortly."));
    }
}
