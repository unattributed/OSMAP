//! Minimal HTTP and browser handling for the first OSMAP web slice.
//!
//! This module deliberately avoids a framework while the project is still
//! proving its security and operational shape. The goal is not feature breadth;
//! the goal is an explicit, reviewable request path that consumes the existing
//! auth, session, mailbox, and rendering layers.

#[path = "http_browser.rs"]
mod http_browser;
#[path = "http_gateway.rs"]
mod http_gateway;
#[path = "http_runtime.rs"]
mod http_runtime;
mod routes_auth;
mod routes_compose;
mod routes_mail;
mod routes_settings;

use std::collections::BTreeMap;
use std::path::PathBuf;

use crate::attachment::{
    AttachmentDownloadDecision, AttachmentDownloadPolicy, AttachmentDownloadPublicFailureReason,
    AttachmentDownloadService, DownloadedAttachment,
};
use crate::auth::{
    AuthenticationContext, AuthenticationDecision, AuthenticationPolicy, AuthenticationService,
    DoveadmAuthTestBackend, PublicFailureReason, RequiredSecondFactor, SecondFactorService,
    SystemCommandExecutor,
};
#[cfg(test)]
use crate::config::LogLevel;
use crate::config::{AppConfig, RuntimeEnvironment};
use crate::http_form::{parse_compose_form, parse_urlencoded_form};
#[cfg(test)]
use crate::http_parse::normalize_peer_addr;
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
    render_compose_page, render_login_page, render_mailboxes_page, render_message_list_page,
    render_message_search_page, render_message_view_page, render_sessions_page,
    render_settings_page, ComposePageModel, SettingsPageModel,
};
use crate::logging::LogEvent;
#[cfg(test)]
use crate::logging::{EventCategory, Logger};
use crate::mailbox::{
    DoveadmMailboxListBackend, DoveadmMessageListBackend, DoveadmMessageMoveBackend,
    DoveadmMessageSearchBackend, DoveadmMessageViewBackend, MailboxEntry, MailboxListingDecision,
    MailboxListingPolicy, MailboxListingService, MessageListDecision, MessageListPolicy,
    MessageListRequest, MessageListService, MessageMoveDecision, MessageMoveOutcome,
    MessageMovePolicy, MessageMoveRequest, MessageMoveService, MessageSearchDecision,
    MessageSearchPolicy, MessageSearchRequest, MessageSearchResult, MessageSearchService,
    MessageSummary, MessageViewDecision, MessageViewPolicy, MessageViewRequest, MessageViewService,
};
use crate::mailbox_helper::{
    MailboxHelperAttachmentDownloadBackend, MailboxHelperMailboxListBackend,
    MailboxHelperMessageListBackend, MailboxHelperMessageMoveBackend,
    MailboxHelperMessageSearchBackend, MailboxHelperMessageViewBackend, MailboxHelperPolicy,
};
use crate::rendering::{
    HtmlDisplayPreference, PlainTextMessageRenderer, RenderedMessageView, RenderingPolicy,
};
use crate::send::{
    ComposeDraft, ComposeIntent, ComposePolicy, ComposeRequest, SendmailSubmissionBackend,
    SubmissionDecision, SubmissionOutcome, SubmissionPublicFailureReason, SubmissionService,
    UploadedAttachment,
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
pub const DEFAULT_HTTP_MAX_UPLOAD_BODY_BYTES: usize = 1024 * 1024;

/// Conservative upper bound for parsed HTML form fields.
pub const DEFAULT_HTTP_MAX_FORM_FIELDS: usize = 16;

/// Conservative upper bound for header count in one request.
pub const DEFAULT_HTTP_MAX_HEADER_COUNT: usize = 64;

/// Conservative upper bound for the `Host` header value.
pub const DEFAULT_HTTP_MAX_HOST_HEADER_BYTES: usize = 512;

/// Conservative upper bound for one browser `Cookie` header value.
pub const DEFAULT_HTTP_MAX_COOKIE_HEADER_BYTES: usize = 4096;

/// Conservative upper bound for one `Content-Type` header value.
pub const DEFAULT_HTTP_MAX_CONTENT_TYPE_HEADER_BYTES: usize = 256;

/// Conservative per-connection read timeout for the sequential HTTP listener.
pub const DEFAULT_HTTP_READ_TIMEOUT_SECS: u64 = 5;

/// Conservative per-connection write timeout for the sequential HTTP listener.
pub const DEFAULT_HTTP_WRITE_TIMEOUT_SECS: u64 = 5;

/// Conservative bound for concurrently handled HTTP connections.
pub const DEFAULT_HTTP_MAX_CONCURRENT_CONNECTIONS: usize = 16;

/// The fixed cookie name used by the current browser session slice.
pub const DEFAULT_SESSION_COOKIE_NAME: &str = "osmap_session";

/// Policy controlling the first bounded HTTP/browser slice.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct HttpPolicy {
    pub max_header_bytes: usize,
    pub max_request_target_bytes: usize,
    pub max_header_count: usize,
    pub max_query_fields: usize,
    pub max_body_bytes: usize,
    pub max_upload_body_bytes: usize,
    pub max_form_fields: usize,
    pub session_cookie_name: &'static str,
    pub secure_session_cookie: bool,
    pub read_timeout_secs: u64,
    pub write_timeout_secs: u64,
    pub max_concurrent_connections: usize,
    pub authentication_policy: AuthenticationPolicy,
}

impl HttpPolicy {
    /// Builds the browser policy from validated application configuration.
    pub fn from_config(config: &AppConfig) -> Self {
        Self {
            max_header_bytes: DEFAULT_HTTP_MAX_HEADER_BYTES,
            max_request_target_bytes: DEFAULT_HTTP_MAX_REQUEST_TARGET_BYTES,
            max_header_count: DEFAULT_HTTP_MAX_HEADER_COUNT,
            max_query_fields: DEFAULT_HTTP_MAX_QUERY_FIELDS,
            max_body_bytes: DEFAULT_HTTP_MAX_BODY_BYTES,
            max_upload_body_bytes: DEFAULT_HTTP_MAX_UPLOAD_BODY_BYTES,
            max_form_fields: DEFAULT_HTTP_MAX_FORM_FIELDS,
            session_cookie_name: DEFAULT_SESSION_COOKIE_NAME,
            secure_session_cookie: config.environment != RuntimeEnvironment::Development,
            read_timeout_secs: DEFAULT_HTTP_READ_TIMEOUT_SECS,
            write_timeout_secs: DEFAULT_HTTP_WRITE_TIMEOUT_SECS,
            max_concurrent_connections: config.http_max_concurrent_connections as usize,
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
            max_query_fields: DEFAULT_HTTP_MAX_QUERY_FIELDS,
            max_body_bytes: DEFAULT_HTTP_MAX_BODY_BYTES,
            max_upload_body_bytes: DEFAULT_HTTP_MAX_UPLOAD_BODY_BYTES,
            max_form_fields: DEFAULT_HTTP_MAX_FORM_FIELDS,
            session_cookie_name: DEFAULT_SESSION_COOKIE_NAME,
            secure_session_cookie: false,
            read_timeout_secs: DEFAULT_HTTP_READ_TIMEOUT_SECS,
            write_timeout_secs: DEFAULT_HTTP_WRITE_TIMEOUT_SECS,
            max_concurrent_connections: DEFAULT_HTTP_MAX_CONCURRENT_CONNECTIONS,
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
        self.headers.push((name.into(), value.into()));
        self
    }

    /// Encodes the response into a connection-close HTTP/1.1 payload.
    pub fn to_http_bytes(&self) -> Vec<u8> {
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

/// A response plus the log events emitted while building it.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct HandledHttpResponse {
    pub response: HttpResponse,
    pub audit_events: Vec<LogEvent>,
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
}

impl<G> BrowserApp<G> {
    /// Creates a browser app from the supplied policy and gateway.
    pub fn new(policy: HttpPolicy, gateway: G) -> Self {
        Self { policy, gateway }
    }

    /// Returns the current request-reading limits.
    pub fn policy(&self) -> &HttpPolicy {
        &self.policy
    }
}

pub use self::http_browser::{
    BrowserAttachmentDownloadDecision, BrowserAttachmentDownloadOutcome, BrowserGateway,
    BrowserLoginDecision, BrowserLoginOutcome, BrowserLogoutOutcome, BrowserMailboxDecision,
    BrowserMailboxOutcome, BrowserMessageListDecision, BrowserMessageListOutcome,
    BrowserMessageMoveDecision, BrowserMessageMoveOutcome, BrowserMessageSearchDecision,
    BrowserMessageSearchOutcome, BrowserMessageViewDecision, BrowserMessageViewOutcome,
    BrowserSendDecision, BrowserSendOutcome, BrowserSessionDecision, BrowserSessionListDecision,
    BrowserSessionListOutcome, BrowserSessionRevokeDecision, BrowserSessionRevokeOutcome,
    BrowserSessionValidationOutcome, BrowserSettingsDecision, BrowserSettingsOutcome,
    BrowserSettingsUpdateDecision, BrowserSettingsUpdateOutcome, BrowserVisibleSession,
    BrowserVisibleSettings,
};
pub use self::http_gateway::RuntimeBrowserGateway;
pub use self::http_runtime::run_http_server;

#[cfg(test)]
mod tests {
    use super::*;
    use crate::auth::RequiredSecondFactor;
    use crate::mailbox::MessageView;
    use crate::mime::{AttachmentDisposition, MimeBodySource};
    use crate::rendering::RenderingMode;
    use crate::session::SessionRecord;
    use crate::throttle::LoginThrottleStore;
    use std::fs;
    use std::io::{Read as _, Write as _};
    use std::net::{Shutdown, SocketAddr, TcpListener};
    use std::path::PathBuf;
    use std::sync::atomic::{AtomicUsize, Ordering};
    use std::sync::Arc;
    use std::thread;
    use std::time::Duration;

    #[derive(Debug, Clone)]
    struct StubGateway;

    impl StubGateway {
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
    }

    impl BrowserGateway for StubGateway {
        fn login(
            &self,
            _context: &AuthenticationContext,
            username: &str,
            password: &str,
            totp_code: &str,
        ) -> BrowserLoginOutcome {
            if username == "alice@example.com"
                && password == "correct horse battery staple"
                && totp_code == "123456"
            {
                BrowserLoginOutcome {
                    decision: BrowserLoginDecision::Authenticated {
                        canonical_username: username.to_string(),
                        session_token: SessionToken::new(
                            "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
                        )
                        .expect("token should be valid"),
                    },
                    audit_events: vec![LogEvent::new(
                        LogLevel::Info,
                        EventCategory::Auth,
                        "stub_login_ok",
                        "stub login accepted",
                    )],
                }
            } else {
                BrowserLoginOutcome {
                    decision: BrowserLoginDecision::Denied {
                        public_reason: "invalid_credentials".to_string(),
                    },
                    audit_events: vec![LogEvent::new(
                        LogLevel::Warn,
                        EventCategory::Auth,
                        "stub_login_denied",
                        "stub login denied",
                    )],
                }
            }
        }

        fn validate_session(
            &self,
            _context: &AuthenticationContext,
            presented_token: &str,
        ) -> BrowserSessionValidationOutcome {
            if presented_token == "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"
            {
                BrowserSessionValidationOutcome {
                    decision: BrowserSessionDecision::Valid {
                        validated_session: Box::new(Self::validated_session()),
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
            _context: &AuthenticationContext,
            _presented_token: &str,
        ) -> BrowserLogoutOutcome {
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
            _context: &AuthenticationContext,
            validated_session: &ValidatedSession,
        ) -> BrowserSessionListOutcome {
            BrowserSessionListOutcome {
                decision: BrowserSessionListDecision::Listed {
                    canonical_username: validated_session.record.canonical_username.clone(),
                    sessions: vec![
                        BrowserVisibleSession {
                            session_id: validated_session.record.session_id.clone(),
                            issued_at: validated_session.record.issued_at,
                            expires_at: validated_session.record.expires_at,
                            last_seen_at: validated_session.record.last_seen_at,
                            revoked_at: None,
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
            _context: &AuthenticationContext,
            validated_session: &ValidatedSession,
            session_id: &str,
        ) -> BrowserSessionRevokeOutcome {
            if session_id == validated_session.record.session_id {
                BrowserSessionRevokeOutcome {
                    decision: BrowserSessionRevokeDecision::Revoked {
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

        fn load_settings(
            &self,
            _context: &AuthenticationContext,
            validated_session: &ValidatedSession,
        ) -> BrowserSettingsOutcome {
            BrowserSettingsOutcome {
                decision: BrowserSettingsDecision::Loaded {
                    canonical_username: validated_session.record.canonical_username.clone(),
                    settings: BrowserVisibleSettings {
                        html_display_preference: HtmlDisplayPreference::PreferSanitizedHtml,
                        archive_mailbox_name: Some("Archive/2026".to_string()),
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

        fn update_settings(
            &self,
            _context: &AuthenticationContext,
            _validated_session: &ValidatedSession,
            html_display_preference: HtmlDisplayPreference,
            archive_mailbox_name: Option<&str>,
        ) -> BrowserSettingsUpdateOutcome {
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

        fn list_mailboxes(
            &self,
            _context: &AuthenticationContext,
            validated_session: &ValidatedSession,
        ) -> BrowserMailboxOutcome {
            BrowserMailboxOutcome {
                decision: BrowserMailboxDecision::Listed {
                    canonical_username: validated_session.record.canonical_username.clone(),
                    mailboxes: vec![
                        MailboxEntry {
                            name: "INBOX".to_string(),
                        },
                        MailboxEntry {
                            name: "Archive/2026".to_string(),
                        },
                    ],
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
            _context: &AuthenticationContext,
            validated_session: &ValidatedSession,
            mailbox_name: &str,
        ) -> BrowserMessageListOutcome {
            BrowserMessageListOutcome {
                decision: BrowserMessageListDecision::Listed {
                    canonical_username: validated_session.record.canonical_username.clone(),
                    mailbox_name: mailbox_name.to_string(),
                    messages: vec![MessageSummary {
                        mailbox_name: mailbox_name.to_string(),
                        uid: 9,
                        flags: vec!["\\Seen".to_string()],
                        date_received: "2026-03-27 11:00:00 +0000".to_string(),
                        size_virtual: 512,
                    }],
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
            _context: &AuthenticationContext,
            validated_session: &ValidatedSession,
            mailbox_name: Option<&str>,
            query: &str,
        ) -> BrowserMessageSearchOutcome {
            let mailbox_name = mailbox_name.map(str::to_string);
            let results = match mailbox_name.as_deref() {
                Some(mailbox_name) => vec![MessageSearchResult {
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
                        mailbox_name: "INBOX".to_string(),
                        uid: 17,
                        flags: vec!["\\Seen".to_string()],
                        date_received: "2026-03-27 17:00:00 +0000".to_string(),
                        size_virtual: 2048,
                        subject: Some("Quarterly report".to_string()),
                        from: Some("Alice <alice@example.com>".to_string()),
                    },
                    MessageSearchResult {
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
            _context: &AuthenticationContext,
            validated_session: &ValidatedSession,
            mailbox_name: &str,
            uid: u64,
        ) -> BrowserMessageViewOutcome {
            let _unused_fixture = MessageView {
                mailbox_name: mailbox_name.to_string(),
                uid,
                flags: vec!["\\Seen".to_string()],
                date_received: "2026-03-27 11:00:00 +0000".to_string(),
                size_virtual: 512,
                header_block: "Subject: Example\n".to_string(),
                body_text: "Hello world\n".to_string(),
            };

            BrowserMessageViewOutcome {
                decision: BrowserMessageViewDecision::Rendered {
                    canonical_username: validated_session.record.canonical_username.clone(),
                    rendered: Box::new(RenderedMessageView {
                        mailbox_name: mailbox_name.to_string(),
                        uid,
                        subject: Some("Example".to_string()),
                        from: Some("Alice <alice@example.com>".to_string()),
                        date_received: "2026-03-27 11:00:00 +0000".to_string(),
                        mime_top_level_content_type: "multipart/mixed".to_string(),
                        body_source: MimeBodySource::MultipartPlainTextPart,
                        contains_html_body: true,
                        body_html: "<pre>Hello world</pre>".to_string(),
                        body_text_for_compose: "Hello world".to_string(),
                        attachments: vec![
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
                        ],
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
            _context: &AuthenticationContext,
            _validated_session: &ValidatedSession,
            recipients: &str,
            _subject: &str,
            _body: &str,
            attachments: &[UploadedAttachment],
        ) -> BrowserSendOutcome {
            if recipients == "locked@example.com" {
                BrowserSendOutcome {
                    decision: BrowserSendDecision::Denied {
                        public_reason: TOO_MANY_SUBMISSIONS_PUBLIC_REASON.to_string(),
                        retry_after_seconds: Some(120),
                    },
                    audit_events: vec![LogEvent::new(
                        LogLevel::Warn,
                        EventCategory::Submission,
                        "stub_send_throttled",
                        "stub submission throttled",
                    )],
                }
            } else if recipients == "bob@example.com" && attachments.len() <= 1 {
                BrowserSendOutcome {
                    decision: BrowserSendDecision::Submitted,
                    audit_events: vec![LogEvent::new(
                        LogLevel::Info,
                        EventCategory::Submission,
                        "stub_send_ok",
                        "stub submission accepted",
                    )],
                }
            } else {
                BrowserSendOutcome {
                    decision: BrowserSendDecision::Denied {
                        public_reason: "invalid_request".to_string(),
                        retry_after_seconds: None,
                    },
                    audit_events: vec![LogEvent::new(
                        LogLevel::Warn,
                        EventCategory::Submission,
                        "stub_send_denied",
                        "stub submission denied",
                    )],
                }
            }
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
            _context: &AuthenticationContext,
            _validated_session: &ValidatedSession,
            source_mailbox_name: &str,
            uid: u64,
            destination_mailbox_name: &str,
        ) -> BrowserMessageMoveOutcome {
            if destination_mailbox_name == "Locked" {
                return BrowserMessageMoveOutcome {
                    decision: BrowserMessageMoveDecision::Denied {
                        public_reason: TOO_MANY_MESSAGE_MOVES_PUBLIC_REASON.to_string(),
                        retry_after_seconds: Some(180),
                    },
                    audit_events: vec![LogEvent::new(
                        LogLevel::Warn,
                        EventCategory::Mailbox,
                        "stub_message_move_throttled",
                        "stub message move throttled",
                    )],
                };
            }
            if source_mailbox_name == "INBOX" && uid == 9 && !destination_mailbox_name.is_empty() {
                BrowserMessageMoveOutcome {
                    decision: BrowserMessageMoveDecision::Moved {
                        source_mailbox_name: source_mailbox_name.to_string(),
                        destination_mailbox_name: destination_mailbox_name.to_string(),
                        uid,
                    },
                    audit_events: vec![LogEvent::new(
                        LogLevel::Info,
                        EventCategory::Mailbox,
                        "stub_message_move",
                        "stub message move completed",
                    )],
                }
            } else {
                BrowserMessageMoveOutcome {
                    decision: BrowserMessageMoveDecision::Denied {
                        public_reason: "invalid_request".to_string(),
                        retry_after_seconds: None,
                    },
                    audit_events: vec![LogEvent::new(
                        LogLevel::Warn,
                        EventCategory::Mailbox,
                        "stub_message_move_denied",
                        "stub message move denied",
                    )],
                }
            }
        }
    }

    fn app() -> BrowserApp<StubGateway> {
        BrowserApp::new(HttpPolicy::default(), StubGateway)
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

    fn body_text(response: &HandledHttpResponse) -> String {
        String::from_utf8_lossy(&response.response.body).into_owned()
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
        assert!(body.contains("totp_code"));
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
            "bob@example.com",
            "Test",
            "Hello",
            &[],
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

        let outcome = gateway.move_message(&context, &validated_session, "INBOX", 9, "Archive");
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
        assert!(body.contains("Archive/2026"));
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
        assert!(body.contains("name=\"destination_mailbox\" value=\"Archive/2026\""));
        assert!(body.contains(">Archive</button>"));
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
        assert!(body.contains("<h1>Search Results</h1>"));
        assert!(body.contains("Quarterly report"));
        assert!(body.contains("Alice &lt;alice@example.com&gt;"));
        assert!(body.contains("/message?mailbox=INBOX&amp;uid=17"));
        assert!(body.contains("<strong>Scope:</strong> INBOX"));
    }

    #[test]
    fn search_page_rejects_missing_query() {
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

        assert_eq!(response.response.status_code, 400);
        assert!(body_text(&response).contains("A search query is required."));
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
        assert!(body.contains("<strong>Scope:</strong> All mailboxes"));
        assert!(body.contains("name=\"scope\" value=\"all\" checked"));
        assert!(body.contains("/message?mailbox=INBOX&amp;uid=17"));
        assert!(body.contains("/message?mailbox=Archive%2F2026&amp;uid=23"));
        assert!(body.contains("Archive/2026"));
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
        assert!(body.contains("report.pdf"));
        assert!(body.contains("<pre>Hello world</pre>"));
        assert!(body.contains("mode=reply"));
        assert!(body.contains("mode=forward"));
        assert!(body.contains("Archive Message"));
        assert!(body.contains("name=\"destination_mailbox\" value=\"Archive/2026\""));
        assert!(body.contains("action=\"/message/move\""));
        assert!(body.contains("name=\"destination_mailbox\""));
        assert!(body.contains("/attachment?mailbox=INBOX&amp;uid=9&amp;part=1.2"));
        assert!(body.contains("chart.png"));
        assert!(body.contains("Content-ID <strong>cid:chart@example.com</strong>"));
        assert!(body.contains(
            "including <strong>1</strong> with Content-ID metadata used by `cid:` HTML references"
        ));
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
        assert!(body.contains("matches your configured archive destination"));
        assert!(!body.contains(">Archive</button>"));
    }

    #[test]
    fn message_move_redirects_back_to_mailbox_after_success() {
        let response = app().handle_request(
            &request(
                "POST",
                "/message/move",
                &[
                    ("User-Agent", "Firefox/Test"),
                    (
                        "Cookie",
                        "osmap_session=aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
                    ),
                ],
                "csrf_token=fedcba9876543210fedcba9876543210fedcba9876543210fedcba9876543210&mailbox=INBOX&uid=9&destination_mailbox=Archive%2F2026",
            ),
            "127.0.0.1",
        );

        assert_eq!(response.response.status_code, 303);
        assert!(response.response.headers.iter().any(|(name, value)| {
            name == "Location" && value == "/mailbox?name=INBOX&moved_to=Archive%2F2026"
        }));
    }

    #[test]
    fn mailbox_page_renders_move_success_notice() {
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
        assert!(body_text(&response).contains("Message moved to Archive/2026."));
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
        assert!(body.contains("<h1>Sessions</h1>"));
        assert!(body.contains("203.0.113.9"));
        assert!(body.contains("Revoke This Session"));
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
        assert!(body.contains("prefer_sanitized_html"));
        assert!(body.contains("name=\"archive_mailbox_name\""));
        assert!(body.contains("value=\"Archive/2026\""));
        assert!(body.contains("Save Settings"));
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
        assert!(body.contains("does not resend attachments automatically"));
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
        assert!(body.contains("does not reattach files yet"));
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
            &request(
                "POST",
                "/send",
                &[
                    ("User-Agent", "Firefox/Test"),
                    (
                        "Cookie",
                        "osmap_session=aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
                    ),
                ],
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
            &request(
                "POST",
                "/send",
                &[
                    ("User-Agent", "Firefox/Test"),
                    (
                        "Cookie",
                        "osmap_session=aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
                    ),
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
            .any(|(name, value)| name == "Location" && value == "/compose?sent=1"));
    }

    #[test]
    fn send_route_returns_retry_after_when_submission_is_throttled() {
        let response = app().handle_request(
            &request(
                "POST",
                "/send",
                &[
                    ("User-Agent", "Firefox/Test"),
                    (
                        "Cookie",
                        "osmap_session=aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
                    ),
                ],
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
        let response = app().handle_request(
            &request(
                "POST",
                "/message/move",
                &[
                    ("User-Agent", "Firefox/Test"),
                    (
                        "Cookie",
                        "osmap_session=aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
                    ),
                ],
                "csrf_token=fedcba9876543210fedcba9876543210fedcba9876543210fedcba9876543210&mailbox=INBOX&uid=9&destination_mailbox=Locked",
            ),
            "127.0.0.1",
        );

        assert_eq!(response.response.status_code, 429);
        assert!(body_text(&response).contains("Too many mailbox move requests were observed."));
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
                &[
                    ("User-Agent", "Firefox/Test"),
                    (
                        "Cookie",
                        "osmap_session=aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
                    ),
                ],
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
    fn session_revoke_clears_cookie_when_current_session_is_revoked() {
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
                ],
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
    fn settings_update_redirects_after_successful_save() {
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
                ],
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
                &[
                    ("User-Agent", "Firefox/Test"),
                    (
                        "Cookie",
                        "osmap_session=aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
                    ),
                ],
                "csrf_token=fedcba9876543210fedcba9876543210fedcba9876543210fedcba9876543210&html_display_preference=prefer_plain_text&archive_mailbox_name=Archive%0A2026",
            ),
            "127.0.0.1",
        );

        assert_eq!(response.response.status_code, 400);
        assert!(body_text(&response).contains("archive mailbox name was not valid"));
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
            &request_bytes(
                "POST",
                "/send",
                &[
                    ("User-Agent", "Firefox/Test"),
                    (
                        "Cookie",
                        "osmap_session=aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
                    ),
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
            .any(|(name, value)| name == "Location" && value == "/compose?sent=1"));
    }

    #[test]
    fn logout_clears_session_cookie() {
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
                ],
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
            "ts=4242 level=info category=http action=http_login_form_served msg=\"login form served\" request_id=\"http-1\" remote_addr=\"127.0.0.1\" user_agent=\"Firefox/Test\""
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

    #[test]
    fn normalizes_peer_addresses_to_bare_ip_strings() {
        let ipv4 = "127.0.0.1:18091"
            .parse::<SocketAddr>()
            .expect("ipv4 socket addr should parse");
        let ipv6 = "[::1]:18091"
            .parse::<SocketAddr>()
            .expect("ipv6 socket addr should parse");

        assert_eq!(normalize_peer_addr(ipv4), "127.0.0.1");
        assert_eq!(normalize_peer_addr(ipv6), "::1");
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
            let app = BrowserApp::new(policy, StubGateway);
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
            let app = BrowserApp::new(HttpPolicy::default(), StubGateway);
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
            let app = BrowserApp::new(HttpPolicy::default(), StubGateway);
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
        let app = Arc::new(BrowserApp::new(HttpPolicy::default(), StubGateway));
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
        let app = BrowserApp::new(HttpPolicy::default(), StubGateway);
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
