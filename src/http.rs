//! Minimal HTTP and browser handling for the first OSMAP web slice.
//!
//! This module deliberately avoids a framework while the project is still
//! proving its security and operational shape. The goal is not feature breadth;
//! the goal is an explicit, reviewable request path that consumes the existing
//! auth, session, mailbox, and rendering layers.

mod routes_auth;
mod routes_mail;

use std::collections::BTreeMap;
use std::io::Write as _;
use std::net::{TcpListener, TcpStream};
use std::path::PathBuf;
use std::sync::atomic::{AtomicU64, Ordering};
use std::time::Duration;

use crate::attachment::{
    AttachmentDownloadDecision, AttachmentDownloadPolicy, AttachmentDownloadPublicFailureReason,
    AttachmentDownloadService, DownloadedAttachment,
};
use crate::auth::{
    AuthenticationContext, AuthenticationDecision, AuthenticationPolicy, AuthenticationService,
    DoveadmAuthTestBackend, PublicFailureReason, RequiredSecondFactor, SecondFactorService,
    SystemCommandExecutor,
};
use crate::config::{AppConfig, AppRunMode, LogLevel, RuntimeEnvironment};
use crate::http_form::{parse_compose_form, parse_urlencoded_form};
use crate::http_parse::{
    allows_urlencoded_request_body, build_session_cookie, clear_session_cookie,
    compose_source_from_request, normalize_peer_addr, read_http_request, session_cookie_value,
};
use crate::http_support::{
    attachment_download_response, build_auth_warning_event, build_http_info_event,
    build_http_warning_event, constant_time_eq, escape_html, html_response,
    login_throttle_error_label, public_reason_message, redirect_response, session_error_label,
    url_encode,
};
use crate::http_ui::{
    render_compose_page, render_login_page, render_mailboxes_page, render_message_list_page,
    render_message_search_page, render_message_view_page, render_sessions_page, ComposePageModel,
};
use crate::logging::{EventCategory, LogEvent, Logger};
use crate::mailbox::{
    DoveadmMailboxListBackend, DoveadmMessageListBackend, DoveadmMessageMoveBackend,
    DoveadmMessageSearchBackend, DoveadmMessageViewBackend, MailboxEntry, MailboxListingDecision,
    MailboxListingPolicy, MailboxListingService, MessageListDecision, MessageListPolicy,
    MessageListRequest, MessageListService, MessageMoveDecision, MessageMovePolicy,
    MessageMoveRequest, MessageMoveService, MessageSearchDecision, MessageSearchPolicy,
    MessageSearchRequest, MessageSearchResult, MessageSearchService, MessageSummary,
    MessageViewDecision, MessageViewPolicy, MessageViewRequest, MessageViewService,
};
use crate::mailbox_helper::{
    MailboxHelperMailboxListBackend, MailboxHelperMessageListBackend,
    MailboxHelperMessageMoveBackend, MailboxHelperMessageSearchBackend,
    MailboxHelperMessageViewBackend, MailboxHelperPolicy,
};
use crate::openbsd::apply_runtime_confinement;
use crate::rendering::{PlainTextMessageRenderer, RenderedMessageView, RenderingPolicy};
use crate::send::{
    ComposeDraft, ComposeIntent, ComposePolicy, ComposeRequest, SendmailSubmissionBackend,
    SubmissionDecision, SubmissionPublicFailureReason, SubmissionService, UploadedAttachment,
};
use crate::session::{
    FileSessionStore, SessionService, SessionToken, SystemRandomSource, ValidatedSession,
    SESSION_ID_HEX_LEN,
};
use crate::throttle::{
    FileLoginThrottleStore, LoginThrottleDecision, LoginThrottleError, LoginThrottlePolicy,
    LoginThrottleService, TOO_MANY_ATTEMPTS_PUBLIC_REASON,
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

/// The fixed cookie name used by the current browser session slice.
pub const DEFAULT_SESSION_COOKIE_NAME: &str = "osmap_session";

static REQUEST_COUNTER: AtomicU64 = AtomicU64::new(1);

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
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct HttpRequestError {
    pub reason: String,
}

/// A runtime-facing gateway for browser operations.
pub trait BrowserGateway {
    fn login(
        &self,
        context: &AuthenticationContext,
        username: &str,
        password: &str,
        totp_code: &str,
    ) -> BrowserLoginOutcome;

    fn validate_session(
        &self,
        context: &AuthenticationContext,
        presented_token: &str,
    ) -> BrowserSessionValidationOutcome;

    fn logout(
        &self,
        context: &AuthenticationContext,
        presented_token: &str,
    ) -> BrowserLogoutOutcome;

    fn list_sessions(
        &self,
        context: &AuthenticationContext,
        validated_session: &ValidatedSession,
    ) -> BrowserSessionListOutcome;

    fn revoke_session(
        &self,
        context: &AuthenticationContext,
        validated_session: &ValidatedSession,
        session_id: &str,
    ) -> BrowserSessionRevokeOutcome;

    fn list_mailboxes(
        &self,
        context: &AuthenticationContext,
        validated_session: &ValidatedSession,
    ) -> BrowserMailboxOutcome;

    fn list_messages(
        &self,
        context: &AuthenticationContext,
        validated_session: &ValidatedSession,
        mailbox_name: &str,
    ) -> BrowserMessageListOutcome;

    fn search_messages(
        &self,
        context: &AuthenticationContext,
        validated_session: &ValidatedSession,
        mailbox_name: &str,
        query: &str,
    ) -> BrowserMessageSearchOutcome;

    fn view_message(
        &self,
        context: &AuthenticationContext,
        validated_session: &ValidatedSession,
        mailbox_name: &str,
        uid: u64,
    ) -> BrowserMessageViewOutcome;

    fn download_attachment(
        &self,
        context: &AuthenticationContext,
        validated_session: &ValidatedSession,
        mailbox_name: &str,
        uid: u64,
        part_path: &str,
    ) -> BrowserAttachmentDownloadOutcome;

    fn move_message(
        &self,
        context: &AuthenticationContext,
        validated_session: &ValidatedSession,
        source_mailbox_name: &str,
        uid: u64,
        destination_mailbox_name: &str,
    ) -> BrowserMessageMoveOutcome;

    fn send_message(
        &self,
        context: &AuthenticationContext,
        validated_session: &ValidatedSession,
        recipients: &str,
        subject: &str,
        body: &str,
        attachments: &[UploadedAttachment],
    ) -> BrowserSendOutcome;
}

/// The result of a browser login attempt.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct BrowserLoginOutcome {
    pub decision: BrowserLoginDecision,
    pub audit_events: Vec<LogEvent>,
}

/// Login decisions visible to the browser layer.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum BrowserLoginDecision {
    Authenticated {
        canonical_username: String,
        session_token: SessionToken,
    },
    Denied {
        public_reason: String,
    },
}

/// The result of validating a presented browser session.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct BrowserSessionValidationOutcome {
    pub decision: BrowserSessionDecision,
    pub audit_events: Vec<LogEvent>,
}

/// Session validation decisions visible to the browser layer.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum BrowserSessionDecision {
    Valid {
        validated_session: Box<ValidatedSession>,
    },
    Invalid,
}

/// The result of a browser logout attempt.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct BrowserLogoutOutcome {
    pub session_was_revoked: bool,
    pub audit_events: Vec<LogEvent>,
}

/// Safe browser-visible session metadata.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct BrowserVisibleSession {
    pub session_id: String,
    pub issued_at: u64,
    pub expires_at: u64,
    pub last_seen_at: u64,
    pub revoked_at: Option<u64>,
    pub remote_addr: String,
    pub user_agent: String,
    pub factor: RequiredSecondFactor,
}

/// The result of a browser-visible session listing operation.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct BrowserSessionListOutcome {
    pub decision: BrowserSessionListDecision,
    pub audit_events: Vec<LogEvent>,
}

/// Session-list decisions visible to the browser layer.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum BrowserSessionListDecision {
    Listed {
        canonical_username: String,
        sessions: Vec<BrowserVisibleSession>,
    },
    Denied {
        public_reason: String,
    },
}

/// The result of a browser-driven session revocation.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct BrowserSessionRevokeOutcome {
    pub decision: BrowserSessionRevokeDecision,
    pub audit_events: Vec<LogEvent>,
}

/// Session-revocation decisions visible to the browser layer.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum BrowserSessionRevokeDecision {
    Revoked {
        revoked_session_id: String,
        revoked_current_session: bool,
    },
    Denied {
        public_reason: String,
    },
}

/// The result of a mailbox-listing browser operation.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct BrowserMailboxOutcome {
    pub decision: BrowserMailboxDecision,
    pub audit_events: Vec<LogEvent>,
}

/// Mailbox-list decisions visible to the browser layer.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum BrowserMailboxDecision {
    Listed {
        canonical_username: String,
        mailboxes: Vec<MailboxEntry>,
    },
    Denied {
        public_reason: String,
    },
}

/// The result of a message-list browser operation.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct BrowserMessageListOutcome {
    pub decision: BrowserMessageListDecision,
    pub audit_events: Vec<LogEvent>,
}

/// Message-list decisions visible to the browser layer.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum BrowserMessageListDecision {
    Listed {
        canonical_username: String,
        mailbox_name: String,
        messages: Vec<MessageSummary>,
    },
    Denied {
        public_reason: String,
    },
}

/// The result of a message-search browser operation.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct BrowserMessageSearchOutcome {
    pub decision: BrowserMessageSearchDecision,
    pub audit_events: Vec<LogEvent>,
}

/// Message-search decisions visible to the browser layer.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum BrowserMessageSearchDecision {
    Listed {
        canonical_username: String,
        mailbox_name: String,
        query: String,
        results: Vec<MessageSearchResult>,
    },
    Denied {
        public_reason: String,
    },
}

/// The result of a rendered message-view browser operation.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct BrowserMessageViewOutcome {
    pub decision: BrowserMessageViewDecision,
    pub audit_events: Vec<LogEvent>,
}

/// Message-view decisions visible to the browser layer.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum BrowserMessageViewDecision {
    Rendered {
        canonical_username: String,
        rendered: Box<RenderedMessageView>,
    },
    Denied {
        public_reason: String,
    },
}

/// The result of a browser attachment-download operation.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct BrowserAttachmentDownloadOutcome {
    pub decision: BrowserAttachmentDownloadDecision,
    pub audit_events: Vec<LogEvent>,
}

/// Attachment-download decisions visible to the browser layer.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum BrowserAttachmentDownloadDecision {
    Downloaded {
        canonical_username: String,
        attachment: DownloadedAttachment,
    },
    Denied {
        public_reason: String,
    },
}

/// The result of a browser message-move operation.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct BrowserMessageMoveOutcome {
    pub decision: BrowserMessageMoveDecision,
    pub audit_events: Vec<LogEvent>,
}

/// Message-move decisions visible to the browser layer.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum BrowserMessageMoveDecision {
    Moved {
        source_mailbox_name: String,
        destination_mailbox_name: String,
        uid: u64,
    },
    Denied {
        public_reason: String,
    },
}

/// The result of a browser send operation.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct BrowserSendOutcome {
    pub decision: BrowserSendDecision,
    pub audit_events: Vec<LogEvent>,
}

/// Send decisions visible to the browser layer.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum BrowserSendDecision {
    Submitted,
    Denied { public_reason: String },
}

/// The concrete runtime gateway built from the existing OSMAP services.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RuntimeBrowserGateway {
    authentication_policy: AuthenticationPolicy,
    totp_policy: TotpPolicy,
    login_throttle_policy: LoginThrottlePolicy,
    session_lifetime_seconds: u64,
    session_dir: PathBuf,
    login_throttle_dir: PathBuf,
    totp_secret_dir: PathBuf,
    doveadm_path: PathBuf,
    doveadm_auth_socket_path: Option<PathBuf>,
    doveadm_userdb_socket_path: Option<PathBuf>,
    mailbox_helper_socket_path: Option<PathBuf>,
    sendmail_path: PathBuf,
    render_policy: RenderingPolicy,
}

impl RuntimeBrowserGateway {
    /// Builds the runtime gateway from validated configuration.
    pub fn from_config(config: &AppConfig) -> Self {
        Self {
            authentication_policy: AuthenticationPolicy::default(),
            totp_policy: TotpPolicy {
                allowed_skew_steps: config.totp_allowed_skew_steps,
                ..TotpPolicy::default()
            },
            login_throttle_policy: LoginThrottlePolicy {
                max_failures: config.login_throttle_max_failures,
                failure_window_seconds: config.login_throttle_window_seconds,
                lockout_seconds: config.login_throttle_lockout_seconds,
            },
            session_lifetime_seconds: config.session_lifetime_seconds,
            session_dir: config.state_layout.session_dir.clone(),
            login_throttle_dir: config.state_layout.cache_dir.join("login-throttle"),
            totp_secret_dir: config.state_layout.totp_secret_dir.clone(),
            doveadm_path: PathBuf::from("/usr/local/bin/doveadm"),
            doveadm_auth_socket_path: config.doveadm_auth_socket_path.clone(),
            doveadm_userdb_socket_path: config.doveadm_userdb_socket_path.clone(),
            mailbox_helper_socket_path: config.mailbox_helper_socket_path.clone(),
            sendmail_path: PathBuf::from("/usr/sbin/sendmail"),
            render_policy: RenderingPolicy::default(),
        }
    }

    /// Builds the current auth service around `doveadm auth test`.
    fn build_auth_service(
        &self,
    ) -> AuthenticationService<DoveadmAuthTestBackend<SystemCommandExecutor>> {
        AuthenticationService::new(
            self.authentication_policy,
            DoveadmAuthTestBackend::new(
                SystemCommandExecutor,
                self.doveadm_path.clone(),
                self.doveadm_auth_socket_path.clone(),
                "imap",
            ),
        )
    }

    /// Builds the current second-factor service around the file-backed TOTP store.
    fn build_factor_service(
        &self,
    ) -> SecondFactorService<TotpVerifier<FileTotpSecretStore, SystemTimeProvider>> {
        SecondFactorService::new(
            self.authentication_policy,
            TotpVerifier::new(
                FileTotpSecretStore::new(self.totp_secret_dir.clone()),
                SystemTimeProvider,
                self.totp_policy,
            ),
        )
    }

    /// Builds the current file-backed session service.
    fn build_session_service(
        &self,
    ) -> SessionService<FileSessionStore, SystemTimeProvider, SystemRandomSource> {
        SessionService::new(
            FileSessionStore::new(self.session_dir.clone()),
            SystemTimeProvider,
            SystemRandomSource,
            self.session_lifetime_seconds,
        )
    }

    /// Builds the current file-backed login-throttle service.
    fn build_login_throttle_service(
        &self,
    ) -> LoginThrottleService<FileLoginThrottleStore, SystemTimeProvider> {
        LoginThrottleService::new(
            FileLoginThrottleStore::new(self.login_throttle_dir.clone()),
            SystemTimeProvider,
            self.login_throttle_policy,
        )
    }

    /// Builds the current send-path service around the local sendmail surface.
    fn build_submission_service(
        &self,
    ) -> SubmissionService<SendmailSubmissionBackend<SystemCommandExecutor>> {
        SubmissionService::new(SendmailSubmissionBackend::new(
            SystemCommandExecutor,
            self.sendmail_path.clone(),
        ))
    }

    /// Builds the current attachment-download service from the MIME policy.
    fn build_attachment_download_service(&self) -> AttachmentDownloadService {
        AttachmentDownloadService::new(AttachmentDownloadPolicy::default())
    }

    /// Projects persisted session metadata into a browser-safe summary.
    fn visible_session(record: crate::session::SessionRecord) -> BrowserVisibleSession {
        BrowserVisibleSession {
            session_id: record.session_id,
            issued_at: record.issued_at,
            expires_at: record.expires_at,
            last_seen_at: record.last_seen_at,
            revoked_at: record.revoked_at,
            remote_addr: record.remote_addr,
            user_agent: record.user_agent,
            factor: record.factor,
        }
    }

    /// Selects the current message-view backend based on whether the local
    /// mailbox helper is configured for read-path proxying.
    fn build_message_search_backend(&self) -> MessageSearchRuntimeBackend {
        match &self.mailbox_helper_socket_path {
            Some(socket_path) => {
                MessageSearchRuntimeBackend::Helper(MailboxHelperMessageSearchBackend::new(
                    socket_path,
                    MailboxHelperPolicy::default(),
                    MessageSearchPolicy::default(),
                ))
            }
            None => MessageSearchRuntimeBackend::Direct(
                DoveadmMessageSearchBackend::new(
                    MessageSearchPolicy::default(),
                    SystemCommandExecutor,
                    self.doveadm_path.clone(),
                )
                .with_userdb_socket_path(self.doveadm_userdb_socket_path.clone()),
            ),
        }
    }

    /// Selects the current message-view backend based on whether the local
    /// mailbox helper is configured for read-path proxying.
    fn build_message_view_backend(&self) -> MessageViewRuntimeBackend {
        match &self.mailbox_helper_socket_path {
            Some(socket_path) => {
                MessageViewRuntimeBackend::Helper(MailboxHelperMessageViewBackend::new(
                    socket_path,
                    MailboxHelperPolicy::default(),
                    MessageViewPolicy::default(),
                ))
            }
            None => MessageViewRuntimeBackend::Direct(
                DoveadmMessageViewBackend::new(
                    MessageViewPolicy::default(),
                    SystemCommandExecutor,
                    self.doveadm_path.clone(),
                )
                .with_userdb_socket_path(self.doveadm_userdb_socket_path.clone()),
            ),
        }
    }

    /// Selects the current message-move backend based on whether the local
    /// mailbox helper is configured for mailbox-authoritative operations.
    fn build_message_move_backend(&self) -> MessageMoveRuntimeBackend {
        match &self.mailbox_helper_socket_path {
            Some(socket_path) => MessageMoveRuntimeBackend::Helper(
                MailboxHelperMessageMoveBackend::new(socket_path, MailboxHelperPolicy::default()),
            ),
            None => MessageMoveRuntimeBackend::Direct(
                DoveadmMessageMoveBackend::new(SystemCommandExecutor, self.doveadm_path.clone())
                    .with_userdb_socket_path(self.doveadm_userdb_socket_path.clone()),
            ),
        }
    }

    /// Records a non-fatal throttle-store failure so operators can diagnose
    /// missing abuse resistance without crashing the login path.
    fn build_login_throttle_store_error_event(
        &self,
        action: &'static str,
        message: &'static str,
        context: &AuthenticationContext,
        error: &LoginThrottleError,
    ) -> LogEvent {
        build_auth_warning_event(action, message, context)
            .with_field("reason", login_throttle_error_label(error))
    }
}

impl BrowserGateway for RuntimeBrowserGateway {
    fn login(
        &self,
        context: &AuthenticationContext,
        username: &str,
        password: &str,
        totp_code: &str,
    ) -> BrowserLoginOutcome {
        let mut audit_events = Vec::new();
        let throttle_service = self.build_login_throttle_service();

        match throttle_service.check(context, username) {
            Ok(check) => {
                if let Some(audit_event) = check.audit_event {
                    audit_events.push(audit_event);
                }

                if let LoginThrottleDecision::Throttled { .. } = check.decision {
                    return BrowserLoginOutcome {
                        decision: BrowserLoginDecision::Denied {
                            public_reason: TOO_MANY_ATTEMPTS_PUBLIC_REASON.to_string(),
                        },
                        audit_events,
                    };
                }
            }
            Err(error) => audit_events.push(self.build_login_throttle_store_error_event(
                "login_throttle_check_failed",
                "login throttle check failed",
                context,
                &error,
            )),
        }

        let auth_outcome = self
            .build_auth_service()
            .authenticate(context, username, password);
        audit_events.push(auth_outcome.audit_event.clone());

        match auth_outcome.decision {
            AuthenticationDecision::Denied { public_reason } => {
                let mut effective_public_reason = public_reason.as_str().to_string();
                if public_reason == PublicFailureReason::InvalidCredentials {
                    match throttle_service.record_failure(context, username) {
                        Ok(record) => {
                            if let Some(audit_event) = record.audit_event {
                                audit_events.push(audit_event);
                            }
                            if record.lockout_engaged {
                                effective_public_reason =
                                    TOO_MANY_ATTEMPTS_PUBLIC_REASON.to_string();
                            }
                        }
                        Err(error) => audit_events.push(
                            self.build_login_throttle_store_error_event(
                                "login_throttle_record_failed",
                                "login throttle failure recording failed",
                                context,
                                &error,
                            ),
                        ),
                    }
                }

                BrowserLoginOutcome {
                    decision: BrowserLoginDecision::Denied {
                        public_reason: effective_public_reason,
                    },
                    audit_events,
                }
            }
            AuthenticationDecision::MfaRequired {
                canonical_username,
                second_factor,
            } => {
                let factor_outcome = self.build_factor_service().verify(
                    context,
                    canonical_username.clone(),
                    second_factor,
                    totp_code,
                );
                audit_events.push(factor_outcome.audit_event.clone());

                match factor_outcome.decision {
                    AuthenticationDecision::Denied { public_reason } => {
                        let mut effective_public_reason = public_reason.as_str().to_string();
                        if public_reason == PublicFailureReason::InvalidSecondFactor {
                            match throttle_service.record_failure(context, username) {
                                Ok(record) => {
                                    if let Some(audit_event) = record.audit_event {
                                        audit_events.push(audit_event);
                                    }
                                    if record.lockout_engaged {
                                        effective_public_reason =
                                            TOO_MANY_ATTEMPTS_PUBLIC_REASON.to_string();
                                    }
                                }
                                Err(error) => audit_events.push(
                                    self.build_login_throttle_store_error_event(
                                        "login_throttle_record_failed",
                                        "login throttle failure recording failed",
                                        context,
                                        &error,
                                    ),
                                ),
                            }
                        }

                        BrowserLoginOutcome {
                            decision: BrowserLoginDecision::Denied {
                                public_reason: effective_public_reason,
                            },
                            audit_events,
                        }
                    }
                    AuthenticationDecision::AuthenticatedPendingSession { canonical_username } => {
                        match self.build_session_service().issue(
                            context,
                            &canonical_username,
                            second_factor,
                        ) {
                            Ok(issued_session) => {
                                audit_events.push(issued_session.audit_event.clone());
                                match throttle_service.clear_success(context, username) {
                                    Ok(Some(audit_event)) => audit_events.push(audit_event),
                                    Ok(None) => {}
                                    Err(error) => audit_events.push(
                                        self.build_login_throttle_store_error_event(
                                            "login_throttle_clear_failed",
                                            "login throttle clear failed after successful authentication",
                                            context,
                                            &error,
                                        ),
                                    ),
                                }
                                BrowserLoginOutcome {
                                    decision: BrowserLoginDecision::Authenticated {
                                        canonical_username,
                                        session_token: issued_session.token,
                                    },
                                    audit_events,
                                }
                            }
                            Err(error) => {
                                audit_events.push(
                                    build_http_warning_event(
                                        "session_issue_failed",
                                        "session issuance failed during browser login",
                                        context,
                                    )
                                    .with_field("reason", session_error_label(&error)),
                                );
                                BrowserLoginOutcome {
                                    decision: BrowserLoginDecision::Denied {
                                        public_reason: PublicFailureReason::TemporarilyUnavailable
                                            .as_str()
                                            .to_string(),
                                    },
                                    audit_events,
                                }
                            }
                        }
                    }
                    AuthenticationDecision::MfaRequired { .. } => BrowserLoginOutcome {
                        decision: BrowserLoginDecision::Denied {
                            public_reason: PublicFailureReason::TemporarilyUnavailable
                                .as_str()
                                .to_string(),
                        },
                        audit_events,
                    },
                }
            }
            AuthenticationDecision::AuthenticatedPendingSession { .. } => BrowserLoginOutcome {
                decision: BrowserLoginDecision::Denied {
                    public_reason: PublicFailureReason::TemporarilyUnavailable
                        .as_str()
                        .to_string(),
                },
                audit_events,
            },
        }
    }

    fn validate_session(
        &self,
        context: &AuthenticationContext,
        presented_token: &str,
    ) -> BrowserSessionValidationOutcome {
        let token = match SessionToken::new(presented_token.to_string()) {
            Ok(token) => token,
            Err(_) => {
                return BrowserSessionValidationOutcome {
                    decision: BrowserSessionDecision::Invalid,
                    audit_events: Vec::new(),
                };
            }
        };

        match self.build_session_service().validate(context, &token) {
            Ok(validated_session) => BrowserSessionValidationOutcome {
                decision: BrowserSessionDecision::Valid {
                    validated_session: Box::new(validated_session.clone()),
                },
                audit_events: vec![validated_session.audit_event],
            },
            Err(error) => BrowserSessionValidationOutcome {
                decision: BrowserSessionDecision::Invalid,
                audit_events: vec![build_http_warning_event(
                    "session_validation_failed",
                    "browser session validation failed",
                    context,
                )
                .with_field("reason", session_error_label(&error))],
            },
        }
    }

    fn logout(
        &self,
        context: &AuthenticationContext,
        presented_token: &str,
    ) -> BrowserLogoutOutcome {
        let token = match SessionToken::new(presented_token.to_string()) {
            Ok(token) => token,
            Err(_) => {
                return BrowserLogoutOutcome {
                    session_was_revoked: false,
                    audit_events: Vec::new(),
                };
            }
        };

        match self
            .build_session_service()
            .revoke_by_token(context, &token)
        {
            Ok(revoked_session) => BrowserLogoutOutcome {
                session_was_revoked: true,
                audit_events: vec![revoked_session.audit_event],
            },
            Err(error) => BrowserLogoutOutcome {
                session_was_revoked: false,
                audit_events: vec![build_http_warning_event(
                    "session_revoke_failed",
                    "browser session revocation failed",
                    context,
                )
                .with_field("reason", session_error_label(&error))],
            },
        }
    }

    fn list_sessions(
        &self,
        context: &AuthenticationContext,
        validated_session: &ValidatedSession,
    ) -> BrowserSessionListOutcome {
        match self
            .build_session_service()
            .list_for_user(&validated_session.record.canonical_username)
        {
            Ok(records) => BrowserSessionListOutcome {
                decision: BrowserSessionListDecision::Listed {
                    canonical_username: validated_session.record.canonical_username.clone(),
                    sessions: records.into_iter().map(Self::visible_session).collect(),
                },
                audit_events: vec![build_http_info_event(
                    "session_listed",
                    "browser session list returned",
                    context,
                )
                .with_field(
                    "canonical_username",
                    validated_session.record.canonical_username.clone(),
                )],
            },
            Err(error) => BrowserSessionListOutcome {
                decision: BrowserSessionListDecision::Denied {
                    public_reason: "temporarily_unavailable".to_string(),
                },
                audit_events: vec![build_http_warning_event(
                    "session_list_failed",
                    "browser session listing failed",
                    context,
                )
                .with_field("reason", session_error_label(&error))],
            },
        }
    }

    fn revoke_session(
        &self,
        context: &AuthenticationContext,
        validated_session: &ValidatedSession,
        session_id: &str,
    ) -> BrowserSessionRevokeOutcome {
        if session_id.len() != SESSION_ID_HEX_LEN
            || !session_id.chars().all(|ch| ch.is_ascii_hexdigit())
        {
            return BrowserSessionRevokeOutcome {
                decision: BrowserSessionRevokeDecision::Denied {
                    public_reason: "invalid_request".to_string(),
                },
                audit_events: vec![build_http_warning_event(
                    "session_revoke_request_rejected",
                    "browser session revoke request validation failed",
                    context,
                )
                .with_field("reason", "invalid_session_id")],
            };
        }

        let owned_session = match self
            .build_session_service()
            .list_for_user(&validated_session.record.canonical_username)
        {
            Ok(records) => records
                .into_iter()
                .any(|record| record.session_id == session_id),
            Err(error) => {
                return BrowserSessionRevokeOutcome {
                    decision: BrowserSessionRevokeDecision::Denied {
                        public_reason: "temporarily_unavailable".to_string(),
                    },
                    audit_events: vec![build_http_warning_event(
                        "session_revoke_lookup_failed",
                        "browser session ownership lookup failed",
                        context,
                    )
                    .with_field("reason", session_error_label(&error))],
                };
            }
        };

        if !owned_session {
            return BrowserSessionRevokeOutcome {
                decision: BrowserSessionRevokeDecision::Denied {
                    public_reason: "not_found".to_string(),
                },
                audit_events: vec![build_http_warning_event(
                    "session_revoke_denied",
                    "browser session revoke target not found for user",
                    context,
                )
                .with_field(
                    "canonical_username",
                    validated_session.record.canonical_username.clone(),
                )
                .with_field("session_id", session_id.to_string())],
            };
        }

        match self.build_session_service().revoke(context, session_id) {
            Ok(revoked_session) => BrowserSessionRevokeOutcome {
                decision: BrowserSessionRevokeDecision::Revoked {
                    revoked_session_id: revoked_session.record.session_id.clone(),
                    revoked_current_session: revoked_session.record.session_id
                        == validated_session.record.session_id,
                },
                audit_events: vec![revoked_session.audit_event],
            },
            Err(error) => BrowserSessionRevokeOutcome {
                decision: BrowserSessionRevokeDecision::Denied {
                    public_reason: "temporarily_unavailable".to_string(),
                },
                audit_events: vec![build_http_warning_event(
                    "session_revoke_failed",
                    "browser session revoke failed",
                    context,
                )
                .with_field("reason", session_error_label(&error))],
            },
        }
    }

    fn list_mailboxes(
        &self,
        context: &AuthenticationContext,
        validated_session: &ValidatedSession,
    ) -> BrowserMailboxOutcome {
        let backend = match &self.mailbox_helper_socket_path {
            Some(socket_path) => MailboxListRuntimeBackend::Helper(
                MailboxHelperMailboxListBackend::new(socket_path, MailboxHelperPolicy::default()),
            ),
            None => MailboxListRuntimeBackend::Direct(
                DoveadmMailboxListBackend::new(
                    MailboxListingPolicy::default(),
                    SystemCommandExecutor,
                    self.doveadm_path.clone(),
                )
                .with_userdb_socket_path(self.doveadm_userdb_socket_path.clone()),
            ),
        };
        let outcome = MailboxListingService::new(backend)
            .list_for_validated_session(context, validated_session);

        match outcome.decision {
            MailboxListingDecision::Listed {
                canonical_username,
                mailboxes,
                ..
            } => BrowserMailboxOutcome {
                decision: BrowserMailboxDecision::Listed {
                    canonical_username,
                    mailboxes,
                },
                audit_events: vec![outcome.audit_event],
            },
            MailboxListingDecision::Denied { public_reason } => BrowserMailboxOutcome {
                decision: BrowserMailboxDecision::Denied {
                    public_reason: public_reason.as_str().to_string(),
                },
                audit_events: vec![outcome.audit_event],
            },
        }
    }

    fn list_messages(
        &self,
        context: &AuthenticationContext,
        validated_session: &ValidatedSession,
        mailbox_name: &str,
    ) -> BrowserMessageListOutcome {
        let request = match MessageListRequest::new(MessageListPolicy::default(), mailbox_name) {
            Ok(request) => request,
            Err(error) => {
                return BrowserMessageListOutcome {
                    decision: BrowserMessageListDecision::Denied {
                        public_reason: "invalid_request".to_string(),
                    },
                    audit_events: vec![build_http_warning_event(
                        "message_list_request_rejected",
                        "message list request validation failed",
                        context,
                    )
                    .with_field("reason", error.reason)],
                };
            }
        };

        let backend = match &self.mailbox_helper_socket_path {
            Some(socket_path) => {
                MessageListRuntimeBackend::Helper(MailboxHelperMessageListBackend::new(
                    socket_path,
                    MailboxHelperPolicy::default(),
                    MessageListPolicy::default(),
                ))
            }
            None => MessageListRuntimeBackend::Direct(
                DoveadmMessageListBackend::new(
                    MessageListPolicy::default(),
                    SystemCommandExecutor,
                    self.doveadm_path.clone(),
                )
                .with_userdb_socket_path(self.doveadm_userdb_socket_path.clone()),
            ),
        };
        let outcome = MessageListService::new(backend).list_for_validated_session(
            context,
            validated_session,
            &request,
        );

        match outcome.decision {
            MessageListDecision::Listed {
                canonical_username,
                mailbox_name,
                messages,
                ..
            } => BrowserMessageListOutcome {
                decision: BrowserMessageListDecision::Listed {
                    canonical_username,
                    mailbox_name,
                    messages,
                },
                audit_events: vec![outcome.audit_event],
            },
            MessageListDecision::Denied { public_reason } => BrowserMessageListOutcome {
                decision: BrowserMessageListDecision::Denied {
                    public_reason: public_reason.as_str().to_string(),
                },
                audit_events: vec![outcome.audit_event],
            },
        }
    }

    fn search_messages(
        &self,
        context: &AuthenticationContext,
        validated_session: &ValidatedSession,
        mailbox_name: &str,
        query: &str,
    ) -> BrowserMessageSearchOutcome {
        let request =
            match MessageSearchRequest::new(MessageSearchPolicy::default(), mailbox_name, query) {
                Ok(request) => request,
                Err(error) => {
                    return BrowserMessageSearchOutcome {
                        decision: BrowserMessageSearchDecision::Denied {
                            public_reason: "invalid_request".to_string(),
                        },
                        audit_events: vec![build_http_warning_event(
                            "message_search_request_rejected",
                            "message search request validation failed",
                            context,
                        )
                        .with_field("reason", error.reason)],
                    };
                }
            };

        let outcome = MessageSearchService::new(self.build_message_search_backend())
            .search_for_validated_session(context, validated_session, &request);

        match outcome.decision {
            MessageSearchDecision::Listed {
                canonical_username,
                mailbox_name,
                query,
                results,
                ..
            } => BrowserMessageSearchOutcome {
                decision: BrowserMessageSearchDecision::Listed {
                    canonical_username,
                    mailbox_name,
                    query,
                    results,
                },
                audit_events: vec![outcome.audit_event],
            },
            MessageSearchDecision::Denied { public_reason } => BrowserMessageSearchOutcome {
                decision: BrowserMessageSearchDecision::Denied {
                    public_reason: public_reason.as_str().to_string(),
                },
                audit_events: vec![outcome.audit_event],
            },
        }
    }

    fn view_message(
        &self,
        context: &AuthenticationContext,
        validated_session: &ValidatedSession,
        mailbox_name: &str,
        uid: u64,
    ) -> BrowserMessageViewOutcome {
        let request = match MessageViewRequest::new(MessageViewPolicy::default(), mailbox_name, uid)
        {
            Ok(request) => request,
            Err(error) => {
                return BrowserMessageViewOutcome {
                    decision: BrowserMessageViewDecision::Denied {
                        public_reason: "invalid_request".to_string(),
                    },
                    audit_events: vec![build_http_warning_event(
                        "message_view_request_rejected",
                        "message view request validation failed",
                        context,
                    )
                    .with_field("reason", error.reason)],
                };
            }
        };

        let message_outcome = MessageViewService::new(self.build_message_view_backend())
            .fetch_for_validated_session(context, validated_session, &request);
        let mut audit_events = vec![message_outcome.audit_event.clone()];

        match message_outcome.decision {
            MessageViewDecision::Retrieved {
                canonical_username,
                message,
                ..
            } => match PlainTextMessageRenderer::new(self.render_policy)
                .render_for_validated_session(context, validated_session, &message)
            {
                Ok(rendered_outcome) => {
                    audit_events.push(rendered_outcome.audit_event.clone());
                    BrowserMessageViewOutcome {
                        decision: BrowserMessageViewDecision::Rendered {
                            canonical_username,
                            rendered: Box::new(rendered_outcome.rendered),
                        },
                        audit_events,
                    }
                }
                Err(error) => {
                    audit_events.push(
                        build_http_warning_event(
                            "message_render_failed",
                            "message rendering failed",
                            context,
                        )
                        .with_field("reason", error.reason),
                    );
                    BrowserMessageViewOutcome {
                        decision: BrowserMessageViewDecision::Denied {
                            public_reason: "temporarily_unavailable".to_string(),
                        },
                        audit_events,
                    }
                }
            },
            MessageViewDecision::Denied { public_reason } => BrowserMessageViewOutcome {
                decision: BrowserMessageViewDecision::Denied {
                    public_reason: public_reason.as_str().to_string(),
                },
                audit_events,
            },
        }
    }

    fn download_attachment(
        &self,
        context: &AuthenticationContext,
        validated_session: &ValidatedSession,
        mailbox_name: &str,
        uid: u64,
        part_path: &str,
    ) -> BrowserAttachmentDownloadOutcome {
        let request = match MessageViewRequest::new(MessageViewPolicy::default(), mailbox_name, uid)
        {
            Ok(request) => request,
            Err(error) => {
                return BrowserAttachmentDownloadOutcome {
                    decision: BrowserAttachmentDownloadDecision::Denied {
                        public_reason: AttachmentDownloadPublicFailureReason::InvalidRequest
                            .as_str()
                            .to_string(),
                    },
                    audit_events: vec![build_http_warning_event(
                        "attachment_download_request_rejected",
                        "attachment download request validation failed",
                        context,
                    )
                    .with_field("reason", error.reason)],
                };
            }
        };

        let message_outcome = MessageViewService::new(self.build_message_view_backend())
            .fetch_for_validated_session(context, validated_session, &request);
        let mut audit_events = vec![message_outcome.audit_event.clone()];

        match message_outcome.decision {
            MessageViewDecision::Retrieved {
                canonical_username,
                message,
                ..
            } => {
                let attachment_outcome = self
                    .build_attachment_download_service()
                    .download_for_validated_session(
                        context,
                        validated_session,
                        &message,
                        part_path,
                    );
                audit_events.push(attachment_outcome.audit_event.clone());

                match attachment_outcome.decision {
                    AttachmentDownloadDecision::Downloaded { attachment, .. } => {
                        BrowserAttachmentDownloadOutcome {
                            decision: BrowserAttachmentDownloadDecision::Downloaded {
                                canonical_username,
                                attachment,
                            },
                            audit_events,
                        }
                    }
                    AttachmentDownloadDecision::Denied { public_reason } => {
                        BrowserAttachmentDownloadOutcome {
                            decision: BrowserAttachmentDownloadDecision::Denied {
                                public_reason: public_reason.as_str().to_string(),
                            },
                            audit_events,
                        }
                    }
                }
            }
            MessageViewDecision::Denied { public_reason } => BrowserAttachmentDownloadOutcome {
                decision: BrowserAttachmentDownloadDecision::Denied {
                    public_reason: public_reason.as_str().to_string(),
                },
                audit_events,
            },
        }
    }

    fn send_message(
        &self,
        context: &AuthenticationContext,
        validated_session: &ValidatedSession,
        recipients: &str,
        subject: &str,
        body: &str,
        attachments: &[UploadedAttachment],
    ) -> BrowserSendOutcome {
        let request = match ComposeRequest::new_with_attachments(
            ComposePolicy::default(),
            recipients,
            subject,
            body,
            attachments.to_vec(),
        ) {
            Ok(request) => request,
            Err(error) => {
                return BrowserSendOutcome {
                    decision: BrowserSendDecision::Denied {
                        public_reason: SubmissionPublicFailureReason::InvalidRequest
                            .as_str()
                            .to_string(),
                    },
                    audit_events: vec![build_http_warning_event(
                        "compose_request_rejected",
                        "compose request validation failed",
                        context,
                    )
                    .with_field("reason", error.reason)],
                };
            }
        };

        let outcome = self
            .build_submission_service()
            .submit_for_validated_session(context, validated_session, &request);

        match outcome.decision {
            SubmissionDecision::Submitted { .. } => BrowserSendOutcome {
                decision: BrowserSendDecision::Submitted,
                audit_events: vec![outcome.audit_event],
            },
            SubmissionDecision::Denied { public_reason } => BrowserSendOutcome {
                decision: BrowserSendDecision::Denied {
                    public_reason: public_reason.as_str().to_string(),
                },
                audit_events: vec![outcome.audit_event],
            },
        }
    }

    fn move_message(
        &self,
        context: &AuthenticationContext,
        validated_session: &ValidatedSession,
        source_mailbox_name: &str,
        uid: u64,
        destination_mailbox_name: &str,
    ) -> BrowserMessageMoveOutcome {
        let request = match MessageMoveRequest::new(
            MessageMovePolicy::default(),
            source_mailbox_name,
            destination_mailbox_name,
            uid,
        ) {
            Ok(request) => request,
            Err(error) => {
                return BrowserMessageMoveOutcome {
                    decision: BrowserMessageMoveDecision::Denied {
                        public_reason: "invalid_request".to_string(),
                    },
                    audit_events: vec![build_http_warning_event(
                        "message_move_request_rejected",
                        "message move request validation failed",
                        context,
                    )
                    .with_field("reason", error.reason)],
                };
            }
        };

        let outcome = MessageMoveService::new(self.build_message_move_backend())
            .move_for_validated_session(context, validated_session, &request);

        match outcome.decision {
            MessageMoveDecision::Moved {
                source_mailbox_name,
                destination_mailbox_name,
                uid,
                ..
            } => BrowserMessageMoveOutcome {
                decision: BrowserMessageMoveDecision::Moved {
                    source_mailbox_name,
                    destination_mailbox_name,
                    uid,
                },
                audit_events: vec![outcome.audit_event],
            },
            MessageMoveDecision::Denied { public_reason } => BrowserMessageMoveOutcome {
                decision: BrowserMessageMoveDecision::Denied {
                    public_reason: public_reason.as_str().to_string(),
                },
                audit_events: vec![outcome.audit_event],
            },
        }
    }
}

/// Selects the current mailbox-list backend without widening the browser
/// runtime's authority when a local helper is configured.
enum MailboxListRuntimeBackend {
    Direct(DoveadmMailboxListBackend<SystemCommandExecutor>),
    Helper(MailboxHelperMailboxListBackend),
}

impl crate::mailbox::MailboxBackend for MailboxListRuntimeBackend {
    fn list_mailboxes(
        &self,
        canonical_username: &str,
    ) -> Result<Vec<MailboxEntry>, crate::mailbox::MailboxBackendError> {
        match self {
            Self::Direct(backend) => backend.list_mailboxes(canonical_username),
            Self::Helper(backend) => backend.list_mailboxes(canonical_username),
        }
    }
}

/// Selects the current message-list backend without widening the browser
/// runtime's authority when a local helper is configured.
enum MessageListRuntimeBackend {
    Direct(DoveadmMessageListBackend<SystemCommandExecutor>),
    Helper(MailboxHelperMessageListBackend),
}

impl crate::mailbox::MessageListBackend for MessageListRuntimeBackend {
    fn list_messages(
        &self,
        canonical_username: &str,
        request: &MessageListRequest,
    ) -> Result<Vec<MessageSummary>, crate::mailbox::MailboxBackendError> {
        match self {
            Self::Direct(backend) => backend.list_messages(canonical_username, request),
            Self::Helper(backend) => backend.list_messages(canonical_username, request),
        }
    }
}

/// Selects the current message-search backend without widening the browser
/// runtime's authority when a local helper is configured.
enum MessageSearchRuntimeBackend {
    Direct(DoveadmMessageSearchBackend<SystemCommandExecutor>),
    Helper(MailboxHelperMessageSearchBackend),
}

impl crate::mailbox::MessageSearchBackend for MessageSearchRuntimeBackend {
    fn search_messages(
        &self,
        canonical_username: &str,
        request: &MessageSearchRequest,
    ) -> Result<Vec<MessageSearchResult>, crate::mailbox::MailboxBackendError> {
        match self {
            Self::Direct(backend) => backend.search_messages(canonical_username, request),
            Self::Helper(backend) => backend.search_messages(canonical_username, request),
        }
    }
}

/// Selects the current message-move backend without widening the browser
/// runtime's authority when a local helper is configured.
enum MessageMoveRuntimeBackend {
    Direct(DoveadmMessageMoveBackend<SystemCommandExecutor>),
    Helper(MailboxHelperMessageMoveBackend),
}

impl crate::mailbox::MessageMoveBackend for MessageMoveRuntimeBackend {
    fn move_message(
        &self,
        canonical_username: &str,
        request: &MessageMoveRequest,
    ) -> Result<(), crate::mailbox::MailboxBackendError> {
        match self {
            Self::Direct(backend) => backend.move_message(canonical_username, request),
            Self::Helper(backend) => backend.move_message(canonical_username, request),
        }
    }
}

/// Selects the current message-view backend without widening the browser
/// runtime's authority when a local helper is configured.
enum MessageViewRuntimeBackend {
    Direct(DoveadmMessageViewBackend<SystemCommandExecutor>),
    Helper(MailboxHelperMessageViewBackend),
}

impl crate::mailbox::MessageViewBackend for MessageViewRuntimeBackend {
    fn fetch_message(
        &self,
        canonical_username: &str,
        request: &MessageViewRequest,
    ) -> Result<crate::mailbox::MessageView, crate::mailbox::MailboxBackendError> {
        match self {
            Self::Direct(backend) => backend.fetch_message(canonical_username, request),
            Self::Helper(backend) => backend.fetch_message(canonical_username, request),
        }
    }
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

impl<G> BrowserApp<G>
where
    G: BrowserGateway,
{
    /// Handles one parsed HTTP request from the supplied remote address.
    pub fn handle_request(&self, request: &HttpRequest, remote_addr: &str) -> HandledHttpResponse {
        let context = match AuthenticationContext::new(
            self.policy.authentication_policy,
            next_request_id(),
            remote_addr,
            request
                .headers
                .get("user-agent")
                .cloned()
                .unwrap_or_else(|| "<unknown>".to_string()),
        ) {
            Ok(context) => context,
            Err(error) => {
                return HandledHttpResponse {
                    response: html_response(
                        400,
                        "Bad Request",
                        "Invalid Request",
                        "<p>Request context could not be validated.</p>",
                    ),
                    audit_events: vec![build_http_warning_event(
                        "http_context_rejected",
                        "http request context validation failed",
                        &AuthenticationContext {
                            request_id: "<invalid>".to_string(),
                            remote_addr: remote_addr.to_string(),
                            user_agent: "<invalid>".to_string(),
                        },
                    )
                    .with_field("reason", error.as_str())],
                };
            }
        };

        match (request.method, request.path.as_str()) {
            (HttpMethod::Get, "/healthz") => HandledHttpResponse {
                response: HttpResponse::text(200, "OK", "ok\n")
                    .with_header("Content-Type", "text/plain; charset=utf-8")
                    .with_header("Cache-Control", "no-store"),
                audit_events: vec![build_http_info_event(
                    "http_healthz",
                    "health check served",
                    &context,
                )],
            },
            (HttpMethod::Get, "/login") => self.handle_login_form(&context),
            (HttpMethod::Post, "/login") => self.handle_login(request, &context),
            (HttpMethod::Get, "/") => self.handle_root_redirect(request, &context),
            (HttpMethod::Get, "/mailboxes") => self.handle_mailboxes(request, &context),
            (HttpMethod::Get, "/mailbox") => self.handle_mailbox_messages(request, &context),
            (HttpMethod::Get, "/search") => self.handle_message_search(request, &context),
            (HttpMethod::Get, "/message") => self.handle_message_view(request, &context),
            (HttpMethod::Get, "/attachment") => self.handle_attachment_download(request, &context),
            (HttpMethod::Get, "/compose") => self.handle_compose_form(request, &context),
            (HttpMethod::Get, "/sessions") => self.handle_sessions_page(request, &context),
            (HttpMethod::Post, "/message/move") => self.handle_message_move(request, &context),
            (HttpMethod::Post, "/send") => self.handle_send(request, &context),
            (HttpMethod::Post, "/sessions/revoke") => self.handle_session_revoke(request, &context),
            (HttpMethod::Post, "/logout") => self.handle_logout(request, &context),
            _ => HandledHttpResponse {
                response: html_response(
                    404,
                    "Not Found",
                    "Not Found",
                    "<p>The requested path does not exist in the current OSMAP browser slice.</p>",
                ),
                audit_events: vec![build_http_warning_event(
                    "http_route_not_found",
                    "http route not found",
                    &context,
                )
                .with_field("path", request.path.clone())],
            },
        }
    }

    /// Handles the compose form for the validated browser session.
    fn handle_compose_form(
        &self,
        request: &HttpRequest,
        context: &AuthenticationContext,
    ) -> HandledHttpResponse {
        let (validated_session, mut audit_events) =
            match self.require_validated_session(request, context) {
                Ok(result) => result,
                Err(response) => return response,
            };

        let success_message = if request.query_params.get("sent").map(String::as_str) == Some("1") {
            Some("Message submission completed.")
        } else {
            None
        };
        let mut compose_heading = "Compose";
        let mut context_notice: Option<String> = None;
        let mut to_value = String::new();
        let mut subject_value = String::new();
        let mut body_value = String::new();

        match compose_source_from_request(request) {
            Ok(Some((intent, mailbox_name, uid))) => {
                let outcome =
                    self.gateway
                        .view_message(context, &validated_session, &mailbox_name, uid);
                audit_events.extend(outcome.audit_events);

                match outcome.decision {
                    BrowserMessageViewDecision::Rendered { rendered, .. } => {
                        let draft = match ComposeDraft::from_rendered_message(
                            ComposePolicy::default(),
                            intent,
                            &rendered,
                        ) {
                            Ok(draft) => draft,
                            Err(error) => {
                                return HandledHttpResponse {
                                    response: html_response(
                                        503,
                                        "Service Unavailable",
                                        "Compose Unavailable",
                                        "<p>The compose draft could not be prepared safely.</p>",
                                    ),
                                    audit_events: vec![build_http_warning_event(
                                        "compose_draft_failed",
                                        "compose draft generation failed",
                                        context,
                                    )
                                    .with_field("reason", error.reason)],
                                };
                            }
                        };

                        compose_heading = match draft.intent {
                            ComposeIntent::Reply => "Reply",
                            ComposeIntent::Forward => "Forward",
                        };
                        context_notice = draft.context_notice;
                        to_value = draft.to;
                        subject_value = draft.subject;
                        body_value = draft.body;
                    }
                    BrowserMessageViewDecision::Denied { public_reason } => {
                        return HandledHttpResponse {
                            response: html_response(
                                503,
                                "Service Unavailable",
                                "Compose Unavailable",
                                &format!(
                                    "<p>{}</p>",
                                    escape_html(public_reason_message(&public_reason))
                                ),
                            ),
                            audit_events,
                        };
                    }
                }
            }
            Ok(None) => {}
            Err(reason) => {
                return HandledHttpResponse {
                    response: html_response(
                        400,
                        "Bad Request",
                        "Invalid Compose Request",
                        "<p>The compose reference was not valid.</p>",
                    ),
                    audit_events: vec![build_http_warning_event(
                        "compose_reference_rejected",
                        "compose reference validation failed",
                        context,
                    )
                    .with_field("reason", reason)],
                };
            }
        }

        HandledHttpResponse {
            response: html_response(
                200,
                "OK",
                compose_heading,
                &render_compose_page(&ComposePageModel {
                    heading: compose_heading,
                    canonical_username: &validated_session.record.canonical_username,
                    csrf_token: &validated_session.record.csrf_token,
                    success_message,
                    error_message: None,
                    context_notice: context_notice.as_deref(),
                    to_value: &to_value,
                    subject_value: &subject_value,
                    body_value: &body_value,
                }),
            ),
            audit_events,
        }
    }

    /// Handles the current compose/send form submission.
    fn handle_send(
        &self,
        request: &HttpRequest,
        context: &AuthenticationContext,
    ) -> HandledHttpResponse {
        let parsed_form = match parse_compose_form(
            &request.body,
            request.headers.get("content-type").map(String::as_str),
            self.policy.max_form_fields,
            self.policy.max_upload_body_bytes,
            ComposePolicy::default(),
        ) {
            Ok(form) => form,
            Err(error) => {
                return HandledHttpResponse {
                    response: html_response(
                        400,
                        "Bad Request",
                        "Invalid Compose Request",
                        "<p>The compose form could not be parsed.</p>",
                    ),
                    audit_events: vec![build_http_warning_event(
                        "http_send_parse_failed",
                        "compose form parsing failed",
                        context,
                    )
                    .with_field("reason", error.reason)],
                };
            }
        };
        let form = parsed_form.fields;
        let attachments = parsed_form.attachments;

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

        let recipients = form.get("to").cloned().unwrap_or_default();
        let subject = form.get("subject").cloned().unwrap_or_default();
        let body = form.get("body").cloned().unwrap_or_default();
        let outcome = self.gateway.send_message(
            context,
            &validated_session,
            &recipients,
            &subject,
            &body,
            &attachments,
        );
        audit_events.extend(outcome.audit_events);

        match outcome.decision {
            BrowserSendDecision::Submitted => HandledHttpResponse {
                response: redirect_response(303, "See Other", "/compose?sent=1"),
                audit_events,
            },
            BrowserSendDecision::Denied { public_reason } => {
                let status_code = if public_reason == "invalid_request" {
                    400
                } else {
                    503
                };
                let reason_phrase = if public_reason == "invalid_request" {
                    "Bad Request"
                } else {
                    "Service Unavailable"
                };
                HandledHttpResponse {
                    response: html_response(
                        status_code,
                        reason_phrase,
                        "Compose",
                        &render_compose_page(&ComposePageModel {
                            heading: "Compose",
                            canonical_username: &validated_session.record.canonical_username,
                            csrf_token: &validated_session.record.csrf_token,
                            success_message: None,
                            error_message: Some(public_reason_message(&public_reason)),
                            context_notice: None,
                            to_value: &recipients,
                            subject_value: &subject,
                            body_value: &body,
                        }),
                    ),
                    audit_events,
                }
            }
        }
    }

}

/// Runs the first sequential HTTP server for the current browser slice.
pub fn run_http_server(config: &AppConfig, logger: &Logger) -> Result<(), String> {
    if config.run_mode != AppRunMode::Serve {
        return Ok(());
    }

    apply_runtime_confinement(config, logger)?;

    let listener = TcpListener::bind(&config.listen_addr)
        .map_err(|error| format!("failed to bind {}: {error}", config.listen_addr))?;
    let app = BrowserApp::new(
        HttpPolicy::from_config(config),
        RuntimeBrowserGateway::from_config(config),
    );
    logger.emit(
        &LogEvent::new(
            LogLevel::Info,
            EventCategory::Http,
            "http_server_started",
            "http server started",
        )
        .with_field("listen_addr", config.listen_addr.clone())
        .with_field("run_mode", config.run_mode.as_str()),
    );

    for stream in listener.incoming() {
        match stream {
            Ok(mut stream) => handle_client_stream(&app, logger, &mut stream),
            Err(error) => logger.emit(
                &LogEvent::new(
                    LogLevel::Warn,
                    EventCategory::Http,
                    "http_accept_failed",
                    "http connection accept failed",
                )
                .with_field("reason", error.to_string()),
            ),
        }
    }

    Ok(())
}

/// Handles one accepted client connection and closes it after one response.
fn handle_client_stream<G>(app: &BrowserApp<G>, logger: &Logger, stream: &mut TcpStream)
where
    G: BrowserGateway,
{
    let remote_addr = stream
        .peer_addr()
        .map(normalize_peer_addr)
        .unwrap_or_else(|_| "<unknown>".to_string());

    if let Err(error) =
        stream.set_read_timeout(Some(Duration::from_secs(app.policy().read_timeout_secs)))
    {
        logger.emit(
            &LogEvent::new(
                LogLevel::Warn,
                EventCategory::Http,
                "http_read_timeout_config_failed",
                "http read timeout configuration failed",
            )
            .with_field("remote_addr", remote_addr.clone())
            .with_field("reason", error.to_string()),
        );
    }
    if let Err(error) =
        stream.set_write_timeout(Some(Duration::from_secs(app.policy().write_timeout_secs)))
    {
        logger.emit(
            &LogEvent::new(
                LogLevel::Warn,
                EventCategory::Http,
                "http_write_timeout_config_failed",
                "http write timeout configuration failed",
            )
            .with_field("remote_addr", remote_addr.clone())
            .with_field("reason", error.to_string()),
        );
    }

    let handled = match read_http_request(stream, app.policy()) {
        Ok(request) => app.handle_request(&request, &remote_addr),
        Err(error) => HandledHttpResponse {
            response: html_response(
                400,
                "Bad Request",
                "Invalid Request",
                "<p>The request could not be parsed safely.</p>",
            ),
            audit_events: vec![LogEvent::new(
                LogLevel::Warn,
                EventCategory::Http,
                "http_request_rejected",
                "http request rejected before routing",
            )
            .with_field("remote_addr", remote_addr.clone())
            .with_field("reason", error.reason)],
        },
    };

    for event in &handled.audit_events {
        logger.emit(event);
    }

    let response_bytes = handled.response.to_http_bytes();
    if let Err(error) = stream.write_all(&response_bytes) {
        logger.emit(
            &LogEvent::new(
                LogLevel::Warn,
                EventCategory::Http,
                "http_response_write_failed",
                "http response write failed",
            )
            .with_field("remote_addr", remote_addr)
            .with_field("reason", error.to_string()),
        );
    }
}

/// Builds a redirect response with the current browser-security headers.
/// Generates the next bounded synthetic request identifier.
fn next_request_id() -> String {
    let id = REQUEST_COUNTER.fetch_add(1, Ordering::Relaxed);
    format!("http-{id}")
}


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
    use std::net::SocketAddr;
    use std::path::PathBuf;

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
            mailbox_name: &str,
            query: &str,
        ) -> BrowserMessageSearchOutcome {
            BrowserMessageSearchOutcome {
                decision: BrowserMessageSearchDecision::Listed {
                    canonical_username: validated_session.record.canonical_username.clone(),
                    mailbox_name: mailbox_name.to_string(),
                    query: query.trim().to_string(),
                    results: vec![MessageSearchResult {
                        mailbox_name: mailbox_name.to_string(),
                        uid: 17,
                        flags: vec!["\\Seen".to_string()],
                        date_received: "2026-03-27 17:00:00 +0000".to_string(),
                        size_virtual: 2048,
                        subject: Some("Quarterly report".to_string()),
                        from: Some("Alice <alice@example.com>".to_string()),
                    }],
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
                        attachments: vec![crate::mime::AttachmentMetadata {
                            part_path: "1.2".to_string(),
                            filename: Some("report.pdf".to_string()),
                            content_type: "application/pdf".to_string(),
                            disposition: AttachmentDisposition::Attachment,
                            size_hint_bytes: 128,
                        }],
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
            if recipients == "bob@example.com" && attachments.len() <= 1 {
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
        let throttle_store = FileLoginThrottleStore::new(temp_root.join("cache").join("login-throttle"));
        let throttle_key = crate::throttle::LoginThrottleKey::new("alice@example.com", &context.remote_addr);
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
        let gateway = RuntimeBrowserGateway {
            authentication_policy: AuthenticationPolicy::default(),
            totp_policy: TotpPolicy::default(),
            login_throttle_policy: LoginThrottlePolicy {
                max_failures: 5,
                failure_window_seconds: 300,
                lockout_seconds: 600,
            },
            session_lifetime_seconds: 3600,
            session_dir: temp_root.join("sessions"),
            login_throttle_dir: temp_root.join("cache").join("login-throttle"),
            totp_secret_dir: temp_root.join("totp"),
            doveadm_path: PathBuf::from("/nonexistent/doveadm"),
            doveadm_auth_socket_path: None,
            doveadm_userdb_socket_path: None,
            mailbox_helper_socket_path: None,
            sendmail_path: PathBuf::from("/usr/sbin/sendmail"),
            render_policy: RenderingPolicy::default(),
        };

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
        assert!(body.contains("Search this mailbox"));
        assert!(body.contains("action=\"/search\""));
        assert!(body.contains("name=\"mailbox\" value=\"INBOX\""));
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
        assert!(body.contains("action=\"/message/move\""));
        assert!(body.contains("name=\"destination_mailbox\""));
        assert!(body.contains("/attachment?mailbox=INBOX&amp;uid=9&amp;part=1.2"));
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
}
