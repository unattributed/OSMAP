//! Minimal HTTP and browser handling for the first OSMAP web slice.
//!
//! This module deliberately avoids a framework while the project is still
//! proving its security and operational shape. The goal is not feature breadth;
//! the goal is an explicit, reviewable request path that consumes the existing
//! auth, session, mailbox, and rendering layers.

use std::collections::BTreeMap;
use std::io::{Read as _, Write as _};
use std::net::{SocketAddr, TcpListener, TcpStream};
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
use crate::http_form::{
    is_multipart_form_data, parse_compose_form, parse_query_string, parse_urlencoded_form,
};
use crate::logging::{EventCategory, LogEvent, Logger};
use crate::mailbox::{
    DoveadmMailboxListBackend, DoveadmMessageListBackend, DoveadmMessageViewBackend, MailboxEntry,
    MailboxListingDecision, MailboxListingPolicy, MailboxListingService, MessageListDecision,
    MessageListPolicy, MessageListRequest, MessageListService, MessageSummary, MessageViewDecision,
    MessageViewPolicy, MessageViewRequest, MessageViewService,
};
use crate::mailbox_helper::{
    MailboxHelperMailboxListBackend, MailboxHelperMessageListBackend,
    MailboxHelperMessageViewBackend, MailboxHelperPolicy,
};
use crate::openbsd::apply_runtime_confinement;
use crate::rendering::{PlainTextMessageRenderer, RenderedMessageView, RenderingPolicy};
use crate::send::{
    ComposeDraft, ComposeIntent, ComposePolicy, ComposeRequest, SendmailSubmissionBackend,
    SubmissionDecision, SubmissionPublicFailureReason, SubmissionService, UploadedAttachment,
};
use crate::session::{
    FileSessionStore, SessionError, SessionService, SessionToken, SystemRandomSource,
    ValidatedSession,
};
use crate::totp::{FileTotpSecretStore, SystemTimeProvider, TotpPolicy, TotpVerifier};

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
    session_lifetime_seconds: u64,
    session_dir: PathBuf,
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
            session_lifetime_seconds: config.session_lifetime_seconds,
            session_dir: config.state_layout.session_dir.clone(),
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
        let auth_outcome = self
            .build_auth_service()
            .authenticate(context, username, password);
        audit_events.push(auth_outcome.audit_event.clone());

        match auth_outcome.decision {
            AuthenticationDecision::Denied { public_reason } => BrowserLoginOutcome {
                decision: BrowserLoginDecision::Denied {
                    public_reason: public_reason.as_str().to_string(),
                },
                audit_events,
            },
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
                    AuthenticationDecision::Denied { public_reason } => BrowserLoginOutcome {
                        decision: BrowserLoginDecision::Denied {
                            public_reason: public_reason.as_str().to_string(),
                        },
                        audit_events,
                    },
                    AuthenticationDecision::AuthenticatedPendingSession { canonical_username } => {
                        match self.build_session_service().issue(
                            context,
                            &canonical_username,
                            second_factor,
                        ) {
                            Ok(issued_session) => {
                                audit_events.push(issued_session.audit_event.clone());
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
            (HttpMethod::Get, "/login") => HandledHttpResponse {
                response: html_response(200, "OK", "OSMAP Login", &render_login_page(None)),
                audit_events: vec![build_http_info_event(
                    "http_login_form_served",
                    "login form served",
                    &context,
                )],
            },
            (HttpMethod::Post, "/login") => self.handle_login(request, &context),
            (HttpMethod::Get, "/") => self.handle_root_redirect(request, &context),
            (HttpMethod::Get, "/mailboxes") => self.handle_mailboxes(request, &context),
            (HttpMethod::Get, "/mailbox") => self.handle_mailbox_messages(request, &context),
            (HttpMethod::Get, "/message") => self.handle_message_view(request, &context),
            (HttpMethod::Get, "/attachment") => self.handle_attachment_download(request, &context),
            (HttpMethod::Get, "/compose") => self.handle_compose_form(request, &context),
            (HttpMethod::Post, "/send") => self.handle_send(request, &context),
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

    /// Handles login form submission using the existing auth/session layers.
    fn handle_login(
        &self,
        request: &HttpRequest,
        context: &AuthenticationContext,
    ) -> HandledHttpResponse {
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
    fn handle_root_redirect(
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

    /// Handles the mailbox-home page for the validated browser session.
    fn handle_mailboxes(
        &self,
        request: &HttpRequest,
        context: &AuthenticationContext,
    ) -> HandledHttpResponse {
        let (validated_session, mut audit_events) =
            match self.require_validated_session(request, context) {
                Ok(result) => result,
                Err(response) => return response,
            };

        let outcome = self.gateway.list_mailboxes(context, &validated_session);
        audit_events.extend(outcome.audit_events);

        match outcome.decision {
            BrowserMailboxDecision::Listed {
                canonical_username,
                mailboxes,
            } => HandledHttpResponse {
                response: html_response(
                    200,
                    "OK",
                    "Mailboxes",
                    &render_mailboxes_page(
                        &canonical_username,
                        &validated_session.record.csrf_token,
                        &mailboxes,
                    ),
                ),
                audit_events,
            },
            BrowserMailboxDecision::Denied { public_reason } => HandledHttpResponse {
                response: html_response(
                    503,
                    "Service Unavailable",
                    "Mailbox Access Unavailable",
                    &format!(
                        "<p>{}</p>",
                        escape_html(public_reason_message(&public_reason))
                    ),
                ),
                audit_events,
            },
        }
    }

    /// Handles per-mailbox message-list requests.
    fn handle_mailbox_messages(
        &self,
        request: &HttpRequest,
        context: &AuthenticationContext,
    ) -> HandledHttpResponse {
        let mailbox_name = match request.query_params.get("name") {
            Some(mailbox_name) if !mailbox_name.is_empty() => mailbox_name.clone(),
            _ => {
                return HandledHttpResponse {
                    response: html_response(
                        400,
                        "Bad Request",
                        "Invalid Mailbox Request",
                        "<p>A mailbox name is required.</p>",
                    ),
                    audit_events: vec![build_http_warning_event(
                        "http_mailbox_request_rejected",
                        "mailbox query parameter missing",
                        context,
                    )],
                };
            }
        };

        let (validated_session, mut audit_events) =
            match self.require_validated_session(request, context) {
                Ok(result) => result,
                Err(response) => return response,
            };

        let outcome = self
            .gateway
            .list_messages(context, &validated_session, &mailbox_name);
        audit_events.extend(outcome.audit_events);

        match outcome.decision {
            BrowserMessageListDecision::Listed {
                canonical_username,
                mailbox_name,
                messages,
            } => HandledHttpResponse {
                response: html_response(
                    200,
                    "OK",
                    "Mailbox Messages",
                    &render_message_list_page(
                        &canonical_username,
                        &validated_session.record.csrf_token,
                        &mailbox_name,
                        &messages,
                    ),
                ),
                audit_events,
            },
            BrowserMessageListDecision::Denied { public_reason } => HandledHttpResponse {
                response: html_response(
                    503,
                    "Service Unavailable",
                    "Message List Unavailable",
                    &format!(
                        "<p>{}</p>",
                        escape_html(public_reason_message(&public_reason))
                    ),
                ),
                audit_events,
            },
        }
    }

    /// Handles per-message view requests for the validated browser session.
    fn handle_message_view(
        &self,
        request: &HttpRequest,
        context: &AuthenticationContext,
    ) -> HandledHttpResponse {
        let mailbox_name = match request.query_params.get("mailbox") {
            Some(mailbox_name) if !mailbox_name.is_empty() => mailbox_name.clone(),
            _ => {
                return HandledHttpResponse {
                    response: html_response(
                        400,
                        "Bad Request",
                        "Invalid Message Request",
                        "<p>A mailbox name is required.</p>",
                    ),
                    audit_events: vec![build_http_warning_event(
                        "http_message_request_rejected",
                        "message mailbox parameter missing",
                        context,
                    )],
                };
            }
        };
        let uid = match request
            .query_params
            .get("uid")
            .and_then(|value| value.parse::<u64>().ok())
        {
            Some(uid) if uid > 0 => uid,
            _ => {
                return HandledHttpResponse {
                    response: html_response(
                        400,
                        "Bad Request",
                        "Invalid Message Request",
                        "<p>A positive IMAP UID is required.</p>",
                    ),
                    audit_events: vec![build_http_warning_event(
                        "http_message_uid_rejected",
                        "message uid parameter invalid",
                        context,
                    )],
                };
            }
        };

        let (validated_session, mut audit_events) =
            match self.require_validated_session(request, context) {
                Ok(result) => result,
                Err(response) => return response,
            };

        let outcome = self
            .gateway
            .view_message(context, &validated_session, &mailbox_name, uid);
        audit_events.extend(outcome.audit_events);

        match outcome.decision {
            BrowserMessageViewDecision::Rendered {
                canonical_username,
                rendered,
            } => HandledHttpResponse {
                response: html_response(
                    200,
                    "OK",
                    "Message View",
                    &render_message_view_page(
                        &canonical_username,
                        &validated_session.record.csrf_token,
                        &rendered,
                    ),
                ),
                audit_events,
            },
            BrowserMessageViewDecision::Denied { public_reason } => HandledHttpResponse {
                response: html_response(
                    503,
                    "Service Unavailable",
                    "Message View Unavailable",
                    &format!(
                        "<p>{}</p>",
                        escape_html(public_reason_message(&public_reason))
                    ),
                ),
                audit_events,
            },
        }
    }

    /// Handles one session-gated attachment download request.
    fn handle_attachment_download(
        &self,
        request: &HttpRequest,
        context: &AuthenticationContext,
    ) -> HandledHttpResponse {
        let mailbox_name = match request.query_params.get("mailbox") {
            Some(mailbox_name) if !mailbox_name.is_empty() => mailbox_name.clone(),
            _ => {
                return HandledHttpResponse {
                    response: html_response(
                        400,
                        "Bad Request",
                        "Invalid Attachment Request",
                        "<p>A mailbox name is required.</p>",
                    ),
                    audit_events: vec![build_http_warning_event(
                        "http_attachment_mailbox_rejected",
                        "attachment mailbox parameter missing",
                        context,
                    )],
                };
            }
        };
        let uid = match request
            .query_params
            .get("uid")
            .and_then(|value| value.parse::<u64>().ok())
        {
            Some(uid) if uid > 0 => uid,
            _ => {
                return HandledHttpResponse {
                    response: html_response(
                        400,
                        "Bad Request",
                        "Invalid Attachment Request",
                        "<p>A positive IMAP UID is required.</p>",
                    ),
                    audit_events: vec![build_http_warning_event(
                        "http_attachment_uid_rejected",
                        "attachment uid parameter invalid",
                        context,
                    )],
                };
            }
        };
        let part_path = match request.query_params.get("part") {
            Some(part_path) if !part_path.is_empty() => part_path.clone(),
            _ => {
                return HandledHttpResponse {
                    response: html_response(
                        400,
                        "Bad Request",
                        "Invalid Attachment Request",
                        "<p>An attachment part path is required.</p>",
                    ),
                    audit_events: vec![build_http_warning_event(
                        "http_attachment_part_rejected",
                        "attachment part parameter missing",
                        context,
                    )],
                };
            }
        };

        let (validated_session, mut audit_events) =
            match self.require_validated_session(request, context) {
                Ok(result) => result,
                Err(response) => return response,
            };

        let outcome = self.gateway.download_attachment(
            context,
            &validated_session,
            &mailbox_name,
            uid,
            &part_path,
        );
        audit_events.extend(outcome.audit_events);

        match outcome.decision {
            BrowserAttachmentDownloadDecision::Downloaded { attachment, .. } => {
                HandledHttpResponse {
                    response: attachment_download_response(&attachment),
                    audit_events,
                }
            }
            BrowserAttachmentDownloadDecision::Denied { public_reason } => {
                let (status_code, reason_phrase, title) = match public_reason.as_str() {
                    "invalid_request" => (400, "Bad Request", "Invalid Attachment Request"),
                    "not_found" => (404, "Not Found", "Attachment Not Found"),
                    _ => (
                        503,
                        "Service Unavailable",
                        "Attachment Download Unavailable",
                    ),
                };

                HandledHttpResponse {
                    response: html_response(
                        status_code,
                        reason_phrase,
                        title,
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

    /// Handles logout and clears the browser session cookie regardless of outcome.
    fn handle_logout(
        &self,
        request: &HttpRequest,
        context: &AuthenticationContext,
    ) -> HandledHttpResponse {
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
    fn require_validated_session(
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
    fn require_valid_csrf(
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

/// Normalizes a peer socket address to the bare IP string used in audit
/// context and auth-helper metadata.
fn normalize_peer_addr(addr: SocketAddr) -> String {
    addr.ip().to_string()
}

/// Reads one bounded HTTP request from the supplied stream.
fn read_http_request(
    stream: &mut TcpStream,
    policy: &HttpPolicy,
) -> Result<HttpRequest, HttpRequestError> {
    let mut buffer = Vec::new();
    let mut content_length = None;
    let mut header_end = None;

    loop {
        let mut chunk = [0_u8; 2048];
        let read = stream.read(&mut chunk).map_err(|error| HttpRequestError {
            reason: format!("failed reading request: {error}"),
        })?;
        if read == 0 {
            break;
        }

        buffer.extend_from_slice(&chunk[..read]);

        if header_end.is_none() {
            if buffer.len() > policy.max_header_bytes + policy.max_upload_body_bytes {
                return Err(HttpRequestError {
                    reason: "request exceeded maximum allowed size".to_string(),
                });
            }
            header_end = find_header_end(&buffer);
            if let Some(end) = header_end {
                if end > policy.max_header_bytes {
                    return Err(HttpRequestError {
                        reason: "http headers exceeded maximum length".to_string(),
                    });
                }
                let header_text =
                    std::str::from_utf8(&buffer[..end]).map_err(|_| HttpRequestError {
                        reason: "http headers were not valid utf-8".to_string(),
                    })?;
                let headers = parse_headers(header_text, policy)?;
                content_length = Some(parse_content_length_from_headers(&headers)?);
            }
        }

        if let (Some(end), Some(content_length)) = (header_end, content_length) {
            let expected_len = end + 4 + content_length;
            if content_length
                > allowed_request_body_bytes(
                    parse_content_type_header_bytes(&buffer[..end]),
                    policy,
                )
            {
                return Err(HttpRequestError {
                    reason: "http body exceeded maximum length".to_string(),
                });
            }
            if buffer.len() >= expected_len {
                break;
            }
        }
    }

    parse_http_request_bytes(&buffer, policy)
}

/// Parses a raw HTTP request into the bounded request shape used by the router.
pub fn parse_http_request(
    input: &str,
    policy: &HttpPolicy,
) -> Result<HttpRequest, HttpRequestError> {
    parse_http_request_bytes(input.as_bytes(), policy)
}

/// Parses raw HTTP request bytes into the bounded request shape used by the router.
pub fn parse_http_request_bytes(
    input: &[u8],
    policy: &HttpPolicy,
) -> Result<HttpRequest, HttpRequestError> {
    let header_end = find_header_end(input).ok_or_else(|| HttpRequestError {
        reason: "missing http header terminator".to_string(),
    })?;

    if header_end > policy.max_header_bytes {
        return Err(HttpRequestError {
            reason: "http headers exceeded maximum length".to_string(),
        });
    }

    let header_block = std::str::from_utf8(&input[..header_end]).map_err(|_| HttpRequestError {
        reason: "http headers were not valid utf-8".to_string(),
    })?;
    let body = &input[header_end + 4..];
    if body.len()
        > allowed_request_body_bytes(
            parse_content_type_header_bytes(&input[..header_end]),
            policy,
        )
    {
        return Err(HttpRequestError {
            reason: "http body exceeded maximum length".to_string(),
        });
    }

    let mut lines = header_block.split("\r\n");
    let request_line = lines.next().ok_or_else(|| HttpRequestError {
        reason: "missing http request line".to_string(),
    })?;
    let mut request_line_parts = request_line.split_whitespace();
    let method_text = request_line_parts.next().ok_or_else(|| HttpRequestError {
        reason: "http request line missing method".to_string(),
    })?;
    let target = request_line_parts.next().ok_or_else(|| HttpRequestError {
        reason: "http request line missing target".to_string(),
    })?;
    let version = request_line_parts.next().ok_or_else(|| HttpRequestError {
        reason: "http request line missing version".to_string(),
    })?;
    if request_line_parts.next().is_some() {
        return Err(HttpRequestError {
            reason: "http request line contained unexpected fields".to_string(),
        });
    }

    if version != "HTTP/1.1" && version != "HTTP/1.0" {
        return Err(HttpRequestError {
            reason: "unsupported http version".to_string(),
        });
    }

    let method = match method_text {
        "GET" => HttpMethod::Get,
        "POST" => HttpMethod::Post,
        _ => {
            return Err(HttpRequestError {
                reason: "unsupported http method".to_string(),
            });
        }
    };

    let (path, query_params) = parse_request_target(
        target,
        policy.max_query_fields,
        policy.max_request_target_bytes,
    )?;
    let headers = parse_headers(header_block, policy)?;

    if version == "HTTP/1.1" && !headers.contains_key("host") {
        return Err(HttpRequestError {
            reason: "http/1.1 requests must include host".to_string(),
        });
    }

    let content_length = parse_content_length_from_headers(&headers)?;
    if content_length != body.len() {
        return Err(HttpRequestError {
            reason: "http body length did not match content-length".to_string(),
        });
    }

    if method == HttpMethod::Post && !headers.contains_key("content-length") && !body.is_empty() {
        return Err(HttpRequestError {
            reason: "post requests must send content-length".to_string(),
        });
    }

    Ok(HttpRequest {
        method,
        path,
        query_params,
        headers,
        body: body.to_vec(),
    })
}

/// Finds the end of the HTTP header block.
fn find_header_end(buffer: &[u8]) -> Option<usize> {
    buffer.windows(4).position(|window| window == b"\r\n\r\n")
}

/// Parses headers into one bounded lower-case map and rejects ambiguity.
fn parse_headers(
    header_block: &str,
    policy: &HttpPolicy,
) -> Result<BTreeMap<String, String>, HttpRequestError> {
    let mut headers = BTreeMap::new();

    for (index, line) in header_block.lines().skip(1).enumerate() {
        if index >= policy.max_header_count {
            return Err(HttpRequestError {
                reason: "http request contained too many headers".to_string(),
            });
        }

        let Some((name, value)) = line.split_once(':') else {
            return Err(HttpRequestError {
                reason: "malformed http header line".to_string(),
            });
        };

        let normalized_name = name.trim().to_ascii_lowercase();
        if normalized_name.is_empty() {
            return Err(HttpRequestError {
                reason: "http header name must not be empty".to_string(),
            });
        }
        if !normalized_name
            .chars()
            .all(|ch| ch.is_ascii_lowercase() || ch.is_ascii_digit() || ch == '-')
        {
            return Err(HttpRequestError {
                reason: "http header name contained unsupported characters".to_string(),
            });
        }
        if headers.contains_key(&normalized_name) {
            return Err(HttpRequestError {
                reason: format!("duplicate http header: {normalized_name}"),
            });
        }

        let normalized_value = value.trim().to_string();
        if normalized_value.chars().any(char::is_control) {
            return Err(HttpRequestError {
                reason: format!(
                    "http header value for {normalized_name} contained control characters"
                ),
            });
        }

        headers.insert(normalized_name, normalized_value);
    }

    Ok(headers)
}

/// Parses the content-length header from parsed headers.
fn parse_content_length_from_headers(
    headers: &BTreeMap<String, String>,
) -> Result<usize, HttpRequestError> {
    headers
        .get("content-length")
        .map(|value| {
            value.parse::<usize>().map_err(|_| HttpRequestError {
                reason: "invalid content-length header".to_string(),
            })
        })
        .transpose()
        .map(|value| value.unwrap_or(0))
}

/// Extracts the raw content-type header from one raw header block when present.
fn parse_content_type_header_bytes(header_bytes: &[u8]) -> Option<&str> {
    let header_text = std::str::from_utf8(header_bytes).ok()?;
    for line in header_text.lines().skip(1) {
        if let Some((name, value)) = line.split_once(':') {
            if name.trim().eq_ignore_ascii_case("content-type") {
                return Some(value.trim());
            }
        }
    }

    None
}

/// Returns the allowed request-body budget for the current content type.
fn allowed_request_body_bytes(content_type: Option<&str>, policy: &HttpPolicy) -> usize {
    match content_type {
        Some(value) if is_multipart_form_data(value) => policy.max_upload_body_bytes,
        _ => policy.max_body_bytes,
    }
}

/// Parses the request target into a path and decoded query map.
fn parse_request_target(
    target: &str,
    max_query_fields: usize,
    max_request_target_bytes: usize,
) -> Result<(String, BTreeMap<String, String>), HttpRequestError> {
    if target.len() > max_request_target_bytes {
        return Err(HttpRequestError {
            reason: "request target exceeded maximum length".to_string(),
        });
    }
    if target.chars().any(char::is_control) {
        return Err(HttpRequestError {
            reason: "request target contained control characters".to_string(),
        });
    }
    if target.contains('#') {
        return Err(HttpRequestError {
            reason: "request target fragments are not supported".to_string(),
        });
    }

    let (path, query) = target.split_once('?').unwrap_or((target, ""));
    if path.is_empty() || !path.starts_with('/') {
        return Err(HttpRequestError {
            reason: "request target must start with '/'".to_string(),
        });
    }
    if path.contains('\\') {
        return Err(HttpRequestError {
            reason: "request target contained unsupported path characters".to_string(),
        });
    }

    Ok((
        path.to_string(),
        parse_query_string(query, max_query_fields).map_err(|error| HttpRequestError {
            reason: error.reason,
        })?,
    ))
}

/// Reads the current session cookie from the request if present.
fn session_cookie_value(request: &HttpRequest, cookie_name: &str) -> Option<String> {
    let cookie_header = request.headers.get("cookie")?;
    for cookie in cookie_header.split(';') {
        let trimmed = cookie.trim();
        if let Some((name, value)) = trimmed.split_once('=') {
            if name.trim() == cookie_name {
                return Some(value.trim().to_string());
            }
        }
    }

    None
}

/// Builds the current session cookie for successful login responses.
fn build_session_cookie(cookie_name: &str, token: &str, secure: bool) -> String {
    let mut cookie = format!("{cookie_name}={token}; Path=/; HttpOnly; SameSite=Strict");
    if secure {
        cookie.push_str("; Secure");
    }
    cookie
}

/// Builds an expired session cookie used to clear browser session state.
fn clear_session_cookie(cookie_name: &str, secure: bool) -> String {
    let mut cookie = format!("{cookie_name}=; Path=/; HttpOnly; SameSite=Strict; Max-Age=0");
    if secure {
        cookie.push_str("; Secure");
    }
    cookie
}

/// Builds a redirect response with the current browser-security headers.
fn redirect_response(
    status_code: u16,
    reason_phrase: &'static str,
    location: &str,
) -> HttpResponse {
    HttpResponse::text(
        status_code,
        reason_phrase,
        format!(
            "<!doctype html><html><body><p>Redirecting to <a href=\"{}\">{}</a>.</p></body></html>",
            escape_html(location),
            escape_html(location),
        ),
    )
    .with_header("Location", location)
    .with_header("Cache-Control", "no-store")
    .with_header("Content-Security-Policy", browser_csp())
    .with_header("Referrer-Policy", "no-referrer")
    .with_header("X-Content-Type-Options", "nosniff")
    .with_header("X-Frame-Options", "DENY")
}

/// Builds an HTML response with the current browser-safety headers.
fn html_response(
    status_code: u16,
    reason_phrase: &'static str,
    title: &str,
    body_html: &str,
) -> HttpResponse {
    HttpResponse::text(
        status_code,
        reason_phrase,
        format!(
            "<!doctype html><html lang=\"en\"><head><meta charset=\"utf-8\"><meta name=\"viewport\" content=\"width=device-width, initial-scale=1\"><title>{}</title><style>body{{font-family:ui-monospace,monospace;max-width:72rem;margin:2rem auto;padding:0 1rem;line-height:1.5}}table{{border-collapse:collapse;width:100%}}th,td{{border:1px solid #444;padding:.5rem;text-align:left;vertical-align:top}}form{{margin:0}}input,textarea{{display:block;margin:.25rem 0 1rem;padding:.5rem;width:100%;max-width:48rem}}textarea{{min-height:16rem}}button{{padding:.5rem .9rem}}nav{{margin-bottom:1.5rem}}.muted{{color:#555}}</style></head><body>{}</body></html>",
            escape_html(title),
            body_html,
        ),
    )
    .with_header("Cache-Control", "no-store")
    .with_header("Content-Security-Policy", browser_csp())
    .with_header("Referrer-Policy", "no-referrer")
    .with_header("X-Content-Type-Options", "nosniff")
    .with_header("X-Frame-Options", "DENY")
}

/// Builds a forced-download response for one resolved attachment payload.
fn attachment_download_response(attachment: &DownloadedAttachment) -> HttpResponse {
    HttpResponse::binary(200, "OK", attachment.body.clone())
        .with_header("Content-Type", attachment.content_type.clone())
        .with_header(
            "Content-Disposition",
            build_attachment_content_disposition(&attachment.filename),
        )
        .with_header("Cache-Control", "no-store")
        .with_header("Referrer-Policy", "no-referrer")
        .with_header("X-Content-Type-Options", "nosniff")
        .with_header("X-Frame-Options", "DENY")
}

/// Builds a conservative attachment-style `Content-Disposition` header value.
fn build_attachment_content_disposition(filename: &str) -> String {
    format!(
        "attachment; filename=\"{}\"",
        escape_header_quoted_string(filename)
    )
}

/// Escapes a response header quoted-string without widening filename syntax.
fn escape_header_quoted_string(value: &str) -> String {
    let mut escaped = String::with_capacity(value.len());
    for ch in value.chars() {
        match ch {
            '"' => escaped.push_str("\\\""),
            '\\' => escaped.push_str("\\\\"),
            _ => escaped.push(ch),
        }
    }
    escaped
}

/// Returns the current narrow content-security-policy for HTML responses.
fn browser_csp() -> &'static str {
    "default-src 'none'; style-src 'unsafe-inline'; form-action 'self'; base-uri 'none'; frame-ancestors 'none'"
}

/// Builds a structured HTTP info event with the shared request fields attached.
fn build_http_info_event(
    action: &'static str,
    message: &str,
    context: &AuthenticationContext,
) -> LogEvent {
    LogEvent::new(LogLevel::Info, EventCategory::Http, action, message)
        .with_field("request_id", context.request_id.clone())
        .with_field("remote_addr", context.remote_addr.clone())
        .with_field("user_agent", context.user_agent.clone())
}

/// Builds a structured HTTP warning event with the shared request fields attached.
fn build_http_warning_event(
    action: &'static str,
    message: &str,
    context: &AuthenticationContext,
) -> LogEvent {
    LogEvent::new(LogLevel::Warn, EventCategory::Http, action, message)
        .with_field("request_id", context.request_id.clone())
        .with_field("remote_addr", context.remote_addr.clone())
        .with_field("user_agent", context.user_agent.clone())
}

/// Maps session errors into small stable labels for browser-operation logs.
fn session_error_label(error: &SessionError) -> &'static str {
    match error {
        SessionError::InvalidToken { .. } => "invalid_token",
        SessionError::RandomSourceFailure { .. } => "random_source_failure",
        SessionError::StoreFailure { .. } => "store_failure",
        SessionError::SessionNotFound { .. } => "session_not_found",
    }
}

/// Generates the next bounded synthetic request identifier.
fn next_request_id() -> String {
    let id = REQUEST_COUNTER.fetch_add(1, Ordering::Relaxed);
    format!("http-{id}")
}

/// Maps a public reason string into a small browser-facing message.
fn public_reason_message(reason: &str) -> &'static str {
    match reason {
        "invalid_credentials" => "The supplied credentials were not accepted.",
        "invalid_request" => "The submitted request was not valid.",
        "invalid_second_factor" => "The submitted second-factor code was not accepted.",
        "not_found" => "The requested item was not found.",
        _ => "The service could not complete the request at this time.",
    }
}

/// Renders the current login page with an optional operator-safe error banner.
fn render_login_page(error_message: Option<&str>) -> String {
    let banner = match error_message {
        Some(error_message) => format!(
            "<p><strong>Request failed:</strong> {}</p>",
            escape_html(error_message)
        ),
        None => String::new(),
    };

    format!(
        "<h1>OSMAP Login</h1><p class=\"muted\">This first browser slice uses one form for username, password, and TOTP while still enforcing the underlying primary-auth and second-factor boundaries.</p>{banner}<form method=\"post\" action=\"/login\"><label>Username<input type=\"text\" name=\"username\" autocomplete=\"username\"></label><label>Password<input type=\"password\" name=\"password\" autocomplete=\"current-password\"></label><label>TOTP Code<input type=\"text\" name=\"totp_code\" inputmode=\"numeric\" autocomplete=\"one-time-code\"></label><button type=\"submit\">Sign In</button></form>"
    )
}

/// Renders the mailbox home page for the validated user.
fn render_mailboxes_page(
    canonical_username: &str,
    csrf_token: &str,
    mailboxes: &[MailboxEntry],
) -> String {
    let mut items = String::new();
    for mailbox in mailboxes {
        let mailbox_name = escape_html(&mailbox.name);
        let mailbox_href = format!("/mailbox?name={}", url_encode(&mailbox.name));
        items.push_str(&format!(
            "<li><a href=\"{}\">{}</a></li>",
            escape_html(&mailbox_href),
            mailbox_name,
        ));
    }

    format!(
        "<nav><a href=\"/compose\">Compose</a> | <form method=\"post\" action=\"/logout\" style=\"display:inline\"><input type=\"hidden\" name=\"csrf_token\" value=\"{}\"><button type=\"submit\">Log Out</button></form></nav><h1>Mailboxes</h1><p>Signed in as <strong>{}</strong>.</p><ul>{}</ul>",
        escape_html(csrf_token),
        escape_html(canonical_username),
        items,
    )
}

/// Renders the message-list page for one mailbox.
fn render_message_list_page(
    canonical_username: &str,
    csrf_token: &str,
    mailbox_name: &str,
    messages: &[MessageSummary],
) -> String {
    let mut rows = String::new();
    for message in messages {
        let message_href = format!(
            "/message?mailbox={}&uid={}",
            url_encode(mailbox_name),
            message.uid
        );
        rows.push_str(&format!(
            "<tr><td><a href=\"{}\">{}</a></td><td>{}</td><td>{}</td><td>{}</td></tr>",
            escape_html(&message_href),
            message.uid,
            escape_html(&message.date_received),
            escape_html(&message.flags.join(" ")),
            message.size_virtual,
        ));
    }

    format!(
        "<nav><a href=\"/mailboxes\">Back to mailboxes</a> | <a href=\"/compose\">Compose</a> | <form method=\"post\" action=\"/logout\" style=\"display:inline\"><input type=\"hidden\" name=\"csrf_token\" value=\"{}\"><button type=\"submit\">Log Out</button></form></nav><h1>Mailbox: {}</h1><p>Signed in as <strong>{}</strong>.</p><table><thead><tr><th>UID</th><th>Received</th><th>Flags</th><th>Size</th></tr></thead><tbody>{}</tbody></table>",
        escape_html(csrf_token),
        escape_html(mailbox_name),
        escape_html(canonical_username),
        rows,
    )
}

/// Renders the message-view page using the existing safe renderer output.
fn render_message_view_page(
    canonical_username: &str,
    csrf_token: &str,
    rendered: &RenderedMessageView,
) -> String {
    let mut attachments = String::new();
    if rendered.attachments.is_empty() {
        attachments.push_str("<li>No attachment metadata surfaced for this message.</li>");
    } else {
        for attachment in &rendered.attachments {
            let download_href = format!(
                "/attachment?mailbox={}&uid={}&part={}",
                url_encode(&rendered.mailbox_name),
                rendered.uid,
                url_encode(&attachment.part_path),
            );
            attachments.push_str(&format!(
                "<li>Part <strong>{}</strong>: {} ({}, {}, {} bytes) [<a href=\"{}\">Download</a>]</li>",
                escape_html(&attachment.part_path),
                escape_html(attachment.filename.as_deref().unwrap_or("<unnamed>")),
                escape_html(&attachment.content_type),
                escape_html(attachment.disposition.as_str()),
                attachment.size_hint_bytes,
                escape_html(&download_href),
            ));
        }
    }

    format!(
        "<nav><a href=\"/mailbox?name={}\">Back to mailbox</a> | <a href=\"/compose\">Compose</a> | <a href=\"/compose?mode=reply&mailbox={}&uid={}\">Reply</a> | <a href=\"/compose?mode=forward&mailbox={}&uid={}\">Forward</a> | <form method=\"post\" action=\"/logout\" style=\"display:inline\"><input type=\"hidden\" name=\"csrf_token\" value=\"{}\"><button type=\"submit\">Log Out</button></form></nav><h1>Message View</h1><p>Signed in as <strong>{}</strong>.</p><dl><dt>Mailbox</dt><dd>{}</dd><dt>UID</dt><dd>{}</dd><dt>Subject</dt><dd>{}</dd><dt>From</dt><dd>{}</dd><dt>Received</dt><dd>{}</dd><dt>MIME Type</dt><dd>{}</dd><dt>Body Source</dt><dd>{}</dd><dt>HTML Present</dt><dd>{}</dd></dl><h2>Attachments</h2><ul>{}</ul><h2>Body</h2>{}",
        escape_html(&url_encode(&rendered.mailbox_name)),
        escape_html(&url_encode(&rendered.mailbox_name)),
        rendered.uid,
        escape_html(&url_encode(&rendered.mailbox_name)),
        rendered.uid,
        escape_html(csrf_token),
        escape_html(canonical_username),
        escape_html(&rendered.mailbox_name),
        rendered.uid,
        escape_html(rendered.subject.as_deref().unwrap_or("<none>")),
        escape_html(rendered.from.as_deref().unwrap_or("<none>")),
        escape_html(&rendered.date_received),
        escape_html(&rendered.mime_top_level_content_type),
        escape_html(rendered.body_source.as_str()),
        if rendered.contains_html_body { "yes" } else { "no" },
        attachments,
        rendered.body_html,
    )
}

/// Small view model for the current server-rendered compose page.
struct ComposePageModel<'a> {
    heading: &'a str,
    canonical_username: &'a str,
    csrf_token: &'a str,
    success_message: Option<&'a str>,
    error_message: Option<&'a str>,
    context_notice: Option<&'a str>,
    to_value: &'a str,
    subject_value: &'a str,
    body_value: &'a str,
}

/// Renders the compose page for the current user and CSRF-bound session.
fn render_compose_page(model: &ComposePageModel<'_>) -> String {
    let success_banner = match model.success_message {
        Some(success_message) => format!(
            "<p><strong>Submission complete:</strong> {}</p>",
            escape_html(success_message)
        ),
        None => String::new(),
    };
    let error_banner = match model.error_message {
        Some(error_message) => format!(
            "<p><strong>Request failed:</strong> {}</p>",
            escape_html(error_message)
        ),
        None => String::new(),
    };
    let context_banner = match model.context_notice {
        Some(context_notice) => format!(
            "<p><strong>Context:</strong> {}</p>",
            escape_html(context_notice)
        ),
        None => String::new(),
    };

    format!(
        "<nav><a href=\"/mailboxes\">Back to mailboxes</a> | <form method=\"post\" action=\"/logout\" style=\"display:inline\"><input type=\"hidden\" name=\"csrf_token\" value=\"{}\"><button type=\"submit\">Log Out</button></form></nav><h1>{}</h1><p>Signed in as <strong>{}</strong>.</p><p class=\"muted\">This send slice uses the local submission surface, keeps the browser body plain-text-first, accepts bounded new file uploads, and still does not reattach files from the source message automatically.</p>{}{}{}<form method=\"post\" action=\"/send\" enctype=\"multipart/form-data\"><input type=\"hidden\" name=\"csrf_token\" value=\"{}\"><label>To<input type=\"text\" name=\"to\" value=\"{}\" autocomplete=\"off\"></label><label>Subject<input type=\"text\" name=\"subject\" value=\"{}\"></label><label>Body<textarea name=\"body\">{}</textarea></label><label>Attachments<input type=\"file\" name=\"attachment\" multiple></label><button type=\"submit\">Send Message</button></form>",
        escape_html(model.csrf_token),
        escape_html(model.heading),
        escape_html(model.canonical_username),
        success_banner,
        error_banner,
        context_banner,
        escape_html(model.csrf_token),
        escape_html(model.to_value),
        escape_html(model.subject_value),
        escape_html(model.body_value),
    )
}

/// Parses the optional compose source reference from the current request.
fn compose_source_from_request(
    request: &HttpRequest,
) -> Result<Option<(ComposeIntent, String, u64)>, String> {
    let mode = request.query_params.get("mode").map(String::as_str);
    let mailbox = request.query_params.get("mailbox").cloned();
    let uid = request.query_params.get("uid").cloned();

    match (mode, mailbox, uid) {
        (None, None, None) => Ok(None),
        (Some(mode), Some(mailbox), Some(uid)) => {
            let intent = match mode {
                "reply" => ComposeIntent::Reply,
                "forward" => ComposeIntent::Forward,
                _ => {
                    return Err("compose mode must be reply or forward".to_string());
                }
            };
            let uid = uid
                .parse::<u64>()
                .map_err(|_| "compose source uid must be a positive integer".to_string())?;
            if uid == 0 {
                return Err("compose source uid must be greater than zero".to_string());
            }

            Ok(Some((intent, mailbox, uid)))
        }
        _ => Err("compose source requires mode, mailbox, and uid together".to_string()),
    }
}

/// Escapes HTML-significant characters for simple template insertion.
fn escape_html(value: &str) -> String {
    let mut escaped = String::with_capacity(value.len());
    for ch in value.chars() {
        match ch {
            '&' => escaped.push_str("&amp;"),
            '<' => escaped.push_str("&lt;"),
            '>' => escaped.push_str("&gt;"),
            '"' => escaped.push_str("&quot;"),
            '\'' => escaped.push_str("&#39;"),
            _ => escaped.push(ch),
        }
    }
    escaped
}

/// URL-encodes a query component without bringing in an HTTP utility crate.
fn url_encode(value: &str) -> String {
    let mut encoded = String::new();
    for byte in value.bytes() {
        match byte {
            b'A'..=b'Z' | b'a'..=b'z' | b'0'..=b'9' | b'-' | b'_' | b'.' | b'~' => {
                encoded.push(byte as char)
            }
            b' ' => encoded.push('+'),
            _ => encoded.push_str(&format!("%{:02X}", byte)),
        }
    }
    encoded
}

/// Compares two byte slices without early exit for CSRF token validation.
fn constant_time_eq(left: &[u8], right: &[u8]) -> bool {
    if left.len() != right.len() {
        return false;
    }

    let mut diff = 0_u8;
    for (left_byte, right_byte) in left.iter().zip(right.iter()) {
        diff |= left_byte ^ right_byte;
    }

    diff == 0
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::auth::RequiredSecondFactor;
    use crate::mailbox::MessageView;
    use crate::mime::{AttachmentDisposition, MimeBodySource};
    use crate::rendering::RenderingMode;
    use crate::session::SessionRecord;

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
        .expect("request should parse");

        assert_eq!(request.method, HttpMethod::Get);
        assert_eq!(request.path, "/mailbox");
        assert_eq!(
            request.query_params.get("name").map(String::as_str),
            Some("INBOX")
        );
        assert_eq!(
            session_cookie_value(&request, DEFAULT_SESSION_COOKIE_NAME).as_deref(),
            Some("abc")
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
        assert!(body.contains("/attachment?mailbox=INBOX&amp;uid=9&amp;part=1.2"));
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
}
