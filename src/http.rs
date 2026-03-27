//! Minimal HTTP and browser handling for the first OSMAP web slice.
//!
//! This module deliberately avoids a framework while the project is still
//! proving its security and operational shape. The goal is not feature breadth;
//! the goal is an explicit, reviewable request path that consumes the existing
//! auth, session, mailbox, and rendering layers.

use std::collections::BTreeMap;
use std::io::{Read as _, Write as _};
use std::net::{TcpListener, TcpStream};
use std::path::PathBuf;
use std::sync::atomic::{AtomicU64, Ordering};

use crate::auth::{
    AuthenticationContext, AuthenticationDecision, AuthenticationPolicy, AuthenticationService,
    DoveadmAuthTestBackend, PublicFailureReason, RequiredSecondFactor, SecondFactorService,
    SystemCommandExecutor,
};
use crate::config::{AppConfig, AppRunMode, LogLevel, RuntimeEnvironment};
use crate::logging::{EventCategory, LogEvent, Logger};
use crate::mailbox::{
    DoveadmMailboxListBackend, DoveadmMessageListBackend, DoveadmMessageViewBackend, MailboxEntry,
    MailboxListingDecision, MailboxListingPolicy, MailboxListingService, MessageListDecision,
    MessageListPolicy, MessageListRequest, MessageListService, MessageSummary, MessageViewDecision,
    MessageViewPolicy, MessageViewRequest, MessageViewService,
};
use crate::openbsd::apply_runtime_confinement;
use crate::rendering::{PlainTextMessageRenderer, RenderedMessageView, RenderingPolicy};
use crate::send::{
    ComposeDraft, ComposeIntent, ComposePolicy, ComposeRequest, SendmailSubmissionBackend,
    SubmissionDecision, SubmissionPublicFailureReason, SubmissionService,
};
use crate::session::{
    FileSessionStore, SessionError, SessionService, SessionToken, SystemRandomSource,
    ValidatedSession,
};
use crate::totp::{FileTotpSecretStore, SystemTimeProvider, TotpPolicy, TotpVerifier};

/// Conservative upper bound for the full header section of an inbound request.
pub const DEFAULT_HTTP_MAX_HEADER_BYTES: usize = 16 * 1024;

/// Conservative upper bound for a small HTML form request body.
pub const DEFAULT_HTTP_MAX_BODY_BYTES: usize = 8 * 1024;

/// Conservative upper bound for parsed HTML form fields.
pub const DEFAULT_HTTP_MAX_FORM_FIELDS: usize = 16;

/// The fixed cookie name used by the current browser session slice.
pub const DEFAULT_SESSION_COOKIE_NAME: &str = "osmap_session";

static REQUEST_COUNTER: AtomicU64 = AtomicU64::new(1);

/// Policy controlling the first bounded HTTP/browser slice.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct HttpPolicy {
    pub max_header_bytes: usize,
    pub max_body_bytes: usize,
    pub max_form_fields: usize,
    pub session_cookie_name: &'static str,
    pub secure_session_cookie: bool,
    pub authentication_policy: AuthenticationPolicy,
}

impl HttpPolicy {
    /// Builds the browser policy from validated application configuration.
    pub fn from_config(config: &AppConfig) -> Self {
        Self {
            max_header_bytes: DEFAULT_HTTP_MAX_HEADER_BYTES,
            max_body_bytes: DEFAULT_HTTP_MAX_BODY_BYTES,
            max_form_fields: DEFAULT_HTTP_MAX_FORM_FIELDS,
            session_cookie_name: DEFAULT_SESSION_COOKIE_NAME,
            secure_session_cookie: config.environment != RuntimeEnvironment::Development,
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
            max_body_bytes: DEFAULT_HTTP_MAX_BODY_BYTES,
            max_form_fields: DEFAULT_HTTP_MAX_FORM_FIELDS,
            session_cookie_name: DEFAULT_SESSION_COOKIE_NAME,
            secure_session_cookie: false,
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
    pub body: String,
}

/// A small HTTP response that can be written directly to a socket.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct HttpResponse {
    pub status_code: u16,
    pub reason_phrase: &'static str,
    pub headers: Vec<(String, String)>,
    pub body: String,
}

impl HttpResponse {
    /// Creates a response with the supplied status and body.
    pub fn new(status_code: u16, reason_phrase: &'static str, body: impl Into<String>) -> Self {
        Self {
            status_code,
            reason_phrase,
            headers: Vec::new(),
            body: body.into(),
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
        output.push_str(&self.body);
        output.into_bytes()
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

    fn send_message(
        &self,
        context: &AuthenticationContext,
        validated_session: &ValidatedSession,
        recipients: &str,
        subject: &str,
        body: &str,
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
        validated_session: ValidatedSession,
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
        rendered: RenderedMessageView,
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
    Denied {
        public_reason: String,
    },
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
                None,
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
        let auth_outcome = self.build_auth_service().authenticate(context, username, password);
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
                    AuthenticationDecision::AuthenticatedPendingSession {
                        canonical_username,
                    } => match self.build_session_service().issue(
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
                            audit_events.push(build_http_warning_event(
                                "session_issue_failed",
                                "session issuance failed during browser login",
                                context,
                            )
                            .with_field("reason", session_error_label(&error)));
                            BrowserLoginOutcome {
                                decision: BrowserLoginDecision::Denied {
                                    public_reason:
                                        PublicFailureReason::TemporarilyUnavailable
                                            .as_str()
                                            .to_string(),
                                },
                                audit_events,
                            }
                        }
                    },
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
                    validated_session: validated_session.clone(),
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

        match self.build_session_service().revoke_by_token(context, &token) {
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
        let outcome = MailboxListingService::new(DoveadmMailboxListBackend::new(
            MailboxListingPolicy::default(),
            SystemCommandExecutor,
            self.doveadm_path.clone(),
        ))
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

        let outcome = MessageListService::new(DoveadmMessageListBackend::new(
            MessageListPolicy::default(),
            SystemCommandExecutor,
            self.doveadm_path.clone(),
        ))
        .list_for_validated_session(context, validated_session, &request);

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
        let request = match MessageViewRequest::new(MessageViewPolicy::default(), mailbox_name, uid) {
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

        let message_outcome = MessageViewService::new(DoveadmMessageViewBackend::new(
            MessageViewPolicy::default(),
            SystemCommandExecutor,
            self.doveadm_path.clone(),
        ))
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
                            rendered: rendered_outcome.rendered,
                        },
                        audit_events,
                    }
                }
                Err(error) => {
                    audit_events.push(build_http_warning_event(
                        "message_render_failed",
                        "message rendering failed",
                        context,
                    )
                    .with_field("reason", error.reason));
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

    fn send_message(
        &self,
        context: &AuthenticationContext,
        validated_session: &ValidatedSession,
        recipients: &str,
        subject: &str,
        body: &str,
    ) -> BrowserSendOutcome {
        let request = match ComposeRequest::new(
            ComposePolicy::default(),
            recipients,
            subject,
            body,
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
    pub fn handle_request(
        &self,
        request: &HttpRequest,
        remote_addr: &str,
    ) -> HandledHttpResponse {
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
                response: HttpResponse::new(200, "OK", "ok\n")
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
        let form = match parse_form_urlencoded(
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

        let outcome = self.gateway.login(context, &username, &password, &totp_code);

        match outcome.decision {
            BrowserLoginDecision::Authenticated { session_token, .. } => HandledHttpResponse {
                response: redirect_response(303, "See Other", "/mailboxes")
                    .with_header(
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
        if let Some(session_token) = session_cookie_value(request, self.policy.session_cookie_name) {
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
                &render_compose_page(
                    compose_heading,
                    &validated_session.record.canonical_username,
                    &validated_session.record.csrf_token,
                    success_message,
                    None,
                    context_notice.as_deref(),
                    &to_value,
                    &subject_value,
                    &body_value,
                ),
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
        let form = match parse_form_urlencoded(
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
        let outcome = self
            .gateway
            .send_message(context, &validated_session, &recipients, &subject, &body);
        audit_events.extend(outcome.audit_events);

        match outcome.decision {
            BrowserSendDecision::Submitted => HandledHttpResponse {
                response: redirect_response(303, "See Other", "/compose?sent=1"),
                audit_events,
            },
            BrowserSendDecision::Denied { public_reason } => {
                let status_code = if public_reason == "invalid_request" { 400 } else { 503 };
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
                        &render_compose_page(
                            "Compose",
                            &validated_session.record.canonical_username,
                            &validated_session.record.csrf_token,
                            None,
                            Some(public_reason_message(&public_reason)),
                            None,
                            &recipients,
                            &subject,
                            &body,
                        ),
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
        let form = match parse_form_urlencoded(
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
        if let Some(session_token) = session_cookie_value(request, self.policy.session_cookie_name) {
            let validation = self.gateway.validate_session(context, &session_token);
            audit_events.extend(validation.audit_events.clone());
            if let BrowserSessionDecision::Valid { validated_session } = validation.decision {
                if let Some(response) = self.require_valid_csrf(
                    form.get("csrf_token").map(String::as_str),
                    &validated_session,
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
                clear_session_cookie(self.policy.session_cookie_name, self.policy.secure_session_cookie),
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
        let Some(session_token) = session_cookie_value(request, self.policy.session_cookie_name) else {
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
                Ok((validated_session, outcome.audit_events))
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
pub fn run_http_server(
    config: &AppConfig,
    logger: &Logger,
) -> Result<(), String> {
    if config.run_mode != AppRunMode::Serve {
        return Ok(());
    }

    apply_runtime_confinement(config, logger)?;

    let listener = TcpListener::bind(&config.listen_addr)
        .map_err(|error| format!("failed to bind {}: {error}", config.listen_addr))?;
    let app = BrowserApp::new(HttpPolicy::from_config(config), RuntimeBrowserGateway::from_config(config));
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
        .map(|addr| addr.to_string())
        .unwrap_or_else(|_| "<unknown>".to_string());

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

/// Reads one bounded HTTP request from the supplied stream.
fn read_http_request(stream: &mut TcpStream, policy: &HttpPolicy) -> Result<HttpRequest, HttpRequestError> {
    let mut buffer = Vec::new();
    let mut content_length = None;
    let mut header_end = None;

    loop {
        let mut chunk = [0_u8; 2048];
        let read = stream
            .read(&mut chunk)
            .map_err(|error| HttpRequestError {
                reason: format!("failed reading request: {error}"),
            })?;
        if read == 0 {
            break;
        }

        buffer.extend_from_slice(&chunk[..read]);

        if header_end.is_none() {
            if buffer.len() > policy.max_header_bytes + policy.max_body_bytes {
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
                let header_text = std::str::from_utf8(&buffer[..end]).map_err(|_| HttpRequestError {
                    reason: "http headers were not valid utf-8".to_string(),
                })?;
                content_length = Some(parse_content_length(header_text)?);
            }
        }

        if let (Some(end), Some(content_length)) = (header_end, content_length) {
            let expected_len = end + 4 + content_length;
            if content_length > policy.max_body_bytes {
                return Err(HttpRequestError {
                    reason: "http body exceeded maximum length".to_string(),
                });
            }
            if buffer.len() >= expected_len {
                break;
            }
        }
    }

    let request_text = String::from_utf8(buffer).map_err(|_| HttpRequestError {
        reason: "request bytes were not valid utf-8".to_string(),
    })?;
    parse_http_request(&request_text, policy)
}

/// Parses a raw HTTP request into the bounded request shape used by the router.
pub fn parse_http_request(input: &str, policy: &HttpPolicy) -> Result<HttpRequest, HttpRequestError> {
    let header_end = input.find("\r\n\r\n").ok_or_else(|| HttpRequestError {
        reason: "missing http header terminator".to_string(),
    })?;

    if header_end > policy.max_header_bytes {
        return Err(HttpRequestError {
            reason: "http headers exceeded maximum length".to_string(),
        });
    }

    let header_block = &input[..header_end];
    let body = &input[header_end + 4..];
    if body.len() > policy.max_body_bytes {
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

    let (path, query_params) = parse_request_target(target)?;
    let mut headers = BTreeMap::new();
    for line in lines {
        let Some((name, value)) = line.split_once(':') else {
            return Err(HttpRequestError {
                reason: "malformed http header line".to_string(),
            });
        };
        headers.insert(name.trim().to_ascii_lowercase(), value.trim().to_string());
    }

    if let Some(content_length_value) = headers.get("content-length") {
        let content_length = content_length_value.parse::<usize>().map_err(|_| HttpRequestError {
            reason: "invalid content-length header".to_string(),
        })?;
        if content_length != body.len() {
            return Err(HttpRequestError {
                reason: "http body length did not match content-length".to_string(),
            });
        }
    } else if method == HttpMethod::Post && !body.is_empty() {
        return Err(HttpRequestError {
            reason: "post requests must send content-length".to_string(),
        });
    }

    Ok(HttpRequest {
        method,
        path,
        query_params,
        headers,
        body: body.to_string(),
    })
}

/// Finds the end of the HTTP header block.
fn find_header_end(buffer: &[u8]) -> Option<usize> {
    buffer.windows(4).position(|window| window == b"\r\n\r\n")
}

/// Parses the content-length header from a raw header block.
fn parse_content_length(header_text: &str) -> Result<usize, HttpRequestError> {
    for line in header_text.lines().skip(1) {
        if let Some((name, value)) = line.split_once(':') {
            if name.trim().eq_ignore_ascii_case("content-length") {
                return value.trim().parse::<usize>().map_err(|_| HttpRequestError {
                    reason: "invalid content-length header".to_string(),
                });
            }
        }
    }

    Ok(0)
}

/// Parses the request target into a path and decoded query map.
fn parse_request_target(target: &str) -> Result<(String, BTreeMap<String, String>), HttpRequestError> {
    let (path, query) = target.split_once('?').unwrap_or((target, ""));
    if path.is_empty() || !path.starts_with('/') {
        return Err(HttpRequestError {
            reason: "request target must start with '/'".to_string(),
        });
    }

    Ok((path.to_string(), parse_urlencoded_map(query, usize::MAX)?))
}

/// Parses a URL-encoded form body into a bounded key/value map.
fn parse_form_urlencoded(
    body: &str,
    max_fields: usize,
    max_bytes: usize,
) -> Result<BTreeMap<String, String>, HttpRequestError> {
    if body.len() > max_bytes {
        return Err(HttpRequestError {
            reason: "form body exceeded maximum length".to_string(),
        });
    }

    parse_urlencoded_map(body, max_fields)
}

/// Parses a URL-encoded string into a key/value map.
fn parse_urlencoded_map(
    input: &str,
    max_fields: usize,
) -> Result<BTreeMap<String, String>, HttpRequestError> {
    let mut output = BTreeMap::new();

    if input.is_empty() {
        return Ok(output);
    }

    for (index, pair) in input.split('&').enumerate() {
        if index >= max_fields {
            return Err(HttpRequestError {
                reason: "form field count exceeded maximum".to_string(),
            });
        }

        let (key, value) = pair.split_once('=').unwrap_or((pair, ""));
        output.insert(percent_decode(key)?, percent_decode(value)?);
    }

    Ok(output)
}

/// Decodes one URL-encoded segment into UTF-8 text.
fn percent_decode(input: &str) -> Result<String, HttpRequestError> {
    let mut bytes = Vec::with_capacity(input.len());
    let mut chars = input.as_bytes().iter().copied();

    while let Some(byte) = chars.next() {
        match byte {
            b'+' => bytes.push(b' '),
            b'%' => {
                let high = chars.next().ok_or_else(|| HttpRequestError {
                    reason: "truncated percent-encoded sequence".to_string(),
                })?;
                let low = chars.next().ok_or_else(|| HttpRequestError {
                    reason: "truncated percent-encoded sequence".to_string(),
                })?;
                bytes.push((hex_value(high)? << 4) | hex_value(low)?);
            }
            _ => bytes.push(byte),
        }
    }

    String::from_utf8(bytes).map_err(|_| HttpRequestError {
        reason: "url-encoded field was not valid utf-8".to_string(),
    })
}

/// Decodes one hexadecimal ASCII byte used in percent encoding.
fn hex_value(byte: u8) -> Result<u8, HttpRequestError> {
    match byte {
        b'0'..=b'9' => Ok(byte - b'0'),
        b'a'..=b'f' => Ok(byte - b'a' + 10),
        b'A'..=b'F' => Ok(byte - b'A' + 10),
        _ => Err(HttpRequestError {
            reason: "invalid percent-encoded byte".to_string(),
        }),
    }
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
    let mut cookie =
        format!("{cookie_name}=; Path=/; HttpOnly; SameSite=Strict; Max-Age=0");
    if secure {
        cookie.push_str("; Secure");
    }
    cookie
}

/// Builds a redirect response with the current browser-security headers.
fn redirect_response(status_code: u16, reason_phrase: &'static str, location: &str) -> HttpResponse {
    HttpResponse::new(
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
    HttpResponse::new(
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
            attachments.push_str(&format!(
                "<li>Part <strong>{}</strong>: {} ({}, {}, {} bytes)</li>",
                escape_html(&attachment.part_path),
                escape_html(attachment.filename.as_deref().unwrap_or("<unnamed>")),
                escape_html(&attachment.content_type),
                escape_html(attachment.disposition.as_str()),
                attachment.size_hint_bytes,
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

/// Renders the compose page for the current user and CSRF-bound session.
fn render_compose_page(
    heading: &str,
    canonical_username: &str,
    csrf_token: &str,
    success_message: Option<&str>,
    error_message: Option<&str>,
    context_notice: Option<&str>,
    to_value: &str,
    subject_value: &str,
    body_value: &str,
) -> String {
    let success_banner = match success_message {
        Some(success_message) => format!(
            "<p><strong>Submission complete:</strong> {}</p>",
            escape_html(success_message)
        ),
        None => String::new(),
    };
    let error_banner = match error_message {
        Some(error_message) => format!(
            "<p><strong>Request failed:</strong> {}</p>",
            escape_html(error_message)
        ),
        None => String::new(),
    };
    let context_banner = match context_notice {
        Some(context_notice) => format!(
            "<p><strong>Context:</strong> {}</p>",
            escape_html(context_notice)
        ),
        None => String::new(),
    };

    format!(
        "<nav><a href=\"/mailboxes\">Back to mailboxes</a> | <form method=\"post\" action=\"/logout\" style=\"display:inline\"><input type=\"hidden\" name=\"csrf_token\" value=\"{}\"><button type=\"submit\">Log Out</button></form></nav><h1>{}</h1><p>Signed in as <strong>{}</strong>.</p><p class=\"muted\">This send slice uses the local submission surface, keeps the browser body plain-text-first, and does not attach files automatically yet.</p>{}{}{}<form method=\"post\" action=\"/send\"><input type=\"hidden\" name=\"csrf_token\" value=\"{}\"><label>To<input type=\"text\" name=\"to\" value=\"{}\" autocomplete=\"off\"></label><label>Subject<input type=\"text\" name=\"subject\" value=\"{}\"></label><label>Body<textarea name=\"body\">{}</textarea></label><button type=\"submit\">Send Message</button></form>",
        escape_html(csrf_token),
        escape_html(heading),
        escape_html(canonical_username),
        success_banner,
        error_banner,
        context_banner,
        escape_html(csrf_token),
        escape_html(to_value),
        escape_html(subject_value),
        escape_html(body_value),
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
                    session_id:
                        "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef"
                            .to_string(),
                    csrf_token:
                        "fedcba9876543210fedcba9876543210fedcba9876543210fedcba9876543210"
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
            if presented_token
                == "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"
            {
                BrowserSessionValidationOutcome {
                    decision: BrowserSessionDecision::Valid {
                        validated_session: Self::validated_session(),
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
                    rendered: RenderedMessageView {
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
                    },
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
        ) -> BrowserSendOutcome {
            if recipients == "bob@example.com" {
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
    }

    fn app() -> BrowserApp<StubGateway> {
        BrowserApp::new(HttpPolicy::default(), StubGateway)
    }

    fn request(method: &str, path: &str, headers: &[(&str, &str)], body: &str) -> HttpRequest {
        let mut raw = format!("{method} {path} HTTP/1.1\r\nHost: localhost\r\n");
        for (name, value) in headers {
            raw.push_str(&format!("{name}: {value}\r\n"));
        }
        raw.push_str(&format!("Content-Length: {}\r\n\r\n{}", body.len(), body));
        parse_http_request(&raw, &HttpPolicy::default()).expect("request should parse")
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
        assert_eq!(request.query_params.get("name").map(String::as_str), Some("INBOX"));
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
        assert!(response.response.body.contains("OSMAP Login"));
        assert!(response.response.body.contains("totp_code"));
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
        assert!(response.response.body.contains("alice@example.com"));
        assert!(response.response.body.contains("Archive/2026"));
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
        assert!(response.response.body.contains("multipart/mixed"));
        assert!(response.response.body.contains("report.pdf"));
        assert!(response.response.body.contains("<pre>Hello world</pre>"));
        assert!(response.response.body.contains("mode=reply"));
        assert!(response.response.body.contains("mode=forward"));
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
        assert!(response.response.body.contains("name=\"csrf_token\""));
        assert!(response.response.body.contains("action=\"/send\""));
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
        assert!(response.response.body.contains("<h1>Reply</h1>"));
        assert!(response.response.body.contains("alice@example.com"));
        assert!(response.response.body.contains("Re: Example"));
        assert!(response.response.body.contains("does not resend attachments automatically"));
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
        assert!(response.response.body.contains("<h1>Forward</h1>"));
        assert!(response.response.body.contains("Fwd: Example"));
        assert!(response.response.body.contains("report.pdf"));
        assert!(response.response.body.contains("does not reattach files yet"));
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
        assert!(response.response.body.contains("CSRF Validation Failed"));
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
}
