use std::io::Write as _;
use std::net::{TcpListener, TcpStream};
use std::sync::atomic::{AtomicU64, Ordering};
use std::thread;
use std::time::{Duration, Instant};

use crate::auth::AuthenticationContext;
use crate::config::{AppConfig, AppRunMode, LogLevel};
use crate::http_parse::{normalize_peer_addr, read_http_request};
use crate::http_support::{build_http_info_event, build_http_warning_event, html_response};
use crate::logging::{EventCategory, LogEvent, Logger};
use crate::openbsd::apply_runtime_confinement;

use super::{
    BrowserApp, BrowserGateway, HandledHttpResponse, HttpMethod, HttpPolicy, HttpRequest,
    HttpRequestErrorKind, HttpResponse, RuntimeBrowserGateway,
};

static REQUEST_COUNTER: AtomicU64 = AtomicU64::new(1);
const HTTP_ACCEPT_FAILURE_BACKOFF_CAP_MILLIS: u64 = 1000;
const HTTP_REQUEST_SLOW_THRESHOLD_MILLIS: u128 = 1000;

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
            (HttpMethod::Get, "/settings") => self.handle_settings_page(request, &context),
            (HttpMethod::Post, "/message/move") => self.handle_message_move(request, &context),
            (HttpMethod::Post, "/send") => self.handle_send(request, &context),
            (HttpMethod::Post, "/sessions/revoke") => self.handle_session_revoke(request, &context),
            (HttpMethod::Post, "/settings") => self.handle_settings_update(request, &context),
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

    let mut consecutive_accept_failures = 0_u32;
    for stream in listener.incoming() {
        match stream {
            Ok(mut stream) => {
                consecutive_accept_failures = 0;
                handle_client_stream(&app, logger, &mut stream)
            }
            Err(error) => {
                consecutive_accept_failures = consecutive_accept_failures.saturating_add(1);
                let backoff_millis = accept_failure_backoff_millis(consecutive_accept_failures);
                logger.emit(
                    &LogEvent::new(
                        LogLevel::Warn,
                        EventCategory::Http,
                        "http_accept_failed",
                        "http connection accept failed",
                    )
                    .with_field("reason", error.to_string())
                    .with_field(
                        "consecutive_failures",
                        consecutive_accept_failures.to_string(),
                    )
                    .with_field("backoff_millis", backoff_millis.to_string()),
                );
                if backoff_millis != 0 {
                    thread::sleep(Duration::from_millis(backoff_millis));
                }
            }
        }
    }

    Ok(())
}

/// Returns the bounded backoff used after consecutive accept failures.
pub(super) fn accept_failure_backoff_millis(consecutive_failures: u32) -> u64 {
    if consecutive_failures == 0 {
        return 0;
    }

    let exponent = consecutive_failures.saturating_sub(1).min(5);
    let backoff = 50_u64.saturating_mul(1_u64 << exponent);
    backoff.min(HTTP_ACCEPT_FAILURE_BACKOFF_CAP_MILLIS)
}

/// Handles one accepted client connection and closes it after one response.
pub(super) fn handle_client_stream<G>(app: &BrowserApp<G>, logger: &Logger, stream: &mut TcpStream)
where
    G: BrowserGateway,
{
    let connection_started = Instant::now();
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

    let (handled, request_completion) = match read_http_request(stream, app.policy()) {
        Ok(request) => {
            let handled = app.handle_request(&request, &remote_addr);
            let response_bytes = handled.response.to_http_bytes();
            let completion_event = build_request_completion_event(
                &remote_addr,
                request.method,
                &request.path,
                handled.response.status_code,
                response_bytes.len(),
                connection_started.elapsed(),
            );
            (handled, Some((response_bytes, completion_event)))
        }
        Err(error) => match error.kind {
            HttpRequestErrorKind::Empty => {
                logger.emit(
                    &LogEvent::new(
                        LogLevel::Info,
                        EventCategory::Http,
                        "http_connection_closed_without_request",
                        "http connection closed before request bytes were received",
                    )
                    .with_field("remote_addr", remote_addr),
                );
                return;
            }
            HttpRequestErrorKind::Truncated => {
                logger.emit(
                    &LogEvent::new(
                        LogLevel::Warn,
                        EventCategory::Http,
                        "http_request_incomplete",
                        "http request ended before a complete request was received",
                    )
                    .with_field("remote_addr", remote_addr)
                    .with_field("reason", error.reason),
                );
                return;
            }
            HttpRequestErrorKind::Timeout => (
                HandledHttpResponse {
                    response: html_response(
                        408,
                        "Request Timeout",
                        "Request Timed Out",
                        "<p>The request was not completed before the connection timed out.</p>",
                    ),
                    audit_events: vec![LogEvent::new(
                        LogLevel::Warn,
                        EventCategory::Http,
                        "http_request_timed_out",
                        "http request timed out before completion",
                    )
                    .with_field("remote_addr", remote_addr.clone())
                    .with_field("reason", error.reason)],
                },
                None,
            ),
            HttpRequestErrorKind::Parse => (
                HandledHttpResponse {
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
                None,
            ),
        },
    };

    for event in &handled.audit_events {
        logger.emit(event);
    }

    let response_bytes = request_completion
        .as_ref()
        .map(|(response_bytes, _)| response_bytes.clone())
        .unwrap_or_else(|| handled.response.to_http_bytes());
    if let Some((_, completion_event)) = &request_completion {
        logger.emit(completion_event);
    }
    if let Err(error) = stream.write_all(&response_bytes) {
        logger.emit(
            &LogEvent::new(
                LogLevel::Warn,
                EventCategory::Http,
                "http_response_write_failed",
                "http response write failed",
            )
            .with_field("remote_addr", remote_addr)
            .with_field("status_code", handled.response.status_code.to_string())
            .with_field(
                "duration_ms",
                connection_started.elapsed().as_millis().to_string(),
            )
            .with_field("reason", error.to_string()),
        );
    }
}

/// Builds a central completion event for one parsed HTTP request.
pub(super) fn build_request_completion_event(
    remote_addr: &str,
    method: HttpMethod,
    path: &str,
    status_code: u16,
    response_bytes: usize,
    duration: Duration,
) -> LogEvent {
    let duration_ms = duration.as_millis();
    let (level, action, message) = if duration_ms >= HTTP_REQUEST_SLOW_THRESHOLD_MILLIS {
        (
            LogLevel::Warn,
            "http_request_slow",
            "http request completed slowly",
        )
    } else {
        (
            LogLevel::Info,
            "http_request_completed",
            "http request completed",
        )
    };

    LogEvent::new(level, EventCategory::Http, action, message)
        .with_field("remote_addr", remote_addr.to_string())
        .with_field("method", method.as_str())
        .with_field("path", path.to_string())
        .with_field("status_code", status_code.to_string())
        .with_field("response_bytes", response_bytes.to_string())
        .with_field("duration_ms", duration_ms.to_string())
}

/// Generates the next bounded synthetic request identifier.
fn next_request_id() -> String {
    let id = REQUEST_COUNTER.fetch_add(1, Ordering::Relaxed);
    format!("http-{id}")
}
