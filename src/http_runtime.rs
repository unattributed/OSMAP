use std::io::Write as _;
use std::net::{TcpListener, TcpStream};
use std::sync::atomic::{AtomicU64, Ordering};
use std::time::Duration;

use crate::auth::AuthenticationContext;
use crate::config::{AppConfig, AppRunMode, LogLevel};
use crate::http_parse::{normalize_peer_addr, read_http_request};
use crate::http_support::{build_http_info_event, build_http_warning_event, html_response};
use crate::logging::{EventCategory, LogEvent, Logger};
use crate::openbsd::apply_runtime_confinement;

use super::{
    BrowserApp, BrowserGateway, HandledHttpResponse, HttpMethod, HttpPolicy, HttpRequest,
    HttpResponse, RuntimeBrowserGateway,
};

static REQUEST_COUNTER: AtomicU64 = AtomicU64::new(1);

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

/// Generates the next bounded synthetic request identifier.
fn next_request_id() -> String {
    let id = REQUEST_COUNTER.fetch_add(1, Ordering::Relaxed);
    format!("http-{id}")
}
