use std::io::Write as _;
use std::net::{TcpListener, TcpStream};
use std::panic::{catch_unwind, AssertUnwindSafe};
use std::sync::atomic::{AtomicU64, AtomicUsize, Ordering};
use std::sync::Arc;
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
const HTTP_ACCEPT_FAILURE_ESCALATION_THRESHOLD: u32 = 5;
const HTTP_RESPONSE_WRITE_FAILURE_ESCALATION_THRESHOLD: u32 = 5;
const HTTP_REQUEST_SLOW_THRESHOLD_MILLIS: u128 = 1000;
const HTTP_OVER_CAPACITY_RETRY_AFTER_SECS: u64 = 1;
const HTTP_WORKER_THREAD_NAME: &str = "osmap-http-conn";

pub(super) struct ResponseWriteFailureContext<'a> {
    pub(super) remote_addr: String,
    pub(super) reason: String,
    pub(super) consecutive_failures: usize,
    pub(super) status_code: Option<u16>,
    pub(super) request_context: Option<(&'a str, &'a str, usize)>,
    pub(super) response_bytes: usize,
    pub(super) active_connections: Option<usize>,
    pub(super) over_capacity_response: bool,
}

pub(super) struct RequestCompletionContext {
    pub(super) remote_addr: String,
    pub(super) method: HttpMethod,
    pub(super) path: String,
    pub(super) status_code: u16,
    pub(super) response_bytes: usize,
}

struct ConnectionSlotGuard {
    active_connections: Arc<AtomicUsize>,
}

impl ConnectionSlotGuard {
    fn new(active_connections: Arc<AtomicUsize>) -> Self {
        Self { active_connections }
    }
}

impl Drop for ConnectionSlotGuard {
    fn drop(&mut self) {
        release_connection_slot(self.active_connections.as_ref());
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

/// Runs the current bounded-concurrency HTTP server for the browser slice.
pub fn run_http_server(config: &AppConfig, logger: &Logger) -> Result<(), String> {
    if config.run_mode != AppRunMode::Serve {
        return Ok(());
    }

    apply_runtime_confinement(config, logger)?;

    let listener = TcpListener::bind(&config.listen_addr)
        .map_err(|error| format!("failed to bind {}: {error}", config.listen_addr))?;
    let app = Arc::new(BrowserApp::new(
        HttpPolicy::from_config(config),
        RuntimeBrowserGateway::from_config(config),
    ));
    let active_connections = Arc::new(AtomicUsize::new(0));
    let peak_connections = Arc::new(AtomicUsize::new(0));
    let consecutive_response_write_failures = Arc::new(AtomicUsize::new(0));
    logger.emit(
        &LogEvent::new(
            LogLevel::Info,
            EventCategory::Http,
            "http_server_started",
            "http server started",
        )
        .with_field("listen_addr", config.listen_addr.clone())
        .with_field("run_mode", config.run_mode.as_str())
        .with_field(
            "max_concurrent_connections",
            app.policy().max_concurrent_connections.to_string(),
        ),
    );

    let mut consecutive_accept_failures = 0_u32;
    for stream in listener.incoming() {
        match stream {
            Ok(mut stream) => {
                if consecutive_accept_failures >= HTTP_ACCEPT_FAILURE_ESCALATION_THRESHOLD {
                    logger.emit(&build_accept_recovery_event(consecutive_accept_failures));
                }
                consecutive_accept_failures = 0;
                let active_after_accept =
                    match try_acquire_connection_slot(&active_connections, app.policy()) {
                        Some(active_after_accept) => active_after_accept,
                        None => {
                            let observed_active_connections =
                                active_connections.load(Ordering::Acquire);
                            handle_over_capacity_stream(
                                logger,
                                &mut stream,
                                app.policy(),
                                observed_active_connections,
                                &consecutive_response_write_failures,
                            );
                            continue;
                        }
                    };

                maybe_log_connection_high_watermark(
                    logger,
                    app.policy(),
                    &peak_connections,
                    active_after_accept,
                );

                let app = Arc::clone(&app);
                let worker_logger = logger.clone();
                let worker_active_connections = Arc::clone(&active_connections);
                let consecutive_response_write_failures =
                    Arc::clone(&consecutive_response_write_failures);
                if let Err(event) = spawn_connection_worker(
                    app,
                    worker_logger,
                    stream,
                    worker_active_connections,
                    consecutive_response_write_failures,
                    spawn_http_connection_worker,
                ) {
                    logger.emit(&event);
                }
            }
            Err(error) => {
                consecutive_accept_failures = consecutive_accept_failures.saturating_add(1);
                let backoff_millis = accept_failure_backoff_millis(consecutive_accept_failures);
                logger.emit(&build_accept_failure_event(
                    error.to_string(),
                    consecutive_accept_failures,
                    backoff_millis,
                ));
                if backoff_millis != 0 {
                    thread::sleep(Duration::from_millis(backoff_millis));
                }
            }
        }
    }

    Ok(())
}

pub(super) fn spawn_connection_worker<G, S>(
    app: Arc<BrowserApp<G>>,
    logger: Logger,
    stream: TcpStream,
    active_connections: Arc<AtomicUsize>,
    consecutive_response_write_failures: Arc<AtomicUsize>,
    spawn_fn: S,
) -> Result<(), LogEvent>
where
    G: BrowserGateway + Send + Sync + 'static,
    S: FnOnce(
        Arc<BrowserApp<G>>,
        Logger,
        TcpStream,
        Arc<AtomicUsize>,
        Arc<AtomicUsize>,
    ) -> std::io::Result<()>,
{
    let active_before_release = active_connections.load(Ordering::Acquire);
    match spawn_fn(
        app,
        logger,
        stream,
        Arc::clone(&active_connections),
        consecutive_response_write_failures,
    ) {
        Ok(()) => Ok(()),
        Err(error) => {
            let active_after_release = release_connection_slot(active_connections.as_ref());
            Err(build_connection_worker_spawn_failed_event(
                error.to_string(),
                active_before_release,
                active_after_release,
            ))
        }
    }
}

/// Attempts to reserve one in-flight connection slot under the configured cap.
pub(super) fn try_acquire_connection_slot(
    active_connections: &AtomicUsize,
    policy: &HttpPolicy,
) -> Option<usize> {
    let limit = policy.max_concurrent_connections;
    let mut current = active_connections.load(Ordering::Acquire);

    loop {
        if current >= limit {
            return None;
        }

        match active_connections.compare_exchange_weak(
            current,
            current + 1,
            Ordering::AcqRel,
            Ordering::Acquire,
        ) {
            Ok(_) => return Some(current + 1),
            Err(observed) => current = observed,
        }
    }
}

fn spawn_http_connection_worker<G>(
    app: Arc<BrowserApp<G>>,
    logger: Logger,
    mut stream: TcpStream,
    active_connections: Arc<AtomicUsize>,
    consecutive_response_write_failures: Arc<AtomicUsize>,
) -> std::io::Result<()>
where
    G: BrowserGateway + Send + Sync + 'static,
{
    thread::Builder::new()
        .name(HTTP_WORKER_THREAD_NAME.to_string())
        .spawn(move || {
            if let Some(event) = run_connection_worker(
                app.as_ref(),
                &logger,
                &mut stream,
                &active_connections,
                consecutive_response_write_failures.as_ref(),
                handle_client_stream_with_write_tracking,
            ) {
                logger.emit(&event);
            }
        })
        .map(|_| ())
}

pub(super) fn run_connection_worker<G, H>(
    app: &BrowserApp<G>,
    logger: &Logger,
    stream: &mut TcpStream,
    active_connections: &Arc<AtomicUsize>,
    consecutive_response_write_failures: &AtomicUsize,
    handler: H,
) -> Option<LogEvent>
where
    G: BrowserGateway,
    H: FnOnce(&BrowserApp<G>, &Logger, &mut TcpStream, &AtomicUsize),
{
    let remote_addr = stream
        .peer_addr()
        .map(normalize_peer_addr)
        .unwrap_or_else(|_| "<unknown>".to_string());
    let slot_guard = ConnectionSlotGuard::new(Arc::clone(active_connections));
    let panic_result = catch_unwind(AssertUnwindSafe(|| {
        handler(app, logger, stream, consecutive_response_write_failures);
    }));
    drop(slot_guard);

    panic_result.err().map(|payload| {
        build_connection_worker_panicked_event(
            describe_panic_payload(payload.as_ref()),
            remote_addr,
            active_connections.load(Ordering::Acquire),
        )
    })
}

pub(super) fn release_connection_slot(active_connections: &AtomicUsize) -> usize {
    let mut current = active_connections.load(Ordering::Acquire);

    loop {
        if current == 0 {
            return 0;
        }

        match active_connections.compare_exchange_weak(
            current,
            current - 1,
            Ordering::AcqRel,
            Ordering::Acquire,
        ) {
            Ok(_) => return current - 1,
            Err(observed) => current = observed,
        }
    }
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

/// Builds the current accept-failure event with thresholded escalation for
/// sustained listener faults.
pub(super) fn build_accept_failure_event(
    reason: String,
    consecutive_failures: u32,
    backoff_millis: u64,
) -> LogEvent {
    let escalated = consecutive_failures >= HTTP_ACCEPT_FAILURE_ESCALATION_THRESHOLD;
    let (level, action, message) = if escalated {
        (
            LogLevel::Error,
            "http_accept_failed_sustained",
            "http connection accept has failed repeatedly",
        )
    } else {
        (
            LogLevel::Warn,
            "http_accept_failed",
            "http connection accept failed",
        )
    };

    LogEvent::new(level, EventCategory::Http, action, message)
        .with_field("reason", reason)
        .with_field("consecutive_failures", consecutive_failures.to_string())
        .with_field("backoff_millis", backoff_millis.to_string())
}

/// Builds the recovery event emitted when the listener accepts again after a
/// sustained accept-failure streak.
pub(super) fn build_accept_recovery_event(previous_failure_streak: u32) -> LogEvent {
    LogEvent::new(
        LogLevel::Info,
        EventCategory::Http,
        "http_accept_recovered",
        "http listener recovered after repeated accept failures",
    )
    .with_field(
        "previous_consecutive_failures",
        previous_failure_streak.to_string(),
    )
}

pub(super) fn build_connection_worker_spawn_failed_event(
    reason: String,
    active_connections_before_release: usize,
    active_connections_after_release: usize,
) -> LogEvent {
    LogEvent::new(
        LogLevel::Error,
        EventCategory::Http,
        "http_connection_worker_spawn_failed",
        "http connection worker could not be started",
    )
    .with_field("reason", reason)
    .with_field(
        "active_connections_before_release",
        active_connections_before_release.to_string(),
    )
    .with_field(
        "active_connections_after_release",
        active_connections_after_release.to_string(),
    )
}

pub(super) fn build_connection_worker_panicked_event(
    reason: String,
    remote_addr: String,
    active_connections_after_release: usize,
) -> LogEvent {
    LogEvent::new(
        LogLevel::Error,
        EventCategory::Http,
        "http_connection_worker_panicked",
        "http connection worker panicked",
    )
    .with_field("reason", reason)
    .with_field("remote_addr", remote_addr)
    .with_field("thread_name", HTTP_WORKER_THREAD_NAME)
    .with_field(
        "active_connections_after_release",
        active_connections_after_release.to_string(),
    )
}

fn describe_panic_payload(payload: &(dyn std::any::Any + Send)) -> String {
    if let Some(message) = payload.downcast_ref::<&str>() {
        return (*message).to_string();
    }
    if let Some(message) = payload.downcast_ref::<String>() {
        return message.clone();
    }

    "non-string panic payload".to_string()
}

/// Rejects an accepted connection when the runtime is already at capacity.
pub(super) fn handle_over_capacity_stream(
    logger: &Logger,
    stream: &mut TcpStream,
    policy: &HttpPolicy,
    active_connections: usize,
    consecutive_response_write_failures: &AtomicUsize,
) {
    let remote_addr = stream
        .peer_addr()
        .map(normalize_peer_addr)
        .unwrap_or_else(|_| "<unknown>".to_string());
    let _ = stream.set_write_timeout(Some(Duration::from_secs(policy.write_timeout_secs)));

    logger.emit(
        &LogEvent::new(
            LogLevel::Warn,
            EventCategory::Http,
            "http_connection_rejected_over_capacity",
            "http connection rejected because the runtime was already at capacity",
        )
        .with_field("remote_addr", remote_addr.clone())
        .with_field(
            "max_concurrent_connections",
            policy.max_concurrent_connections.to_string(),
        )
        .with_field("active_connections", active_connections.to_string()),
    );

    let response = html_response(
        503,
        "Service Unavailable",
        "Service Busy",
        "<p>The service is temporarily busy. Please retry shortly.</p>",
    )
    .with_header(
        "Retry-After",
        HTTP_OVER_CAPACITY_RETRY_AFTER_SECS.to_string(),
    );

    let response_bytes = response.to_http_bytes();
    match stream.write_all(&response_bytes) {
        Ok(()) => {
            if let Some(event) = take_response_write_recovery_event(
                consecutive_response_write_failures,
                &remote_addr,
            ) {
                logger.emit(&event);
            }
        }
        Err(error) => {
            let consecutive_failures = consecutive_response_write_failures
                .fetch_add(1, Ordering::AcqRel)
                .saturating_add(1);
            logger.emit(&build_response_write_failure_event(
                ResponseWriteFailureContext {
                    remote_addr,
                    reason: error.to_string(),
                    consecutive_failures,
                    status_code: None,
                    request_context: None,
                    response_bytes: response_bytes.len(),
                    active_connections: Some(active_connections),
                    over_capacity_response: true,
                },
            ));
        }
    }
}

/// Handles one accepted client connection and closes it after one response.
#[cfg(test)]
#[allow(dead_code)]
pub(super) fn handle_client_stream<G>(app: &BrowserApp<G>, logger: &Logger, stream: &mut TcpStream)
where
    G: BrowserGateway,
{
    let standalone_tracking = AtomicUsize::new(0);
    handle_client_stream_with_write_tracking(app, logger, stream, &standalone_tracking);
}

/// Handles one accepted client connection and tracks response-write failure
/// streaks across the wider runtime.
fn handle_client_stream_with_write_tracking<G>(
    app: &BrowserApp<G>,
    logger: &Logger,
    stream: &mut TcpStream,
    consecutive_response_write_failures: &AtomicUsize,
) where
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

    let (handled, request_completion, request_write_context) =
        match read_http_request(stream, app.policy()) {
            Ok(request) => {
                let handled = app.handle_request(&request, &remote_addr);
                let status_code = handled.response.status_code;
                let response_bytes = handled.response.to_http_bytes();
                (
                    handled,
                    Some(RequestCompletionContext {
                        remote_addr: remote_addr.clone(),
                        method: request.method,
                        path: request.path.clone(),
                        status_code,
                        response_bytes: response_bytes.len(),
                    }),
                    Some((
                        request.method.as_str().to_string(),
                        request.path.clone(),
                        response_bytes.len(),
                    )),
                )
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
                    None,
                ),
            },
        };

    for event in &handled.audit_events {
        logger.emit(event);
    }

    let response_bytes = handled.response.to_http_bytes();
    match stream.write_all(&response_bytes) {
        Ok(()) => {
            for event in build_successful_response_events(
                request_completion.as_ref(),
                consecutive_response_write_failures,
                connection_started.elapsed(),
                &remote_addr,
            ) {
                logger.emit(&event);
            }
        }
        Err(error) => {
            let consecutive_failures = consecutive_response_write_failures
                .fetch_add(1, Ordering::AcqRel)
                .saturating_add(1);
            let request_context =
                request_write_context
                    .as_ref()
                    .map(|(method, path, attempted_bytes)| {
                        (method.as_str(), path.as_str(), *attempted_bytes)
                    });
            logger.emit(
                &build_response_write_failure_event(ResponseWriteFailureContext {
                    remote_addr,
                    reason: error.to_string(),
                    consecutive_failures,
                    status_code: Some(handled.response.status_code),
                    request_context,
                    response_bytes: response_bytes.len(),
                    active_connections: None,
                    over_capacity_response: false,
                })
                .with_field(
                    "duration_ms",
                    connection_started.elapsed().as_millis().to_string(),
                ),
            );
        }
    }
}

/// Emits a bounded observability event when the runtime reaches a new
/// in-flight connection high-water mark.
pub(super) fn maybe_log_connection_high_watermark(
    logger: &Logger,
    policy: &HttpPolicy,
    peak_connections: &AtomicUsize,
    active_connections: usize,
) {
    let mut observed_peak = peak_connections.load(Ordering::Acquire);

    loop {
        if active_connections <= observed_peak {
            return;
        }

        match peak_connections.compare_exchange_weak(
            observed_peak,
            active_connections,
            Ordering::AcqRel,
            Ordering::Acquire,
        ) {
            Ok(_) => {
                logger.emit(&build_connection_high_watermark_event(
                    policy,
                    active_connections,
                ));
                return;
            }
            Err(observed) => observed_peak = observed,
        }
    }
}

/// Builds an observability event for a new in-flight connection high-water
/// mark.
pub(super) fn build_connection_high_watermark_event(
    policy: &HttpPolicy,
    active_connections: usize,
) -> LogEvent {
    let utilization_percent =
        (active_connections.saturating_mul(100)) / policy.max_concurrent_connections.max(1);
    let (level, action, message) = if active_connections >= policy.max_concurrent_connections {
        (
            LogLevel::Warn,
            "http_connection_capacity_reached",
            "http runtime reached its configured connection capacity",
        )
    } else {
        (
            LogLevel::Info,
            "http_connection_high_watermark_reached",
            "http runtime reached a new in-flight connection high-water mark",
        )
    };

    LogEvent::new(level, EventCategory::Http, action, message)
        .with_field("active_connections", active_connections.to_string())
        .with_field(
            "max_concurrent_connections",
            policy.max_concurrent_connections.to_string(),
        )
        .with_field("utilization_percent", utilization_percent.to_string())
}

/// Builds a response-write failure event with thresholded escalation for
/// sustained output failures.
pub(super) fn build_response_write_failure_event(
    context: ResponseWriteFailureContext<'_>,
) -> LogEvent {
    let ResponseWriteFailureContext {
        remote_addr,
        reason,
        consecutive_failures,
        status_code,
        request_context,
        response_bytes,
        active_connections,
        over_capacity_response,
    } = context;

    let escalated =
        consecutive_failures >= HTTP_RESPONSE_WRITE_FAILURE_ESCALATION_THRESHOLD as usize;
    let (level, action, message) = if over_capacity_response {
        if escalated {
            (
                LogLevel::Error,
                "http_over_capacity_response_write_failed_sustained",
                "http over-capacity response writes have failed repeatedly",
            )
        } else {
            (
                LogLevel::Warn,
                "http_over_capacity_response_write_failed",
                "http over-capacity response write failed",
            )
        }
    } else if escalated {
        (
            LogLevel::Error,
            "http_response_write_failed_sustained",
            "http response writes have failed repeatedly",
        )
    } else {
        (
            LogLevel::Warn,
            "http_response_write_failed",
            "http response write failed",
        )
    };

    let mut event = LogEvent::new(level, EventCategory::Http, action, message)
        .with_field("remote_addr", remote_addr)
        .with_field("consecutive_failures", consecutive_failures.to_string())
        .with_field("response_bytes", response_bytes.to_string())
        .with_field("reason", reason);

    if let Some(status_code) = status_code {
        event = event.with_field("status_code", status_code.to_string());
    }

    if let Some((method, path, attempted_response_bytes)) = request_context {
        event = event
            .with_field("method", method.to_string())
            .with_field("path", path.to_string())
            .with_field(
                "attempted_response_bytes",
                attempted_response_bytes.to_string(),
            );
    }

    if let Some(active_connections) = active_connections {
        event = event.with_field("active_connections", active_connections.to_string());
    }

    event
}

pub(super) fn build_successful_response_events(
    request_completion: Option<&RequestCompletionContext>,
    consecutive_response_write_failures: &AtomicUsize,
    duration: Duration,
    remote_addr: &str,
) -> Vec<LogEvent> {
    let mut events = Vec::new();

    if let Some(completion_context) = request_completion {
        events.push(build_request_completion_event(
            &completion_context.remote_addr,
            completion_context.method,
            &completion_context.path,
            completion_context.status_code,
            completion_context.response_bytes,
            duration,
        ));
    }

    if let Some(recovery_event) =
        take_response_write_recovery_event(consecutive_response_write_failures, remote_addr)
    {
        events.push(recovery_event);
    }

    events
}

/// Returns the recovery event emitted after a sustained response-write failure
/// streak, if one should be recorded.
fn take_response_write_recovery_event(
    consecutive_response_write_failures: &AtomicUsize,
    remote_addr: &str,
) -> Option<LogEvent> {
    let previous_failures = consecutive_response_write_failures.swap(0, Ordering::AcqRel);
    if previous_failures < HTTP_RESPONSE_WRITE_FAILURE_ESCALATION_THRESHOLD as usize {
        return None;
    }

    Some(
        LogEvent::new(
            LogLevel::Info,
            EventCategory::Http,
            "http_response_write_recovered",
            "http response writes recovered after repeated failures",
        )
        .with_field("remote_addr", remote_addr.to_string())
        .with_field(
            "previous_consecutive_failures",
            previous_failures.to_string(),
        ),
    )
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
