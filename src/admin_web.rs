//! Private admin HTTP entry. Only an authenticated local TLS proxy reaches it.
//! The trusted service owns credentials, sessions, factors and current grants.
use crate::admin_config::WebConfig;
use crate::admin_transport::{Client, Error, Operation, Request, Response, VERSION};
use crate::auth::{AuthenticationPolicy, RequiredSecondFactor};
use crate::http::{HttpMethod, HttpPolicy, HttpRequest, HttpRequestErrorKind, HttpResponse};
use crate::http_form::{is_urlencoded_form_content_type, parse_urlencoded_form};
use crate::http_parse::{build_session_cookie, clear_session_cookie, read_http_request};
use std::collections::BTreeMap;
use std::io::{self, Read, Write};
use std::net::IpAddr;
use std::os::unix::fs::{MetadataExt, PermissionsExt};
use std::os::unix::net::{UnixListener, UnixStream};
use std::path::Path;
use std::sync::atomic::Ordering;
use std::time::{Duration, Instant};

const SESSION_COOKIE: &str = "__Host-osmap_admin";
const LOGIN_COOKIE: &str = "__Host-osmap_admin_login";
const APPEARANCE_COOKIE: &str = "__Host-osmap_admin_appearance";
const IO_LIMIT: Duration = Duration::from_secs(5);
const RESPONSE_LIMIT: usize = 1024 * 1024;

/// A narrow dependency seam for route tests, not a second execution framework.
trait Exchange {
    fn exchange(&self, request: &Request) -> Result<Response, Error>;
}
impl Exchange for Client {
    fn exchange(&self, request: &Request) -> Result<Response, Error> {
        Client::exchange(self, request)
    }
}

fn policy(config: &WebConfig) -> HttpPolicy {
    HttpPolicy {
        max_header_bytes: 4096,
        max_request_target_bytes: 512,
        max_header_count: 24,
        max_header_value_bytes: 1024,
        max_query_fields: 4,
        max_body_bytes: 8192,
        max_upload_body_bytes: 8192,
        max_form_fields: 10,
        allowed_hosts: vec![config.host.clone()],
        session_cookie_name: SESSION_COOKIE,
        secure_session_cookie: true,
        read_timeout_secs: 5,
        write_timeout_secs: 5,
        max_concurrent_connections: 1,
        mailbox_worker_budget: 0,
        search_worker_budget: 0,
        send_worker_budget: 0,
        auth_worker_budget: 1,
        expensive_request_timeout_secs: 20,
        request_budget_retry_after_secs: 1,
        authentication_policy: AuthenticationPolicy {
            username_max_len: 96,
            password_max_len: 72,
            request_id_max_len: 64,
            remote_addr_max_len: 45,
            user_agent_max_len: 128,
            factor_code_max_len: 6,
            required_second_factor: RequiredSecondFactor::Totp,
        },
    }
}

fn hex64(value: &str) -> bool {
    value.len() == 64 && value.bytes().all(|b| b.is_ascii_hexdigit())
}

fn bearer(value: &str) -> bool {
    value.strip_prefix("osmap-admin1.").is_some_and(hex64)
}

/// Reject duplicate target cookies instead of allowing proxy/parser ambiguity.
fn cookie<'a>(request: &'a HttpRequest, name: &str) -> Result<Option<&'a str>, ()> {
    let Some(header) = request.headers.get("cookie") else {
        return Ok(None);
    };
    let mut found = None;
    for part in header.split(';') {
        let part = part.trim();
        if part.is_empty() {
            continue;
        }
        let Some((key, value)) = part.split_once('=') else {
            return Err(());
        };
        if key.trim() == name {
            if found.is_some() {
                return Err(());
            }
            found = Some(value.trim());
        }
    }
    Ok(found)
}

fn form(request: &HttpRequest, expected: &[&str]) -> Result<BTreeMap<String, String>, ()> {
    bounded_form(request, expected, 2048)
}

fn bounded_form(
    request: &HttpRequest,
    expected: &[&str],
    maximum_bytes: usize,
) -> Result<BTreeMap<String, String>, ()> {
    if !request
        .headers
        .get("content-type")
        .is_some_and(|value| is_urlencoded_form_content_type(value))
    {
        return Err(());
    }
    let values =
        parse_urlencoded_form(&request.body, expected.len(), maximum_bytes).map_err(|_| ())?;
    if values.len() != expected.len() || expected.iter().any(|key| !values.contains_key(*key)) {
        return Err(());
    }
    Ok(values)
}

fn redirect(path: &'static str) -> HttpResponse {
    // A static destination and empty body keep bearer handles out of HTML.
    HttpResponse::text(303, "See Other", "")
        .with_header("Location", path)
        .with_header("Cache-Control", "no-store")
        .with_header(
            "Content-Security-Policy",
            crate::http_support::browser_csp(),
        )
        .with_header("Referrer-Policy", "same-origin")
        .with_header("X-Content-Type-Options", "nosniff")
        .with_header("X-Frame-Options", "DENY")
}

fn sign_in(denied: bool) -> HttpResponse {
    let mut random = [0_u8; 32];
    if getrandom::getrandom(&mut random).is_err() {
        return crate::admin_ui::error_page(503);
    }
    let csrf = random
        .iter()
        .map(|b| format!("{b:02x}"))
        .collect::<String>();
    crate::admin_ui::login_page(&csrf, denied).with_header(
        "Set-Cookie",
        build_session_cookie(LOGIN_COOKIE, &csrf, true),
    )
}

fn login<C: Exchange>(request: &HttpRequest, client_addr: &str, client: &C) -> HttpResponse {
    let Ok(values) = form(request, &["login", "password", "totp", "csrf"]) else {
        return crate::admin_ui::error_page(400);
    };
    let Ok(Some(expected)) = cookie(request, LOGIN_COOKIE) else {
        return crate::admin_ui::error_page(403);
    };
    if !hex64(expected)
        || !hex64(&values["csrf"])
        || !crate::http_support::constant_time_eq(expected.as_bytes(), values["csrf"].as_bytes())
    {
        return crate::admin_ui::error_page(403);
    }
    let rpc = Request {
        version: VERSION,
        client: client_addr.into(),
        operation: Operation::Login {
            login: values["login"].clone(),
            password: values["password"].clone(),
            totp: values["totp"].clone(),
        },
    };
    if rpc.validate().is_err() {
        return crate::admin_ui::error_page(400);
    }
    match client.exchange(&rpc) {
        Ok(Response::SignedIn { token }) if bearer(&token) => redirect("/admin")
            .with_header(
                "Set-Cookie",
                build_session_cookie(SESSION_COOKIE, &token, true),
            )
            .with_header("Set-Cookie", clear_session_cookie(LOGIN_COOKIE, true)),
        Ok(Response::Denied) => sign_in(true),
        Ok(Response::Invalid) => crate::admin_ui::error_page(400),
        _ => crate::admin_ui::error_page(503),
    }
}

fn scope<C: Exchange>(request: &HttpRequest, client_addr: &str, client: &C) -> HttpResponse {
    let token = match cookie(request, SESSION_COOKIE) {
        Ok(Some(value)) if bearer(value) => value,
        Ok(_) => {
            return redirect("/admin/login")
                .with_header("Set-Cookie", clear_session_cookie(SESSION_COOKIE, true));
        }
        Err(_) => return crate::admin_ui::error_page(403),
    };
    let rpc = Request {
        version: VERSION,
        client: client_addr.into(),
        operation: Operation::Scope {
            token: token.into(),
        },
    };
    match client.exchange(&rpc) {
        Ok(response @ Response::Scope { .. }) if response.validate().is_ok() => {
            let Response::Scope {
                login,
                system,
                domains,
                csrf,
            } = response
            else {
                return crate::admin_ui::error_page(503);
            };
            crate::admin_ui::scope_page(&login, system, &domains, &csrf)
        }
        Ok(Response::Denied) => redirect("/admin/login")
            .with_header("Set-Cookie", clear_session_cookie(SESSION_COOKIE, true)),
        _ => crate::admin_ui::error_page(503),
    }
}

fn logout<C: Exchange>(request: &HttpRequest, client_addr: &str, client: &C) -> HttpResponse {
    let Ok(values) = form(request, &["csrf"]) else {
        return crate::admin_ui::error_page(400);
    };
    let Ok(Some(token)) = cookie(request, SESSION_COOKIE) else {
        return crate::admin_ui::error_page(403);
    };
    let rpc = Request {
        version: VERSION,
        client: client_addr.into(),
        operation: Operation::Logout {
            token: token.into(),
            csrf: values["csrf"].clone(),
        },
    };
    if rpc.validate().is_err() {
        return crate::admin_ui::error_page(403);
    }
    match client.exchange(&rpc) {
        Ok(Response::SignedOut) => redirect("/admin/login")
            .with_header("Set-Cookie", clear_session_cookie(SESSION_COOKIE, true))
            .with_header("Set-Cookie", clear_session_cookie(LOGIN_COOKIE, true))
            .with_header("Set-Cookie", clear_session_cookie(APPEARANCE_COOKIE, true)),
        Ok(Response::Denied) | Ok(Response::Invalid) => crate::admin_ui::error_page(403),
        _ => crate::admin_ui::error_page(503),
    }
}

/// Called only after the accepted Unix stream's proxy UID has been verified.
fn handle<C: Exchange>(config: &WebConfig, request: &HttpRequest, client: &C) -> HttpResponse {
    let mut response = handle_inner(config, request, client);
    let supplied = response
        .headers
        .iter()
        .filter(|(key, _)| key.eq_ignore_ascii_case("Set-Cookie"))
        .find_map(|(_, value)| {
            value
                .strip_prefix(&format!("{APPEARANCE_COOKIE}="))
                .and_then(|v| v.split(';').next())
                .and_then(crate::admin_access::AdminPreferences::parse)
        });
    let preferences = supplied
        .or_else(|| {
            cookie(request, APPEARANCE_COOKIE)
                .ok()
                .flatten()
                .and_then(crate::admin_access::AdminPreferences::parse)
        })
        .unwrap_or_default();
    preferences.apply(&mut response);
    if request.path != "/admin/login" {
        preferences.apply_menus(&mut response);
    }
    response
}
fn handle_inner<C: Exchange>(
    config: &WebConfig,
    request: &HttpRequest,
    client: &C,
) -> HttpResponse {
    let inventory =
        request.path == "/admin/mailboxes" || request.path.starts_with("/admin/mailboxes/");
    if request.headers.get("host") != Some(&config.host)
        || (!request.query_params.is_empty()
            && !inventory
            && !matches!(
                request.path.as_str(),
                "/admin" | "/admin/domains" | "/admin/settings"
            ))
        || request
            .headers
            .get("origin")
            .is_some_and(|origin| origin != &config.origin)
    {
        return crate::admin_ui::error_page(403);
    }
    // This header is admitted only from the UID-checked Unix proxy, whose
    // protected configuration overwrites it from the accepted TLS connection.
    // Generic X-Forwarded-* and Forwarded headers never become source authority.
    let Some(client_addr) = request
        .headers
        .get("x-real-ip")
        .and_then(|value| value.parse::<IpAddr>().ok())
        .map(|value| value.to_string())
    else {
        return crate::admin_ui::error_page(403);
    };
    if request.method == HttpMethod::Post && request.headers.get("origin") != Some(&config.origin) {
        return crate::admin_ui::error_page(403);
    }
    match (&request.method, request.path.as_str()) {
        (HttpMethod::Get, "/admin/login") => sign_in(false),
        (HttpMethod::Post, "/admin/login") => login(request, &client_addr, client),
        (HttpMethod::Get, "/admin" | "/admin/domains" | "/admin/settings") => {
            dashboard(request, &client_addr, client)
        }
        (HttpMethod::Get, "/admin/account/scope") => scope(request, &client_addr, client),
        (HttpMethod::Get, path) if path.starts_with("/admin/domains/") => {
            dashboard(request, &client_addr, client)
        }
        (HttpMethod::Post, "/admin/settings/appearance") => {
            dashboard(request, &client_addr, client)
        }
        (HttpMethod::Get, "/admin/mailboxes") => {
            mailbox_inventory(request, &client_addr, client, None)
        }
        (HttpMethod::Get | HttpMethod::Post, "/admin/mailboxes/new") => {
            mailbox_create(request, &client_addr, client)
        }
        (HttpMethod::Get, path) if path.starts_with("/admin/mailboxes/") => mailbox_inventory(
            request,
            &client_addr,
            client,
            path.strip_prefix("/admin/mailboxes/"),
        ),
        _ if inventory => crate::admin_ui::error_page(405),
        (HttpMethod::Post, "/admin/logout") => logout(request, &client_addr, client),
        (
            _,
            "/admin"
            | "/admin/logout"
            | "/admin/domains"
            | "/admin/settings"
            | "/admin/settings/appearance",
        ) => crate::admin_ui::error_page(405),
        (_, path) if path.starts_with("/admin/domains/") => crate::admin_ui::error_page(405),
        _ => crate::admin_ui::error_page(404),
    }
}

fn appearance_cookie(preferences: &crate::admin_access::AdminPreferences) -> String {
    format!(
        "{APPEARANCE_COOKIE}={}; Path=/; Secure; HttpOnly; SameSite=Strict; Max-Age=31536000",
        preferences.value()
    )
}
fn dashboard<C: Exchange>(request: &HttpRequest, addr: &str, client: &C) -> HttpResponse {
    let token = match cookie(request, SESSION_COOKIE) {
        Ok(Some(value)) if bearer(value) => value,
        Ok(_) => {
            return redirect("/admin/login")
                .with_header("Set-Cookie", clear_session_cookie(SESSION_COOKIE, true))
        }
        Err(_) => return crate::admin_ui::error_page(403),
    };
    let path = request.path.as_str();
    let mut section = "appearance";
    let operation = match path {
        "/admin" | "/admin/domains" => {
            if request
                .query_params
                .iter()
                .any(|(key, _)| !matches!(key.as_str(), "q" | "page"))
            {
                return crate::admin_ui::error_page(400);
            }
            let query = request.query_params.get("q").cloned().unwrap_or_default();
            let page = match request.query_params.get("page") {
                Some(value) => match value.parse::<u8>() {
                    Ok(n) => n,
                    Err(_) => return crate::admin_ui::error_page(400),
                },
                None => 1,
            };
            Operation::Overview {
                token: token.into(),
                query,
                page,
            }
        }
        "/admin/settings" => {
            if request.query_params.iter().any(|(key, _)| key != "section") {
                return crate::admin_ui::error_page(400);
            }
            section = request
                .query_params
                .get("section")
                .map(String::as_str)
                .unwrap_or("appearance");
            if !matches!(section, "appearance" | "account" | "system") {
                return crate::admin_ui::error_page(400);
            }
            Operation::Settings {
                token: token.into(),
            }
        }
        "/admin/settings/appearance" => {
            let Ok(values) = form(
                request,
                &[
                    "csrf",
                    "theme",
                    "density",
                    "font_size",
                    "presentation_style",
                ],
            ) else {
                return crate::admin_ui::error_page(400);
            };
            Operation::SavePreferences {
                token: token.into(),
                csrf: values["csrf"].clone(),
                preferences: crate::admin_access::AdminPreferences {
                    theme: values["theme"].clone(),
                    density: values["density"].clone(),
                    font_size: values["font_size"].clone(),
                    presentation_style: values["presentation_style"].clone(),
                },
            }
        }
        _ => Operation::DomainDetails {
            token: token.into(),
            id: path.strip_prefix("/admin/domains/").unwrap_or("").into(),
        },
    };
    let rpc = Request {
        version: VERSION,
        client: addr.into(),
        operation,
    };
    if rpc.validate().is_err() {
        return crate::admin_ui::error_page(400);
    }
    match client.exchange(&rpc) {
        Ok(Response::Overview { page })
            if matches!(path, "/admin" | "/admin/domains") && page.valid() =>
        {
            let (query, requested) = match &rpc.operation {
                Operation::Overview { query, page, .. } => (query.trim(), *page),
                _ => return crate::admin_ui::error_page(503),
            };
            if page.query != query || page.page != requested.min(page.pages()) {
                return crate::admin_ui::error_page(503);
            }
            crate::admin_ui::overview_page(&page, path == "/admin/domains")
                .with_header("Set-Cookie", appearance_cookie(&page.preferences))
        }
        Ok(Response::DomainDetails { page })
            if path.strip_prefix("/admin/domains/") == Some(page.domain.id.as_str())
                && page.valid() =>
        {
            crate::admin_ui::domain_page(&page)
                .with_header("Set-Cookie", appearance_cookie(&page.preferences))
        }
        Ok(Response::Settings { page })
            if matches!(path, "/admin/settings" | "/admin/settings/appearance") && page.valid() =>
        {
            if path == "/admin/settings/appearance" {
                let expected = match &rpc.operation {
                    Operation::SavePreferences { preferences, .. } => preferences,
                    _ => return crate::admin_ui::error_page(503),
                };
                if expected != &page.preferences {
                    return crate::admin_ui::error_page(503);
                }
                crate::admin_ui::settings_page(&page, "appearance", true)
                    .with_header("Set-Cookie", appearance_cookie(&page.preferences))
            } else {
                crate::admin_ui::settings_page(&page, section, false)
                    .with_header("Set-Cookie", appearance_cookie(&page.preferences))
            }
        }
        Ok(Response::Denied) => redirect("/admin/login")
            .with_header("Set-Cookie", clear_session_cookie(SESSION_COOKIE, true)),
        Ok(Response::Missing) => crate::admin_ui::error_page(404),
        Ok(Response::Capacity) => crate::admin_ui::domain_capacity_page(),
        _ => crate::admin_ui::error_page(503),
    }
}

fn mailbox_create<C: Exchange>(request: &HttpRequest, addr: &str, client: &C) -> HttpResponse {
    use crate::admin_access::{CreateFailure, CreateMailbox};
    let token = match cookie(request, SESSION_COOKIE) {
        Ok(Some(value)) if bearer(value) => value,
        Ok(_) => {
            return redirect("/admin/login")
                .with_header("Set-Cookie", clear_session_cookie(SESSION_COOKIE, true))
        }
        Err(_) => return crate::admin_ui::error_page(403),
    };
    let (operation, domain, operation_id, expected_username, expected_quota) =
        if request.method == HttpMethod::Get {
            if request.query_params.len() != 1 {
                return crate::admin_ui::error_page(400);
            }
            let Some(domain) = request.query_params.get("domain") else {
                return crate::admin_ui::error_page(400);
            };
            (
                Operation::CreateMailboxForm {
                    token: token.into(),
                    domain: domain.clone(),
                },
                domain.clone(),
                None,
                None,
                None,
            )
        } else {
            if !request.query_params.is_empty() {
                return crate::admin_ui::error_page(400);
            }
            let Ok(values) = bounded_form(
                request,
                &[
                    "domain",
                    "local_part",
                    "display_name",
                    "password",
                    "confirmation",
                    "totp",
                    "csrf",
                    "request_id",
                    "quota_mib",
                    "revision",
                ],
                8192,
            ) else {
                return crate::admin_ui::error_page(400);
            };
            let (Ok(quota_mib), Ok(revision)) = (
                values["quota_mib"].parse::<u32>(),
                values["revision"].parse::<u64>(),
            ) else {
                return crate::admin_ui::error_page(400);
            };
            let create = CreateMailbox {
                domain: values["domain"].clone(),
                local_part: values["local_part"].clone(),
                display_name: values["display_name"].clone(),
                password: values["password"].clone(),
                confirmation: values["confirmation"].clone(),
                totp: values["totp"].clone(),
                csrf: values["csrf"].clone(),
                request_id: values["request_id"].clone(),
                quota_mib,
                revision,
            };
            if !create.valid() {
                return crate::admin_ui::error_page(400);
            }
            let domain = create.domain.clone();
            let operation_id = create.request_id.clone();
            let username = format!(
                "{}@{}",
                create.local_part.to_ascii_lowercase(),
                create.domain
            );
            let quota = u64::from(create.quota_mib) * 1_048_576;
            (
                Operation::CreateMailbox {
                    token: token.into(),
                    request: create,
                },
                domain,
                Some(operation_id),
                Some(username),
                Some(quota),
            )
        };
    let rpc = Request {
        version: VERSION,
        client: addr.into(),
        operation,
    };
    if rpc.validate().is_err() {
        return crate::admin_ui::error_page(400);
    }
    let uncertain = || {
        crate::admin_ui::create_failure_page(
            if operation_id.is_some() {
                CreateFailure::Unconfirmed
            } else {
                CreateFailure::Unavailable
            },
            &domain,
            operation_id.as_deref(),
        )
    };
    match client.exchange(&rpc) {
        Ok(Response::CreateMailboxForm { page })
            if operation_id.is_none() && page.domain == domain && page.valid() =>
        {
            crate::admin_ui::create_mailbox_page(&page)
        }
        Ok(Response::MailboxCreated { receipt })
            if receipt.valid()
                && Some(receipt.request_id.as_str()) == operation_id.as_deref()
                && receipt.domain == domain
                && Some(receipt.username.as_str()) == expected_username.as_deref()
                && Some(receipt.quota) == expected_quota =>
        {
            crate::admin_ui::mailbox_created_page(&receipt)
        }
        Ok(Response::CreateMailboxFailed { reason }) => {
            crate::admin_ui::create_failure_page(reason, &domain, operation_id.as_deref())
        }
        Ok(Response::Denied) => redirect("/admin/login")
            .with_header("Set-Cookie", clear_session_cookie(SESSION_COOKIE, true)),
        _ => uncertain(),
    }
}

fn mailbox_inventory<C: Exchange>(
    request: &HttpRequest,
    addr: &str,
    client: &C,
    id: Option<&str>,
) -> HttpResponse {
    let token = match cookie(request, SESSION_COOKIE) {
        Ok(Some(value)) if bearer(value) => value,
        Ok(_) => {
            return redirect("/admin/login")
                .with_header("Set-Cookie", clear_session_cookie(SESSION_COOKIE, true))
        }
        Err(_) => return crate::admin_ui::error_page(403),
    };
    let keys = if id.is_some() {
        &["domain"][..]
    } else {
        &["domain", "q", "page", "sort"][..]
    };
    if request
        .query_params
        .keys()
        .any(|key| !keys.contains(&key.as_str()))
    {
        return crate::admin_ui::error_page(400);
    }
    let Some(domain) = request.query_params.get("domain") else {
        return crate::admin_ui::error_page(400);
    };
    let query = request
        .query_params
        .get("q")
        .map(String::as_str)
        .unwrap_or("");
    let page = match request
        .query_params
        .get("page")
        .map(String::as_str)
        .unwrap_or("1")
        .parse::<u8>()
    {
        Ok(value) => value,
        Err(_) => return crate::admin_ui::error_page(400),
    };
    let sort = request
        .query_params
        .get("sort")
        .map(String::as_str)
        .unwrap_or("address");
    let operation = if let Some(id) = id {
        Operation::Mailbox {
            token: token.into(),
            domain: domain.clone(),
            id: id.into(),
        }
    } else {
        Operation::Mailboxes {
            token: token.into(),
            domain: domain.clone(),
            query: query.into(),
            page,
            sort: sort.into(),
        }
    };
    let rpc = Request {
        version: VERSION,
        client: addr.into(),
        operation,
    };
    if rpc.validate().is_err() {
        return crate::admin_ui::error_page(400);
    }
    match client.exchange(&rpc) {
        Ok(response) if response.validate().is_ok() => match response {
            Response::Mailboxes { page: result }
                if id.is_none()
                    && result.domain == *domain
                    && result.query == query
                    && result.page == page
                    && result.sort == sort =>
            {
                crate::admin_ui::mailboxes_page(&result)
            }
            Response::Mailbox {
                login,
                csrf,
                domain: returned,
                mailbox,
            } if id == Some(mailbox.id.as_str()) && returned == *domain => {
                crate::admin_ui::mailbox_page(&login, &csrf, domain, &mailbox)
            }
            Response::Denied => redirect("/admin/login")
                .with_header("Set-Cookie", clear_session_cookie(SESSION_COOKIE, true)),
            Response::Missing => crate::admin_ui::error_page(404),
            Response::Capacity => crate::admin_ui::capacity_page(),
            Response::Invalid => crate::admin_ui::error_page(400),
            _ => crate::admin_ui::error_page(503),
        },
        _ => crate::admin_ui::error_page(503),
    }
}

struct DeadlineReader<'a> {
    stream: &'a mut UnixStream,
    deadline: Instant,
    read_bytes: usize,
}
impl Read for DeadlineReader<'_> {
    fn read(&mut self, buffer: &mut [u8]) -> io::Result<usize> {
        let remaining = self
            .deadline
            .checked_duration_since(Instant::now())
            .filter(|remaining| !remaining.is_zero())
            .ok_or(io::ErrorKind::TimedOut)?;
        self.stream.set_read_timeout(Some(remaining))?;
        let count = self.stream.read(buffer)?;
        self.read_bytes = self.read_bytes.saturating_add(count);
        Ok(count)
    }
}

fn write_response(stream: &mut UnixStream, response: &HttpResponse) -> Result<(), &'static str> {
    let bytes = response.to_http_bytes();
    if bytes.len() > RESPONSE_LIMIT {
        return Err("ADMIN_WEB_RESPONSE_LIMIT");
    }
    let deadline = Instant::now() + IO_LIMIT;
    let mut rest = bytes.as_slice();
    while !rest.is_empty() {
        let remaining = deadline
            .checked_duration_since(Instant::now())
            .filter(|remaining| !remaining.is_zero())
            .ok_or("ADMIN_WEB_WRITE_TIMEOUT")?;
        stream
            .set_write_timeout(Some(remaining))
            .map_err(|_| "ADMIN_WEB_WRITE_SETUP_REFUSED")?;
        match stream.write(rest) {
            Ok(0) => return Err("ADMIN_WEB_WRITE_CLOSED"),
            Ok(count) => rest = &rest[count..],
            Err(error) if error.kind() == io::ErrorKind::Interrupted => continue,
            Err(_) => return Err("ADMIN_WEB_WRITE_UNAVAILABLE"),
        }
    }
    Ok(())
}

fn bind(path: &Path) -> Result<UnixListener, &'static str> {
    let parent = path.parent().ok_or("ADMIN_WEB_SOCKET_PARENT_REFUSED")?;
    let info = std::fs::symlink_metadata(parent).map_err(|_| "ADMIN_WEB_SOCKET_PARENT_REFUSED")?;
    if !path.is_absolute()
        || parent
            .canonicalize()
            .map_err(|_| "ADMIN_WEB_SOCKET_PARENT_REFUSED")?
            != parent
        || !info.is_dir()
        || info.uid() != crate::openbsd::effective_uid()
        || !matches!(info.mode() & 0o7777, 0o700 | 0o750)
    {
        return Err("ADMIN_WEB_SOCKET_PARENT_REFUSED");
    }
    match std::fs::symlink_metadata(path) {
        Err(error) if error.kind() == io::ErrorKind::NotFound => {}
        _ => return Err("ADMIN_WEB_SOCKET_ALREADY_PRESENT"),
    }
    let listener = UnixListener::bind(path).map_err(|_| "ADMIN_WEB_BIND_REFUSED")?;
    std::fs::set_permissions(path, std::fs::Permissions::from_mode(0o600))
        .map_err(|_| "ADMIN_WEB_SOCKET_MODE_REFUSED")?;
    listener
        .set_nonblocking(true)
        .map_err(|_| "ADMIN_WEB_ACCEPT_SETUP_REFUSED")?;
    Ok(listener)
}

/// Serve one bounded request at a time behind the private TLS proxy.
pub(crate) fn run(config: &WebConfig) -> Result<(), &'static str> {
    let client = Client::new(config.service_socket.clone(), config.service_uid)
        .map_err(|_| "ADMIN_WEB_SERVICE_CUSTODY_REFUSED")?;
    let listener = bind(&config.socket)?;
    let signals = crate::openbsd::AccountAdmissionSignals::install()
        .map_err(|_| "ADMIN_WEB_SIGNAL_SETUP_REFUSED")?;
    crate::openbsd::seal_admin_web(&config.socket, &config.service_socket)
        .map_err(|_| "ADMIN_WEB_CONFINEMENT_REFUSED")?;
    let policy = policy(config);
    while !signals.stop_flag().load(Ordering::SeqCst) {
        match listener.accept() {
            Ok((mut stream, _)) => {
                if crate::openbsd::unix_stream_peer_uid(&stream)
                    .ok()
                    .filter(|uid| *uid == config.proxy_uid)
                    .is_none()
                {
                    eprintln!("ADMIN_WEB_PROXY_PEER_REFUSED");
                    continue;
                }
                if stream.set_nonblocking(false).is_err() {
                    eprintln!("ADMIN_WEB_REQUEST_SETUP_REFUSED");
                    continue;
                }
                let mut reader = DeadlineReader {
                    stream: &mut stream,
                    deadline: Instant::now() + IO_LIMIT,
                    read_bytes: 0,
                };
                let response = match read_http_request(&mut reader, &policy) {
                    Ok(request) => handle(config, &request, &client),
                    Err(error) => {
                        let code = match error.kind {
                            HttpRequestErrorKind::Parse => "ADMIN_WEB_REQUEST_PARSE_REFUSED",
                            HttpRequestErrorKind::Timeout => "ADMIN_WEB_REQUEST_TIMEOUT",
                            HttpRequestErrorKind::Truncated => "ADMIN_WEB_REQUEST_TRUNCATED",
                            HttpRequestErrorKind::Empty => "ADMIN_WEB_REQUEST_EMPTY",
                        };
                        eprintln!("{code} read_bytes={}", reader.read_bytes);
                        crate::admin_ui::error_page(400)
                    }
                };
                if let Err(code) = write_response(&mut stream, &response) {
                    eprintln!("{code}");
                }
            }
            Err(error) if error.kind() == io::ErrorKind::WouldBlock => {
                std::thread::sleep(Duration::from_millis(25));
            }
            Err(error) if error.kind() == io::ErrorKind::Interrupted => continue,
            Err(_) => return Err("ADMIN_WEB_ACCEPT_UNAVAILABLE"),
        }
    }
    // Root's exact-owned disposition removes this socket after durable evidence
    // readback. The process never unlinks an existing or replaced namespace.
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::cell::RefCell;

    struct Fake {
        response: RefCell<Option<Response>>,
        calls: RefCell<Vec<Request>>,
    }
    impl Fake {
        fn new(response: Response) -> Self {
            Self {
                response: RefCell::new(Some(response)),
                calls: RefCell::new(Vec::new()),
            }
        }
    }
    impl Exchange for Fake {
        fn exchange(&self, request: &Request) -> Result<Response, Error> {
            let copy = serde_json::from_slice(&serde_json::to_vec(request).unwrap()).unwrap();
            self.calls.borrow_mut().push(copy);
            self.response.borrow_mut().take().ok_or(Error::Unavailable)
        }
    }
    fn config() -> WebConfig {
        WebConfig {
            socket: "/tmp/admin-web-test.sock".into(),
            proxy_uid: crate::openbsd::effective_uid(),
            service_socket: "/tmp/admin-service-test.sock".into(),
            service_uid: crate::openbsd::effective_uid(),
            origin: "https://admin.example.test".into(),
            host: "admin.example.test".into(),
        }
    }
    fn token() -> String {
        format!("osmap-admin1.{}", "a".repeat(64))
    }
    fn overview_model() -> crate::admin_access::DomainOverview {
        crate::admin_access::DomainOverview {
            login: "operator@example.test".into(),
            csrf: "c".repeat(64),
            system: true,
            query: String::new(),
            page: 1,
            total: 0,
            domain_total: 0,
            mailbox_total: 0,
            forward_total: 0,
            rows: vec![],
            preferences: Default::default(),
        }
    }

    #[test]
    fn menu_cookie_never_changes_the_approved_login_presentation() {
        let fake = Fake::new(Response::Unavailable);
        let response = handle(
            &config(),
            &parse(
                "GET",
                "/admin/login",
                &format!("Cookie: {APPEARANCE_COOKIE}=system.comfortable.medium.icons\r\n"),
                "",
            ),
            &fake,
        );
        assert_eq!(response.status_code, 200);
        let body = std::str::from_utf8(&response.body).unwrap();
        assert!(body.contains("Private Administration"));
        assert!(!body
            .split_once("<head>")
            .unwrap()
            .0
            .contains("data-presentation-style="));
        assert!(!body.contains("Presentation style"));
        assert!(fake.calls.borrow().is_empty());
    }

    #[test]
    fn settings_save_uses_admin_fields_cookie_and_shared_appearance_only() {
        let preferences = crate::admin_access::AdminPreferences {
            theme: "dark".into(),
            density: "compact".into(),
            font_size: "large".into(),
            presentation_style: "icons".into(),
        };
        let fake = Fake::new(Response::Settings {
            page: crate::admin_access::SettingsPage {
                login: "operator@example.test".into(),
                csrf: "c".repeat(64),
                system: true,
                preferences,
            },
        });
        let headers=format!("Origin: https://admin.example.test\r\nContent-Type: application/x-www-form-urlencoded\r\nCookie: {SESSION_COOKIE}={}; osmap_appearance=light\r\n",token());
        let response = handle(
            &config(),
            &parse(
                "POST",
                "/admin/settings/appearance",
                &headers,
                &format!(
                    "csrf={}&theme=dark&density=compact&font_size=large&presentation_style=icons",
                    "c".repeat(64)
                ),
            ),
            &fake,
        );
        assert_eq!(response.status_code, 200);
        let text = std::str::from_utf8(&response.body).unwrap();
        assert!(text.contains("Appearance saved."));
        assert!(text.contains("data-appearance=\"dark\""));
        assert!(text.contains("data-density=\"compact\""));
        assert!(text.contains("data-presentation-style=\"icons\""));
        assert!(text.contains("Presentation style"));
        assert!(response
            .headers
            .iter()
            .any(|(key, value)| key == "Set-Cookie" && value.starts_with(APPEARANCE_COOKIE)));
        assert!(!response
            .headers
            .iter()
            .any(|(key, value)| key == "Set-Cookie" && value.starts_with("osmap_")));
        assert!(
            matches!(&fake.calls.borrow()[0].operation,Operation::SavePreferences {preferences,..} if preferences.theme=="dark")
        );
    }
    fn parse(method: &str, path: &str, headers: &str, body: &str) -> HttpRequest {
        let request = format!("{method} {path} HTTP/1.1\r\nHost: admin.example.test\r\nX-Real-IP: 192.0.2.10\r\n{headers}Content-Length: {}\r\n\r\n{body}", body.len());
        crate::http_parse::parse_http_request(&request, &policy(&config())).unwrap()
    }
    fn login_request() -> HttpRequest {
        parse(
            "POST",
            "/admin/login",
            &format!("Origin: https://admin.example.test\r\nContent-Type: application/x-www-form-urlencoded\r\nCookie: {LOGIN_COOKIE}={}\r\n", "b".repeat(64)),
            &format!("login=operator%40example.test&password=public-synthetic-password&totp=123456&csrf={}", "b".repeat(64)),
        )
    }
    fn header<'a>(response: &'a HttpResponse, name: &str) -> Option<&'a str> {
        response
            .headers
            .iter()
            .find(|(key, _)| key == name)
            .map(|(_, value)| value.as_str())
    }

    fn inventory_page() -> crate::admin_access::MailboxPage {
        use sha2::{Digest, Sha256};
        crate::admin_access::MailboxPage {
            login: "operator@example.test".into(),
            csrf: "b".repeat(64),
            domain: "example.test".into(),
            query: "".into(),
            sort: "address".into(),
            page: 1,
            total: 1,
            rows: vec![crate::admin_access::MailboxView {
                id: format!("{:x}", Sha256::digest(b"alice@example.test")),
                username: "alice@example.test".into(),
                quota: 2048,
                active: true,
                smtp_active: false,
            }],
        }
    }

    fn creation_page() -> crate::admin_access::CreatePage {
        crate::admin_access::CreatePage {
            login: "operator@example.test".into(),
            csrf: "c".repeat(64),
            domain: "example.test".into(),
            revision: 7,
            request_id: "b".repeat(64),
        }
    }

    fn creation_receipt() -> crate::admin_access::CreateReceipt {
        crate::admin_access::CreateReceipt {
            login: "operator@example.test".into(),
            csrf: "c".repeat(64),
            domain: "example.test".into(),
            username: "alice@example.test".into(),
            request_id: "b".repeat(64),
            quota: 2 * 1_048_576,
        }
    }

    fn creation_body(password: &str) -> String {
        format!("domain=example.test&local_part=ALICE&display_name=Public%20Alice&password={}&confirmation={}&totp=123456&csrf={}&request_id={}&quota_mib=2&revision=7",
            crate::http_support::url_encode(password),crate::http_support::url_encode(password),"c".repeat(64),"b".repeat(64))
    }

    fn creation_headers() -> String {
        format!("Origin: https://admin.example.test\r\nContent-Type: application/x-www-form-urlencoded\r\nCookie: {SESSION_COOKIE}={}\r\n",token())
    }

    #[test]
    fn create_form_route_precedes_opaque_detail_and_reports_disabled_writer() {
        let fake = Fake::new(Response::CreateMailboxForm {
            page: creation_page(),
        });
        let request = parse(
            "GET",
            "/admin/mailboxes/new?domain=example.test",
            &creation_headers(),
            "",
        );
        let response = handle(&config(), &request, &fake);
        assert_eq!(response.status_code, 200);
        assert!(
            matches!(&fake.calls.borrow()[0].operation,Operation::CreateMailboxForm {domain,..} if domain=="example.test")
        );
        assert!(String::from_utf8(response.body)
            .unwrap()
            .contains("action=\"/admin/mailboxes/new\""));
        let disabled = Fake::new(Response::CreateMailboxFailed {
            reason: crate::admin_access::CreateFailure::WriterDisabled,
        });
        let response = handle(&config(), &request, &disabled);
        assert_eq!(response.status_code, 503);
        let html = String::from_utf8(response.body).unwrap();
        assert!(html.contains("administration writer is disabled"));
        assert!(!html.contains("<form"));
    }

    #[test]
    fn create_post_preserves_private_unicode_proof_and_correlates_receipt() {
        let password = "🦀".repeat(128);
        let body = creation_body(&password);
        assert!(body.len() > 2048);
        let request = parse("POST", "/admin/mailboxes/new", &creation_headers(), &body);
        let fake = Fake::new(Response::MailboxCreated {
            receipt: creation_receipt(),
        });
        let response = handle(&config(), &request, &fake);
        assert_eq!(response.status_code, 201);
        assert!(
            matches!(&fake.calls.borrow()[0].operation,Operation::CreateMailbox {request,..}
            if request.password==password && request.confirmation==password && request.local_part=="ALICE"
            && request.csrf=="c".repeat(64) && request.request_id=="b".repeat(64) && request.revision==7 && request.quota_mib==2)
        );
        let html = String::from_utf8(response.body).unwrap();
        assert!(html.contains("alice@example.test"));
        assert!(html.contains("have not yet been verified"));
        assert!(!html.contains(&password));
        assert!(!html.contains("123456"));
        assert!(!html.contains(&token()));
    }

    #[test]
    fn create_post_refuses_field_ambiguity_origin_and_public_cookie_before_rpc() {
        let body = creation_body("public-mailbox-password");
        for case in [
            "extra",
            "duplicate",
            "quota_overflow",
            "stale_shape",
            "query",
            "origin",
            "public_cookie",
        ] {
            let fake = Fake::new(Response::Denied);
            let mut request = parse("POST", "/admin/mailboxes/new", &creation_headers(), &body);
            match case {
                "extra" => request.body.extend_from_slice(b"&role=system"),
                "duplicate" => request.body.extend_from_slice(b"&csrf=forged"),
                "quota_overflow" => {
                    request.body = body
                        .replace("quota_mib=2", "quota_mib=4294967296")
                        .into_bytes()
                }
                "stale_shape" => {
                    request.body = body.replace("revision=7", "revision=0").into_bytes()
                }
                "query" => {
                    request
                        .query_params
                        .insert("domain".into(), "foreign.test".into());
                }
                "origin" => {
                    request.headers.insert("origin".into(), "null".into());
                }
                _ => {
                    request
                        .headers
                        .insert("cookie".into(), format!("osmap_session={}", "a".repeat(64)));
                }
            }
            let response = handle(&config(), &request, &fake);
            assert!(matches!(response.status_code, 303 | 400 | 403));
            assert!(fake.calls.borrow().is_empty());
        }
    }

    #[test]
    fn create_lost_or_mismatched_receipt_stays_unconfirmed_without_retry() {
        let request = parse(
            "POST",
            "/admin/mailboxes/new",
            &creation_headers(),
            &creation_body("public-mailbox-password"),
        );
        let mut wrong = creation_receipt();
        wrong.request_id = "d".repeat(64);
        for response in [
            Response::Unavailable,
            Response::MailboxCreated { receipt: wrong },
        ] {
            let fake = Fake::new(response);
            let response = handle(&config(), &request, &fake);
            assert_eq!(response.status_code, 503);
            assert_eq!(fake.calls.borrow().len(), 1);
            let html = String::from_utf8(response.body).unwrap();
            assert!(html.contains("Do not retry or resubmit this operation."));
            assert!(html.contains(&"b".repeat(64)));
            assert!(!html.contains("<form"));
            assert!(!html.contains("public-mailbox-password"));
            assert!(!html.contains("/admin/mailboxes/new"));
        }
        let fake = Fake::new(Response::CreateMailboxFailed {
            reason: crate::admin_access::CreateFailure::StepUp,
        });
        assert_eq!(handle(&config(), &request, &fake).status_code, 403);
        assert_eq!(fake.calls.borrow().len(), 1);
    }

    #[test]
    fn authorized_inventory_and_opaque_detail_render_only_public_projection() {
        let page = inventory_page();
        let id = page.rows[0].id.clone();
        let fake = Fake::new(Response::Mailboxes { page });
        let headers = format!("Cookie: {SESSION_COOKIE}={}\r\n", token());
        let result = handle(
            &config(),
            &parse("GET", "/admin/mailboxes?domain=example.test", &headers, ""),
            &fake,
        );
        assert_eq!(result.status_code, 200);
        let html = String::from_utf8(result.body).unwrap();
        assert!(html.contains("alice@example.test"));
        assert!(html.contains(&format!("/admin/mailboxes/{id}?domain=")));
        assert!(!html.contains("maildir"));
        assert!(!html.contains("password"));
        assert!(matches!(
            &fake.calls.borrow()[0].operation,
            Operation::Mailboxes { page: 1, .. }
        ));
        let row = inventory_page().rows.remove(0);
        let fake = Fake::new(Response::Mailbox {
            login: "operator@example.test".into(),
            csrf: "b".repeat(64),
            domain: "example.test".into(),
            mailbox: row,
        });
        let result = handle(
            &config(),
            &parse(
                "GET",
                &format!("/admin/mailboxes/{id}?domain=example.test"),
                &headers,
                "",
            ),
            &fake,
        );
        assert_eq!(result.status_code, 200);
        assert!(String::from_utf8(result.body)
            .unwrap()
            .contains("Not verified"));
    }

    #[test]
    fn inventory_inputs_and_writes_refuse_before_rpc() {
        let headers = format!(
            "Origin: https://admin.example.test\r\nCookie: {SESSION_COOKIE}={}\r\n",
            token()
        );
        for path in [
            "/admin/mailboxes?domain=example.test&role=system",
            "/admin/mailboxes?domain=example.test&page=0",
            "/admin/mailboxes?domain=example.test&page=11",
            "/admin/mailboxes?domain=example.test&sort=sql",
            "/admin/mailboxes/short?domain=example.test",
        ] {
            let fake = Fake::new(Response::Unavailable);
            assert_eq!(
                handle(&config(), &parse("GET", path, &headers, ""), &fake).status_code,
                400
            );
            assert!(fake.calls.borrow().is_empty());
        }
        let fake = Fake::new(Response::Unavailable);
        assert_eq!(
            handle(
                &config(),
                &parse("POST", "/admin/mailboxes?domain=example.test", &headers, ""),
                &fake
            )
            .status_code,
            405
        );
        assert!(fake.calls.borrow().is_empty());
        let raw = format!("GET /admin/mailboxes?domain=example.test&%64omain=foreign.test HTTP/1.1\r\nHost: admin.example.test\r\nCookie: {SESSION_COOKIE}={}\r\n\r\n", token());
        assert!(crate::http_parse::parse_http_request(&raw, &policy(&config())).is_err());
    }

    #[test]
    fn empty_unavailable_capacity_and_foreign_missing_are_truthful() {
        let headers = format!("Cookie: {SESSION_COOKIE}={}\r\n", token());
        let request = parse("GET", "/admin/mailboxes?domain=example.test", &headers, "");
        let mut page = inventory_page();
        page.rows.clear();
        page.total = 0;
        let empty = handle(
            &config(),
            &request,
            &Fake::new(Response::Mailboxes { page }),
        );
        assert_eq!(empty.status_code, 200);
        assert!(String::from_utf8(empty.body)
            .unwrap()
            .contains("No mailboxes are configured"));
        let unavailable = handle(&config(), &request, &Fake::new(Response::Unavailable));
        assert_eq!(unavailable.status_code, 503);
        assert!(!String::from_utf8(unavailable.body)
            .unwrap()
            .contains("No mailboxes"));
        let capacity = handle(&config(), &request, &Fake::new(Response::Capacity));
        assert_eq!(capacity.status_code, 503);
        assert!(String::from_utf8(capacity.body)
            .unwrap()
            .contains("No partial list"));
        let missing = handle(&config(), &request, &Fake::new(Response::Missing));
        let foreign = handle(
            &config(),
            &parse("GET", "/admin/mailboxes?domain=foreign.test", &headers, ""),
            &Fake::new(Response::Missing),
        );
        assert_eq!(
            (missing.status_code, missing.body),
            (foreign.status_code, foreign.body)
        );
        let mut page = inventory_page();
        page.rows.clear();
        page.total = 0;
        page.query = "\"><script>".into();
        let escaped = handle(
            &config(),
            &parse(
                "GET",
                "/admin/mailboxes?domain=example.test&q=%22%3E%3Cscript%3E",
                &headers,
                "",
            ),
            &Fake::new(Response::Mailboxes { page }),
        );
        assert_eq!(escaped.status_code, 200);
        let html = String::from_utf8(escaped.body).unwrap();
        assert!(html.contains("&quot;&gt;&lt;script&gt;"));
        assert!(!html.contains("<script>"));
    }

    #[test]
    fn login_cookie_is_secure_and_csrf_bounded_without_creating_authority() {
        let fake = Fake::new(Response::Denied);
        let request = parse("GET", "/admin/login", "", "");
        let response = handle(&config(), &request, &fake);
        assert_eq!(response.status_code, 200);
        let cookie = header(&response, "Set-Cookie").unwrap();
        let csrf = cookie
            .strip_prefix(&format!("{LOGIN_COOKIE}="))
            .unwrap()
            .split(';')
            .next()
            .unwrap();
        assert!(hex64(csrf));
        assert!(cookie.contains("; Secure"));
        assert!(cookie.contains("; HttpOnly"));
        assert!(cookie.contains("; SameSite=Strict"));
        assert!(cookie.contains("; Path=/"));
        assert!(!cookie.contains("Domain="));
        assert!(fake.calls.borrow().is_empty());
    }

    #[test]
    fn successful_login_relays_only_fixed_proof_and_returns_token_only_in_cookie() {
        let fake = Fake::new(Response::SignedIn { token: token() });
        let response = handle(&config(), &login_request(), &fake);
        assert_eq!(response.status_code, 303);
        assert_eq!(header(&response, "Location"), Some("/admin"));
        assert_eq!(header(&response, "Referrer-Policy"), Some("same-origin"));
        assert!(header(&response, "Set-Cookie")
            .unwrap()
            .starts_with(&format!("{SESSION_COOKIE}=osmap-admin1.")));
        assert!(response.body.is_empty());
        let calls = fake.calls.borrow();
        assert_eq!(calls.len(), 1);
        assert!(calls[0].client == "192.0.2.10");
        assert!(
            matches!(&calls[0].operation, Operation::Login {login, password, totp} if login=="operator@example.test" && password=="public-synthetic-password" && totp=="123456")
        );
    }

    #[test]
    fn canonical_landing_passes_real_parser_and_trailing_slash_refuses() {
        let fake = Fake::new(Response::Overview {
            page: overview_model(),
        });
        let request = parse(
            "GET",
            "/admin",
            &format!("Cookie: {SESSION_COOKIE}={}\r\n", token()),
            "",
        );
        assert_eq!(handle(&config(), &request, &fake).status_code, 200);
        assert_eq!(fake.calls.borrow().len(), 1);
        assert!(matches!(
            &fake.calls.borrow()[0].operation,
            Operation::Overview { .. }
        ));

        let trailing =
            "GET /admin/ HTTP/1.1\r\nHost: admin.example.test\r\nX-Real-IP: 192.0.2.10\r\n\r\n";
        assert!(matches!(
            crate::http_parse::parse_http_request(trailing, &policy(&config())),
            Err(error) if error.kind == HttpRequestErrorKind::Parse
        ));
        assert_eq!(fake.calls.borrow().len(), 1);
    }

    #[test]
    fn foreign_host_origin_and_csrf_refuse_before_service_dispatch() {
        for kind in [
            "host",
            "origin",
            "null_origin",
            "missing_origin",
            "csrf",
            "duplicate_cookie",
            "field",
        ] {
            let fake = Fake::new(Response::Denied);
            let mut request = login_request();
            match kind {
                "host" => {
                    request
                        .headers
                        .insert("host".into(), "foreign.example.test".into());
                }
                "origin" => {
                    request
                        .headers
                        .insert("origin".into(), "https://foreign.example.test".into());
                }
                "null_origin" => {
                    request.headers.insert("origin".into(), "null".into());
                }
                "missing_origin" => {
                    request.headers.remove("origin");
                }
                "csrf" => request.body.extend_from_slice(b"x"),
                "duplicate_cookie" => {
                    request.headers.insert(
                        "cookie".into(),
                        format!(
                            "{LOGIN_COOKIE}={}; {LOGIN_COOKIE}={}",
                            "b".repeat(64),
                            "b".repeat(64)
                        ),
                    );
                }
                _ => request.body.extend_from_slice(b"&role=system"),
            }
            let response = handle(&config(), &request, &fake);
            assert!(matches!(response.status_code, 400 | 403));
            assert!(fake.calls.borrow().is_empty());
        }
    }

    #[test]
    fn forwarded_headers_do_not_change_the_authenticated_proxy_source() {
        let fake = Fake::new(Response::Denied);
        let mut request = login_request();
        request
            .headers
            .insert("x-forwarded-for".into(), "198.51.100.44".into());
        request.headers.insert(
            "forwarded".into(),
            "for=198.51.100.44;host=foreign.example.test".into(),
        );
        let response = handle(&config(), &request, &fake);
        assert_eq!(response.status_code, 401);
        assert!(fake.calls.borrow()[0].client == "192.0.2.10");
        let missing = Fake::new(Response::Denied);
        request.headers.remove("x-real-ip");
        assert_eq!(handle(&config(), &request, &missing).status_code, 403);
        assert!(missing.calls.borrow().is_empty());
    }

    #[test]
    fn public_cookie_cannot_reach_admin_scope_and_unavailable_service_keeps_session() {
        let fake = Fake::new(Response::Overview {
            page: overview_model(),
        });
        let public = parse(
            "GET",
            "/admin",
            &format!("Cookie: osmap_session={}\r\n", "d".repeat(64)),
            "",
        );
        let response = handle(&config(), &public, &fake);
        assert_eq!(response.status_code, 303);
        assert!(fake.calls.borrow().is_empty());
        let request = parse(
            "GET",
            "/admin",
            &format!("Cookie: {SESSION_COOKIE}={}\r\n", token()),
            "",
        );
        let response = handle(&config(), &request, &fake);
        assert_eq!(response.status_code, 200);
        assert!(!std::str::from_utf8(&response.body)
            .unwrap()
            .contains(&token()));
        let unavailable = Fake::new(Response::Unavailable);
        let response = handle(&config(), &request, &unavailable);
        assert_eq!(response.status_code, 503);
        assert!(header(&response, "Set-Cookie").is_none());
    }

    #[test]
    fn logout_requires_service_csrf_and_no_get_mutates_state() {
        let fake = Fake::new(Response::SignedOut);
        let get = parse("GET", "/admin/logout", "", "");
        assert_eq!(handle(&config(), &get, &fake).status_code, 405);
        assert!(fake.calls.borrow().is_empty());
        let post = parse("POST", "/admin/logout", &format!("Origin: https://admin.example.test\r\nContent-Type: application/x-www-form-urlencoded\r\nCookie: {SESSION_COOKIE}={}\r\n", token()), &format!("csrf={}", "c".repeat(64)));
        let response = handle(&config(), &post, &fake);
        assert_eq!(response.status_code, 303);
        assert!(
            matches!(&fake.calls.borrow()[0].operation, Operation::Logout {token: sent,csrf} if sent==&token() && csrf==&"c".repeat(64))
        );
        for cookie in [SESSION_COOKIE, LOGIN_COOKIE, APPEARANCE_COOKIE] {
            assert!(response
                .headers
                .iter()
                .any(|(name, value)| name == "Set-Cookie"
                    && value.starts_with(&format!("{cookie}="))
                    && value.contains("Max-Age=0")));
        }
        assert!(!response
            .headers
            .iter()
            .any(|(name, value)| name == "Set-Cookie" && value.starts_with("osmap_")));
    }

    #[test]
    fn expired_read_deadline_does_not_wait_for_more_bytes() {
        let (mut reader, _writer) = UnixStream::pair().unwrap();
        let mut bounded = DeadlineReader {
            stream: &mut reader,
            deadline: Instant::now() - Duration::from_secs(1),
            read_bytes: 0,
        };
        let mut byte = [0_u8; 1];
        assert!(
            matches!(bounded.read(&mut byte), Err(error) if error.kind()==io::ErrorKind::TimedOut)
        );
    }
}
