//! HTTP parsing and request-shape helpers for the bounded browser runtime.
//!
//! Keeping these parser and request-shape utilities separate from route
//! handling makes the browser boundary easier to audit without changing the
//! current behavior or accepted request surface.

use std::collections::BTreeMap;
use std::io::Read as _;
use std::net::{SocketAddr, TcpStream};

use crate::http::{
    HttpMethod, HttpPolicy, HttpRequest, HttpRequestError, DEFAULT_HTTP_MAX_CONTENT_TYPE_HEADER_BYTES,
    DEFAULT_HTTP_MAX_COOKIE_HEADER_BYTES, DEFAULT_HTTP_MAX_HOST_HEADER_BYTES,
};
use crate::http_form::{is_multipart_form_data, is_urlencoded_form_content_type, parse_query_string};
use crate::send::ComposeIntent;
use crate::session::SessionToken;

/// Normalizes a peer socket address to the bare IP string used in audit
/// context and auth-helper metadata.
pub(crate) fn normalize_peer_addr(addr: SocketAddr) -> String {
    addr.ip().to_string()
}

/// Reads one bounded HTTP request from the supplied stream.
pub(crate) fn read_http_request(
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

/// Parses raw HTTP request bytes into the bounded request shape used by the
/// router.
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
    if headers.contains_key("transfer-encoding") {
        return Err(HttpRequestError {
            reason: "unsupported transfer-encoding header".to_string(),
        });
    }

    let content_length = parse_content_length_from_headers(&headers)?;
    if method == HttpMethod::Post && !headers.contains_key("content-length") {
        return Err(HttpRequestError {
            reason: "post requests must send content-length".to_string(),
        });
    }
    if method == HttpMethod::Get && (content_length != 0 || !body.is_empty()) {
        return Err(HttpRequestError {
            reason: "get requests must not send a request body".to_string(),
        });
    }
    if content_length != body.len() {
        return Err(HttpRequestError {
            reason: "http body length did not match content-length".to_string(),
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

/// Reads the current session cookie from the request if present.
pub(crate) fn session_cookie_value(request: &HttpRequest, cookie_name: &str) -> Option<String> {
    let cookie_header = request.headers.get("cookie")?;
    let mut matched_value = None;
    for cookie in cookie_header.split(';') {
        let trimmed = cookie.trim();
        if let Some((name, value)) = trimmed.split_once('=') {
            if name.trim() == cookie_name {
                let candidate = value.trim();
                if matched_value.is_some() {
                    return None;
                }
                let token = SessionToken::new(candidate.to_string()).ok()?;
                matched_value = Some(token.as_str().to_string());
            }
        }
    }

    matched_value
}

/// Returns true when the route may safely interpret the body as URL-encoded.
pub(crate) fn allows_urlencoded_request_body(content_type: Option<&str>) -> bool {
    match content_type.map(str::trim) {
        None | Some("") => true,
        Some(value) => is_urlencoded_form_content_type(value),
    }
}

/// Builds the current session cookie for successful login responses.
pub(crate) fn build_session_cookie(cookie_name: &str, token: &str, secure: bool) -> String {
    let mut cookie = format!("{cookie_name}={token}; Path=/; HttpOnly; SameSite=Strict");
    if secure {
        cookie.push_str("; Secure");
    }
    cookie
}

/// Builds an expired session cookie used to clear browser session state.
pub(crate) fn clear_session_cookie(cookie_name: &str, secure: bool) -> String {
    let mut cookie = format!("{cookie_name}=; Path=/; HttpOnly; SameSite=Strict; Max-Age=0");
    if secure {
        cookie.push_str("; Secure");
    }
    cookie
}

/// Parses the optional compose source reference from the current request.
pub(crate) fn compose_source_from_request(
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
        validate_known_header_value(&normalized_name, &normalized_value)?;

        headers.insert(normalized_name, normalized_value);
    }

    Ok(headers)
}

/// Applies small per-header constraints for the current browser surface.
fn validate_known_header_value(name: &str, value: &str) -> Result<(), HttpRequestError> {
    match name {
        "host" => validate_host_header_value(value),
        "cookie" => {
            if value.len() > DEFAULT_HTTP_MAX_COOKIE_HEADER_BYTES {
                return Err(HttpRequestError {
                    reason: "cookie header exceeded maximum length".to_string(),
                });
            }
            Ok(())
        }
        "content-type" => {
            if value.len() > DEFAULT_HTTP_MAX_CONTENT_TYPE_HEADER_BYTES {
                return Err(HttpRequestError {
                    reason: "content-type header exceeded maximum length".to_string(),
                });
            }
            Ok(())
        }
        _ => Ok(()),
    }
}

/// Rejects obviously malformed host headers instead of routing through them.
fn validate_host_header_value(value: &str) -> Result<(), HttpRequestError> {
    if value.is_empty() {
        return Err(HttpRequestError {
            reason: "host header must not be empty".to_string(),
        });
    }
    if value.len() > DEFAULT_HTTP_MAX_HOST_HEADER_BYTES {
        return Err(HttpRequestError {
            reason: "host header exceeded maximum length".to_string(),
        });
    }
    if value
        .chars()
        .any(|ch| matches!(ch, '/' | '\\' | '?' | '#' | '@'))
    {
        return Err(HttpRequestError {
            reason: "host header contained unsupported characters".to_string(),
        });
    }

    Ok(())
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
    let normalized_path = normalize_request_path(path)?;

    Ok((
        normalized_path,
        parse_query_string(query, max_query_fields).map_err(|error| HttpRequestError {
            reason: error.reason,
        })?,
    ))
}

/// Rejects ambiguous request-path forms instead of routing aliases.
fn normalize_request_path(path: &str) -> Result<String, HttpRequestError> {
    if path == "/" {
        return Ok(path.to_string());
    }

    for segment in path.split('/').skip(1) {
        if segment.is_empty() {
            return Err(HttpRequestError {
                reason: "request target path must be normalized".to_string(),
            });
        }
        if segment == "." || segment == ".." {
            return Err(HttpRequestError {
                reason: "request target path must not contain dot segments".to_string(),
            });
        }
    }

    Ok(path.to_string())
}
