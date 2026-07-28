use std::env;
use std::io::{self, Read};
use std::process;

use osmap::http::{parse_http_request_bytes, HttpPolicy};
use serde_json::{json, Value};

fn emit(value: &Value) -> Result<(), String> {
    let encoded = serde_json::to_string(value)
        .map_err(|error| format!("failed encoding parser result: {error}"))?;
    println!("{encoded}");
    Ok(())
}

fn run() -> Result<(), String> {
    let authority = env::args()
        .nth(1)
        .filter(|value| !value.is_empty())
        .unwrap_or_else(|| "localhost".to_string());

    let mut input = Vec::new();
    io::stdin()
        .read_to_end(&mut input)
        .map_err(|error| format!("failed reading raw request bytes: {error}"))?;

    let policy = HttpPolicy {
        allowed_hosts: vec![
            authority.clone(),
            format!("{authority}:8080"),
            "localhost".to_string(),
            "localhost:8080".to_string(),
            "127.0.0.1".to_string(),
            "127.0.0.1:8080".to_string(),
        ],
        ..HttpPolicy::default()
    };

    let result = match parse_http_request_bytes(&input, &policy) {
        Ok(request) => json!({
            "accepted": true,
            "method": request.method.as_str(),
            "path": request.path,
            "host": request.headers.get("host").cloned(),
            "header_count": request.headers.len(),
            "header_names": request.headers.keys().cloned().collect::<Vec<_>>(),
            "body_length": request.body.len(),
            "query_field_count": request.query_params.len(),
            "error_kind": Value::Null,
            "reason": Value::Null,
        }),
        Err(error) => json!({
            "accepted": false,
            "method": Value::Null,
            "path": Value::Null,
            "host": Value::Null,
            "header_count": Value::Null,
            "header_names": Vec::<String>::new(),
            "body_length": Value::Null,
            "query_field_count": Value::Null,
            "error_kind": format!("{:?}", error.kind),
            "reason": error.reason,
        }),
    };

    emit(&result)
}

fn main() {
    if let Err(error) = run() {
        eprintln!("{error}");
        process::exit(1);
    }
}
