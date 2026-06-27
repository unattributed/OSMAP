use std::time::Duration;

pub const OPENPGP_HELPER_PROTOCOL_ARG: &str = "--protocol-only";
pub const MAX_HELPER_REQUEST_BYTES: usize = 4096;
pub const MAX_HELPER_STDOUT_BYTES: usize = 8192;
pub const MAX_HELPER_STDERR_BYTES: usize = 2048;
pub const DEFAULT_HELPER_TIMEOUT: Duration = Duration::from_secs(5);

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum OpenPgpHelperOperation {
    CapabilityStatus,
    DiagnosticPing,
    PolicyCheck,
}

impl OpenPgpHelperOperation {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::CapabilityStatus => "capability_status",
            Self::DiagnosticPing => "diagnostic_ping",
            Self::PolicyCheck => "policy_check",
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct OpenPgpHelperRequest {
    operation: OpenPgpHelperOperation,
    account: Option<String>,
}

impl OpenPgpHelperRequest {
    pub fn new(operation: OpenPgpHelperOperation) -> Self {
        Self {
            operation,
            account: None,
        }
    }

    pub fn with_account(
        operation: OpenPgpHelperOperation,
        account: &str,
    ) -> Result<Self, OpenPgpHelperClientError> {
        validate_bounded_text(account, 254)?;
        Ok(Self {
            operation,
            account: Some(account.to_string()),
        })
    }

    pub fn to_stdin_json(&self) -> Result<String, OpenPgpHelperClientError> {
        let json = match &self.account {
            Some(account) => format!(
                "{{\"schema\":\"osmap-openpgp-helper-request-v1\",\"operation\":\"{}\",\"account\":\"{}\"}}",
                self.operation.as_str(),
                json_escape(account)
            ),
            None => format!(
                "{{\"schema\":\"osmap-openpgp-helper-request-v1\",\"operation\":\"{}\"}}",
                self.operation.as_str()
            ),
        };
        if json.len() > MAX_HELPER_REQUEST_BYTES {
            return Err(OpenPgpHelperClientError::OversizedRequest);
        }
        Ok(json)
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct OpenPgpHelperInvocationPlan {
    pub program: String,
    pub args: Vec<String>,
    pub stdin_json: String,
    pub timeout: Duration,
    pub max_stdout_bytes: usize,
    pub max_stderr_bytes: usize,
}

impl OpenPgpHelperInvocationPlan {
    pub fn build(
        helper_path: &str,
        request: OpenPgpHelperRequest,
    ) -> Result<Self, OpenPgpHelperClientError> {
        validate_helper_path(helper_path)?;
        let stdin_json = request.to_stdin_json()?;
        Ok(Self {
            program: helper_path.to_string(),
            args: vec![OPENPGP_HELPER_PROTOCOL_ARG.to_string()],
            stdin_json,
            timeout: DEFAULT_HELPER_TIMEOUT,
            max_stdout_bytes: MAX_HELPER_STDOUT_BYTES,
            max_stderr_bytes: MAX_HELPER_STDERR_BYTES,
        })
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum OpenPgpHelperClientError {
    InvalidHelperPath,
    InvalidTextField,
    OversizedRequest,
    OversizedStdout,
    OversizedStderr,
    HelperExitNonZero,
    MalformedHelperJson,
}

pub fn classify_helper_result(
    exit_status: i32,
    stdout: &[u8],
    stderr: &[u8],
) -> Result<(), OpenPgpHelperClientError> {
    if stdout.len() > MAX_HELPER_STDOUT_BYTES {
        return Err(OpenPgpHelperClientError::OversizedStdout);
    }
    if stderr.len() > MAX_HELPER_STDERR_BYTES {
        return Err(OpenPgpHelperClientError::OversizedStderr);
    }
    if exit_status != 0 {
        return Err(OpenPgpHelperClientError::HelperExitNonZero);
    }
    let text =
        std::str::from_utf8(stdout).map_err(|_| OpenPgpHelperClientError::MalformedHelperJson)?;
    let trimmed = text.trim();
    if !(trimmed.starts_with('{')
        && trimmed.ends_with('}')
        && trimmed.contains("\"schema\"")
        && trimmed.contains("\"ok\":true"))
    {
        return Err(OpenPgpHelperClientError::MalformedHelperJson);
    }
    Ok(())
}

fn validate_helper_path(helper_path: &str) -> Result<(), OpenPgpHelperClientError> {
    if helper_path.is_empty()
        || !helper_path.starts_with('/')
        || helper_path
            .bytes()
            .any(|byte| !is_safe_helper_path_byte(byte))
    {
        return Err(OpenPgpHelperClientError::InvalidHelperPath);
    }
    Ok(())
}

fn is_safe_helper_path_byte(byte: u8) -> bool {
    byte.is_ascii_alphanumeric() || matches!(byte, b'/' | b'.' | b'_' | b'-')
}

fn validate_bounded_text(value: &str, max_len: usize) -> Result<(), OpenPgpHelperClientError> {
    if value.is_empty() || value.len() > max_len || value.chars().any(|c| c.is_control()) {
        return Err(OpenPgpHelperClientError::InvalidTextField);
    }
    Ok(())
}

fn json_escape(value: &str) -> String {
    let mut escaped = String::with_capacity(value.len());
    for c in value.chars() {
        match c {
            '"' => escaped.push_str("\\\""),
            '\\' => escaped.push_str("\\\\"),
            _ => escaped.push(c),
        }
    }
    escaped
}
