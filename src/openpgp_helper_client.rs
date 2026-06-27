use serde::{Deserialize, Serialize};
use std::time::Duration;

pub const OPENPGP_HELPER_PATH: &str = "/usr/local/libexec/osmap/osmap-openpgp-helper";
pub const OPENPGP_HELPER_PROTOCOL_ARG: &str = "--protocol-only";
pub const OPENPGP_HELPER_REQUEST_SCHEMA: &str = "osmap-openpgp-helper-request-v1";
pub const OPENPGP_HELPER_RESPONSE_SCHEMA: &str = "osmap-openpgp-helper-response-v1";
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

#[derive(Debug, Serialize)]
#[serde(deny_unknown_fields)]
struct OpenPgpHelperWireRequest<'a> {
    schema: &'static str,
    operation: &'static str,
    #[serde(skip_serializing_if = "Option::is_none")]
    account_fingerprint: Option<&'a str>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct OpenPgpHelperRequest {
    operation: OpenPgpHelperOperation,
    account_fingerprint: Option<String>,
}

impl OpenPgpHelperRequest {
    pub fn new(operation: OpenPgpHelperOperation) -> Self {
        Self {
            operation,
            account_fingerprint: None,
        }
    }

    pub fn with_account_fingerprint(
        operation: OpenPgpHelperOperation,
        account_fingerprint: &str,
    ) -> Result<Self, OpenPgpHelperClientError> {
        if operation != OpenPgpHelperOperation::PolicyCheck {
            return Err(OpenPgpHelperClientError::UnexpectedAccountFingerprint);
        }
        let account_fingerprint = normalize_full_fingerprint(account_fingerprint)?;
        Ok(Self {
            operation,
            account_fingerprint: Some(account_fingerprint),
        })
    }

    pub fn to_stdin_json(&self) -> Result<String, OpenPgpHelperClientError> {
        if self.operation == OpenPgpHelperOperation::PolicyCheck
            && self.account_fingerprint.is_none()
        {
            return Err(OpenPgpHelperClientError::MissingAccountFingerprint);
        }
        let request = OpenPgpHelperWireRequest {
            schema: OPENPGP_HELPER_REQUEST_SCHEMA,
            operation: self.operation.as_str(),
            account_fingerprint: self.account_fingerprint.as_deref(),
        };
        let json = serde_json::to_string(&request)
            .map_err(|_| OpenPgpHelperClientError::RequestSerializationFailed)?;
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
    pub fn build(request: OpenPgpHelperRequest) -> Result<Self, OpenPgpHelperClientError> {
        let stdin_json = request.to_stdin_json()?;
        Ok(Self {
            program: OPENPGP_HELPER_PATH.to_string(),
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
    InvalidAccountFingerprint,
    MissingAccountFingerprint,
    UnexpectedAccountFingerprint,
    RequestSerializationFailed,
    OversizedRequest,
    OversizedStdout,
    OversizedStderr,
    UnexpectedStderr,
    HelperExitNonZero,
    MalformedHelperJson,
    UnexpectedHelperSchema,
    UnexpectedHelperOperation,
    RuntimeCryptoEnabled,
    HelperRejectedRequest,
    InvalidOperationResult,
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct OpenPgpHelperWireResponse {
    schema: String,
    ok: bool,
    operation: String,
    runtime_crypto_enabled: bool,
    #[serde(default)]
    response: Option<String>,
    #[serde(default)]
    helper_protocol: Option<String>,
    #[serde(default)]
    supported_operations: Option<Vec<String>>,
    #[serde(default)]
    gpgme_required_for_future_crypto: Option<bool>,
    #[serde(default)]
    account_binding_present: Option<bool>,
    #[serde(default)]
    policy_decision: Option<String>,
}

pub fn classify_helper_result(
    expected_operation: OpenPgpHelperOperation,
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
    if !stderr.is_empty() {
        return Err(OpenPgpHelperClientError::UnexpectedStderr);
    }
    if exit_status != 0 {
        return Err(OpenPgpHelperClientError::HelperExitNonZero);
    }
    let response: OpenPgpHelperWireResponse = serde_json::from_slice(stdout)
        .map_err(|_| OpenPgpHelperClientError::MalformedHelperJson)?;
    if response.schema != OPENPGP_HELPER_RESPONSE_SCHEMA {
        return Err(OpenPgpHelperClientError::UnexpectedHelperSchema);
    }
    if response.operation != expected_operation.as_str() {
        return Err(OpenPgpHelperClientError::UnexpectedHelperOperation);
    }
    if response.runtime_crypto_enabled {
        return Err(OpenPgpHelperClientError::RuntimeCryptoEnabled);
    }
    if !response.ok {
        return Err(OpenPgpHelperClientError::HelperRejectedRequest);
    }
    let valid_operation_result = match expected_operation {
        OpenPgpHelperOperation::DiagnosticPing => {
            response.response.as_deref() == Some("pong")
                && response.helper_protocol.is_none()
                && response.supported_operations.is_none()
                && response.gpgme_required_for_future_crypto.is_none()
                && response.account_binding_present.is_none()
                && response.policy_decision.is_none()
        }
        OpenPgpHelperOperation::CapabilityStatus => {
            response.response.is_none()
                && response.helper_protocol.as_deref()
                    == Some("osmap-v12-openpgp-helper-protocol-only-v1")
                && response.supported_operations.as_deref()
                    == Some(&[
                        "capability_status".to_string(),
                        "diagnostic_ping".to_string(),
                        "policy_check".to_string(),
                    ])
                && response.gpgme_required_for_future_crypto == Some(true)
                && response.account_binding_present.is_none()
                && response.policy_decision.is_none()
        }
        OpenPgpHelperOperation::PolicyCheck => {
            response.response.is_none()
                && response.helper_protocol.is_none()
                && response.supported_operations.is_none()
                && response.gpgme_required_for_future_crypto.is_none()
                && response.account_binding_present == Some(true)
                && response.policy_decision.as_deref() == Some("runtime_crypto_disabled")
        }
    };
    if !valid_operation_result {
        return Err(OpenPgpHelperClientError::InvalidOperationResult);
    }
    Ok(())
}

fn normalize_full_fingerprint(value: &str) -> Result<String, OpenPgpHelperClientError> {
    if !matches!(value.len(), 40 | 64) || !value.bytes().all(|byte| byte.is_ascii_hexdigit()) {
        return Err(OpenPgpHelperClientError::InvalidAccountFingerprint);
    }
    Ok(value.to_ascii_uppercase())
}

#[cfg(test)]
mod tests {
    use super::*;

    fn response(operation: OpenPgpHelperOperation) -> Vec<u8> {
        match operation {
            OpenPgpHelperOperation::DiagnosticPing => br#"{"schema":"osmap-openpgp-helper-response-v1","ok":true,"operation":"diagnostic_ping","runtime_crypto_enabled":false,"response":"pong"}"#.to_vec(),
            OpenPgpHelperOperation::CapabilityStatus => br#"{"schema":"osmap-openpgp-helper-response-v1","ok":true,"operation":"capability_status","runtime_crypto_enabled":false,"helper_protocol":"osmap-v12-openpgp-helper-protocol-only-v1","supported_operations":["capability_status","diagnostic_ping","policy_check"],"gpgme_required_for_future_crypto":true}"#.to_vec(),
            OpenPgpHelperOperation::PolicyCheck => br#"{"schema":"osmap-openpgp-helper-response-v1","ok":true,"operation":"policy_check","runtime_crypto_enabled":false,"account_binding_present":true,"policy_decision":"runtime_crypto_disabled"}"#.to_vec(),
        }
    }

    #[test]
    fn request_and_invocation_plan_use_exact_protocol_contract() {
        let request = OpenPgpHelperRequest::new(OpenPgpHelperOperation::DiagnosticPing);
        let plan = OpenPgpHelperInvocationPlan::build(request).expect("plan");
        assert_eq!(plan.program, OPENPGP_HELPER_PATH);
        assert_eq!(plan.args, [OPENPGP_HELPER_PROTOCOL_ARG]);
        assert_eq!(
            plan.stdin_json,
            r#"{"schema":"osmap-openpgp-helper-request-v1","operation":"diagnostic_ping"}"#
        );
        assert_eq!(plan.timeout, DEFAULT_HELPER_TIMEOUT);
    }

    #[test]
    fn policy_request_requires_and_normalizes_full_fingerprint() {
        let error = OpenPgpHelperRequest::new(OpenPgpHelperOperation::PolicyCheck)
            .to_stdin_json()
            .expect_err("missing fingerprint must fail");
        assert_eq!(error, OpenPgpHelperClientError::MissingAccountFingerprint);

        for invalid in ["", "ABCDEF", &"G".repeat(40), &"A".repeat(41)] {
            assert_eq!(
                OpenPgpHelperRequest::with_account_fingerprint(
                    OpenPgpHelperOperation::PolicyCheck,
                    invalid,
                ),
                Err(OpenPgpHelperClientError::InvalidAccountFingerprint)
            );
        }

        let request = OpenPgpHelperRequest::with_account_fingerprint(
            OpenPgpHelperOperation::PolicyCheck,
            &"a".repeat(40),
        )
        .expect("valid fingerprint");
        assert!(request
            .to_stdin_json()
            .expect("json")
            .contains(&"A".repeat(40)));
        assert_eq!(
            OpenPgpHelperRequest::with_account_fingerprint(
                OpenPgpHelperOperation::DiagnosticPing,
                &"A".repeat(40),
            ),
            Err(OpenPgpHelperClientError::UnexpectedAccountFingerprint)
        );
    }

    #[test]
    fn valid_operation_responses_are_accepted() {
        for operation in [
            OpenPgpHelperOperation::DiagnosticPing,
            OpenPgpHelperOperation::CapabilityStatus,
            OpenPgpHelperOperation::PolicyCheck,
        ] {
            assert_eq!(
                classify_helper_result(operation, 0, &response(operation), b""),
                Ok(())
            );
        }
    }

    #[test]
    fn malformed_or_ambiguous_responses_fail_closed() {
        let operation = OpenPgpHelperOperation::DiagnosticPing;
        for malformed in [
            br#"{"schema":"wrong","ok":true,"operation":"diagnostic_ping","runtime_crypto_enabled":false,"response":"pong"}"#.as_slice(),
            br#"{"schema":"osmap-openpgp-helper-response-v1","ok":true,"operation":"policy_check","runtime_crypto_enabled":false,"response":"pong"}"#.as_slice(),
            br#"{"schema":"osmap-openpgp-helper-response-v1","ok":true,"operation":"diagnostic_ping","runtime_crypto_enabled":true,"response":"pong"}"#.as_slice(),
            br#"{"schema":"osmap-openpgp-helper-response-v1","ok":true,"ok":false,"operation":"diagnostic_ping","runtime_crypto_enabled":false,"response":"pong"}"#.as_slice(),
            br#"{"schema":"osmap-openpgp-helper-response-v1","ok":false,"operation":"diagnostic_ping","runtime_crypto_enabled":false,"response":"\"ok\":true"}"#.as_slice(),
            br#"{"schema":"osmap-openpgp-helper-response-v1","ok":true,"operation":"diagnostic_ping","runtime_crypto_enabled":false,"response":"pong","unknown":true}"#.as_slice(),
        ] {
            assert!(classify_helper_result(operation, 0, malformed, b"").is_err());
        }
    }

    #[test]
    fn transport_limits_and_exit_state_fail_closed() {
        let operation = OpenPgpHelperOperation::DiagnosticPing;
        assert_eq!(
            classify_helper_result(operation, 1, &response(operation), b""),
            Err(OpenPgpHelperClientError::HelperExitNonZero)
        );
        assert_eq!(
            classify_helper_result(operation, 0, &response(operation), b"diagnostic"),
            Err(OpenPgpHelperClientError::UnexpectedStderr)
        );
        assert_eq!(
            classify_helper_result(operation, 0, &vec![b'A'; MAX_HELPER_STDOUT_BYTES + 1], b""),
            Err(OpenPgpHelperClientError::OversizedStdout)
        );
        assert_eq!(
            classify_helper_result(
                operation,
                0,
                &response(operation),
                &vec![b'A'; MAX_HELPER_STDERR_BYTES + 1]
            ),
            Err(OpenPgpHelperClientError::OversizedStderr)
        );
    }
}
