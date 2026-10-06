//! Dedicated Documents transport. Ordinary mailbox response budgets are unchanged.
use super::*;
use crate::documents::{Backend, Error, Location, QuotaStatus, MAX_FILE_BYTES};
#[cfg(test)]
use crate::documents_doveadm::reserved_documents_mailbox as reserved_mailbox;
use hmac::{Hmac, Mac};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};

const PREFIX: &[u8] = b"documents-v1\n";
const BASE64_BYTES: usize = MAX_FILE_BYTES.div_ceil(3) * 4;
/// Exact base64 expansion plus finite metadata/framing allowance (no MIME on wire).
pub const MAX_DOCUMENTS_WIRE_BYTES: usize = BASE64_BYTES + 8192;

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "action", rename_all = "snake_case", deny_unknown_fields)]
enum Operation {
    Quota,
    Inspect {
        id: String,
    },
    Append {
        id: String,
        name: String,
        media_type: String,
        body_b64: String,
        size: usize,
        sha256: String,
    },
    Read {
        id: String,
        location: Location,
    },
    Bin {
        id: String,
        location: Location,
    },
    Restore {
        id: String,
        location: Location,
    },
    Expunge {
        id: String,
        location: Location,
    },
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct Payload {
    account: String,
    operation: Operation,
    issued_at: u64,
    expires_at: u64,
    nonce: String,
}
#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct Request {
    payload: Payload,
    signature: String,
}
#[derive(Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "result", rename_all = "snake_case", deny_unknown_fields)]
enum Outcome {
    Done,
    Quota {
        quota: Option<QuotaStatus>,
    },
    Locations {
        locations: Vec<Location>,
    },
    Location {
        location: Location,
    },
    Body {
        body_b64: String,
        size: usize,
        sha256: String,
    },
    Failure {
        kind: Failure,
    },
}
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
enum Failure {
    Invalid,
    NotFound,
    Stale,
    Limit,
    Busy,
    Unavailable,
    PreDispatchUnavailable,
    ConfirmedNoWrite,
    Unconfirmed,
}
#[derive(Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct Response {
    request_hash: String,
    nonce: String,
    outcome: Outcome,
}

fn hex(bytes: &[u8]) -> String {
    bytes.iter().map(|byte| format!("{byte:02x}")).collect()
}
fn hash(bytes: &[u8]) -> String {
    hex(&Sha256::digest(bytes))
}
fn valid_hex(value: &str, length: usize) -> bool {
    value.len() == length
        && value
            .bytes()
            .all(|byte| matches!(byte, b'0'..=b'9' | b'a'..=b'f'))
}
fn validate_location(location: &Location, expected: &str) -> Result<(), Error> {
    if location.mailbox != expected
        || location.uid == 0
        || !valid_hex(&location.mailbox_guid, 32)
        || !valid_hex(&location.message_guid, 32)
    {
        return Err(Error::Invalid);
    }
    Ok(())
}
fn validate_locations(locations: &[Location]) -> Result<(), Error> {
    if locations.len() > 2 {
        return Err(Error::Invalid);
    }
    let mut mailboxes = std::collections::BTreeSet::new();
    for location in locations {
        if !matches!(
            location.mailbox.as_str(),
            "OSMAP.Documents" | "OSMAP.DocumentsBin"
        ) || !mailboxes.insert(&location.mailbox)
        {
            return Err(Error::Invalid);
        }
        validate_location(location, &location.mailbox)?;
    }
    Ok(())
}
fn encode_body(body: &[u8]) -> String {
    mailbox_helper_protocol::encode_base64(body)
}
fn decode_body(body: &str, size: usize, sha256: &str) -> Result<Vec<u8>, Error> {
    if size == 0
        || size > MAX_FILE_BYTES
        || body.len() != size.div_ceil(3) * 4
        || !valid_hex(sha256, 64)
    {
        return Err(Error::Invalid);
    }
    let bytes =
        crate::attachment::decode_base64_bytes(body, MAX_FILE_BYTES).map_err(|_| Error::Invalid)?;
    if bytes.len() != size || hash(&bytes) != sha256 || encode_body(&bytes) != body {
        return Err(Error::Invalid);
    }
    Ok(bytes)
}
fn validate(payload: &Payload) -> Result<(), Error> {
    let canonical =
        crate::identity::CanonicalUsername::parse(&payload.account).map_err(|_| Error::Invalid)?;
    if canonical.as_str() != payload.account
        || !valid_hex(&payload.nonce, 32)
        || payload.expires_at.checked_sub(payload.issued_at) != Some(60)
    {
        return Err(Error::Invalid);
    }
    match &payload.operation {
        Operation::Quota => Ok(()),
        Operation::Inspect { id } => {
            if valid_hex(id, 32) {
                Ok(())
            } else {
                Err(Error::Invalid)
            }
        }
        Operation::Append {
            id,
            name,
            media_type,
            body_b64,
            size,
            sha256,
        } => {
            if !valid_hex(id, 32)
                || name.is_empty()
                || name.len() > crate::documents::MAX_NAME_BYTES
                || matches!(name.as_str(), "." | "..")
                || name
                    .chars()
                    .any(|c| c.is_control() || matches!(c, '/' | '\\'))
                || media_type.len() > 100
                || !media_type.contains('/')
                || !media_type.bytes().all(
                    |byte| matches!(byte, b'a'..=b'z' | b'0'..=b'9' | b'/' | b'-' | b'+' | b'.'),
                )
            {
                return Err(Error::Invalid);
            }
            if *size == 0
                || *size > MAX_FILE_BYTES
                || body_b64.len() != size.div_ceil(3) * 4
                || !valid_hex(sha256, 64)
            {
                return Err(Error::Invalid);
            }
            Ok(())
        }
        Operation::Read { id, location } => {
            if !valid_hex(id, 32)
                || !matches!(
                    location.mailbox.as_str(),
                    "OSMAP.Documents" | "OSMAP.DocumentsBin"
                )
            {
                return Err(Error::Invalid);
            }
            validate_location(location, &location.mailbox)
        }
        Operation::Bin { id, location } => {
            if !valid_hex(id, 32) {
                return Err(Error::Invalid);
            }
            validate_location(location, "OSMAP.Documents")
        }
        Operation::Restore { id, location } | Operation::Expunge { id, location } => {
            if !valid_hex(id, 32) {
                return Err(Error::Invalid);
            }
            validate_location(location, "OSMAP.DocumentsBin")
        }
    }
}
fn grant_bytes(payload: &Payload) -> Result<Vec<u8>, Error> {
    // The grant binds the exact decoded content digest and byte count. Body
    // bytes are validated against that digest once, after grant verification,
    // avoiding repeated 14 MiB JSON encoding and content decoding.
    let mut metadata = payload.clone();
    if let Operation::Append { body_b64, .. } = &mut metadata.operation {
        body_b64.clear();
    }
    serde_json::to_vec(&metadata).map_err(|_| Error::Invalid)
}
fn mac(payload: &Payload, key: &[u8]) -> Result<Hmac<Sha256>, Error> {
    if key.len() < 32 {
        return Err(Error::Unavailable);
    }
    let bytes = grant_bytes(payload)?;
    let mut mac = Hmac::<Sha256>::new_from_slice(key).map_err(|_| Error::Unavailable)?;
    mac.update(PREFIX);
    mac.update(&bytes);
    Ok(mac)
}
fn parse(bytes: &[u8]) -> Result<Request, Error> {
    if bytes.len() > MAX_DOCUMENTS_WIRE_BYTES {
        return Err(Error::Invalid);
    }
    let json = bytes.strip_prefix(PREFIX).ok_or(Error::Invalid)?;
    let request: Request = serde_json::from_slice(json).map_err(|_| Error::Invalid)?;
    if !matches!(request.payload.operation, Operation::Append { .. }) && bytes.len() > 8192 {
        return Err(Error::Invalid);
    }
    validate(&request.payload)?;
    Ok(request)
}
fn verify(
    request: &Request,
    key: &[u8],
    now: u64,
    replay: &Mutex<BTreeMap<String, u64>>,
) -> Result<(), Error> {
    validate(&request.payload)?;
    if now < request.payload.issued_at
        || now > request.payload.expires_at
        || !valid_hex(&request.signature, 64)
    {
        return Err(Error::Invalid);
    }
    let signature: Vec<u8> = request
        .signature
        .as_bytes()
        .chunks_exact(2)
        .map(|chunk| {
            u8::from_str_radix(std::str::from_utf8(chunk).unwrap_or(""), 16)
                .map_err(|_| Error::Invalid)
        })
        .collect::<Result<_, _>>()?;
    mac(&request.payload, key)?
        .verify_slice(&signature)
        .map_err(|_| Error::Invalid)?;
    let mut cache = replay.lock().map_err(|_| Error::Unavailable)?;
    cache.retain(|_, expiry| *expiry >= now);
    if cache.contains_key(&request.signature) || cache.len() >= 4096 {
        return Err(Error::Invalid);
    }
    cache.insert(request.signature.clone(), request.payload.expires_at);
    Ok(())
}
fn failure(error: Error) -> Outcome {
    Outcome::Failure {
        kind: match error {
            Error::Invalid => Failure::Invalid,
            Error::NotFound => Failure::NotFound,
            Error::Stale => Failure::Stale,
            Error::Limit => Failure::Limit,
            Error::Busy => Failure::Busy,
            Error::Unavailable => Failure::Unavailable,
            Error::PreDispatchUnavailable => Failure::PreDispatchUnavailable,
            Error::ConfirmedNoWrite => Failure::ConfirmedNoWrite,
            Error::Unconfirmed => Failure::Unconfirmed,
        },
    }
}
fn error(kind: Failure) -> Error {
    match kind {
        Failure::Invalid => Error::Invalid,
        Failure::NotFound => Error::NotFound,
        Failure::Stale => Error::Stale,
        Failure::Limit => Error::Limit,
        Failure::Busy => Error::Busy,
        Failure::Unavailable => Error::Unavailable,
        Failure::PreDispatchUnavailable => Error::PreDispatchUnavailable,
        Failure::ConfirmedNoWrite => Error::ConfirmedNoWrite,
        Failure::Unconfirmed => Error::Unconfirmed,
    }
}
fn dispatch(backend: &dyn Backend, payload: &Payload) -> Result<Outcome, Error> {
    let account = &payload.account;
    match &payload.operation {
        Operation::Quota => backend.quota_status(account).and_then(|quota| {
            if quota.as_ref().is_some_and(|quota| quota.limit_bytes == 0) {
                return Err(Error::Unavailable);
            }
            Ok(Outcome::Quota { quota })
        }),
        Operation::Inspect { id } => {
            let locations = backend.inspect(account, id)?;
            validate_locations(&locations).map_err(|_| Error::Unavailable)?;
            Ok(Outcome::Locations { locations })
        }
        Operation::Append {
            id,
            name,
            media_type,
            body_b64,
            size,
            sha256,
        } => {
            let bytes = decode_body(body_b64, *size, sha256)?;
            let location = backend.append(account, id, name, media_type, &bytes)?;
            validate_location(&location, "OSMAP.Documents").map_err(|_| Error::Unconfirmed)?;
            Ok(Outcome::Location { location })
        }
        Operation::Read { id, location } => {
            let bytes = backend.read(account, id, location)?;
            if bytes.is_empty() || bytes.len() > MAX_FILE_BYTES {
                return Err(Error::Unavailable);
            }
            Ok(Outcome::Body {
                body_b64: encode_body(&bytes),
                size: bytes.len(),
                sha256: hash(&bytes),
            })
        }
        Operation::Bin { id, location } => {
            let location = backend.move_to_bin(account, id, location)?;
            validate_location(&location, "OSMAP.DocumentsBin").map_err(|_| Error::Unconfirmed)?;
            Ok(Outcome::Location { location })
        }
        Operation::Restore { id, location } => {
            let location = backend.restore(account, id, location)?;
            validate_location(&location, "OSMAP.Documents").map_err(|_| Error::Unconfirmed)?;
            Ok(Outcome::Location { location })
        }
        Operation::Expunge { id, location } => {
            backend.expunge(account, id, location)?;
            Ok(Outcome::Done)
        }
    }
}

#[cfg(unix)]
pub(super) fn read_request_bytes(
    stream: &mut UnixStream,
    policy: MailboxHelperPolicy,
) -> Result<Vec<u8>, String> {
    let deadline = mailbox_helper_client::helper_request_deadline(policy);
    let mut bytes = Vec::new();
    let mut chunk = [0u8; 4096];
    // Determine the dedicated operation before allocating its body. Ordinary
    // requests retain their established per-read budget and request cap.
    while bytes.len() < PREFIX.len() {
        let remaining = deadline
            .checked_duration_since(std::time::Instant::now())
            .filter(|remaining| !remaining.is_zero())
            .ok_or("helper request deadline expired")?;
        stream
            .set_read_timeout(Some(remaining))
            .map_err(|_| "helper read timeout unavailable")?;
        let read = stream
            .read(&mut chunk)
            .map_err(|_| "helper request read failed")?;
        if read == 0 {
            return Ok(bytes);
        }
        if read > policy.max_request_bytes.saturating_sub(bytes.len()) {
            return Err("helper request exceeded byte limit".into());
        }
        bytes.extend_from_slice(&chunk[..read]);
    }
    if !bytes.starts_with(PREFIX) {
        configure_stream_timeouts(stream, policy);
        let remainder =
            read_bounded_from_stream(stream, policy.max_request_bytes.saturating_sub(bytes.len()))?;
        bytes.extend_from_slice(&remainder);
        return Ok(bytes);
    }
    let limit = policy.max_request_bytes.min(MAX_DOCUMENTS_WIRE_BYTES);
    loop {
        let remaining = deadline
            .checked_duration_since(std::time::Instant::now())
            .filter(|remaining| !remaining.is_zero())
            .ok_or("Documents request deadline expired")?;
        stream
            .set_read_timeout(Some(remaining))
            .map_err(|_| "helper read timeout unavailable")?;
        let read = stream
            .read(&mut chunk)
            .map_err(|_| "Documents request read failed")?;
        if read == 0 {
            return Ok(bytes);
        }
        if read > limit.saturating_sub(bytes.len()) {
            return Err("Documents request exceeded byte limit".into());
        }
        bytes.extend_from_slice(&chunk[..read]);
    }
}

#[cfg(unix)]
pub(super) fn handle(
    bytes: &[u8],
    backend: Option<&dyn Backend>,
    stream: &mut UnixStream,
    key: &[u8],
    replay: &Mutex<BTreeMap<String, u64>>,
) -> bool {
    if !bytes.starts_with(PREFIX) {
        return false;
    }
    // Bad envelopes have no reflected body or request details.
    let response = match parse(bytes) {
        Ok(request) => {
            let outcome = current_unix_time_secs()
                .map_err(|_| Error::Unavailable)
                .and_then(|now| verify(&request, key, now, replay))
                .and_then(|()| backend.ok_or(Error::Unavailable))
                .and_then(|backend| dispatch(backend, &request.payload))
                .unwrap_or_else(failure);
            Response {
                request_hash: hash(&grant_bytes(&request.payload).unwrap_or_default()),
                nonce: request.payload.nonce,
                outcome,
            }
        }
        Err(error) => Response {
            request_hash: String::new(),
            nonce: String::new(),
            outcome: failure(error),
        },
    };
    if let Ok(bytes) = serde_json::to_vec(&response) {
        if bytes.len() <= MAX_DOCUMENTS_WIRE_BYTES {
            let deadline = std::time::Instant::now()
                + Duration::from_secs(DEFAULT_MAILBOX_HELPER_WRITE_TIMEOUT_SECS);
            let mut remainder = bytes.as_slice();
            while !remainder.is_empty() {
                let Some(remaining) = deadline
                    .checked_duration_since(std::time::Instant::now())
                    .filter(|remaining| !remaining.is_zero())
                else {
                    break;
                };
                if stream.set_write_timeout(Some(remaining)).is_err() {
                    break;
                }
                match stream.write(remainder) {
                    Ok(0) => break,
                    Ok(written) => remainder = &remainder[written..],
                    Err(error) if error.kind() == std::io::ErrorKind::Interrupted => continue,
                    Err(_) => break,
                }
            }
        }
    }
    let _ = stream.shutdown(Shutdown::Write);
    true
}

#[derive(Clone, Debug)]
pub struct MailboxHelperDocumentsBackend {
    socket: PathBuf,
    key: PathBuf,
    policy: MailboxHelperPolicy,
    peer: Option<u32>,
}
impl MailboxHelperDocumentsBackend {
    pub fn new(
        socket: impl Into<PathBuf>,
        key: impl Into<PathBuf>,
        policy: MailboxHelperPolicy,
    ) -> Self {
        Self {
            socket: socket.into(),
            key: key.into(),
            policy,
            peer: None,
        }
    }
    pub fn with_helper_uid(mut self, uid: u32) -> Self {
        self.peer = Some(uid);
        self
    }
    fn exchange(&self, account: &str, operation: Operation) -> Result<Outcome, Error> {
        #[cfg(not(unix))]
        {
            let _ = (account, operation);
            Err(Error::Unavailable)
        }
        #[cfg(unix)]
        {
            let deadline = mailbox_helper_client::helper_request_deadline(self.policy);
            let peer = self.peer.ok_or(Error::Unavailable)?;
            let key = load_helper_grant_key(&self.key).map_err(|_| Error::Unavailable)?;
            let now = current_unix_time_secs().map_err(|_| Error::Unavailable)?;
            let response_limit = if matches!(operation, Operation::Read { .. }) {
                MAX_DOCUMENTS_WIRE_BYTES
            } else {
                8192
            };
            let request_limit = if matches!(operation, Operation::Append { .. }) {
                MAX_DOCUMENTS_WIRE_BYTES
            } else {
                8192
            };
            let payload = Payload {
                account: account.into(),
                operation,
                issued_at: now,
                expires_at: now.checked_add(60).ok_or(Error::Unavailable)?,
                nonce: crate::draft::generate_draft_id().map_err(|_| Error::Unavailable)?,
            };
            validate(&payload)?;
            let request_hash = hash(&grant_bytes(&payload)?);
            let nonce = payload.nonce.clone();
            let signature = hex(&mac(&payload, &key)?.finalize().into_bytes());
            let mut bytes = PREFIX.to_vec();
            bytes.extend(
                serde_json::to_vec(&Request { payload, signature })
                    .map_err(|_| Error::Unavailable)?,
            );
            let policy = MailboxHelperPolicy {
                max_request_bytes: self.policy.max_request_bytes.min(request_limit),
                max_response_bytes: response_limit,
                ..self.policy
            };
            let bytes = mailbox_helper_client::helper_exchange_before_with_peer(
                &self.socket,
                &bytes,
                policy,
                deadline,
                Some(peer),
            )
            .map_err(|_| Error::Unavailable)?;
            let response: Response =
                serde_json::from_slice(&bytes).map_err(|_| Error::Unavailable)?;
            if response.request_hash != request_hash || response.nonce != nonce {
                return Err(Error::Unavailable);
            }
            match response.outcome {
                Outcome::Failure { kind } => Err(error(kind)),
                outcome => Ok(outcome),
            }
        }
    }
    fn location(
        &self,
        account: &str,
        operation: Operation,
        mailbox: &str,
    ) -> Result<Location, Error> {
        match self.exchange(account, operation)? {
            Outcome::Location { location } => {
                validate_location(&location, mailbox).map_err(|_| Error::Unconfirmed)?;
                Ok(location)
            }
            _ => Err(Error::Unconfirmed),
        }
    }
}
impl Backend for MailboxHelperDocumentsBackend {
    fn quota_ready(&self, account: &str) -> Result<bool, Error> {
        self.quota_status(account).map(|quota| quota.is_some())
    }
    fn quota_status(&self, account: &str) -> Result<Option<QuotaStatus>, Error> {
        match self.exchange(account, Operation::Quota)? {
            Outcome::Quota { quota }
                if quota.as_ref().is_none_or(|quota| quota.limit_bytes > 0) =>
            {
                Ok(quota)
            }
            _ => Err(Error::Unavailable),
        }
    }
    fn inspect(&self, account: &str, id: &str) -> Result<Vec<Location>, Error> {
        match self.exchange(account, Operation::Inspect { id: id.into() })? {
            Outcome::Locations { locations } => {
                validate_locations(&locations).map_err(|_| Error::Unavailable)?;
                Ok(locations)
            }
            _ => Err(Error::Unavailable),
        }
    }
    fn append(
        &self,
        account: &str,
        id: &str,
        name: &str,
        media_type: &str,
        body: &[u8],
    ) -> Result<Location, Error> {
        if body.is_empty() || body.len() > MAX_FILE_BYTES {
            return Err(Error::Invalid);
        }
        self.location(
            account,
            Operation::Append {
                id: id.into(),
                name: name.into(),
                media_type: media_type.into(),
                body_b64: encode_body(body),
                size: body.len(),
                sha256: hash(body),
            },
            "OSMAP.Documents",
        )
    }
    fn read(&self, account: &str, id: &str, location: &Location) -> Result<Vec<u8>, Error> {
        match self.exchange(
            account,
            Operation::Read {
                id: id.into(),
                location: location.clone(),
            },
        )? {
            Outcome::Body {
                body_b64,
                size,
                sha256,
            } => decode_body(&body_b64, size, &sha256).map_err(|_| Error::Unavailable),
            _ => Err(Error::Unavailable),
        }
    }
    fn move_to_bin(&self, account: &str, id: &str, location: &Location) -> Result<Location, Error> {
        self.location(
            account,
            Operation::Bin {
                id: id.into(),
                location: location.clone(),
            },
            "OSMAP.DocumentsBin",
        )
    }
    fn restore(&self, account: &str, id: &str, location: &Location) -> Result<Location, Error> {
        self.location(
            account,
            Operation::Restore {
                id: id.into(),
                location: location.clone(),
            },
            "OSMAP.Documents",
        )
    }
    fn expunge(&self, account: &str, id: &str, location: &Location) -> Result<(), Error> {
        match self.exchange(
            account,
            Operation::Expunge {
                id: id.into(),
                location: location.clone(),
            },
        )? {
            Outcome::Done => Ok(()),
            _ => Err(Error::Unconfirmed),
        }
    }
}

#[cfg(all(test, unix))]
#[path = "mailbox_helper_documents_tests.rs"]
mod tests;
