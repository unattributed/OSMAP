//! Fixed, bounded private admin RPC. Peer UIDs come from the kernel; requests
//! contain neither grants nor executable, SQL, configuration or identity paths.
use crate::admin_access::{AdminPreferences, DomainDetails, DomainOverview, SettingsPage};
use crate::admin_access::{CreateFailure, CreateMailbox, CreatePage, CreateReceipt};
use crate::admin_access::{MailboxPage, MailboxView};
use crate::openpgp_inventory_runtime::{read_frame, validate_socket, write_frame};
use serde::{Deserialize, Serialize};
use std::collections::BTreeSet;
use std::io::Read;
use std::net::{IpAddr, Shutdown};
use std::os::unix::fs::{FileTypeExt, MetadataExt};
use std::os::unix::net::UnixStream;
use std::path::{Path, PathBuf};
use std::time::{Duration, Instant};

pub(crate) const VERSION: u8 = 1;
pub(crate) const MAX_FRAME: usize = 8192;
pub(crate) const TIMEOUT: Duration = Duration::from_secs(20);
const TOKEN_PREFIX: &str = "osmap-admin1.";

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum Error {
    Invalid,
    Unavailable,
    Denied,
}

// Deliberately no Debug: credentials, bearer handles and CSRF values are private.
#[derive(Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct Request {
    pub(crate) version: u8,
    pub(crate) client: String,
    pub(crate) operation: Operation,
}

#[derive(Serialize, Deserialize)]
#[serde(tag = "op", rename_all = "snake_case", deny_unknown_fields)]
pub(crate) enum Operation {
    Login {
        login: String,
        password: String,
        totp: String,
    },
    Scope {
        token: String,
    },
    Overview {
        token: String,
        query: String,
        page: u8,
    },
    DomainDetails {
        token: String,
        id: String,
    },
    Settings {
        token: String,
    },
    SavePreferences {
        token: String,
        csrf: String,
        preferences: AdminPreferences,
    },
    Logout {
        token: String,
        csrf: String,
    },
    Mailboxes {
        token: String,
        domain: String,
        query: String,
        page: u8,
        sort: String,
    },
    Mailbox {
        token: String,
        domain: String,
        id: String,
    },
    CreateMailboxForm {
        token: String,
        domain: String,
    },
    CreateMailbox {
        token: String,
        request: CreateMailbox,
    },
}

#[derive(Serialize)]
#[serde(tag = "status", rename_all = "snake_case", deny_unknown_fields)]
pub(crate) enum Response {
    Overview {
        page: DomainOverview,
    },
    DomainDetails {
        page: DomainDetails,
    },
    Settings {
        page: SettingsPage,
    },
    Mailboxes {
        page: MailboxPage,
    },
    Mailbox {
        login: String,
        csrf: String,
        domain: String,
        mailbox: MailboxView,
    },
    CreateMailboxForm {
        page: CreatePage,
    },
    MailboxCreated {
        receipt: CreateReceipt,
    },
    CreateMailboxFailed {
        reason: CreateFailure,
    },
    Missing,
    Capacity,
    SignedIn {
        token: String,
    },
    SignedOut,
    Scope {
        login: String,
        system: bool,
        domains: Vec<String>,
        csrf: String,
    },
    Denied,
    Invalid,
    Unavailable,
}

// Serde's internally-tagged *unit* visitor ignores remaining fields even with
// deny_unknown_fields. Decode fixed results as empty struct variants instead,
// preserving the caller-facing unit API and rejecting extra wire fields.
#[derive(Deserialize)]
#[serde(tag = "status", rename_all = "snake_case", deny_unknown_fields)]
enum WireResponse {
    Overview {
        page: DomainOverview,
    },
    DomainDetails {
        page: DomainDetails,
    },
    Settings {
        page: SettingsPage,
    },
    Mailboxes {
        page: MailboxPage,
    },
    Mailbox {
        login: String,
        csrf: String,
        domain: String,
        mailbox: MailboxView,
    },
    CreateMailboxForm {
        page: CreatePage,
    },
    MailboxCreated {
        receipt: CreateReceipt,
    },
    CreateMailboxFailed {
        reason: CreateFailure,
    },
    Missing {},
    Capacity {},
    SignedIn {
        token: String,
    },
    SignedOut {},
    Scope {
        login: String,
        system: bool,
        domains: Vec<String>,
        csrf: String,
    },
    Denied {},
    Invalid {},
    Unavailable {},
}

impl<'de> Deserialize<'de> for Response {
    fn deserialize<D: serde::Deserializer<'de>>(deserializer: D) -> Result<Self, D::Error> {
        Ok(match WireResponse::deserialize(deserializer)? {
            WireResponse::Overview { page } => Self::Overview { page },
            WireResponse::DomainDetails { page } => Self::DomainDetails { page },
            WireResponse::Settings { page } => Self::Settings { page },
            WireResponse::CreateMailboxForm { page } => Self::CreateMailboxForm { page },
            WireResponse::MailboxCreated { receipt } => Self::MailboxCreated { receipt },
            WireResponse::CreateMailboxFailed { reason } => Self::CreateMailboxFailed { reason },
            WireResponse::SignedIn { token } => Self::SignedIn { token },
            WireResponse::SignedOut {} => Self::SignedOut,
            WireResponse::Scope {
                login,
                system,
                domains,
                csrf,
            } => Self::Scope {
                login,
                system,
                domains,
                csrf,
            },
            WireResponse::Denied {} => Self::Denied,
            WireResponse::Mailboxes { page } => Self::Mailboxes { page },
            WireResponse::Mailbox {
                login,
                csrf,
                domain,
                mailbox,
            } => Self::Mailbox {
                login,
                csrf,
                domain,
                mailbox,
            },
            WireResponse::Missing {} => Self::Missing,
            WireResponse::Capacity {} => Self::Capacity,
            WireResponse::Invalid {} => Self::Invalid,
            WireResponse::Unavailable {} => Self::Unavailable,
        })
    }
}

fn login_valid(login: &str) -> bool {
    !login.is_empty()
        && login.len() <= 96
        && login
            .bytes()
            .all(|b| b.is_ascii_alphanumeric() || b"@._-".contains(&b))
}

fn hex64(value: &str) -> bool {
    value.len() == 64 && value.bytes().all(|b| b.is_ascii_hexdigit())
}

fn token_valid(token: &str) -> bool {
    token.strip_prefix(TOKEN_PREFIX).is_some_and(hex64)
}

impl Request {
    pub(crate) fn validate(&self) -> Result<(), Error> {
        if self.version != VERSION
            || self.client.len() > 45
            || self.client.parse::<IpAddr>().is_err()
        {
            return Err(Error::Invalid);
        }
        let valid = match &self.operation {
            Operation::Login {
                login,
                password,
                totp,
            } => {
                login_valid(login)
                    && !password.is_empty()
                    && password.len() <= 72
                    && !password.as_bytes().contains(&0)
                    && totp.len() == 6
                    && totp.bytes().all(|b| b.is_ascii_digit())
            }
            Operation::Scope { token } => token_valid(token),
            Operation::Overview { token, query, page } => {
                token_valid(token) && crate::admin_access::pages::overview_options(query, *page)
            }
            Operation::DomainDetails { token, id } => token_valid(token) && hex64(id),
            Operation::Settings { token } => token_valid(token),
            Operation::SavePreferences {
                token,
                csrf,
                preferences,
            } => token_valid(token) && hex64(csrf) && preferences.valid(),
            Operation::Logout { token, csrf } => token_valid(token) && hex64(csrf),
            Operation::Mailboxes {
                token,
                domain,
                query,
                page,
                sort,
            } => {
                token_valid(token)
                    && crate::admin_directory::Scope::domains(&[domain]).is_ok()
                    && crate::admin_access::inventory_options_valid(query, *page, sort)
            }
            Operation::Mailbox { token, domain, id } => {
                token_valid(token)
                    && hex64(id)
                    && crate::admin_directory::Scope::domains(&[domain]).is_ok()
            }
            Operation::CreateMailboxForm { token, domain } => {
                token_valid(token) && crate::admin_directory::Scope::domains(&[domain]).is_ok()
            }
            Operation::CreateMailbox { token, request } => token_valid(token) && request.valid(),
        };
        if valid {
            Ok(())
        } else {
            Err(Error::Invalid)
        }
    }
}

impl Response {
    pub(crate) fn validate(&self) -> Result<(), Error> {
        match self {
            Self::CreateMailboxForm { page } => {
                if page.valid() {
                    Ok(())
                } else {
                    Err(Error::Invalid)
                }
            }
            Self::MailboxCreated { receipt } => {
                if receipt.valid() {
                    Ok(())
                } else {
                    Err(Error::Invalid)
                }
            }
            Self::Overview { page } => {
                if page.valid() {
                    Ok(())
                } else {
                    Err(Error::Invalid)
                }
            }
            Self::DomainDetails { page } => {
                if page.valid() {
                    Ok(())
                } else {
                    Err(Error::Invalid)
                }
            }
            Self::Settings { page } => {
                if page.valid() {
                    Ok(())
                } else {
                    Err(Error::Invalid)
                }
            }
            Self::Mailboxes { page } => {
                if page.valid() {
                    Ok(())
                } else {
                    Err(Error::Invalid)
                }
            }
            Self::Mailbox {
                login,
                csrf,
                domain,
                mailbox,
            } => {
                if login_valid(login)
                    && hex64(csrf)
                    && crate::admin_directory::Scope::domains(&[domain]).is_ok()
                    && mailbox.valid(domain)
                {
                    Ok(())
                } else {
                    Err(Error::Invalid)
                }
            }
            Self::SignedIn { token } if !token_valid(token) => Err(Error::Invalid),
            Self::Scope {
                login,
                system: _,
                domains,
                csrf,
            } => {
                if !login_valid(login)
                    || !hex64(csrf)
                    || domains.len() > 16
                    || domains.iter().collect::<BTreeSet<_>>().len() != domains.len()
                {
                    return Err(Error::Invalid);
                }
                if !domains.is_empty() {
                    crate::admin_directory::Scope::domains(
                        &domains.iter().map(String::as_str).collect::<Vec<_>>(),
                    )
                    .map_err(|_| Error::Invalid)?;
                }
                Ok(())
            }
            _ => Ok(()),
        }
    }
}

#[derive(Clone, Copy, PartialEq, Eq)]
struct ParentIdentity {
    device: u64,
    inode: u64,
    uid: u32,
    gid: u32,
    mode: u32,
}

#[derive(Clone, Copy, PartialEq, Eq)]
struct Identity {
    parent: ParentIdentity,
    socket_device: u64,
    socket_inode: u64,
}

/// Constructor-only ancestry/canonical checks before the Web role is sealed.
fn endpoint_before_seal(path: &Path, service_uid: u32) -> Result<Identity, Error> {
    if !path.is_absolute() || path.as_os_str().len() > 100 {
        return Err(Error::Invalid);
    }
    crate::openpgp_inventory_runtime::custody::exact_path(path, service_uid)
        .map_err(|_| Error::Unavailable)?;
    let identity = endpoint_leaves(path, service_uid)?;
    if identity.parent.uid == service_uid {
        validate_socket(path, service_uid).map_err(|_| Error::Unavailable)?;
    }
    Ok(identity)
}

/// Post-seal checks touch only the narrowly unveiled socket and its parent.
/// Trusted ancestors were admitted before sealing; Web cannot replace them.
fn endpoint_leaves(path: &Path, service_uid: u32) -> Result<Identity, Error> {
    let parent = path.parent().ok_or(Error::Invalid)?;
    let directory = std::fs::symlink_metadata(parent).map_err(|_| Error::Unavailable)?;
    if !directory.is_dir()
        || (directory.uid() != 0 && directory.uid() != service_uid)
        || directory.mode() & 0o022 != 0
    {
        return Err(Error::Unavailable);
    }
    let socket = std::fs::symlink_metadata(path).map_err(|_| Error::Unavailable)?;
    if !socket.file_type().is_socket()
        || socket.uid() != service_uid
        || socket.nlink() != 1
        || !matches!(socket.mode() & 0o7777, 0o600 | 0o660)
    {
        return Err(Error::Unavailable);
    }
    Ok(Identity {
        parent: ParentIdentity {
            device: directory.dev(),
            inode: directory.ino(),
            uid: directory.uid(),
            gid: directory.gid(),
            mode: directory.mode(),
        },
        socket_device: socket.dev(),
        socket_inode: socket.ino(),
    })
}

fn remaining(deadline: Instant) -> Result<Duration, Error> {
    deadline
        .checked_duration_since(Instant::now())
        .filter(|left| !left.is_zero())
        .ok_or(Error::Unavailable)
}

fn frame_error(error: crate::openpgp_inventory::Error) -> Error {
    match error {
        crate::openpgp_inventory::Error::Invalid | crate::openpgp_inventory::Error::Limit => {
            Error::Invalid
        }
        _ => Error::Unavailable,
    }
}

fn terminal_eof(stream: &mut UnixStream, deadline: Instant) -> Result<(), Error> {
    stream
        .set_read_timeout(Some(remaining(deadline)?))
        .map_err(|_| Error::Unavailable)?;
    let mut extra = [0_u8; 1];
    match stream.read(&mut extra) {
        Ok(0) => Ok(()),
        Ok(_) => Err(Error::Invalid),
        Err(_) => Err(Error::Unavailable),
    }
}

#[derive(Clone)]
pub(crate) struct Client {
    socket: PathBuf,
    service_uid: u32,
    parent: ParentIdentity,
}

impl Client {
    /// Paths/UID are protected startup configuration, never request fields.
    pub(crate) fn new(socket: PathBuf, service_uid: u32) -> Result<Self, Error> {
        let identity = endpoint_before_seal(&socket, service_uid)?;
        Ok(Self {
            socket,
            service_uid,
            parent: identity.parent,
        })
    }

    pub(crate) fn exchange(&self, request: &Request) -> Result<Response, Error> {
        request.validate()?;
        let deadline = Instant::now() + TIMEOUT;
        let before = endpoint_leaves(&self.socket, self.service_uid)?;
        if before.parent != self.parent {
            return Err(Error::Unavailable);
        }
        let mut stream = crate::openbsd::connect_unix_before(&self.socket, deadline)
            .map_err(|_| Error::Unavailable)?;
        if crate::openbsd::unix_stream_peer_uid(&stream).map_err(|_| Error::Unavailable)?
            != self.service_uid
        {
            return Err(Error::Denied);
        }
        if endpoint_leaves(&self.socket, self.service_uid)? != before {
            return Err(Error::Unavailable);
        }
        let bytes = serde_json::to_vec(request).map_err(|_| Error::Invalid)?;
        if bytes.len() > MAX_FRAME {
            return Err(Error::Invalid);
        }
        write_frame(&mut stream, &bytes, deadline).map_err(frame_error)?;
        stream
            .shutdown(Shutdown::Write)
            .map_err(|_| Error::Unavailable)?;
        let raw = read_frame(&mut stream, MAX_FRAME, deadline).map_err(frame_error)?;
        terminal_eof(&mut stream, deadline)?;
        let response: Response = serde_json::from_slice(&raw).map_err(|_| Error::Invalid)?;
        response.validate()?;
        Ok(response)
    }
}

/// Authenticate the Web process before consuming any caller-selected bytes.
pub(crate) fn read_request(
    stream: &mut UnixStream,
    expected_web_uid: u32,
    deadline: Instant,
) -> Result<Request, Error> {
    let deadline = deadline.min(Instant::now() + TIMEOUT);
    if crate::openbsd::unix_stream_peer_uid(stream).map_err(|_| Error::Unavailable)?
        != expected_web_uid
    {
        return Err(Error::Denied);
    }
    let raw = read_frame(stream, MAX_FRAME, deadline).map_err(frame_error)?;
    terminal_eof(stream, deadline)?;
    let request: Request = serde_json::from_slice(&raw).map_err(|_| Error::Invalid)?;
    request.validate()?;
    Ok(request)
}

pub(crate) fn write_response(
    stream: &mut UnixStream,
    response: &Response,
    deadline: Instant,
) -> Result<(), Error> {
    let deadline = deadline.min(Instant::now() + TIMEOUT);
    response.validate()?;
    let bytes = serde_json::to_vec(response).map_err(|_| Error::Invalid)?;
    if bytes.len() > MAX_FRAME {
        return Err(Error::Invalid);
    }
    write_frame(stream, &bytes, deadline).map_err(frame_error)?;
    stream
        .shutdown(Shutdown::Write)
        .map_err(|_| Error::Unavailable)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn creation_rpc_roundtrips_private_request_and_rejects_extra_authority_fields() {
        let request = Request {
            version: VERSION,
            client: "127.0.0.1".into(),
            operation: Operation::CreateMailbox {
                token: token(),
                request: CreateMailbox {
                    domain: "example.test".into(),
                    local_part: "alice".into(),
                    display_name: "Public Alice".into(),
                    password: String::new(),
                    confirmation: String::new(),
                    setup_contact: Some("owner@independent.test".into()),
                    totp: "123456".into(),
                    csrf: "c".repeat(64),
                    request_id: "b".repeat(64),
                    quota_mib: 2,
                    revision: 7,
                },
            },
        };
        assert_eq!(request.validate(), Ok(()));
        let bytes = serde_json::to_vec(&request).unwrap();
        assert!(bytes.len() <= MAX_FRAME);
        assert_eq!(
            serde_json::from_slice::<Request>(&bytes)
                .unwrap()
                .validate(),
            Ok(())
        );
        let mut forged = serde_json::to_value(&request).unwrap();
        forged["operation"]["request"]["role"] = serde_json::Value::String("system".into());
        assert!(serde_json::from_value::<Request>(forged).is_err());
        let response = Response::CreateMailboxForm {
            page: CreatePage {
                login: "operator@example.test".into(),
                csrf: "c".repeat(64),
                domain: "example.test".into(),
                revision: 7,
                request_id: "b".repeat(64),
                setup_enabled: true,
            },
        };
        assert_eq!(response.validate(), Ok(()));
        let mut value = serde_json::to_value(&response).unwrap();
        value["page"]["password"] = serde_json::Value::String("public-unexpected-proof".into());
        assert!(serde_json::from_value::<Response>(value).is_err());
        assert!(serde_json::from_str::<Response>(
            r#"{"status":"create_mailbox_failed","reason":"unconfirmed","token":"public-forged"}"#
        )
        .is_err());
    }

    #[test]
    fn maximum_domain_page_fits_existing_frame_and_roundtrips() {
        use crate::admin_access::pages::DomainSummary;
        use sha2::{Digest, Sha256};
        let rows = (0..10)
            .map(|i| {
                let name = format!(
                    "{i}{}.{}.{}.test",
                    "d".repeat(62),
                    "d".repeat(63),
                    "d".repeat(56)
                );
                DomainSummary {
                    id: format!("{:x}", Sha256::digest(name.as_bytes())),
                    name,
                    active: true,
                    mailboxes: u64::MAX / 100,
                    forwards: u64::MAX / 100,
                    created: Some("x".repeat(32)),
                }
            })
            .collect();
        let response = Response::Overview {
            page: DomainOverview {
                login: "a".repeat(96),
                csrf: "a".repeat(64),
                system: true,
                query: "\"".repeat(64),
                page: 1,
                total: 100,
                domain_total: 100,
                preferences: AdminPreferences::default(),
                mailbox_total: u64::MAX,
                forward_total: u64::MAX,
                rows,
            },
        };
        assert_eq!(response.validate(), Ok(()));
        let bytes = serde_json::to_vec(&response).unwrap();
        assert!(bytes.len() <= MAX_FRAME);
        assert_eq!(
            serde_json::from_slice::<Response>(&bytes)
                .unwrap()
                .validate(),
            Ok(())
        );
        let forged = format!(
            r#"{{"version":1,"client":"127.0.0.1","operation":{{"op":"overview","token":"{}","query":"","page":1,"system":true}}}}"#,
            token()
        );
        assert!(serde_json::from_str::<Request>(&forged).is_err());
    }

    #[test]
    fn maximum_mailbox_page_fits_existing_frame_and_roundtrips() {
        use sha2::{Digest, Sha256};
        let domain = format!(
            "{}.{}.{}.test",
            "d".repeat(63),
            "d".repeat(63),
            "d".repeat(56)
        );
        let rows = (0..10)
            .map(|i| {
                let username = format!("{i}{}@{domain}", "\\".repeat(63));
                MailboxView {
                    id: format!("{:x}", Sha256::digest(username.as_bytes())),
                    username,
                    quota: i64::MAX,
                    active: true,
                    smtp_active: true,
                }
            })
            .collect();
        let response = Response::Mailboxes {
            page: MailboxPage {
                login: "a".repeat(96),
                csrf: "a".repeat(64),
                domain,
                query: "\"".repeat(64),
                sort: "address".into(),
                page: 1,
                total: 100,
                rows,
            },
        };
        assert_eq!(response.validate(), Ok(()));
        let bytes = serde_json::to_vec(&response).unwrap();
        assert!(bytes.len() <= MAX_FRAME);
        assert_eq!(
            serde_json::from_slice::<Response>(&bytes)
                .unwrap()
                .validate(),
            Ok(())
        );
        for extra in [
            br#"{"status":"missing","role":"system"}"#.as_slice(),
            br#"{"status":"capacity","sql":"private"}"#,
        ] {
            assert!(serde_json::from_slice::<Response>(extra).is_err());
        }
    }
    use std::io::Write;
    use std::os::unix::fs::{DirBuilderExt, PermissionsExt};
    use std::os::unix::net::UnixListener;
    use std::thread;

    fn login_request() -> Request {
        Request {
            version: VERSION,
            client: "127.0.0.1".into(),
            operation: Operation::Login {
                login: "operator@example.test".into(),
                password: "public-synthetic-password".into(),
                totp: "123456".into(),
            },
        }
    }

    fn token() -> String {
        format!("{TOKEN_PREFIX}{}", "a".repeat(64))
    }

    struct Fixture(PathBuf);
    impl Fixture {
        fn new() -> Self {
            let mut nonce = [0_u8; 12];
            getrandom::getrandom(&mut nonce).unwrap();
            let suffix: String = nonce.iter().map(|n| format!("{n:02x}")).collect();
            let path = std::env::temp_dir()
                .canonicalize()
                .unwrap()
                .join(format!("osmap-admin-rpc-{suffix}"));
            std::fs::DirBuilder::new()
                .mode(0o700)
                .create(&path)
                .unwrap();
            Self(path)
        }

        fn listener(&self) -> UnixListener {
            let path = self.0.join("service.sock");
            let listener = UnixListener::bind(&path).unwrap();
            std::fs::set_permissions(path, std::fs::Permissions::from_mode(0o600)).unwrap();
            listener.set_nonblocking(true).unwrap();
            listener
        }
    }
    impl Drop for Fixture {
        fn drop(&mut self) {
            if thread::panicking() {
                eprintln!("ADMIN_RPC_TEST_FIXTURE_RETAINED root={}", self.0.display());
            } else {
                std::fs::remove_dir_all(&self.0).unwrap();
            }
        }
    }

    fn accept(listener: &UnixListener) -> Result<UnixStream, Error> {
        let end = Instant::now() + Duration::from_secs(2);
        loop {
            match listener.accept() {
                Ok((stream, _)) => return Ok(stream),
                Err(e) if e.kind() == std::io::ErrorKind::WouldBlock && Instant::now() < end => {
                    thread::sleep(Duration::from_millis(2));
                }
                _ => return Err(Error::Unavailable),
            }
        }
    }

    #[test]
    fn actual_peer_framed_exchange_and_legitimate_service_rebind() {
        let fixture = Fixture::new();
        let path = fixture.0.join("service.sock");
        let listener = fixture.listener();
        let client = Client::new(path.clone(), crate::openbsd::effective_uid()).unwrap();
        for listener in [Some(listener), None] {
            let listener = listener.unwrap_or_else(|| fixture.listener());
            let worker = thread::spawn(move || {
                let mut stream = accept(&listener)?;
                let deadline = Instant::now() + Duration::from_secs(2);
                let request = read_request(&mut stream, crate::openbsd::effective_uid(), deadline)?;
                if !matches!(request.operation, Operation::Login { .. }) {
                    return Err(Error::Invalid);
                }
                write_response(
                    &mut stream,
                    &Response::SignedIn { token: token() },
                    deadline,
                )
            });
            let response = client.exchange(&login_request());
            let worker_result = worker.join().unwrap();
            assert!(worker_result.is_ok());
            assert!(
                matches!(response, Ok(Response::SignedIn { token: value }) if value == token())
            );
            std::fs::remove_file(&path).unwrap();
        }
    }

    #[test]
    fn typed_wire_rejects_extra_fields_and_caller_privileges() {
        for raw in [
            r#"{"version":1,"client":"127.0.0.1","uid":1000,"operation":{"op":"scope","token":"x"}}"#,
            r#"{"version":1,"client":"127.0.0.1","operation":{"op":"login","login":"x","password":"y","totp":"123456","system":true}}"#,
            r#"{"version":1,"client":"127.0.0.1","operation":{"op":"sql","query":"SELECT 1"}}"#,
            r#"{"version":1,"client":"127.0.0.1","operation":{"op":"redeem_setup","account":"new@example.test","invitation":"retired"}}"#,
            r#"{"version":1,"client":"127.0.0.1","operation":{"op":"setup_view","account":"new@example.test","grant":"retired"}}"#,
            r#"{"version":1,"client":"127.0.0.1","operation":{"op":"complete_setup","account":"new@example.test","grant":"retired"}}"#,
        ] {
            assert!(serde_json::from_str::<Request>(raw).is_err());
        }
        assert!(
            serde_json::from_str::<Response>(r#"{"status":"denied","token":"unexpected"}"#)
                .is_err()
        );
        let mut request = login_request();
        assert!(request.validate().is_ok());
        request.version = 2;
        assert_eq!(request.validate(), Err(Error::Invalid));
        request.version = VERSION;
        request.client = "127.0.0.1,198.51.100.1".into();
        assert_eq!(request.validate(), Err(Error::Invalid));
    }

    #[test]
    fn password_and_scope_payload_bounds_are_explicit() {
        let mut request = login_request();
        request.operation = Operation::Login {
            login: "operator@example.test".into(),
            password: "é".repeat(37),
            totp: "123456".into(),
        };
        assert_eq!(request.validate(), Err(Error::Invalid));
        request.operation = Operation::Scope {
            token: "a".repeat(64),
        };
        assert_eq!(request.validate(), Err(Error::Invalid));
        for response in [
            Response::Scope {
                login: "operator@example.test".into(),
                system: false,
                domains: vec!["example.test".into(), "example.test".into()],
                csrf: "b".repeat(64),
            },
            Response::Scope {
                login: "operator@example.test".into(),
                system: true,
                domains: (0..17).map(|n| format!("d{n}.test")).collect(),
                csrf: "b".repeat(64),
            },
        ] {
            assert_eq!(response.validate(), Err(Error::Invalid));
        }
    }

    #[test]
    fn domain_admin_without_active_grants_has_a_valid_scope_response() {
        let response = Response::Scope {
            login: "operator@example.test".into(),
            system: false,
            domains: vec![],
            csrf: "b".repeat(64),
        };
        assert_eq!(response.validate(), Ok(()));
        let bytes = serde_json::to_vec(&response).unwrap();
        let decoded: Response = serde_json::from_slice(&bytes).unwrap();
        assert_eq!(decoded.validate(), Ok(()));
        assert!(
            matches!(decoded, Response::Scope { system: false, domains, .. } if domains.is_empty())
        );
    }

    #[test]
    fn signed_out_has_a_fixed_unambiguous_wire_result() {
        let bytes = serde_json::to_vec(&Response::SignedOut).unwrap();
        assert_eq!(bytes, br#"{"status":"signed_out"}"#);
        let response: Response = serde_json::from_slice(&bytes).unwrap();
        assert!(matches!(response, Response::SignedOut));
        assert!(response.validate().is_ok());
        assert!(serde_json::from_slice::<Response>(
            br#"{"status":"signed_out","token":"unexpected"}"#
        )
        .is_err());
    }

    #[test]
    fn peer_denial_happens_without_reading_request_payload() {
        let (_, mut service) = UnixStream::pair().unwrap();
        let wrong_uid = crate::openbsd::effective_uid().wrapping_add(1);
        assert!(matches!(
            read_request(
                &mut service,
                wrong_uid,
                Instant::now() + Duration::from_secs(1)
            ),
            Err(Error::Denied)
        ));
    }

    #[test]
    fn frame_limit_and_trailing_bytes_refuse_before_dispatch() {
        for trailing in [false, true] {
            let (mut caller, mut service) = UnixStream::pair().unwrap();
            if trailing {
                let bytes = serde_json::to_vec(&login_request()).unwrap();
                caller
                    .write_all(&(bytes.len() as u32).to_be_bytes())
                    .unwrap();
                caller.write_all(&bytes).unwrap();
                caller.write_all(b"x").unwrap();
            } else {
                caller
                    .write_all(&((MAX_FRAME + 1) as u32).to_be_bytes())
                    .unwrap();
            }
            caller.shutdown(Shutdown::Write).unwrap();
            assert!(matches!(
                read_request(
                    &mut service,
                    crate::openbsd::effective_uid(),
                    Instant::now() + Duration::from_secs(1)
                ),
                Err(Error::Invalid)
            ));
        }
    }

    #[test]
    fn client_rejects_unsafe_socket_custody_and_wrong_service_owner() {
        let fixture = Fixture::new();
        let path = fixture.0.join("service.sock");
        let _listener = fixture.listener();
        assert!(Client::new(path.clone(), crate::openbsd::effective_uid()).is_ok());
        assert!(Client::new(
            path.clone(),
            crate::openbsd::effective_uid().wrapping_add(1)
        )
        .is_err());
        std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o666)).unwrap();
        assert!(Client::new(path.clone(), crate::openbsd::effective_uid()).is_err());
        std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o600)).unwrap();
        let alias = fixture.0.join("alias.sock");
        std::os::unix::fs::symlink(&path, &alias).unwrap();
        assert!(Client::new(alias, crate::openbsd::effective_uid()).is_err());
    }

    #[test]
    fn client_pins_parent_identity_but_not_service_socket_lifetime() {
        let fixture = Fixture::new();
        let run = fixture.0.join("run");
        std::fs::DirBuilder::new().mode(0o700).create(&run).unwrap();
        let path = run.join("service.sock");
        let _old_listener = UnixListener::bind(&path).unwrap();
        std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o600)).unwrap();
        let client = Client::new(path, crate::openbsd::effective_uid()).unwrap();
        std::fs::rename(&run, fixture.0.join("old-run")).unwrap();
        std::fs::DirBuilder::new().mode(0o700).create(&run).unwrap();
        let path = run.join("service.sock");
        let _replacement_listener = UnixListener::bind(&path).unwrap();
        std::fs::set_permissions(path, std::fs::Permissions::from_mode(0o600)).unwrap();
        assert!(matches!(
            client.exchange(&login_request()),
            Err(Error::Unavailable)
        ));
    }

    #[test]
    fn client_refuses_a_valid_frame_followed_by_extra_response_bytes() {
        let fixture = Fixture::new();
        let listener = fixture.listener();
        let client = Client::new(
            fixture.0.join("service.sock"),
            crate::openbsd::effective_uid(),
        )
        .unwrap();
        let worker = thread::spawn(move || {
            let mut stream = accept(&listener)?;
            let deadline = Instant::now() + Duration::from_secs(2);
            read_request(&mut stream, crate::openbsd::effective_uid(), deadline)?;
            write_frame(&mut stream, br#"{"status":"denied"}"#, deadline).map_err(frame_error)?;
            stream.write_all(b"x").map_err(|_| Error::Unavailable)?;
            stream
                .shutdown(Shutdown::Write)
                .map_err(|_| Error::Unavailable)
        });
        let response = client.exchange(&login_request());
        let worker_result = worker.join().unwrap();
        assert!(worker_result.is_ok());
        assert!(matches!(response, Err(Error::Invalid)));
    }

    #[test]
    fn absence_of_terminal_eof_is_not_a_complete_request() {
        let (mut caller, mut service) = UnixStream::pair().unwrap();
        let bytes = serde_json::to_vec(&login_request()).unwrap();
        let deadline = Instant::now() + Duration::from_millis(30);
        write_frame(&mut caller, &bytes, deadline).unwrap();
        assert!(matches!(
            read_request(&mut service, crate::openbsd::effective_uid(), deadline),
            Err(Error::Unavailable)
        ));
    }
}
