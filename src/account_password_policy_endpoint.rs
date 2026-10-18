//! Bounded fixed Dovecot policy HTTP and one-request IMAP publication adapter.
//! Listener creation, native peer evidence and installed routing are not
//! supplied here. They must be qualified before this adapter can be activated.
use crate::account_password_policy::{Clock, Decision, Fence, RegistrationObserver};
use hmac::{Hmac, Mac};
use serde::de::{MapAccess, Visitor};
use serde::{Deserialize, Deserializer};
use sha2::Sha256;
use std::collections::BTreeMap;
use std::io::{Read, Write};
use std::net::TcpStream;
use std::os::unix::net::UnixStream;
use std::time::{Duration, Instant};

#[derive(Debug, Copy, Clone, PartialEq, Eq)]
pub(crate) enum Error {
    Refused,
    Unavailable,
    Expired,
}
pub(crate) trait BoundedStream: Read + Write {
    fn read_bound(&self, left: Duration) -> std::io::Result<()>;
    fn write_bound(&self, left: Duration) -> std::io::Result<()>;
}
impl BoundedStream for UnixStream {
    fn read_bound(&self, left: Duration) -> std::io::Result<()> {
        self.set_read_timeout(Some(left))
    }
    fn write_bound(&self, left: Duration) -> std::io::Result<()> {
        self.set_write_timeout(Some(left))
    }
}
impl BoundedStream for TcpStream {
    fn read_bound(&self, left: Duration) -> std::io::Result<()> {
        self.set_read_timeout(Some(left))
    }
    fn write_bound(&self, left: Duration) -> std::io::Result<()> {
        self.set_write_timeout(Some(left))
    }
}
pub(crate) struct PublishClaim {
    pub account: String,
    pub session: String,
    pub tls: bool,
    pub pid: u32,
    pub fd_in: i32,
    pub fd_out: i32,
    pub fds: usize,
}
/// Constructed by the actual native accepted-connection adapter. `admit` must
/// establish peer/process custody before reading even one untrusted byte.
pub(crate) trait PeerInspector: RegistrationObserver {
    type Binding;
    fn admit(&self, stream: &UnixStream, deadline: Instant) -> Result<Self::Binding, Error>;
    fn validate(
        &self,
        binding: &Self::Binding,
        stream: &UnixStream,
        claim: &PublishClaim,
        deadline: Instant,
    ) -> Result<(), Error>;
    fn attest_io(
        &self,
        binding: &Self::Binding,
        stream: &UnixStream,
        claim: &PublishClaim,
        io: crate::openbsd::ReceivedImapIo,
        deadline: Instant,
    ) -> Result<crate::account_password_imap::AttestedIo, Error> {
        let _ = (binding, stream, claim, io, deadline);
        Err(Error::Refused)
    }
}

struct UniqueObject(BTreeMap<String, serde_json::Value>);
impl<'de> Deserialize<'de> for UniqueObject {
    fn deserialize<D: Deserializer<'de>>(deserializer: D) -> Result<Self, D::Error> {
        struct Object;
        impl<'de> Visitor<'de> for Object {
            type Value = UniqueObject;
            fn expecting(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
                formatter.write_str("unique object fields")
            }
            fn visit_map<M: MapAccess<'de>>(self, mut source: M) -> Result<Self::Value, M::Error> {
                let mut value = BTreeMap::new();
                while let Some((key, item)) = source.next_entry::<String, serde_json::Value>()? {
                    if value.insert(key, item).is_some() {
                        return Err(serde::de::Error::custom("duplicate policy field"));
                    }
                }
                Ok(UniqueObject(value))
            }
        }
        deserializer.deserialize_map(Object)
    }
}
pub(crate) struct Endpoint<'a, C> {
    fence: &'a Fence<C>,
    api_key: [u8; 64],
}
impl<'a, C: Clock> Endpoint<'a, C> {
    pub(crate) fn new(fence: &'a Fence<C>, api_key: [u8; 64]) -> Result<Self, Error> {
        if !api_key
            .iter()
            .all(|v| v.is_ascii_digit() || (b'a'..=b'f').contains(v))
        {
            return Err(Error::Refused);
        }
        Ok(Self { fence, api_key })
    }
    fn authenticated(&self, candidate: &[u8]) -> bool {
        if candidate.len() != 64 {
            return false;
        }
        let Ok(mut expected) = Hmac::<Sha256>::new_from_slice(&self.api_key) else {
            return false;
        };
        let Ok(mut supplied) = Hmac::<Sha256>::new_from_slice(candidate) else {
            return false;
        };
        expected.update(b"osmap-dovecot-policy-api-v1");
        supplied.update(b"osmap-dovecot-policy-api-v1");
        expected
            .verify_slice(&supplied.finalize().into_bytes())
            .is_ok()
    }
    pub(crate) fn policy(
        &self,
        body: &[u8],
        api_key: &[u8],
        command: &str,
        original_deadline: Instant,
    ) -> Decision {
        if crate::account_password_process::execution_quarantined() {
            return Decision::Deny;
        }
        let decision = self.policy_inner(body, api_key, command, original_deadline);
        if crate::account_password_process::execution_quarantined() {
            Decision::Deny
        } else {
            decision
        }
    }
    fn policy_inner(
        &self,
        body: &[u8],
        api_key: &[u8],
        command: &str,
        original_deadline: Instant,
    ) -> Decision {
        if !self.authenticated(api_key)
            || !matches!(command, "allow" | "report")
            || body.is_empty()
            || body.len() > 4096
            || valid_deadline(original_deadline).is_err()
        {
            return Decision::Deny;
        }
        let Ok(UniqueObject(mut request)) = serde_json::from_slice(body) else {
            return Decision::Deny;
        };
        let Some(login) = request.get("login").and_then(serde_json::Value::as_str) else {
            return Decision::Deny;
        };
        // The same server-owned Fence scope drives policy and final publication.
        // Outside scope is transparent only after API authentication.
        if !self.fence.manages(login) {
            return Decision::Allow;
        }
        if command == "report" {
            return Decision::Deny;
        }
        if request.get("phase").and_then(serde_json::Value::as_str) == Some("") {
            request.insert("phase".into(), "before".into());
        }
        let Ok(normalized) = serde_json::to_vec(&request) else {
            return Decision::Deny;
        };
        self.fence.allow(&normalized, original_deadline)
    }
    pub(crate) fn policy_connection<S: BoundedStream>(
        &self,
        mut stream: S,
        original_deadline: Instant,
    ) -> Result<(), Error> {
        valid_deadline(original_deadline)?;
        let mut header = Vec::new();
        while !header.ends_with(b"\r\n\r\n") {
            if header.len() >= 8192 {
                return Err(Error::Refused);
            }
            header.push(read_byte(&mut stream, original_deadline)?);
        }
        let text = std::str::from_utf8(&header).map_err(|_| Error::Refused)?;
        let mut lines = text[..text.len() - 4].split("\r\n");
        let command = match lines.next() {
            Some("POST /epoch/?command=allow HTTP/1.0" | "POST /epoch/?command=allow HTTP/1.1") => {
                "allow"
            }
            Some(
                "POST /epoch/?command=report HTTP/1.0" | "POST /epoch/?command=report HTTP/1.1",
            ) => "report",
            _ => return Err(Error::Refused),
        };
        let mut headers = BTreeMap::new();
        for line in lines {
            let (key, value) = line.split_once(':').ok_or(Error::Refused)?;
            if key.is_empty()
                || !key.bytes().all(|v| v.is_ascii_alphanumeric() || v == b'-')
                || value.bytes().any(|v| !(32..=126).contains(&v))
            {
                return Err(Error::Refused);
            }
            if headers
                .insert(key.to_ascii_lowercase(), value.trim_matches(' '))
                .is_some()
            {
                return Err(Error::Refused);
            }
        }
        if headers.contains_key("transfer-encoding") {
            return Err(Error::Refused);
        }
        let length = headers.get("content-length").ok_or(Error::Refused)?;
        if length.is_empty()
            || length.len() > 4
            || !matches!(length.as_bytes()[0], b'1'..=b'9')
            || !length.bytes().all(|v| v.is_ascii_digit())
        {
            return Err(Error::Refused);
        }
        let length: usize = length.parse().map_err(|_| Error::Refused)?;
        if length > 4096 {
            return Err(Error::Refused);
        }
        let mut body = Vec::with_capacity(length);
        while body.len() < length {
            body.push(read_byte(&mut stream, original_deadline)?);
        }
        let result = self
            .policy(
                &body,
                headers
                    .get("x-osmap-policy")
                    .map_or(b"".as_slice(), |v| v.as_bytes()),
                command,
                original_deadline,
            )
            .body();
        let mut response = format!("HTTP/1.1 200 OK\r\nContent-Type: application/json\r\nConnection: close\r\nContent-Length: {}\r\n\r\n", result.len()).into_bytes();
        response.extend_from_slice(result);
        write_response(&mut stream, &response, original_deadline)
    }
    pub(crate) fn final_connection<P: PeerInspector>(
        &self,
        mut stream: UnixStream,
        inspector: &P,
        registry: &crate::account_password_imap::Registry,
        original_deadline: Instant,
    ) -> Result<(), Error> {
        valid_deadline(original_deadline)?;
        let binding = inspector.admit(&stream, original_deadline)?;
        let (first, io) =
            crate::openbsd::password_receive_imap_io_first(&stream, original_deadline)
                .map_err(|_| Error::Refused)?;
        let mut line = vec![first];
        while !line.ends_with(b"\n") {
            if line.len() >= 1024 {
                return Err(Error::Refused);
            }
            line.push(read_byte(&mut stream, original_deadline)?);
        }
        let result = (|| {
            let claim = publication_claim(&line)?;
            if io.len() != claim.fds {
                return Err(Error::Refused);
            }
            inspector.validate(&binding, &stream, &claim, original_deadline)?;
            let attested = inspector.attest_io(&binding, &stream, &claim, io, original_deadline)?;
            let control = stream.try_clone().map_err(|_| Error::Unavailable)?;
            let body = serde_json::to_vec(&serde_json::json!({"login":claim.account,"protocol":"imap","session_id":claim.session,"phase":"after","tls":claim.tls})).map_err(|_| Error::Refused)?;
            let published = self
                .fence
                .publish_imap_registered(
                    &body,
                    inspector,
                    registry,
                    attested,
                    control,
                    original_deadline,
                )
                .map_err(|_| Error::Refused)?;
            if published.pid() != claim.pid {
                return Err(Error::Refused);
            }
            Ok(())
        })();
        let reply = if result.is_ok() {
            b"OK\n".as_slice()
        } else {
            b"NO\n".as_slice()
        };
        write_response(&mut stream, reply, original_deadline)
    }
}
fn publication_claim(line: &[u8]) -> Result<PublishClaim, Error> {
    let line = std::str::from_utf8(line).map_err(|_| Error::Refused)?;
    let fields: Vec<_> = line
        .strip_suffix('\n')
        .ok_or(Error::Refused)?
        .split('\t')
        .collect();
    if fields.len() != 8 || fields[0] != "PUBLISH2" || !matches!(fields[3], "0" | "1") {
        return Err(Error::Refused);
    }
    crate::account_admission::valid_account(fields[1]).map_err(|_| Error::Refused)?;
    if fields[1].len() > 254
        || fields[1].bytes().any(|v| v.is_ascii_uppercase())
        || fields[2].is_empty()
        || fields[2].len() > 128
        || !fields[2]
            .bytes()
            .all(|v| v.is_ascii_alphanumeric() || b"/+_=.-".contains(&v))
    {
        return Err(Error::Refused);
    }
    let pid: u32 = fields[4].parse().map_err(|_| Error::Refused)?;
    if pid <= 1 || pid >= i32::MAX as u32 || pid.to_string() != fields[4] {
        return Err(Error::Refused);
    }
    let descriptor = |field: &str, prefix: &str| -> Result<i32, Error> {
        let raw = field.strip_prefix(prefix).ok_or(Error::Refused)?;
        let value: i32 = raw.parse().map_err(|_| Error::Refused)?;
        if value < 0 || value.to_string() != raw {
            return Err(Error::Refused);
        }
        Ok(value)
    };
    let fd_in = descriptor(fields[5], "fd_in=")?;
    let fd_out = descriptor(fields[6], "fd_out=")?;
    let fds = match fields[7] {
        "fds=1" if fd_in == fd_out => 1,
        "fds=2" if fd_in != fd_out => 2,
        _ => return Err(Error::Refused),
    };
    Ok(PublishClaim {
        account: fields[1].into(),
        session: fields[2].into(),
        tls: fields[3] == "1",
        pid,
        fd_in,
        fd_out,
        fds,
    })
}
fn valid_deadline(deadline: Instant) -> Result<(), Error> {
    let now = Instant::now();
    if deadline <= now || deadline > now + Duration::from_millis(500) {
        Err(Error::Expired)
    } else {
        Ok(())
    }
}
fn remaining(deadline: Instant) -> Result<Duration, Error> {
    deadline
        .checked_duration_since(Instant::now())
        .filter(|v| !v.is_zero())
        .ok_or(Error::Expired)
}
fn read_byte<S: BoundedStream>(stream: &mut S, deadline: Instant) -> Result<u8, Error> {
    stream
        .read_bound(remaining(deadline)?)
        .map_err(|_| Error::Unavailable)?;
    let mut byte = [0];
    match stream.read(&mut byte) {
        Ok(1) => Ok(byte[0]),
        _ => Err(Error::Unavailable),
    }
}
fn write_response<S: BoundedStream>(
    stream: &mut S,
    mut bytes: &[u8],
    deadline: Instant,
) -> Result<(), Error> {
    while !bytes.is_empty() {
        stream
            .write_bound(remaining(deadline)?)
            .map_err(|_| Error::Unavailable)?;
        let count = stream.write(bytes).map_err(|_| Error::Unavailable)?;
        if count == 0 {
            return Err(Error::Unavailable);
        }
        bytes = &bytes[count..];
    }
    remaining(deadline)?;
    Ok(())
}

#[cfg(test)]
#[path = "account_password_policy_endpoint_tests.rs"]
mod tests;
