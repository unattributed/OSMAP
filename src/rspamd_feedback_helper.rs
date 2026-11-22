//! One fixed, root-invoked bridge from a bounded RFC 5322 message on stdin to
//! Rspamd's local spam-learning endpoint.
//!
//! The caller cannot choose a controller command, socket, header or file path.
//! The fixed socket is connected under Web's inherited path restriction;
//! OpenBSD pledge then removes all authority to create or connect sockets.

use std::io::{self, Read, Write};
#[cfg(unix)]
use std::net::Shutdown;
#[cfg(unix)]
use std::os::unix::net::UnixStream;
use std::path::Path;
use std::time::Duration;

pub const RSPAMD_FEEDBACK_SOCKET: &str = "/var/run/rspamd/osmap-controller.sock";
pub const MAX_SPAM_FEEDBACK_BYTES: usize = 4 * 1024 * 1024;
const MAX_RESPONSE_BYTES: usize = 64 * 1024;
const IO_TIMEOUT: Duration = Duration::from_secs(8);

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Error {
    InvalidInput,
    Unavailable,
    Uncertain,
    Refused,
}

impl Error {
    pub fn public_code(self) -> &'static str {
        match self {
            Self::InvalidInput => "invalid_input",
            Self::Unavailable => "controller_unavailable",
            Self::Uncertain => "learning_unconfirmed",
            Self::Refused => "learning_refused",
        }
    }

    pub fn exit_code(self) -> u8 {
        match self {
            Self::InvalidInput | Self::Unavailable | Self::Refused => 10,
            Self::Uncertain => 11,
        }
    }
}

pub fn run() -> Result<(), Error> {
    #[cfg(unix)]
    if crate::openbsd::effective_uid() != 0 {
        return Err(Error::Unavailable);
    }
    run_with_socket(
        Path::new(RSPAMD_FEEDBACK_SOCKET),
        &mut io::stdin(),
        &mut io::stdout(),
    )
}

#[cfg(unix)]
fn run_with_socket(
    socket_path: &Path,
    input: &mut dyn Read,
    output: &mut dyn Write,
) -> Result<(), Error> {
    let mut message = Vec::new();
    input
        .take((MAX_SPAM_FEEDBACK_BYTES + 1) as u64)
        .read_to_end(&mut message)
        .map_err(|_| Error::InvalidInput)?;
    if message.is_empty() || message.len() > MAX_SPAM_FEEDBACK_BYTES {
        return Err(Error::InvalidInput);
    }

    let mut stream = UnixStream::connect(socket_path).map_err(|_| Error::Unavailable)?;
    // OpenBSD requires the `unix` promise for setsockopt(2). Establish both
    // bounded I/O timeouts before confinement removes that promise; afterward
    // the helper retains only stdio authority on this already-open descriptor.
    stream
        .set_read_timeout(Some(IO_TIMEOUT))
        .map_err(|_| Error::Unavailable)?;
    stream
        .set_write_timeout(Some(IO_TIMEOUT))
        .map_err(|_| Error::Unavailable)?;
    apply_openbsd_confinement(socket_path)?;
    let header = format!(
        "POST /learnspam HTTP/1.1\r\nHost: localhost\r\nContent-Type: message/rfc822\r\nContent-Length: {}\r\nConnection: close\r\n\r\n",
        message.len()
    );
    stream
        .write_all(header.as_bytes())
        .and_then(|()| stream.write_all(&message))
        .and_then(|()| stream.flush())
        .map_err(|_| Error::Uncertain)?;
    stream
        .shutdown(Shutdown::Write)
        .map_err(|_| Error::Uncertain)?;

    let mut response = Vec::new();
    stream
        .take((MAX_RESPONSE_BYTES + 1) as u64)
        .read_to_end(&mut response)
        .map_err(|_| Error::Uncertain)?;
    if response.len() > MAX_RESPONSE_BYTES {
        return Err(Error::Uncertain);
    }
    let status_line = response
        .split(|byte| *byte == b'\n')
        .next()
        .and_then(|line| std::str::from_utf8(line).ok())
        .map(str::trim_end)
        .ok_or(Error::Uncertain)?;
    let mut parts = status_line.split_whitespace();
    if !parts
        .next()
        .is_some_and(|value| value.starts_with("HTTP/1."))
    {
        return Err(Error::Uncertain);
    }
    let status = parts
        .next()
        .and_then(|value| value.parse::<u16>().ok())
        .ok_or(Error::Uncertain)?;
    if !(200..300).contains(&status) {
        return Err(Error::Refused);
    }
    let body = response
        .windows(4)
        .position(|window| window == b"\r\n\r\n")
        .map(|index| &response[index + 4..])
        .or_else(|| {
            response
                .windows(2)
                .position(|window| window == b"\n\n")
                .map(|index| &response[index + 2..])
        })
        .ok_or(Error::Uncertain)?;
    let confirmed = serde_json::from_slice::<serde_json::Value>(body)
        .ok()
        .and_then(|value| value.get("success").and_then(serde_json::Value::as_bool))
        == Some(true);
    if !confirmed {
        return Err(Error::Uncertain);
    }
    output.write_all(b"learned\n").map_err(|_| Error::Uncertain)
}

#[cfg(not(unix))]
fn run_with_socket(
    _socket_path: &Path,
    _input: &mut dyn Read,
    _output: &mut dyn Write,
) -> Result<(), Error> {
    Err(Error::Unavailable)
}

#[cfg(target_os = "openbsd")]
fn apply_openbsd_confinement(_socket_path: &Path) -> Result<(), Error> {
    crate::openbsd::apply_rspamd_feedback_confinement().map_err(|_| Error::Unavailable)
}

#[cfg(not(target_os = "openbsd"))]
fn apply_openbsd_confinement(_socket_path: &Path) -> Result<(), Error> {
    Ok(())
}

#[cfg(all(test, unix))]
mod tests {
    use super::*;
    use std::os::unix::net::UnixListener;
    use std::thread;

    fn socket_path(name: &str) -> std::path::PathBuf {
        std::env::temp_dir().join(format!("osmap-rspamd-{name}-{}", std::process::id()))
    }

    #[test]
    fn fixed_learning_request_sends_only_message_bytes_and_accepts_200() {
        let path = socket_path("ok");
        let _ = std::fs::remove_file(&path);
        let listener = UnixListener::bind(&path).unwrap();
        #[cfg(not(target_os = "openbsd"))]
        let worker_path = path.clone();
        let worker = thread::spawn(move || {
            let (mut stream, _) = listener.accept().unwrap();
            let mut request = Vec::new();
            stream.read_to_end(&mut request).unwrap();
            let text = String::from_utf8_lossy(&request);
            assert!(text.starts_with("POST /learnspam HTTP/1.1\r\n"));
            assert!(text.contains("Content-Type: message/rfc822\r\n"));
            assert!(text.ends_with("Subject: fixture\r\n\r\nbody"));
            stream
                .write_all(b"HTTP/1.1 200 OK\r\nContent-Length: 16\r\n\r\n{\"success\":true}")
                .unwrap();
            // pledge(2) is process-wide on OpenBSD. The fixture socket uses a
            // per-process name and is removed before the next run; attempting
            // unlink after the helper narrows to stdio would correctly abort.
            #[cfg(not(target_os = "openbsd"))]
            {
                drop(stream);
                drop(listener);
                let _ = std::fs::remove_file(worker_path);
            }
        });
        let mut input = &b"Subject: fixture\r\n\r\nbody"[..];
        let mut output = Vec::new();
        assert_eq!(run_with_socket(&path, &mut input, &mut output), Ok(()));
        assert_eq!(output, b"learned\n");
        worker.join().unwrap();
    }

    #[test]
    fn empty_input_is_refused_before_controller_connection() {
        let path = socket_path("empty");
        let mut input = &b""[..];
        let mut output = Vec::new();
        assert_eq!(
            run_with_socket(&path, &mut input, &mut output),
            Err(Error::InvalidInput)
        );
    }

    #[test]
    fn two_hundred_without_success_confirmation_is_uncertain() {
        let path = socket_path("unconfirmed");
        let _ = std::fs::remove_file(&path);
        let listener = UnixListener::bind(&path).unwrap();
        #[cfg(not(target_os = "openbsd"))]
        let worker_path = path.clone();
        let worker = thread::spawn(move || {
            let (mut stream, _) = listener.accept().unwrap();
            let mut request = Vec::new();
            stream.read_to_end(&mut request).unwrap();
            stream
                .write_all(b"HTTP/1.1 200 OK\r\nContent-Length: 2\r\n\r\n{}")
                .unwrap();
            #[cfg(not(target_os = "openbsd"))]
            {
                drop(stream);
                drop(listener);
                let _ = std::fs::remove_file(worker_path);
            }
        });
        let mut input = &b"Subject: fixture\r\n\r\nbody"[..];
        let mut output = Vec::new();
        assert_eq!(
            run_with_socket(&path, &mut input, &mut output),
            Err(Error::Uncertain)
        );
        assert!(output.is_empty());
        worker.join().unwrap();
    }
}
