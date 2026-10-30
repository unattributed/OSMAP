//! One fixed loopback submission to the existing MTA. The native account
//! service supplies the registered recipient. No network target or command is
//! accepted from a browser; SMTP transcripts and proof values are never logged.
use crate::access_recovery::Notifier;
use crate::recovery_contact::RecoveryContactDelivery as Delivery;
use std::io::{BufRead, BufReader, Read, Write};
use std::net::{Ipv4Addr, SocketAddr, SocketAddrV4, TcpStream};
use std::time::{Duration, Instant};

pub(crate) struct NativeSmtp;
impl Notifier for NativeSmtp {
    fn deliver(
        &self,
        account: &str,
        email: &str,
        code: &str,
        _: u64,
        deadline: Instant,
    ) -> Delivery {
        if !address(account)
            || !address(email)
            || code.len() != 6
            || !code.bytes().all(|b| b.is_ascii_digit())
        {
            return Delivery::Refused;
        }
        let deadline = deadline.min(Instant::now() + Duration::from_secs(10));
        let Some(timeout) = deadline.checked_duration_since(Instant::now()) else {
            return Delivery::Refused;
        };
        let target = SocketAddr::V4(SocketAddrV4::new(Ipv4Addr::LOCALHOST, 25));
        let Ok(stream) = TcpStream::connect_timeout(&target, timeout) else {
            return Delivery::Refused;
        };
        transaction(stream, account, email, code, deadline)
    }
}
fn address(value: &str) -> bool {
    value.is_ascii()
        && !value.chars().any(char::is_control)
        && crate::mail_address::validate_address(crate::send::ComposePolicy::default(), value)
            .is_ok()
}
trait Channel: Read + Write {
    fn timeout(&self, deadline: Instant) -> std::io::Result<()>;
}
impl Channel for TcpStream {
    fn timeout(&self, deadline: Instant) -> std::io::Result<()> {
        let remaining = deadline
            .checked_duration_since(Instant::now())
            .filter(|v| !v.is_zero())
            .ok_or(std::io::ErrorKind::TimedOut)?;
        self.set_read_timeout(Some(remaining))?;
        self.set_write_timeout(Some(remaining))
    }
}
fn reply_details<S: Channel>(io: &mut BufReader<S>, deadline: Instant) -> Option<(u16, bool)> {
    let mut code = None;
    let mut dsn = false;
    for _ in 0..16 {
        io.get_ref().timeout(deadline).ok()?;
        let mut line = Vec::new();
        io.take(513).read_until(b'\n', &mut line).ok()?;
        if !(6..=512).contains(&line.len())
            || !line.ends_with(b"\r\n")
            || !line[..3].iter().all(u8::is_ascii_digit)
        {
            return None;
        }
        let current = std::str::from_utf8(&line[..3]).ok()?.parse::<u16>().ok()?;
        if code.is_some_and(|v| v != current) {
            return None;
        }
        code = Some(current);
        dsn |= line
            .get(4..line.len() - 2)
            .is_some_and(|text| text.eq_ignore_ascii_case(b"DSN"));
        match line[3] {
            b' ' => return Some((current, dsn)),
            b'-' => {}
            _ => return None,
        }
    }
    None
}
fn reply<S: Channel>(io: &mut BufReader<S>, deadline: Instant) -> Option<u16> {
    reply_details(io, deadline).map(|v| v.0)
}
fn send<S: Channel>(io: &mut BufReader<S>, bytes: &[u8], deadline: Instant) -> bool {
    if io.get_ref().timeout(deadline).is_err() {
        return false;
    }
    io.get_mut()
        .write_all(bytes)
        .and_then(|_| io.get_mut().flush())
        .is_ok()
}
fn transaction<S: Channel>(
    stream: S,
    account: &str,
    email: &str,
    code: &str,
    deadline: Instant,
) -> Delivery {
    let mut io = BufReader::new(stream);
    let before_data = |value: Option<u16>, expected: u16| -> Result<(), Delivery> {
        match value {
            Some(n) if n == expected => Ok(()),
            Some(400..=599) => Err(Delivery::Refused),
            _ => Err(Delivery::Unconfirmed),
        }
    };
    if let Err(d) = before_data(reply(&mut io, deadline), 220) {
        return d;
    }
    if !send(&mut io, b"EHLO localhost\r\n", deadline) {
        return Delivery::Unconfirmed;
    }
    match reply_details(&mut io, deadline) {
        Some((250, true)) => {}
        Some((400..=599, _)) | Some((250, false)) => return Delivery::Refused,
        _ => return Delivery::Unconfirmed,
    }
    for (command, expected) in [
        (format!("MAIL FROM:<{account}>\r\n"), 250),
        (format!("RCPT TO:<{email}> NOTIFY=NEVER\r\n"), 250),
        ("DATA\r\n".to_owned(), 354),
    ] {
        if !send(&mut io, command.as_bytes(), deadline) {
            return Delivery::Unconfirmed;
        }
        if let Err(d) = before_data(reply(&mut io, deadline), expected) {
            return d;
        }
    }
    let body = format!("From: {account}\r\nTo: {email}\r\nSubject: Your OSMAP recovery code\r\nAuto-Submitted: auto-generated\r\nX-Auto-Response-Suppress: All\r\nMIME-Version: 1.0\r\nContent-Type: text/plain; charset=utf-8\r\n\r\nUse this one-time code on the OSMAP recovery page:\r\n\r\n{code}\r\n\r\nThis code expires in 10 minutes. If you did not request recovery, ignore this message.\r\n.\r\n");
    // From this point a timeout/disconnect cannot prove nonacceptance.
    if !send(&mut io, body.as_bytes(), deadline) {
        return Delivery::Unconfirmed;
    }
    if reply(&mut io, deadline) == Some(250) && Instant::now() < deadline {
        // Queue acceptance is the result; QUIT success is not delivery evidence.
        let _ = send(&mut io, b"QUIT\r\n", deadline);
        Delivery::Accepted
    } else {
        Delivery::Unconfirmed
    }
}
#[cfg(test)]
mod tests {
    use super::*;
    use std::{cell::RefCell, io::Cursor, rc::Rc};
    struct Fixture {
        input: Cursor<Vec<u8>>,
        output: Rc<RefCell<Vec<u8>>>,
    }
    impl Read for Fixture {
        fn read(&mut self, b: &mut [u8]) -> std::io::Result<usize> {
            self.input.read(b)
        }
    }
    impl Write for Fixture {
        fn write(&mut self, b: &[u8]) -> std::io::Result<usize> {
            self.output.borrow_mut().extend_from_slice(b);
            Ok(b.len())
        }
        fn flush(&mut self) -> std::io::Result<()> {
            Ok(())
        }
    }
    impl Channel for Fixture {
        fn timeout(&self, deadline: Instant) -> std::io::Result<()> {
            if Instant::now() < deadline {
                Ok(())
            } else {
                Err(std::io::ErrorKind::TimedOut.into())
            }
        }
    }
    fn run(input: &str) -> Delivery {
        transaction(
            Fixture {
                input: Cursor::new(input.as_bytes().to_vec()),
                output: Default::default(),
            },
            "account@example.test",
            "recovery@example.test",
            "123456",
            Instant::now() + Duration::from_secs(1),
        )
    }
    #[test]
    fn fixed_smtp_accepts_only_final_queue_acceptance() {
        assert_eq!(
            run("220 ready\r\n250-DSN\r\n250 ok\r\n250 ok\r\n250 ok\r\n354 data\r\n250 queued\r\n"),
            Delivery::Accepted
        );
        assert_eq!(
            run("220 ready\r\n250 DSN\r\n250 ok\r\n550 refused\r\n"),
            Delivery::Refused
        );
        assert_eq!(
            run("220 ready\r\n250 DSN\r\n250 ok\r\n250 ok\r\n354 data\r\n"),
            Delivery::Unconfirmed
        );
        assert_eq!(run("220 ready\n"), Delivery::Unconfirmed);
        assert_eq!(
            run("220 ready\r\n250-other\r\n251 wrong\r\n"),
            Delivery::Unconfirmed
        );
    }
    #[test]
    fn observed_dsn_is_required_and_suppression_is_sent_before_proof_data() {
        for (ehlo, expected) in [
            ("250 ready\r\n", Delivery::Refused),
            ("250-localhost\r\n250 DSN\r\n", Delivery::Accepted),
        ] {
            let output = Rc::new(RefCell::new(Vec::new()));
            let result = transaction(
                Fixture {
                    input: Cursor::new(format!("220 ready\r\n{ehlo}250 sender\r\n250 recipient\r\n354 data\r\n250 queued\r\n").into_bytes()),
                    output: output.clone(),
                },
                "account@example.test", "recovery@example.test", "123456",
                Instant::now() + Duration::from_secs(1),
            );
            assert_eq!(result, expected);
            let wire = String::from_utf8(output.borrow().clone()).unwrap();
            if expected == Delivery::Refused {
                assert_eq!(wire, "EHLO localhost\r\n");
                assert!(!wire.contains("MAIL"));
                assert!(!wire.contains("123456"));
            } else {
                assert!(wire.contains("RCPT TO:<recovery@example.test> NOTIFY=NEVER\r\n"));
                let (commands, data) = wire.split_once("DATA\r\n").unwrap();
                assert!(!commands.contains("123456"));
                assert!(data.contains("\r\n123456\r\n"));
                assert!(data.contains("Auto-Submitted: auto-generated\r\n"));
            }
        }
    }

    #[test]
    fn destination_and_proof_input_refuse_injection_before_connect() {
        assert!(!address(
            "recovery@example.test\r\nBcc: attacker@example.test"
        ));
        assert_eq!(
            NativeSmtp.deliver(
                "a@example.test",
                "b@example.test",
                "bad",
                0,
                Instant::now() + Duration::from_secs(1)
            ),
            Delivery::Refused
        );
    }
}
