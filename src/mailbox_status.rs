//! Exact-folder status. Virtual message bytes are neither disk usage nor quota.
use crate::auth::CommandExecution;
use crate::mailbox::{MailboxBackendError, MailboxEntry, MailboxListingPolicy};
use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct MailboxStatus {
    mailbox: String,
    guid: String,
    messages: u64,
    virtual_bytes: u64,
}
impl MailboxStatus {
    pub fn new(
        mailbox: &str,
        guid: &str,
        messages: u64,
        virtual_bytes: u64,
    ) -> Result<Self, MailboxBackendError> {
        validate_name(mailbox)?;
        if guid.len() != 32
            || !guid
                .bytes()
                .all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(&b))
            || guid.bytes().all(|b| b == b'0')
            || messages > i64::MAX as u64
            || virtual_bytes > i64::MAX as u64
        {
            return Err(unavailable());
        }
        Ok(Self {
            mailbox: mailbox.into(),
            guid: guid.into(),
            messages,
            virtual_bytes,
        })
    }
    pub fn mailbox(&self) -> &str {
        &self.mailbox
    }
    pub fn guid(&self) -> &str {
        &self.guid
    }
    pub fn messages(&self) -> u64 {
        self.messages
    }
    pub fn virtual_bytes(&self) -> u64 {
        self.virtual_bytes
    }
    pub fn validate(&self, expected: &str) -> Result<(), MailboxBackendError> {
        if self.mailbox != expected {
            return Err(unavailable());
        }
        Self::new(&self.mailbox, &self.guid, self.messages, self.virtual_bytes).map(|_| ())
    }
}
pub(crate) fn unavailable() -> MailboxBackendError {
    MailboxBackendError {
        backend: "mailbox-status",
        reason: "exact folder status is unavailable".into(),
    }
}
pub(crate) fn validate_name(name: &str) -> Result<(), MailboxBackendError> {
    MailboxEntry::new(MailboxListingPolicy::default(), name.to_owned())
        .map_err(|_| unavailable())?;
    if name.starts_with('-') || name.contains(['*', '%', '?', '[', ']', '\\']) {
        return Err(unavailable());
    }
    Ok(())
}
#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct NativeStatus {
    mailbox: String,
    guid: String,
    messages: String,
    vsize: String,
}
fn number(text: &str) -> Result<u64, MailboxBackendError> {
    if text.is_empty()
        || !text.bytes().all(|b| b.is_ascii_digit())
        || text.len() > 19
        || (text.len() > 1 && text.starts_with('0'))
    {
        return Err(unavailable());
    }
    text.parse().map_err(|_| unavailable())
}
pub(crate) fn parse_native(
    expected: &str,
    result: &CommandExecution,
) -> Result<MailboxStatus, MailboxBackendError> {
    validate_name(expected)?;
    if result.status_code != 0 || result.stdout.len() > 4096 {
        return Err(unavailable());
    }
    let mut rows: Vec<NativeStatus> =
        serde_json::from_str(&result.stdout).map_err(|_| unavailable())?;
    if rows.len() != 1 {
        return Err(unavailable());
    }
    let row = rows.pop().ok_or_else(unavailable)?;
    let status = MailboxStatus::new(
        &row.mailbox,
        &row.guid,
        number(&row.messages)?,
        number(&row.vsize)?,
    )?;
    status.validate(expected)?;
    Ok(status)
}

pub(crate) fn validate_account(account: &str) -> Result<(), MailboxBackendError> {
    if account.is_empty()
        || account.len() > crate::auth::DEFAULT_USERNAME_MAX_LEN
        || account.starts_with('-')
        || account.contains(['*', '?', '%', '[', ']', '\\'])
        || account.chars().any(|c| c.is_control() || c.is_whitespace())
    {
        return Err(unavailable());
    }
    Ok(())
}
#[cfg(test)]
mod tests {
    use super::*;
    use crate::auth::{CommandExecutionError, CommandExecutor};
    use crate::mailbox::{DoveadmMailboxListBackend, MailboxBackend};
    use std::{sync::Mutex, time::Duration};
    const GOOD: &str = r#"[{"mailbox":"INBOX","guid":"1234567890abcdef1234567890abcdef","messages":"42","vsize":"8192"}]"#;
    #[test]
    fn mailbox_status_strict_native_projection() {
        let run = |text: &str| {
            parse_native(
                "INBOX",
                &CommandExecution {
                    status_code: 0,
                    stdout: text.into(),
                    stderr: String::new(),
                },
            )
        };
        assert_eq!(run(GOOD).unwrap().messages(), 42);
        for bad in [
            GOOD.replace("INBOX", "Other"),
            GOOD.replace("42", "-1"),
            GOOD.replace("42", "01"),
            GOOD.replace("8192", "18446744073709551615"),
            GOOD.replace(
                "1234567890abcdef1234567890abcdef",
                "00000000000000000000000000000000",
            ),
            GOOD.replace("\"42\"", "42"),
            GOOD.replace("\"vsize\"", "\"vsize2\""),
            GOOD.replace("\"messages\":", "\"messages\":\"1\",\"messages\":"),
            "[]".into(),
            format!(
                "[{},{}]",
                &GOOD[1..GOOD.len() - 1],
                &GOOD[1..GOOD.len() - 1]
            ),
            " ".repeat(4097),
        ] {
            assert!(run(&bad).is_err(), "{bad}");
        }
    }
    struct Executor(Mutex<usize>);
    impl CommandExecutor for Executor {
        fn run_with_stdin_bytes(
            &self,
            _: &str,
            _: &[String],
            _: &[u8],
        ) -> Result<CommandExecution, CommandExecutionError> {
            panic!("deadline/limit bypass")
        }
        fn run_with_stdin_bytes_timeout_and_output_limit(
            &self,
            program: &str,
            args: &[String],
            input: &[u8],
            timeout: Duration,
            limit: usize,
        ) -> Result<CommandExecution, CommandExecutionError> {
            *self.0.lock().unwrap() += 1;
            assert_eq!(program, "/synthetic/doveadm");
            assert_eq!(input, b"");
            assert_eq!(
                timeout.as_secs(),
                crate::auth::DEFAULT_EXTERNAL_COMMAND_TIMEOUT_SECS
            );
            assert_eq!(limit, 4096);
            assert_eq!(
                args,
                [
                    "-o",
                    "stats_writer_socket_path=",
                    "-f",
                    "json",
                    "mailbox",
                    "status",
                    "-u",
                    "alice@example.test",
                    "guid messages vsize",
                    "INBOX"
                ]
            );
            Ok(CommandExecution {
                status_code: 0,
                stdout: GOOD.into(),
                stderr: String::new(),
            })
        }
    }
    #[test]
    fn mailbox_status_argv_boundaries() {
        let backend = DoveadmMailboxListBackend::new(
            MailboxListingPolicy::default(),
            Executor(Mutex::new(0)),
            "/synthetic/doveadm",
        );
        for name in ["*", "INBOX%", "?", "[x]", "\\INBOX", "-A", ""] {
            assert!(backend.mailbox_status("alice@example.test", name).is_err());
        }
        for owner in ["*", "-A", "a?b", "a\nb", ""] {
            assert!(backend.mailbox_status(owner, "INBOX").is_err());
        }
        assert_eq!(
            backend
                .mailbox_status("alice@example.test", "INBOX")
                .unwrap()
                .virtual_bytes(),
            8192
        );
    }
}
