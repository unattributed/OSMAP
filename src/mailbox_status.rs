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

/// One account-bound, request-local metadata and exact STATUS observation.
/// This is not an atomic mail-server snapshot or a reusable mutation permit.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct FolderFacts {
    snapshot: crate::folder_metadata::FolderSnapshot,
    statuses: Vec<MailboxStatus>,
}
pub(crate) const MAX_FACT_FOLDERS: usize = 11;
pub(crate) fn validate_fact_names(
    account: &str,
    names: &[String],
) -> Result<(), MailboxBackendError> {
    validate_account(account)?;
    if names.is_empty() || names.len() > MAX_FACT_FOLDERS {
        return Err(unavailable());
    }
    let mut seen = std::collections::BTreeSet::new();
    for name in names {
        validate_name(name)?;
        if crate::documents_doveadm::reserved_documents_mailbox(name) || !seen.insert(name) {
            return Err(unavailable());
        }
    }
    Ok(())
}
impl FolderFacts {
    pub fn new(
        account: &str,
        names: &[String],
        snapshot: crate::folder_metadata::FolderSnapshot,
        statuses: Vec<MailboxStatus>,
    ) -> Result<Self, MailboxBackendError> {
        validate_fact_names(account, names)?;
        snapshot.validate_for(account).map_err(|_| unavailable())?;
        if statuses.len() != names.len() {
            return Err(unavailable());
        }
        let mut rows = std::collections::BTreeMap::new();
        let mut guids = std::collections::BTreeSet::new();
        for status in statuses {
            status.validate(status.mailbox())?;
            if !names.iter().any(|name| name == status.mailbox())
                || !guids.insert(status.guid().to_owned())
                || rows.insert(status.mailbox().to_owned(), status).is_some()
            {
                return Err(unavailable());
            }
        }
        let mut statuses = Vec::with_capacity(names.len());
        for name in names {
            snapshot.folder(account, name).map_err(|_| unavailable())?;
            statuses.push(rows.remove(name).ok_or_else(unavailable)?);
        }
        Ok(Self { snapshot, statuses })
    }
    pub fn validate_for(&self, account: &str, names: &[String]) -> Result<(), MailboxBackendError> {
        Self::new(account, names, self.snapshot.clone(), self.statuses.clone()).map(|_| ())
    }
    pub fn snapshot(&self) -> &crate::folder_metadata::FolderSnapshot {
        &self.snapshot
    }
    pub fn statuses(&self) -> &[MailboxStatus] {
        &self.statuses
    }
    pub fn status(&self, name: &str) -> Result<&MailboxStatus, MailboxBackendError> {
        self.statuses
            .iter()
            .find(|row| row.mailbox() == name)
            .ok_or_else(unavailable)
    }
}

pub(crate) fn parse_native_facts(
    expected: &[String],
    result: &CommandExecution,
) -> Result<Vec<MailboxStatus>, MailboxBackendError> {
    if result.status_code != 0 || result.stdout.len() > 8192 || expected.len() > MAX_FACT_FOLDERS {
        return Err(unavailable());
    }
    let rows: Vec<NativeStatus> =
        serde_json::from_str(&result.stdout).map_err(|_| unavailable())?;
    if rows.len() != expected.len() {
        return Err(unavailable());
    }
    let mut statuses = Vec::with_capacity(rows.len());
    let mut seen = std::collections::BTreeSet::new();
    for row in rows {
        if !expected.contains(&row.mailbox) || !seen.insert(row.mailbox.clone()) {
            return Err(unavailable());
        }
        statuses.push(MailboxStatus::new(
            &row.mailbox,
            &row.guid,
            number(&row.messages)?,
            number(&row.vsize)?,
        )?);
    }
    Ok(statuses)
}

#[cfg(test)]
mod facts_tests {
    use super::*;
    use crate::{
        auth::{CommandExecutionError, CommandExecutor},
        mailbox::{DoveadmMailboxListBackend, MailboxBackend},
    };
    use std::{sync::Mutex, time::Duration};
    const TRANSCRIPT: &str = "* PREAUTH ready\r\n* NAMESPACE ((\"\" \".\")) NIL NIL\r\nN1 OK done\r\n* LIST (\\HasChildren) \".\" INBOX\r\n* LIST (\\HasNoChildren) \".\" INBOX.Child\r\nL1 OK done\r\n* BYE done\r\nZ1 OK done\r\n";
    fn rows() -> String {
        format!(
            r#"[{{"mailbox":"INBOX.Child","guid":"{}","messages":"0","vsize":"0"}},{{"mailbox":"INBOX","guid":"{}","messages":"1","vsize":"668"}}]"#,
            "b".repeat(32),
            "a".repeat(32)
        )
    }
    #[derive(Clone)]
    struct Executor(std::sync::Arc<Mutex<Vec<Duration>>>);
    impl CommandExecutor for Executor {
        fn run_with_stdin_bytes(
            &self,
            _: &str,
            _: &[String],
            _: &[u8],
        ) -> Result<CommandExecution, CommandExecutionError> {
            panic!("unbounded command forbidden")
        }
        fn run_with_stdin_bytes_timeout_and_output_limit(
            &self,
            path: &str,
            args: &[String],
            input: &[u8],
            timeout: Duration,
            cap: usize,
        ) -> Result<CommandExecution, CommandExecutionError> {
            assert_eq!(path, "/fixed/doveadm");
            let mut calls = self.0.lock().unwrap();
            assert!(!timeout.is_zero() && timeout <= Duration::from_secs(10));
            if calls.is_empty() {
                assert_eq!(
                    args,
                    [
                        "exec",
                        "imap",
                        "-o",
                        "stats_writer_socket_path=",
                        "-o",
                        "auth_socket_path=/private/userdb",
                        "-u",
                        "alice@fixture.test"
                    ]
                );
                assert_eq!(input, crate::folder_metadata_backend::TRANSCRIPT);
                assert_eq!(cap, 512 * 1024);
            } else {
                assert_eq!(
                    args,
                    [
                        "-o",
                        "stats_writer_socket_path=",
                        "-o",
                        "auth_socket_path=/private/userdb",
                        "-f",
                        "json",
                        "mailbox",
                        "status",
                        "-u",
                        "alice@fixture.test",
                        "guid messages vsize",
                        "INBOX",
                        "INBOX.Child"
                    ]
                );
                assert!(input.is_empty());
                assert_eq!(cap, 8192);
                assert!(timeout <= calls[0]);
            }
            calls.push(timeout);
            Ok(CommandExecution {
                status_code: 0,
                stdout: if calls.len() == 1 {
                    TRANSCRIPT.into()
                } else {
                    rows()
                },
                stderr: String::new(),
            })
        }
    }
    #[test]
    fn folder_facts_native_exact_batch_argv_shared_budget_and_missing_duplicate_refusal() {
        let names = vec!["INBOX".into(), "INBOX.Child".into()];
        let executor = Executor(std::sync::Arc::new(Mutex::new(Vec::new())));
        let backend = DoveadmMailboxListBackend::new(
            MailboxListingPolicy::default(),
            executor.clone(),
            "/fixed/doveadm",
        )
        .with_userdb_socket_path(Some("/private/userdb".into()));
        let facts = backend.folder_facts("alice@fixture.test", &names).unwrap();
        assert_eq!(executor.0.lock().unwrap().len(), 2);
        assert_eq!(facts.statuses()[0].mailbox(), "INBOX");
        assert_eq!(facts.status("INBOX.Child").unwrap().guid(), "b".repeat(32));
        let good = CommandExecution {
            status_code: 0,
            stdout: rows(),
            stderr: String::new(),
        };
        assert!(parse_native_facts(&names, &good).is_ok());
        for bad in [
            "[]".into(),
            rows().replace("INBOX.Child", "INBOX"),
            rows().replace("INBOX.Child", "Foreign"),
            rows().replace("\"0\"", "\"-1\""),
            rows().replace(&"a".repeat(32), &"0".repeat(32)),
        ] {
            assert!(parse_native_facts(
                &names,
                &CommandExecution {
                    stdout: bad,
                    ..good.clone()
                }
            )
            .is_err());
        }
        assert!(
            parse_native("INBOX", &good).is_err(),
            "legacy singleton parser does not silently accept a batch"
        );
    }
}
