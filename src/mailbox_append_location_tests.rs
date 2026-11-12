use super::*;
use crate::auth::{CommandExecution, CommandExecutionError};
use std::sync::{Arc, Mutex};
const ACCOUNT: &str = "alice@example.test";
const FOLDER: &str = "INBOX.CopyA";
const GUID: &str = "1234567890abcdef1234567890abcdef";
#[derive(Clone)]
struct Executor {
    calls: Arc<Mutex<Vec<Vec<String>>>>,
    before: &'static str,
    after: &'static str,
    folder: bool,
}
impl Executor {
    fn new(before: &'static str, after: &'static str, folder: bool) -> Self {
        Self {
            calls: Arc::default(),
            before,
            after,
            folder,
        }
    }
}
impl CommandExecutor for Executor {
    fn run_with_stdin_bytes(
        &self,
        _: &str,
        _: &[String],
        _: &[u8],
    ) -> Result<CommandExecution, CommandExecutionError> {
        panic!("unbounded operation forbidden")
    }
    fn run_with_stdin_bytes_timeout_and_output_limit(
        &self,
        program: &str,
        args: &[String],
        input: &[u8],
        timeout: Duration,
        limit: usize,
    ) -> Result<CommandExecution, CommandExecutionError> {
        assert_eq!(program, "/fixed/doveadm");
        assert!(!timeout.is_zero() && timeout <= Duration::from_secs(10));
        let mut calls = self.calls.lock().unwrap();
        calls.push(args.to_vec());
        let text = if args.first().map(String::as_str) == Some("exec") {
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
                    ACCOUNT
                ]
            );
            assert_eq!(input, crate::folder_metadata_backend::TRANSCRIPT);
            assert_eq!(limit, 512 * 1024);
            format!("* PREAUTH fixture\r\n* NAMESPACE ((\"\" \".\")) NIL NIL\r\nN1 OK done\r\n{}L1 OK done\r\n* BYE done\r\nZ1 OK done\r\n",if self.folder {"* LIST () \".\" \"INBOX.CopyA\"\r\n"}else{""})
        } else if args.iter().any(|v| v == "status") {
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
                    ACCOUNT,
                    "guid messages vsize",
                    FOLDER
                ]
            );
            assert!(input.is_empty());
            assert_eq!(limit, 4096);
            let guid = if calls.iter().any(|a| a.iter().any(|v| v == "save")) {
                self.after
            } else {
                self.before
            };
            serde_json::json!([{"mailbox":FOLDER,"guid":guid,"messages":"1","vsize":"32"}])
                .to_string()
        } else {
            assert_eq!(
                args,
                [
                    "-o",
                    "stats_writer_socket_path=",
                    "-o",
                    "auth_socket_path=/private/userdb",
                    "save",
                    "-u",
                    ACCOUNT,
                    "-m",
                    FOLDER
                ]
            );
            assert_eq!(input, b"Subject: fixture\r\n\r\npublic");
            assert_eq!(limit, 1024 * 1024);
            String::new()
        };
        Ok(CommandExecution {
            status_code: 0,
            stdout: text,
            stderr: String::new(),
        })
    }
}
fn request() -> MessageAppendRequest {
    MessageAppendRequest::new(FOLDER, b"Subject: fixture\r\n\r\npublic".to_vec())
        .unwrap()
        .with_destination_mailbox_guid(GUID)
        .unwrap()
}
fn backend(e: Executor) -> DoveadmMessageAppendBackend<Executor> {
    DoveadmMessageAppendBackend::new(e, "/fixed/doveadm")
        .with_userdb_socket_path(Some("/private/userdb".into()))
}
#[test]
fn sent_location_append_current_private_guid_qualifies_before_save_and_rechecks_after() {
    let e = Executor::new(GUID, GUID, true);
    backend(e.clone())
        .append_message(ACCOUNT, &request())
        .unwrap();
    let calls = e.calls.lock().unwrap();
    assert_eq!(calls.len(), 4);
    assert_eq!(
        calls
            .iter()
            .filter(|a| a.iter().any(|v| v == "save"))
            .count(),
        1
    );
}
#[test]
fn sent_location_append_missing_or_replaced_current_folder_never_saves_or_creates() {
    for e in [
        Executor::new(GUID, GUID, false),
        Executor::new("abcdef1234567890abcdef1234567890", GUID, true),
    ] {
        assert!(backend(e.clone())
            .append_message(ACCOUNT, &request())
            .is_err());
        assert!(e
            .calls
            .lock()
            .unwrap()
            .iter()
            .all(|a| !a.iter().any(|v| v == "save" || v == "create")));
    }
}
#[test]
fn sent_location_append_postsave_guid_drift_is_unconfirmed_and_never_retries() {
    let e = Executor::new(GUID, "abcdef1234567890abcdef1234567890", true);
    assert!(backend(e.clone())
        .append_message(ACCOUNT, &request())
        .is_err());
    assert_eq!(
        e.calls
            .lock()
            .unwrap()
            .iter()
            .filter(|a| a.iter().any(|v| v == "save"))
            .count(),
        1
    );
}
#[test]
fn sent_location_append_mutation_gate_busy_and_invalid_capture_refuse_without_native_calls() {
    let e = Executor::new(GUID, GUID, true);
    let gate = Arc::new(Mutex::new(()));
    let _held = gate.lock().unwrap();
    let backend = backend(e.clone()).with_operation_gate(Arc::clone(&gate));
    assert!(backend.append_message(ACCOUNT, &request()).is_err());
    assert!(e.calls.lock().unwrap().is_empty());
    let mut bad = request();
    bad.destination_mailbox_guid = Some("bad\nGUID".into());
    assert!(backend.append_message(ACCOUNT, &bad).is_err());
    assert!(e.calls.lock().unwrap().is_empty());
}
