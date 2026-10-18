use super::*;
use crate::auth::{CommandExecution, CommandExecutionError};
const ACCOUNT: &str = "alice@osmap-peer.invalid";
fn process(pid: u32, parent: u32, uid: u32, command: &str) -> Row {
    row(
        &format!("{pid} {parent} 10 {uid} {uid} Sun Oct 18 01:02:03 2026 {command}\n"),
        pid,
    )
    .unwrap()
}
fn pin() -> FilePin {
    FilePin {
        path: IMAP,
        dev: 0,
        inode: 42,
        mode: 0o100555,
        size: 100,
        modified: (0, 0),
        changed: (0, 0),
    }
}
fn header() -> &'static str {
    "USER CMD PID FD DEV INUM MODE R/W SZ|DV\n"
}

#[test]
fn exact_process_birth_parent_principal_and_executable_are_bound() {
    let master = process(10, 1, 0, "dovecot");
    let own = process(30, 1, 0, "password-helper");
    let child = process(20, 10, 518, "imap");
    let rows = vec![master.clone(), child.clone(), own.clone()];
    assert_eq!(roles(&rows, &master, &own, (20, 518, 518)), Ok(()));
    for changed in [
        process(20, 11, 518, "imap"),
        process(20, 10, 519, "imap"),
        process(20, 10, 518, "sh"),
    ] {
        assert_eq!(
            roles(
                &[master.clone(), changed, own.clone()],
                &master,
                &own,
                (20, 518, 518)
            ),
            Err(Error::Refused)
        );
    }
    for raw in ["020 10 10 518 518 Sun Oct 18 01:02:03 2026 imap\n","20 10 10 518 518 Sun Oct 18 25:02:03 2026 imap\n","20 10 10 518 518 Sun Oct 18 01:02:03 2026 imap\n20 10 10 518 518 Sun Oct 18 01:02:03 2026 imap\n"]{assert!(row(raw,20).is_err());}
    let mut changed = rows.clone();
    changed[0].birth = "Sun Oct 18 01:02:04 2026".into();
    assert_eq!(
        roles(&changed, &master, &own, (20, 518, 518)),
        Err(Error::Refused)
    );
}

#[test]
fn exact_text_inode_and_reciprocal_accepted_descriptor_are_required() {
    let process = process(20, 10, 518, "imap");
    let raw = format!(
        "{}mail imap 20 text 0, 0 42 100555 r 100\nmail imap 20 7* unix stream 0x11 <-> 0x22\n",
        header()
    );
    let peer = descriptors(&raw, &process, &pin()).unwrap();
    let own = [(8, (0x22, 0x11))].into();
    assert_eq!(reciprocal(&own, &peer, 8), Ok((0x22, 0x11)));
    assert!(reciprocal(&own, &peer, 9).is_err());
    let mut wrong = peer.clone();
    wrong.insert(9, (0x11, 0x22));
    assert!(reciprocal(&own, &wrong, 8).is_err());
    for invalid in [
        raw.replace("42 100555", "43 100555"),
        raw.replace("0x11 <-> 0x22", "0x11 <-> 0x00"),
        raw.replace("7* unix", "7 unix"),
        raw.replace("imap 20 text", "sh 20 text"),
    ] {
        assert!(descriptors(&invalid, &process, &pin()).is_err());
    }
}

#[test]
fn actual_anvil_row_requires_single_exact_account_pid_and_count() {
    let row = format!("{WHO_HEADER}{ACCOUNT}\t1\timap\t(1234)\t(127.0.0.1)\n");
    assert_eq!(registered(&row, ACCOUNT, 1234), Ok(()));
    for invalid in [
        row.replace(ACCOUNT, "bob@osmap-peer.invalid"),
        row.replace("(1234)", "(1235)"),
        row.replace("(1234)", "(1234 1234)"),
        row.replace("\t1\timap", "\t2\timap"),
        row.replace("\timap\t", "\tsubmission\t"),
        format!("{row}{ACCOUNT}\t1\timap\t(1234)\t(127.0.0.1)\n"),
    ] {
        assert!(registered(&invalid, ACCOUNT, 1234).is_err());
    }
}

struct Never;
impl CommandExecutor for Never {
    fn run_with_stdin_bytes(
        &self,
        _: &str,
        _: &[String],
        _: &[u8],
    ) -> Result<CommandExecution, CommandExecutionError> {
        panic!("foreign native factory dispatched command")
    }
}
#[test]
fn unknown_native_authority_never_creates_peer_or_dispatches_metadata() {
    if !crate::openbsd::password_native_authority() {
        assert!(Startup::native(&Never, 10, Instant::now() + Duration::from_millis(500)).is_err());
    }
    assert_eq!(ps_args(1234), vec!["-p", "1234", "-o", PS_FIELDS]);
    assert_eq!(fstat_args(1234), vec!["-n", "-p", "1234"]);
}
