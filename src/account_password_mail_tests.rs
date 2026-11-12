use super::*;
use crate::auth::{CommandExecution, CommandExecutionError};
use std::collections::VecDeque;
use std::sync::Mutex;
const ALICE: &str = "alice@osmap-password.invalid";
const BOB: &str = "bob@osmap-password.invalid";
struct Fake {
    replies: Mutex<VecDeque<(i32, String)>>,
    calls: Mutex<Vec<(Vec<String>, Vec<u8>)>>,
    timeouts: Mutex<Vec<Duration>>,
}
impl Fake {
    fn new(rows: Vec<(i32, String)>) -> Self {
        Self {
            replies: Mutex::new(rows.into()),
            calls: Mutex::new(vec![]),
            timeouts: Mutex::new(vec![]),
        }
    }
}
impl CommandExecutor for Fake {
    fn run_with_stdin_bytes_timeout_and_output_limit(
        &self,
        program: &str,
        args: &[String],
        input: &[u8],
        timeout: Duration,
        cap: usize,
    ) -> Result<CommandExecution, CommandExecutionError> {
        assert_eq!(cap, LIMIT);
        self.timeouts.lock().unwrap().push(timeout);
        self.run_with_stdin_bytes(program, args, input)
    }
    fn run_with_stdin_bytes(
        &self,
        program: &str,
        args: &[String],
        input: &[u8],
    ) -> Result<CommandExecution, CommandExecutionError> {
        assert_eq!(program, PROGRAM);
        self.calls.lock().unwrap().push((args.into(), input.into()));
        let (status_code, stdout) = self
            .replies
            .lock()
            .unwrap()
            .pop_front()
            .expect("no extra utility dispatch");
        Ok(CommandExecution {
            status_code,
            stdout,
            stderr: String::new(),
        })
    }
}
fn until() -> Instant {
    Instant::now() + Duration::from_secs(1)
}
fn header() -> String {
    "username\tproto\tsrc ip\tdest ip\tport\n".into()
}

#[test]
fn fixed_primary_uses_private_socket_stdin_and_exact_account_result() {
    let fake = Fake::new(vec![
        (
            0,
            format!("passdb: {ALICE} auth succeeded\nextra fields:\n user={ALICE}\n"),
        ),
        (77, format!("passdb: {ALICE} auth failed\n")),
    ]);
    assert_eq!(
        primary(
            &fake,
            ALICE,
            "a private test password",
            Instant::now() + Duration::from_secs(60)
        ),
        Ok(true)
    );
    assert_eq!(
        primary(
            &fake,
            ALICE,
            "a private test password",
            Instant::now() + Duration::from_secs(60)
        ),
        Ok(false)
    );
    assert_eq!(
        *fake.timeouts.lock().unwrap(),
        vec![Duration::from_secs(25); 2]
    );
    let controls = Fake::new(vec![(0, "0 cache entries flushed\n".into())]);
    assert_eq!(
        flush(&controls, ALICE, Instant::now() + Duration::from_secs(60)),
        Ok(())
    );
    assert_eq!(
        *controls.timeouts.lock().unwrap(),
        vec![Duration::from_secs(10)]
    );
    let calls = fake.calls.lock().unwrap();
    assert!(fixed_args(&calls[0].0));
    assert_eq!(calls[0].1, b"a private test password\n");
    assert!(!calls[0]
        .0
        .iter()
        .any(|v| v.contains("private test password")));
    let other = Fake::new(vec![(0, format!("auth succeeded\nuser={BOB}\n"))]);
    assert_eq!(
        primary(&other, ALICE, "test", until()),
        Err(Error::Unavailable)
    );
}
#[test]
fn real_proxy_contract_kicks_only_bound_account_once_and_observes_zero() {
    let rows=format!("{}{ALICE}\tsubmission\t127.0.0.2\t127.0.0.1\t2525\n{BOB}\tsubmission\t127.0.0.3\t127.0.0.1\t2525\n",header());
    let after = format!(
        "{}{BOB}\tsubmission\t127.0.0.3\t127.0.0.1\t2525\n",
        header()
    );
    let fake = Fake::new(vec![
        (0, rows),
        (0, "1 connections kicked\n".into()),
        (0, after),
    ]);
    let namespace = SubmissionNamespace::fixture();
    let mut control = SubmissionControl::new(&fake, &namespace, ALICE).unwrap();
    assert_eq!(control.preflight(until()), Ok(1));
    assert_eq!(control.terminate(until()), Ok(()));
    assert_eq!(control.terminate(until()), Err(Error::Unavailable));
    let calls = fake.calls.lock().unwrap();
    assert_eq!(calls.len(), 3);
    assert_eq!(calls[1].0.last().unwrap(), ALICE);
    assert_eq!(calls[1].0, namespace.args(Some(ALICE)));
    assert!(calls.iter().all(|(_, input)| input.is_empty()));
}
#[test]
fn malformed_or_remaining_proxy_rows_refuse_without_second_kick() {
    for bad in [
        format!("{}{ALICE}\timap\t127.0.0.2\t127.0.0.1\t2525\n", header()),
        format!(
            "{}{ALICE}\tsubmission\t127.0.0.2\t127.0.0.9\t2525\n",
            header()
        ),
    ] {
        let fake = Fake::new(vec![(0, bad)]);
        let namespace = SubmissionNamespace::fixture();
        assert!(SubmissionControl::new(&fake, &namespace, ALICE)
            .unwrap()
            .preflight(until())
            .is_err());
        assert_eq!(fake.calls.lock().unwrap().len(), 1);
    }
    let row = format!(
        "{}{ALICE}\tsubmission\t127.0.0.2\t127.0.0.1\t2525\n",
        header()
    );
    let fake = Fake::new(vec![
        (0, row.clone()),
        (0, "1 connections kicked\n".into()),
        (0, row),
    ]);
    let namespace = SubmissionNamespace::fixture();
    let mut control = SubmissionControl::new(&fake, &namespace, ALICE).unwrap();
    control.preflight(until()).unwrap();
    assert!(control.terminate(until()).is_err());
    assert!(control.terminate(until()).is_err());
    assert_eq!(fake.calls.lock().unwrap().len(), 3);
}
#[test]
fn cache_acknowledgement_requires_exact_count_and_bound_command() {
    let fake = Fake::new(vec![(0, "2 cache entries flushed\n".into())]);
    assert_eq!(flush(&fake, ALICE, until()), Ok(()));
    assert_eq!(fake.calls.lock().unwrap()[0].0.last().unwrap(), ALICE);
    let wrong = Fake::new(vec![(0, "ambiguous cache reply\n".into())]);
    assert!(flush(&wrong, ALICE, until()).is_err());
    assert_eq!(wrong.calls.lock().unwrap().len(), 1);
}
#[test]
fn caller_socket_flags_and_shell_accounts_never_become_commands() {
    assert!(!fixed_args(&["kick".into(), "-A".into()]));
    assert!(!fixed_args(&[
        "kick".into(),
        "-a".into(),
        "/var/dovecot/anvil".into(),
        ALICE.into()
    ]));
    assert!(!fixed_args(
        &account_args(WHO, ALICE)
            .unwrap()
            .into_iter()
            .chain(["-f".into()])
            .collect::<Vec<_>>()
    ));
    assert!(account_args(PRIMARY, "alice;id@example.invalid").is_err());
    let fake = Fake::new(vec![]);
    assert!(primary(&fake, ALICE, "bad\ninput", until()).is_err());
    assert!(fake.calls.lock().unwrap().is_empty());
}
