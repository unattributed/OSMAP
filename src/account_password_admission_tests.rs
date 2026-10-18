use super::*;
use crate::auth::{CommandExecution, CommandExecutionError};
use sha2::{Digest, Sha256};
use std::fs::{self, OpenOptions};
use std::io::Write;
use std::os::unix::fs::{OpenOptionsExt, PermissionsExt};
use std::path::PathBuf;
use std::sync::{
    atomic::{AtomicU64, Ordering},
    Mutex,
};

const ALICE: &str = "alice@osmap-admission.invalid";
const BOB: &str = "bob@osmap-admission.invalid";
const KEY: &[u8; 32] = &[29; 32];
const STAMP: &str = "20261018120000";
struct Clock(AtomicU64);
impl TimeProvider for Clock {
    fn unix_timestamp(&self) -> u64 {
        self.0.load(Ordering::SeqCst)
    }
}
struct Fixture {
    root: PathBuf,
    store: Store,
    clock: Clock,
}
impl Fixture {
    fn new() -> Self {
        let root = std::env::temp_dir().join(format!(
            "osmap-password-admission-{}",
            crate::draft::generate_draft_id().unwrap()
        ));
        fs::create_dir(&root).unwrap();
        fs::set_permissions(&root, fs::Permissions::from_mode(0o700)).unwrap();
        // Explicit fixture provisioning, never reached from service requests.
        for account in [ALICE, BOB] {
            let stem = format!(
                "{:x}",
                Sha256::digest(
                    [b"osmap-account-epoch-v1\0".as_slice(), account.as_bytes()].concat()
                )
            );
            let record = format!("{{\"epoch\":7,\"state\":\"active\",\"changed_at\":\"{STAMP}\",\"intent\":null,\"used_intents\":[]}}");
            for (suffix, data) in [("lock", b"".as_slice()), ("json", record.as_bytes())] {
                let mut file = OpenOptions::new()
                    .write(true)
                    .create_new(true)
                    .mode(0o600)
                    .open(root.join(format!("{stem}.{suffix}")))
                    .unwrap();
                file.write_all(data).unwrap();
                file.sync_all().unwrap();
            }
        }
        let store = Store::open(&root, crate::openbsd::effective_uid()).unwrap();
        Self {
            root,
            store,
            clock: Clock(AtomicU64::new(1000)),
        }
    }
    fn request(&self, operation: Operation) -> Request {
        Request::issue(ALICE, operation, self.clock.unix_timestamp(), KEY).unwrap()
    }
}
impl Drop for Fixture {
    fn drop(&mut self) {
        let _ = fs::remove_dir_all(&self.root);
    }
}
struct Primary<'a> {
    fixture: &'a Fixture,
    code: i32,
    user: &'static str,
    late_wall: bool,
    calls: Mutex<Vec<(Vec<String>, Vec<u8>)>>,
}
impl CommandExecutor for Primary<'_> {
    fn run_with_stdin_bytes(
        &self,
        program: &str,
        args: &[String],
        input: &[u8],
    ) -> Result<CommandExecution, CommandExecutionError> {
        assert_eq!(program, crate::account_password_mail::PROGRAM);
        assert!(crate::account_password_mail::fixed_args(args));
        self.calls.lock().unwrap().push((args.into(), input.into()));
        assert!(
            self.fixture
                .store
                .lock_before(ALICE, Instant::now() + Duration::from_millis(2))
                .is_err(),
            "authentication did not hold the shared writer lock"
        );
        if self.late_wall {
            self.fixture.clock.0.store(1035, Ordering::SeqCst);
        }
        Ok(CommandExecution {
            status_code: self.code,
            stdout: if self.code == 0 {
                format!("auth succeeded\nuser={}\n", self.user)
            } else {
                "auth failed\n".into()
            },
            stderr: String::new(),
        })
    }
}
fn until() -> Instant {
    Instant::now() + Duration::from_secs(1)
}
fn primary(f: &Fixture) -> Primary<'_> {
    Primary {
        fixture: f,
        code: 0,
        user: ALICE,
        late_wall: false,
        calls: Mutex::new(vec![]),
    }
}
fn make_service<'a>(f: &'a Fixture, primary: &'a Primary<'a>) -> Service<'a, Primary<'a>, Clock> {
    Service::new(&f.store, primary, &f.clock, KEY, [ALICE.into()].into()).unwrap()
}

#[test]
fn authenticated_current_password_returns_existing_client_epoch_and_bound_status() {
    let f = Fixture::new();
    let p = primary(&f);
    let mut service = make_service(&f, &p);
    let request = f.request(Operation::Authenticate {
        password: "public current passphrase".into(),
    });
    let reply = service.process(&request.bytes().unwrap(), until()).unwrap();
    let (admitted, stamp) = Verifier::default()
        .response_with_status(&request, &reply, KEY, 1000)
        .unwrap();
    assert_eq!(
        admitted.unwrap(),
        crate::account_admission::Admission {
            account: ALICE.into(),
            epoch: 7
        }
    );
    assert_eq!(stamp.as_deref(), Some(STAMP));
    let calls = p.calls.lock().unwrap();
    assert_eq!(calls.len(), 1);
    assert_eq!(calls[0].1, b"public current passphrase\n");
    assert!(calls[0].0.iter().all(|arg| !arg.contains("passphrase")));
    assert!(!String::from_utf8(reply).unwrap().contains("passphrase"));
    assert_eq!(
        f.store
            .lock_before(BOB, until())
            .unwrap()
            .admission(Some(7))
            .unwrap()
            .epoch,
        7
    );
}

#[test]
fn admit_status_is_readonly_and_stale_epoch_refuses_without_primary_dispatch() {
    let f = Fixture::new();
    let p = primary(&f);
    let mut service = make_service(&f, &p);
    for (epoch, accepted) in [(7, true), (6, false)] {
        let request = f.request(Operation::Admit { epoch });
        let reply = service.process(&request.bytes().unwrap(), until()).unwrap();
        let result = Verifier::default().response_with_status(&request, &reply, KEY, 1000);
        if accepted {
            assert_eq!(result.unwrap().1.as_deref(), Some(STAMP));
        } else {
            assert_eq!(result.err(), Some(Error::Refused));
        }
    }
    assert!(p.calls.lock().unwrap().is_empty());
}

#[test]
fn pending_or_contained_refuses_both_operations_and_does_not_reopen_on_restart() {
    for contained in [false, true] {
        let f = Fixture::new();
        {
            let mut guard = f.store.lock_before(ALICE, until()).unwrap();
            guard.begin(7, &"a".repeat(64), 1000).unwrap();
            if contained {
                guard.contain().unwrap();
            }
        }
        let p = primary(&f);
        let mut service = make_service(&f, &p);
        for operation in [
            Operation::Authenticate {
                password: "public current passphrase".into(),
            },
            Operation::Admit { epoch: 7 },
        ] {
            let request = f.request(operation);
            let reply = service.process(&request.bytes().unwrap(), until()).unwrap();
            assert!(String::from_utf8(reply).unwrap().contains("rejected"));
        }
        assert!(p.calls.lock().unwrap().is_empty());
        assert!(f
            .store
            .lock_before(ALICE, until())
            .unwrap()
            .admission(Some(7))
            .is_err());
    }
}

#[test]
fn wrong_current_password_rejects_but_foreign_canonical_is_unavailable() {
    for (code, user, expected_error) in [(77, ALICE, false), (0, BOB, true)] {
        let f = Fixture::new();
        let mut p = primary(&f);
        p.code = code;
        p.user = user;
        let mut service = make_service(&f, &p);
        let request = f.request(Operation::Authenticate {
            password: "public wrong passphrase".into(),
        });
        let result = service.process(&request.bytes().unwrap(), until());
        if expected_error {
            assert_eq!(result.err(), Some(Error::Unavailable));
        } else {
            assert_eq!(
                Verifier::default()
                    .response_with_status(&request, &result.unwrap(), KEY, 1000)
                    .unwrap(),
                (None, None)
            );
        }
    }
}

#[test]
fn signed_nonce_scope_expiry_and_late_primary_never_admit_or_retry() {
    let f = Fixture::new();
    let p = primary(&f);
    let mut service = make_service(&f, &p);
    let request = f.request(Operation::Admit { epoch: 7 });
    let frame = request.bytes().unwrap();
    service.process(&frame, until()).unwrap();
    assert_eq!(service.process(&frame, until()).err(), Some(Error::Replay));
    let foreign = Request::issue(BOB, Operation::Admit { epoch: 7 }, 1000, KEY).unwrap();
    assert_eq!(
        service.process(&foreign.bytes().unwrap(), until()).err(),
        Some(Error::Refused)
    );
    assert_eq!(
        service.process(&frame, Instant::now()).err(),
        Some(Error::Expired)
    );
    let mut tampered = request.bytes().unwrap();
    *tampered.last_mut().unwrap() = b'!';
    assert!(service.process(&tampered, until()).is_err());
    let mut late = primary(&f);
    late.late_wall = true;
    let mut service = make_service(&f, &late);
    let auth = f.request(Operation::Authenticate {
        password: "public current passphrase".into(),
    });
    assert_eq!(
        service.process(&auth.bytes().unwrap(), until()).err(),
        Some(Error::Expired)
    );
    assert_eq!(late.calls.lock().unwrap().len(), 1);
}
