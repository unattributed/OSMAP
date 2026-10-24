use super::*;
use crate::auth::{CommandExecution, CommandExecutionError};
use sha2::{Digest, Sha256};
use std::cell::RefCell;
use std::fs;
use std::os::unix::fs::PermissionsExt;
use std::path::PathBuf;
use std::rc::Rc;

const ACCOUNT: &str = "alice@example.test";
const BOB: &str = "bob@example.test";
const CURRENT: &str = "public-old-value";
const NEW: &str = "public-new-passphrase";
const STAMP: &str = "20261018120000";
const KEY: [u8; 32] = [17; 32];
struct Clock;
impl TimeProvider for Clock {
    fn unix_timestamp(&self) -> u64 {
        100
    }
}
struct Scratch(PathBuf);
impl Scratch {
    fn new() -> Self {
        let path = std::env::temp_dir().join(format!(
            "osmap-password-service-{}",
            crate::draft::generate_draft_id().unwrap()
        ));
        fs::create_dir(&path).unwrap();
        fs::set_permissions(&path, fs::Permissions::from_mode(0o700)).unwrap();
        Self(path)
    }
    fn stem(account: &str) -> String {
        let mut hash = Sha256::new();
        hash.update(b"osmap-account-epoch-v1\0");
        hash.update(account.as_bytes());
        format!("{:x}", hash.finalize())
    }
    fn record(&self, account: &str) -> PathBuf {
        self.0.join(format!("{}.json", Self::stem(account)))
    }
    fn provision(&self, account: &str, state: &str) {
        let intent = (state != "active").then_some("a".repeat(64));
        for (name, bytes) in [
            (format!("{}.lock", Self::stem(account)), Vec::new()),
            (format!("{}.json", Self::stem(account)), serde_json::to_vec(&serde_json::json!({"epoch":3,"state":state,"changed_at":null,"intent":intent,"used_intents":[]})).unwrap()),
        ] {
            let path = self.0.join(name); fs::write(&path, bytes).unwrap(); fs::set_permissions(path, fs::Permissions::from_mode(0o600)).unwrap();
        }
    }
    fn status(&self) -> serde_json::Value {
        serde_json::from_slice(&fs::read(self.record(ACCOUNT)).unwrap()).unwrap()
    }
}
impl Drop for Scratch {
    fn drop(&mut self) {
        let _ = fs::remove_dir_all(&self.0);
    }
}
#[derive(Default)]
struct Trace {
    events: Vec<&'static str>,
    written: bool,
    sql_writes: usize,
    stored_row: Option<(String, String)>,
}
struct Executor {
    trace: Rc<RefCell<Trace>>,
    zero_rows: bool,
    malformed_receipt: bool,
}
fn hash() -> String {
    format!(
        "{{ARGON2ID}}$argon2id$v=19$m=65536,t=3,p=1${}${}",
        "S".repeat(22),
        "B".repeat(43)
    )
}
fn hex(value: &str) -> String {
    value.bytes().map(|b| format!("{b:02X}")).collect()
}
impl CommandExecutor for Executor {
    fn run_with_stdin_bytes(
        &self,
        _: &str,
        _: &[String],
        _: &[u8],
    ) -> Result<CommandExecution, CommandExecutionError> {
        panic!("bounded method required")
    }
    fn run_with_stdin_bytes_timeout_and_output_limit(
        &self,
        program: &str,
        _: &[String],
        input: &[u8],
        _: Duration,
        _: usize,
    ) -> Result<CommandExecution, CommandExecutionError> {
        let mut trace = self.trace.borrow_mut();
        let stdout = if program == crate::account_password_backend::HASH_PROGRAM {
            trace.events.push("hash");
            format!("{}\n", hash())
        } else if input.starts_with(b"START TRANSACTION;") {
            trace.events.push("write");
            trace.sql_writes += 1;
            let (stored_hash, modified) = trace.stored_row.clone().unwrap_or_else(|| {
                (
                    format!("{{BLF-CRYPT}}$2y$05${}", "A".repeat(53)),
                    "20261017120000".into(),
                )
            });
            let query = std::str::from_utf8(input).unwrap();
            let matches_snapshot = query.contains(&format!(
                "AND BINARY password=BINARY CONVERT(0x{} USING utf8mb4) AND modified=STR_TO_DATE('{}','%Y%m%d%H%i%s')",
                hex(&stored_hash), modified
            ));
            trace.written = !self.zero_rows && matches_snapshot;
            if trace.written {
                trace.stored_row = Some((hash(), STAMP.into()));
            }
            if self.malformed_receipt {
                "1\nunknown\n".into()
            } else {
                let (stored_hash, modified) =
                    trace.stored_row.clone().unwrap_or((stored_hash, modified));
                format!(
                    "{}\n{}\t{}\n",
                    u8::from(trace.written),
                    hex(&stored_hash),
                    modified
                )
            }
        } else {
            trace.events.push("read");
            let (stored_hash, modified) = trace.stored_row.clone().unwrap_or_else(|| {
                (
                    format!("{{BLF-CRYPT}}$2y$05${}", "A".repeat(53)),
                    "20261017120000".into(),
                )
            });
            format!("{}\t{}\t1\t1\n", hex(&stored_hash), modified)
        };
        Ok(CommandExecution {
            status_code: 0,
            stdout,
            stderr: String::new(),
        })
    }
}
struct Deps {
    trace: Rc<RefCell<Trace>>,
    failure: Option<&'static str>,
    record: PathBuf,
}
impl Deps {
    fn event(&self, name: &'static str) -> Result<(), DependencyError> {
        let state: serde_json::Value =
            serde_json::from_slice(&fs::read(&self.record).unwrap()).unwrap();
        assert_eq!(
            state["state"],
            if name == "authorize" {
                "active"
            } else {
                "pending"
            }
        );
        self.trace.borrow_mut().events.push(name);
        if self.failure == Some(name) {
            Err(DependencyError::Unavailable)
        } else {
            Ok(())
        }
    }
}
impl Dependencies for Deps {
    fn authorize(&self, _: &Request, _: Instant) -> Result<(), DependencyError> {
        self.event("authorize")
    }
    fn authenticate(
        &self,
        account: &str,
        password: &str,
        _: Instant,
    ) -> Result<bool, DependencyError> {
        assert_eq!(account, ACCOUNT);
        let written = self.trace.borrow().written;
        let name = if !written {
            "current"
        } else if password == CURRENT {
            "old"
        } else {
            "new"
        };
        self.event(name)?;
        if self.failure == Some("external-change") && !written {
            self.trace.borrow_mut().stored_row = Some((
                format!("{{BLF-CRYPT}}$2y$05${}", "C".repeat(53)),
                "20261018115959".into(),
            ));
        }
        if self.failure == Some("wrong-current") && !written {
            return Ok(false);
        }
        if password == CURRENT {
            Ok(!written || self.failure == Some("old-still-valid"))
        } else {
            assert_eq!(password, NEW);
            Ok(written && self.failure != Some("new-invalid"))
        }
    }
    fn preflight(&self, _: &Request, _: Instant) -> Result<(), DependencyError> {
        self.event("preflight")
    }
    fn confirm_pending(&self, _: &Request, _: Instant) -> Result<(), DependencyError> {
        self.event("pending")
    }
    fn before_write(&self, _: &Request, _: Instant) -> Result<(), DependencyError> {
        self.event("before-write")
    }
    fn invalidate_cache(&self, _: &str, _: Instant) -> Result<(), DependencyError> {
        self.event("flush")
    }
    fn finish_mail(&self, _: &str, _: Instant) -> Result<(), DependencyError> {
        self.event("finish")
    }
}
fn frame() -> Vec<u8> {
    crate::account_mutation::tests::issue(CURRENT, NEW, 3, 100)
        .unwrap()
        .bytes()
        .unwrap()
}
fn deadline() -> Instant {
    Instant::now() + Duration::from_secs(2)
}

#[test]
fn transaction_orders_real_store_pending_write_auth_mail_and_epoch() {
    let scratch = Scratch::new();
    scratch.provision(ACCOUNT, "active");
    scratch.provision(BOB, "active");
    let bob = fs::read(scratch.record(BOB)).unwrap();
    let store = Store::open(&scratch.0, crate::openbsd::effective_uid()).unwrap();
    let trace = Rc::new(RefCell::new(Trace::default()));
    let backend = Backend::new(Executor {
        trace: trace.clone(),
        zero_rows: false,
        malformed_receipt: false,
    });
    let deps = Deps {
        trace: trace.clone(),
        failure: None,
        record: scratch.record(ACCOUNT),
    };
    let mut service = Service::new(&store, &backend, &deps, &Clock, KEY);
    let (_, outcome) = service.execute(&frame(), deadline()).unwrap();
    assert_eq!(
        outcome,
        Outcome::Changed {
            epoch: 4,
            changed_at: STAMP.into()
        }
    );
    assert_eq!(
        trace.borrow().events,
        [
            "authorize",
            "read",
            "current",
            "preflight",
            "pending",
            "hash",
            "before-write",
            "write",
            "flush",
            "old",
            "new",
            "finish"
        ]
    );
    assert_eq!(trace.borrow().sql_writes, 1);
    let state = scratch.status();
    assert_eq!(state["epoch"], 4);
    assert_eq!(state["state"], "active");
    assert_eq!(state["changed_at"], STAMP);
    assert_eq!(fs::read(scratch.record(BOB)).unwrap(), bob);
    let record = fs::read_to_string(scratch.record(ACCOUNT)).unwrap();
    for secret in [CURRENT, NEW, &hash()] {
        assert!(!record.contains(secret));
    }
}

#[test]
fn external_credential_change_during_authentication_conflicts_with_original_snapshot() {
    let scratch = Scratch::new();
    scratch.provision(ACCOUNT, "active");
    scratch.provision(BOB, "active");
    let bob = fs::read(scratch.record(BOB)).unwrap();
    let store = Store::open(&scratch.0, crate::openbsd::effective_uid()).unwrap();
    let trace = Rc::new(RefCell::new(Trace::default()));
    let backend = Backend::new(Executor {
        trace: trace.clone(),
        zero_rows: false,
        malformed_receipt: false,
    });
    let deps = Deps {
        trace: trace.clone(),
        failure: Some("external-change"),
        record: scratch.record(ACCOUNT),
    };
    let mut service = Service::new(&store, &backend, &deps, &Clock, KEY);
    assert_eq!(
        service.execute(&frame(), deadline()).unwrap().1,
        Outcome::KnownRefused
    );
    let trace = trace.borrow();
    assert_eq!(trace.sql_writes, 1);
    assert!(!trace.written);
    assert_eq!(
        trace.stored_row,
        Some((
            format!("{{BLF-CRYPT}}$2y$05${}", "C".repeat(53)),
            "20261018115959".into()
        ))
    );
    assert!(!trace.events.contains(&"flush"));
    assert!(!trace.events.contains(&"finish"));
    let status = scratch.status();
    assert_eq!(status["state"], "active");
    assert_eq!(status["epoch"], 3);
    assert_eq!(status["changed_at"], serde_json::Value::Null);
    assert_eq!(status["used_intents"].as_array().unwrap().len(), 1);
    assert_eq!(fs::read(scratch.record(BOB)).unwrap(), bob);
}

#[test]
fn wrong_current_and_zero_row_are_known_no_write_with_durable_replay_refusal() {
    for (failure, zero_rows, count) in [(Some("wrong-current"), false, 0), (None, true, 1)] {
        let scratch = Scratch::new();
        scratch.provision(ACCOUNT, "active");
        let store = Store::open(&scratch.0, crate::openbsd::effective_uid()).unwrap();
        let trace = Rc::new(RefCell::new(Trace::default()));
        let backend = Backend::new(Executor {
            trace: trace.clone(),
            zero_rows,
            malformed_receipt: false,
        });
        let deps = Deps {
            trace: trace.clone(),
            failure,
            record: scratch.record(ACCOUNT),
        };
        let bytes = frame();
        let mut service = Service::new(&store, &backend, &deps, &Clock, KEY);
        assert_eq!(
            service.execute(&bytes, deadline()).unwrap().1,
            Outcome::KnownRefused
        );
        let state = scratch.status();
        assert_eq!(state["state"], "active");
        assert_eq!(state["epoch"], 3);
        assert_eq!(state["used_intents"].as_array().unwrap().len(), 1);
        let before = trace.borrow().sql_writes;
        assert_eq!(before, count);
        drop(service);
        let mut restarted = Service::new(&store, &backend, &deps, &Clock, KEY);
        assert_eq!(
            restarted.execute(&bytes, deadline()).unwrap().1,
            Outcome::KnownRefused
        );
        assert_eq!(trace.borrow().sql_writes, before);
    }
}

#[test]
fn failed_postwrite_effects_preserve_exact_time_and_never_reopen_account() {
    for failure in ["flush", "old-still-valid", "new-invalid", "finish"] {
        let scratch = Scratch::new();
        scratch.provision(ACCOUNT, "active");
        let store = Store::open(&scratch.0, crate::openbsd::effective_uid()).unwrap();
        let trace = Rc::new(RefCell::new(Trace::default()));
        let backend = Backend::new(Executor {
            trace: trace.clone(),
            zero_rows: false,
            malformed_receipt: false,
        });
        let deps = Deps {
            trace: trace.clone(),
            failure: Some(failure),
            record: scratch.record(ACCOUNT),
        };
        let mut service = Service::new(&store, &backend, &deps, &Clock, KEY);
        assert_eq!(
            service.execute(&frame(), deadline()).unwrap().1,
            Outcome::ChangedIncomplete {
                changed_at: STAMP.into()
            }
        );
        let state = scratch.status();
        assert_eq!(state["state"], "contained");
        assert_eq!(state["epoch"], 3);
        assert_eq!(state["changed_at"], STAMP);
        assert_eq!(trace.borrow().sql_writes, 1);
    }
}

#[test]
fn uncertain_prewrite_or_unknown_receipt_stays_contained() {
    for (failure, malformed, count) in [
        (Some("preflight"), false, 0),
        (Some("pending"), false, 0),
        (Some("before-write"), false, 0),
        (None, true, 1),
    ] {
        let scratch = Scratch::new();
        scratch.provision(ACCOUNT, "active");
        let store = Store::open(&scratch.0, crate::openbsd::effective_uid()).unwrap();
        let trace = Rc::new(RefCell::new(Trace::default()));
        let backend = Backend::new(Executor {
            trace: trace.clone(),
            zero_rows: false,
            malformed_receipt: malformed,
        });
        let deps = Deps {
            trace: trace.clone(),
            failure,
            record: scratch.record(ACCOUNT),
        };
        let mut service = Service::new(&store, &backend, &deps, &Clock, KEY);
        assert_eq!(
            service.execute(&frame(), deadline()).unwrap().1,
            Outcome::Contained
        );
        assert_eq!(scratch.status()["state"], "contained");
        assert_eq!(trace.borrow().sql_writes, count);
    }
}

#[test]
fn invalid_hmac_expiry_and_preexisting_safety_state_never_dispatch() {
    for state in ["active", "pending", "contained"] {
        let scratch = Scratch::new();
        scratch.provision(ACCOUNT, state);
        let before = fs::read(scratch.record(ACCOUNT)).unwrap();
        let store = Store::open(&scratch.0, crate::openbsd::effective_uid()).unwrap();
        let trace = Rc::new(RefCell::new(Trace::default()));
        let backend = Backend::new(Executor {
            trace: trace.clone(),
            zero_rows: false,
            malformed_receipt: false,
        });
        let deps = Deps {
            trace: trace.clone(),
            failure: None,
            record: scratch.record(ACCOUNT),
        };
        let mut service = Service::new(&store, &backend, &deps, &Clock, [18; 32]);
        assert!(matches!(
            service.execute(&frame(), deadline()),
            Err(Error::Authentication)
        ));
        assert!(matches!(
            service.execute(&frame(), Instant::now()),
            Err(Error::Expired)
        ));
        if state != "active" {
            let mut service = Service::new(&store, &backend, &deps, &Clock, KEY);
            assert_eq!(
                service.execute(&frame(), deadline()).unwrap().1,
                Outcome::Contained
            );
        }
        assert!(trace.borrow().events.is_empty());
        assert_eq!(fs::read(scratch.record(ACCOUNT)).unwrap(), before);
    }
}
