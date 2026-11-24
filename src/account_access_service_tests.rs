use super::*;
use crate::auth::{CommandExecution, CommandExecutionError, RequiredSecondFactor};
use crate::recovery_contact::RecoveryContactDelivery;
use crate::session::{FileSessionStore, SessionRecord, SessionStore};
use std::cell::{Cell, RefCell};
use std::fs;
use std::os::unix::fs::{MetadataExt, PermissionsExt};

const ACCOUNT: &str = "alice@recovery.invalid";
const OTHER: &str = "bob@recovery.invalid";
const NEW_ACCOUNT: &str = "new-user@recovery.invalid";
const NEW_CONTACT: &str = "new-owner@independent.test";
const CSRF: &str = "ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff";
const SESSION: &str = "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa";
const BASELINE: &str = "secret=GEZDGNBVGY3TQOJQGEZDGNBVGY3TQOJQ\n";
fn now() -> u64 {
    SystemTimeProvider.unix_timestamp()
}
const STAMP: &str = "20261030010000";
const NEW_PASSWORD: &str = "public replacement password";
fn deadline() -> Instant {
    Instant::now() + Duration::from_secs(3)
}
struct Fixture {
    root: PathBuf,
    service: NativeAccess,
    accounts: BTreeSet<String>,
    cache_checks: Cell<usize>,
    refuse_cache: Cell<bool>,
}
impl Fixture {
    fn new() -> Self {
        let root = std::env::temp_dir().join(format!(
            "osmap-native-access-{}",
            crate::draft::generate_draft_id().unwrap()
        ));
        for name in [
            "", "epoch", "sessions", "factors", "revoked", "settings", "access",
        ] {
            let path = root.join(name);
            fs::create_dir_all(&path).unwrap();
            fs::set_permissions(&path, fs::Permissions::from_mode(0o700)).unwrap();
        }
        let meta = fs::metadata(&root).unwrap();
        for account in [ACCOUNT, OTHER] {
            let id = sha([b"osmap-account-epoch-v1\0".as_slice(), account.as_bytes()]
                .concat()
                .as_slice());
            fs::write(root.join("epoch").join(format!("{id}.json")), b"{\"epoch\":3,\"state\":\"active\",\"changed_at\":null,\"intent\":null,\"used_intents\":[]}").unwrap();
            fs::write(root.join("epoch").join(format!("{id}.lock")), b"").unwrap();
        }
        for entry in fs::read_dir(root.join("epoch")).unwrap() {
            fs::set_permissions(entry.unwrap().path(), fs::Permissions::from_mode(0o600)).unwrap();
        }
        let factors = crate::totp::FileTotpSecretStore::new(root.join("factors"));
        fs::write(factors.secret_path_for_username(ACCOUNT), BASELINE).unwrap();
        fs::set_permissions(
            factors.secret_path_for_username(ACCOUNT),
            fs::Permissions::from_mode(0o600),
        )
        .unwrap();
        let sessions = FileSessionStore::new(root.join("sessions"));
        for (account, id) in [(ACCOUNT, SESSION.to_owned()), (OTHER, "b".repeat(64))] {
            sessions
                .save(&SessionRecord {
                    account_epoch: Some(3),
                    session_id: id,
                    csrf_token: CSRF.into(),
                    canonical_username: account.into(),
                    issued_at: now() - 100,
                    expires_at: now() + 1000,
                    last_seen_at: now() - 10,
                    revoked_at: None,
                    remote_addr: "127.0.0.1".into(),
                    user_agent: "native-source-fixture".into(),
                    factor: RequiredSecondFactor::Totp,
                })
                .unwrap();
        }
        let contact = crate::private_account_file::PrivateAccountFile::new(
            root.join("settings/recovery-contact-v1"),
            "osmap-recovery-contact-v1",
            16384,
        );
        contact
            .lock(ACCOUNT)
            .unwrap()
            .write(
                &serde_json::to_vec(&serde_json::json!({
                    "version":1,"account":ACCOUNT,"revision":1,"updated_at":1,
                    "verified":{"email":"registered@example.test","verified_at":1},
                    "pending":null,"notice":null,"sends":[]
                }))
                .unwrap(),
            )
            .unwrap();
        let service = NativeAccess {
            config: Config {
                version: 1,
                initial_setup: false,
                contacts: vec![Contact {
                    account: ACCOUNT.into(),
                    email: "registered@example.test".into(),
                    revision: 1,
                    verified_at: 1,
                }],
            },
            config_sha256: String::new(),
            paths: crate::account_recovery_operator::RuntimePaths {
                session_directory: root.join("sessions"),
                factor_directory: root.join("factors"),
                replay_directory: root.join("replay"),
                revoked_directory: root.join("revoked"),
                settings_directory: root.join("settings"),
            },
            uid: meta.uid(),
            gid: meta.gid(),
            root: root.join("access"),
            selected: Some(BTreeSet::from([ACCOUNT.into()])),
            automatic_enrollment: false,
            session_idle_seconds: 900,
            epoch_root: root.join("epoch"),
            operator_uid: meta.uid(),
        };
        Self {
            root,
            service,
            accounts: [ACCOUNT.into(), OTHER.into()].into_iter().collect(),
            cache_checks: Cell::new(0),
            refuse_cache: Cell::new(false),
        }
    }
    fn epochs(&self) -> EpochStore {
        EpochStore::open(&self.root.join("epoch"), self.service.operator_uid).unwrap()
    }
    fn action(
        &self,
        authority: Authority,
        action: Action,
        db: &Backend<Commands>,
        primary: &Commands,
    ) -> Result<AccessOutcome, AccessError> {
        let request =
            Request::issue(authority, action, CSRF, "127.0.0.1", now(), &[b'k'; 64]).unwrap();
        self.service.execute(
            &request,
            &self.epochs(),
            &self.accounts,
            db,
            primary,
            &|budget| {
                assert!(budget > Instant::now());
                self.cache_checks.set(self.cache_checks.get() + 1);
                if self.refuse_cache.get() {
                    Err(AccessError::Unavailable)
                } else {
                    Ok(())
                }
            },
            now(),
            deadline(),
        )
    }
    fn session(&self) -> Authority {
        Authority::Session {
            account: ACCOUNT.into(),
            epoch: 3,
            session_id: SESSION.into(),
        }
    }
    fn current_factor(&self) -> Vec<u8> {
        fs::read(
            crate::totp::FileTotpSecretStore::new(&self.service.paths.factor_directory)
                .secret_path_for_username(ACCOUNT),
        )
        .unwrap()
    }
    fn assert_active(&self, epoch: u64) {
        assert_eq!(
            self.epochs()
                .lock_before(ACCOUNT, deadline())
                .unwrap()
                .admission(Some(epoch))
                .unwrap()
                .epoch,
            epoch
        );
    }
}
impl Drop for Fixture {
    fn drop(&mut self) {
        let _ = fs::remove_dir_all(&self.root);
    }
}
#[derive(Default)]
struct Commands {
    written: RefCell<bool>,
    calls: RefCell<usize>,
    registration_read: Option<Result<String, ()>>,
    initial_root: Option<PathBuf>,
    initial_approved: u64,
}
fn new_hash() -> String {
    format!(
        "{{ARGON2ID}}$argon2id$v=19$m=65536,t=3,p=1${}${}",
        "S".repeat(22),
        "B".repeat(43)
    )
}
impl CommandExecutor for Commands {
    fn run_with_stdin_bytes(
        &self,
        _: &str,
        _: &[String],
        _: &[u8],
    ) -> Result<CommandExecution, CommandExecutionError> {
        panic!("unbounded utility dispatch")
    }
    fn run_with_stdin_bytes_timeout_and_output_limit(
        &self,
        program: &str,
        args: &[String],
        input: &[u8],
        timeout: Duration,
        limit: usize,
    ) -> Result<CommandExecution, CommandExecutionError> {
        assert!(!timeout.is_zero());
        assert!(limit <= 4096);
        *self.calls.borrow_mut() += 1;
        let text = if program == crate::account_password_backend::SQL_PROGRAM {
            let query = std::str::from_utf8(input).unwrap();
            if let Some(reply) = &self.registration_read {
                assert!(query.starts_with("SELECT HEX(o.username),HEX(i.username)"));
                reply.clone().map_err(|()| CommandExecutionError {
                    reason: "SQL unavailable".into(),
                })?
            } else if let Some(root) = &self.initial_root {
                let hex = |value: &str| {
                    value
                        .as_bytes()
                        .iter()
                        .map(|b| format!("{b:02X}"))
                        .collect::<String>()
                };
                if query.contains("START TRANSACTION;") {
                    assert!(!*self.written.borrow());
                    let factors = crate::totp::FileTotpSecretStore::new(root.join("factors"));
                    assert!(factors.secret_path_for_username(NEW_ACCOUNT).is_file());
                    assert!(fs::read_dir(root.join("replay")).unwrap().any(|e| e
                        .unwrap()
                        .path()
                        .extension()
                        .is_some_and(|s| s == "counter")));
                    let contact = crate::recovery_contact::RecoveryContactStore::new(
                        root.join("settings/recovery-contact-v1"),
                    )
                    .snapshot(NEW_ACCOUNT, now())
                    .unwrap();
                    assert_eq!(contact.verified.unwrap().email, NEW_CONTACT);
                    let store =
                        EpochStore::open(&root.join("epoch"), fs::metadata(root).unwrap().uid())
                            .unwrap();
                    assert_eq!(
                        store
                            .lock_before(NEW_ACCOUNT, deadline())
                            .unwrap()
                            .admission(Some(0))
                            .unwrap()
                            .epoch,
                        0
                    );
                    assert!(query.contains("SET status='complete',activated=UTC_TIMESTAMP()"));
                    *self.written.borrow_mut() = true;
                    "activated\n".into()
                } else if query.starts_with("SELECT HEX(o.username),HEX(i.username)") {
                    let phase = if *self.written.borrow() {
                        "complete"
                    } else {
                        "pending"
                    };
                    format!(
                        "{0}\t{0}\t{1}\tmailbox.create\t{2}\t{2}\t{phase}\t{3}\n",
                        hex(NEW_ACCOUNT),
                        hex(NEW_ACCOUNT.split_once('@').unwrap().1),
                        "c".repeat(64),
                        u8::from(*self.written.borrow())
                    )
                } else if query.contains("UNIX_TIMESTAMP(i.activated)") {
                    if *self.written.borrow() {
                        format!(
                            "{}\t{}\t1\t{}\n",
                            hex(NEW_ACCOUNT),
                            hex(NEW_CONTACT),
                            self.initial_approved
                        )
                    } else {
                        String::new()
                    }
                } else if query.contains("UNIX_TIMESTAMP(i.created)") {
                    if *self.written.borrow() {
                        String::new()
                    } else {
                        format!(
                            "{}\t{}\t{}\t1\t{}\t{}\t{}\t1\n",
                            hex(NEW_ACCOUNT),
                            hex(NEW_CONTACT),
                            "c".repeat(64),
                            self.initial_approved,
                            "d".repeat(64),
                            "a".repeat(32)
                        )
                    }
                } else {
                    assert!(*self.written.borrow());
                    assert!(query.starts_with("SELECT HEX(m.password)"));
                    format!("{}\t{STAMP}\n", hex(&new_hash()))
                }
            } else if input.starts_with(b"SELECT HEX(password)") {
                let h = format!("{{BLF-CRYPT}}$2y$05${}", "A".repeat(53));
                format!(
                    "{}\t{STAMP}\t1\t1\n",
                    h.as_bytes()
                        .iter()
                        .map(|b| format!("{b:02X}"))
                        .collect::<String>()
                )
            } else {
                assert!(input.starts_with(b"START TRANSACTION;"));
                assert!(!*self.written.borrow());
                *self.written.borrow_mut() = true;
                format!(
                    "1\n{}\t{STAMP}\n",
                    new_hash()
                        .as_bytes()
                        .iter()
                        .map(|b| format!("{b:02X}"))
                        .collect::<String>()
                )
            }
        } else if args.iter().any(|s| s == "pw") {
            format!("{}\n", new_hash())
        } else if args.iter().any(|s| s == "cache") {
            return Err(CommandExecutionError {
                reason: "unsupported stock FLUSH".into(),
            });
        } else {
            let account = if args.iter().any(|arg| arg == NEW_ACCOUNT) {
                NEW_ACCOUNT
            } else {
                ACCOUNT
            };
            format!("auth succeeded\nuser={account}\n")
        };
        Ok(CommandExecution {
            status_code: 0,
            stdout: text,
            stderr: String::new(),
        })
    }
}
fn code(enrollment: &PendingEnrollment) -> String {
    let bytes = crate::totp::decode_base32(&enrollment.secret_base32).unwrap();
    crate::totp::generate_totp_code(&bytes, now() / 30, crate::totp::TotpPolicy::default()).unwrap()
}
#[test]
fn signed_in_replacement_requires_fresh_proofs_and_commits_real_files() {
    let f = Fixture::new();
    let db = Backend::new(Commands::default());
    let primary = Commands::default();
    let first = f.current_factor();
    assert!(f
        .action(
            f.session(),
            Action::BeginReset {
                password: "public old password".into(),
                totp: "000000".into()
            },
            &db,
            &primary
        )
        .is_err());
    assert_eq!(first, f.current_factor());
    f.assert_active(3);
    let current = crate::totp::generate_totp_code(
        &crate::totp::decode_base32("GEZDGNBVGY3TQOJQGEZDGNBVGY3TQOJQ").unwrap(),
        now() / 30,
        crate::totp::TotpPolicy::default(),
    )
    .unwrap();
    let begun = f
        .action(
            f.session(),
            Action::BeginReset {
                password: "public old password".into(),
                totp: current,
            },
            &db,
            &primary,
        )
        .unwrap();
    let AccessView::TotpReplacement { enrollment, .. } = begun.view else {
        panic!("no enrollment")
    };
    assert_eq!(first, f.current_factor());
    let confirmed = f
        .action(
            f.session(),
            Action::Confirm {
                enrollment_id: enrollment.id.clone(),
                revision: enrollment.revision,
                code: code(&enrollment),
                password: None,
                confirmation: None,
            },
            &db,
            &primary,
        )
        .unwrap();
    assert!(matches!(confirmed.view, AccessView::Complete));
    assert_ne!(first, f.current_factor());
    f.assert_active(4);
    assert!(f
        .action(f.session(), Action::View {}, &db, &primary)
        .is_err());
    let sessions = FileSessionStore::new(&f.service.paths.session_directory);
    assert!(sessions
        .load(SESSION)
        .unwrap()
        .unwrap()
        .revoked_at
        .is_some());
    assert!(sessions
        .load(&"b".repeat(64))
        .unwrap()
        .unwrap()
        .revoked_at
        .is_none());
}
struct Mail(RefCell<String>);
impl recovery::Notifier for Mail {
    fn deliver(
        &self,
        account: &str,
        email: &str,
        code: &str,
        _: u64,
        _: Instant,
    ) -> RecoveryContactDelivery {
        assert_eq!(
            email,
            if account == NEW_ACCOUNT {
                NEW_CONTACT
            } else {
                "registered@example.test"
            }
        );
        *self.0.borrow_mut() = code.into();
        RecoveryContactDelivery::Accepted
    }
}
#[test]
fn email_grant_commits_password_and_factor_under_one_native_fence() {
    let f = Fixture::new();
    let (token, enrollment) = email_enrollment(&f);
    let db = Backend::new(Commands::default());
    let primary = Commands::default();
    let result = f
        .action(
            Authority::Grant {
                token: token.clone(),
            },
            Action::Confirm {
                enrollment_id: enrollment.id.clone(),
                revision: enrollment.revision,
                code: code(&enrollment),
                password: Some(NEW_PASSWORD.into()),
                confirmation: Some(NEW_PASSWORD.into()),
            },
            &db,
            &primary,
        )
        .unwrap();
    assert!(matches!(result.view, AccessView::Complete));
    f.assert_active(4);
    let epochs = f.epochs();
    let eligible = Eligible {
        service: &f.service,
        accounts: &f.accounts,
        epochs: &epochs,
        backend: &db,
    };
    assert!(f
        .service
        .recovery()
        .lookup_grant(&token, CSRF, now(), deadline(), &eligible)
        .is_err());
    assert_eq!(f.cache_checks.get(), 1);
    assert_ne!(f.current_factor(), BASELINE.as_bytes());
    assert_eq!(
        f.epochs()
            .lock_before(ACCOUNT, deadline())
            .unwrap()
            .status()
            .unwrap()
            .changed_at
            .as_deref(),
        Some(STAMP)
    );
}

fn email_enrollment(f: &Fixture) -> (String, PendingEnrollment) {
    let db = Backend::new(Commands::default());
    email_enrollment_for(f, ACCOUNT, &db)
}
fn email_enrollment_for(
    f: &Fixture,
    account: &str,
    db: &Backend<Commands>,
) -> (String, PendingEnrollment) {
    let epochs = f.epochs();
    let eligible = Eligible {
        service: &f.service,
        accounts: &f.accounts,
        epochs: &epochs,
        backend: db,
    };
    let mail = Mail(RefCell::new(String::new()));
    let started = f
        .service
        .recovery()
        .start(
            recovery::Start {
                account,
                source: "127.0.0.1",
                flow: CSRF,
                now: now(),
                deadline: deadline(),
            },
            &eligible,
            &mail,
        )
        .unwrap();
    let grant = f
        .service
        .recovery()
        .verify_challenge(
            &started.challenge_id,
            CSRF,
            "127.0.0.1",
            &mail.0.borrow(),
            now(),
            deadline(),
            &eligible,
        )
        .unwrap();
    let binding = f
        .service
        .grant_binding(&grant.binding, grant.token(), deadline())
        .unwrap();
    let enrollment = f.service.begin(binding, now(), deadline()).unwrap();
    (grant.token().into(), enrollment)
}

#[test]
fn admin_recorded_contact_uses_existing_email_proof_for_first_setup_and_later_recovery() {
    first_setup_and_later_recovery(false);
}

#[test]
fn automatic_initial_setup_enrolls_without_a_manual_roster_or_rollout_entry() {
    first_setup_and_later_recovery(true);
}

fn first_setup_and_later_recovery(automatic: bool) {
    let mut f = Fixture::new();
    f.service.config.initial_setup = true;
    f.service.automatic_enrollment = automatic;
    if !automatic {
        f.service.selected = Some(BTreeSet::from([ACCOUNT.into(), NEW_ACCOUNT.into()]));
        f.accounts.insert(NEW_ACCOUNT.into());
    }
    fs::create_dir(f.root.join("replay")).unwrap();
    fs::set_permissions(f.root.join("replay"), fs::Permissions::from_mode(0o700)).unwrap();
    let db = Backend::new(Commands {
        initial_root: Some(f.root.clone()),
        initial_approved: now(),
        ..Commands::default()
    });
    let (token, enrollment) = email_enrollment_for(&f, NEW_ACCOUNT, &db);
    let result = f
        .action(
            Authority::Grant {
                token: token.clone(),
            },
            Action::Confirm {
                enrollment_id: enrollment.id.clone(),
                revision: enrollment.revision,
                code: code(&enrollment),
                password: Some(NEW_PASSWORD.into()),
                confirmation: Some(NEW_PASSWORD.into()),
            },
            &db,
            &Commands::default(),
        )
        .unwrap();
    assert!(matches!(result.view, AccessView::Complete));
    let epochs = f.epochs();
    let authority = Eligible {
        service: &f.service,
        accounts: &f.accounts,
        epochs: &epochs,
        backend: &db,
    };
    assert!(f
        .service
        .recovery()
        .lookup_grant(&token, CSRF, now(), deadline(), &authority)
        .is_err());
    let registered = recovery::Authority::eligible(&authority, NEW_ACCOUNT, deadline())
        .unwrap()
        .unwrap();
    assert_eq!(registered.purpose, recovery::Purpose::AccountRecoverySetup);
    assert!(registered.factor.existing_sha256().is_some());
    assert_eq!(registered.verified_email, NEW_CONTACT);
    f.service.automatic_enrollment = false;
    f.service.selected = Some(BTreeSet::from([ACCOUNT.into()]));
    let authority = Eligible {
        service: &f.service,
        accounts: &f.accounts,
        epochs: &epochs,
        backend: &db,
    };
    assert!(
        recovery::Authority::eligible(&authority, NEW_ACCOUNT, deadline())
            .unwrap()
            .is_none()
    );
}

#[test]
fn unavailable_sql_and_ineligible_creation_have_distinct_recovery_outcomes() {
    let username: String = NEW_ACCOUNT
        .bytes()
        .map(|byte| format!("{byte:02X}"))
        .collect();
    let domain: String = NEW_ACCOUNT
        .split_once('@')
        .unwrap()
        .1
        .bytes()
        .map(|byte| format!("{byte:02X}"))
        .collect();
    let operation = "b".repeat(64);
    let orphan =
        format!("{username}\tNULL\t{domain}\tmailbox.create\t{operation}\tNULL\tNULL\t0\n");
    let conflict = format!(
        "{username}\t{username}\t{domain}\tmailbox.create\t{operation}\t{}\tpending\t0\n",
        "d".repeat(64)
    );
    for reply in [Ok(String::new()), Ok(orphan), Ok(conflict), Err(())] {
        let mut f = Fixture::new();
        f.service.config.initial_setup = true;
        f.service.automatic_enrollment = true;
        let failed = reply.is_err();
        let db = Backend::new(Commands {
            registration_read: Some(reply),
            ..Default::default()
        });
        let epochs = f.epochs();
        let authority = Eligible {
            service: &f.service,
            accounts: &f.accounts,
            epochs: &epochs,
            backend: &db,
        };
        let mail = Mail(RefCell::new(String::new()));
        let started = f.service.recovery().start(
            recovery::Start {
                account: NEW_ACCOUNT,
                source: "127.0.0.1",
                flow: CSRF,
                now: now(),
                deadline: deadline(),
            },
            &authority,
            &mail,
        );
        if failed {
            assert!(matches!(started, Err(recovery::Error::Unavailable)));
        } else {
            let started = started.unwrap();
            assert!(!started.source_limited && !started.challenge_id.is_empty());
        }
        assert!(mail.0.borrow().is_empty());
    }
}

#[test]
fn pending_setup_requires_the_native_roster_and_selected_rollout() {
    let mut f = Fixture::new();
    f.service.config.initial_setup = true;
    // This executor intentionally cannot answer pending SQL. Both refusals
    // must occur before SQL, email submission or state creation.
    let db = Backend::new(Commands::default());
    let epochs = f.epochs();
    for selected in [NEW_ACCOUNT, ACCOUNT] {
        f.service.selected = Some(BTreeSet::from([selected.into()]));
        if selected == ACCOUNT {
            f.accounts.insert(NEW_ACCOUNT.into());
        }
        let authority = Eligible {
            service: &f.service,
            accounts: &f.accounts,
            epochs: &epochs,
            backend: &db,
        };
        assert!(
            recovery::Authority::eligible(&authority, NEW_ACCOUNT, deadline())
                .unwrap()
                .is_none()
        );
    }
    assert!(!f.root.join("replay").exists());
    assert!(
        !crate::totp::FileTotpSecretStore::new(f.root.join("factors"))
            .secret_path_for_username(NEW_ACCOUNT)
            .exists()
    );
}

#[test]
fn cache_zero_refusal_preserves_confirmed_sql_stamp_without_releasing_or_retrying() {
    let f = Fixture::new();
    let (token, enrollment) = email_enrollment(&f);
    let db = Backend::new(Commands::default());
    let primary = Commands::default();
    f.refuse_cache.set(true);
    let result = f.action(
        Authority::Grant { token },
        Action::Confirm {
            enrollment_id: enrollment.id.clone(),
            revision: enrollment.revision,
            code: code(&enrollment),
            password: Some(NEW_PASSWORD.into()),
            confirmation: Some(NEW_PASSWORD.into()),
        },
        &db,
        &primary,
    );
    assert!(matches!(result, Err(AccessError::Unconfirmed)));
    assert_eq!(f.cache_checks.get(), 1);
    assert_eq!(*primary.calls.borrow(), 0);
    let store = f.epochs();
    let guard = store.lock_before(ACCOUNT, deadline()).unwrap();
    let status = guard.status().unwrap();
    assert_eq!(status.state, crate::account_password_state::State::Pending);
    assert_eq!(status.epoch, 3);
    assert_eq!(status.changed_at.as_deref(), Some(STAMP));
    assert_ne!(f.current_factor(), BASELINE.as_bytes());
}
