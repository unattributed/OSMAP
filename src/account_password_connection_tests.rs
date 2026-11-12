use super::*;
use crate::account_admission::{Admission, EpochAuthority};
use crate::auth::*;
use crate::password_change::{self, EpochPrimaryBackend};
use crate::session::{FileSessionStore, SessionService, SystemRandomSource, ValidatedSession};
use crate::totp::SystemTimeProvider;
use sha2::{Digest, Sha256};
use std::fs;
use std::net::Shutdown;
use std::os::unix::fs::PermissionsExt;
use std::path::PathBuf;
use std::sync::{Arc, Mutex};

const ACCOUNT: &str = "alice@example.test";
const CURRENT: &str = "public-old-value";
const NEW: &str = "public-new-passphrase";
const STAMP: &str = "20261018120000";
// Same raw 64-ASCII-byte format as the existing installed private key files;
// these synthetic bytes are deliberately not decoded into a different key.
const KEY: [u8; 64] = [b'a'; 64];
const SESSION_KEY: [u8; 64] = [b'b'; 64];
struct Auth;
struct StoredEpochAuthority(PathBuf);
impl EpochAuthority for StoredEpochAuthority {
    fn admit(&self, account: &str, epoch: u64) -> Result<(), crate::account_admission::Error> {
        let store = Store::open(&self.0, crate::openbsd::effective_uid())
            .map_err(|_| crate::account_admission::Error::Unavailable)?;
        let guard = store
            .lock_before(account, Instant::now() + Duration::from_secs(2))
            .map_err(|_| crate::account_admission::Error::Unavailable)?;
        guard
            .admission(Some(epoch))
            .map(|_| ())
            .map_err(|_| crate::account_admission::Error::Refused)
    }
}
impl EpochAuthority for Auth {
    fn admit(&self, account: &str, epoch: u64) -> Result<(), crate::account_admission::Error> {
        if account == ACCOUNT && epoch == 3 {
            Ok(())
        } else {
            Err(crate::account_admission::Error::Refused)
        }
    }
}
impl PrimaryCredentialBackend for Auth {
    fn verify_primary(
        &self,
        _: &AuthenticationContext,
        account: &str,
        _: &str,
    ) -> Result<PrimaryAuthVerdict, PrimaryAuthBackendError> {
        Ok(PrimaryAuthVerdict::Accept {
            canonical_username: account.into(),
        })
    }
}
impl EpochPrimaryBackend for Auth {
    fn captured_admission(&self) -> Result<Admission, password_change::Error> {
        Ok(Admission {
            account: ACCOUNT.into(),
            epoch: 3,
        })
    }
}
struct Factor;
impl SecondFactorVerifier for Factor {
    fn verify_second_factor(
        &self,
        _: &str,
        _: RequiredSecondFactor,
        _: &str,
    ) -> Result<SecondFactorVerdict, SecondFactorBackendError> {
        Ok(SecondFactorVerdict::Accept)
    }
}
struct Scratch {
    root: PathBuf,
    epoch: PathBuf,
    record: PathBuf,
}
impl Scratch {
    fn new() -> Self {
        let root = std::env::temp_dir().join(format!(
            "osmap-password-connection-{}",
            crate::draft::generate_draft_id().unwrap()
        ));
        fs::create_dir(&root).unwrap();
        fs::set_permissions(&root, fs::Permissions::from_mode(0o700)).unwrap();
        let epoch = root.join("epoch");
        fs::create_dir(&epoch).unwrap();
        fs::set_permissions(&epoch, fs::Permissions::from_mode(0o700)).unwrap();
        let mut h = Sha256::new();
        h.update(b"osmap-account-epoch-v1\0");
        h.update(ACCOUNT.as_bytes());
        let stem = format!("{:x}", h.finalize());
        let record = epoch.join(format!("{stem}.json"));
        for (path,bytes) in [(record.clone(),br#"{"epoch":3,"state":"active","changed_at":null,"intent":null,"used_intents":[]}"#.to_vec()),(epoch.join(format!("{stem}.lock")),Vec::new())]{fs::write(&path,bytes).unwrap();fs::set_permissions(path,fs::Permissions::from_mode(0o600)).unwrap();}
        Self {
            root,
            epoch,
            record,
        }
    }
}
impl Drop for Scratch {
    fn drop(&mut self) {
        let _ = fs::remove_dir_all(&self.root);
    }
}
#[derive(Default)]
struct Trace {
    written: bool,
    sql: usize,
    finished: bool,
}
struct Executor(Arc<Mutex<Trace>>);
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
        let mut t = self.0.lock().unwrap();
        let stdout = if program == crate::account_password_backend::HASH_PROGRAM {
            format!("{}\n", hash())
        } else if input.starts_with(b"START TRANSACTION;") {
            t.written = true;
            t.sql += 1;
            format!("1\n{}\t{STAMP}\n", hex(&hash()))
        } else {
            format!(
                "{}\t20261017120000\t1\t1\n",
                hex(&format!("{{BLF-CRYPT}}$2y$05${}", "A".repeat(53)))
            )
        };
        Ok(CommandExecution {
            status_code: 0,
            stdout,
            stderr: String::new(),
        })
    }
}
struct FixedEffects(Arc<Mutex<Trace>>, Option<std::sync::mpsc::Receiver<()>>);
impl Effects for FixedEffects {
    fn authenticate(
        &self,
        account: &str,
        password: &str,
        _: Instant,
    ) -> Result<bool, DependencyError> {
        assert_eq!(account, ACCOUNT);
        let changed = self.0.lock().unwrap().written;
        if password == CURRENT {
            Ok(!changed)
        } else {
            assert_eq!(password, NEW);
            Ok(changed)
        }
    }
    fn preflight(&self, _: &Request, _: Instant) -> Result<(), DependencyError> {
        Ok(())
    }
    fn before_write(&self, _: &Request, _: Instant) -> Result<(), DependencyError> {
        Ok(())
    }
    fn invalidate_cache(&self, _: &str, _: Instant) -> Result<(), DependencyError> {
        Ok(())
    }
    fn finish_mail(&self, _: &str, _: Instant) -> Result<(), DependencyError> {
        if let Some(closed) = &self.1 {
            closed
                .recv_timeout(Duration::from_secs(1))
                .map_err(|_| DependencyError::Unavailable)?;
        }
        self.0.lock().unwrap().finished = true;
        Ok(())
    }
}

#[test]
fn actual_guarded_socket_exchange_requires_pending_ack_eof_before_one_write() {
    // Real socket transport, file-session lease, epoch store and both MACs.
    // SQL and mail effects are explicitly scripted source-test dependencies.
    for mode in ["complete", "trailing", "missing", "lost-terminal"] {
        let scratch = Scratch::new();
        let session_root = scratch.root.join("sessions");
        fs::create_dir(&session_root).unwrap();
        fs::set_permissions(&session_root, fs::Permissions::from_mode(0o700)).unwrap();
        let context = AuthenticationContext::new(
            AuthenticationPolicy::default(),
            "public-password-connection",
            "127.0.0.1",
            "Fixture/Test",
        )
        .unwrap();
        let sessions = SessionService::new(
            FileSessionStore::new(session_root),
            SystemTimeProvider,
            SystemRandomSource,
            600,
            300,
        )
        .with_epoch_authority(Arc::new(StoredEpochAuthority(scratch.epoch.clone())));
        let issued = sessions
            .issue_with_epoch(&context, ACCOUNT, RequiredSecondFactor::Totp, Some(3))
            .unwrap();
        let session = ValidatedSession {
            record: issued.record,
            audit_event: issued.audit_event,
        };
        let rate = crate::password_change_rate::Store::new(scratch.root.join("rate"));
        let factor = SecondFactorService::new(AuthenticationPolicy::default(), Factor);
        let prepared = password_change::prepare(
            password_change::Services {
                primary: &Auth,
                factor: &factor,
                epoch: &Auth,
                rate: &rate,
                clock: &SystemTimeProvider,
                policy: AuthenticationPolicy::default(),
            },
            password_change::Attempt {
                context: &context,
                session: &session,
                request: password_change::Request::new(CURRENT, NEW, NEW, "123456").unwrap(),
            },
        )
        .authorization
        .unwrap();
        let request = Request::issue(
            prepared
                .into_dispatch(&context, &session, &Auth, &SystemTimeProvider)
                .unwrap(),
            &KEY,
            SystemTimeProvider.unix_timestamp(),
        )
        .unwrap();
        let trace = Arc::new(Mutex::new(Trace::default()));
        let (mut client, server) = UnixStream::pair().unwrap();
        let keys = Keys::new(KEY, SESSION_KEY).unwrap();
        let deadline = Instant::now() + Duration::from_secs(3);
        let (read_closed, observe_read_closed) = std::sync::mpsc::sync_channel(1);
        std::thread::scope(|scope| {
            let trace_server = trace.clone();
            let epoch = &scratch.epoch;
            let task = scope.spawn(move || {
                let store = Store::open(epoch, crate::openbsd::effective_uid()).unwrap();
                let backend = Backend::new(Executor(trace_server.clone()));
                let effects = FixedEffects(
                    trace_server,
                    (mode == "lost-terminal").then_some(observe_read_closed),
                );
                serve_once(
                    server,
                    crate::openbsd::effective_uid(),
                    &store,
                    &backend,
                    &effects,
                    &SystemTimeProvider,
                    &keys,
                    deadline,
                )
            });
            let outcome = sessions
                .with_guarded_session_lease(&context, &issued.token, |_, lease| {
                    let guarded = lease
                        .authorize_mutation(request, &KEY, &SESSION_KEY, deadline)
                        .unwrap();
                    guarded.consume(|request, frame, deadline| {
                        write_frame(
                            &mut client,
                            &frame,
                            crate::account_guarded_mutation::MAX_FRAME,
                            deadline,
                        )
                        .unwrap();
                        let challenge = read_frame(
                            &mut client,
                            crate::account_mutation_continuity::LIMIT,
                            deadline,
                        )
                        .unwrap();
                        let pending: serde_json::Value =
                            serde_json::from_slice(&fs::read(&scratch.record).unwrap()).unwrap();
                        assert_eq!(pending["state"], "pending");
                        assert_eq!(trace.lock().unwrap().sql, 0);
                        assert!(sessions
                            .with_guarded_validated_session(&context, &issued.token, |_| ())
                            .is_err());
                        if mode != "missing" {
                            let ack = crate::account_mutation_continuity::acknowledge(
                                &request,
                                &frame,
                                &challenge,
                                &KEY,
                                wall_millis().unwrap(),
                            )
                            .unwrap();
                            write_frame(
                                &mut client,
                                &ack,
                                crate::account_mutation_continuity::LIMIT,
                                deadline,
                            )
                            .unwrap();
                            if mode == "trailing" {
                                client.write_all(b"x").unwrap();
                            }
                        }
                        client.shutdown(Shutdown::Write).unwrap();
                        if mode == "lost-terminal" {
                            // The issuer ACK has been sent, but the peer cannot
                            // receive the terminal receipt. This must not roll
                            // back the committed credential or epoch, or issue
                            // a second SQL write to recover an acknowledgement.
                            client.shutdown(Shutdown::Read).unwrap();
                            read_closed.send(()).unwrap();
                            return None;
                        }
                        let reply =
                            read_frame(&mut client, crate::account_mutation::MAX_FRAME, deadline)
                                .unwrap();
                        require_eof(&mut client, deadline).unwrap();
                        Some(
                            crate::account_mutation::Verifier::default()
                                .terminal_response(
                                    request,
                                    &reply,
                                    &KEY,
                                    SystemTimeProvider.unix_timestamp(),
                                )
                                .unwrap(),
                        )
                    })
                })
                .unwrap();
            let served = task.join().unwrap();
            if mode == "lost-terminal" {
                assert_eq!(served, Err(Error::Transport));
                assert!(outcome.is_none());
                return;
            }
            assert_eq!(served, Ok(()));
            let outcome = outcome.unwrap();
            if mode == "complete" {
                assert!(matches!(
                    outcome.outcome(),
                    crate::account_mutation::Outcome::Changed { epoch: 4, .. }
                ));
            } else {
                assert!(matches!(
                    outcome.outcome(),
                    crate::account_mutation::Outcome::Contained
                ));
            }
        });
        let t = trace.lock().unwrap();
        let committed = matches!(mode, "complete" | "lost-terminal");
        assert_eq!(t.sql, usize::from(committed));
        assert_eq!(t.finished, committed);
        let value: serde_json::Value =
            serde_json::from_slice(&fs::read(&scratch.record).unwrap()).unwrap();
        assert_eq!(
            value["state"],
            if committed { "active" } else { "contained" }
        );
        assert_eq!(value["epoch"], if committed { 4 } else { 3 });
        // Session authority is re-read from the real on-disk Store after the
        // connection has ended. A lost terminal receipt cannot preserve the
        // previous session's authority or prevent fresh epoch4 admission once
        // the credential and epoch really committed.
        assert!(sessions.validate(&context, &issued.token).is_err());
        assert_eq!(
            sessions
                .issue_with_epoch(&context, ACCOUNT, RequiredSecondFactor::Totp, Some(4))
                .is_ok(),
            committed
        );
    }
}

#[test]
fn wrong_kernel_peer_closes_without_read_or_state_change() {
    let scratch = Scratch::new();
    let before = fs::read(&scratch.record).unwrap();
    let store = Store::open(&scratch.epoch, crate::openbsd::effective_uid()).unwrap();
    let trace = Arc::new(Mutex::new(Trace::default()));
    let backend = Backend::new(Executor(trace.clone()));
    let effects = FixedEffects(trace.clone(), None);
    let (mut client, server) = UnixStream::pair().unwrap();
    let result = serve_once(
        server,
        crate::openbsd::effective_uid().checked_add(1).unwrap(),
        &store,
        &backend,
        &effects,
        &SystemTimeProvider,
        &Keys::new(KEY, SESSION_KEY).unwrap(),
        Instant::now() + Duration::from_secs(1),
    );
    assert_eq!(result, Err(Error::Peer));
    client
        .set_read_timeout(Some(Duration::from_secs(1)))
        .unwrap();
    let mut byte = [0u8; 1];
    assert_eq!(client.read(&mut byte).unwrap(), 0);
    assert_eq!(fs::read(&scratch.record).unwrap(), before);
    assert_eq!(trace.lock().unwrap().sql, 0);
}
