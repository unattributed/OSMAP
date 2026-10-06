//! Test-only actual stored-session issuer for the exact disposable mail accounts.
//! Public primary/TOTP/epoch inputs are projections. Native factories stay off.
use crate::account_admission::{Admission, EpochAuthority};
use crate::account_mutation::{Outcome as MutationOutcome, TerminalReceipt};
use crate::account_mutation_client::Client;
use crate::auth::{
    AuthenticationContext, AuthenticationPolicy, PrimaryAuthBackendError, PrimaryAuthVerdict,
    PrimaryCredentialBackend, RequiredSecondFactor, SecondFactorBackendError, SecondFactorService,
    SecondFactorVerdict, SecondFactorVerifier,
};
use crate::password_change::{self, Attempt, EpochPrimaryBackend, Request, Services};
use crate::session::{
    FileSessionStore, SessionService, SessionStore, SessionToken, SystemRandomSource,
    ValidatedSession,
};
use crate::totp::{SystemTimeProvider, TimeProvider};
use std::fs::{self, OpenOptions};
use std::io::{Read, Write};
use std::os::{
    fd::AsRawFd,
    unix::{
        fs::{MetadataExt, OpenOptionsExt, PermissionsExt},
        net::UnixStream,
    },
};
use std::path::{Path, PathBuf};
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};

const ALICE: &str = "alice@osmap-proxy.invalid";
const BOB: &str = "bob@osmap-proxy.invalid";
const CURRENT: &str = "public-old-value";
const NEW: &str = "public-new-passphrase";
const ORIGINAL: Duration = Duration::from_secs(3);
#[derive(Debug, PartialEq, Eq)]
enum Refusal {
    Configuration,
    Current,
    Preparation,
    Transport,
}
struct PublicEpoch;
impl EpochAuthority for PublicEpoch {
    fn admit(&self, account: &str, epoch: u64) -> Result<(), crate::account_admission::Error> {
        if account == ALICE && epoch == 0 {
            Ok(())
        } else {
            Err(crate::account_admission::Error::Refused)
        }
    }
}
struct PublicPrimary {
    captured: Mutex<Option<Admission>>,
}
impl PrimaryCredentialBackend for PublicPrimary {
    fn verify_primary(
        &self,
        _: &AuthenticationContext,
        account: &str,
        password: &str,
    ) -> Result<PrimaryAuthVerdict, PrimaryAuthBackendError> {
        if account != ALICE || password != CURRENT {
            return Ok(PrimaryAuthVerdict::Reject);
        }
        *self.captured.lock().unwrap() = Some(Admission {
            account: ALICE.into(),
            epoch: 0,
        });
        Ok(PrimaryAuthVerdict::Accept {
            canonical_username: ALICE.into(),
        })
    }
}
impl EpochPrimaryBackend for PublicPrimary {
    fn captured_admission(&self) -> Result<Admission, password_change::Error> {
        self.captured
            .lock()
            .unwrap()
            .clone()
            .ok_or(password_change::Error::Unavailable)
    }
}
struct PublicTotp;
impl SecondFactorVerifier for PublicTotp {
    fn verify_second_factor(
        &self,
        account: &str,
        factor: RequiredSecondFactor,
        value: &str,
    ) -> Result<SecondFactorVerdict, SecondFactorBackendError> {
        Ok(
            if account == ALICE && factor == RequiredSecondFactor::Totp && value == "123456" {
                SecondFactorVerdict::Accept
            } else {
                SecondFactorVerdict::Reject
            },
        )
    }
}
fn private_write(path: &Path, bytes: &[u8]) -> Result<(), Refusal> {
    let mut file = OpenOptions::new()
        .write(true)
        .create_new(true)
        .mode(0o600)
        .custom_flags(libc::O_NOFOLLOW | libc::O_NONBLOCK)
        .open(path)
        .map_err(|_| Refusal::Configuration)?;
    file.write_all(bytes).map_err(|_| Refusal::Configuration)?;
    file.sync_all().map_err(|_| Refusal::Configuration)
}
/// Warm-up owns private role files and real stored sessions BEFORE receipt.
/// No caller-supplied account, credentials, proof or operation deadline enters.
struct WarmIssuer {
    root: PathBuf,
    identity: (u64, u64, u32, u32),
    client: Client,
    context: AuthenticationContext,
    session: ValidatedSession,
    token: SessionToken,
    epoch: Arc<PublicEpoch>,
    bob_path: PathBuf,
    bob_bytes: Vec<u8>,
}
impl WarmIssuer {
    fn warm(
        root: &Path,
        socket: &Path,
        request_key: &[u8; 32],
        session_key: &[u8; 32],
    ) -> Result<Self, Refusal> {
        let info = fs::symlink_metadata(root).map_err(|_| Refusal::Configuration)?;
        if !info.is_dir()
            || info.uid() != crate::openbsd::effective_uid()
            || info.mode() & 0o777 != 0o700
            || fs::canonicalize(root).map_err(|_| Refusal::Configuration)? != root
            || request_key == session_key
        {
            return Err(Refusal::Configuration);
        }
        let identity = (info.dev(), info.ino(), info.uid(), info.mode());
        let sessions = root.join("sessions");
        fs::create_dir(&sessions).map_err(|_| Refusal::Configuration)?;
        fs::set_permissions(&sessions, fs::Permissions::from_mode(0o700))
            .map_err(|_| Refusal::Configuration)?;
        private_write(&root.join("request.key"), request_key)?;
        private_write(&root.join("session.key"), session_key)?;
        let client = Client::stored_fixture_files(
            socket,
            &root.join("request.key"),
            &root.join("session.key"),
            crate::openbsd::effective_uid(),
        )
        .map_err(|_| Refusal::Configuration)?;
        let context = AuthenticationContext::new(
            AuthenticationPolicy::default(),
            "native-stored-issuer",
            "127.0.0.1",
            "OSMAP/NativeFixture",
        )
        .map_err(|_| Refusal::Configuration)?;
        let epoch = Arc::new(PublicEpoch);
        let service = SessionService::new(
            FileSessionStore::new(&sessions),
            SystemTimeProvider,
            SystemRandomSource,
            3600,
            1800,
        )
        .with_epoch_authority(epoch.clone());
        let issued = service
            .issue_with_epoch(&context, ALICE, RequiredSecondFactor::Totp, Some(0))
            .map_err(|_| Refusal::Current)?;
        let session = ValidatedSession {
            record: issued.record,
            audit_event: issued.audit_event,
        };
        // Bob is unrelated stored state and uses an ordinary fixture session;
        // the Alice-only mutation authority never grants Bob a mutation.
        let bob = SessionService::new(
            FileSessionStore::new(&sessions),
            SystemTimeProvider,
            SystemRandomSource,
            3600,
            1800,
        )
        .issue(&context, BOB, RequiredSecondFactor::Totp)
        .map_err(|_| Refusal::Current)?;
        let bob_path = FileSessionStore::new(&sessions).session_path(&bob.record.session_id);
        let bob_bytes = fs::read(&bob_path).map_err(|_| Refusal::Current)?;
        let value = Self {
            root: root.into(),
            identity,
            client,
            context,
            session,
            token: issued.token,
            epoch,
            bob_path,
            bob_bytes,
        };
        value.current_root()?;
        Ok(value)
    }
    fn current_root(&self) -> Result<(), Refusal> {
        let info = fs::symlink_metadata(&self.root).map_err(|_| Refusal::Configuration)?;
        if (info.dev(), info.ino(), info.uid(), info.mode()) != self.identity
            || fs::canonicalize(&self.root).map_err(|_| Refusal::Configuration)? != self.root
        {
            return Err(Refusal::Configuration);
        }
        Ok(())
    }
    fn service(&self) -> SessionService<FileSessionStore, SystemTimeProvider, SystemRandomSource> {
        SessionService::new(
            FileSessionStore::new(self.root.join("sessions")),
            SystemTimeProvider,
            SystemRandomSource,
            3600,
            1800,
        )
        .with_epoch_authority(self.epoch.clone())
    }
    fn execute(&self, original_deadline: Instant) -> Result<TerminalReceipt, Refusal> {
        self.current_root()?;
        let primary = PublicPrimary {
            captured: Mutex::new(None),
        };
        let factor = SecondFactorService::new(AuthenticationPolicy::default(), PublicTotp);
        let prepared = password_change::prepare_before(
            Services {
                primary: &primary,
                factor: &factor,
                epoch: self.epoch.as_ref(),
                rate: &crate::password_change_rate::Store::new(self.root.join("rate")),
                clock: &SystemTimeProvider,
                policy: AuthenticationPolicy::default(),
            },
            Attempt {
                context: &self.context,
                session: &self.session,
                request: Request::new(CURRENT, NEW, NEW, "123456")
                    .map_err(|_| Refusal::Preparation)?,
            },
            original_deadline,
        )
        .authorization
        .map_err(|_| Refusal::Preparation)?;
        let service = self.service();
        let result = service
            .with_guarded_session_lease(&self.context, &self.token, |current, lease| {
                let dispatch = prepared
                    .into_dispatch(
                        &self.context,
                        &current,
                        self.epoch.as_ref(),
                        &SystemTimeProvider,
                    )
                    .map_err(|_| Refusal::Current)?;
                service
                    .recheck_guarded_session(&current)
                    .map_err(|_| Refusal::Current)?;
                self.client
                    .execute_stored_continuous(dispatch, lease, original_deadline)
                    .map_err(|_| Refusal::Transport)
            })
            .map_err(|_| Refusal::Current)?;
        if fs::read(&self.bob_path).map_err(|_| Refusal::Current)? != self.bob_bytes {
            return Err(Refusal::Current);
        }
        self.current_root()?;
        result
    }
}

/// Ownership of the inherited socket is a descriptor witness, not a unique
/// peer-process claim. Root must still bind its exact born process/socketpair.
struct BootstrapControl {
    stream: UnixStream,
    identity: (libc::dev_t, libc::ino_t, libc::mode_t),
}
impl BootstrapControl {
    fn facts(stream: &UnixStream) -> Result<(libc::dev_t, libc::ino_t, libc::mode_t), Refusal> {
        crate::openbsd::fixture_unix_stream_identity(stream).map_err(|_| Refusal::Configuration)
    }
    fn owned(stream: UnixStream) -> Result<Self, Refusal> {
        let identity = Self::facts(&stream)?;
        Ok(Self { stream, identity })
    }
    fn current(&self) -> Result<(), Refusal> {
        if Self::facts(&self.stream)? != self.identity {
            return Err(Refusal::Configuration);
        }
        Ok(())
    }
    fn read(&mut self, limit: usize, deadline: Instant) -> Result<Vec<u8>, Refusal> {
        self.current()?;
        let value = crate::openpgp_inventory_runtime::read_frame(&mut self.stream, limit, deadline)
            .map_err(|_| Refusal::Configuration)?;
        self.current()?;
        Ok(value)
    }
    fn write(&mut self, raw: &[u8], deadline: Instant) -> Result<(), Refusal> {
        self.current()?;
        crate::openpgp_inventory_runtime::write_frame(&mut self.stream, raw, deadline)
            .map_err(|_| Refusal::Configuration)?;
        self.current()
    }
}

#[derive(serde::Deserialize)]
#[serde(deny_unknown_fields)]
struct Bootstrap {
    version: u8,
    root: PathBuf,
    request_key: [u8; 32],
    session_key: [u8; 32],
}
/// Explicit ignored process adapter. Root owns its born inherited descriptor,
/// compiled test binary, private namespace and listener; UID is only one witness.
#[test]
#[ignore = "root-reviewed born fixture only; never production admission"]
fn native_issuer_entrypoint() {
    let fd = std::env::var("OSMAP_TEST_STORED_ISSUER_FD")
        .ok()
        .and_then(|v| v.parse::<i32>().ok())
        .filter(|v| (3..=1024).contains(v))
        .expect("fixture descriptor required");
    let mut control = BootstrapControl::owned(
        crate::openbsd::fixture_owned_unix_stream(fd).expect("fixture descriptor refused"),
    )
    .expect("fixture descriptor refused");
    let setup = Instant::now() + Duration::from_secs(20);
    let raw = control
        .read(2048, setup)
        .expect("fixture bootstrap refused");
    let boot: Bootstrap = serde_json::from_slice(&raw)
        .map_err(|_| Refusal::Configuration)
        .expect("fixture shape refused");
    let parent = boot.root.parent().expect("fixture root refused");
    let name = parent.file_name().and_then(|v| v.to_str()).unwrap_or("");
    assert!(
        boot.version == 1
            && boot.root.file_name().is_some_and(|v| v == "rust-issuer")
            && parent.parent() == Some(Path::new("/var/run"))
            && name
                .strip_prefix("osmap-pxp-")
                .is_some_and(|v| v.len() == 16
                    && v.bytes()
                        .all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(&b))),
        "fixed fixture namespace refused"
    );
    let issuer = WarmIssuer::warm(
        &boot.root,
        &parent.join("rust-mutation.sock"),
        &boot.request_key,
        &boot.session_key,
    )
    .expect("fixture warm refused");
    control
        .write(b"READY", setup)
        .expect("fixture ready refused");
    assert_eq!(
        control.read(1, setup).ok().as_deref(),
        Some(b"G".as_slice()),
        "fixture start refused"
    );
    // The original receipt starts ONCE, before actual typed preparation. The
    // signed budget is then emitted by real GuardedSessionLease/Client; root
    // must authenticate its first receive and preserve those signed fields.
    let began = Instant::now();
    let original = began + ORIGINAL;
    let result = issuer.execute(original);
    let changed = result
        .as_ref()
        .is_ok_and(|r| matches!(r.outcome(), MutationOutcome::Changed { epoch: 1, .. }));
    let report = serde_json::to_vec(
        &serde_json::json!({"schema":"osmap-rust-stored-issuer-v1","changed":changed,
        "elapsed_millis":began.elapsed().as_millis(),"original_budget_millis":3000,
        "SQL_primary_epoch_topology_projections":true,"browser_cleanup_qualified":false}),
    )
    .unwrap();
    // Report only closed scalars after the original exchange; no raw frames,
    // keys, session token, request credentials or exception text are retained.
    control
        .write(&report, setup)
        .expect("fixture report refused");
    assert!(changed, "fixture issuer did not qualify");
}

#[cfg(test)]
mod controls;
