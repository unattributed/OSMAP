//! Test-only actual stored-session issuer for the exact disposable mail accounts.
//! Actual admission/epoch and file-backed replay-protected TOTP; native gates stay off.
use crate::account_admission_runtime::{Client as AdmissionClient, CredentialBackend};
use crate::account_mutation_client::Client;
use crate::auth::{
    AuthenticationContext, AuthenticationPolicy, RequiredSecondFactor, SecondFactorService,
};
use crate::password_change::{self, Attempt, Request, Services};
use crate::session::BrowserRevocation;
use crate::session::{
    FileSessionStore, SessionService, SessionToken, SystemRandomSource, ValidatedSession,
};
use crate::totp::{
    FileTotpSecretStore, SystemTimeProvider, TimeProvider, TotpPolicy, TotpVerifier,
};
use hmac::{Hmac, Mac};
use sha1::Sha1;
use std::fs::{self, OpenOptions};
use std::io::Write;
use std::os::unix::{
    fs::{MetadataExt, OpenOptionsExt, PermissionsExt},
    net::UnixStream,
};
use std::path::{Path, PathBuf};
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};

const ALICE: &str = "alice@osmap-proxy.invalid";
const BOB: &str = "bob@osmap-proxy.invalid";
// Fixed harmless values on disposable loopback-only accounts; never real mail.
const CURRENT: &str = "000000000000000000000000000000000000000000000000";
const NEW: &str = "111111111111111111111111111111111111111111111111";
const ORIGINAL: Duration = Duration::from_secs(60);
#[derive(Debug, PartialEq, Eq)]
enum Refusal {
    Configuration,
    Current,
    Preparation,
    Transport,
}
// Public disposable fixture seed, never an operator TOTP secret. The helper
// below generates input only; unmodified TotpVerifier/store consumes it.
const TOTP_BASE32: &[u8] = b"secret=GEZDGNBVGY3TQOJQGEZDGNBVGY3TQOJQ\n";
fn fixture_totp() -> Result<String, Refusal> {
    let counter = SystemTimeProvider.unix_timestamp() / 30;
    let mut mac =
        Hmac::<Sha1>::new_from_slice(b"12345678901234567890").map_err(|_| Refusal::Preparation)?;
    mac.update(&counter.to_be_bytes());
    let digest = mac.finalize().into_bytes();
    let offset = usize::from(digest[19] & 15);
    let binary = (u32::from(digest[offset]) & 127) << 24
        | u32::from(digest[offset + 1]) << 16
        | u32::from(digest[offset + 2]) << 8
        | u32::from(digest[offset + 3]);
    Ok(format!("{:06}", binary % 1_000_000))
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
    epoch: Arc<AdmissionClient>,
    bob_path: PathBuf,
    bob_bytes: Vec<u8>,
}
impl WarmIssuer {
    fn warm(
        root: &Path,
        socket: &Path,
        request_key: &[u8; 32],
        session_key: &[u8; 32],
        setup_deadline: Instant,
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
        let runtime = root.parent().ok_or(Refusal::Configuration)?;
        let epoch = Arc::new(
            AdmissionClient::paired_fixture_files(
                &runtime.join("admission/admission.sock"),
                &runtime.join("bootstrap/account-admission.key"),
                crate::openbsd::effective_uid(),
            )
            .map_err(|_| Refusal::Configuration)?,
        );
        let alice = epoch
            .authenticate_before(ALICE, CURRENT, setup_deadline)
            .map_err(|_| Refusal::Current)?
            .ok_or(Refusal::Current)?;
        let bob_admission = epoch
            .authenticate_before(BOB, CURRENT, setup_deadline)
            .map_err(|_| Refusal::Current)?
            .ok_or(Refusal::Current)?;
        if alice.account != ALICE
            || alice.epoch != 0
            || bob_admission.account != BOB
            || bob_admission.epoch != 0
        {
            return Err(Refusal::Current);
        }
        for leaf in ["totp", "totp-replay"] {
            fs::create_dir(root.join(leaf)).map_err(|_| Refusal::Configuration)?;
            fs::set_permissions(root.join(leaf), fs::Permissions::from_mode(0o700))
                .map_err(|_| Refusal::Configuration)?;
        }
        let totp = FileTotpSecretStore::new(root.join("totp"));
        private_write(&totp.secret_path_for_username(ALICE), TOTP_BASE32)?;
        let service = SessionService::new(
            FileSessionStore::new(&sessions),
            SystemTimeProvider,
            SystemRandomSource,
            3600,
            1800,
        )
        .with_epoch_authority(epoch.clone());
        let issued = service
            .issue_with_epoch(
                &context,
                ALICE,
                RequiredSecondFactor::Totp,
                Some(alice.epoch),
            )
            .map_err(|_| Refusal::Current)?;
        let session = ValidatedSession {
            record: issued.record,
            audit_event: issued.audit_event,
        };
        // Bob uses the actual epoch authority and remains unrelated state.
        // The Alice-only mutation authority never grants Bob a mutation.
        let bob = SessionService::new(
            FileSessionStore::new(&sessions),
            SystemTimeProvider,
            SystemRandomSource,
            3600,
            1800,
        )
        .with_epoch_authority(epoch.clone())
        .issue_with_epoch(
            &context,
            BOB,
            RequiredSecondFactor::Totp,
            Some(bob_admission.epoch),
        )
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
    fn execute(&self, original_deadline: Instant) -> Result<BrowserRevocation, Refusal> {
        self.current_root()?;
        let primary = CredentialBackend {
            client: self.epoch.as_ref().clone(),
            captured: Arc::new(Mutex::new(None)),
        };
        let totp = FileTotpSecretStore::new(self.root.join("totp"))
            .with_replay_dir(self.root.join("totp-replay"));
        let factor = SecondFactorService::new(
            AuthenticationPolicy::default(),
            TotpVerifier::new(totp, SystemTimeProvider, TotpPolicy::default()),
        );
        let code = fixture_totp()?;
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
                request: Request::new(CURRENT, NEW, NEW, &code)
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
        let receipt = result?;
        // The guarded callback has returned and released its actual store lock.
        // Browser revocation consumes the authentic receipt on the SAME deadline.
        let disposition = service.revoke_password_change_sessions(receipt, original_deadline);
        if fs::read(&self.bob_path).map_err(|_| Refusal::Current)? != self.bob_bytes {
            return Err(Refusal::Current);
        }
        Ok(disposition)
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
fn native_full_factory_issuer_entrypoint() {
    assert_eq!(std::env::consts::OS, "openbsd");
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
        setup,
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
        .is_ok_and(|r| matches!(r, BrowserRevocation::OldSessionsRevoked { count: 1 }));
    let report = serde_json::to_vec(
        &serde_json::json!({"schema":"osmap-rust-full-factory-issuer-v1","changed":changed,
        "elapsed_millis":began.elapsed().as_millis(),"original_budget_millis":60000,
        "admission_epoch_TOTP_callbacks_projected":false,"browser_cleanup_returned":result.is_ok()}),
    )
    .unwrap();
    // Report only closed scalars after the original exchange; no raw frames,
    // keys, session token, request credentials or exception text are retained.
    control
        .write(&report, original)
        .expect("fixture report refused");
    assert!(changed, "fixture issuer did not qualify");
}
