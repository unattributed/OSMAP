//! Root-provisioned native client for the ordinary stock password service.
//! Only constructor qualification is test-only: authentication, guarded issuer,
//! mutation transport, epoch authority and stored-session cleanup are real.
use crate::account_admission_runtime::{Client as AdmissionClient, CredentialBackend};
use crate::account_mutation::Outcome;
use crate::account_mutation_client::Client as MutationClient;
use crate::auth::{
    AuthenticationContext, AuthenticationPolicy, RequiredSecondFactor, SecondFactorService,
};
use crate::password_change;
use crate::session::{
    BrowserRevocation, FileSessionStore, SessionService, SystemRandomSource, ValidatedSession,
};
use crate::totp::{
    SystemTimeProvider, TimeProvider, TotpPolicy, TotpSecret, TotpSecretStore,
    TotpSecretStoreError, TotpVerifier,
};
use hmac::{Hmac, Mac};
use sha1::Sha1;
use std::fs;
use std::io::Read;
use std::os::unix::fs::MetadataExt;
use std::path::{Path, PathBuf};
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};

const ACCOUNT: &str = "s04-02-transaction-20261025-04@osmap-password.invalid";
const BOB: &str = "bob@osmap-password.invalid";

#[derive(serde::Deserialize)]
#[serde(deny_unknown_fields)]
struct Bootstrap {
    version: u8,
    client_root: PathBuf,
    current_password: String,
    replacement_password: String,
    totp_secret_hex: String,
}
fn hex_secret(value: &str) -> Option<Vec<u8>> {
    if value.len() != 64
        || !value
            .bytes()
            .all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(&b))
    {
        return None;
    }
    value
        .as_bytes()
        .chunks_exact(2)
        .map(|pair| u8::from_str_radix(std::str::from_utf8(pair).ok()?, 16).ok())
        .collect()
}
fn fixed_client_root(path: &Path) -> bool {
    path.parent() == Some(Path::new("/var/run"))
        && path
            .file_name()
            .and_then(|x| x.to_str())
            .is_some_and(|name| {
                name.strip_prefix("osmap-transaction-client-")
                    .is_some_and(|suffix| {
                        suffix.len() == 16
                            && suffix
                                .bytes()
                                .all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(&b))
                    })
            })
}

// The actual TotpVerifier consumes a fresh RAM-only fixture secret. This is not
// installed TOTP-file qualification; no reusable secret reaches disk or argv.
struct RamTotp {
    secret: Vec<u8>,
    consumed: Mutex<Option<u64>>,
}
impl TotpSecretStore for RamTotp {
    fn load_secret(&self, account: &str) -> Result<Option<TotpSecret>, TotpSecretStoreError> {
        Ok((account == ACCOUNT).then(|| TotpSecret {
            secret_bytes: self.secret.clone(),
        }))
    }
    fn consume_counter(&self, account: &str, counter: u64) -> Result<bool, TotpSecretStoreError> {
        if account != ACCOUNT {
            return Ok(false);
        }
        let mut previous = self.consumed.lock().map_err(|_| TotpSecretStoreError {
            reason: "fixture counter unavailable".into(),
        })?;
        if previous.is_some_and(|value| counter <= value) {
            return Ok(false);
        }
        *previous = Some(counter);
        Ok(true)
    }
}
fn totp(secret: &[u8], now: u64) -> Result<String, &'static str> {
    let mut mac = Hmac::<Sha1>::new_from_slice(secret).map_err(|_| "TOTP key refused")?;
    mac.update(&(now / 30).to_be_bytes());
    let digest = mac.finalize().into_bytes();
    let offset = usize::from(digest[19] & 15);
    let value = u32::from_be_bytes(
        digest[offset..offset + 4]
            .try_into()
            .map_err(|_| "TOTP offset refused")?,
    ) & 0x7fff_ffff;
    Ok(format!("{:06}", value % 1_000_000))
}

#[test]
fn native_transaction_bootstrap_restricts_root_and_private_material_shape() {
    assert!(fixed_client_root(Path::new(
        "/var/run/osmap-transaction-client-0123456789abcdef"
    )));
    for path in [
        "/tmp/osmap-transaction-client-0123456789abcdef",
        "/var/run/osmap-transaction-client-0123456789abcdeg",
        "/var/run/osmap-transaction-client-0123456789abcde",
        "/var/run/osmap-transaction-client-0123456789abcdef/extra",
    ] {
        assert!(!fixed_client_root(Path::new(path)));
    }
    assert_eq!(hex_secret(&"a1".repeat(32)).unwrap().len(), 32);
    assert!(hex_secret(&"A1".repeat(32)).is_none());
    assert!(hex_secret(&"a1".repeat(31)).is_none());
    // Independent RFC6238 SHA1 vector at time59, truncated to six digits.
    assert_eq!(totp(b"12345678901234567890", 59).unwrap(), "287082");
}

/// Root starts the ordinary account-passwd CLI with fixed protected account
/// configuration and a separate fresh SQL/epoch fixture. There is no readonly
/// projection, alternate service dispatch or fixture-selected SQL executor.
#[test]
#[ignore = "requires one reviewed OpenBSD ordinary stock helper and fresh owned transaction fixture"]
fn native_ordinary_stock_password_transaction() -> Result<(), &'static str> {
    if !cfg!(target_os = "openbsd") || crate::openbsd::effective_uid() == 0 {
        return Err("fixed nonroot OpenBSD client required");
    }
    crate::openbsd::disable_core_dumps().map_err(|_| "client core limit refused")?;
    let deadline = Instant::now() + Duration::from_secs(60);
    let mut bytes = Vec::new();
    std::io::stdin()
        .take(4097)
        .read_to_end(&mut bytes)
        .map_err(|_| "private bootstrap read refused")?;
    if bytes.len() > 4096 {
        return Err("private bootstrap bound refused");
    }
    let boot: Bootstrap =
        serde_json::from_slice(&bytes).map_err(|_| "private bootstrap shape refused")?;
    bytes.fill(0);
    let secret = hex_secret(&boot.totp_secret_hex).ok_or("private TOTP shape refused")?;
    if boot.version != 1
        || !fixed_client_root(&boot.client_root)
        || hex_secret(&boot.current_password).is_none()
        || hex_secret(&boot.replacement_password).is_none()
        || boot.current_password == boot.replacement_password
    {
        return Err("private bootstrap authority refused");
    }
    let root = &boot.client_root;
    let metadata = fs::symlink_metadata(root).map_err(|_| "client directory unavailable")?;
    if !metadata.is_dir()
        || metadata.uid() != crate::openbsd::effective_uid()
        || metadata.mode() & 0o7777 != 0o700
        || fs::canonicalize(root).map_err(|_| "client directory canonicalization refused")? != *root
    {
        return Err("client directory custody refused");
    }
    let admission = Arc::new(
        AdmissionClient::paired_fixture_files(
            Path::new("/var/run/osmap-account-admission/admission.sock"),
            &root.join("admission.key"),
            0,
        )
        .map_err(|_| "admission client custody refused")?,
    );
    let mutation = MutationClient::stored_fixture_files(
        Path::new("/var/run/osmap-account-mutation/mutation.sock"),
        &root.join("mutation.key"),
        &root.join("session-proof.key"),
        0,
    )
    .map_err(|_| "mutation client custody refused")?;
    let authenticated = admission
        .authenticate_before(ACCOUNT, &boot.current_password, deadline)
        .map_err(|_| "initial authoritative authentication unavailable")?
        .ok_or("initial authoritative authentication refused")?;
    if authenticated.account != ACCOUNT || authenticated.epoch != 0 {
        return Err("initial signed authority mismatch");
    }
    admission
        .admit_before(BOB, 0, deadline)
        .map_err(|_| "untargeted account authority refused")?;
    let session_root = root.join("sessions");
    fs::create_dir(&session_root).map_err(|_| "exclusive session namespace refused")?;
    use std::os::unix::fs::PermissionsExt;
    fs::set_permissions(&session_root, fs::Permissions::from_mode(0o700))
        .map_err(|_| "session namespace mode refused")?;
    let context = AuthenticationContext::new(
        AuthenticationPolicy::default(),
        "native-ordinary-credential-transaction",
        "127.0.0.1",
        "OSMAP/NativeTransaction",
    )
    .map_err(|_| "session context refused")?;
    let sessions = SessionService::new(
        FileSessionStore::new(&session_root),
        SystemTimeProvider,
        SystemRandomSource,
        600,
        300,
    )
    .with_epoch_authority(admission.clone());
    let first = sessions
        .issue_with_epoch(&context, ACCOUNT, RequiredSecondFactor::Totp, Some(0))
        .map_err(|_| "first old-session issuance refused")?;
    let second = sessions
        .issue_with_epoch(&context, ACCOUNT, RequiredSecondFactor::Totp, Some(0))
        .map_err(|_| "second old-session issuance refused")?;
    let bob = sessions
        .issue_with_epoch(&context, BOB, RequiredSecondFactor::Totp, Some(0))
        .map_err(|_| "untargeted session issuance refused")?;
    let bob_path = FileSessionStore::new(&session_root).session_path(&bob.record.session_id);
    let bob_before = fs::read(&bob_path).map_err(|_| "untargeted session snapshot refused")?;
    let session = ValidatedSession {
        record: first.record,
        audit_event: first.audit_event,
    };
    let primary = CredentialBackend {
        client: admission.as_ref().clone(),
        captured: Arc::new(Mutex::new(None)),
    };
    let code = totp(&secret, SystemTimeProvider.unix_timestamp())?;
    let verifier = TotpVerifier::new(
        RamTotp {
            secret,
            consumed: Mutex::new(None),
        },
        SystemTimeProvider,
        TotpPolicy::default(),
    );
    let factor = SecondFactorService::new(AuthenticationPolicy::default(), verifier);
    let rate = crate::password_change_rate::Store::new(root.join("rate"));
    let prepared = password_change::prepare_before(
        password_change::Services {
            primary: &primary,
            factor: &factor,
            epoch: admission.as_ref(),
            rate: &rate,
            clock: &SystemTimeProvider,
            policy: AuthenticationPolicy::default(),
        },
        password_change::Attempt {
            context: &context,
            session: &session,
            request: password_change::Request::new(
                &boot.current_password,
                &boot.replacement_password,
                &boot.replacement_password,
                &code,
            )
            .map_err(|_| "credential request shape refused")?,
        },
        deadline,
    )
    .authorization
    .map_err(|_| "authoritative password and TOTP preparation refused")?;
    let receipt = sessions
        .with_guarded_session_lease(&context, &first.token, |stored, lease| {
            let dispatch = prepared
                .into_dispatch(&context, &stored, admission.as_ref(), &SystemTimeProvider)
                .map_err(|_| "stored dispatch authority refused")?;
            mutation
                .execute_stored_continuous(dispatch, lease, deadline)
                .map_err(|error| {
                    eprintln!("native_transaction stage=guarded_mutation error={error:?}");
                    "single guarded mutation uncertain or refused; no retry"
                })
        })
        .map_err(|_| "stored session guard refused")??;
    match receipt.outcome() {
        Outcome::Changed { epoch: 1, .. } => {}
        Outcome::ChangedIncomplete { .. } => {
            return Err("credential write verified but effects incomplete; no retry")
        }
        Outcome::KnownRefused => return Err("credential transaction settled refused"),
        Outcome::Contained => return Err("credential transaction contained; no retry"),
        Outcome::Changed { .. } => return Err("changed response epoch mismatch"),
    }
    // First prove old authority fails before physically revoking session files.
    // This closes the security question even if browser cleanup later fails.
    for token in [&first.token, &second.token] {
        if sessions.validate(&context, token).is_ok() {
            return Err("old stored session retained authority after transaction");
        }
    }
    if admission.admit_before(ACCOUNT, 0, deadline) != Err(crate::account_admission::Error::Refused)
    {
        return Err("old epoch did not receive authoritative refusal");
    }
    let revoked = sessions.revoke_password_change_sessions(receipt, deadline);
    if revoked != (BrowserRevocation::OldSessionsRevoked { count: 2 }) {
        return Err("old browser session revocation incomplete");
    }
    if admission
        .authenticate_before(ACCOUNT, &boot.current_password, deadline)
        .map_err(|_| "obsolete password verdict unavailable")?
        .is_some()
    {
        return Err("obsolete password still accepted");
    }
    let changed = admission
        .authenticate_before(ACCOUNT, &boot.replacement_password, deadline)
        .map_err(|_| "replacement password verdict unavailable")?
        .ok_or("replacement password refused")?;
    if changed.account != ACCOUNT || changed.epoch != 1 {
        return Err("replacement signed epoch mismatch");
    }
    let fresh = sessions
        .issue_with_epoch(
            &context,
            ACCOUNT,
            RequiredSecondFactor::Totp,
            Some(changed.epoch),
        )
        .map_err(|_| "new epoch stored session issuance refused")?;
    sessions
        .validate(&context, &fresh.token)
        .map_err(|_| "new epoch stored session validation refused")?;
    if fs::read(&bob_path).map_err(|_| "untargeted session readback refused")? != bob_before {
        return Err("untargeted stored session changed");
    }
    sessions
        .validate(&context, &bob.token)
        .map_err(|_| "untargeted stored session authority refused")?;
    if Instant::now() >= deadline {
        return Err("original transaction client deadline expired");
    }
    println!("\nnative_ordinary_transaction result=PASS ordinary_service=true current_authorized=true real_totp_verified=true single_dispatch=true credential_changed=true old_password_refused=true replacement_password_accepted=true epoch=1 old_sessions_authority_refused=2 old_sessions_revoked=2 fresh_session_valid=true bob_session_preserved=true installed_browser_qualified=false");
    Ok(())
}

/// One read through the ordinary stock SQL child after the identical actual
/// parent seal. This entrypoint cannot begin an epoch transaction, authenticate,
/// execute a password hash command or dispatch a credential UPDATE.
#[test]
#[ignore = "requires reviewed root OpenBSD read-only snapshot of retained transaction account02"]
fn native_parent_sealed_readonly_transaction_snapshot() -> Result<(), &'static str> {
    const SNAPSHOT_ACCOUNT: &str = "s04-02-transaction-20261025-02@osmap-password.invalid";
    use crate::account_password_backend::Backend;
    use crate::account_password_confinement::ParentPlan;
    use crate::account_password_fstat::{StartupOperation, StartupTrace};
    use crate::account_password_native::{NativeProfile, Role};
    use crate::account_password_peer::StockPeer;
    use crate::account_password_process::{FixedExecutor, MetadataExecutor};
    if !crate::openbsd::password_native_authority() {
        return Err("fixed root OpenBSD snapshot authority required");
    }
    crate::openbsd::disable_core_dumps().map_err(|_| "snapshot core limit refused")?;
    std::env::set_current_dir("/").map_err(|_| "snapshot root cwd refused")?;
    let original = Instant::now() + Duration::from_secs(30);
    let startup = Instant::now() + Duration::from_secs(5);
    let mut trace = StartupTrace::new(StartupOperation::ServiceStartup);
    let peer = Arc::new(
        StockPeer::observe(Arc::new(MetadataExecutor::readonly()), startup, &mut trace).map_err(
            |_| {
                trace.emit_metadata(&crate::account_admission::Error::Unavailable);
                "snapshot stock authority observation refused"
            },
        )?,
    );
    trace.set(StartupOperation::ParentPrepare);
    let mut parent = ParentPlan::prepare_stock_with_trace(startup, &mut trace).map_err(|_| {
        trace.emit_metadata(&crate::account_admission::Error::Unavailable);
        "snapshot stock parent preparation refused"
    })?;
    trace.set(StartupOperation::ParentSeal);
    let seal = crate::openbsd::seal_password_parent(&parent)
        .map_err(|_| "snapshot actual parent seal refused")?;
    parent
        .activate(seal)
        .map_err(|_| "snapshot parent activation refused")?;
    if Instant::now() >= startup {
        return Err("snapshot unchanged startup deadline expired");
    }
    // Match stock_operation: profiles are observed after the parent is sealed.
    // Hash occupies only the required unused executor slots; Backend::read
    // dispatches exactly one fixed SELECT and never requests those roles.
    let sql = NativeProfile::from_stock_backend(Role::Sql, peer.clone(), original)
        .map_err(|_| "snapshot SQL profile refused")?;
    let hash = NativeProfile::from_stock_backend(Role::Hash, peer, original)
        .map_err(|_| "snapshot unused hash profile refused")?;
    let backend = Backend::new(FixedExecutor::from_profiles(
        original, &sql, &hash, &hash, &hash,
    ));
    crate::account_password_backend::reset_native_read_diagnostic();
    crate::account_password_process::reset_native_sql_read_diagnostic();
    let result = backend.read(SNAPSHOT_ACCOUNT, original);
    let [stage, errno, status, stdout, stderr, sql_code] =
        crate::account_password_process::native_sql_read_diagnostic();
    let [pid, signal] = crate::account_password_process::native_sql_child_diagnostic();
    let parser = crate::account_password_backend::native_read_diagnostic();
    println!("\nnative_readonly_transaction_snapshot result={} process_stage={} errno={} status={} stdout_bytes={} stderr_bytes={} sql_code={} parser_phase={} child_pid={} term_signal={} snapshot_calls=1 credential_dispatch=false epoch_mutation=false authentication=false",
        if result.is_ok() { "PASS" } else { "REFUSED" }, stage, errno, status, stdout, stderr, sql_code, parser, pid, signal);
    result
        .map(|_| ())
        .map_err(|_| "read-only authoritative snapshot refused")
}
