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
const CONCURRENT_ACCOUNT: &str = "s04-02-concurrent-20261025-01@osmap-password.invalid";
const CONCURRENT_CONTROL: &str = "s04-02-concurrent-control-20261025-01@osmap-password.invalid";

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
    account: &'static str,
    secret: Vec<u8>,
    consumed: Mutex<Option<u64>>,
}
impl TotpSecretStore for RamTotp {
    fn load_secret(&self, account: &str) -> Result<Option<TotpSecret>, TotpSecretStoreError> {
        Ok((account == self.account).then(|| TotpSecret {
            secret_bytes: self.secret.clone(),
        }))
    }
    fn consume_counter(&self, account: &str, counter: u64) -> Result<bool, TotpSecretStoreError> {
        if account != self.account {
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
    native_stock_password_transaction_case(ACCOUNT, BOB, false)
}

/// Same single real guarded transaction as native04, on the fixed fresh T04
/// pair. The existing cfg(test) hook resends only its consumed signed wire
/// frame; independent root SQL/Store witnesses must prove no second write.
#[test]
#[ignore = "requires fresh T04 P/G helper, actual issuer and independent no-second-write witnesses"]
fn native_installed_concurrent_replay_transaction() -> Result<(), &'static str> {
    native_stock_password_transaction_case(CONCURRENT_ACCOUNT, CONCURRENT_CONTROL, true)
}

fn native_stock_password_transaction_case(
    account: &'static str,
    bob: &'static str,
    native_replay: bool,
) -> Result<(), &'static str> {
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
        if native_replay {
            AdmissionClient::from_native_local_operator_files(&root.join("admission.key"))
        } else {
            AdmissionClient::paired_fixture_files(
                Path::new("/var/run/osmap-account-admission/admission.sock"),
                &root.join("admission.key"),
                0,
            )
        }
        .map_err(|_| "admission client custody refused")?,
    );
    let mutation = if native_replay {
        MutationClient::from_native_local_operator_files(
            &root.join("mutation.key"),
            &root.join("session-proof.key"),
        )
    } else {
        MutationClient::stored_fixture_files(
            Path::new("/var/run/osmap-account-mutation/mutation.sock"),
            &root.join("mutation.key"),
            &root.join("session-proof.key"),
            0,
        )
    }
    .map_err(|_| "mutation client custody refused")?;
    if native_replay {
        if !mutation.purpose_separated_from(admission.as_ref()) {
            return Err("native purpose-key separation refused");
        }
        mutation
            .enable_native_consumed_replay_fixture()
            .map_err(|_| "native consumed-wire replay arm refused")?;
    }
    let authenticated = admission
        .authenticate_before(account, &boot.current_password, deadline)
        .map_err(|_| "initial authoritative authentication unavailable")?
        .ok_or("initial authoritative authentication refused")?;
    if authenticated.account != account || authenticated.epoch != 0 {
        return Err("initial signed authority mismatch");
    }
    admission
        .admit_before(bob, 0, deadline)
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
        .issue_with_epoch(&context, account, RequiredSecondFactor::Totp, Some(0))
        .map_err(|_| "first old-session issuance refused")?;
    let second = sessions
        .issue_with_epoch(&context, account, RequiredSecondFactor::Totp, Some(0))
        .map_err(|_| "second old-session issuance refused")?;
    let bob = sessions
        .issue_with_epoch(&context, bob, RequiredSecondFactor::Totp, Some(0))
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
            account,
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
    let replay_refusal = if native_replay {
        match mutation.native_consumed_replay_refusal_fixture() {
            Some(value @ ("SIGNED_KNOWN_REFUSED" | "CLOSED_WITHOUT_RECEIPT")) => value,
            _ => return Err("native consumed-wire replay verdict unconfirmed; no retry"),
        }
    } else {
        "NOT_REQUESTED"
    };
    // First prove old authority fails before physically revoking session files.
    // This closes the security question even if browser cleanup later fails.
    for token in [&first.token, &second.token] {
        if sessions.validate(&context, token).is_ok() {
            return Err("old stored session retained authority after transaction");
        }
    }
    if admission.admit_before(account, 0, deadline) != Err(crate::account_admission::Error::Refused)
    {
        return Err("old epoch did not receive authoritative refusal");
    }
    let revoked = sessions.revoke_password_change_sessions(receipt, deadline);
    if revoked != (BrowserRevocation::OldSessionsRevoked { count: 2 }) {
        return Err("old browser session revocation incomplete");
    }
    if admission
        .authenticate_before(account, &boot.current_password, deadline)
        .map_err(|_| "obsolete password verdict unavailable")?
        .is_some()
    {
        return Err("obsolete password still accepted");
    }
    let changed = admission
        .authenticate_before(account, &boot.replacement_password, deadline)
        .map_err(|_| "replacement password verdict unavailable")?
        .ok_or("replacement password refused")?;
    if changed.account != account || changed.epoch != 1 {
        return Err("replacement signed epoch mismatch");
    }
    let fresh = sessions
        .issue_with_epoch(
            &context,
            account,
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
    if native_replay {
        println!("\nnative_concurrent_transaction result=PASS ordinary_native_client=true real_totp_verified=true single_original_dispatch=true consumed_wire_replay={replay_refusal} credential_changed=true old_password_refused=true replacement_password_accepted=true epoch=1 old_sessions_authority_refused=2 old_sessions_revoked=2 fresh_session_valid=true control_session_preserved=true independent_no_second_write=parent installed_browser_qualified=false");
    } else {
        println!("\nnative_ordinary_transaction result=PASS ordinary_service=true current_authorized=true real_totp_verified=true single_dispatch=true credential_changed=true old_password_refused=true replacement_password_accepted=true epoch=1 old_sessions_authority_refused=2 old_sessions_revoked=2 fresh_session_valid=true bob_session_preserved=true installed_browser_qualified=false");
    }
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

// Fixed T04 root-only controller. Outer root actor owns the fresh fixture,
// allowlists, ordinary CLI publication/restoration and authoritative readbacks.
#[cfg(unix)]
#[test]
#[ignore = "requires fixed fresh T04 root fixture and matching protected test artifact"]
fn native_installed_t04_root_controller() -> Result<(), &'static str> {
    use std::io::{BufRead, Write};
    use std::os::fd::OwnedFd;
    use std::os::unix::fs::FileTypeExt;
    use std::os::unix::net::UnixStream;
    use std::process::Stdio;
    if !cfg!(target_os = "openbsd") || crate::openbsd::effective_uid() != 0 {
        return Err("T04_ROOT_REQUIRED");
    }
    crate::openbsd::disable_core_dumps().map_err(|_| "T04_CORE_LIMIT")?;
    let deadline = Instant::now() + Duration::from_secs(120);
    let outer_cleanup_deadline = deadline + Duration::from_secs(5);
    let program = Path::new("/var/run/osmap-installed-t04-web-20261025-01/native-service");
    crate::openpgp_inventory_runtime::exact_path(program, 1001)
        .map_err(|_| "T04_PROGRAM_ANCESTRY")?;
    let before = fs::symlink_metadata(program).map_err(|_| "T04_PROGRAM_METADATA")?;
    if std::env::current_exe().map_err(|_| "T04_CURRENT_PROGRAM")? != program
        || !before.is_file()
        || before.uid() != 0
        || before.gid() != 1001
        || before.mode() & 0o7777 != 0o550
        || before.nlink() != 1
    {
        return Err("T04_FIXED_PROGRAM_CUSTODY");
    }
    let identity = (
        before.dev(),
        before.ino(),
        before.mode(),
        before.len(),
        before.mtime(),
        before.ctime(),
    );
    let mut raw = Vec::new();
    std::io::stdin()
        .lock()
        .take(4097)
        .read_until(b'\n', &mut raw)
        .map_err(|_| "T04_BOOT_READ")?;
    if raw.len() > 4096 || raw.last() != Some(&b'\n') {
        return Err("T04_BOOT_BOUND");
    }
    let boot: Bootstrap = serde_json::from_slice(&raw).map_err(|_| "T04_BOOT_SHAPE")?;
    if boot.version != 1
        || !fixed_client_root(&boot.client_root)
        || hex_secret(&boot.current_password).is_none()
        || hex_secret(&boot.replacement_password).is_none()
        || hex_secret(&boot.totp_secret_hex).is_none()
        || boot.current_password == boot.replacement_password
    {
        return Err("T04_BOOT_AUTHORITY");
    }
    for path in [
        crate::config::LOCAL_ACCOUNT_ADMISSION_SOCKET,
        crate::config::LOCAL_ACCOUNT_MUTATION_SOCKET,
    ] {
        if fs::symlink_metadata(path).is_ok() {
            return Err("T04_SOCKET_ALREADY_PRESENT");
        }
    }
    let (mut gate, child_gate) = UnixStream::pair().map_err(|_| "T04_GATE_PAIR")?;
    let mut helper = T04Actor::spawn(
        crate::auth::native_t04_fixture_command(0)?,
        Stdio::from(OwnedFd::from(child_gate)),
        outer_cleanup_deadline,
    )?;
    let mut issuer = None;
    let mut client = None;
    let mut phase = "HELPER_STARTUP";
    let result = (|| {
        let startup = deadline.min(Instant::now() + Duration::from_secs(8));
        loop {
            helper.pump()?;
            if helper.exited()? || Instant::now() >= startup {
                return Err("T04_HELPER_NOT_READY");
            }
            if [
                crate::config::LOCAL_ACCOUNT_ADMISSION_SOCKET,
                crate::config::LOCAL_ACCOUNT_MUTATION_SOCKET,
            ]
            .iter()
            .all(|path| {
                fs::symlink_metadata(path).is_ok_and(|m| m.file_type().is_socket() && m.uid() == 0)
            }) {
                break;
            }
            std::thread::sleep(Duration::from_millis(5));
        }
        let after = fs::symlink_metadata(program).map_err(|_| "T04_PROGRAM_RECHECK")?;
        if identity
            != (
                after.dev(),
                after.ino(),
                after.mode(),
                after.len(),
                after.mtime(),
                after.ctime(),
            )
        {
            return Err("T04_PROGRAM_CHANGED");
        }
        phase = "ISSUER_WARMUP";
        let (mut control, child_control) = UnixStream::pair().map_err(|_| "T04_ISSUER_PAIR")?;
        issuer = Some(T04Actor::spawn(
            crate::auth::native_t04_fixture_command(1)?,
            Stdio::from(OwnedFd::from(child_control)),
            outer_cleanup_deadline,
        )?);
        let primary =
            serde_json::to_vec(&serde_json::json!({"alice_password":boot.current_password}))
                .map_err(|_| "T04_PRIMARY_FRAME")?;
        crate::openpgp_inventory_runtime::write_frame(&mut control, &primary, deadline)
            .map_err(|_| "T04_PRIMARY_SEND")?;
        let ready = crate::openpgp_inventory_runtime::read_frame(&mut control, 2048, deadline)
            .map_err(|_| "T04_ISSUER_READY_READ")?;
        if serde_json::from_slice::<serde_json::Value>(&ready)
            .map_err(|_| "T04_ISSUER_READY_JSON")?
            != serde_json::json!({"schema":"osmap-native-issuance-race-ready-v1","captured_epoch":0})
        {
            return Err("T04_ISSUER_NOT_PREWARMED");
        }
        phase = "SINGLE_TRANSACTION";
        client = Some(T04Actor::spawn(
            crate::auth::native_t04_fixture_command(2)?,
            Stdio::piped(),
            outer_cleanup_deadline,
        )?);
        let mut input = client
            .as_mut()
            .unwrap()
            .child
            .stdin
            .take()
            .ok_or("T04_CLIENT_STDIN")?;
        input.write_all(&raw).map_err(|_| "T04_CLIENT_BOOT_WRITE")?;
        drop(input); // The actual native04-derived client requires real EOF.
        raw.fill(0);
        let pending = crate::openpgp_inventory_runtime::read_frame(&mut gate, 1, deadline)
            .map_err(|_| "T04_PENDING_FRAME")?;
        if pending != b"P" {
            return Err("T04_PENDING_UNCONFIRMED");
        }
        phase = "HELD_ISSUANCE";
        // Helper's existing five-second gate began before P. Reserve 500ms;
        // no second primary authentication, cold launch or parent handshake here.
        let held = deadline.min(Instant::now() + Duration::from_millis(4500));
        crate::openpgp_inventory_runtime::write_frame(&mut control, b"G", held)
            .map_err(|_| "T04_ISSUER_RELEASE")?;
        let bytes = crate::openpgp_inventory_runtime::read_frame(&mut control, 2048, held)
            .map_err(|_| "T04_HELD_READ")?;
        let value: serde_json::Value =
            serde_json::from_slice(&bytes).map_err(|_| "T04_HELD_JSON")?;
        let refusal = value
            .get("native_admission_refusal")
            .and_then(|v| v.as_str())
            .ok_or("T04_HELD_REFUSAL")?;
        if !matches!(refusal, "SIGNED_REFUSED" | "UNAVAILABLE" | "EXPIRED")
            || value
                != serde_json::json!({"schema":"osmap-native-issuance-race-held-v1","issuance_denied":true,"new_sessions":0,"native_admission_deadline_ms":2000,"native_admission_calls":1,"native_admission_refusal":refusal})
        {
            return Err("T04_HELD_NOT_CONFIRMED");
        }
        crate::openpgp_inventory_runtime::write_frame(&mut gate, b"G", held)
            .map_err(|_| "T04_GATE_RELEASE")?;
        phase = "TRANSACTION_AND_REPLAY";
        let actor = client.as_mut().unwrap();
        actor.finish(deadline)?;
        let text = std::str::from_utf8(&actor.out).map_err(|_| "T04_CLIENT_OUTPUT_ENCODING")?;
        let signed = text
            .lines()
            .filter(|line| {
                line.starts_with("native_concurrent_transaction result=PASS ")
                    && line.contains(" consumed_wire_replay=SIGNED_KNOWN_REFUSED ")
            })
            .count();
        let closed = text
            .lines()
            .filter(|line| {
                line.starts_with("native_concurrent_transaction result=PASS ")
                    && line.contains(" consumed_wire_replay=CLOSED_WITHOUT_RECEIPT ")
            })
            .count();
        if signed + closed != 1 {
            return Err("T04_REPLAY_RESULT_UNCONFIRMED");
        }
        phase = "POST_TRANSACTION_ISSUER";
        crate::openpgp_inventory_runtime::write_frame(&mut control, b"G", deadline)
            .map_err(|_| "T04_FINAL_ISSUER_RELEASE")?;
        let final_bytes =
            crate::openpgp_inventory_runtime::read_frame(&mut control, 2048, deadline)
                .map_err(|_| "T04_FINAL_ISSUER_READ")?;
        if serde_json::from_slice::<serde_json::Value>(&final_bytes)
            .map_err(|_| "T04_FINAL_ISSUER_JSON")?
            != serde_json::json!({"schema":"osmap-native-issuance-race-v1","issuance_denied":true,"new_sessions":0,"stale_epoch_refused":true,"current_epoch":1,"bob_epoch":0})
        {
            return Err("T04_FINAL_ISSUER_UNCONFIRMED");
        }
        issuer.as_mut().unwrap().finish(deadline)?;
        println!("native_t04_runtime result=PASS held_issuance_denied=true issued_during_hold=0 consumed_wire_replay={} independent_sql_store_witness=parent browser_qualification=separate", if signed == 1 {"SIGNED_KNOWN_REFUSED"} else {"CLOSED_WITHOUT_RECEIPT"});
        Ok(())
    })();
    raw.fill(0);
    // Each unreaped born leader retains its group lease through signalling.
    let cleanup_deadline = Instant::now() + Duration::from_secs(5);
    let client_clean = client.as_mut().is_none_or(|a| a.stop(cleanup_deadline));
    let issuer_clean = issuer.as_mut().is_none_or(|a| a.stop(cleanup_deadline));
    let helper_clean = helper.stop(cleanup_deadline);
    for (role, actor) in [
        ("HELPER", Some(&helper)),
        ("ISSUER", issuer.as_ref()),
        ("CLIENT", client.as_ref()),
    ] {
        if let Some(actor) = actor {
            actor.diagnostic(role);
        }
    }
    println!(
        "native_t04_controller phase={phase} functional={} cleanup={} private_native_text=RAM_ONLY",
        if result.is_ok() {
            "PASS"
        } else {
            "REFUSED_OR_UNCERTAIN"
        },
        if client_clean && issuer_clean && helper_clean {
            "PASS"
        } else {
            "UNCERTAIN"
        }
    );
    result?;
    if !(client_clean && issuer_clean && helper_clean) {
        return Err("T04_OWNED_CLEANUP_UNCERTAIN");
    }
    Ok(())
}

#[cfg(unix)]
struct T04Actor {
    child: std::process::Child,
    stdout: Option<std::process::ChildStdout>,
    stderr: Option<std::process::ChildStderr>,
    out: Vec<u8>,
    err: Vec<u8>,
    out_eof: bool,
    err_eof: bool,
    status: Option<std::process::ExitStatus>,
    cleanup_deadline: Instant,
}
#[cfg(unix)]
impl T04Actor {
    fn spawn(
        mut command: std::process::Command,
        input: std::process::Stdio,
        cleanup_deadline: Instant,
    ) -> Result<Self, &'static str> {
        use std::os::fd::AsRawFd;
        use std::os::unix::process::CommandExt;
        command
            .stdin(input)
            .stdout(std::process::Stdio::piped())
            .stderr(std::process::Stdio::piped())
            .process_group(0);
        let mut child = command.spawn().map_err(|_| "T04_ACTOR_SPAWN")?;
        let stdout = child.stdout.take();
        let stderr = child.stderr.take();
        let actor = Self {
            child,
            stdout,
            stderr,
            out: Vec::new(),
            err: Vec::new(),
            out_eof: false,
            err_eof: false,
            status: None,
            cleanup_deadline,
        };
        crate::openbsd::set_descriptor_nonblocking(
            actor
                .stdout
                .as_ref()
                .ok_or("T04_STDOUT_MISSING")?
                .as_raw_fd(),
        )
        .map_err(|_| "T04_STDOUT_NONBLOCK")?;
        crate::openbsd::set_descriptor_nonblocking(
            actor
                .stderr
                .as_ref()
                .ok_or("T04_STDERR_MISSING")?
                .as_raw_fd(),
        )
        .map_err(|_| "T04_STDERR_NONBLOCK")?;
        println!(
            "native_t04_born pid={} process_group=OWNED_UNREAPED",
            actor.child.id()
        );
        Ok(actor)
    }
    fn pump(&mut self) -> Result<(), &'static str> {
        fn drain(
            reader: &mut dyn Read,
            bytes: &mut Vec<u8>,
            eof: &mut bool,
        ) -> Result<(), &'static str> {
            let mut block = [0; 4096];
            loop {
                match reader.read(&mut block) {
                    Ok(0) => {
                        *eof = true;
                        return Ok(());
                    }
                    Ok(n) => {
                        if bytes.len() + n > 65536 {
                            return Err("T04_PRIVATE_OUTPUT_BOUND");
                        };
                        bytes.extend_from_slice(&block[..n]);
                    }
                    Err(e) if e.kind() == std::io::ErrorKind::WouldBlock => return Ok(()),
                    Err(e) if e.kind() == std::io::ErrorKind::Interrupted => continue,
                    Err(_) => return Err("T04_PRIVATE_OUTPUT_READ"),
                }
            }
        }
        drain(
            self.stdout.as_mut().ok_or("T04_STDOUT_MISSING")?,
            &mut self.out,
            &mut self.out_eof,
        )?;
        drain(
            self.stderr.as_mut().ok_or("T04_STDERR_MISSING")?,
            &mut self.err,
            &mut self.err_eof,
        )
    }
    fn exited(&self) -> Result<bool, &'static str> {
        if self.status.is_some() {
            return Ok(true);
        }
        crate::openbsd::owned_child_exited_without_reap(self.child.id())
            .map_err(|_| "T04_OWNED_EXIT_OBSERVATION")
    }
    fn finish(&mut self, deadline: Instant) -> Result<(), &'static str> {
        while !self.exited()? {
            self.pump()?;
            if Instant::now() >= deadline {
                return Err("T04_ACTOR_DEADLINE");
            }
            std::thread::sleep(Duration::from_millis(2));
        }
        if self.status.is_none() {
            if crate::openbsd::process_group_exists(self.child.id())
                .map_err(|_| "T04_GROUP_OBSERVATION")?
            {
                crate::openbsd::kill_process_group(self.child.id())
                    .map_err(|_| "T04_OWNED_GROUP_KILL")?;
            }
            // WNOWAIT above proves wait cannot block, and kept PID/PGID leased.
            self.status = Some(self.child.wait().map_err(|_| "T04_OWNED_REAP")?);
        }
        while !(self.out_eof && self.err_eof) {
            self.pump()?;
            if Instant::now() >= deadline {
                return Err("T04_PIPE_EOF_DEADLINE");
            }
            std::thread::sleep(Duration::from_millis(2));
        }
        if !self.status.is_some_and(|s| s.success()) {
            return Err("T04_ACTOR_EXIT_REFUSED");
        }
        Ok(())
    }
    fn stop(&mut self, deadline: Instant) -> bool {
        self.cleanup_deadline = deadline;
        if self.status.is_some() {
            return self.out_eof && self.err_eof;
        }
        // A failed ownership observation refuses signalling; no PID inference.
        match self.exited() {
            Ok(false) => {
                if crate::openbsd::fixture_t04_terminate_owned_group(self.child.id()).is_err() {
                    return false;
                }
            }
            Ok(true) => {}
            Err(_) => return false,
        }
        let graceful = deadline
            .checked_sub(Duration::from_secs(1))
            .unwrap_or(deadline);
        let _ = self.finish(graceful);
        if self.status.is_none() {
            if self.exited().is_err()
                || crate::openbsd::kill_process_group(self.child.id()).is_err()
            {
                return false;
            }
            let _ = self.finish(deadline);
        }
        // Expected TERM/nonzero exit is a process outcome, not failed cleanup.
        self.status.is_some() && self.out_eof && self.err_eof
    }
    fn diagnostic(&self, role: &str) {
        use sha2::{Digest, Sha256};
        use std::os::unix::process::ExitStatusExt;
        println!("native_t04_actor role={role} exit_code={} term_signal={} stdout_bytes={} stderr_bytes={} stdout_sha256={:x} stderr_sha256={:x} private_text=NOT_EXPORTED",self.status.and_then(|s|s.code()).unwrap_or(-1),self.status.and_then(|s|s.signal()).unwrap_or(-1),self.out.len(),self.err.len(),Sha256::digest(&self.out),Sha256::digest(&self.err));
    }
}
#[cfg(unix)]
impl Drop for T04Actor {
    fn drop(&mut self) {
        let until = self
            .cleanup_deadline
            .min(Instant::now() + Duration::from_secs(5));
        if self.status.is_none()
            && Instant::now() < until
            && self.exited().is_ok()
            && crate::openbsd::kill_process_group(self.child.id()).is_ok()
        {
            while Instant::now() < until {
                if matches!(self.exited(), Ok(true)) {
                    self.status = self.child.wait().ok();
                    break;
                }
                std::thread::sleep(Duration::from_millis(2));
            }
        }
        self.out.fill(0);
        self.err.fill(0);
    }
}
