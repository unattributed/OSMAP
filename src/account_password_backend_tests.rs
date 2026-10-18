use super::*;
use crate::auth::{CommandExecution, CommandExecutionError};
use std::cell::RefCell;
use std::collections::VecDeque;

const ACCOUNT: &str = "alice@example.test";
const STAMP: &str = "20261004170000";
const NEXT: &str = "20261004170001";
const PASSWORD: &str = "public-new-passphrase";

struct Call {
    program: String,
    args: Vec<String>,
    input: Vec<u8>,
    timeout: Duration,
    limit: usize,
}
struct Executor {
    calls: RefCell<Vec<Call>>,
    replies: RefCell<VecDeque<Result<CommandExecution, CommandExecutionError>>>,
    late_write: bool,
}
impl Executor {
    fn new(replies: Vec<Result<CommandExecution, CommandExecutionError>>) -> Self {
        Self {
            calls: Default::default(),
            replies: RefCell::new(replies.into()),
            late_write: false,
        }
    }
}
impl CommandExecutor for Executor {
    fn run_with_stdin_bytes(
        &self,
        _: &str,
        _: &[String],
        _: &[u8],
    ) -> Result<CommandExecution, CommandExecutionError> {
        panic!("bounded executor method must be used")
    }
    fn run_with_stdin_bytes_timeout_and_output_limit(
        &self,
        program: &str,
        args: &[String],
        input: &[u8],
        timeout: Duration,
        limit: usize,
    ) -> Result<CommandExecution, CommandExecutionError> {
        self.calls.borrow_mut().push(Call {
            program: program.into(),
            args: args.to_vec(),
            input: input.to_vec(),
            timeout,
            limit,
        });
        if self.late_write && input.starts_with(b"START TRANSACTION;") {
            std::thread::sleep(timeout + Duration::from_millis(2));
        }
        self.replies
            .borrow_mut()
            .pop_front()
            .expect("unexpected utility dispatch")
    }
}
fn old_hash() -> String {
    format!("{{BLF-CRYPT}}$2y$05${}", "A".repeat(53))
}
fn new_hash() -> String {
    format!("{ARGON_PREFIX}{}${}", "S".repeat(22), "B".repeat(43))
}
fn ok(text: String) -> Result<CommandExecution, CommandExecutionError> {
    Ok(CommandExecution {
        status_code: 0,
        stdout: text,
        stderr: String::new(),
    })
}
fn row() -> Result<CommandExecution, CommandExecutionError> {
    ok(format!(
        "{}\t{STAMP}\t1\t1\n",
        upper_hex(old_hash().as_bytes())
    ))
}
fn hash() -> Result<CommandExecution, CommandExecutionError> {
    ok(format!("{}\n", new_hash()))
}
fn receipt(count: &str) -> Result<CommandExecution, CommandExecutionError> {
    ok(format!(
        "{count}\n{}\t{NEXT}\n",
        upper_hex(new_hash().as_bytes())
    ))
}
fn request(password: &str) -> Request {
    crate::account_mutation::tests::issue("public-old-value", password, 3, 100).unwrap()
}
fn deadline() -> Instant {
    Instant::now() + Duration::from_secs(2)
}

#[test]
fn fixed_read_hash_and_conditional_write_return_only_database_time() {
    let backend = Backend::new(Executor::new(vec![row(), hash(), receipt("1")]));
    let snapshot = backend.read(ACCOUNT, deadline()).unwrap();
    let admitted = RefCell::new(false);
    let receipt = backend
        .replace(snapshot, &request(PASSWORD), deadline(), || {
            *admitted.borrow_mut() = true;
            Ok(())
        })
        .unwrap();
    assert_eq!(receipt.changed_at(), NEXT);
    assert!(*admitted.borrow());
    let calls = backend.executor.calls.borrow();
    assert_eq!(calls.len(), 3);
    assert_eq!(calls[0].program, SQL_PROGRAM);
    assert_eq!(calls[0].args, SQL_ARGS);
    assert!(calls[0].input.starts_with(b"SELECT HEX(password),"));
    let read_query = std::str::from_utf8(&calls[0].input).unwrap();
    assert!(read_query.contains("WHERE BINARY username=BINARY CONVERT(0x"));
    assert!(!read_query.contains("WHERE username="));
    assert_eq!(calls[1].program, HASH_PROGRAM);
    assert_eq!(calls[1].args, HASH_ARGS);
    assert_eq!(
        calls[1].input,
        format!("{PASSWORD}\n{PASSWORD}\n").as_bytes()
    );
    let query = std::str::from_utf8(&calls[2].input).unwrap();
    for term in [
        "START TRANSACTION;",
        "AND active=1 AND smtp_active=1",
        "AND BINARY password=BINARY",
        "AND modified=STR_TO_DATE",
        "SELECT ROW_COUNT();",
        "COMMIT;",
    ] {
        assert!(query.contains(term));
    }
    // The actual mailbox collation is case-insensitive. Read, CAS and receipt
    // readback must all select the exact canonical account bytes.
    assert_eq!(
        query
            .matches("WHERE BINARY username=BINARY CONVERT(0x")
            .count(),
        2
    );
    assert!(!query.contains("WHERE username="));
    for value in [ACCOUNT, PASSWORD, &old_hash(), &new_hash()] {
        assert!(!query.contains(value));
    }
    for call in calls.iter() {
        assert!(call.timeout > Duration::ZERO && call.timeout <= PHASE_LIMIT);
        assert_eq!(call.limit, OUTPUT_LIMIT);
        assert!(!call
            .args
            .iter()
            .any(|arg| arg.contains(PASSWORD) || arg.contains(ACCOUNT)));
    }
}

#[test]
fn account_snapshot_and_fresh_before_write_are_required() {
    let backend = Backend::new(Executor::new(vec![row()]));
    let snapshot = backend.read("bob@example.test", deadline()).unwrap();
    assert!(matches!(
        backend.replace(snapshot, &request(PASSWORD), deadline(), || Ok(())),
        Err(Error::Refused)
    ));
    assert_eq!(backend.executor.calls.borrow().len(), 1);
    let backend = Backend::new(Executor::new(vec![row(), hash()]));
    let snapshot = backend.read(ACCOUNT, deadline()).unwrap();
    assert!(matches!(
        backend.replace(snapshot, &request(PASSWORD), deadline(), || Err(unknown())),
        Err(Error::Refused)
    ));
    assert_eq!(backend.executor.calls.borrow().len(), 2);
}

#[test]
fn zero_row_conflict_refuses_and_ambiguous_write_never_retries() {
    for (response, refused) in [
        (receipt("0"), true),
        (receipt("2"), false),
        (ok("1\n".into()), false),
        (ok(format!("1\n00\t{NEXT}\n")), false),
        (
            Err(CommandExecutionError {
                reason: "synthetic private diagnostic".into(),
            }),
            false,
        ),
    ] {
        let backend = Backend::new(Executor::new(vec![row(), hash(), response]));
        let snapshot = backend.read(ACCOUNT, deadline()).unwrap();
        let result = backend.replace(snapshot, &request(PASSWORD), deadline(), || Ok(()));
        if refused {
            assert!(matches!(result, Err(Error::Refused)));
        } else {
            assert!(matches!(
                result,
                Err(Error::Unconfirmed { changed_at: None })
            ));
        }
        assert_eq!(backend.executor.calls.borrow().len(), 3);
    }
}

#[test]
fn read_refuses_duplicate_disabled_unknown_hash_and_bad_calendar() {
    let valid = format!("{}\t{STAMP}\t1\t1\n", upper_hex(old_hash().as_bytes()));
    for text in [
        String::new(),
        valid.repeat(2),
        valid.replace("\t1\t1", "\t0\t1"),
        valid.replace(STAMP, "20260230000000"),
        format!("00\t{STAMP}\t1\t1\n"),
        valid.replace("\t1\t1", "\t1\t2"),
    ] {
        assert!(matches!(
            Backend::new(Executor::new(vec![ok(text)])).read(ACCOUNT, deadline()),
            Err(Error::Refused)
        ));
    }
}

#[test]
fn shell_shaped_accounts_and_expired_requests_never_dispatch() {
    let backend = Backend::new(Executor::new(vec![]));
    for account in [
        "../alice",
        "alice@example.test\n",
        "alice@example.test';DROP TABLE mailbox",
        "alice@example.test`id`",
    ] {
        assert!(matches!(
            backend.read(account, deadline()),
            Err(Error::Refused)
        ));
    }
    assert!(matches!(
        backend.read(ACCOUNT, Instant::now()),
        Err(Error::Refused)
    ));
    assert!(backend.executor.calls.borrow().is_empty());
}

#[test]
fn unsupported_or_multiline_generated_hash_never_dispatches_sql() {
    for text in [
        old_hash(),
        "unknown".into(),
        format!("{}\n\n", new_hash()),
        new_hash().replace("m=65536", "m=8192"),
        format!("{}\r\n", new_hash()),
    ] {
        let backend = Backend::new(Executor::new(vec![row(), ok(text)]));
        let snapshot = backend.read(ACCOUNT, deadline()).unwrap();
        assert!(matches!(
            backend.replace(snapshot, &request(PASSWORD), deadline(), || Ok(())),
            Err(Error::Refused)
        ));
        assert_eq!(backend.executor.calls.borrow().len(), 2);
    }
}

#[test]
fn stderr_overflow_nonascii_and_nonzero_refuse_at_correct_boundary() {
    for response in [
        CommandExecution {
            status_code: 0,
            stdout: String::new(),
            stderr: "private warning".into(),
        },
        CommandExecution {
            status_code: 1,
            stdout: String::new(),
            stderr: String::new(),
        },
        CommandExecution {
            status_code: 0,
            stdout: "x".repeat(OUTPUT_LIMIT + 1),
            stderr: String::new(),
        },
        CommandExecution {
            status_code: 0,
            stdout: "é".into(),
            stderr: String::new(),
        },
    ] {
        let code = response.status_code;
        let out = response.stdout.clone();
        let err = response.stderr.clone();
        assert!(matches!(
            Backend::new(Executor::new(vec![Ok(response)])).read(ACCOUNT, deadline()),
            Err(Error::Refused)
        ));
        let backend = Backend::new(Executor::new(vec![
            row(),
            hash(),
            Ok(CommandExecution {
                status_code: code,
                stdout: out,
                stderr: err,
            }),
        ]));
        let snapshot = backend.read(ACCOUNT, deadline()).unwrap();
        assert!(matches!(
            backend.replace(snapshot, &request(PASSWORD), deadline(), || Ok(())),
            Err(Error::Unconfirmed { changed_at: None })
        ));
        assert_eq!(backend.executor.calls.borrow().len(), 3);
    }
}

#[test]
fn full_unicode_passphrase_bytes_reach_hash_input_without_truncation() {
    for password in [
        "x".repeat(15),
        "x".repeat(128),
        "🙂".repeat(128),
        format!("{}z", "🙂".repeat(127)),
    ] {
        let backend = Backend::new(Executor::new(vec![row(), hash(), receipt("1")]));
        let snapshot = backend.read(ACCOUNT, deadline()).unwrap();
        backend
            .replace(snapshot, &request(&password), deadline(), || Ok(()))
            .unwrap();
        assert_eq!(
            backend.executor.calls.borrow()[1].input,
            format!("{password}\n{password}\n").as_bytes()
        );
    }
}

#[test]
fn late_verified_write_preserves_time_and_late_conflict_is_uncertain() {
    for (response, expected) in [(receipt("1"), Some(NEXT.into())), (receipt("0"), None)] {
        let mut executor = Executor::new(vec![row(), hash(), response]);
        executor.late_write = true;
        let backend = Backend::new(executor);
        let snapshot = backend.read(ACCOUNT, deadline()).unwrap();
        let result = backend.replace(
            snapshot,
            &request(PASSWORD),
            Instant::now() + Duration::from_millis(30),
            || Ok(()),
        );
        assert!(matches!(result, Err(Error::Unconfirmed { changed_at }) if changed_at == expected));
        assert_eq!(backend.executor.calls.borrow().len(), 3);
    }
}

/// Component proof only: authoritative native SQL/hash plus durable refusal.
/// It deliberately finishes contained because native mail/factor/browser
/// containment is outside this test. No operator account or provider is used.
#[cfg(target_os = "openbsd")]
#[test]
#[ignore = "root-provisioned fixed SQL/hash role grants and synthetic rows required"]
fn native_parent_sealed_sql_hash_cas_preserves_bob_and_contains_alice() -> Result<(), &'static str>
{
    use crate::account_password_confinement::ParentPlan;
    use crate::account_password_native::{NativeProfile, Role};
    use crate::account_password_process::FixedExecutor;
    use crate::account_password_state::{State, Store};
    use hmac::{Hmac, Mac};
    use sha2::{Digest, Sha256};
    use std::io::Read;
    use std::os::unix::fs::MetadataExt;
    use std::path::Path;
    use std::time::{SystemTime, UNIX_EPOCH};

    const ALICE: &str = "alice@osmap-password.invalid";
    const BOB: &str = "bob@osmap-password.invalid";
    const EPOCH: &str = "/var/db/osmap-account/epoch";
    const CONTEXT: &str = "/etc/osmap/account-runtime/sql-native-fixture.json";
    const KEY: [u8; 32] = [17; 32];
    #[derive(serde::Deserialize)]
    #[serde(deny_unknown_fields)]
    struct RowReceipt {
        account: String,
        initial_hash_sha256: String,
        modified: String,
        before_count: u8,
        inserted_count: u8,
    }
    #[derive(serde::Deserialize)]
    #[serde(deny_unknown_fields)]
    struct FixtureReceipt {
        version: u8,
        authority: String,
        purpose: String,
        issued_at: u64,
        expires_at: u64,
        lease_nonce: String,
        rows: [RowReceipt; 2],
    }
    fn lower_hex(bytes: &[u8]) -> String {
        bytes.iter().map(|b| format!("{b:02x}")).collect()
    }
    fn hex64(value: &str) -> bool {
        value.len() == 64
            && value
                .bytes()
                .all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(&b))
    }
    fn unix_now() -> Result<u64, &'static str> {
        SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .map(|v| v.as_secs())
            .map_err(|_| "native clock unavailable")
    }
    fn random_credential() -> Result<String, &'static str> {
        let mut random = [0_u8; 32];
        getrandom::getrandom(&mut random).map_err(|_| "native random source unavailable")?;
        Ok(lower_hex(&random))
    }
    let original = Instant::now() + Duration::from_secs(60);
    if !crate::openbsd::password_native_authority() {
        return Err("fixed native root authority required");
    }
    crate::openbsd::disable_core_dumps().map_err(|_| "core limit refused")?;
    std::env::set_current_dir("/").map_err(|_| "fixed working directory refused")?;
    // A short-lived root-only receipt attests that the future root custodian
    // observed these two reserved rows absent, then created them once. It holds
    // digests, never the random provisioned passwords or reusable verifiers.
    // Read and close it before the actual irreversible parent seal.
    let receipt_file = crate::openpgp_inventory_runtime::file(Path::new(CONTEXT), 0, false, 4096)
        .map_err(|_| "fixed fixture receipt unavailable")?;
    let metadata = receipt_file
        .metadata()
        .map_err(|_| "fixture receipt metadata unavailable")?;
    if metadata.nlink() != 1 || metadata.mode() & 0o7777 != 0o600 {
        return Err("fixture receipt ownership or mode refused");
    }
    let mut receipt_bytes = Vec::new();
    receipt_file
        .take(4097)
        .read_to_end(&mut receipt_bytes)
        .map_err(|_| "fixture receipt read refused")?;
    if receipt_bytes.len() > 4096 {
        return Err("fixture receipt overflow");
    }
    let fixture: FixtureReceipt =
        serde_json::from_slice(&receipt_bytes).map_err(|_| "fixed fixture receipt invalid")?;
    let now = unix_now()?;
    if fixture.version != 1
        || fixture.authority != "mail.blackbagsecurity.com"
        || fixture.purpose != "osmap-password-native-sql-hash-fixture"
        || now
            .checked_sub(fixture.issued_at)
            .is_none_or(|age| age > 30)
        || fixture.expires_at < now.checked_add(63).ok_or("native clock overflow")?
        || fixture.expires_at
            > fixture
                .issued_at
                .checked_add(180)
                .ok_or("fixture clock overflow")?
        || !hex64(&fixture.lease_nonce)
        || fixture.rows[0].account != ALICE
        || fixture.rows[1].account != BOB
        || fixture.rows.iter().any(|row| {
            row.before_count != 0
                || row.inserted_count != 1
                || !hex64(&row.initial_hash_sha256)
                || !crate::account_mutation::changed_at_valid(&row.modified)
        })
    {
        return Err("fixture receipt authority, freshness or creation lease refused");
    }
    // Neither value is the provisioned old password. Current-password/TOTP
    // authentication is outside this SQL-only component proof. Both action
    // credential fields are unpredictable, RAM-only and never diagnostic data.
    let current_credential = random_credential()?;
    let next_credential = random_credential()?;
    let sql = NativeProfile::qualification_candidate(Role::Sql, original)
        .map_err(|_| "fixed SQL role/configuration unavailable")?;
    let hash_profile = NativeProfile::qualification_candidate(Role::Hash, original)
        .map_err(|_| "fixed hash role/configuration unavailable")?;
    let store = Store::open(Path::new(EPOCH), 0).map_err(|_| "fixed epoch store unavailable")?;
    for account in [ALICE, BOB] {
        let status = store
            .lock_before(account, original)
            .map_err(|_| "fixture epoch lock refused")?
            .admission(Some(0))
            .map_err(|_| "unexpected fixture epoch state")?;
        if status.changed_at.is_some() {
            return Err("unexpected fixture prior write time");
        }
    }
    let now = unix_now()?;
    let mut intent_digest = Sha256::new();
    intent_digest.update(b"osmap native SQL/hash component fixture v1\0");
    intent_digest.update(fixture.lease_nonce.as_bytes());
    let intent = lower_hex(&intent_digest.finalize());
    // Public fixture MAC only; this does not claim current-password/TOTP or
    // stored-browser-session authentication. The real typed receiver parses it.
    let payload = serde_json::to_vec(&serde_json::json!([
        "osmap-account-mutation-v1",
        "change_password",
        "request",
        ALICE,
        0,
        intent,
        "a".repeat(64),
        "native-sql-hash-component",
        "127.0.0.1",
        now,
        now.checked_add(300).ok_or("native clock overflow")?,
        current_credential,
        next_credential,
        next_credential
    ]))
    .map_err(|_| "fixture action encoding refused")?;
    let mut mac = Hmac::<Sha256>::new_from_slice(&KEY).map_err(|_| "fixture MAC refused")?;
    mac.update(&payload);
    let signature: String = mac
        .finalize()
        .into_bytes()
        .iter()
        .map(|b| format!("{b:02x}"))
        .collect();
    let raw = serde_json::to_vec(&serde_json::json!({
        "schema":"osmap-account-mutation-v1", "action":"change_password", "account":ALICE,
        "epoch":0, "intent_reference":intent, "session_id":"a".repeat(64),
        "request_id":"native-sql-hash-component", "source":"127.0.0.1", "issued":now,
        "expires":now.checked_add(300).ok_or("native clock overflow")?, "current":current_credential,
        "new":next_credential, "confirmation":next_credential, "signature":signature
    })).map_err(|_| "fixture action encoding refused")?;
    let request = crate::account_mutation::Verifier::default()
        .request(&raw, &KEY, now)
        .map_err(|_| "typed fixture action refused")?;
    let mut parent = ParentPlan::prepare(original).map_err(|_| "fixed parent plan unavailable")?;
    let seal =
        crate::openbsd::seal_password_parent(&parent).map_err(|_| "actual parent seal refused")?;
    parent
        .activate(seal)
        .map_err(|_| "parent custody activation refused")?;
    // No private Primary/Control peers are fabricated. The unused slots carry
    // Hash, whose exact matches_command rejects every Primary/Control command.
    let backend = Backend::new(FixedExecutor::from_profiles(
        original,
        &sql,
        &hash_profile,
        &hash_profile,
        &hash_profile,
    ));
    let mut guard = store
        .lock_before(ALICE, original)
        .map_err(|_| "fixture account lock unavailable")?;
    guard
        .admission(Some(0))
        .map_err(|_| "fixture account no longer active")?;
    let mut pending_attempted = false;
    let mut potential_write = false;
    let mut verified_time: Option<String> = None;
    let mut phase = "initial SQL reads";
    let result = (|| -> Result<(), &'static str> {
        let alice = backend
            .read(ALICE, original)
            .map_err(|_| {
                let [stage, errno, status, stdout_len, stderr_len, sql_code] =
                    crate::account_password_process::native_sql_read_diagnostic();
                let parser = native_read_diagnostic();
                println!("\nnative_sql_read_diagnostic stage={stage} errno={errno} status={status} stdout_len={stdout_len} stderr_len={stderr_len} sql_code={sql_code} parser={parser}");
                "initial Alice SQL read refused"
            })?;
        let bob = backend
            .read(BOB, original)
            .map_err(|_| "initial Bob SQL read refused")?;
        for (snapshot, row) in [&alice, &bob].into_iter().zip(&fixture.rows) {
            if !argon_hash(&snapshot.password_hash)
                || lower_hex(&Sha256::digest(snapshot.password_hash.as_bytes()))
                    != row.initial_hash_sha256
                || snapshot.modified != row.modified
                || !snapshot.smtp_active
            {
                return Err("unexpected synthetic mailbox row; no credential write");
            }
        }
        if unix_now()? >= fixture.expires_at || Instant::now() >= original {
            return Err("fixture lease expired before durable pending");
        }
        let initial_hash = alice.password_hash.clone();
        let initial_time = alice.modified.clone();
        phase = "durable pending";
        pending_attempted = true;
        guard
            .begin(0, request.intent_reference(), now)
            .map_err(|_| "durable pending refused")?;
        phase = "native hash and conditional SQL";
        potential_write = true;
        let write = backend.replace(alice, &request, original, || {
            let status = guard.status().map_err(|_| Error::Refused)?;
            if status.state != State::Pending || status.epoch != 0 || status.changed_at.is_some() {
                return Err(Error::Refused);
            }
            Ok(())
        });
        let receipt = match write {
            Ok(receipt) => receipt,
            Err(Error::Refused) => {
                potential_write = false;
                guard
                    .known_refused()
                    .map_err(|_| "settled no-write state publication refused")?;
                return Err("native hash or conditional write settled refused");
            }
            Err(Error::Unconfirmed { changed_at }) => {
                if let Some(stamp) = changed_at {
                    verified_time = Some(stamp.clone());
                    let _ = guard.record_verified_write(&stamp);
                }
                let _ = guard.contain();
                return Err("native write uncertain; no retry or credential restoration");
            }
        };
        verified_time = Some(receipt.changed_at().into());
        phase = "durable verified write containment";
        guard
            .record_verified_write(receipt.changed_at())
            .map_err(|_| "verified timestamp publication refused")?;
        // Mail/factor/browser containment was not performed; never complete or
        // advance the epoch as though this component established that workflow.
        guard
            .contain()
            .map_err(|_| "durable containment publication refused")?;
        phase = "native SQL readback";
        let after = backend
            .read(ALICE, original)
            .map_err(|_| "Alice write readback unavailable")?;
        let bob_after = backend
            .read(BOB, original)
            .map_err(|_| "Bob preservation readback unavailable")?;
        if !argon_hash(&after.password_hash)
            || after.password_hash == initial_hash
            || after.modified != receipt.changed_at()
            || !after.smtp_active
            || bob_after.password_hash != bob.password_hash
            || bob_after.modified != bob.modified
            || bob_after.smtp_active != bob.smtp_active
        {
            return Err("native write/readback or Bob preservation mismatch");
        }
        if !crate::account_mutation::changed_at_valid(receipt.changed_at())
            || receipt.changed_at() == initial_time
        {
            return Err("authoritative performed-write timestamp absent");
        }
        if Instant::now() >= original {
            return Err("original component operation deadline expired");
        }
        Ok(())
    })();
    if result.is_err() && pending_attempted {
        // A failed write/containment publication may leave durable Pending plus
        // the uncertainty marker. Never clear it or redispatch the SQL write.
        let _ = guard.contain();
    }
    drop(guard);
    // Only local durable-state reconciliation gets this separate finite cleanup
    // bound. No utility, auth, credential write or remote retry occurs here.
    let cleanup = Instant::now() + Duration::from_secs(3);
    let alice_status = store
        .lock_before(ALICE, cleanup)
        .map_err(|_| "Alice persisted disposition unavailable")?
        .status()
        .map_err(|_| "Alice persisted state unavailable")?;
    let bob_status = store
        .lock_before(BOB, cleanup)
        .map_err(|_| "Bob persisted disposition unavailable")?
        .admission(Some(0))
        .map_err(|_| "Bob epoch changed or blocked")?;
    if alice_status.epoch != 0
        || bob_status.changed_at.is_some()
        || potential_write && !matches!(alice_status.state, State::Pending | State::Contained)
        || result.is_ok()
            && (alice_status.state != State::Contained || alice_status.changed_at != verified_time)
    {
        return Err("persisted epoch/containment invariant failed");
    }
    println!("native_sql_hash_component phase={phase:?} result={} alice_state={:?} epoch={} performed_write_time_known={} bob_epoch_preserved=true credential_retry=false full_workflow_qualified=false", if result.is_ok() {"PASS"} else {"FAIL"}, alice_status.state, alice_status.epoch, alice_status.changed_at.is_some());
    result
}
