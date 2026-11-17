use super::*;
use crate::auth::{CommandExecution, CommandExecutionError};
use std::sync::{
    atomic::{AtomicU64, Ordering},
    Mutex,
};
const LOGIN: &str = "operator@example.test";
const PASSWORD: &str = "synthetic-admin-password";
const SECRET: &[u8] = b"public-synthetic-admin-factor-32";
#[derive(Clone)]
struct Clock(Arc<AtomicU64>);
impl TimeProvider for Clock {
    fn unix_timestamp(&self) -> u64 {
        self.0.load(Ordering::SeqCst)
    }
}
impl Clock {
    fn new() -> Self {
        Self(Arc::new(AtomicU64::new(1_800_000_000)))
    }
}
struct Password;
impl PasswordVerifier for Password {
    fn verify(&self, password: &str, _: &str) -> Result<bool, Error> {
        Ok(password == PASSWORD)
    }
}
struct State {
    grants: Vec<String>,
    system: bool,
    hash: String,
    active: bool,
    unavailable: bool,
    directory_reads: usize,
    mailbox_rows: usize,
    domain_missing: bool,
}
#[derive(Clone)]
struct Sql(Arc<Mutex<State>>);
impl CommandExecutor for Sql {
    fn run_with_stdin_bytes(
        &self,
        program: &str,
        args: &[String],
        input: &[u8],
    ) -> Result<CommandExecution, CommandExecutionError> {
        assert_eq!(program, PROGRAM);
        assert_eq!(
            args,
            &ARGS.iter().map(|s| (*s).to_owned()).collect::<Vec<_>>()
        );
        let query = std::str::from_utf8(input).unwrap();
        let mut state = self.0.lock().unwrap();
        if state.unavailable {
            return Ok(CommandExecution {
                status_code: 1,
                stdout: String::new(),
                stderr: "private backend detail".into(),
            });
        }
        let output = if query.contains("FROM admin a")
            && !query.contains(&format!(
                "SET @admin_login=CONVERT(0x{} USING",
                upper_hex(LOGIN.as_bytes())
            )) {
            String::new()
        } else if query.contains("FROM admin a") {
            let grants = if state.grants.is_empty() {
                vec!["NULL".into()]
            } else {
                state
                    .grants
                    .iter()
                    .map(|s| upper_hex(s.as_bytes()))
                    .collect()
            };
            grants
                .into_iter()
                .map(|grant| {
                    format!(
                        "{}\t{}\t{}\t{}\t{}\t{}\n",
                        upper_hex(LOGIN.as_bytes()),
                        upper_hex(state.hash.as_bytes()),
                        u8::from(state.active),
                        upper_hex(b"2026-11-16 00:00:00"),
                        u8::from(state.system),
                        grant
                    )
                })
                .collect::<String>()
        } else if query.contains("FROM domain d WHERE") {
            state.directory_reads += 1;
            let mut names = if state.domain_missing {
                vec![]
            } else {
                vec!["example.test"]
            };
            if query.contains("SET @osmap_system=1;") {
                names.push("foreign.test");
            }
            names
                .into_iter()
                .map(|name| format!("{}\t1\t12\t2\tNULL\n", upper_hex(name.as_bytes())))
                .collect()
        } else if query.contains("SELECT HEX(CONVERT(description") {
            format!(
                "{}\tNULL\tNULL\t{}\n",
                upper_hex(b"Development domain"),
                upper_hex(b"virtual")
            )
        } else if query.contains("FROM mailbox WHERE") {
            state.directory_reads += 1;
            (0..state.mailbox_rows)
                .map(|index| {
                    let address = if index == 0 {
                        "alice@example.test".into()
                    } else {
                        format!("user{index:02}@example.test")
                    };
                    format!(
                        "{}\t{}\t{}\t{}\t1\n",
                        upper_hex(address.as_bytes()),
                        upper_hex(b"private-storage/path/"),
                        index * 1024,
                        u8::from(index % 2 == 0)
                    )
                })
                .collect()
        } else {
            state.directory_reads += 1;
            let domain = if query.contains(&upper_hex(b"foreign.test")) {
                "foreign.test"
            } else {
                "example.test"
            };
            if state.domain_missing {
                String::new()
            } else {
                format!("{}\t1\t4\t5\t100\t200\t0\n", upper_hex(domain.as_bytes()))
            }
        };
        Ok(CommandExecution {
            status_code: 0,
            stdout: output,
            stderr: String::new(),
        })
    }
}
struct Fixture {
    root: PathBuf,
    sql: Sql,
    clock: Clock,
}
fn root(label: &str) -> PathBuf {
    let mut random = [0u8; 8];
    getrandom::getrandom(&mut random).unwrap();
    let root = std::env::temp_dir().join(format!("osmap-admin-{label}-{}", upper_hex(&random)));
    use std::os::unix::fs::DirBuilderExt as _;
    std::fs::DirBuilder::new()
        .mode(0o700)
        .create(&root)
        .unwrap();
    root.canonicalize().unwrap()
}
fn install_factor(root: &Path) {
    use std::os::unix::fs::PermissionsExt as _;
    let dir = root.join("factors");
    std::fs::create_dir_all(&dir).unwrap();
    std::fs::set_permissions(&dir, std::fs::Permissions::from_mode(0o700)).unwrap();
    let path = FileTotpSecretStore::new(&dir).secret_path_for_username(&factor_subject(LOGIN));
    std::fs::write(
        &path,
        format!("secret={}\n", crate::totp::encode_base32(SECRET)),
    )
    .unwrap();
    std::fs::set_permissions(path, std::fs::Permissions::from_mode(0o600)).unwrap();
}
fn code(clock: &Clock) -> String {
    crate::totp::generate_totp_code(SECRET, clock.unix_timestamp() / 30, TotpPolicy::default())
        .unwrap()
}
impl Fixture {
    fn new() -> Self {
        let root = root("access");
        install_factor(&root);
        Self {
            root,
            sql: Sql(Arc::new(Mutex::new(State {
                grants: vec!["example.test".into()],
                system: false,
                hash: format!("$2b$12${}", ".".repeat(53)),
                active: true,
                unavailable: false,
                directory_reads: 0,
                mailbox_rows: 12,
                domain_missing: false,
            }))),
            clock: Clock::new(),
        }
    }
    fn service(&self) -> Service<Sql, Clock, Password> {
        Service::new(
            self.sql.clone(),
            self.clock.clone(),
            Password,
            self.root.clone(),
        )
        .unwrap()
    }
    fn login(&self) -> Result<Token, Error> {
        self.service().login(LOGIN, PASSWORD, &code(&self.clock))
    }
}
impl Drop for Fixture {
    fn drop(&mut self) {
        if !std::thread::panicking() {
            std::fs::remove_dir_all(&self.root).unwrap();
        } else {
            // Private test output names the exact synthetic fixture for recovery.
            eprintln!("ADMIN_TEST_FIXTURE_RETAINED root={}", self.root.display());
        }
    }
}
#[test]
fn mailbox_inventory_uses_live_context_and_refuses_foreign_before_directory_read() {
    let f = Fixture::new();
    let context = AuthenticationContext {
        request_id: "admin-web".into(),
        remote_addr: "192.0.2.12".into(),
        user_agent: "osmap-admin-web".into(),
    };
    let service = f.service();
    let token = service
        .login_from(&context, LOGIN, PASSWORD, &code(&f.clock))
        .unwrap();
    assert!(matches!(
        service.mailboxes_from(&token, &context, "foreign.test", "", 1, "address"),
        Err(Error::Forbidden)
    ));
    assert_eq!(f.sql.0.lock().unwrap().directory_reads, 0);
    let page = service
        .mailboxes_from(&token, &context, "example.test", "", 1, "address")
        .unwrap();
    assert_eq!(page.domain, "example.test");
    assert_eq!(page.rows[0].username, "alice@example.test");
}

#[test]
fn mailbox_pages_filter_sort_and_stable_details_exclude_private_storage() {
    let f = Fixture::new();
    let service = f.service();
    let token = f.login().unwrap();
    let context = Service::<Sql, Clock, Password>::context();
    let second = service
        .mailboxes_from(&token, &context, "example.test", "", 2, "address")
        .unwrap();
    assert_eq!(
        (second.total, second.rows.len(), second.pages()),
        (12, 2, 2)
    );
    let filtered = service
        .mailboxes_from(&token, &context, "example.test", "ALICE", 1, "address")
        .unwrap();
    assert_eq!(filtered.total, 1);
    let id = filtered.rows[0].id.clone();
    let (_, row) = service
        .mailbox_from(&token, &context, "example.test", &id)
        .unwrap();
    assert_eq!(row.username, "alice@example.test");
    assert!(!serde_json::to_string(&row)
        .unwrap()
        .contains("private-storage"));
    let sorted = service
        .mailboxes_from(&token, &context, "example.test", "", 1, "quota")
        .unwrap();
    assert_eq!(sorted.rows[0].username, "user11@example.test");
    f.sql.0.lock().unwrap().mailbox_rows = 13;
    assert_eq!(
        service
            .mailbox_from(&token, &context, "example.test", &id)
            .unwrap()
            .1
            .id,
        id
    );
    let foreign_id = format!("{:x}", Sha256::digest(b"alice@foreign.test"));
    assert!(matches!(
        service.mailbox_from(&token, &context, "example.test", &foreign_id),
        Err(Error::Missing)
    ));
}

#[test]
fn mailbox_empty_missing_capacity_and_unavailable_remain_distinct() {
    let f = Fixture::new();
    let service = f.service();
    let token = f.login().unwrap();
    let context = Service::<Sql, Clock, Password>::context();
    f.sql.0.lock().unwrap().mailbox_rows = 0;
    assert_eq!(
        service
            .mailboxes_from(&token, &context, "example.test", "", 1, "address")
            .unwrap()
            .total,
        0
    );
    f.sql.0.lock().unwrap().domain_missing = true;
    assert!(matches!(
        service.mailboxes_from(&token, &context, "example.test", "", 1, "address"),
        Err(Error::Missing)
    ));
    {
        let mut state = f.sql.0.lock().unwrap();
        state.domain_missing = false;
        state.mailbox_rows = 101;
    }
    assert!(matches!(
        service.mailboxes_from(&token, &context, "example.test", "", 1, "address"),
        Err(Error::Capacity)
    ));
    f.sql.0.lock().unwrap().unavailable = true;
    assert!(matches!(
        service.mailboxes_from(&token, &context, "example.test", "", 1, "address"),
        Err(Error::Unavailable)
    ));
}

#[test]
fn runtime_mailbox_dispatch_uses_current_peer_context_and_revoked_grants() {
    use crate::admin_transport::{Operation, Request, Response, VERSION};
    let f = Fixture::new();
    let service = f.service();
    let context = AuthenticationContext {
        request_id: "admin-private-request".into(),
        remote_addr: "192.0.2.12".into(),
        user_agent: "admin-private-web".into(),
    };
    let token = service
        .login_from(&context, LOGIN, PASSWORD, &code(&f.clock))
        .unwrap();
    let read = || Request {
        version: VERSION,
        client: context.remote_addr.clone(),
        operation: Operation::Mailboxes {
            token: token.as_str().into(),
            domain: "example.test".into(),
            query: "".into(),
            page: 1,
            sort: "address".into(),
        },
    };
    assert!(matches!(
        crate::admin_runtime::dispatch(&service, read()),
        Response::Mailboxes { .. }
    ));
    let before = f.sql.0.lock().unwrap().directory_reads;
    f.sql.0.lock().unwrap().grants.clear();
    assert!(matches!(
        crate::admin_runtime::dispatch(&service, read()),
        Response::Denied | Response::Missing
    ));
    assert_eq!(f.sql.0.lock().unwrap().directory_reads, before);
}

#[test]
fn authenticated_domain_read_and_foreign_refusal() {
    let f = Fixture::new();
    let token = f.login().unwrap();
    assert_eq!(
        f.service()
            .domain(&token, "example.test")
            .unwrap()
            .unwrap()
            .name,
        "example.test"
    );
    let before = f.sql.0.lock().unwrap().directory_reads;
    assert_eq!(
        f.service().domain(&token, "foreign.test"),
        Err(Error::Denied)
    );
    assert_eq!(f.sql.0.lock().unwrap().directory_reads, before);
}
#[test]
fn fresh_factor_required_and_replay_survives_backend_reconstruction() {
    let f = Fixture::new();
    assert!(matches!(
        f.service().login(LOGIN, "wrong", &code(&f.clock)),
        Err(Error::Denied)
    ));
    let valid = code(&f.clock);
    let wrong = if valid == "000000" {
        "000001"
    } else {
        "000000"
    };
    assert!(matches!(
        f.service().login(LOGIN, PASSWORD, wrong),
        Err(Error::Denied)
    ));
    let token = f.login().unwrap();
    assert!(matches!(f.login(), Err(Error::Denied)));
    assert!(f
        .service()
        .domain(&token, "example.test")
        .unwrap()
        .is_some());
}
#[test]
fn current_grants_and_admin_state_invalidate_session_before_directory_read() {
    let f = Fixture::new();
    let token = f.login().unwrap();
    f.sql.0.lock().unwrap().grants.clear();
    assert_eq!(
        f.service().domain(&token, "example.test"),
        Err(Error::Denied)
    );
    assert_eq!(f.sql.0.lock().unwrap().directory_reads, 0);
    f.sql.0.lock().unwrap().grants = vec!["example.test".into()];
    assert_eq!(
        f.service().domain(&token, "example.test"),
        Err(Error::Denied)
    );
    f.clock.0.fetch_add(30, Ordering::SeqCst);
    let fresh = f.login().unwrap();
    assert!(f
        .service()
        .domain(&fresh, "example.test")
        .unwrap()
        .is_some());
    f.sql.0.lock().unwrap().active = false;
    assert_eq!(
        f.service().domain(&token, "example.test"),
        Err(Error::Denied)
    );
}
#[test]
fn mailbox_bearer_and_expired_revoked_sessions_are_denied() {
    let f = Fixture::new();
    use std::os::unix::fs::DirBuilderExt as _;
    let mailbox_root = f.root.join("mailbox-sessions");
    std::fs::DirBuilder::new()
        .mode(0o700)
        .create(&mailbox_root)
        .unwrap();
    let mailbox = SessionService::new(
        FileSessionStore::new(mailbox_root),
        f.clock.clone(),
        SystemRandomSource,
        900,
        300,
    )
    .issue(
        &Service::<Sql, Clock, Password>::context(),
        LOGIN,
        RequiredSecondFactor::Totp,
    )
    .unwrap();
    let forged_purpose = Token::presented(&format!("{PREFIX}{}", mailbox.token.as_str())).unwrap();
    assert_eq!(
        f.service().domain(&forged_purpose, "example.test"),
        Err(Error::Denied)
    );
    assert!(matches!(
        Token::presented(&"a".repeat(64)),
        Err(Error::Denied)
    ));
    let token = f.login().unwrap();
    f.service().logout(&token).unwrap();
    assert_eq!(
        f.service().domain(&token, "example.test"),
        Err(Error::Denied)
    );
    f.clock.0.fetch_add(30, Ordering::SeqCst);
    let token = f.login().unwrap();
    f.clock.0.fetch_add(901, Ordering::SeqCst);
    assert_eq!(
        f.service().domain(&token, "example.test"),
        Err(Error::Denied)
    );
}
#[test]
fn invalid_inputs_and_failures_have_only_fixed_errors() {
    let f = Fixture::new();
    let token = f.login().unwrap();
    assert!(matches!(
        f.service().login(&"a".repeat(97), PASSWORD, "000000"),
        Err(Error::Invalid)
    ));
    assert!(matches!(
        f.service().login(LOGIN, &"a".repeat(73), "000000"),
        Err(Error::Invalid)
    ));
    f.sql.0.lock().unwrap().unavailable = true;
    assert!(matches!(f.login(), Err(Error::Unavailable)));
    assert_eq!(
        f.service().domain(&token, "example.test"),
        Err(Error::Unavailable)
    );
    assert_eq!(format!("{:?}", Error::Unavailable), "Unavailable");
    assert!(!bcrypt(""));
    assert!(!bcrypt(&format!("$2b$31${}", ".".repeat(53))));
}
#[test]
fn legacy_global_grant_never_becomes_system_scope() {
    let f = Fixture::new();
    f.sql.0.lock().unwrap().grants = vec!["ALL".into()];
    assert!(matches!(f.login(), Err(Error::Denied)));
}

#[derive(Clone)]
struct NativeSql {
    root: PathBuf,
}
impl CommandExecutor for NativeSql {
    fn run_with_stdin_bytes(
        &self,
        p: &str,
        a: &[String],
        input: &[u8],
    ) -> Result<CommandExecution, CommandExecutionError> {
        self.run_with_stdin_bytes_timeout_and_output_limit(
            p,
            a,
            input,
            Duration::from_secs(10),
            16384,
        )
    }
    fn run_with_stdin_bytes_timeout_and_output_limit(
        &self,
        p: &str,
        a: &[String],
        input: &[u8],
        timeout: Duration,
        limit: usize,
    ) -> Result<CommandExecution, CommandExecutionError> {
        assert_eq!(p, PROGRAM);
        assert_eq!(a, &ARGS.iter().map(|s| (*s).to_owned()).collect::<Vec<_>>());
        let mut args = a.to_vec();
        args[0] = format!("--defaults-file={}", self.root.join("client.cnf").display());
        args[1] = "--database=osmap_admin_access_fixture".into();
        crate::auth::SystemCommandExecutor
            .run_with_stdin_bytes_timeout_and_output_limit(p, &args, input, timeout, limit)
    }
}
fn native() -> (PathBuf, Service<NativeSql, Clock>, Clock) {
    let root = PathBuf::from(
        std::env::var_os("OSMAP_ADMIN_NATIVE_ROOT").expect("operator fixture root required"),
    );
    let clock = Clock::new();
    let service = Service::new(
        NativeSql { root: root.clone() },
        clock.clone(),
        NativePassword,
        root.clone(),
    )
    .unwrap();
    (root, service, clock)
}
#[test]
#[ignore = "operator-run isolated OpenBSD admin/MariaDB fixture, no production data"]
fn native_authenticated_domain_read() {
    let (root, service, clock) = native();
    install_factor(&root);
    assert!(matches!(
        service.login("unknown@example.test", PASSWORD, &code(&clock)),
        Err(Error::Denied)
    ));
    assert!(matches!(
        service.login(LOGIN, "wrong", &code(&clock)),
        Err(Error::Denied)
    ));
    let token = service.login(LOGIN, PASSWORD, &code(&clock)).unwrap();
    assert_eq!(
        service
            .domain(&token, "example.test")
            .unwrap()
            .unwrap()
            .quota,
        200
    );
    assert_eq!(service.domain(&token, "foreign.test"), Err(Error::Denied));
    assert!(matches!(
        service.login(LOGIN, PASSWORD, &code(&clock)),
        Err(Error::Denied)
    ));
    use std::io::Write as _;
    use std::os::unix::fs::OpenOptionsExt as _;
    let mut file = std::fs::OpenOptions::new()
        .write(true)
        .create_new(true)
        .mode(0o600)
        .open(root.join("fixture.token"))
        .unwrap();
    file.write_all(token.as_str().as_bytes()).unwrap();
    file.sync_all().unwrap();
    println!("ADMIN_NATIVE_PASSWORD_TOTP_SESSION_SQL_PASS");
}
#[test]
#[ignore = "operator-run second process read of isolated admin fixture session"]
fn native_session_resume() {
    let (root, service, _) = native();
    let text = std::fs::read_to_string(root.join("fixture.token")).unwrap();
    let token = Token::presented(&text).unwrap();
    assert_eq!(
        service
            .domain(&token, "example.test")
            .unwrap()
            .unwrap()
            .name,
        "example.test"
    );
    println!("ADMIN_NATIVE_SESSION_RESTART_PASS");
}
#[test]
#[ignore = "operator-run after revoking only disposable fixture domain grant"]
fn native_revoked_grant_refuses() {
    let (root, service, _) = native();
    let text = std::fs::read_to_string(root.join("fixture.token")).unwrap();
    let token = Token::presented(&text).unwrap();
    assert_eq!(service.domain(&token, "example.test"), Err(Error::Denied));
    println!("ADMIN_NATIVE_GRANT_REVOCATION_PASS");
}

#[test]
fn lost_generation_then_new_login_never_revives_old_session() {
    let f = Fixture::new();
    let old = f.login().unwrap();
    let epochs = f.root.join("epochs");
    for entry in std::fs::read_dir(&epochs).unwrap() {
        let path = entry.unwrap().path();
        if path.extension() == Some(std::ffi::OsStr::new("json")) {
            std::fs::remove_file(path).unwrap();
        }
    }
    assert_eq!(
        f.service().domain(&old, "example.test"),
        Err(Error::Unavailable)
    );
    f.clock.0.fetch_add(30, Ordering::SeqCst);
    let fresh = f.login().unwrap();
    assert!(f
        .service()
        .domain(&fresh, "example.test")
        .unwrap()
        .is_some());
    assert_eq!(f.service().domain(&old, "example.test"), Err(Error::Denied));
}
#[test]
fn factor_change_then_restoration_cannot_revive_old_session() {
    let f = Fixture::new();
    let old = f.login().unwrap();
    let path = FileTotpSecretStore::new(f.root.join("factors"))
        .secret_path_for_username(&factor_subject(LOGIN));
    std::fs::write(
        &path,
        format!(
            "secret={}\n",
            crate::totp::encode_base32(b"another-public-synthetic-factor-32")
        ),
    )
    .unwrap();
    assert_eq!(f.service().domain(&old, "example.test"), Err(Error::Denied));
    install_factor(&f.root);
    assert_eq!(f.service().domain(&old, "example.test"), Err(Error::Denied));
}

#[test]
fn toronto_hash_format_is_supported_without_rewriting_stored_value() {
    let f = Fixture::new();
    let stored = format!("$2y$10${}", ".".repeat(53));
    f.sql.0.lock().unwrap().hash = stored.clone();
    assert!(bcrypt(&stored));
    let token = f.login().unwrap();
    assert!(f
        .service()
        .domain(&token, "example.test")
        .unwrap()
        .is_some());
    assert_eq!(f.sql.0.lock().unwrap().hash, stored);
}
#[test]
fn system_scope_requires_both_indicators() {
    let f = Fixture::new();
    f.sql.0.lock().unwrap().system = true;
    assert!(matches!(f.login(), Err(Error::Denied)));
    f.sql.0.lock().unwrap().grants.push("ALL".into());
    let token = f.login().unwrap();
    assert_eq!(
        f.service()
            .domain(&token, "foreign.test")
            .unwrap()
            .unwrap()
            .name,
        "foreign.test"
    );
    f.sql.0.lock().unwrap().system = false;
    assert_eq!(
        f.service().domain(&token, "foreign.test"),
        Err(Error::Denied)
    );
    f.sql.0.lock().unwrap().system = true;
    assert_eq!(
        f.service().domain(&token, "foreign.test"),
        Err(Error::Denied)
    );
}

#[test]
fn bcrypt_compatibility_policy_has_bounded_cost_and_unambiguous_markers() {
    for marker in ["2b", "2y"] {
        for cost in ["10", "11", "12"] {
            assert!(bcrypt(&format!("${marker}${cost}${}", ".".repeat(53))));
        }
    }
    for (marker, cost) in [("2a", "10"), ("2x", "10"), ("2b", "09"), ("2y", "31")] {
        assert!(!bcrypt(&format!("${marker}${cost}${}", ".".repeat(53))));
    }
    assert!(!bcrypt(&format!("$2y$10${}", "é".repeat(26))));
}
#[test]
fn system_role_upgrade_requires_fresh_authentication() {
    let f = Fixture::new();
    let domain_session = f.login().unwrap();
    {
        let mut state = f.sql.0.lock().unwrap();
        state.system = true;
        state.grants.push("ALL".into());
    }
    assert_eq!(
        f.service().domain(&domain_session, "foreign.test"),
        Err(Error::Denied)
    );
    f.clock.0.fetch_add(30, Ordering::SeqCst);
    let fresh = f.login().unwrap();
    assert_eq!(
        f.service()
            .domain(&fresh, "foreign.test")
            .unwrap()
            .unwrap()
            .name,
        "foreign.test"
    );
    assert_eq!(f.service().domain(&fresh, "bad'.test"), Err(Error::Invalid));
}
fn save_token(root: &Path, name: &str, token: &Token) {
    use std::io::Write as _;
    use std::os::unix::fs::OpenOptionsExt as _;
    let mut file = std::fs::OpenOptions::new()
        .write(true)
        .create_new(true)
        .mode(0o600)
        .open(root.join(name))
        .unwrap();
    file.write_all(token.as_str().as_bytes()).unwrap();
    file.sync_all().unwrap();
}
#[test]
#[ignore = "operator-run native independently generated bcrypt compatibility vectors"]
fn native_bcrypt_compatibility_vectors() {
    let (root, _, _) = native();
    for (name, password) in [
        ("ascii-2y.hash", PASSWORD),
        ("utf8-2y.hash", "synthetic-café-password"),
        ("ascii-2b.hash", PASSWORD),
    ] {
        let original = std::fs::read_to_string(root.join(name)).unwrap();
        let hash = original.trim();
        assert!(crate::openbsd::admin_password_matches(password, hash).unwrap());
        assert!(
            !crate::openbsd::admin_password_matches("incorrect-synthetic-password", hash).unwrap()
        );
        assert_eq!(std::fs::read_to_string(root.join(name)).unwrap(), original);
    }
    println!("NATIVE_BCRYPT_COMPATIBILITY_VECTORS_PASS");
}
#[test]
#[ignore = "operator-run after enabling both isolated fixture system indicators"]
fn native_compatibility_system_read() {
    let (root, service, clock) = native();
    clock.0.fetch_add(30, Ordering::SeqCst);
    let before = service.authority.lookup(LOGIN, true).unwrap().unwrap().hash;
    assert!(before.starts_with("$2y$10$"));
    let token = service.login(LOGIN, PASSWORD, &code(&clock)).unwrap();
    assert_eq!(
        service
            .domain(&token, "foreign.test")
            .unwrap()
            .unwrap()
            .name,
        "foreign.test"
    );
    assert!(matches!(
        service.login(LOGIN, PASSWORD, &code(&clock)),
        Err(Error::Denied)
    ));
    assert_eq!(
        service
            .authority
            .lookup(LOGIN, false)
            .unwrap()
            .unwrap()
            .hash,
        before
    );
    save_token(&root, "system.token", &token);
    println!("NATIVE_TORONTO_SHAPED_SYSTEM_READ_PASS");
}
#[test]
#[ignore = "operator-run second process for compatible system-admin read"]
fn native_compatibility_system_resume() {
    let (root, service, clock) = native();
    clock.0.fetch_add(30, Ordering::SeqCst);
    let text = std::fs::read_to_string(root.join("system.token")).unwrap();
    let token = Token::presented(&text).unwrap();
    assert_eq!(
        service
            .domain(&token, "foreign.test")
            .unwrap()
            .unwrap()
            .name,
        "foreign.test"
    );
    println!("NATIVE_SYSTEM_SESSION_RESTART_PASS");
}
#[test]
#[ignore = "operator-run after isolated system role disagreement or restoration"]
fn native_compatibility_system_refuses() {
    let (root, service, clock) = native();
    clock.0.fetch_add(30, Ordering::SeqCst);
    let text = std::fs::read_to_string(root.join("system.token")).unwrap();
    let token = Token::presented(&text).unwrap();
    assert_eq!(service.domain(&token, "foreign.test"), Err(Error::Denied));
    println!("NATIVE_SYSTEM_DEMOTION_OLD_SESSION_REFUSED");
}

#[test]
#[ignore = "operator-run fresh proof against one inconsistent fixture role indicator"]
fn native_compatibility_role_disagreement_login() {
    let (_, service, clock) = native();
    clock.0.fetch_add(60, Ordering::SeqCst);
    assert!(matches!(
        service.login(LOGIN, PASSWORD, &code(&clock)),
        Err(Error::Denied)
    ));
    println!("NATIVE_INCONSISTENT_ROLE_LOGIN_REFUSED");
}
#[test]
#[ignore = "operator-run fresh authentication after restoring both fixture role indicators"]
fn native_compatibility_restored_role_fresh_login() {
    let (_, service, clock) = native();
    clock.0.fetch_add(60, Ordering::SeqCst);
    let fresh = service.login(LOGIN, PASSWORD, &code(&clock)).unwrap();
    assert_eq!(
        service
            .domain(&fresh, "foreign.test")
            .unwrap()
            .unwrap()
            .name,
        "foreign.test"
    );
    println!("NATIVE_RESTORED_SYSTEM_ROLE_FRESH_PROOF_PASS");
}

#[test]
fn current_scope_survives_reconstruction_and_rechecks_authority() {
    let f = Fixture::new();
    let token = f.login().unwrap();
    let context = Service::<Sql, Clock, Password>::context();
    let scope = f.service().scope(&token, &context).unwrap();
    assert_eq!(scope.login, LOGIN);
    assert!(!scope.system);
    assert_eq!(scope.domains, ["example.test"]);
    assert_eq!(scope.csrf.len(), 64);
    f.sql.0.lock().unwrap().grants.clear();
    assert!(matches!(
        f.service().scope(&token, &context),
        Err(Error::Denied)
    ));
}

#[test]
fn domain_overview_and_preferences_use_current_admin_authority() {
    let f = Fixture::new();
    let token = f.login().unwrap();
    let context = Service::<Sql, Clock, Password>::context();
    let overview = f.service().overview_from(&token, &context, "", 1).unwrap();
    assert_eq!(overview.rows.len(), 1);
    assert_eq!(overview.rows[0].name, "example.test");
    assert_eq!(overview.rows[0].mailboxes, 12);
    assert_eq!(overview.rows[0].forwards, 2);
    let dispatched = crate::admin_runtime::dispatch(
        &f.service(),
        crate::admin_transport::Request {
            version: crate::admin_transport::VERSION,
            client: "192.0.2.12".into(),
            operation: crate::admin_transport::Operation::Overview {
                token: token.as_str().into(),
                query: "example".into(),
                page: 1,
            },
        },
    );
    assert!(
        matches!(dispatched,crate::admin_transport::Response::Overview {page} if page.rows.len()==1 && page.rows[0].mailboxes==12)
    );
    let settings = f.service().settings_from(&token, &context).unwrap();
    assert_eq!(settings.preferences.theme, "system");
    let mut preferences = settings.preferences;
    preferences.theme = "dark".into();
    assert!(matches!(
        f.service()
            .save_preferences_from(&token, &context, &"0".repeat(64), preferences.clone()),
        Err(Error::Denied)
    ));
    let mut invalid = preferences.clone();
    invalid.theme = "<script>".into();
    assert!(matches!(
        f.service()
            .save_preferences_from(&token, &context, &settings.csrf, invalid),
        Err(Error::Invalid)
    ));
    f.service()
        .save_preferences_from(&token, &context, &settings.csrf, preferences)
        .unwrap();
    assert_eq!(
        f.service()
            .settings_from(&token, &context)
            .unwrap()
            .preferences
            .theme,
        "dark"
    );
    let id = &overview.rows[0].id;
    assert_eq!(
        f.service()
            .domain_details_from(&token, &context, id)
            .unwrap()
            .description,
        "Development domain"
    );
    let foreign = format!("{:x}", Sha256::digest(b"foreign.test"));
    assert!(matches!(
        f.service().domain_details_from(&token, &context, &foreign),
        Err(Error::Missing)
    ));
    f.sql.0.lock().unwrap().grants.clear();
    assert!(matches!(
        f.service().overview_from(&token, &context, "", 1),
        Err(Error::Denied)
    ));
}

#[test]
fn supported_costs_each_perform_the_same_bounded_password_work() {
    struct Work(Arc<Mutex<Vec<String>>>);
    impl PasswordVerifier for Work {
        fn verify(&self, password: &str, hash: &str) -> Result<bool, Error> {
            self.0.lock().unwrap().push(hash[4..6].into());
            Ok(password == PASSWORD)
        }
    }
    for cost in ["10", "11", "12"] {
        let f = Fixture::new();
        f.sql.0.lock().unwrap().hash = format!("$2y${cost}${}", ".".repeat(53));
        let work = Arc::new(Mutex::new(Vec::new()));
        let service = Service::new(
            f.sql.clone(),
            f.clock.clone(),
            Work(work.clone()),
            f.root.clone(),
        )
        .unwrap();
        let context = Service::<Sql, Clock, Work>::context();
        let token = service
            .login_from(&context, LOGIN, PASSWORD, &code(&f.clock))
            .unwrap();
        assert!(service.scope(&token, &context).is_ok());
        assert_eq!(*work.lock().unwrap(), ["10", "11", "12"]);
        work.lock().unwrap().clear();
        assert!(matches!(
            service.login_from(&context, "unknown@example.test", PASSWORD, &code(&f.clock)),
            Err(Error::Denied)
        ));
        assert_eq!(*work.lock().unwrap(), ["10", "11", "12"]);
    }
}

#[test]
fn account_lockout_survives_client_rotation_and_service_reconstruction() {
    let f = Fixture::new();
    for n in 1..=5 {
        let mut context = Service::<Sql, Clock, Password>::context();
        context.remote_addr = format!("192.0.2.{n}");
        assert!(matches!(
            f.service()
                .login_from(&context, LOGIN, "wrong", &code(&f.clock)),
            Err(Error::Denied)
        ));
    }
    let mut context = Service::<Sql, Clock, Password>::context();
    context.remote_addr = "192.0.2.99".into();
    assert!(matches!(
        f.service()
            .login_from(&context, LOGIN, PASSWORD, &code(&f.clock)),
        Err(Error::Denied)
    ));
    let store = LoginThrottleService::new(
        FileLoginThrottleStore::new(f.root.join("account-throttle")),
        f.clock.clone(),
        LoginThrottlePolicy::default(),
    );
    assert_eq!(
        store
            .check(
                &Service::<Sql, Clock, Password>::account_context("other@example.test"),
                "other@example.test"
            )
            .unwrap()
            .decision,
        LoginThrottleDecision::Allowed
    );
    assert!(matches!(
        store
            .check(
                &Service::<Sql, Clock, Password>::account_context(LOGIN),
                LOGIN
            )
            .unwrap()
            .decision,
        LoginThrottleDecision::Throttled { .. }
    ));
}

#[test]
fn logout_requires_session_csrf_then_persistently_revokes() {
    let f = Fixture::new();
    let token = f.login().unwrap();
    let context = Service::<Sql, Clock, Password>::context();
    let scope = f.service().scope(&token, &context).unwrap();
    assert_eq!(
        f.service().logout_from(&token, &"0".repeat(64), &context),
        Err(Error::Denied)
    );
    assert!(f.service().scope(&token, &context).is_ok());
    f.service()
        .logout_from(&token, &scope.csrf, &context)
        .unwrap();
    assert!(matches!(
        f.service().scope(&token, &context),
        Err(Error::Denied)
    ));
}
