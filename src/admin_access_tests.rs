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
    active: bool,
    unavailable: bool,
    directory_reads: usize,
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
        let output = if query.contains("FROM admin a") {
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
                        "{}\t{}\t{}\t{}\t0\t{}\n",
                        upper_hex(LOGIN.as_bytes()),
                        upper_hex(format!("$2b$12${}", ".".repeat(53)).as_bytes()),
                        u8::from(state.active),
                        upper_hex(b"2026-11-16 00:00:00"),
                        grant
                    )
                })
                .collect::<String>()
        } else {
            state.directory_reads += 1;
            format!("{}\t1\t4\t5\t100\t200\t0\n", upper_hex(b"example.test"))
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
                active: true,
                unavailable: false,
                directory_reads: 0,
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
        }
    }
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
