//! Separate private admin service entry. Startup configuration is operator-owned.
use crate::admin_access::{NativePassword, Service, Token};
use crate::admin_config::ServiceConfig;
use crate::admin_transport::{self, Operation, Request, Response};
use crate::auth::{
    AuthenticationContext, CommandExecution, CommandExecutionError, CommandExecutor,
    SystemCommandExecutor,
};
use crate::totp::SystemTimeProvider;
use sha2::{Digest, Sha256};
use std::ffi::OsString;
use std::fs;
use std::os::unix::fs::{MetadataExt, PermissionsExt};
use std::os::unix::net::UnixListener;
use std::path::{Path, PathBuf};
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};

#[derive(Clone)]
struct Sql {
    profile: PathBuf,
    database: String,
    digest: [u8; 32],
    deadline: Arc<Mutex<Instant>>,
    writer: Option<(PathBuf, [u8; 32])>,
}
impl Sql {
    fn new(config: &ServiceConfig) -> Result<Self, &'static str> {
        crate::admin_config::verify_sql_profile(&config.sql_profile)
            .map_err(|_| "ADMIN_PROFILE_CUSTODY")?;
        let bytes = fs::read(&config.sql_profile).map_err(|_| "ADMIN_PROFILE_READ")?;
        if bytes.len() > 4096 {
            return Err("ADMIN_PROFILE_LIMIT");
        }
        Ok(Self {
            profile: config.sql_profile.clone(),
            database: config.database.clone(),
            digest: Sha256::digest(&bytes).into(),
            deadline: Arc::new(Mutex::new(Instant::now())),
            writer: config
                .writer
                .as_ref()
                .map(|w| {
                    let bytes = fs::read(&w.profile).map_err(|_| "ADMIN_WRITER_PROFILE_READ")?;
                    Ok::<_, &'static str>((w.profile.clone(), Sha256::digest(&bytes).into()))
                })
                .transpose()?,
        })
    }
    fn refused() -> CommandExecutionError {
        CommandExecutionError {
            reason: "admin fixed SQL boundary unavailable".into(),
        }
    }
}
impl CommandExecutor for Sql {
    fn run_with_stdin_bytes(
        &self,
        program: &str,
        args: &[String],
        input: &[u8],
    ) -> Result<CommandExecution, CommandExecutionError> {
        self.run_with_stdin_bytes_timeout_and_output_limit(
            program,
            args,
            input,
            Duration::from_secs(10),
            16384,
        )
    }
    fn run_with_stdin_bytes_timeout_and_output_limit(
        &self,
        program: &str,
        args: &[String],
        input: &[u8],
        timeout: Duration,
        output_limit: usize,
    ) -> Result<CommandExecution, CommandExecutionError> {
        let remaining = self
            .deadline
            .lock()
            .map_err(|_| Self::refused())?
            .checked_duration_since(Instant::now())
            .ok_or_else(Self::refused)?
            .min(timeout)
            .min(Duration::from_secs(10));
        if program == crate::account_password_backend::HASH_PROGRAM
            && args
                .iter()
                .map(String::as_str)
                .eq(crate::account_password_backend::HASH_ARGS.iter().copied())
            && self.writer.is_some()
            && output_limit == 4096
        {
            let result =
                crate::account_password_process::admin_hash(input, Instant::now() + remaining);
            if result
                .as_ref()
                .map_or(true, |o| o.status_code != 0 || !o.stderr.is_empty())
            {
                eprintln!(
                    "ADMIN_CREATE_HASH_REFUSED cleanup_uncertain={}",
                    crate::account_password_process::execution_quarantined()
                );
            }
            return result;
        }
        let writing = args
            .iter()
            .map(String::as_str)
            .eq(crate::admin_access::create::WRITER_ARGS.iter().copied());
        // These are the fixed readers' arguments, not request-selected programs.
        if program != "/usr/local/bin/mariadb"
            || (!writing
                && args
                    != [
                        "--defaults-file=/etc/osmap/admin-read-mariadb.cnf",
                        "--database=postfixadmin",
                        "--batch",
                        "--skip-column-names",
                        "--raw",
                    ])
            || input.len() > 16384
            || output_limit
                > if input.starts_with(b"SET @osmap_domain=") {
                    64 * 1024
                } else {
                    16384
                }
        {
            eprintln!("ADMIN_SQL_FIXED_BOUNDARY_REFUSED");
            return Err(Self::refused());
        }
        let (profile, digest) = if writing {
            self.writer
                .as_ref()
                .map(|(p, d)| (p, d))
                .ok_or_else(Self::refused)?
        } else {
            (&self.profile, &self.digest)
        };
        crate::admin_config::verify_sql_profile(profile).map_err(|_| {
            eprintln!("ADMIN_SQL_PROFILE_CUSTODY_REFUSED");
            Self::refused()
        })?;
        let bytes = fs::read(profile).map_err(|_| Self::refused())?;
        if bytes.len() > 4096 || <[u8; 32]>::from(Sha256::digest(&bytes)) != *digest {
            eprintln!("ADMIN_SQL_PROFILE_CHANGED");
            return Err(Self::refused());
        }
        let fixed = vec![
            format!("--defaults-file={}", profile.display()),
            format!("--database={}", self.database),
            "--batch".into(),
            "--skip-column-names".into(),
            "--raw".into(),
        ];
        let result = SystemCommandExecutor.run_with_stdin_bytes_timeout_and_output_limit(
            "/usr/local/bin/mariadb",
            &fixed,
            input,
            remaining,
            output_limit,
        );
        match &result {
            Ok(output) if output.status_code != 0 || !output.stderr.is_empty() => eprintln!(
                "ADMIN_SQL_PROCESS_REFUSED status={} stdout_bytes={} stderr_bytes={} cause={}",
                output.status_code,
                output.stdout.len(),
                output.stderr.len(),
                sql_failure_code(&output.stderr)
            ),
            Err(error) => eprintln!(
                "ADMIN_SQL_RUNNER_REFUSED private_reason_bytes={} cause=not_observed",
                error.reason.len()
            ),
            _ => (),
        }
        result
    }
}

fn sql_failure_code(stderr: &str) -> &'static str {
    // Only source-owned classifications cross the native diagnostic boundary.
    // Never retain arbitrary SQL/error text (which may contain credentials).
    for line in stderr.lines() {
        if line.starts_with("ERROR 1267 ") || line.starts_with("ERROR 1271 ") {
            return "collation";
        }
        if line.starts_with("ERROR 1142 ") || line.starts_with("ERROR 1143 ") {
            return "permission";
        }
        if line.starts_with("ERROR 1054 ") || line.starts_with("ERROR 1146 ") {
            return "schema";
        }
        if line.starts_with("ERROR 1064 ") {
            return "syntax";
        }
        if line.starts_with("ERROR 1205 ") || line.starts_with("ERROR 1213 ") {
            return "lock";
        }
    }
    "not_observed"
}

/// CLI-only role selection; no browser field supplies configuration or execution.
pub fn run(arguments: &[OsString]) -> Result<(), &'static str> {
    if arguments.len() == 2 && arguments[0] == "initial-factor-service" {
        return crate::initial_factor_service::run(Path::new(&arguments[1]));
    }
    if arguments.len() == 1 && arguments[0] == "writer-schema" {
        print!("{}", crate::admin_access::create::SCHEMA);
        return Ok(());
    }
    if arguments.len() != 2 || crate::openbsd::effective_uid() == 0 {
        return Err("ADMIN_ARGUMENTS_OR_PRINCIPAL");
    }
    crate::openbsd::disable_core_dumps().map_err(|_| "ADMIN_CORE_LIMIT_REFUSED")?;
    let config = Path::new(&arguments[1]);
    match arguments[0].to_str() {
        Some("service") => service(crate::admin_config::load_service(config).map_err(|error| {
            eprintln!("{}", error.code());
            "ADMIN_SERVICE_CONFIG"
        })?),
        Some("web") => {
            crate::admin_web::run(&crate::admin_config::load_web(config).map_err(|error| {
                eprintln!("{}", error.code());
                "ADMIN_WEB_CONFIG"
            })?)
        }
        _ => Err("ADMIN_ARGUMENTS_OR_PRINCIPAL"),
    }
}

fn service(config: ServiceConfig) -> Result<(), &'static str> {
    let signals =
        crate::openbsd::AccountAdmissionSignals::install().map_err(|_| "ADMIN_SIGNAL_SETUP")?;
    let executor = Sql::new(&config)?;
    let deadline = executor.deadline.clone();
    let backend = Service::new(
        executor,
        SystemTimeProvider,
        NativePassword,
        config.state.clone(),
    )
    .map_err(|_| "ADMIN_SERVICE_STATE")?
    .with_writer(config.writer.clone());
    let listener = UnixListener::bind(&config.socket).map_err(|_| "ADMIN_SERVICE_BIND")?;
    let group = fs::symlink_metadata(
        config
            .socket
            .parent()
            .ok_or("ADMIN_SERVICE_SOCKET_PARENT")?,
    )
    .map_err(|_| "ADMIN_SERVICE_SOCKET_PARENT")?
    .gid();
    std::os::unix::fs::lchown(&config.socket, None, Some(group))
        .map_err(|_| "ADMIN_SERVICE_SOCKET_GROUP")?;
    fs::set_permissions(&config.socket, fs::Permissions::from_mode(0o660))
        .map_err(|_| "ADMIN_SERVICE_SOCKET_MODE")?;
    let identity = fs::symlink_metadata(&config.socket).map_err(|_| "ADMIN_SERVICE_SOCKET_STAT")?;
    listener
        .set_nonblocking(true)
        .map_err(|_| "ADMIN_SERVICE_LISTENER")?;
    crate::openbsd::seal_admin_service(
        &config.state,
        &config.socket,
        &config.sql_profile,
        &config.sql_socket,
        config.writer.as_ref().map(|w| w.profile.as_path()),
        config
            .writer
            .as_ref()
            .and_then(|w| w.onboarding.as_ref())
            .map(|s| s.factor_socket.as_path()),
    )
    .map_err(|_| "ADMIN_SERVICE_SEAL")?;
    eprintln!("ADMIN_SERVICE_READY");
    while !signals
        .stop_flag()
        .load(std::sync::atomic::Ordering::SeqCst)
    {
        match listener.accept() {
            Ok((mut stream, _)) => {
                // One sequential worker bounds expensive authentication. Every
                // nested SQL invocation shares this original frame deadline.
                let end = Instant::now() + Duration::from_secs(20);
                let request = admin_transport::read_request(&mut stream, config.web_uid, end);
                match request {
                    Ok(request) => {
                        *deadline.lock().map_err(|_| "ADMIN_DEADLINE_LOCK")? = end;
                        let response = dispatch(&backend, request);
                        if admin_transport::write_response(&mut stream, &response, end).is_err() {
                            eprintln!("ADMIN_SERVICE_RESPONSE_UNCONFIRMED");
                        }
                    }
                    Err(_) => eprintln!("ADMIN_SERVICE_PEER_OR_FRAME_REFUSED"),
                }
            }
            Err(error) if error.kind() == std::io::ErrorKind::WouldBlock => {
                std::thread::sleep(Duration::from_millis(20))
            }
            Err(_) => return Err("ADMIN_SERVICE_ACCEPT"),
        }
    }
    let after = fs::symlink_metadata(&config.socket).map_err(|error| {
        eprintln!(
            "ADMIN_SERVICE_SOCKET_STAT_REFUSED errno={}",
            error
                .raw_os_error()
                .filter(|n| (1..=4095).contains(n))
                .unwrap_or(0)
        );
        "ADMIN_SERVICE_SOCKET_STAT_UNCONFIRMED"
    })?;
    if (identity.dev(), identity.ino(), identity.uid()) != (after.dev(), after.ino(), after.uid()) {
        return Err("ADMIN_SERVICE_SOCKET_CHANGED");
    }
    fs::remove_file(&config.socket).map_err(|error| {
        eprintln!(
            "ADMIN_SERVICE_SOCKET_UNLINK_REFUSED errno={}",
            error
                .raw_os_error()
                .filter(|n| (1..=4095).contains(n))
                .unwrap_or(0)
        );
        "ADMIN_SERVICE_SOCKET_UNLINK_UNCONFIRMED"
    })?;
    eprintln!("ADMIN_SERVICE_STOPPED");
    Ok(())
}

pub(crate) fn dispatch<E, T, P>(backend: &Service<E, T, P>, request: Request) -> Response
where
    E: CommandExecutor + Clone + Send + Sync + 'static,
    T: crate::totp::TimeProvider + Clone,
    P: crate::admin_access::PasswordVerifier,
{
    let context = AuthenticationContext {
        request_id: "admin-private-request".into(),
        remote_addr: request.client,
        user_agent: "admin-private-web".into(),
    };
    match request.operation {
        Operation::RedeemSetup {
            account,
            invitation,
        } => match backend.redeem_initial_setup(&account, &invitation) {
            Ok(page) => Response::Setup { page },
            Err(_) => Response::SetupRefused,
        },
        Operation::SetupView { account, grant } => {
            match backend.view_initial_setup(&account, &grant) {
                Ok(page) => Response::Setup { page },
                Err(_) => Response::SetupRefused,
            }
        }
        Operation::CompleteSetup {
            account,
            grant,
            password,
            confirmation,
            totp,
            enrollment_id,
        } => match backend.complete_initial_setup(
            &account,
            &grant,
            &password,
            &confirmation,
            &totp,
            &enrollment_id,
        ) {
            Ok(()) => Response::SetupComplete,
            Err(crate::admin_access::CreateFailure::Unconfirmed) => Response::SetupUnconfirmed,
            Err(_) => Response::SetupRefused,
        },
        Operation::CreateMailboxForm { token, domain } => match Token::presented(&token)
            .map_err(crate::admin_access::CreateFailure::from)
            .and_then(|t| backend.create_mailbox_form_from(&t, &context, &domain))
        {
            Ok(page) => Response::CreateMailboxForm { page },
            Err(reason) => Response::CreateMailboxFailed { reason },
        },
        Operation::CreateMailbox { token, request } => match Token::presented(&token)
            .map_err(crate::admin_access::CreateFailure::from)
            .and_then(|t| backend.create_mailbox_from(&t, &context, &request))
        {
            Ok(receipt) => Response::MailboxCreated { receipt },
            Err(reason) => Response::CreateMailboxFailed { reason },
        },
        Operation::Login {
            login,
            password,
            totp,
        } => match backend.login_from(&context, &login, &password, &totp) {
            Ok(token) => Response::SignedIn {
                token: token.as_str().into(),
            },
            Err(crate::admin_access::Error::Unavailable) => {
                eprintln!("ADMIN_LOGIN_DEPENDENCY_UNAVAILABLE");
                Response::Unavailable
            }
            Err(_) => {
                eprintln!("ADMIN_LOGIN_NOT_COMPLETED");
                Response::Denied
            }
        },
        Operation::Overview { token, query, page } => match Token::presented(&token)
            .and_then(|token| backend.overview_from(&token, &context, &query, page))
        {
            Ok(page) => Response::Overview { page },
            Err(error) => inventory_error(error),
        },
        Operation::DomainDetails { token, id } => match Token::presented(&token)
            .and_then(|token| backend.domain_details_from(&token, &context, &id))
        {
            Ok(page) => Response::DomainDetails { page },
            Err(error) => inventory_error(error),
        },
        Operation::Settings { token } => match Token::presented(&token)
            .and_then(|token| backend.settings_from(&token, &context))
        {
            Ok(page) => Response::Settings { page },
            Err(error) => inventory_error(error),
        },
        Operation::SavePreferences {
            token,
            csrf,
            preferences,
        } => match Token::presented(&token)
            .and_then(|token| backend.save_preferences_from(&token, &context, &csrf, preferences))
        {
            Ok(page) => Response::Settings { page },
            Err(error) => inventory_error(error),
        },
        Operation::Scope { token } => {
            match Token::presented(&token).and_then(|token| backend.scope(&token, &context)) {
                Ok(scope) => Response::Scope {
                    login: scope.login,
                    system: scope.system,
                    domains: scope.domains,
                    csrf: scope.csrf,
                },
                Err(crate::admin_access::Error::Unavailable) => Response::Unavailable,
                Err(_) => Response::Denied,
            }
        }
        Operation::Mailboxes {
            token,
            domain,
            query,
            page,
            sort,
        } => {
            match Token::presented(&token).and_then(|token| {
                backend.mailboxes_from(&token, &context, &domain, &query, page, &sort)
            }) {
                Ok(page) => Response::Mailboxes { page },
                Err(error) => inventory_error(error),
            }
        }
        Operation::Mailbox { token, domain, id } => {
            match Token::presented(&token)
                .and_then(|token| backend.mailbox_from(&token, &context, &domain, &id))
            {
                Ok((summary, mailbox)) => Response::Mailbox {
                    login: summary.login,
                    csrf: summary.csrf,
                    domain,
                    mailbox,
                },
                Err(error) => inventory_error(error),
            }
        }
        Operation::Logout { token, csrf } => match Token::presented(&token)
            .and_then(|token| backend.logout_from(&token, &csrf, &context))
        {
            Ok(()) => Response::SignedOut,
            Err(crate::admin_access::Error::Unavailable) => Response::Unavailable,
            Err(_) => Response::Denied,
        },
    }
}

fn inventory_error(error: crate::admin_access::Error) -> Response {
    match error {
        crate::admin_access::Error::Denied => Response::Denied,
        crate::admin_access::Error::Forbidden | crate::admin_access::Error::Missing => {
            Response::Missing
        }
        crate::admin_access::Error::Invalid => Response::Invalid,
        crate::admin_access::Error::Capacity => Response::Capacity,
        _ => Response::Unavailable,
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    /// Controlled fixture bootstrap is out-of-band: this qualifies the actual
    /// setup/password/factor writer, not administrator TOTP or email delivery.
    #[test]
    #[ignore = "requires the explicitly prepared private obsd1 onboarding fixture"]
    fn native_initial_owner_setup_uses_real_installer_and_writer() {
        use crate::initial_enrollment::Store;
        use crate::totp::TimeProvider as _;
        use std::io::Write as _;
        use std::os::unix::fs::{DirBuilderExt as _, OpenOptionsExt as _};
        const ACCOUNT: &str = "native-initial-qualification@empty.test";
        const CONTACT: &str = "qualification@outside.test";
        const FACTOR_SOCKET: &str = "/var/osmap-adm-s04-01/factor-run/factor.sock";
        const SQL_SOCKET: &str = "/var/osmap-adm-s01/sql-run/mysql.sock";
        println!("NATIVE_INITIAL_STAGE qualification_target_admission");
        assert!(cfg!(target_os = "openbsd") && crate::openbsd::effective_uid() == 1008);
        crate::openbsd::disable_core_dumps()
            .map_err(|_| ())
            .expect("NATIVE_INITIAL_CORE_LIMIT");
        let raw = crate::admin_config::read_file(
            Path::new("/var/osmap-adm-s04-01/service-qualification.json"),
            0,
            true,
        )
        .map_err(|_| ())
        .expect("NATIVE_INITIAL_CONFIG_CUSTODY");
        let config: ServiceConfig = serde_json::from_slice(&raw)
            .map_err(|_| ())
            .expect("NATIVE_INITIAL_CONFIG_SCHEMA");
        assert!(
            config.database == "osmap_admin_create_fixture"
                && config.sql_socket == Path::new(SQL_SOCKET)
                && config.state == Path::new("/var/osmap-adm-s01-03/state")
        );
        let writer = config
            .writer
            .as_ref()
            .expect("NATIVE_INITIAL_WRITER_ABSENT");
        assert!(writer
            .onboarding
            .as_ref()
            .is_some_and(|setup| setup.factor_socket == Path::new(FACTOR_SOCKET)));
        let actor = writer
            .administrators
            .first()
            .expect("NATIVE_INITIAL_ACTOR_ABSENT");
        assert!(writer.domains.iter().any(|domain| domain == "empty.test"));
        let executor = Sql::new(&config)
            .map_err(|_| ())
            .expect("NATIVE_INITIAL_SQL_CUSTODY");
        let args = crate::admin_access::create::WRITER_ARGS
            .iter()
            .map(|arg| (*arg).into())
            .collect::<Vec<String>>();
        let query = |input: &str| {
            *executor
                .deadline
                .lock()
                .expect("NATIVE_INITIAL_DEADLINE_LOCK") = Instant::now() + Duration::from_secs(20);
            let output = executor
                .run_with_stdin_bytes_timeout_and_output_limit(
                    "/usr/local/bin/mariadb",
                    &args,
                    input.as_bytes(),
                    Duration::from_secs(10),
                    16384,
                )
                .map_err(|_| ())
                .expect("NATIVE_INITIAL_SQL_DISPATCH");
            assert!(
                output.status_code == 0 && output.stderr.is_empty(),
                "NATIVE_INITIAL_SQL_RESULT"
            );
            output.stdout
        };
        // Actual client/daemon identity must match before any fixture write.
        assert!(
            query("SELECT DATABASE(),@@socket;\n")
                == format!("osmap_admin_create_fixture\t{SQL_SOCKET}\n")
        );
        let receipt_dir = config.state.join("qualification");
        match fs::DirBuilder::new().mode(0o700).create(&receipt_dir) {
            Ok(()) => {}
            Err(error) => assert!(error.kind() == std::io::ErrorKind::AlreadyExists),
        }
        crate::private_account_file::check_directory(&receipt_dir)
            .map_err(|_| ())
            .expect("NATIVE_INITIAL_RECEIPT_DIRECTORY");
        let receipt_path = receipt_dir.join("initial-owner.json");
        assert!(
            matches!(fs::symlink_metadata(&receipt_path), Err(error)
            if error.kind()==std::io::ErrorKind::NotFound),
            "NATIVE_INITIAL_RECEIPT_ALREADY_EXISTS"
        );
        assert!(query("SELECT (SELECT COUNT(*) FROM mailbox WHERE username='native-initial-qualification@empty.test')+(SELECT COUNT(*) FROM alias WHERE address='native-initial-qualification@empty.test')+(SELECT COUNT(*) FROM osmap_admin_operations WHERE username='native-initial-qualification@empty.test');\n") == "0\n");
        crate::initial_factor_service::check_absent(
            Path::new(FACTOR_SOCKET),
            ACCOUNT,
            Instant::now() + Duration::from_secs(10),
        )
        .map_err(|_| ())
        .expect("NATIVE_INITIAL_FACTOR_ALREADY_PRESENT");
        let random = || {
            let mut bytes = [0u8; 32];
            getrandom::getrandom(&mut bytes)
                .map_err(|_| ())
                .expect("NATIVE_INITIAL_RANDOM");
            bytes
                .iter()
                .map(|byte| format!("{byte:02x}"))
                .collect::<String>()
        };
        let operation = random();
        let digest = random();
        let password = random();
        let value = |text: &str| {
            format!(
                "CONVERT(0x{} USING utf8mb4)",
                text.as_bytes()
                    .iter()
                    .map(|byte| format!("{byte:02X}"))
                    .collect::<String>()
            )
        };
        println!("NATIVE_INITIAL_STAGE pending_fixture");
        let bootstrap = format!(concat!(
            "SET SESSION innodb_lock_wait_timeout=3; START TRANSACTION;\n",
            "SET @holder=NULL,@epoch=NULL,@revision=NULL,@mode=NULL; SELECT holder,epoch,revision,mode INTO @holder,@epoch,@revision,@mode FROM osmap_admin_writer WHERE id=1 FOR UPDATE;\n",
            "SET @actor=NULL; SELECT username INTO @actor FROM admin WHERE BINARY username=BINARY {actor} AND active=1 FOR UPDATE;\n",
            "SET @hash=NULL; SELECT password INTO @hash FROM mailbox WHERE username='pr101@empty.test' AND active=1 AND smtp_active=1 FOR UPDATE;\n",
            "INSERT INTO mailbox(username,password,name,maildir,quota,local_part,domain,created,modified,active,smtp_active) SELECT '{account}',@hash,'Native initial qualification','empty.test/native-initial-qualification/',20971520,'native-initial-qualification','empty.test',UTC_TIMESTAMP(),UTC_TIMESTAMP(),0,0 WHERE @actor IS NOT NULL AND @hash IS NOT NULL AND @mode='lab_writer' AND BINARY @holder=BINARY {holder} AND @epoch={epoch}; SET @m=ROW_COUNT();\n",
            "INSERT INTO alias(address,goto,domain,created,modified,active) SELECT '{account}','{account}','empty.test',UTC_TIMESTAMP(),UTC_TIMESTAMP(),1 WHERE @m=1; SET @a=ROW_COUNT();\n",
            "INSERT INTO osmap_admin_operations(request_id,actor,digest,credential_digest,username,domain,quota,revision,created,kind) SELECT '{operation}',@actor,'{digest}',SHA2(@hash,256),'{account}','empty.test',20971520,@revision+1,UTC_TIMESTAMP(),'mailbox.create' WHERE @m=1 AND @a=1; SET @o=ROW_COUNT();\n",
            "UPDATE osmap_admin_writer SET revision=revision+1 WHERE id=1 AND @m=1 AND @a=1 AND @o=1; SET @w=ROW_COUNT();\n",
            "SET @finish=IF(@m=1 AND @a=1 AND @o=1 AND @w=1,'COMMIT','ROLLBACK'); PREPARE osmap_finish FROM @finish; EXECUTE osmap_finish; SELECT IF(@finish='COMMIT','fixture_ready','refused');\n"
        ), account=ACCOUNT, actor=value(actor), holder=value(&writer.holder), epoch=writer.epoch,
           operation=operation, digest=digest);
        assert!(
            query(&bootstrap) == "fixture_ready\n",
            "NATIVE_INITIAL_FIXTURE_REFUSED"
        );
        assert!(query("SELECT COUNT(*) FROM mailbox m JOIN alias a ON BINARY a.address=BINARY m.username JOIN osmap_admin_operations o ON BINARY o.username=BINARY m.username WHERE m.username='native-initial-qualification@empty.test' AND m.active=0 AND m.smtp_active=0 AND BINARY a.goto=BINARY m.username AND a.active=1 AND BINARY o.credential_digest=BINARY SHA2(m.password,256);\n") == "1\n");
        println!("NATIVE_INITIAL_STAGE recipient_setup_proof");
        let store = Store::new(config.state.join("initial-enrollment"));
        let now = SystemTimeProvider.unix_timestamp();
        let deadline = || Instant::now() + Duration::from_secs(10);
        let invitation = store
            .provision(ACCOUNT, CONTACT, &operation, now, deadline())
            .map_err(|_| ())
            .expect("NATIVE_INITIAL_INVITATION");
        let grant = store
            .redeem(ACCOUNT, &invitation.token, now, deadline())
            .map_err(|_| ())
            .expect("NATIVE_INITIAL_REDEEM");
        let pending = store
            .pending(ACCOUNT, &grant.token, now, deadline())
            .map_err(|_| ())
            .expect("NATIVE_INITIAL_CANDIDATE");
        let secret = crate::totp::decode_base32(&pending.secret_base32)
            .map_err(|_| ())
            .expect("NATIVE_INITIAL_CANDIDATE_FORMAT");
        let code =
            crate::totp::generate_totp_code(&secret, now / 30, crate::totp::TotpPolicy::default())
                .map_err(|_| ())
                .expect("NATIVE_INITIAL_CODE");
        let counter =
            crate::totp::enrollment_counter(&secret, &code, now).expect("NATIVE_INITIAL_COUNTER");
        let factor_sha256 = format!(
            "{:x}",
            Sha256::digest(format!("# {ACCOUNT}\nsecret={}\n", pending.secret_base32).as_bytes())
        );
        let receipt = serde_json::to_vec(&serde_json::json!({
            "schema":"osmap-private-initial-qualification-v1", "account":ACCOUNT,
            "password":password, "secret_base32":pending.secret_base32,
            "accepted_counter":counter, "operation_id":operation, "factor_sha256":factor_sha256,
        }))
        .map_err(|_| ())
        .expect("NATIVE_INITIAL_PRIVATE_RECEIPT");
        let mut file = fs::OpenOptions::new()
            .write(true)
            .create_new(true)
            .mode(0o600)
            .custom_flags(libc::O_NOFOLLOW | libc::O_CLOEXEC)
            .open(&receipt_path)
            .map_err(|_| ())
            .expect("NATIVE_INITIAL_PRIVATE_RECEIPT_OPEN");
        let metadata = file
            .metadata()
            .map_err(|_| ())
            .expect("NATIVE_INITIAL_PRIVATE_RECEIPT_METADATA");
        assert!(
            metadata.uid() == 1008 && metadata.mode() & 0o7777 == 0o600 && metadata.nlink() == 1
        );
        file.write_all(&receipt)
            .map_err(|_| ())
            .expect("NATIVE_INITIAL_PRIVATE_RECEIPT_WRITE");
        file.sync_all()
            .map_err(|_| ())
            .expect("NATIVE_INITIAL_PRIVATE_RECEIPT_SYNC");
        assert!(fs::read(&receipt_path).ok().as_deref() == Some(receipt.as_slice()));
        fs::File::open(&receipt_dir)
            .map_err(|_| ())
            .expect("NATIVE_INITIAL_DIRECTORY_OPEN")
            .sync_all()
            .map_err(|_| ())
            .expect("NATIVE_INITIAL_DIRECTORY_SYNC");
        let backend = Service::new(
            executor.clone(),
            SystemTimeProvider,
            NativePassword,
            config.state.clone(),
        )
        .map_err(|_| ())
        .expect("NATIVE_INITIAL_SERVICE")
        .with_writer(config.writer.clone());
        *executor
            .deadline
            .lock()
            .expect("NATIVE_INITIAL_DEADLINE_LOCK") = Instant::now() + Duration::from_secs(20);
        println!("NATIVE_INITIAL_STAGE native_activation");
        assert!(
            backend
                .complete_initial_setup(
                    ACCOUNT,
                    &grant.token,
                    &password,
                    &password,
                    &code,
                    &pending.id
                )
                .is_ok(),
            "NATIVE_INITIAL_ACTIVATION_REFUSED"
        );
        assert!(store
            .pending(ACCOUNT, &grant.token, now, deadline())
            .is_err());
        assert!(store
            .redeem(ACCOUNT, &invitation.token, now, deadline())
            .is_err());
        assert!(query(&format!("SELECT COUNT(*) FROM mailbox m JOIN alias a ON BINARY a.address=BINARY m.username JOIN osmap_admin_operations o ON BINARY o.username=BINARY m.username WHERE m.username='{ACCOUNT}' AND m.active=1 AND m.smtp_active=1 AND a.active=1 AND BINARY a.goto=BINARY m.username AND o.request_id='{operation}' AND BINARY o.credential_digest=BINARY SHA2(m.password,256);\n")) == "1\n");
        println!("NATIVE_INITIAL_RESULT activation_pass ordinary_http_login_not_run email_delivery_not_run fixture_retained");
    }

    #[test]
    fn native_sql_diagnostic_keeps_private_error_text_out_of_export() {
        assert_eq!(
            sql_failure_code("ERROR 1267 (HY000): private-token-and-SQL"),
            "collation"
        );
        assert_eq!(sql_failure_code("private-token-and-SQL"), "not_observed");
        assert_eq!(
            sql_failure_code("ERROR 1143 (42000): private-account"),
            "permission"
        );
    }
    #[derive(Clone)]
    struct Unavailable;
    impl CommandExecutor for Unavailable {
        fn run_with_stdin_bytes(
            &self,
            _: &str,
            _: &[String],
            _: &[u8],
        ) -> Result<CommandExecution, CommandExecutionError> {
            Err(CommandExecutionError {
                reason: "private dependency reason".into(),
            })
        }
    }
    struct Password;
    impl crate::admin_access::PasswordVerifier for Password {
        fn verify(&self, _: &str, _: &str) -> Result<bool, crate::admin_access::Error> {
            Ok(false)
        }
    }
    #[test]
    fn unavailable_login_dependency_is_not_a_credential_denial() {
        use std::os::unix::fs::DirBuilderExt;
        let mut random = [0u8; 16];
        getrandom::getrandom(&mut random).unwrap();
        let name = random
            .iter()
            .map(|b| format!("{b:02x}"))
            .collect::<String>();
        let root = std::env::temp_dir().join(format!("osmap-admin-runtime-{name}"));
        fs::DirBuilder::new().mode(0o700).create(&root).unwrap();
        let backend =
            Service::new(Unavailable, SystemTimeProvider, Password, root.clone()).unwrap();
        let response = dispatch(
            &backend,
            Request {
                version: admin_transport::VERSION,
                client: "192.0.2.1".into(),
                operation: Operation::Login {
                    login: "operator@example.test".into(),
                    password: "synthetic-admin-password".into(),
                    totp: "000000".into(),
                },
            },
        );
        assert!(matches!(response, Response::Unavailable));
        fs::remove_dir_all(root).unwrap();
    }
}
