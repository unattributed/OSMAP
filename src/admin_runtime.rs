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
        // These are the fixed readers' arguments, not request-selected programs.
        if program != "/usr/local/bin/mariadb"
            || args
                != [
                    "--defaults-file=/etc/osmap/admin-read-mariadb.cnf",
                    "--database=postfixadmin",
                    "--batch",
                    "--skip-column-names",
                    "--raw",
                ]
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
        crate::admin_config::verify_sql_profile(&self.profile).map_err(|_| {
            eprintln!("ADMIN_SQL_PROFILE_CUSTODY_REFUSED");
            Self::refused()
        })?;
        let bytes = fs::read(&self.profile).map_err(|_| Self::refused())?;
        if bytes.len() > 4096 || <[u8; 32]>::from(Sha256::digest(&bytes)) != self.digest {
            eprintln!("ADMIN_SQL_PROFILE_CHANGED");
            return Err(Self::refused());
        }
        let remaining = self
            .deadline
            .lock()
            .map_err(|_| Self::refused())?
            .checked_duration_since(Instant::now())
            .ok_or_else(|| {
                eprintln!("ADMIN_SQL_DEADLINE_REFUSED");
                Self::refused()
            })?
            .min(timeout)
            .min(Duration::from_secs(10));
        let fixed = vec![
            format!("--defaults-file={}", self.profile.display()),
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
                "ADMIN_SQL_PROCESS_REFUSED status={} stdout_bytes={} stderr_bytes={}",
                output.status_code,
                output.stdout.len(),
                output.stderr.len()
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

/// CLI-only role selection; no browser field supplies configuration or execution.
pub fn run(arguments: &[OsString]) -> Result<(), &'static str> {
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
    .map_err(|_| "ADMIN_SERVICE_STATE")?;
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
