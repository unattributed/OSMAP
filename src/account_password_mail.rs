//! Fixed Dovecot operation semantics, separated from ingress qualification.
//! Proxy list/kick observes and closes real proxy TCP connections; it does not
//! prove that every public SMTP ingress uses this proxy or fence new logins.
use crate::auth::{CommandExecution, CommandExecutor};
use std::net::IpAddr;
use std::path::PathBuf;
use std::time::{Duration, Instant};

pub(crate) const PROGRAM: &str = "/usr/local/bin/doveadm";
pub(crate) const PRIMARY: &[&str] = &[
    "-O",
    "-o",
    "stats_writer_socket_path=",
    "auth",
    "test",
    "-a",
    "/var/dovecot/osmap-account-auth-client",
    "-x",
    "service=imap",
];
pub(crate) const FLUSH: &[&str] = &[
    "-O",
    "-o",
    "stats_writer_socket_path=",
    "auth",
    "cache",
    "flush",
    "-a",
    "/var/dovecot/osmap-account-auth-master",
];
pub(crate) const WHO: &[&str] = &[
    "-O",
    "-o",
    "stats_writer_socket_path=",
    "-f",
    "tab",
    "who",
    "-a",
    "/var/dovecot/osmap-account-anvil",
];
const LIMIT: usize = 4096;

#[derive(Debug, Copy, Clone, PartialEq, Eq)]
pub(crate) enum Error {
    Unavailable,
}

/// Code-owned namespace supplied by the trusted service composition. It cannot
/// be constructed from a browser request; the native producer must also attest
/// root-owned config/IPC custody, complete routing and shared epoch enforcement.
#[allow(dead_code)] // Retained private-proxy adapter, not the selected stock path.
pub(crate) struct SubmissionNamespace {
    ipc: PathBuf,
    backend: IpAddr,
    port: u16,
    topology: Option<crate::account_password_topology::Topology>,
}
#[allow(dead_code)]
impl SubmissionNamespace {
    #[cfg(test)]
    fn fixture() -> Self {
        Self {
            ipc: "/private/fixture/run/login/ipc-client".into(),
            backend: "127.0.0.1".parse().unwrap(),
            port: 2525,
            topology: None,
        }
    }
    pub(crate) fn from_topology(topology: crate::account_password_topology::Topology) -> Self {
        Self {
            ipc: crate::account_password_topology::IPC.into(),
            backend: std::net::Ipv4Addr::LOCALHOST.into(),
            port: crate::account_password_topology::PORT,
            topology: Some(topology),
        }
    }
    pub(crate) fn recheck(&self, account: &str, deadline: Instant) -> Result<(), Error> {
        self.topology
            .as_ref()
            .ok_or(Error::Unavailable)?
            .recheck(account, deadline)
            .map_err(|_| Error::Unavailable)
    }
    fn args(&self, account: Option<&str>) -> Vec<String> {
        let mut args = vec![
            "-O".into(),
            "-o".into(),
            "stats_writer_socket_path=".into(),
            "proxy".into(),
            if account.is_some() {
                "kick".into()
            } else {
                "list".into()
            },
            "-a".into(),
            self.ipc.display().to_string(),
        ];
        if let Some(account) = account {
            args.push(account.into());
        }
        args
    }
}

/// Only these fixed single-account admin/primary invocations are eligible for
/// the helper's command builder. Namespace commands require their typed owner.
pub(crate) fn fixed_args(args: &[String]) -> bool {
    [PRIMARY, FLUSH, WHO].iter().any(|prefix| {
        args.len() == prefix.len() + 1
            && args[..prefix.len()]
                .iter()
                .map(String::as_str)
                .eq(prefix.iter().copied())
            && crate::account_admission::valid_account(args.last().unwrap()).is_ok()
    })
}

/// Existing public sockets, selected only by the dedicated stock child roles.
pub(crate) const STOCK_AUTH: &str = "/var/dovecot/auth-client";
pub(crate) const STOCK_CACHE: &str = "/var/dovecot/auth-master";
pub(crate) fn stock_args(args: &[String], primary: bool) -> Option<Vec<String>> {
    let prefix = if primary { PRIMARY } else { FLUSH };
    if args.len() != prefix.len() + 1
        || !args[..prefix.len()]
            .iter()
            .map(String::as_str)
            .eq(prefix.iter().copied())
        || crate::account_admission::valid_account(args.last()?).is_err()
    {
        return None;
    }
    let mut actual = args.to_vec();
    let slot = if primary { 6 } else { 7 };
    actual[slot] = if primary { STOCK_AUTH } else { STOCK_CACHE }.into();
    Some(actual)
}
pub(crate) fn fixed_stock_args(args: &[String], primary: bool) -> bool {
    let mut original = args.to_vec();
    let slot = if primary { 6 } else { 7 };
    let path = if primary { STOCK_AUTH } else { STOCK_CACHE };
    if original.get(slot).map(String::as_str) != Some(path) {
        return false;
    }
    original[slot] = if primary { PRIMARY[slot] } else { FLUSH[slot] }.into();
    stock_args(&original, primary).as_deref() == Some(args)
}

/// Exact unprivileged control utility surface. IMAP termination uses the
/// owned client socket registry, never numeric-PID signals or doveadm kick.
pub(crate) fn fixed_control_args(args: &[String]) -> bool {
    // Stock-equivalent collateral-process protection needs the complete anvil
    // account map before Rust shuts down owned client sockets. This exact read-only command
    // supplies no account selector, wildcard, force or termination operation.
    if args.iter().map(String::as_str).eq(WHO.iter().copied()) {
        return true;
    }
    if [FLUSH, WHO].iter().any(|prefix| {
        args.len() == prefix.len() + 1
            && args[..prefix.len()]
                .iter()
                .map(String::as_str)
                .eq(prefix.iter().copied())
            && crate::account_admission::valid_account(args.last().unwrap()).is_ok()
    }) {
        return true;
    }
    let prefix = ["-O", "-o", "stats_writer_socket_path=", "proxy"];
    args.len() >= prefix.len()
        && args[..prefix.len()].iter().map(String::as_str).eq(prefix)
        && ((args.len() == 7
            && args[4] == "list"
            && args[5] == "-a"
            && args[6] == crate::account_password_topology::IPC)
            || (args.len() == 8
                && args[4] == "kick"
                && args[5] == "-a"
                && args[6] == crate::account_password_topology::IPC
                && crate::account_admission::valid_account(&args[7]).is_ok()))
}

fn checked_result(result: CommandExecution) -> Result<(i32, String), Error> {
    if !result.stderr.is_empty()
        || result.stdout.len() > LIMIT
        || !result.stdout.is_ascii()
        || result
            .stdout
            .bytes()
            .any(|b| b < 32 && b != b'\n' && b != b'\t')
    {
        return Err(Error::Unavailable);
    }
    Ok((result.status_code, result.stdout))
}
fn execute<E: CommandExecutor>(
    executor: &E,
    args: &[String],
    input: &[u8],
    deadline: Instant,
) -> Result<(i32, String), Error> {
    let remaining = deadline
        .checked_duration_since(Instant::now())
        .ok_or(Error::Unavailable)?;
    let result = executor
        .run_with_stdin_bytes_timeout_and_output_limit(
            PROGRAM,
            args,
            input,
            remaining.min(Duration::from_secs(
                if args.len() == PRIMARY.len() + 1
                    && args
                        .iter()
                        .take(PRIMARY.len())
                        .map(String::as_str)
                        .eq(PRIMARY.iter().copied())
                {
                    25
                } else {
                    10
                },
            )),
            LIMIT,
        )
        .map_err(|_| Error::Unavailable)?;
    if Instant::now() >= deadline {
        return Err(Error::Unavailable);
    }
    checked_result(result)
}
fn account_args(prefix: &[&str], account: &str) -> Result<Vec<String>, Error> {
    crate::account_admission::valid_account(account).map_err(|_| Error::Unavailable)?;
    Ok(prefix
        .iter()
        .map(|s| (*s).into())
        .chain(std::iter::once(account.into()))
        .collect())
}
pub(crate) fn primary<E: CommandExecutor>(
    executor: &E,
    account: &str,
    password: &str,
    deadline: Instant,
) -> Result<bool, Error> {
    if password.is_empty() || password.len() > 1024 || password.chars().any(char::is_control) {
        return Err(Error::Unavailable);
    }
    let args = account_args(PRIMARY, account)?;
    let (code, output) = execute(
        executor,
        &args,
        format!("{password}\n").as_bytes(),
        deadline,
    )?;
    let success = output.lines().any(|line| line.contains("auth succeeded"));
    let failure = output.lines().any(|line| line.contains("auth failed"));
    let users = output
        .lines()
        .filter_map(|line| line.trim().strip_prefix("user="))
        .collect::<Vec<_>>();
    match (code, success, failure) {
        (0, true, false) if users == [account] => Ok(true),
        (77, false, true) if users.is_empty() || users == [account] => Ok(false),
        _ => Err(Error::Unavailable),
    }
}
pub(crate) fn flush<E: CommandExecutor>(
    executor: &E,
    account: &str,
    deadline: Instant,
) -> Result<(), Error> {
    let (code, data) = execute(executor, &account_args(FLUSH, account)?, b"", deadline)?;
    let count = data
        .strip_suffix(" cache entries flushed\n")
        .and_then(decimal);
    if code == 0 && count.is_some_and(|count| count <= u32::MAX as u64) {
        Ok(())
    } else {
        Err(Error::Unavailable)
    }
}
fn decimal(value: &str) -> Option<u64> {
    if value.is_empty()
        || value.len() > 10
        || !value.bytes().all(|v| v.is_ascii_digit())
        || value.len() > 1 && value.starts_with('0')
    {
        None
    } else {
        value.parse().ok()
    }
}
pub(crate) struct SubmissionControl<'a, E> {
    executor: &'a E,
    namespace: &'a SubmissionNamespace,
    account: String,
    observed: bool,
    dispatched: bool,
}
impl<'a, E: CommandExecutor> SubmissionControl<'a, E> {
    pub(crate) fn new(
        executor: &'a E,
        namespace: &'a SubmissionNamespace,
        account: &str,
    ) -> Result<Self, Error> {
        crate::account_admission::valid_account(account).map_err(|_| Error::Unavailable)?;
        Ok(Self {
            executor,
            namespace,
            account: account.into(),
            observed: false,
            dispatched: false,
        })
    }
    fn list(&self, deadline: Instant) -> Result<usize, Error> {
        let (code, data) = execute(self.executor, &self.namespace.args(None), b"", deadline)?;
        let mut lines = data.lines();
        let header = lines.next().ok_or(Error::Unavailable)?;
        // Dovecot emits multiword column names separated by tabs or spaces.
        if code != 0
            || !data.ends_with('\n')
            || header.split_whitespace().collect::<Vec<_>>()
                != ["username", "proto", "src", "ip", "dest", "ip", "port"]
        {
            return Err(Error::Unavailable);
        }
        let rows = lines.collect::<Vec<_>>();
        if rows.len() > 64 {
            return Err(Error::Unavailable);
        }
        let mut own = 0;
        for row in rows {
            let f = row.split_whitespace().collect::<Vec<_>>();
            if f.len() != 5
                || crate::account_admission::valid_account(f[0]).is_err()
                || f[1] != "submission"
                || f[2].parse::<IpAddr>().is_err()
                || f[3] != self.namespace.backend.to_string()
                || f[4] != self.namespace.port.to_string()
            {
                return Err(Error::Unavailable);
            }
            own += usize::from(f[0] == self.account);
        }
        Ok(own)
    }
    pub(crate) fn preflight(&mut self, deadline: Instant) -> Result<usize, Error> {
        if self.observed || self.dispatched {
            return Err(Error::Unavailable);
        }
        let count = self.list(deadline)?;
        self.observed = true;
        Ok(count)
    }
    pub(crate) fn terminate(&mut self, deadline: Instant) -> Result<(), Error> {
        if !self.observed || self.dispatched {
            return Err(Error::Unavailable);
        }
        self.dispatched = true;
        let (code, data) = execute(
            self.executor,
            &self.namespace.args(Some(&self.account)),
            b"",
            deadline,
        )?;
        if code != 0
            || data
                .strip_suffix(" connections kicked\n")
                .and_then(decimal)
                .is_none_or(|v| v > 64)
            || self.list(deadline)? != 0
        {
            return Err(Error::Unavailable);
        }
        Ok(())
    }
}
#[cfg(test)]
#[path = "account_password_mail_tests.rs"]
mod tests;

#[cfg(test)]
mod stock_command_tests {
    use super::*;
    #[test]
    fn stock_commands_translate_only_fixed_single_account_operations() {
        for primary in [true, false] {
            let input =
                account_args(if primary { PRIMARY } else { FLUSH }, "alice@example.test").unwrap();
            let actual = stock_args(&input, primary).unwrap();
            assert!(fixed_stock_args(&actual, primary));
            assert!(!fixed_stock_args(&actual, !primary));
            assert_eq!(actual.len(), input.len());
            assert_eq!(actual.last(), input.last());
            let slot = if primary { 6 } else { 7 };
            assert_eq!(actual[slot], if primary { STOCK_AUTH } else { STOCK_CACHE });
            assert!(actual
                .iter()
                .enumerate()
                .all(|(index, value)| index == slot || value == &input[index]));
            let mut wrong = input.clone();
            wrong[slot] = "/caller/socket".into();
            assert!(stock_args(&wrong, primary).is_none());
            let mut extra = input.clone();
            extra.push("--all".into());
            assert!(stock_args(&extra, primary).is_none());
            let mut wildcard = input.clone();
            *wildcard.last_mut().unwrap() = "*".into();
            assert!(stock_args(&wildcard, primary).is_none());
            assert!(stock_args(&actual, primary).is_none());
        }
        assert!(stock_args(&account_args(WHO, "alice@example.test").unwrap(), false).is_none());
        assert!(stock_args(&["rcctl".into(), "restart".into(), "dovecot".into()], false).is_none());
    }
}
