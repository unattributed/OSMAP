//! Internal, read-only PostfixAdmin projection. A future trusted service must
//! provide an authenticated domain scope; this module is not a web endpoint.
use crate::auth::CommandExecutor;
use std::time::Duration;

const PROGRAM: &str = "/usr/local/bin/mariadb";
const ARGS: &[&str] = &[
    "--defaults-file=/etc/osmap/admin-read-mariadb.cnf",
    "--database=postfixadmin",
    "--batch",
    "--skip-column-names",
    "--raw",
];
const TIMEOUT: Duration = Duration::from_secs(10);
const MAX_ROWS: usize = 100;
const OUTPUT_LIMIT: usize = 64 * 1024;

#[derive(Debug, PartialEq, Eq)]
pub(crate) enum Error {
    Invalid,
    Unauthorized,
    Missing,
    Unavailable,
    Unsupported,
    Limit,
}
pub(crate) struct Scope(Vec<String>);
impl Scope {
    pub(crate) fn domains(names: &[&str]) -> Result<Self, Error> {
        if names.is_empty() || names.len() > 16 || names.iter().any(|n| !valid_domain(n)) {
            return Err(Error::Invalid);
        }
        Ok(Self(names.iter().map(|n| (*n).to_owned()).collect()))
    }
    fn permits(&self, name: &str) -> Result<(), Error> {
        if !valid_domain(name) {
            return Err(Error::Invalid);
        }
        if !self.0.iter().any(|n| n == name) {
            return Err(Error::Unauthorized);
        }
        Ok(())
    }
}
#[derive(Debug, PartialEq, Eq)]
pub(crate) struct Domain {
    pub(crate) name: String,
    pub(crate) active: bool,
    pub(crate) aliases: i64,
    pub(crate) mailboxes: i64,
    pub(crate) maxquota: i64,
    pub(crate) quota: i64,
    pub(crate) backupmx: bool,
}
#[derive(Debug, PartialEq, Eq)]
pub(crate) struct Mailbox {
    pub(crate) username: String,
    pub(crate) maildir: String,
    pub(crate) quota: i64,
    pub(crate) active: bool,
    pub(crate) smtp_active: bool,
}
#[derive(Debug, PartialEq, Eq)]
pub(crate) struct Alias {
    pub(crate) address: String,
    pub(crate) destinations: String,
    pub(crate) active: bool,
}
#[derive(Debug, PartialEq, Eq)]
pub(crate) struct AliasDomain {
    pub(crate) alias_domain: String,
    pub(crate) target_domain: String,
    pub(crate) active: bool,
}

pub(crate) struct Adapter<E> {
    executor: E,
}
impl<E: CommandExecutor> Adapter<E> {
    pub(crate) fn new(executor: E) -> Self {
        Self { executor }
    }
    pub(crate) fn domains(&self, scope: &Scope) -> Result<Vec<Domain>, Error> {
        scope
            .0
            .iter()
            .filter_map(|name| self.domain(scope, name).transpose())
            .collect()
    }
    pub(crate) fn domain(&self, scope: &Scope, name: &str) -> Result<Option<Domain>, Error> {
        let rows = self.rows(scope, name, "SELECT HEX(domain),active,aliases,mailboxes,maxquota,quota,backupmx FROM domain WHERE BINARY domain=BINARY ? LIMIT 2", 7)?;
        if rows.len() > 1 {
            return Err(Error::Unsupported);
        }
        rows.into_iter()
            .next()
            .map(|r| {
                Ok(Domain {
                    name: hex(&r[0])?,
                    active: flag(&r[1])?,
                    aliases: number(&r[2])?,
                    mailboxes: number(&r[3])?,
                    maxquota: number(&r[4])?,
                    quota: number(&r[5])?,
                    backupmx: flag(&r[6])?,
                })
            })
            .transpose()
    }
    pub(crate) fn mailboxes(&self, scope: &Scope, domain: &str) -> Result<Vec<Mailbox>, Error> {
        self.require_domain(scope, domain)?;
        self.rows(scope, domain, "SELECT HEX(username),HEX(maildir),quota,active,smtp_active FROM mailbox WHERE BINARY domain=BINARY ? ORDER BY username LIMIT 101", 5)?
            .into_iter().map(|r| Ok(Mailbox { username: hex(&r[0])?, maildir: hex(&r[1])?, quota: number(&r[2])?, active: flag(&r[3])?, smtp_active: flag(&r[4])? })).collect()
    }
    pub(crate) fn aliases(&self, scope: &Scope, domain: &str) -> Result<Vec<Alias>, Error> {
        self.require_domain(scope, domain)?;
        self.rows(scope, domain, "SELECT HEX(address),HEX(goto),active FROM alias WHERE BINARY domain=BINARY ? ORDER BY address LIMIT 101", 3)?
            .into_iter().map(|r| Ok(Alias { address: hex(&r[0])?, destinations: hex(&r[1])?, active: flag(&r[2])? })).collect()
    }
    pub(crate) fn alias_domains(
        &self,
        scope: &Scope,
        domain: &str,
    ) -> Result<Vec<AliasDomain>, Error> {
        self.rows(scope, domain, "SELECT HEX(alias_domain),HEX(target_domain),active FROM alias_domain WHERE BINARY alias_domain=BINARY ? ORDER BY alias_domain LIMIT 101", 3)?
            .into_iter().map(|r| Ok(AliasDomain { alias_domain: hex(&r[0])?, target_domain: hex(&r[1])?, active: flag(&r[2])? })).collect()
    }
    fn require_domain(&self, scope: &Scope, domain: &str) -> Result<(), Error> {
        if self.domain(scope, domain)?.is_none() {
            return Err(Error::Missing);
        }
        Ok(())
    }
    fn rows(
        &self,
        scope: &Scope,
        domain: &str,
        query: &'static str,
        columns: usize,
    ) -> Result<Vec<Vec<String>>, Error> {
        scope.permits(domain)?;
        // Fixed prepared query. Domain bytes become a bound SQL value, never syntax.
        let input = format!("SET @osmap_domain=CONVERT(0x{} USING utf8mb4); PREPARE osmap_read FROM '{}'; EXECUTE osmap_read USING @osmap_domain;\n", upper_hex(domain.as_bytes()), query);
        let args = ARGS.iter().map(|s| (*s).to_owned()).collect::<Vec<_>>();
        let result = self
            .executor
            .run_with_stdin_bytes_timeout_and_output_limit(
                PROGRAM,
                &args,
                input.as_bytes(),
                TIMEOUT,
                OUTPUT_LIMIT,
            )
            .map_err(|_| Error::Unavailable)?;
        if result.status_code != 0 || !result.stderr.is_empty() {
            // Only fixed MariaDB error numbers are exported; stderr remains private.
            if result
                .stderr
                .lines()
                .any(|s| s.starts_with("ERROR 1054 ") || s.starts_with("ERROR 1146 "))
            {
                return Err(Error::Unsupported);
            }
            return Err(Error::Unavailable);
        }
        if result.stdout.len() > OUTPUT_LIMIT {
            return Err(Error::Limit);
        }
        if !result.stdout.is_ascii() {
            return Err(Error::Unsupported);
        }
        let lines = result.stdout.lines().collect::<Vec<_>>();
        if lines.len() > MAX_ROWS {
            return Err(Error::Limit);
        }
        lines
            .into_iter()
            .map(|line| {
                let fields = line.split('\t').map(str::to_owned).collect::<Vec<_>>();
                if fields.len() != columns {
                    return Err(Error::Unsupported);
                }
                Ok(fields)
            })
            .collect()
    }
}
fn valid_domain(v: &str) -> bool {
    !v.is_empty()
        && v.len() <= 255
        && v.is_ascii()
        && v.split('.').all(|label| {
            !label.is_empty()
                && label.len() <= 63
                && !label.starts_with('-')
                && !label.ends_with('-')
                && label
                    .bytes()
                    .all(|b| b.is_ascii_alphanumeric() || b == b'-')
        })
}
fn upper_hex(bytes: &[u8]) -> String {
    bytes.iter().map(|b| format!("{b:02X}")).collect()
}
fn hex(v: &str) -> Result<String, Error> {
    if v.len() > 8192 || v.len() % 2 != 0 || !v.bytes().all(|b| b.is_ascii_hexdigit()) {
        return Err(Error::Unsupported);
    }
    let bytes = v
        .as_bytes()
        .chunks_exact(2)
        .map(|p| {
            u8::from_str_radix(std::str::from_utf8(p).unwrap_or(""), 16)
                .map_err(|_| Error::Unsupported)
        })
        .collect::<Result<Vec<_>, _>>()?;
    String::from_utf8(bytes).map_err(|_| Error::Unsupported)
}
fn number(v: &str) -> Result<i64, Error> {
    v.parse().map_err(|_| Error::Unsupported)
}
fn flag(v: &str) -> Result<bool, Error> {
    match v {
        "0" => Ok(false),
        "1" => Ok(true),
        _ => Err(Error::Unsupported),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::auth::{CommandExecution, CommandExecutionError};
    struct Fixture;
    impl CommandExecutor for Fixture {
        fn run_with_stdin_bytes(
            &self,
            _: &str,
            _: &[String],
            input: &[u8],
        ) -> Result<CommandExecution, CommandExecutionError> {
            let sql = std::str::from_utf8(input).unwrap();
            let stdout = if sql.contains("FROM domain WHERE") {
                "6578616D706C652E74657374\t1\t4\t5\t100\t200\t0\n"
            } else if sql.contains("FROM mailbox WHERE") {
                "616C696365406578616D706C652E74657374\t6578616D706C652E746573742F616C6963652F\t0\t0\t1\n"
            } else if sql.contains("FROM alias WHERE") {
                "696E666F406578616D706C652E74657374\t616C696365406578616D706C652E746573742C626F62406578616D706C652E74657374\t1\n"
            } else if sql.contains("FROM alias_domain WHERE") {
                "6F746865722E74657374\t6578616D706C652E74657374\t0\n"
            } else {
                ""
            };
            Ok(CommandExecution {
                status_code: 0,
                stdout: stdout.into(),
                stderr: String::new(),
            })
        }
    }
    #[test]
    fn domain_lookup_and_negative_scope() {
        let scope = Scope::domains(&["example.test"]).unwrap();
        let adapter = Adapter::new(Fixture);
        assert_eq!(
            adapter
                .domain(&scope, "example.test")
                .unwrap()
                .unwrap()
                .name,
            "example.test"
        );
        assert_eq!(
            adapter.domain(&scope, "other.test"),
            Err(Error::Unauthorized)
        );
    }

    #[test]
    fn scoped_projections_and_invalid_input() {
        let scope = Scope::domains(&["example.test", "other.test"]).unwrap();
        let adapter = Adapter::new(Fixture);
        assert_eq!(adapter.domains(&scope).unwrap().len(), 2);
        let mailbox = &adapter.mailboxes(&scope, "example.test").unwrap()[0];
        assert_eq!(mailbox.username, "alice@example.test");
        assert!(!mailbox.active);
        assert_eq!(mailbox.quota, 0);
        assert_eq!(
            adapter.aliases(&scope, "example.test").unwrap()[0].destinations,
            "alice@example.test,bob@example.test"
        );
        assert_eq!(
            adapter.alias_domains(&scope, "other.test").unwrap()[0].target_domain,
            "example.test"
        );
        assert_eq!(adapter.mailboxes(&scope, "a'.test"), Err(Error::Invalid));
        assert_eq!(
            adapter.aliases(&scope, "other.example"),
            Err(Error::Unauthorized)
        );
        assert_eq!(
            Scope::domains(&[&"a".repeat(256)]).err(),
            Some(Error::Invalid)
        );
    }
    struct Response {
        status: i32,
        stdout: String,
        stderr: String,
    }
    impl CommandExecutor for Response {
        fn run_with_stdin_bytes(
            &self,
            _: &str,
            _: &[String],
            _: &[u8],
        ) -> Result<CommandExecution, CommandExecutionError> {
            Ok(CommandExecution {
                status_code: self.status,
                stdout: self.stdout.clone(),
                stderr: self.stderr.clone(),
            })
        }
    }
    #[test]
    fn bounded_and_sanitized_failures() {
        let scope = Scope::domains(&["example.test"]).unwrap();
        let run = |status, stdout: String, stderr: &str| {
            Adapter::new(Response {
                status,
                stdout,
                stderr: stderr.into(),
            })
            .domain(&scope, "example.test")
        };
        assert_eq!(
            run(1, String::new(), "ERROR 1054 (42S22): private detail"),
            Err(Error::Unsupported)
        );
        assert_eq!(
            run(1, String::new(), "ERROR 1142 (42000): private detail"),
            Err(Error::Unavailable)
        );
        assert_eq!(run(0, "X".repeat(OUTPUT_LIMIT + 1), ""), Err(Error::Limit));
        assert_eq!(
            run(0, "not a valid row\n".into(), ""),
            Err(Error::Unsupported)
        );
        assert_eq!(run(0, String::new(), ""), Ok(None));
    }
    #[test]
    fn signed_values_and_canonical_case_are_preserved() {
        let scope = Scope::domains(&["Example.Test"]).unwrap();
        let row = "4578616D706C652E54657374\t1\t-1\t2\t-3\t-4\t0\n";
        let adapter = Adapter::new(Response {
            status: 0,
            stdout: row.into(),
            stderr: String::new(),
        });
        let domain = adapter.domain(&scope, "Example.Test").unwrap().unwrap();
        assert_eq!(domain.name, "Example.Test");
        assert_eq!(
            (domain.aliases, domain.maxquota, domain.quota),
            (-1, -3, -4)
        );
        assert_eq!(
            adapter.domain(&scope, "example.test"),
            Err(Error::Unauthorized)
        );
    }
}
