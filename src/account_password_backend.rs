//! Fixed authoritative password SQL/hash semantics. The executor is a trusted
//! helper dependency, never a request-selected program or web command channel.
//! A database receipt alone does not prove authentication or session closure.
use crate::account_mutation::Request;
use crate::auth::CommandExecutor;
use std::time::{Duration, Instant};

// Existing bounded scalar diagnostics are also retained by ordinary requests.
std::thread_local! { static NATIVE_READ_PHASE: std::cell::Cell<u8> = const { std::cell::Cell::new(0) }; }
fn native_read_phase(phase: u8) {
    NATIVE_READ_PHASE.with(|value| value.set(phase));
}
pub(crate) fn reset_native_read_diagnostic() {
    native_read_phase(0);
}
pub(crate) fn native_read_diagnostic() -> u8 {
    NATIVE_READ_PHASE.with(std::cell::Cell::get)
}

pub const SQL_PROGRAM: &str = "/usr/local/bin/mariadb";
pub const HASH_PROGRAM: &str = "/usr/local/bin/doveadm";
pub const SQL_ARGS: &[&str] = &[
    "--defaults-file=/etc/osmap/account-mariadb.cnf",
    "-N",
    "-B",
    "--raw",
    "--database=postfixadmin",
];
pub const HASH_ARGS: &[&str] = &["-O", "pw", "-s", "ARGON2ID"];
const OUTPUT_LIMIT: usize = 4096;
const INPUT_LIMIT: usize = 16384;
const PHASE_LIMIT: Duration = Duration::from_secs(10);
const ARGON_PREFIX: &str = "{ARGON2ID}$argon2id$v=19$m=65536,t=3,p=1$";

#[derive(Debug, PartialEq, Eq)]
pub enum Error {
    Refused,
    /// Dispatch may have changed the credential. Never repeat automatically.
    Unconfirmed {
        changed_at: Option<String>,
    },
}

/// Private comparison material; deliberately lacks Debug, Clone and Serialize.
pub struct Snapshot {
    account: String,
    password_hash: String,
    modified: String,
    smtp_active: bool,
}

/// Verified database write only; no session/authentication success flag exists.
pub struct WriteReceipt {
    changed_at: String,
}
impl WriteReceipt {
    pub fn changed_at(&self) -> &str {
        &self.changed_at
    }
}

pub struct Backend<E> {
    executor: E,
}
impl<E: CommandExecutor> Backend<E> {
    /// Native callers must independently provide fixed command custody,
    /// hash-only CONFIG_FILE/STATS isolation, confinement and owned cleanup.
    /// This constructor establishes none of those deployment properties.
    pub fn new(executor: E) -> Self {
        Self { executor }
    }

    pub fn read(&self, account: &str, deadline: Instant) -> Result<Snapshot, Error> {
        native_read_phase(1);
        crate::account_admission::valid_account(account).map_err(|_| Error::Refused)?;
        let query = format!(
            "SELECT HEX(password),DATE_FORMAT(modified,'%Y%m%d%H%i%s'),active,smtp_active FROM mailbox WHERE BINARY username=BINARY {} LIMIT 2;\n",
            sql_hex(account)
        );
        native_read_phase(2);
        let text = self.run(SQL_PROGRAM, SQL_ARGS, query.as_bytes(), deadline, false)?;
        native_read_phase(6);
        let lines: Vec<_> = text.lines().collect();
        if lines.len() != 1 {
            return Err(Error::Refused);
        }
        native_read_phase(7);
        let fields: Vec<_> = lines[0].split('\t').collect();
        if fields.len() != 4 || fields[2] != "1" || !matches!(fields[3], "0" | "1") {
            return Err(Error::Refused);
        }
        native_read_phase(8);
        let password_hash = decode_hash(fields[0]).ok_or(Error::Refused)?;
        native_read_phase(9);
        if !supported_hash(&password_hash) {
            return Err(Error::Refused);
        }
        native_read_phase(10);
        if !crate::account_mutation::changed_at_valid(fields[1]) {
            return Err(Error::Refused);
        }
        native_read_phase(11);
        Ok(Snapshot {
            account: account.into(),
            password_hash,
            modified: fields[1].into(),
            smtp_active: fields[3] == "1",
        })
    }

    /// The caller has authenticated Request and holds its account lock. The
    /// code-owned callback rechecks containment immediately before SQL dispatch.
    pub fn replace(
        &self,
        snapshot: Snapshot,
        request: &Request,
        deadline: Instant,
        before_write: impl FnOnce() -> Result<(), Error>,
    ) -> Result<WriteReceipt, Error> {
        let deadline = request
            .workflow_deadline()
            .map_or(deadline, |original| original.min(deadline));
        check_deadline(deadline)?;
        crate::account_admission::valid_account(request.account()).map_err(|_| Error::Refused)?;
        if snapshot.account != request.account()
            || !supported_hash(&snapshot.password_hash)
            || !crate::account_mutation::changed_at_valid(&snapshot.modified)
            || crate::password_change::Request::new(
                request.current(),
                request.new_password(),
                request.confirmation(),
                "000000",
            )
            .is_err()
        {
            return Err(Error::Refused);
        }
        let hash_input = format!("{}\n{}\n", request.new_password(), request.new_password());
        let hash_text = self.run(
            HASH_PROGRAM,
            HASH_ARGS,
            hash_input.as_bytes(),
            deadline,
            false,
        )?;
        // Exactly one terminated or unterminated hash line, not arbitrary trim.
        let hashed = hash_text.strip_suffix('\n').unwrap_or(&hash_text);
        if !argon_hash(hashed) || hashed == snapshot.password_hash {
            return Err(Error::Refused);
        }
        let query = format!(
            "START TRANSACTION;\nUPDATE mailbox SET password={},modified=UTC_TIMESTAMP() WHERE BINARY username=BINARY {} AND active=1 AND smtp_active={} AND BINARY password=BINARY {} AND modified=STR_TO_DATE('{}','%Y%m%d%H%i%s');\nSELECT ROW_COUNT();\nSELECT HEX(password),DATE_FORMAT(modified,'%Y%m%d%H%i%s') FROM mailbox WHERE BINARY username=BINARY {};\nCOMMIT;\n",
            sql_hex(hashed), sql_hex(request.account()), u8::from(snapshot.smtp_active),
            sql_hex(&snapshot.password_hash), snapshot.modified, sql_hex(request.account())
        );
        // Callback errors are necessarily before credential dispatch. A callback
        // cannot turn a pre-write refusal into a claimed database write.
        before_write().map_err(|_| Error::Refused)?;
        check_deadline(deadline)?;
        let text = self.run(SQL_PROGRAM, SQL_ARGS, query.as_bytes(), deadline, true)?;
        let lines: Vec<_> = text.lines().collect();
        if lines.len() != 2 {
            return Err(unknown());
        }
        // Exact zero changed rows is a settled no-write conflict, irrespective
        // of the independently changing row returned by the following SELECT.
        if lines[0] == "0" {
            return Err(if Instant::now() >= deadline {
                unknown()
            } else {
                Error::Refused
            });
        }
        if lines[0] != "1" {
            return Err(unknown());
        }
        let fields: Vec<_> = lines[1].split('\t').collect();
        if fields.len() != 2
            || fields[0] != upper_hex(hashed.as_bytes())
            || !crate::account_mutation::changed_at_valid(fields[1])
        {
            return Err(unknown());
        }
        let changed_at = fields[1].to_owned();
        if Instant::now() >= deadline {
            return Err(Error::Unconfirmed {
                changed_at: Some(changed_at),
            });
        }
        Ok(WriteReceipt { changed_at })
    }

    fn run(
        &self,
        program: &str,
        args: &[&str],
        input: &[u8],
        deadline: Instant,
        dispatched_write: bool,
    ) -> Result<String, Error> {
        check_deadline(deadline)?;
        if input.len() > INPUT_LIMIT {
            return Err(Error::Refused);
        }
        let timeout = deadline
            .checked_duration_since(Instant::now())
            .ok_or(Error::Refused)?
            .min(PHASE_LIMIT);
        if timeout.is_zero() {
            return Err(Error::Refused);
        }
        let args: Vec<_> = args.iter().map(|value| (*value).into()).collect();
        if !dispatched_write {
            native_read_phase(3);
        }
        let result = self
            .executor
            .run_with_stdin_bytes_timeout_and_output_limit(
                program,
                &args,
                input,
                timeout,
                OUTPUT_LIMIT,
            )
            .map_err(|_| failure(dispatched_write))?;
        if !dispatched_write {
            native_read_phase(4);
        }
        if result.status_code != 0
            || !result.stderr.is_empty()
            || result.stdout.len() > OUTPUT_LIMIT
            || !result.stdout.is_ascii()
        {
            return Err(failure(dispatched_write));
        }
        // A valid write receipt may preserve its exact time after deadline;
        // its caller parses before classifying expiry as Unconfirmed.
        if !dispatched_write {
            native_read_phase(5);
            check_deadline(deadline)?;
        }
        Ok(result.stdout)
    }
}

fn check_deadline(deadline: Instant) -> Result<(), Error> {
    if Instant::now() >= deadline {
        Err(Error::Refused)
    } else {
        Ok(())
    }
}
fn failure(dispatched: bool) -> Error {
    if dispatched {
        unknown()
    } else {
        Error::Refused
    }
}
fn unknown() -> Error {
    Error::Unconfirmed { changed_at: None }
}
fn upper_hex(bytes: &[u8]) -> String {
    bytes.iter().map(|byte| format!("{byte:02X}")).collect()
}
fn sql_hex(value: &str) -> String {
    format!("CONVERT(0x{} USING utf8mb4)", upper_hex(value.as_bytes()))
}
fn decode_hash(encoded: &str) -> Option<String> {
    if encoded.is_empty()
        || encoded.len() > 510
        || encoded.len() % 2 != 0
        || !encoded
            .bytes()
            .all(|b| b.is_ascii_digit() || (b'A'..=b'F').contains(&b))
    {
        return None;
    }
    let bytes: Option<Vec<u8>> = encoded
        .as_bytes()
        .chunks_exact(2)
        .map(|pair| {
            let text = std::str::from_utf8(pair).ok()?;
            u8::from_str_radix(text, 16).ok()
        })
        .collect();
    let value = String::from_utf8(bytes?).ok()?;
    value.is_ascii().then_some(value)
}
fn argon_hash(value: &str) -> bool {
    let Some(rest) = value.strip_prefix(ARGON_PREFIX) else {
        return false;
    };
    let Some((salt, digest)) = rest.split_once('$') else {
        return false;
    };
    let base64 = |b: u8| b.is_ascii_alphanumeric() || b == b'+' || b == b'/';
    salt.len() == 22 && digest.len() == 43 && salt.bytes().all(base64) && digest.bytes().all(base64)
}
fn supported_hash(value: &str) -> bool {
    if argon_hash(value) {
        return true;
    }
    let Some(rest) = value.strip_prefix("{BLF-CRYPT}$2") else {
        return false;
    };
    let bytes = rest.as_bytes();
    bytes.len() == 58
        && matches!(bytes[0], b'a' | b'b' | b'y')
        && bytes[1] == b'$'
        && bytes[2..4].iter().all(u8::is_ascii_digit)
        && bytes[4] == b'$'
        && bytes[5..]
            .iter()
            .all(|b| b.is_ascii_alphanumeric() || matches!(b, b'.' | b'/'))
}

#[cfg(test)]
#[path = "account_password_backend_tests.rs"]
mod tests;
