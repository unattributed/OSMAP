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
pub(crate) const SQL_SOCKET: &str = "/var/run/mysql/mysql.sock";
const SQL_DATABASE_ARG: &str = "--database=postfixadmin";
// The admin writer and Dovecot reader compare against the native recovery target.
pub(crate) const SQL_DATABASE: &str = SQL_DATABASE_ARG.split_at("--database=".len()).1;
pub const SQL_ARGS: &[&str] = &[
    "--defaults-file=/etc/osmap/account-mariadb.cnf",
    "-N",
    "-B",
    "--raw",
    SQL_DATABASE_ARG,
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

/// Native-owned pending-account comparison material. No browser deserializer,
/// Debug or Serialize exposes the recorded contact or credential comparison.
pub(crate) struct PendingInitial {
    pub(crate) account: String,
    pub(crate) email: String,
    pub(crate) operation: String,
    pub(crate) revision: u64,
    pub(crate) approved_at: u64,
    pub(crate) credential_digest: String,
    writer_holder: String,
    writer_epoch: u64,
}

/// The native setup transaction publishes this contact only after the email
/// proof and initial factor were verified. Later password/admin changes do not
/// remove that verification. Deliberately no Debug or wire deserializer.
pub(crate) struct CompletedInitialContact {
    pub(crate) account: String,
    pub(crate) email: String,
    pub(crate) revision: u64,
    pub(crate) verified_at: u64,
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

    pub(crate) fn pending_initial(
        &self,
        account: &str,
        deadline: Instant,
    ) -> Result<Option<PendingInitial>, Error> {
        crate::account_admission::valid_account(account).map_err(|_| Error::Refused)?;
        let query = format!(concat!(
            "SET time_zone='+00:00'; SELECT HEX(m.username),HEX(i.recovery_email),i.request_id,i.revision,UNIX_TIMESTAMP(i.created),o.credential_digest,i.writer_holder,i.writer_epoch ",
            "FROM osmap_initial_accounts i JOIN mailbox m ON BINARY m.username=BINARY i.username JOIN osmap_admin_operations o ON BINARY o.username=BINARY m.username AND BINARY o.request_id=BINARY i.request_id ",
            "JOIN domain d ON BINARY d.domain=BINARY m.domain JOIN alias a ON BINARY a.address=BINARY m.username JOIN admin actor ON BINARY actor.username=BINARY o.actor JOIN osmap_admin_writer w ON w.id=1 ",
            "WHERE BINARY m.username=BINARY {account} AND i.status='pending' AND i.activated IS NULL AND i.revision>0 AND m.active=0 AND m.smtp_active=0 ",
            "AND o.kind='mailbox.create' AND BINARY o.domain=BINARY m.domain AND BINARY o.credential_digest=BINARY SHA2(m.password,256) AND d.active=1 AND d.backupmx=0 ",
            "AND a.active=1 AND BINARY a.goto=BINARY m.username AND BINARY a.domain=BINARY m.domain AND actor.active=1 ",
            "AND ((actor.superadmin=1 AND EXISTS(SELECT 1 FROM domain_admins g WHERE BINARY g.username=BINARY actor.username AND BINARY g.domain=BINARY 'ALL' AND g.active=1)) ",
            "OR (actor.superadmin=0 AND EXISTS(SELECT 1 FROM domain_admins g WHERE BINARY g.username=BINARY actor.username AND BINARY g.domain=BINARY m.domain AND g.active=1) AND NOT EXISTS(SELECT 1 FROM domain_admins g WHERE BINARY g.username=BINARY actor.username AND BINARY g.domain=BINARY 'ALL' AND g.active=1))) ",
            "AND w.mode='lab_writer' AND BINARY w.holder=BINARY i.writer_holder AND w.epoch=i.writer_epoch LIMIT 2;\n"
        ), account=sql_hex(account));
        let text = self.run(SQL_PROGRAM, SQL_ARGS, query.as_bytes(), deadline, false)?;
        if text.is_empty() {
            return Ok(None);
        }
        let rows = text.lines().collect::<Vec<_>>();
        if rows.len() != 1 {
            return Err(Error::Refused);
        }
        let fields = rows[0].split('\t').collect::<Vec<_>>();
        if fields.len() != 8 {
            return Err(Error::Refused);
        }
        let selected = decode_hash(fields[0]).ok_or(Error::Refused)?;
        let email = decode_hash(fields[1]).ok_or(Error::Refused)?;
        let number = |text: &str| {
            text.parse::<u64>()
                .ok()
                .filter(|value| *value > 0 && value.to_string() == text)
                .ok_or(Error::Refused)
        };
        let revision = number(fields[3])?;
        let approved_at = number(fields[4])?;
        let writer_epoch = number(fields[7])?;
        let reference = |text: &str, length: usize| {
            text.len() == length && text.bytes().all(|b| b.is_ascii_hexdigit())
        };
        if selected != account
            || email.eq_ignore_ascii_case(account)
            || email.len() > 254
            || email.chars().any(char::is_control)
            || crate::mail_address::validate_address(crate::send::ComposePolicy::default(), &email)
                .is_err()
            || !reference(fields[2], 64)
            || !reference(fields[5], 64)
            || !reference(fields[6], 32)
        {
            return Err(Error::Refused);
        }
        Ok(Some(PendingInitial {
            account: selected,
            email,
            operation: fields[2].into(),
            revision,
            approved_at,
            credential_digest: fields[5].into(),
            writer_holder: fields[6].into(),
            writer_epoch,
        }))
    }

    pub(crate) fn completed_initial_contact(
        &self,
        account: &str,
        deadline: Instant,
    ) -> Result<Option<CompletedInitialContact>, Error> {
        crate::account_admission::valid_account(account).map_err(|_| Error::Refused)?;
        let query=format!(concat!(
            "SET time_zone='+00:00'; SELECT HEX(m.username),HEX(i.recovery_email),i.revision,UNIX_TIMESTAMP(i.activated) ",
            "FROM osmap_initial_accounts i JOIN mailbox m ON BINARY m.username=BINARY i.username JOIN osmap_admin_operations o ON BINARY o.username=BINARY m.username AND BINARY o.request_id=BINARY i.request_id ",
            "JOIN domain d ON BINARY d.domain=BINARY m.domain JOIN alias a ON BINARY a.address=BINARY m.username ",
            "WHERE BINARY m.username=BINARY {account} AND i.status='complete' AND i.activated IS NOT NULL AND i.revision>0 ",
            "AND o.kind='mailbox.create' AND BINARY o.domain=BINARY m.domain AND m.active=1 AND m.smtp_active=1 AND d.active=1 AND d.backupmx=0 ",
            "AND a.active=1 AND BINARY a.goto=BINARY m.username AND BINARY a.domain=BINARY m.domain LIMIT 2;\n"
        ),account=sql_hex(account));
        let text = self.run(SQL_PROGRAM, SQL_ARGS, query.as_bytes(), deadline, false)?;
        if text.is_empty() {
            return Ok(None);
        }
        let rows = text.lines().collect::<Vec<_>>();
        if rows.len() != 1 {
            return Err(Error::Refused);
        }
        let fields = rows[0].split('\t').collect::<Vec<_>>();
        if fields.len() != 4 {
            return Err(Error::Refused);
        }
        let selected = decode_hash(fields[0]).ok_or(Error::Refused)?;
        let email = decode_hash(fields[1]).ok_or(Error::Refused)?;
        let number = |value: &str| {
            value
                .parse::<u64>()
                .ok()
                .filter(|number| *number > 0 && number.to_string() == value)
                .ok_or(Error::Refused)
        };
        let revision = number(fields[2])?;
        let verified_at = number(fields[3])?;
        if selected != account
            || email.eq_ignore_ascii_case(account)
            || email.len() > 254
            || email.chars().any(char::is_control)
            || crate::mail_address::validate_address(crate::send::ComposePolicy::default(), &email)
                .is_err()
        {
            return Err(Error::Refused);
        }
        Ok(Some(CompletedInitialContact {
            account: selected,
            email,
            revision,
            verified_at,
        }))
    }

    /// Consume only the initial-purpose grant's exact pending operation. The
    /// native callback installs the proved first factor and replay counter;
    /// all subsequent failures retain uncertainty rather than retrying it.
    pub(crate) fn activate_initial(
        &self,
        pending: PendingInitial,
        grant: &crate::access_recovery::GrantBinding,
        password: &str,
        confirmation: &str,
        deadline: Instant,
        before_write: impl FnOnce() -> Result<(), Error>,
    ) -> Result<WriteReceipt, Error> {
        use crate::access_recovery::{FactorBinding, Purpose};
        check_deadline(deadline)?;
        if grant.account != pending.account
            || grant.purpose != Purpose::InitialAccountSetup
            || grant.epoch != 0
            || !matches!(&grant.factor, FactorBinding::Absent {provision_operation, revision}
                if provision_operation==&pending.operation && *revision==pending.revision)
            || !crate::password_change::valid_new_password(password, confirmation)
        {
            return Err(Error::Refused);
        }
        let input = format!("{password}\n{password}\n");
        let text = self.run(HASH_PROGRAM, HASH_ARGS, input.as_bytes(), deadline, false)?;
        let hash = text.strip_suffix('\n').unwrap_or(&text);
        if !argon_hash(hash) {
            return Err(Error::Refused);
        }
        let domain = pending.account.split_once('@').ok_or(Error::Refused)?.1;
        let query = format!(concat!(
            "SET time_zone='+00:00'; SET SESSION innodb_lock_wait_timeout=3; START TRANSACTION;\n",
            "SET @h=NULL,@e=NULL,@mode=NULL; SELECT holder,epoch,mode INTO @h,@e,@mode FROM osmap_admin_writer WHERE id=1 FOR UPDATE;\n",
            "SET @i=NULL; SELECT username INTO @i FROM osmap_initial_accounts WHERE BINARY username=BINARY {account} AND BINARY request_id=BINARY {operation} AND revision={revision} AND BINARY recovery_email=BINARY {email} AND UNIX_TIMESTAMP(created)={approved} AND status='pending' AND activated IS NULL AND BINARY writer_holder=BINARY {holder} AND writer_epoch={epoch} FOR UPDATE;\n",
            "SET @domain=NULL; SELECT domain INTO @domain FROM domain WHERE BINARY domain=BINARY {domain} AND active=1 AND backupmx=0 FOR UPDATE;\n",
            "SET @actor=NULL; SELECT actor INTO @actor FROM osmap_admin_operations WHERE BINARY username=BINARY {account} AND BINARY request_id=BINARY {operation} AND BINARY domain=BINARY {domain} AND kind='mailbox.create' AND BINARY credential_digest=BINARY {old_digest} FOR UPDATE;\n",
            "SET @admin=NULL,@system=NULL; SELECT username,superadmin INTO @admin,@system FROM admin WHERE BINARY username=BINARY @actor AND active=1 FOR UPDATE;\n",
            "SET @all=NULL,@grant=NULL; SELECT domain INTO @all FROM domain_admins WHERE BINARY username=BINARY @actor AND BINARY domain=BINARY 'ALL' AND active=1 FOR UPDATE; SELECT domain INTO @grant FROM domain_admins WHERE BINARY username=BINARY @actor AND BINARY domain=BINARY {domain} AND active=1 FOR UPDATE;\n",
            "SET @alias=NULL; SELECT address INTO @alias FROM alias WHERE BINARY address=BINARY {account} AND BINARY goto=BINARY {account} AND BINARY domain=BINARY {domain} AND active=1 FOR UPDATE;\n",
            "UPDATE mailbox SET password={hash},modified=UTC_TIMESTAMP(),active=1,smtp_active=1 WHERE BINARY username=BINARY {account} AND BINARY domain=BINARY {domain} AND active=0 AND smtp_active=0 AND BINARY SHA2(password,256)=BINARY {old_digest} AND @i IS NOT NULL AND @domain IS NOT NULL AND @admin IS NOT NULL AND @alias IS NOT NULL AND ((@system=1 AND @all IS NOT NULL) OR (@system=0 AND @all IS NULL AND @grant IS NOT NULL)) AND @mode='lab_writer' AND BINARY @h=BINARY {holder} AND @e={epoch}; SET @m=ROW_COUNT();\n",
            "UPDATE osmap_admin_operations SET credential_digest=SHA2({hash},256) WHERE BINARY request_id=BINARY {operation} AND BINARY username=BINARY {account} AND @m=1; SET @o=ROW_COUNT();\n",
            "UPDATE osmap_initial_accounts SET status='complete',activated=UTC_TIMESTAMP() WHERE BINARY username=BINARY {account} AND BINARY request_id=BINARY {operation} AND revision={revision} AND status='pending' AND @m=1 AND @o=1; SET @i=ROW_COUNT();\n",
            "UPDATE osmap_admin_writer SET revision=revision+1 WHERE id=1 AND @m=1 AND @o=1 AND @i=1; SET @w=ROW_COUNT();\n",
            "SET @finish=IF(@m=1 AND @o=1 AND @i=1 AND @w=1,'COMMIT','ROLLBACK'); PREPARE osmap_finish FROM @finish; EXECUTE osmap_finish; SELECT IF(@finish='COMMIT','activated','refused');\n"
        ), account=sql_hex(&pending.account),operation=sql_hex(&pending.operation),revision=pending.revision,
            email=sql_hex(&pending.email),approved=pending.approved_at,holder=sql_hex(&pending.writer_holder),
            epoch=pending.writer_epoch,domain=sql_hex(domain),hash=sql_hex(hash),old_digest=sql_hex(&pending.credential_digest));
        before_write().map_err(|_| unknown())?;
        check_deadline(deadline).map_err(|_| unknown())?;
        if self
            .run(SQL_PROGRAM, SQL_ARGS, query.as_bytes(), deadline, true)
            .map_err(|_| unknown())?
            != "activated\n"
        {
            return Err(unknown());
        }
        let readback = format!("SELECT HEX(m.password),DATE_FORMAT(m.modified,'%Y%m%d%H%i%s') FROM mailbox m JOIN osmap_initial_accounts i ON BINARY i.username=BINARY m.username JOIN osmap_admin_operations o ON BINARY o.username=BINARY m.username AND BINARY o.request_id=BINARY i.request_id JOIN alias a ON BINARY a.address=BINARY m.username WHERE BINARY m.username=BINARY {} AND BINARY i.request_id=BINARY {} AND i.revision={} AND i.status='complete' AND i.activated IS NOT NULL AND m.active=1 AND m.smtp_active=1 AND a.active=1 AND BINARY a.goto=BINARY m.username AND BINARY a.domain=BINARY m.domain AND BINARY o.credential_digest=BINARY SHA2(m.password,256);\n",sql_hex(&pending.account),sql_hex(&pending.operation),pending.revision);
        let text = self
            .run(SQL_PROGRAM, SQL_ARGS, readback.as_bytes(), deadline, true)
            .map_err(|_| unknown())?;
        let rows = text.lines().collect::<Vec<_>>();
        if rows.len() != 1 {
            return Err(unknown());
        }
        let fields = rows[0].split('\t').collect::<Vec<_>>();
        if fields.len() != 2
            || fields[0] != upper_hex(hash.as_bytes())
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
        self.replace_validated(snapshot, request.new_password(), deadline, before_write)
    }

    /// Only native recovery composition calls this while consuming a genuine
    /// one-use email recovery grant and holding the account containment guard.
    /// It shares the exact existing hash/CAS writer without inventing a current
    /// password or a normal login/session proof.
    pub(crate) fn reset_after_recovery(
        &self,
        snapshot: Snapshot,
        grant: &crate::access_recovery::GrantBinding,
        new_password: &str,
        confirmation: &str,
        deadline: Instant,
        before_write: impl FnOnce() -> Result<(), Error>,
    ) -> Result<WriteReceipt, Error> {
        if snapshot.account != grant.account
            || grant.purpose != crate::access_recovery::Purpose::AccountRecoverySetup
            || !crate::password_change::valid_new_password(new_password, confirmation)
        {
            return Err(Error::Refused);
        }
        self.replace_validated(snapshot, new_password, deadline, before_write)
    }

    fn replace_validated(
        &self,
        snapshot: Snapshot,
        new_password: &str,
        deadline: Instant,
        before_write: impl FnOnce() -> Result<(), Error>,
    ) -> Result<WriteReceipt, Error> {
        check_deadline(deadline)?;
        let hash_input = format!("{new_password}\n{new_password}\n");
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
            sql_hex(hashed), sql_hex(&snapshot.account), u8::from(snapshot.smtp_active),
            sql_hex(&snapshot.password_hash), snapshot.modified, sql_hex(&snapshot.account)
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
pub(crate) fn argon_hash(value: &str) -> bool {
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
    // Stock Dovecot BLF passdbs may store the self-identifying 60-byte bcrypt
    // form without a scheme prefix. This is snapshot syntax only: the caller
    // still authenticates through the qualified passdb before any write. Never
    // normalize these bytes; the CAS must compare the actual stored value.
    let (bcrypt, bare) = match value.strip_prefix("{BLF-CRYPT}") {
        Some(bcrypt) => (bcrypt, false),
        None => (value, true),
    };
    let Some(rest) = bcrypt.strip_prefix("$2") else {
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
        // Keep the existing prefixed language unchanged; newly admitted bare
        // bcrypt must also carry a supported decimal work factor,04 through31.
        && (!bare || (4..=31).contains(&((bytes[2] - b'0') * 10 + bytes[3] - b'0')))
}

#[cfg(test)]
#[path = "account_password_backend_tests.rs"]
mod tests;
