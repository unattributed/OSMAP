//! Existing-domain mailbox provisioning. No web-selected SQL, paths or native UID.
use super::*;
use crate::admin_config::WriterConfig;
use crate::private_account_file::PrivateAccountFile;
use hmac::{Hmac, Mac};

pub(crate) const WRITER_ARGS: &[&str] = &[
    "--defaults-file=/etc/osmap/admin-write-mariadb.cnf",
    "--database=postfixadmin",
    "--batch",
    "--skip-column-names",
    "--raw",
];
/// Additive schema fragment for a privileged local installer. It enables no writer.
/// The selected compatibility tables must already exist and use InnoDB.
pub(crate) const SCHEMA: &str = "CREATE TABLE osmap_admin_writer (id TINYINT NOT NULL PRIMARY KEY CHECK(id=1), mode VARCHAR(16) NOT NULL, holder CHAR(32) CHARACTER SET ascii COLLATE ascii_bin NOT NULL, epoch BIGINT UNSIGNED NOT NULL, revision BIGINT UNSIGNED NOT NULL) ENGINE=InnoDB;\nINSERT INTO osmap_admin_writer VALUES (1,'disabled','00000000000000000000000000000000',0,1);\nCREATE TABLE osmap_admin_operations (request_id CHAR(64) CHARACTER SET ascii COLLATE ascii_bin NOT NULL PRIMARY KEY, actor VARBINARY(96) NOT NULL, digest CHAR(64) CHARACTER SET ascii COLLATE ascii_bin NOT NULL, credential_digest CHAR(64) CHARACTER SET ascii COLLATE ascii_bin NOT NULL, username VARBINARY(254) NOT NULL UNIQUE, domain VARBINARY(253) NOT NULL, quota BIGINT UNSIGNED NOT NULL, revision BIGINT UNSIGNED NOT NULL, created DATETIME NOT NULL, kind VARCHAR(32) NOT NULL CHECK(kind='mailbox.create')) ENGINE=InnoDB;\nCREATE TABLE osmap_initial_accounts (username VARBINARY(254) NOT NULL PRIMARY KEY, request_id CHAR(64) CHARACTER SET ascii COLLATE ascii_bin NOT NULL UNIQUE, recovery_email VARBINARY(254) NOT NULL, revision BIGINT UNSIGNED NOT NULL CHECK(revision>0), writer_holder CHAR(32) CHARACTER SET ascii COLLATE ascii_bin NOT NULL, writer_epoch BIGINT UNSIGNED NOT NULL, created DATETIME NOT NULL, status VARCHAR(16) CHARACTER SET ascii COLLATE ascii_bin NOT NULL DEFAULT 'pending' CHECK(status IN ('pending','complete')), activated DATETIME NULL, CHECK((status='pending' AND activated IS NULL) OR (status='complete' AND activated IS NOT NULL))) ENGINE=InnoDB;\n";

const INITIAL_READY: &str = "SELECT username,request_id,recovery_email,revision,writer_holder,writer_epoch,created,status,activated FROM osmap_initial_accounts LIMIT 0;\nSTART TRANSACTION; INSERT INTO osmap_initial_accounts (username,request_id,recovery_email,revision,writer_holder,writer_epoch,created) SELECT '',REPEAT('0',64),'',1,REPEAT('0',32),1,UTC_TIMESTAMP() WHERE 0; ROLLBACK; SELECT 'ready';\n";

#[derive(Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub(crate) enum CreateFailure {
    WriterDisabled,
    Invalid,
    Denied,
    Missing,
    Conflict,
    Stale,
    Limit,
    StepUp,
    Unconfirmed,
    Unavailable,
}
impl From<Error> for CreateFailure {
    fn from(value: Error) -> Self {
        match value {
            Error::Denied | Error::Forbidden => Self::Denied,
            Error::Missing => Self::Missing,
            Error::Invalid => Self::Invalid,
            _ => Self::Unavailable,
        }
    }
}
fn hex64(s: &str) -> bool {
    s.len() == 64 && s.bytes().all(|b| b.is_ascii_hexdigit())
}
fn request64(s: &str) -> bool {
    hex64(s) && s == s.to_ascii_lowercase()
}
fn local(s: &str) -> bool {
    !s.is_empty()
        && s.len() <= 64
        && !s.starts_with('.')
        && !s.ends_with('.')
        && !s.contains("..")
        && s.bytes()
            .all(|b| b.is_ascii_alphanumeric() || b"._-".contains(&b))
}
#[derive(Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct CreatePage {
    pub(crate) login: String,
    pub(crate) csrf: String,
    pub(crate) domain: String,
    pub(crate) revision: u64,
    pub(crate) request_id: String,
    #[serde(default)]
    pub(crate) setup_enabled: bool,
}
impl CreatePage {
    pub(crate) fn valid(&self) -> bool {
        valid_login(&self.login)
            && hex64(&self.csrf)
            && Scope::domains(&[&self.domain]).is_ok()
            && self.domain == self.domain.to_ascii_lowercase()
            && self.revision > 0
            && request64(&self.request_id)
    }
}
/// Private input, intentionally no Debug. Never echo or persist serialized input.
#[derive(Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct CreateMailbox {
    pub(crate) domain: String,
    pub(crate) local_part: String,
    pub(crate) display_name: String,
    pub(crate) password: String,
    pub(crate) confirmation: String,
    pub(crate) totp: String,
    pub(crate) csrf: String,
    pub(crate) request_id: String,
    pub(crate) quota_mib: u32,
    pub(crate) revision: u64,
    #[serde(default)]
    pub(crate) setup_contact: Option<String>,
}
impl CreateMailbox {
    pub(crate) fn valid(&self) -> bool {
        Scope::domains(&[&self.domain]).is_ok()
            && local(&self.local_part)
            && self.domain == self.domain.to_ascii_lowercase()
            && crate::account_admission::valid_account(&self.username()).is_ok()
            && self.display_name.chars().count() <= 255
            && self.display_name.len() <= 1020
            && !self.display_name.chars().any(char::is_control)
            && self.setup_contact.as_deref().is_some_and(|contact| {
                contact.is_ascii()
                    && !contact.chars().any(char::is_control)
                    && crate::mail_address::validate_address(
                        crate::send::ComposePolicy::default(),
                        contact,
                    )
                    .is_ok()
                    && !contact.eq_ignore_ascii_case(&self.username())
                    && contact
                        .rsplit_once('@')
                        .is_some_and(|(_, domain)| !domain.eq_ignore_ascii_case(&self.domain))
                    && self.password.is_empty()
                    && self.confirmation.is_empty()
            })
            && self.totp.len() == 6
            && self.totp.bytes().all(|b| b.is_ascii_digit())
            && hex64(&self.csrf)
            && request64(&self.request_id)
            && self.revision > 0
            && (1..=1_048_576).contains(&self.quota_mib)
    }
    fn username(&self) -> String {
        format!("{}@{}", self.local_part.to_ascii_lowercase(), self.domain)
    }
}
#[derive(Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct CreateReceipt {
    pub(crate) login: String,
    pub(crate) csrf: String,
    pub(crate) domain: String,
    pub(crate) username: String,
    pub(crate) request_id: String,
    pub(crate) quota: u64,
    #[serde(default)]
    pub(crate) setup_pending: bool,
}
impl CreateReceipt {
    pub(crate) fn valid(&self) -> bool {
        valid_login(&self.login)
            && hex64(&self.csrf)
            && request64(&self.request_id)
            && Scope::domains(&[&self.domain]).is_ok()
            && self
                .username
                .strip_suffix(&format!("@{}", self.domain))
                .is_some_and(local)
            && self.username == self.username.to_ascii_lowercase()
            && self.username.len() <= 254
            && crate::account_admission::valid_account(&self.username).is_ok()
            && self.quota > 0
            && self.quota <= 1_048_576u64 * 1_048_576
    }
}
#[derive(Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct Intent {
    request_id: String,
    digest: String,
    actor: String,
    pending: bool,
}
fn sql(s: &str) -> String {
    format!("CONVERT(0x{} USING utf8mb4)", upper_hex(s.as_bytes()))
}

impl<E, T, P> Service<E, T, P>
where
    E: CommandExecutor + Clone + Send + Sync + 'static,
    T: TimeProvider + Clone,
    P: PasswordVerifier,
{
    pub(crate) fn with_writer(mut self, writer: Option<WriterConfig>) -> Self {
        self.writer = writer;
        self
    }
    pub(super) fn writer_scope(
        &self,
        summary: &Summary,
        domain: &str,
    ) -> Result<&WriterConfig, CreateFailure> {
        let writer = self.writer.as_ref().ok_or(CreateFailure::WriterDisabled)?;
        if Scope::domains(&[domain]).is_err() || domain != domain.to_ascii_lowercase() {
            return Err(CreateFailure::Invalid);
        }
        if !writer.administrators.iter().any(|a| a == &summary.login)
            || !writer.domains.iter().any(|d| d == domain)
            || (!summary.system && !summary.domains.iter().any(|d| d == domain))
        {
            return Err(CreateFailure::Missing);
        }
        Ok(writer)
    }
    pub(super) fn writer_sql(
        &self,
        input: &str,
        dispatched: bool,
    ) -> Result<String, CreateFailure> {
        let failed = if dispatched {
            CreateFailure::Unconfirmed
        } else {
            CreateFailure::Unavailable
        };
        let output = self
            .authority
            .executor
            .run_with_stdin_bytes_timeout_and_output_limit(
                PROGRAM,
                &WRITER_ARGS.iter().map(|s| (*s).into()).collect::<Vec<_>>(),
                input.as_bytes(),
                Duration::from_secs(10),
                16384,
            )
            .map_err(|_| failed)?;
        if output.status_code != 0 || !output.stderr.is_empty() || output.stdout.len() > 16384 {
            return Err(failed);
        }
        Ok(output.stdout)
    }
    fn initial_setup_ready(&self) -> Result<(), CreateFailure> {
        if self.writer_sql(INITIAL_READY, false)? != "ready\n" {
            return Err(CreateFailure::Unavailable);
        }
        Ok(())
    }
    pub(crate) fn create_mailbox_form_from(
        &self,
        token: &Token,
        context: &AuthenticationContext,
        domain: &str,
    ) -> Result<CreatePage, CreateFailure> {
        let summary = self.scope(token, context)?;
        let writer = self.writer_scope(&summary, domain)?;
        self.initial_setup_ready()?;
        let scope = Scope::domains(&[domain]).map_err(|_| CreateFailure::Invalid)?;
        let record = Adapter::new(self.authority.executor.clone())
            .domain(&scope, domain)
            .map_err(|_| CreateFailure::Unavailable)?
            .ok_or(CreateFailure::Missing)?;
        if !record.active || record.backupmx {
            return Err(CreateFailure::Denied);
        }
        let output=self.writer_sql(&format!("SELECT revision FROM osmap_admin_writer WHERE id=1 AND mode='lab_writer' AND BINARY holder=BINARY {} AND epoch={};\n",sql(&writer.holder),writer.epoch),false)?;
        let revision = output
            .trim_end_matches('\n')
            .parse::<u64>()
            .map_err(|_| CreateFailure::WriterDisabled)?;
        let mut bytes = [0u8; 32];
        getrandom::getrandom(&mut bytes).map_err(|_| CreateFailure::Unavailable)?;
        Ok(CreatePage {
            login: summary.login,
            csrf: summary.csrf,
            domain: domain.into(),
            revision,
            request_id: upper_hex(&bytes).to_ascii_lowercase(),
            setup_enabled: true,
        })
    }
    pub(crate) fn create_mailbox_from(
        &self,
        token: &Token,
        context: &AuthenticationContext,
        r: &CreateMailbox,
    ) -> Result<CreateReceipt, CreateFailure> {
        if !r.valid() {
            return Err(CreateFailure::Invalid);
        }
        let summary = self.scope(token, context)?;
        let writer = self.writer_scope(&summary, &r.domain)?;
        let contact = r.setup_contact.as_deref().ok_or(CreateFailure::Invalid)?;
        if contact.rsplit_once('@').is_some_and(|(_, domain)| {
            writer
                .domains
                .iter()
                .any(|managed| managed.eq_ignore_ascii_case(domain))
        }) {
            return Err(CreateFailure::Invalid);
        }
        if !crate::http_support::constant_time_eq(summary.csrf.as_bytes(), r.csrf.as_bytes()) {
            return Err(CreateFailure::Denied);
        }
        self.initial_setup_ready()?;
        let username = r.username();
        if username.len() > 254 {
            return Err(CreateFailure::Invalid);
        }
        use crate::totp::TotpSecretStore as _;
        let factor = self
            .authority
            .factors()
            .load_secret(&factor_subject(&summary.login))
            .map_err(|_| CreateFailure::Unavailable)?
            .ok_or(CreateFailure::Denied)?;
        // Keyed digest binds retries to the canonical input without storing a
        // fast, publicly testable password digest in the operation journal.
        let mut mac = Hmac::<Sha256>::new_from_slice(&factor.secret_bytes)
            .map_err(|_| CreateFailure::Unavailable)?;
        for value in [
            &summary.login,
            &r.request_id,
            &username,
            &r.display_name,
            &r.password,
            &r.quota_mib.to_string(),
            &r.revision.to_string(),
            "initial-setup-contact-v1",
            contact,
        ] {
            mac.update(&(value.len() as u64).to_be_bytes());
            mac.update(value.as_bytes());
        }
        let digest = upper_hex(&mac.finalize().into_bytes());
        let store = PrivateAccountFile::new(
            self.authority.root.join("creation"),
            "admin-mailbox-create-v1",
            1024,
        );
        let held = store
            .lock(&username)
            .map_err(|_| CreateFailure::Unavailable)?;
        let previous = held
            .read()
            .map_err(|_| CreateFailure::Unavailable)?
            .map(|bytes| {
                serde_json::from_slice::<Intent>(&bytes).map_err(|_| CreateFailure::Unavailable)
            })
            .transpose()?;
        let lookup=format!("SELECT HEX(actor),digest,HEX(username),quota FROM osmap_admin_operations WHERE request_id={};\n",sql(&r.request_id));
        let prior = self.writer_sql(&lookup, false)?;
        let receipt = || CreateReceipt {
            login: summary.login.clone(),
            csrf: summary.csrf.clone(),
            domain: r.domain.clone(),
            username: username.clone(),
            request_id: r.request_id.clone(),
            quota: u64::from(r.quota_mib) * 1_048_576,
            setup_pending: true,
        };
        let expected = format!(
            "{}\t{}\t{}\t{}\n",
            upper_hex(summary.login.as_bytes()),
            digest,
            upper_hex(username.as_bytes()),
            u64::from(r.quota_mib) * 1_048_576
        );
        let handoff = format!(" AND EXISTS(SELECT 1 FROM osmap_initial_accounts i WHERE BINARY i.username=BINARY m.username AND BINARY i.request_id=BINARY o.request_id AND BINARY i.recovery_email=BINARY {} AND i.revision=1 AND BINARY i.writer_holder=BINARY {} AND i.writer_epoch={} AND i.status='pending' AND i.activated IS NULL)",sql(contact),sql(&writer.holder),writer.epoch);
        let verify=format!("SELECT COUNT(*) FROM mailbox m JOIN alias a ON BINARY a.address=BINARY m.username JOIN osmap_admin_operations o ON BINARY o.username=BINARY m.username WHERE o.request_id={} AND BINARY o.actor=BINARY {} AND o.digest={} AND BINARY m.username=BINARY {} AND BINARY o.credential_digest=BINARY SHA2(m.password,256) AND BINARY m.maildir=BINARY {} AND BINARY m.name=BINARY {} AND BINARY m.domain=BINARY {} AND BINARY a.domain=BINARY m.domain AND m.quota={} AND o.quota=m.quota AND m.active=0 AND m.smtp_active=0 AND BINARY a.goto=BINARY m.username AND a.active=1{handoff};\n",sql(&r.request_id),sql(&summary.login),sql(&digest),sql(&username),sql(&format!("{}/{}/",r.domain,r.local_part.to_ascii_lowercase())),sql(&r.display_name),sql(&r.domain),u64::from(r.quota_mib)*1_048_576);
        if !prior.is_empty() {
            if prior != expected {
                return Err(CreateFailure::Conflict);
            }
            if self.writer_sql(&verify, true)? != "1\n" {
                return Err(CreateFailure::Unconfirmed);
            }
            held.write(
                &serde_json::to_vec(&Intent {
                    request_id: r.request_id.clone(),
                    digest: digest.clone(),
                    actor: summary.login.clone(),
                    pending: false,
                })
                .map_err(|_| CreateFailure::Unconfirmed)?,
            )
            .map_err(|_| CreateFailure::Unconfirmed)?;
            return Ok(receipt());
        }
        if previous.as_ref().is_some_and(|p| p.pending) {
            return Err(CreateFailure::Unconfirmed);
        }
        let step_up_context = Self::account_context(&summary.login);
        let step_up_throttle = LoginThrottleService::new(
            FileLoginThrottleStore::new(self.authority.root.join("account-throttle")),
            self.clock.clone(),
            LoginThrottlePolicy::default(),
        );
        if step_up_throttle
            .check(&step_up_context, &summary.login)
            .map_err(|_| CreateFailure::Unavailable)?
            .decision
            != LoginThrottleDecision::Allowed
        {
            return Err(CreateFailure::StepUp);
        }
        let verdict = TotpVerifier::new(
            self.authority.factors(),
            self.clock.clone(),
            TotpPolicy::default(),
        )
        .verify_second_factor(
            &factor_subject(&summary.login),
            RequiredSecondFactor::Totp,
            &r.totp,
        )
        .map_err(|_| CreateFailure::Unavailable)?;
        if verdict != SecondFactorVerdict::Accept {
            step_up_throttle
                .record_failure(&step_up_context, &summary.login)
                .map_err(|_| CreateFailure::Unavailable)?;
            return Err(CreateFailure::StepUp);
        }
        step_up_throttle
            .clear_success(&step_up_context, &summary.login)
            .map_err(|_| CreateFailure::Unavailable)?;
        // Recheck authority after step-up/hash and again atomically in SQL.
        let admin = self
            .authority
            .lookup(&summary.login, false)?
            .filter(|a| a.active)
            .ok_or(CreateFailure::Denied)?;
        let mut placeholder = [0u8; 32];
        getrandom::getrandom(&mut placeholder).map_err(|_| CreateFailure::Unavailable)?;
        let hash = self.initial_password_hash(&upper_hex(&placeholder))?;
        let current = self.scope(token, context)?;
        self.writer_scope(&current, &r.domain)?;
        let intent = Intent {
            request_id: r.request_id.clone(),
            digest: digest.clone(),
            actor: summary.login.clone(),
            pending: true,
        };
        held.write(&serde_json::to_vec(&intent).map_err(|_| CreateFailure::Unavailable)?)
            .map_err(|_| CreateFailure::Unavailable)?;
        let query = transaction(
            writer,
            &summary.login,
            &admin.hash,
            &admin.modified,
            r,
            &hash,
            &digest,
        )?;
        // The durable pending intent precedes dispatch. Any uncertain result
        // prevents another request key for this account until reconciliation.
        let output = self.writer_sql(&query, true)?;
        let lines = output.lines().collect::<Vec<_>>();
        if lines.len() == 1
            && matches!(
                lines[0],
                "fence" | "stale" | "denied" | "limit" | "conflict"
            )
        {
            held.write(
                &serde_json::to_vec(&Intent {
                    pending: false,
                    ..intent
                })
                .map_err(|_| CreateFailure::Unconfirmed)?,
            )
            .map_err(|_| CreateFailure::Unconfirmed)?;
            return Err(match lines[0] {
                "fence" => CreateFailure::WriterDisabled,
                "stale" => CreateFailure::Stale,
                "denied" => CreateFailure::Denied,
                "limit" => CreateFailure::Limit,
                _ => CreateFailure::Conflict,
            });
        }
        if output != format!("committed\n{expected}") {
            return Err(CreateFailure::Unconfirmed);
        }
        // Separately read committed state, including the self alias, immutable
        // path and credential projection. This is configuration, not live auth.
        if self.writer_sql(&verify, true)? != "1\n" {
            return Err(CreateFailure::Unconfirmed);
        }
        held.write(
            &serde_json::to_vec(&Intent {
                pending: false,
                ..intent
            })
            .map_err(|_| CreateFailure::Unconfirmed)?,
        )
        .map_err(|_| CreateFailure::Unconfirmed)?;
        Ok(receipt())
    }
    pub(super) fn initial_password_hash(&self, password: &str) -> Result<String, CreateFailure> {
        if !crate::password_change::valid_new_password(password, password) {
            return Err(CreateFailure::Invalid);
        }
        let args = crate::account_password_backend::HASH_ARGS
            .iter()
            .map(|s| (*s).into())
            .collect::<Vec<_>>();
        let input = format!("{password}\n{password}\n");
        let output = self
            .authority
            .executor
            .run_with_stdin_bytes_timeout_and_output_limit(
                crate::account_password_backend::HASH_PROGRAM,
                &args,
                input.as_bytes(),
                Duration::from_secs(10),
                4096,
            )
            .map_err(|_| CreateFailure::Unavailable)?;
        let hash = output.stdout.strip_suffix('\n').unwrap_or(&output.stdout);
        if output.status_code != 0
            || !output.stderr.is_empty()
            || !crate::account_password_backend::argon_hash(hash)
        {
            return Err(CreateFailure::Unavailable);
        }
        Ok(hash.into())
    }
}

fn transaction(
    w: &WriterConfig,
    actor: &str,
    actor_hash: &str,
    actor_modified: &str,
    r: &CreateMailbox,
    hash: &str,
    digest: &str,
) -> Result<String, CreateFailure> {
    let contact = r.setup_contact.as_deref().ok_or(CreateFailure::Invalid)?;
    let account = r.username();
    let bytes = u64::from(r.quota_mib) * 1_048_576;
    // All variable text is encoded as SQL value bytes; numeric values are typed.
    // No FORCE/IGNORE/upsert: a SQL error disconnects and rolls the transaction
    // back. Conditional inserts and final row counts cannot commit a partial pair.
    Ok(format!("SET SESSION innodb_lock_wait_timeout=3; START TRANSACTION;\n\
SET @holder=NULL,@epoch=NULL,@rev=NULL,@mode=NULL; SELECT holder,epoch,revision,mode INTO @holder,@epoch,@rev,@mode FROM osmap_admin_writer WHERE id=1 FOR UPDATE;\n\
SET @d=NULL,@active=NULL,@mx=NULL,@cap=NULL,@maxquota=NULL,@quota=NULL,@aliascap=NULL; SELECT domain,active,backupmx,mailboxes,maxquota,quota,aliases INTO @d,@active,@mx,@cap,@maxquota,@quota,@aliascap FROM domain WHERE BINARY domain=BINARY {domain} FOR UPDATE;\n\
SET @actor=NULL,@system=NULL,@all=NULL,@grant=NULL; SELECT username,superadmin INTO @actor,@system FROM admin WHERE BINARY username=BINARY {actor} AND BINARY password=BINARY {actor_hash} AND BINARY CAST(modified AS CHAR)=BINARY {actor_modified} AND active=1 FOR UPDATE;\n\
SELECT domain INTO @all FROM domain_admins WHERE BINARY username=BINARY {actor} AND BINARY domain=BINARY 'ALL' AND active=1 FOR UPDATE;\n\
SELECT domain INTO @grant FROM domain_admins WHERE BINARY username=BINARY {actor} AND BINARY domain=BINARY {domain} AND active=1 FOR UPDATE;\n\
SET @count=(SELECT COUNT(*) FROM mailbox WHERE BINARY domain=BINARY {domain}),@aliases=(SELECT COUNT(*) FROM alias WHERE BINARY domain=BINARY {domain}),@used=(SELECT COALESCE(SUM(quota),0) FROM mailbox WHERE BINARY domain=BINARY {domain});\n\
SET @reason=CASE WHEN @holder IS NULL OR BINARY @holder<>BINARY {holder} OR @epoch<>{epoch} OR @mode<>'lab_writer' THEN 'fence' WHEN @rev IS NULL OR @rev<>{revision} THEN 'stale' WHEN @actor IS NULL OR @system IS NULL OR NOT ((@system=1 AND @all IS NOT NULL) OR (@system=0 AND @all IS NULL AND @grant IS NOT NULL)) OR @d IS NULL OR @active IS NULL OR @mx IS NULL OR @active<>1 OR @mx<>0 THEN 'denied' WHEN @cap IS NULL OR @maxquota IS NULL OR @quota IS NULL OR @aliascap IS NULL OR @cap<0 OR @maxquota<0 OR @quota<0 OR @aliascap<0 OR EXISTS(SELECT 1 FROM mailbox WHERE BINARY domain=BINARY {domain} AND (quota IS NULL OR quota<0)) OR @count>=100 OR (@cap>0 AND @count>=@cap) OR (@aliascap>0 AND @aliases>=@aliascap) OR (@maxquota>0 AND {bytes}>@maxquota*{quota_unit}) OR (@quota>0 AND @used+{bytes}>@quota*{quota_unit}) THEN 'limit' WHEN EXISTS(SELECT 1 FROM mailbox WHERE username={account}) OR EXISTS(SELECT 1 FROM alias WHERE address={account}) OR EXISTS(SELECT 1 FROM osmap_admin_operations WHERE request_id={request} OR username={account}) THEN 'conflict' ELSE 'committed' END;\n\
INSERT INTO mailbox (username,password,name,maildir,quota,local_part,domain,created,modified,active,smtp_active) SELECT {account},{hash},{name},{maildir},{bytes},{local},{domain},UTC_TIMESTAMP(),UTC_TIMESTAMP(),0,0 WHERE @reason='committed'; SET @m=ROW_COUNT();\n\
INSERT INTO alias (address,goto,domain,created,modified,active) SELECT {account},{account},{domain},UTC_TIMESTAMP(),UTC_TIMESTAMP(),1 WHERE @reason='committed' AND @m=1; SET @a=ROW_COUNT();\n\
INSERT INTO osmap_admin_operations (request_id,actor,digest,credential_digest,username,domain,quota,revision,created,kind) SELECT {request},{actor},{digest},SHA2({hash},256),{account},{domain},{bytes},@rev+1,UTC_TIMESTAMP(),'mailbox.create' WHERE @reason='committed' AND @m=1 AND @a=1; SET @o=ROW_COUNT();\n\
INSERT INTO osmap_initial_accounts (username,request_id,recovery_email,revision,writer_holder,writer_epoch,created) SELECT {account},{request},{contact},1,{holder},{epoch},UTC_TIMESTAMP() WHERE @reason='committed' AND @m=1 AND @a=1 AND @o=1; SET @i=ROW_COUNT();\n\
UPDATE osmap_admin_writer SET revision=revision+1 WHERE id=1 AND @reason='committed' AND @m=1 AND @a=1 AND @o=1 AND @i=1; SET @w=ROW_COUNT();\n\
SET @finish=IF(@reason='committed' AND @m=1 AND @a=1 AND @o=1 AND @w=1 AND @i=1,'COMMIT','ROLLBACK'); PREPARE osmap_finish FROM @finish; EXECUTE osmap_finish; SELECT IF(@finish='COMMIT','committed',IF(@reason='committed','conflict',@reason));\n\
SELECT HEX(actor),digest,HEX(username),quota FROM osmap_admin_operations WHERE request_id={request} AND @finish='COMMIT';\n",
        domain=sql(&r.domain),actor=sql(actor),actor_hash=sql(actor_hash),actor_modified=sql(actor_modified),holder=sql(&w.holder),epoch=w.epoch,
        revision=r.revision,quota_unit=w.domain_quota_unit_bytes,account=sql(&account),request=sql(&r.request_id),hash=sql(hash),
        name=sql(&r.display_name),maildir=sql(&format!("{}/{}/",r.domain,r.local_part.to_ascii_lowercase())),
        local=sql(&r.local_part.to_ascii_lowercase()),digest=sql(digest),contact=sql(contact)))
}

#[cfg(test)]
mod initial_setup_tests {
    use super::*;

    fn request() -> CreateMailbox {
        CreateMailbox {
            domain: "example.test".into(),
            local_part: "new-owner".into(),
            display_name: "New owner".into(),
            password: String::new(),
            confirmation: String::new(),
            totp: "123456".into(),
            csrf: "a".repeat(64),
            request_id: "b".repeat(64),
            quota_mib: 20,
            revision: 1,
            setup_contact: Some("owner@independent.test".into()),
        }
    }

    #[test]
    fn pending_owner_setup_requires_external_contact_and_no_admin_chosen_password() {
        let mut value = request();
        assert!(value.valid());
        for contact in [
            "new-owner@example.test",
            "another@EXAMPLE.TEST",
            "invalid-contact",
            "owner@independent.test\r\nInjected: value",
        ] {
            value.setup_contact = Some(contact.into());
            assert!(!value.valid());
        }
        value = request();
        value.password = "administrator-chosen-secret".into();
        value.confirmation = value.password.clone();
        assert!(!value.valid());
    }

    #[test]
    fn pending_transaction_disables_both_native_authentication_flags() {
        let writer = WriterConfig {
            profile: "/private/writer.cnf".into(),
            holder: "a".repeat(32),
            epoch: 1,
            domains: vec!["example.test".into()],
            administrators: vec!["operator@example.test".into()],
            domain_quota_unit_bytes: 1_024_000,
            _onboarding: None,
        };
        let mut value = request();
        let generated = transaction(
            &writer,
            "operator@example.test",
            "synthetic-password-hash",
            "2026-11-18 00:00:00",
            &value,
            "synthetic-new-hash",
            &"c".repeat(64),
        );
        let generated = generated.ok().unwrap();
        assert!(generated.contains("UTC_TIMESTAMP(),UTC_TIMESTAMP(),0,0 WHERE @reason='committed'"));
        assert!(
            !generated.contains("UTC_TIMESTAMP(),UTC_TIMESTAMP(),1,1 WHERE @reason='committed'")
        );
        assert!(!generated.contains("owner@independent.test"));
        assert!(
            generated.contains("INSERT INTO osmap_initial_accounts")
                && generated.matches(" AND @i=1").count() == 2
        );
        value.setup_contact = None;
        value.password = "public-legacy-mailbox-passphrase".into();
        value.confirmation = value.password.clone();
        let legacy = transaction(
            &writer,
            "operator@example.test",
            "synthetic-password-hash",
            "2026-11-18 00:00:00",
            &value,
            "synthetic-new-hash",
            &"c".repeat(64),
        );
        assert!(!value.valid());
        assert!(matches!(legacy, Err(CreateFailure::Invalid)));
    }
}
