//! Dovecot-backed Documents byte storage. A document is one MIME message in
//! the account's own Maildir, subject to the same native quota as delivery.
//! The browser reaches this backend only through its authenticated helper.
use std::path::{Path, PathBuf};
use std::time::Duration;

use serde::Deserialize;

use crate::auth::CommandExecutor;
use crate::documents::{Backend, Error, Location, MailStorageReport, QuotaStatus, MAX_FILE_BYTES};

pub const ACTIVE_MAILBOX: &str = "OSMAP.Documents";
pub const BIN_MAILBOX: &str = "OSMAP.DocumentsBin";

/// Reserved mailbox names are excluded from ordinary mail routes and folder
/// metadata, including children under either fixed document mailbox.
pub fn reserved_documents_mailbox(name: &str) -> bool {
    [ACTIVE_MAILBOX, BIN_MAILBOX].iter().any(|reserved| {
        name.eq_ignore_ascii_case(reserved)
            || name.len() > reserved.len()
                && name
                    .get(..reserved.len())
                    .is_some_and(|prefix| prefix.eq_ignore_ascii_case(reserved))
                && matches!(name.as_bytes()[reserved.len()], b'.' | b'/')
    })
}
const COMMAND_TIMEOUT: Duration = Duration::from_secs(5);
const QUOTA_OUTPUT_MAX: usize = 4096;
const CONFIG_OUTPUT_MAX: usize = 32 * 1024;
const INDEX_OUTPUT_MAX: usize = 128 * 1024;
const FETCH_OUTPUT_MAX: usize = 15 * 1024 * 1024;

// Count accepted 86,016 bytes against 65,536 in the retained native race.
// Keep its configuration-only path closed. Filesystem authority additionally
// requires the trusted userdb mapping and an actual read-only kernel probe.
const QUALIFIED_CONCURRENT_QUOTA_DRIVERS: &[&str] = &[];
// Native OpenBSD proof covers ordinary IMAP APPEND, LMTP and simultaneous
// native saves against one kernel hard quota. Readiness still requires every
// current mapping, ownership, mount and hard-limit check below to succeed.
const FILESYSTEM_QUOTA_QUALIFIED: bool = true;
const QUOTA_WORKER: &str = "/usr/local/libexec/osmap/storage-quota";

#[derive(Debug, Clone)]
pub struct DoveadmDocumentsBackend<E> {
    executor: E,
    doveadm: PathBuf,
    doveconf: PathBuf,
    userdb_socket: Option<PathBuf>,
}

impl<E: CommandExecutor> DoveadmDocumentsBackend<E> {
    pub fn new(executor: E, doveadm: impl Into<PathBuf>, doveconf: impl Into<PathBuf>) -> Self {
        Self {
            executor,
            doveadm: doveadm.into(),
            doveconf: doveconf.into(),
            userdb_socket: None,
        }
    }

    pub fn with_userdb_socket_path(mut self, path: Option<PathBuf>) -> Self {
        self.userdb_socket = path;
        self
    }

    fn base(&self) -> Vec<String> {
        let mut args = vec!["-o".into(), "stats_writer_socket_path=".into()];
        if let Some(path) = &self.userdb_socket {
            args.extend(["-o".into(), format!("auth_socket_path={}", path.display())]);
        }
        args
    }

    fn run(
        &self,
        program: &Path,
        args: &[String],
        input: &[u8],
        output_cap: usize,
    ) -> Result<crate::auth::CommandExecution, Error> {
        self.executor
            .run_with_stdin_bytes_timeout_and_output_limit(
                program.to_string_lossy().as_ref(),
                args,
                input,
                COMMAND_TIMEOUT,
                output_cap,
            )
            .map_err(|_| Error::Unavailable)
    }

    // `doveadm save -m` opens an existing mailbox; it does not create one.
    // Provision only the two account-private names owned by Documents, before
    // dispatching any document bytes or a move to the Bin.
    fn reserved_mailbox_openable(&self, account: &str, mailbox: &str) -> Result<bool, Error> {
        if !matches!(mailbox, ACTIVE_MAILBOX | BIN_MAILBOX) {
            return Err(Error::Invalid);
        }
        let mut args = self.base();
        args.extend([
            "mailbox".into(),
            "status".into(),
            "-u".into(),
            account.into(),
            "guid".into(),
            mailbox.into(),
        ]);
        let response = self
            .run(&self.doveadm, &args, b"", QUOTA_OUTPUT_MAX)
            .map_err(|_| Error::PreDispatchUnavailable)?;
        if response.status_code == 68 && response.stdout.is_empty() {
            // Actual Dovecot 2.3.21.1 returns 68 with no stdout for an absent
            // reserved Maildir. Other failures do not authorize a create.
            return Ok(false);
        }
        if response.status_code != 0 {
            return Err(Error::PreDispatchUnavailable);
        }
        let prefix = format!("{mailbox} guid=");
        let guid = response
            .stdout
            .strip_prefix(&prefix)
            .and_then(|value| value.strip_suffix('\n'))
            .ok_or(Error::PreDispatchUnavailable)?;
        if guid.len() != 32 || !guid.bytes().all(|byte| byte.is_ascii_hexdigit()) {
            return Err(Error::PreDispatchUnavailable);
        }
        Ok(true)
    }

    fn ensure_reserved_mailbox(&self, account: &str, mailbox: &str) -> Result<(), Error> {
        if self.reserved_mailbox_openable(account, mailbox)? {
            return Ok(());
        }
        let mut args = self.base();
        args.extend([
            "mailbox".into(),
            "create".into(),
            "-u".into(),
            account.into(),
            mailbox.into(),
        ]);
        // A timeout or nonzero exit can have created a partial mailbox. Only
        // a successful exact GUID status proves it is openable for Save/move.
        let _ = self.run(&self.doveadm, &args, b"", QUOTA_OUTPUT_MAX);
        if self.reserved_mailbox_openable(account, mailbox)? {
            Ok(())
        } else {
            Err(Error::PreDispatchUnavailable)
        }
    }

    fn find(&self, account: &str, id: &str, mailbox: &str) -> Result<Option<Location>, Error> {
        let mut args = self.base();
        args.extend([
            "-f".into(),
            "json".into(),
            "fetch".into(),
            "-u".into(),
            account.into(),
            "uid mailbox mailbox-guid guid hdr.x-osmap-document-id".into(),
            "mailbox".into(),
            mailbox.into(),
            "all".into(),
        ]);
        let response = self.run(&self.doveadm, &args, b"", INDEX_OUTPUT_MAX)?;
        if response.status_code != 0 || response.stdout.len() > INDEX_OUTPUT_MAX {
            return Err(Error::Unavailable);
        }
        let rows: Vec<IndexRow> =
            serde_json::from_str(&response.stdout).map_err(|_| Error::Unavailable)?;
        if rows.len() > 101 {
            return Err(Error::Unavailable);
        }
        let mut found = None;
        for row in rows {
            if row.mailbox != mailbox {
                return Err(Error::Unavailable);
            }
            if row.document_id.as_deref() != Some(id) {
                continue;
            }
            if found.is_some() {
                return Err(Error::Unavailable);
            }
            let uid = row
                .uid
                .parse::<u32>()
                .ok()
                .filter(|v| *v > 0)
                .ok_or(Error::Unavailable)?;
            if row.uid != uid.to_string() || row.mailbox_guid.is_empty() || row.guid.is_empty() {
                return Err(Error::Unavailable);
            }
            found = Some(Location {
                mailbox: row.mailbox,
                uid,
                mailbox_guid: row.mailbox_guid,
                message_guid: row.guid,
            });
        }
        Ok(found)
    }

    fn pre_dispatch_find(
        &self,
        account: &str,
        id: &str,
        mailbox: &str,
    ) -> Result<Option<Location>, Error> {
        // The caller has not dispatched any document bytes or mutation yet.
        // A failed lookup here must not strand a durable pending operation.
        self.find(account, id, mailbox)
            .map_err(|_| Error::PreDispatchUnavailable)
    }

    fn fetch_exact(&self, account: &str, id: &str, location: &Location) -> Result<Vec<u8>, Error> {
        let mut args = self.base();
        args.extend([
            "-f".into(),
            "json".into(),
            "fetch".into(),
            "-u".into(),
            account.into(),
            "uid mailbox mailbox-guid guid hdr body".into(),
            "mailbox".into(),
            location.mailbox.clone(),
            "mailbox-guid".into(),
            location.mailbox_guid.clone(),
            "uid".into(),
            location.uid.to_string(),
            "guid".into(),
            location.message_guid.clone(),
        ]);
        let response = self.run(&self.doveadm, &args, b"", FETCH_OUTPUT_MAX)?;
        if response.status_code != 0 || response.stdout.len() > FETCH_OUTPUT_MAX {
            return Err(Error::Unavailable);
        }
        let mut rows: Vec<BodyRow> =
            serde_json::from_str(&response.stdout).map_err(|_| Error::Unavailable)?;
        if rows.len() != 1 {
            return Err(Error::NotFound);
        }
        let row = rows.pop().ok_or(Error::Unavailable)?;
        if row.uid != location.uid.to_string()
            || row.mailbox != location.mailbox
            || row.mailbox_guid != location.mailbox_guid
            || row.guid != location.message_guid
            || header(&row.hdr, "x-osmap-document-id") != Some(id)
            || header(&row.hdr, "content-type") != Some("application/octet-stream")
            || header(&row.hdr, "content-transfer-encoding") != Some("base64")
        {
            return Err(Error::Unavailable);
        }
        let decoded = crate::attachment::decode_base64_bytes(&row.body, MAX_FILE_BYTES)
            .map_err(|_| Error::Unavailable)?;
        if decoded.is_empty() {
            return Err(Error::Unavailable);
        }
        // Reject noncanonical transfer encodings and hidden trailing payload.
        let source: String = row
            .body
            .chars()
            .filter(|c| !c.is_ascii_whitespace())
            .collect();
        let canonical: String = crate::send::base64_encode_wrapped(&decoded)
            .chars()
            .filter(|c| !c.is_ascii_whitespace())
            .collect();
        if source != canonical {
            return Err(Error::Unavailable);
        }
        Ok(decoded)
    }

    fn move_exact(
        &self,
        account: &str,
        id: &str,
        location: &Location,
        destination: &str,
    ) -> Result<Location, Error> {
        if !matches!(location.mailbox.as_str(), ACTIVE_MAILBOX | BIN_MAILBOX)
            || !matches!(destination, ACTIVE_MAILBOX | BIN_MAILBOX)
            || destination == location.mailbox
        {
            return Err(Error::Invalid);
        }
        if !self.quota_ready(account).unwrap_or(false) {
            return Err(Error::PreDispatchUnavailable);
        }
        let current = self
            .pre_dispatch_find(account, id, &location.mailbox)?
            .ok_or(Error::NotFound)?;
        if current != *location || self.pre_dispatch_find(account, id, destination)?.is_some() {
            return Err(Error::Stale);
        }
        self.ensure_reserved_mailbox(account, destination)?;
        let mut args = self.base();
        args.extend([
            "move".into(),
            "-u".into(),
            account.into(),
            destination.into(),
            "mailbox".into(),
            location.mailbox.clone(),
            "mailbox-guid".into(),
            location.mailbox_guid.clone(),
            "uid".into(),
            location.uid.to_string(),
            "guid".into(),
            location.message_guid.clone(),
        ]);
        let response = self.run(&self.doveadm, &args, b"", QUOTA_OUTPUT_MAX)?;
        if response.status_code != 0 {
            // The child exited, and exact source/destination inspection must
            // both succeed before a no-write result can clear pending state.
            if self
                .find(account, id, &location.mailbox)
                .ok()
                .flatten()
                .as_ref()
                == Some(location)
                && matches!(self.find(account, id, destination), Ok(None))
            {
                return Err(Error::ConfirmedNoWrite);
            }
            return Err(Error::Unconfirmed);
        }
        if self.find(account, id, &location.mailbox)?.is_some() {
            return Err(Error::Unconfirmed);
        }
        self.find(account, id, destination)?
            .ok_or(Error::Unconfirmed)
    }
}

impl<E: CommandExecutor> Backend for DoveadmDocumentsBackend<E> {
    fn storage_report(&self, account: &str) -> Result<MailStorageReport, Error> {
        let canonical =
            crate::identity::CanonicalUsername::parse(account).map_err(|_| Error::Invalid)?;
        if canonical.as_str() != account {
            return Err(Error::Invalid);
        }
        let mut args = self.base();
        args.extend([
            "-o".into(),
            "maildir_stat_dirs=yes".into(),
            "-f".into(),
            "json".into(),
            "mailbox".into(),
            "status".into(),
            "-u".into(),
            account.into(),
            "vsize".into(),
            "*".into(),
        ]);
        let usage = self.run(&self.doveadm, &args, b"", INDEX_OUTPUT_MAX)?;
        if usage.status_code != 0 {
            return Err(Error::Unavailable);
        }
        let message_bytes = parse_message_bytes(&usage.stdout)?;
        let mut args = self.base();
        args.extend(["-f".into(), "json".into(), "user".into(), account.into()]);
        let user = self.run(&self.doveadm, &args, b"", QUOTA_OUTPUT_MAX)?;
        if user.status_code != 0 {
            return Err(Error::Unavailable);
        }
        Ok(MailStorageReport {
            account: account.into(),
            message_bytes,
            configured_limit_bytes: parse_configured_limit(&user.stdout)?,
        })
    }

    fn quota_status(&self, account: &str) -> Result<Option<QuotaStatus>, Error> {
        if crate::identity::CanonicalUsername::parse(account).is_err() {
            return Err(Error::Invalid);
        }
        // Parse the current effective Dovecot configuration on every write.
        // Configuration is necessary but does not prove concurrent enforcement.
        // Only a qualified native driver may attest shared write authority.
        let config = self.run(&self.doveconf, &["-n".into()], b"", CONFIG_OUTPUT_MAX)?;
        if config.status_code != 0 {
            return Ok(None);
        }
        if FILESYSTEM_QUOTA_QUALIFIED && filesystem_config_ready(&config.stdout) {
            let mut args = self.base();
            args.extend(["-f".into(), "json".into(), "user".into(), account.into()]);
            let user = self.run(&self.doveadm, &args, b"", QUOTA_OUTPUT_MAX)?;
            let authority = (user.status_code == 0)
                .then(|| filesystem_authority(&user.stdout))
                .flatten();
            let Some(authority) = authority else {
                return Ok(None);
            };
            let measured = self.run(
                Path::new(QUOTA_WORKER),
                &authority.worker_args(),
                b"",
                QUOTA_OUTPUT_MAX,
            )?;
            if measured.status_code != 0 {
                return Ok(None);
            }
            let kernel: QuotaStatus =
                serde_json::from_str(&measured.stdout).map_err(|_| Error::Unavailable)?;
            if kernel.limit_bytes != authority.limit_bytes || kernel.limit_bytes == 0 {
                return Ok(None);
            }
            return Ok(Some(kernel));
        }
        if !quota_config_ready(&config.stdout) {
            return Ok(None);
        }
        let mut args = self.base();
        args.extend(["quota".into(), "get".into(), "-u".into(), account.into()]);
        let quota = self.run(&self.doveadm, &args, b"", QUOTA_OUTPUT_MAX)?;
        Ok((quota.status_code == 0)
            .then(|| parse_quota_status(&quota.stdout))
            .flatten())
    }

    fn append(
        &self,
        account: &str,
        id: &str,
        _name: &str,
        _media_type: &str,
        body: &[u8],
    ) -> Result<Location, Error> {
        if !valid_id(id) || body.is_empty() || body.len() > MAX_FILE_BYTES {
            return Err(Error::Invalid);
        }
        if !self.quota_ready(account).unwrap_or(false) {
            return Err(Error::PreDispatchUnavailable);
        }
        if self
            .pre_dispatch_find(account, id, ACTIVE_MAILBOX)?
            .is_some()
        {
            return Err(Error::Stale);
        }
        self.ensure_reserved_mailbox(account, ACTIVE_MAILBOX)?;
        let encoded = crate::send::base64_encode_wrapped(body);
        let message = format!("Message-ID: <osmap-document-{id}@osmap.invalid>\r\nX-OSMAP-Document-ID: {id}\r\nMIME-Version: 1.0\r\nContent-Type: application/octet-stream\r\nContent-Transfer-Encoding: base64\r\n\r\n{encoded}\r\n");
        let mut args = self.base();
        args.extend([
            "save".into(),
            "-u".into(),
            account.into(),
            "-m".into(),
            ACTIVE_MAILBOX.into(),
        ]);
        let response = self.run(&self.doveadm, &args, message.as_bytes(), QUOTA_OUTPUT_MAX);
        // A timed-out/unknown dispatch is never retried or called no-write.
        match response {
            Ok(ref done) if done.status_code == 0 => {}
            Ok(_) if matches!(self.find(account, id, ACTIVE_MAILBOX), Ok(None)) => {
                return Err(Error::ConfirmedNoWrite);
            }
            _ => return Err(Error::Unconfirmed),
        }
        self.find(account, id, ACTIVE_MAILBOX)?
            .ok_or(Error::Unconfirmed)
    }

    fn read(&self, account: &str, id: &str, location: &Location) -> Result<Vec<u8>, Error> {
        if !valid_id(id)
            || !matches!(location.mailbox.as_str(), ACTIVE_MAILBOX | BIN_MAILBOX)
            || crate::identity::CanonicalUsername::parse(account).is_err()
        {
            return Err(Error::Invalid);
        }
        self.fetch_exact(account, id, location)
    }

    fn move_to_bin(&self, account: &str, id: &str, location: &Location) -> Result<Location, Error> {
        self.move_exact(account, id, location, BIN_MAILBOX)
    }

    fn restore(&self, account: &str, id: &str, location: &Location) -> Result<Location, Error> {
        self.move_exact(account, id, location, ACTIVE_MAILBOX)
    }

    fn expunge(&self, account: &str, id: &str, location: &Location) -> Result<(), Error> {
        if !valid_id(id) || location.mailbox != BIN_MAILBOX {
            return Err(Error::Invalid);
        }
        let current = self
            .pre_dispatch_find(account, id, BIN_MAILBOX)?
            .ok_or(Error::Stale)?;
        if current != *location {
            return Err(Error::Stale);
        }
        let mut args = self.base();
        args.extend([
            "expunge".into(),
            "-u".into(),
            account.into(),
            "mailbox".into(),
            BIN_MAILBOX.into(),
            "mailbox-guid".into(),
            location.mailbox_guid.clone(),
            "uid".into(),
            location.uid.to_string(),
            "guid".into(),
            location.message_guid.clone(),
        ]);
        let response = self.run(&self.doveadm, &args, b"", QUOTA_OUTPUT_MAX);
        match response {
            Ok(ref done) if done.status_code == 0 => {}
            Ok(_)
                if self.find(account, id, BIN_MAILBOX).ok().flatten().as_ref()
                    == Some(location) =>
            {
                return Err(Error::ConfirmedNoWrite);
            }
            _ => return Err(Error::Unconfirmed),
        }
        if self.find(account, id, BIN_MAILBOX)?.is_some() {
            return Err(Error::Unconfirmed);
        }
        Ok(())
    }

    fn inspect(&self, account: &str, id: &str) -> Result<Vec<Location>, Error> {
        if !valid_id(id) || crate::identity::CanonicalUsername::parse(account).is_err() {
            return Err(Error::Invalid);
        }
        let mut found = Vec::new();
        for mailbox in [ACTIVE_MAILBOX, BIN_MAILBOX] {
            if let Some(location) = self.find(account, id, mailbox)? {
                found.push(location);
            }
        }
        Ok(found)
    }
}

fn decimal_bytes(value: &str) -> Result<u64, Error> {
    if value.is_empty() || value.len() > 20 || !value.bytes().all(|byte| byte.is_ascii_digit()) {
        return Err(Error::Unavailable);
    }
    value.parse().map_err(|_| Error::Unavailable)
}

fn parse_message_bytes(output: &str) -> Result<u64, Error> {
    #[derive(Deserialize)]
    #[serde(untagged)]
    enum Counter {
        Number(u64),
        Decimal(String),
    }
    #[derive(Deserialize)]
    #[serde(deny_unknown_fields)]
    struct Row {
        mailbox: String,
        vsize: Counter,
    }
    if output.len() > INDEX_OUTPUT_MAX {
        return Err(Error::Unavailable);
    }
    let rows: Vec<Row> = serde_json::from_str(output).map_err(|_| Error::Unavailable)?;
    if rows.is_empty() || rows.len() > 1024 {
        return Err(Error::Unavailable);
    }
    let mut names = std::collections::BTreeSet::new();
    let mut total = 0u64;
    for row in rows {
        if row.mailbox.is_empty()
            || row.mailbox.len() > 1024
            || row.mailbox.chars().any(char::is_control)
        {
            return Err(Error::Unavailable);
        }
        let name = if row.mailbox.eq_ignore_ascii_case("INBOX") {
            "INBOX"
        } else {
            &row.mailbox
        };
        if !names.insert(name.to_owned()) {
            return Err(Error::Unavailable);
        }
        let bytes = match row.vsize {
            Counter::Number(bytes) => bytes,
            Counter::Decimal(value) => decimal_bytes(&value)?,
        };
        total = total.checked_add(bytes).ok_or(Error::Unavailable)?;
    }
    Ok(total)
}

fn parse_configured_limit(output: &str) -> Result<Option<u64>, Error> {
    #[derive(Deserialize)]
    #[serde(deny_unknown_fields)]
    struct Field {
        field: String,
        value: String,
    }
    if output.len() > QUOTA_OUTPUT_MAX {
        return Err(Error::Unavailable);
    }
    let rows: Vec<Field> = serde_json::from_str(output).map_err(|_| Error::Unavailable)?;
    if rows.is_empty() || rows.len() > 32 {
        return Err(Error::Unavailable);
    }
    let mut fields = std::collections::BTreeMap::new();
    for row in rows {
        if row.field.is_empty()
            || row.field.len() > 128
            || row.field.chars().any(char::is_control)
            || row.value.len() > 1024
            || row.value.chars().any(char::is_control)
            || fields.insert(row.field, row.value).is_some()
        {
            return Err(Error::Unavailable);
        }
    }
    for key in ["uid", "gid", "home", "mail"] {
        if fields.get(key).is_none_or(String::is_empty) {
            return Err(Error::Unavailable);
        }
    }
    for key in ["uid", "gid"] {
        let value = decimal_bytes(&fields[key])?;
        if value == 0 || value > i32::MAX as u64 {
            return Err(Error::Unavailable);
        }
    }
    fields
        .get("osmap_configured_quota")
        .map(|value| decimal_bytes(value))
        .transpose()
}

#[derive(Deserialize)]
struct IndexRow {
    uid: String,
    mailbox: String,
    #[serde(rename = "mailbox-guid")]
    mailbox_guid: String,
    guid: String,
    #[serde(rename = "hdr.x-osmap-document-id")]
    document_id: Option<String>,
}

#[derive(Deserialize)]
struct BodyRow {
    uid: String,
    mailbox: String,
    #[serde(rename = "mailbox-guid")]
    mailbox_guid: String,
    guid: String,
    hdr: String,
    body: String,
}

fn header<'a>(block: &'a str, name: &str) -> Option<&'a str> {
    let mut values = block.lines().filter_map(|line| {
        let (field, value) = line.trim_end_matches('\r').split_once(':')?;
        field.eq_ignore_ascii_case(name).then_some(value.trim())
    });
    let first = values.next()?;
    values.next().is_none().then_some(first)
}

fn valid_id(id: &str) -> bool {
    id.len() == 32
        && id
            .bytes()
            .all(|byte| matches!(byte, b'0'..=b'9' | b'a'..=b'f'))
}

fn parse_quota_status(output: &str) -> Option<QuotaStatus> {
    if output.len() > QUOTA_OUTPUT_MAX {
        return None;
    }
    // `doveadm quota get`: Quota name / Type / Value / Limit / %. The limit
    // must be a finite positive number; a dash or zero is not authority.
    let rows: Vec<&str> = output.lines().collect();
    if rows.len() < 2 || rows.len() > 8 {
        return None;
    }
    if !rows[0].contains("Quota name")
        || !rows[0].contains("Type")
        || !rows[0].contains("Value")
        || !rows[0].contains("Limit")
    {
        return None;
    }
    let mut values = Vec::new();
    for row in rows.into_iter().skip(1) {
        let fields: Vec<&str> = row.split_whitespace().collect();
        if let Some(index) = fields.iter().position(|value| *value == "STORAGE") {
            if fields.len() < index + 4 {
                return None;
            }
            let value = fields[index + 1].parse::<u64>().ok();
            let limit = fields[index + 2].parse::<u64>().ok();
            match (value, limit) {
                (Some(value), Some(limit)) if limit > 0 => values.push(QuotaStatus {
                    used_bytes: value.checked_mul(1024)?,
                    limit_bytes: limit.checked_mul(1024)?,
                }),
                _ => return None,
            }
        }
    }
    (values.len() == 1).then(|| values.remove(0))
}

#[cfg(test)]
pub(crate) fn native_quota_probe_flags(config: &str, quota: &str) -> (bool, bool) {
    (
        quota_config_ready(config),
        parse_quota_status(quota).is_some(),
    )
}

fn quota_config_ready(output: &str) -> bool {
    quota_configuration(output, false)
}

fn filesystem_config_ready(output: &str) -> bool {
    quota_configuration(output, true)
}

fn quota_configuration(output: &str, filesystem: bool) -> bool {
    if output.len() > CONFIG_OUTPUT_MAX {
        return false;
    }
    let mut global = "";
    let mut lmtp = None;
    let mut imap = None;
    let mut quota_backend = None;
    let mut quota_vsizes = false;
    let mut grace_zero = false;
    let mut stack = Vec::new();
    for line in output.lines() {
        let trimmed = line.trim();
        // The qualified filesystem profile uses one private Maildir location.
        // A second namespace can put payload outside the account filesystem.
        if filesystem && trimmed.starts_with("namespace ") && trimmed != "namespace inbox {" {
            return false;
        }
        if filesystem && trimmed.starts_with("location =") && trimmed != "location =" {
            return false;
        }
        // An existing unrelated rule (for example Trash:ignore) does not
        // weaken Documents. Reserved-path overrides can increase allowance
        // or exempt storage, so refuse them without editing operator policy.
        if trimmed.starts_with("quota_rule") {
            if let Some((_, rule)) = trimmed.split_once('=') {
                if let Some((mailbox, action)) = rule.trim().split_once(':') {
                    let mailbox = mailbox.trim();
                    if mailbox.eq_ignore_ascii_case("OSMAP")
                        || reserved_documents_mailbox(mailbox)
                        || (mailbox != "*" && (mailbox.contains('*') || mailbox.contains('?')))
                        || (mailbox == "*" && action.trim().starts_with("ignore"))
                    {
                        return false;
                    }
                }
            }
        }
        if let Some(name) = trimmed.strip_suffix('{') {
            stack.push(name.trim());
            if stack.len() > 8 {
                return false;
            }
            continue;
        }
        if trimmed == "}" {
            if stack.pop().is_none() {
                return false;
            }
            continue;
        }
        if let Some(value) = trimmed.strip_prefix("mail_plugins =") {
            let value = value.trim();
            match stack.as_slice() {
                ["protocol lmtp"] => lmtp = Some(value),
                ["protocol imap"] => imap = Some(value),
                [] => global = value,
                _ => {}
            }
        }
        if let Some(value) = trimmed.strip_prefix("quota =") {
            if matches!(stack.as_slice(), [] | ["plugin"]) {
                quota_backend = Some(value.trim());
            }
        }
        if let Some(value) = trimmed.strip_prefix("quota_vsizes =") {
            if matches!(stack.as_slice(), [] | ["plugin"]) {
                quota_vsizes = value.trim() == "yes";
            }
        }
        if let Some(value) = trimmed.strip_prefix("quota_grace =") {
            if matches!(stack.as_slice(), [] | ["plugin"]) {
                grace_zero = matches!(value.trim(), "0" | "0%" | "0 B");
            }
        }
    }
    if !stack.is_empty() {
        return false;
    }
    let has_quota = |plugins: &str| plugins.split_whitespace().any(|token| token == "quota");
    let effective_quota = |protocol: Option<&str>| match protocol {
        Some(value) => {
            has_quota(value)
                || (value.split_whitespace().any(|part| part == "$mail_plugins")
                    && has_quota(global))
        }
        None => has_quota(global),
    };
    // `doveadm save` is not an IMAP or LMTP command. Global plugin admission
    // is required for its own quota enforcement; protocol-only enables are
    // insufficient even when quota get returns a finite limit.
    let driver_ready = if filesystem {
        // Each admitted userdb row must supply its own exact fs root. A
        // process-global root cannot establish the account-to-mount mapping.
        quota_backend.is_none()
    } else {
        quota_backend.is_some_and(|backend| {
            let driver = backend.split(':').next().unwrap_or("");
            QUALIFIED_CONCURRENT_QUOTA_DRIVERS.contains(&driver)
                && !backend.is_empty()
                && (!backend.starts_with("count:") || quota_vsizes)
        })
    };
    driver_ready
        && grace_zero
        && has_quota(global)
        && effective_quota(lmtp)
        && effective_quota(imap)
}

#[derive(Debug, PartialEq, Eq)]
struct FilesystemAuthority {
    home: PathBuf,
    uid: u32,
    limit_bytes: u64,
    mount: PathBuf,
    index: PathBuf,
    control: PathBuf,
}

impl FilesystemAuthority {
    fn worker_args(&self) -> Vec<String> {
        vec![
            self.home.to_string_lossy().into_owned(),
            self.uid.to_string(),
            self.limit_bytes.to_string(),
            self.mount.to_string_lossy().into_owned(),
            self.index.to_string_lossy().into_owned(),
            self.control.to_string_lossy().into_owned(),
        ]
    }
}

/// Only the fixed, bounded native user lookup supplies these values. No HTTP
/// input selects a UID, filesystem or worker executable.
fn filesystem_authority(output: &str) -> Option<FilesystemAuthority> {
    #[derive(Deserialize)]
    #[serde(deny_unknown_fields)]
    struct Field {
        field: String,
        value: String,
    }
    if output.len() > QUOTA_OUTPUT_MAX {
        return None;
    }
    let rows: Vec<Field> = serde_json::from_str(output).ok()?;
    if rows.len() != 7 {
        return None;
    }
    let mut fields = std::collections::BTreeMap::new();
    for row in rows {
        if !matches!(
            row.field.as_str(),
            "uid" | "gid" | "home" | "mail" | "quota" | "quota_rule" | "osmap_quota_mount"
        ) || row.value.len() > 1024
            || row.value.chars().any(char::is_control)
            || fields.insert(row.field, row.value).is_some()
        {
            return None;
        }
    }
    let number = |key: &str| -> Option<u64> {
        let value = fields.get(key)?;
        let result = value.parse::<u64>().ok()?;
        (result > 0 && result.to_string() == *value).then_some(result)
    };
    let uid = u32::try_from(number("uid")?).ok()?;
    if uid > i32::MAX as u32 || number("gid")? > i32::MAX as u64 {
        return None;
    }
    let path = |key: &str| -> Option<PathBuf> {
        let path = PathBuf::from(fields.get(key)?);
        (path.is_absolute()
            && path
                .components()
                .all(|c| !matches!(c, std::path::Component::ParentDir))
            && !path.to_str()?.contains(':'))
        .then_some(path)
    };
    let home = path("home")?;
    let mount = path("osmap_quota_mount")?;
    if !home.starts_with(&mount) || mount == Path::new("/") {
        return None;
    }
    let quota = fields.get("quota")?;
    if quota != &format!("fs:User quota:user:mount={}", mount.display()) {
        return None;
    }
    let limit = fields.get("quota_rule")?.strip_prefix("*:bytes=")?;
    let limit_bytes = limit.parse::<u64>().ok()?;
    if limit_bytes == 0 || limit_bytes.to_string() != limit || limit_bytes % 512 != 0 {
        return None;
    }
    let parts: Vec<_> = fields
        .get("mail")?
        .strip_prefix("maildir:")?
        .split(':')
        .collect();
    if parts.len() != 3 {
        return None;
    }
    let mail = PathBuf::from(parts[0]);
    if mail != home && mail != home.join("Maildir") {
        return None;
    }
    let index = PathBuf::from(parts[1].strip_prefix("INDEX=")?);
    let control = PathBuf::from(parts[2].strip_prefix("CONTROL=")?);
    if !index.is_absolute() || !control.is_absolute() {
        return None;
    }
    Some(FilesystemAuthority {
        home,
        uid,
        limit_bytes,
        mount,
        index,
        control,
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::auth::{CommandExecution, CommandExecutionError, CommandExecutor};
    use std::collections::VecDeque;
    use std::sync::{Arc, Mutex};

    fn report_user(limit: Option<&str>) -> String {
        let mut rows = serde_json::json!([
            {"field":"uid","value":"2000"},
            {"field":"gid","value":"2000"},
            {"field":"home","value":"/mail/alice"},
            {"field":"mail","value":"maildir:/mail/alice"}
        ]);
        if let Some(value) = limit {
            rows.as_array_mut()
                .unwrap()
                .push(serde_json::json!({"field":"osmap_configured_quota","value":value}));
        }
        rows.to_string()
    }

    #[test]
    fn mail_storage_report_parses_all_message_bytes_without_quota_attestation() {
        assert_eq!(
            parse_message_bytes(r#"[{"mailbox":"INBOX","vsize":"0"}]"#),
            Ok(0)
        );
        assert_eq!(
            parse_message_bytes(
                r#"[{"mailbox":"INBOX","vsize":"00012"},{"mailbox":"Sent","vsize":7},{"mailbox":"OSMAP.Documents","vsize":"5"},{"mailbox":"OSMAP.DocumentsBin","vsize":"3"}]"#
            ),
            Ok(27)
        );
        assert_eq!(parse_configured_limit(&report_user(None)), Ok(None));
        assert_eq!(parse_configured_limit(&report_user(Some("0"))), Ok(Some(0)));
        assert_eq!(
            parse_configured_limit(&report_user(Some("512000000"))),
            Ok(Some(512000000))
        );
        let mut fields: serde_json::Value = serde_json::from_str(&report_user(None)).unwrap();
        fields
            .as_array_mut()
            .unwrap()
            .push(serde_json::json!({"field":"quota_rule","value":"*:storage=102400000"}));
        assert_eq!(parse_configured_limit(&fields.to_string()), Ok(None));
    }

    #[test]
    fn mail_storage_report_refuses_incomplete_duplicate_malformed_and_overflow_facts() {
        for output in [
            "",
            "[]",
            "[",
            r#"[{"mailbox":"INBOX"}]"#,
            r#"[{"mailbox":"INBOX","vsize":0,"vsize":1}]"#,
            r#"[{"mailbox":"INBOX","vsize":0,"extra":1}]"#,
            r#"[{"mailbox":"INBOX","vsize":"-1"}]"#,
            r#"[{"mailbox":"INBOX","vsize":"+1"}]"#,
            r#"[{"mailbox":"INBOX","vsize":"1.0"}]"#,
            r#"[{"mailbox":"INBOX","vsize":"1e3"}]"#,
            r#"[{"mailbox":"INBOX","vsize":"18446744073709551616"}]"#,
            r#"[{"mailbox":"INBOX","vsize":"18446744073709551615"},{"mailbox":"Sent","vsize":1}]"#,
            r#"[{"mailbox":"INBOX","vsize":0},{"mailbox":"inbox","vsize":1}]"#,
            r#"[{"mailbox":"Sent","vsize":0},{"mailbox":"Sent","vsize":1}]"#,
            r#"[{"mailbox":"bad\nname","vsize":0}]"#,
        ] {
            assert_eq!(
                parse_message_bytes(output),
                Err(Error::Unavailable),
                "{output}"
            );
        }
        for value in ["", "-1", "+1", "1 KiB", "1e3", "18446744073709551616"] {
            assert_eq!(
                parse_configured_limit(&report_user(Some(value))),
                Err(Error::Unavailable)
            );
        }
        for duplicate in ["uid", "osmap_configured_quota"] {
            let mut fields: serde_json::Value =
                serde_json::from_str(&report_user(Some("1"))).unwrap();
            fields
                .as_array_mut()
                .unwrap()
                .push(serde_json::json!({"field":duplicate,"value":"1"}));
            assert_eq!(
                parse_configured_limit(&fields.to_string()),
                Err(Error::Unavailable)
            );
        }
        assert_eq!(parse_configured_limit("[]"), Err(Error::Unavailable));
        assert_eq!(
            parse_message_bytes(&" ".repeat(INDEX_OUTPUT_MAX + 1)),
            Err(Error::Unavailable)
        );
        assert_eq!(
            parse_configured_limit(&" ".repeat(QUOTA_OUTPUT_MAX + 1)),
            Err(Error::Unavailable)
        );
    }

    type StorageReportSteps = Arc<Mutex<VecDeque<(String, usize, i32, String)>>>;
    #[derive(Clone)]
    struct StorageReportScript(StorageReportSteps);
    impl CommandExecutor for StorageReportScript {
        fn run_with_stdin_bytes(
            &self,
            _: &str,
            _: &[String],
            _: &[u8],
        ) -> Result<CommandExecution, CommandExecutionError> {
            panic!("storage reporting requires bounded native execution")
        }
        fn run_with_stdin_bytes_timeout_and_output_limit(
            &self,
            program: &str,
            args: &[String],
            input: &[u8],
            timeout: Duration,
            cap: usize,
        ) -> Result<CommandExecution, CommandExecutionError> {
            let (expected, expected_cap, status_code, stdout) =
                self.0.lock().unwrap().pop_front().unwrap();
            assert_eq!(program, "/fixed/doveadm");
            assert_eq!(
                args,
                &expected.split(' ').map(str::to_owned).collect::<Vec<_>>()
            );
            assert!(input.is_empty() && timeout == COMMAND_TIMEOUT && cap == expected_cap);
            Ok(CommandExecution {
                status_code,
                stdout,
                stderr: String::new(),
            })
        }
    }

    #[test]
    fn mail_storage_report_native_queries_are_fixed_account_bound_and_read_only() {
        let usage = "-o stats_writer_socket_path= -o auth_socket_path=/fixed/userdb -o maildir_stat_dirs=yes -f json mailbox status -u alice@example.test vsize *";
        let user = "-o stats_writer_socket_path= -o auth_socket_path=/fixed/userdb -f json user alice@example.test";
        for limit in [None, Some("0"), Some("512000000")] {
            let script = StorageReportScript(Arc::new(Mutex::new(VecDeque::from([
                (
                    usage.into(),
                    INDEX_OUTPUT_MAX,
                    0,
                    r#"[{"mailbox":"INBOX","vsize":"0"},{"mailbox":"Sent","vsize":"123"}]"#.into(),
                ),
                (user.into(), QUOTA_OUTPUT_MAX, 0, report_user(limit)),
            ]))));
            let backend = DoveadmDocumentsBackend::new(
                script.clone(),
                "/fixed/doveadm",
                "/never-used/doveconf",
            )
            .with_userdb_socket_path(Some("/fixed/userdb".into()));
            assert_eq!(
                backend.storage_report("alice@example.test"),
                Ok(MailStorageReport {
                    account: "alice@example.test".into(),
                    message_bytes: 123,
                    configured_limit_bytes: limit.map(|value| value.parse().unwrap())
                })
            );
            assert!(script.0.lock().unwrap().is_empty());
            assert_eq!(
                backend.storage_report("not an account"),
                Err(Error::Invalid)
            );
        }
        let script = StorageReportScript(Arc::new(Mutex::new(VecDeque::from([(
            usage.into(),
            INDEX_OUTPUT_MAX,
            75,
            r#"[{"mailbox":"INBOX","vsize":"0"}]"#.into(),
        )]))));
        let backend =
            DoveadmDocumentsBackend::new(script.clone(), "/fixed/doveadm", "/never-used/doveconf")
                .with_userdb_socket_path(Some("/fixed/userdb".into()));
        assert_eq!(
            backend.storage_report("alice@example.test"),
            Err(Error::Unavailable)
        );
        assert!(script.0.lock().unwrap().is_empty());
    }

    type MailboxScriptSteps = Arc<Mutex<VecDeque<(&'static str, i32, &'static str)>>>;

    #[derive(Clone)]
    struct MailboxScript(MailboxScriptSteps);

    impl CommandExecutor for MailboxScript {
        fn run_with_stdin_bytes(
            &self,
            _: &str,
            _: &[String],
            _: &[u8],
        ) -> Result<CommandExecution, CommandExecutionError> {
            panic!("Documents mailbox provisioning must use bounded execution")
        }

        fn run_with_stdin_bytes_timeout_and_output_limit(
            &self,
            program: &str,
            args: &[String],
            input: &[u8],
            timeout: Duration,
            output_cap: usize,
        ) -> Result<CommandExecution, CommandExecutionError> {
            assert_eq!(program, "/fixed/doveadm");
            assert!(
                input.is_empty() && timeout == COMMAND_TIMEOUT && output_cap == QUOTA_OUTPUT_MAX
            );
            let (expected, status_code, stdout) = self.0.lock().unwrap().pop_front().unwrap();
            assert_eq!(args[2..].join(" "), expected);
            Ok(CommandExecution {
                status_code,
                stdout: stdout.into(),
                stderr: String::new(),
            })
        }
    }

    #[test]
    fn filesystem_authority_requires_exact_native_mapping_and_limit() {
        let rows = serde_json::json!([
            {"field":"uid","value":"2000"},
            {"field":"gid","value":"2000"},
            {"field":"home","value":"/var/vmail/example.test/alice"},
            {"field":"mail","value":"maildir:/var/vmail/example.test/alice:INDEX=/home/mail-index/alice:CONTROL=/home/mail-control/alice"},
            {"field":"quota","value":"fs:User quota:user:mount=/var/vmail/example.test/alice"},
            {"field":"quota_rule","value":"*:bytes=512000000"},
            {"field":"osmap_quota_mount","value":"/var/vmail/example.test/alice"}
        ]);
        let authority = filesystem_authority(&rows.to_string()).unwrap();
        assert_eq!(authority.uid, 2000);
        assert_eq!(authority.limit_bytes, 512000000);
        assert_eq!(authority.worker_args().len(), 6);
        assert_eq!(authority.worker_args()[3], "/var/vmail/example.test/alice");
        for (index, value) in [
            (0, "0"),
            (0, "02000"),
            (0, "2147483648"),
            (3, "maildir:/other:INDEX=/home/i:CONTROL=/home/c"),
            (4, "fs:User quota:group:mount=/var/vmail/example.test/alice"),
            (4, "fs:User quota:user:mount=/var/vmail/example.test/bob"),
            (5, "*:bytes=0"),
            (5, "*:bytes=513"),
            (5, "*:bytes=0512000000"),
            (6, "/var/vmail/example.test/alice/child"),
        ] {
            let mut bad = rows.clone();
            bad[index]["value"] = value.into();
            assert!(filesystem_authority(&bad.to_string()).is_none(), "{index}");
        }
        let mut extra = rows.clone();
        extra
            .as_array_mut()
            .unwrap()
            .push(serde_json::json!({"field":"namespace/other/location","value":"maildir:/other"}));
        assert!(filesystem_authority(&extra.to_string()).is_none());
        let mut unknown = rows.clone();
        unknown[6]["field"] = "unapproved".into();
        assert!(filesystem_authority(&unknown.to_string()).is_none());
        let mut duplicate = rows.clone();
        duplicate[6] = duplicate[0].clone();
        assert!(filesystem_authority(&duplicate.to_string()).is_none());
    }

    #[test]
    fn filesystem_configuration_requires_all_writers_and_one_private_location() {
        let config="mail_plugins = quota\nplugin {\n quota_grace = 0%\n}\nnamespace inbox {\n location =\n}\nprotocol lmtp {\n mail_plugins = quota sieve\n}\nprotocol imap {\n mail_plugins = quota\n}\n";
        assert!(filesystem_config_ready(config));
        assert!(!quota_config_ready(config));
        for bad in [
            config.replace("mail_plugins = quota sieve", "mail_plugins = sieve"),
            config.replace("quota_grace = 0%", "quota_grace = 10%"),
            config.replace("location =", "location = maildir:/other"),
            format!("{config}namespace shared {{\n}}\n"),
            format!("{config}plugin {{\n quota = fs:User quota:user\n}}\n"),
            format!("{config}plugin {{\n quota_rule2 = OSMAP.Documents:ignore\n}}\n"),
        ] {
            assert!(!filesystem_config_ready(&bad));
        }
    }

    #[test]
    fn first_reserved_mailbox_is_created_before_document_bytes() {
        let script = MailboxScript(Arc::new(Mutex::new(VecDeque::from([
            (
                "mailbox status -u alice@example.test guid OSMAP.Documents",
                68,
                "",
            ),
            (
                "mailbox create -u alice@example.test OSMAP.Documents",
                0,
                "",
            ),
            (
                "mailbox status -u alice@example.test guid OSMAP.Documents",
                0,
                "OSMAP.Documents guid=0123456789abcdef0123456789abcdef\n",
            ),
            (
                "mailbox status -u alice@example.test guid OSMAP.DocumentsBin",
                0,
                "OSMAP.DocumentsBin guid=0123456789abcdef0123456789abcdef\n",
            ),
        ]))));
        let backend =
            DoveadmDocumentsBackend::new(script.clone(), "/fixed/doveadm", "/fixed/doveconf");
        assert_eq!(
            backend.ensure_reserved_mailbox("alice@example.test", ACTIVE_MAILBOX),
            Ok(())
        );
        assert_eq!(
            backend.ensure_reserved_mailbox("alice@example.test", BIN_MAILBOX),
            Ok(())
        );
        assert!(script.0.lock().unwrap().is_empty());
    }

    #[test]
    fn unconfirmed_reserved_mailbox_create_refuses_before_save_or_move() {
        let script = MailboxScript(Arc::new(Mutex::new(VecDeque::from([
            (
                "mailbox status -u alice@example.test guid OSMAP.Documents",
                68,
                "",
            ),
            (
                "mailbox create -u alice@example.test OSMAP.Documents",
                75,
                "",
            ),
            (
                "mailbox status -u alice@example.test guid OSMAP.Documents",
                68,
                "",
            ),
        ]))));
        let backend =
            DoveadmDocumentsBackend::new(script.clone(), "/fixed/doveadm", "/fixed/doveconf");
        assert_eq!(
            backend.ensure_reserved_mailbox("alice@example.test", ACTIVE_MAILBOX),
            Err(Error::PreDispatchUnavailable)
        );
        assert_eq!(
            backend.ensure_reserved_mailbox("alice@example.test", "INBOX"),
            Err(Error::Invalid)
        );
        assert!(script.0.lock().unwrap().is_empty());
    }

    #[test]
    fn unknown_reserved_mailbox_status_does_not_create() {
        for (code, output) in [(75, ""), (68, "unexpected status output\n")] {
            let script = MailboxScript(Arc::new(Mutex::new(VecDeque::from([(
                "mailbox status -u alice@example.test guid OSMAP.Documents",
                code,
                output,
            )]))));
            let backend =
                DoveadmDocumentsBackend::new(script.clone(), "/fixed/doveadm", "/fixed/doveconf");
            assert_eq!(
                backend.ensure_reserved_mailbox("alice@example.test", ACTIVE_MAILBOX),
                Err(Error::PreDispatchUnavailable)
            );
            assert!(script.0.lock().unwrap().is_empty());
        }
    }

    #[test]
    fn reserved_mailbox_status_transport_failure_is_predispatch() {
        struct FailedList;
        impl CommandExecutor for FailedList {
            fn run_with_stdin_bytes(
                &self,
                _: &str,
                _: &[String],
                _: &[u8],
            ) -> Result<CommandExecution, CommandExecutionError> {
                panic!("bounded executor expected")
            }
            fn run_with_stdin_bytes_timeout_and_output_limit(
                &self,
                program: &str,
                args: &[String],
                input: &[u8],
                _: Duration,
                _: usize,
            ) -> Result<CommandExecution, CommandExecutionError> {
                assert_eq!(program, "/fixed/doveadm");
                assert_eq!(
                    args[2..].join(" "),
                    "mailbox status -u alice@example.test guid OSMAP.Documents"
                );
                assert!(input.is_empty());
                Err(CommandExecutionError {
                    reason: "synthetic list timeout".into(),
                })
            }
        }
        let backend = DoveadmDocumentsBackend::new(FailedList, "/fixed/doveadm", "/fixed/doveconf");
        assert_eq!(
            backend.ensure_reserved_mailbox("alice@example.test", ACTIVE_MAILBOX),
            Err(Error::PreDispatchUnavailable)
        );
    }

    #[test]
    fn failed_pre_dispatch_document_lookup_does_not_claim_a_possible_write() {
        struct FailedFetch;
        impl CommandExecutor for FailedFetch {
            fn run_with_stdin_bytes(
                &self,
                _: &str,
                _: &[String],
                _: &[u8],
            ) -> Result<CommandExecution, CommandExecutionError> {
                panic!("bounded executor expected")
            }
            fn run_with_stdin_bytes_timeout_and_output_limit(
                &self,
                program: &str,
                args: &[String],
                input: &[u8],
                _: Duration,
                _: usize,
            ) -> Result<CommandExecution, CommandExecutionError> {
                assert_eq!(program, "/fixed/doveadm");
                assert!(args.iter().any(|arg| arg == "fetch") && input.is_empty());
                Err(CommandExecutionError {
                    reason: "synthetic fetch timeout".into(),
                })
            }
        }
        let backend =
            DoveadmDocumentsBackend::new(FailedFetch, "/fixed/doveadm", "/fixed/doveconf");
        assert_eq!(
            backend.pre_dispatch_find("alice@example.test", &"a".repeat(32), ACTIVE_MAILBOX),
            Err(Error::PreDispatchUnavailable)
        );
    }

    #[test]
    fn quota_requires_finite_account_limit_and_both_protocol_plugins() {
        assert_eq!(parse_quota_status(""), None);
        assert_eq!(
            parse_quota_status("Quota name Type Value Limit %\nUser quota STORAGE 10 - 0\n"),
            None
        );
        assert_eq!(
            parse_quota_status("Quota name Type Value Limit %\nUser quota STORAGE 10 4096 0\n"),
            Some(QuotaStatus {
                used_bytes: 10 * 1024,
                limit_bytes: 4096 * 1024
            })
        );
        assert!(!quota_config_ready(
            "mail_plugins = \nquota = \nprotocol lmtp {\n mail_plugins = sieve\n}\n"
        ));
        assert!(!quota_config_ready("quota = count:User quota\nquota_vsizes = yes\nquota_grace = 0%\nprotocol lmtp {\n mail_plugins = sieve quota\n}\nprotocol imap {\n mail_plugins = quota\n}\n"));
        assert!(!quota_config_ready("quota = count:User quota\nquota_vsizes = yes\nquota_grace = 0%\nprotocol lmtp {\n mail_plugins = sieve quota\n}\nprotocol imap {\n mail_plugins = \n}\n"));
        assert!(!quota_config_ready(
            "mail_plugins = quota\nquota = count:User quota\nquota_grace = 0%\n"
        ));
        assert!(!quota_config_ready(
            "mail_plugins = quota\nquota = count:User quota\nquota_vsizes = yes\nquota_grace = 0%\n"
        ));
        assert!(!quota_config_ready("mail_plugins = quota\nquota = count:User quota\nquota_vsizes = yes\nquota_grace = 0%\nprotocol lmtp {\n mail_plugins = $mail_plugins sieve\n}\n"));
        assert!(!quota_config_ready("mail_plugins = quota\nquota = count:User quota\nquota_vsizes = yes\nquota_grace = 0%\nprotocol lmtp {\n mail_plugins = sieve\n}\n"));
        assert!(!quota_config_ready(
            "mail_plugins = quota\nquota = count:User quota\nquota_vsizes = yes\nquota_grace = 0%\nquota_rule = OSMAP.Documents:ignore\n"
        ));
        assert!(!quota_config_ready("mail_plugins = quota\nquota = count:User quota\nquota_vsizes = yes\nquota_grace = 0%\nquota_rule2 = OSMAP.DocumentsBin:ignore\n"));
        assert!(!quota_config_ready("mail_plugins = quota\nquota = count:User quota\nquota_vsizes = yes\nquota_grace = 0%\nquota_rule2 = OSMAP.Documents:storage=+100M\n"));
        assert!(!quota_config_ready(
            "mail_plugins = quota\nquota = count:User quota\nquota_vsizes = yes\nquota_grace = 0%\nquota_rule = Trash:ignore\n"
        ));
        assert!(!quota_config_ready("quota = count:User quota\nquota_vsizes = yes\nquota_grace = 0%\nprotocol lmtp {\n plugin {\n  mail_plugins = quota\n }\n mail_plugins = sieve\n}\nprotocol imap {\n mail_plugins = quota\n}\n"));
        assert!(!quota_config_ready(
            "mail_plugins = quota\nquota = count:User quota\nquota_vsizes = yes\nquota_grace = 10%\n"
        ));
    }

    #[test]
    fn unqualified_quota_drivers_do_not_grant_shared_concurrent_write_authority() {
        for driver in [
            "count", "dict", "dirsize", "fs", "imapc", "maildir", "unknown",
        ] {
            assert!(!quota_config_ready(&format!(
                "mail_plugins = quota\nquota = {driver}:User quota\nquota_vsizes = yes\nquota_grace = 0%\n"
            )));
        }
    }

    #[test]
    fn count_quota_refuses_append_bin_restore_before_any_native_mailbox_dispatch() {
        #[derive(Clone)]
        struct CountConfig(Arc<std::sync::atomic::AtomicUsize>);
        impl CommandExecutor for CountConfig {
            fn run_with_stdin_bytes(
                &self,
                _: &str,
                _: &[String],
                _: &[u8],
            ) -> Result<CommandExecution, CommandExecutionError> {
                panic!("bounded execution required");
            }
            fn run_with_stdin_bytes_timeout_and_output_limit(
                &self,
                program: &str,
                args: &[String],
                input: &[u8],
                timeout: Duration,
                output_cap: usize,
            ) -> Result<CommandExecution, CommandExecutionError> {
                assert_eq!(
                    program, "/fixed/doveconf",
                    "quota refusal must precede every doveadm lookup/create/save/move"
                );
                assert_eq!(args, ["-n"]);
                assert!(input.is_empty());
                assert_eq!(timeout, COMMAND_TIMEOUT);
                assert_eq!(output_cap, CONFIG_OUTPUT_MAX);
                self.0.fetch_add(1, std::sync::atomic::Ordering::SeqCst);
                Ok(CommandExecution { status_code: 0,
                    stdout: "mail_plugins = quota\nplugin {\n quota = count:User quota\n quota_rule = *:storage=64K\n quota_vsizes = yes\n quota_grace = 0%\n}\n".into(),
                    stderr: String::new() })
            }
        }
        let calls = Arc::new(std::sync::atomic::AtomicUsize::new(0));
        let backend = DoveadmDocumentsBackend::new(
            CountConfig(calls.clone()),
            "/fixed/doveadm",
            "/fixed/doveconf",
        );
        let account = "alice@example.test";
        let id = "a".repeat(32);
        assert_eq!(backend.quota_status(account), Ok(None));
        assert_eq!(
            backend.append(
                account,
                &id,
                "file.bin",
                "application/octet-stream",
                b"bytes"
            ),
            Err(Error::PreDispatchUnavailable)
        );
        let mut location = Location {
            mailbox: ACTIVE_MAILBOX.into(),
            uid: 1,
            mailbox_guid: "b".repeat(32),
            message_guid: "c".repeat(32),
        };
        assert_eq!(
            backend.move_to_bin(account, &id, &location),
            Err(Error::PreDispatchUnavailable)
        );
        location.mailbox = BIN_MAILBOX.into();
        assert_eq!(
            backend.restore(account, &id, &location),
            Err(Error::PreDispatchUnavailable)
        );
        assert_eq!(calls.load(std::sync::atomic::Ordering::SeqCst), 4);
        // Exercise the existing Store rollback with this real backend refusal,
        // so a refused upload cannot leave a durable pending document row.
        use std::os::unix::fs::DirBuilderExt;
        let root = std::env::temp_dir().join(format!(
            "osmap-documents-unqualified-{}-{}",
            std::process::id(),
            crate::draft::generate_draft_id().unwrap()
        ));
        std::fs::DirBuilder::new()
            .mode(0o700)
            .create(&root)
            .unwrap();
        let store = crate::documents::Store::new(root.clone(), backend);
        assert_eq!(
            store.upload(
                account,
                0,
                "file.bin",
                "application/octet-stream",
                b"bytes",
                100
            ),
            Err(Error::PreDispatchUnavailable)
        );
        let index = store.load(account).unwrap();
        assert!(index.documents.is_empty() && !index.has_unconfirmed_change());
        assert_eq!(calls.load(std::sync::atomic::Ordering::SeqCst), 5);
        std::fs::remove_dir_all(root).unwrap();
    }

    #[test]
    fn document_header_requires_one_exact_owner_bound_id() {
        let id = "a".repeat(32);
        let wire =
            format!("X-OSMAP-Document-ID: {id}\r\nContent-Type: application/octet-stream\r\n");
        assert_eq!(header(&wire, "x-osmap-document-id"), Some(id.as_str()));
        assert_eq!(header(&(wire.clone() + &wire), "x-osmap-document-id"), None);
        assert!(!valid_id("../documents"));
    }
}
