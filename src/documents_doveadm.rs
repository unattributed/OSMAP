//! Dovecot-backed Documents byte storage. A document is one MIME message in
//! the account's own Maildir, subject to the same native quota as delivery.
//! The browser reaches this backend only through its authenticated helper.
use std::path::{Path, PathBuf};
use std::time::Duration;

use serde::Deserialize;

use crate::auth::CommandExecutor;
use crate::documents::{Backend, Error, Location, QuotaStatus, MAX_FILE_BYTES};

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
            .find(account, id, &location.mailbox)?
            .ok_or(Error::NotFound)?;
        if current != *location || self.find(account, id, destination)?.is_some() {
            return Err(Error::Stale);
        }
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
    fn quota_status(&self, account: &str) -> Result<Option<QuotaStatus>, Error> {
        if crate::identity::CanonicalUsername::parse(account).is_err() {
            return Err(Error::Invalid);
        }
        // Parse the current effective Dovecot configuration on every write.
        // The native quota plugin, not this preflight, enforces concurrent saves.
        let config = self.run(&self.doveconf, &["-n".into()], b"", CONFIG_OUTPUT_MAX)?;
        if config.status_code != 0 || !quota_config_ready(&config.stdout) {
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
        if self.find(account, id, ACTIVE_MAILBOX)?.is_some() {
            return Err(Error::Stale);
        }
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
        let current = self.find(account, id, BIN_MAILBOX)?.ok_or(Error::Stale)?;
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
    quota_backend.is_some_and(|backend| {
        !backend.is_empty() && (!backend.starts_with("count:") || quota_vsizes)
    }) && grace_zero
        && has_quota(global)
        && effective_quota(lmtp)
        && effective_quota(imap)
}

#[cfg(test)]
mod tests {
    use super::*;

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
        assert!(quota_config_ready(
            "mail_plugins = quota\nquota = count:User quota\nquota_vsizes = yes\nquota_grace = 0%\n"
        ));
        assert!(quota_config_ready("mail_plugins = quota\nquota = count:User quota\nquota_vsizes = yes\nquota_grace = 0%\nprotocol lmtp {\n mail_plugins = $mail_plugins sieve\n}\n"));
        assert!(!quota_config_ready("mail_plugins = quota\nquota = count:User quota\nquota_vsizes = yes\nquota_grace = 0%\nprotocol lmtp {\n mail_plugins = sieve\n}\n"));
        assert!(!quota_config_ready(
            "mail_plugins = quota\nquota = count:User quota\nquota_vsizes = yes\nquota_grace = 0%\nquota_rule = OSMAP.Documents:ignore\n"
        ));
        assert!(!quota_config_ready("mail_plugins = quota\nquota = count:User quota\nquota_vsizes = yes\nquota_grace = 0%\nquota_rule2 = OSMAP.DocumentsBin:ignore\n"));
        assert!(!quota_config_ready("mail_plugins = quota\nquota = count:User quota\nquota_vsizes = yes\nquota_grace = 0%\nquota_rule2 = OSMAP.Documents:storage=+100M\n"));
        assert!(quota_config_ready(
            "mail_plugins = quota\nquota = count:User quota\nquota_vsizes = yes\nquota_grace = 0%\nquota_rule = Trash:ignore\n"
        ));
        assert!(!quota_config_ready("quota = count:User quota\nquota_vsizes = yes\nquota_grace = 0%\nprotocol lmtp {\n plugin {\n  mail_plugins = quota\n }\n mail_plugins = sieve\n}\nprotocol imap {\n mail_plugins = quota\n}\n"));
        assert!(!quota_config_ready(
            "mail_plugins = quota\nquota = count:User quota\nquota_vsizes = yes\nquota_grace = 10%\n"
        ));
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
