//! Post-dispatch cleanup consumes a verified reply after the guarded callback
//! releases the browser lock. This bounded component proves browser revocation
//! only, never SQL mutation, mail containment or overall password-change success.
use super::*;
use crate::account_mutation::{Outcome, TerminalReceipt};
use std::time::{Duration, Instant};

const MAX_ENTRIES: usize = 8192;
const MAX_RECORDS: usize = 4096;

#[derive(Debug, PartialEq, Eq)]
pub enum BrowserRevocation {
    KnownRefused,
    OldSessionsRevoked {
        count: usize,
    },
    /// Includes uncertain or partial cleanup; never a known non-write.
    Contained {
        count: usize,
    },
}

fn current(receipt: &TerminalReceipt, clock: &impl TimeProvider, deadline: Instant) -> bool {
    let now = clock.unix_timestamp();
    Instant::now() < deadline && now >= receipt.responded_at() && now < receipt.expires()
}

impl<T: TimeProvider, R: RandomSource> SessionService<FileSessionStore, T, R> {
    /// Call only after mutation dispatch returns and drops its guarded session
    /// lock. The original absolute deadline must be passed through, not renewed.
    /// File operations have byte/count bounds and deadline checks; a native
    /// whole-operation watchdog is still required before production activation.
    pub fn revoke_password_change_sessions(
        &self,
        receipt: TerminalReceipt,
        deadline: Instant,
    ) -> BrowserRevocation {
        if matches!(receipt.outcome(), Outcome::KnownRefused) {
            return BrowserRevocation::KnownRefused;
        }
        let mut count = 0;
        let result = (|| {
            if deadline > Instant::now() + Duration::from_secs(60)
                || !current(&receipt, &self.time_provider, deadline)
            {
                return Err(());
            }
            let _guard = self.session_store.guarded_lock().map_err(|_| ())?;
            let mut records = Vec::new();
            let mut initiator_present = false;
            // Validate the entire bounded snapshot before the first write.
            for (index, entry) in fs::read_dir(&self.session_store.session_dir)
                .map_err(|_| ())?
                .enumerate()
            {
                if index >= MAX_ENTRIES || !current(&receipt, &self.time_provider, deadline) {
                    return Err(());
                }
                let entry = entry.map_err(|_| ())?;
                let path = entry.path();
                if path.extension().and_then(|s| s.to_str()) != Some("session") {
                    continue;
                }
                if records.len() >= MAX_RECORDS {
                    return Err(());
                }
                let id = path.file_stem().and_then(|s| s.to_str()).ok_or(())?;
                if id.len() != SESSION_ID_HEX_LEN || !id.bytes().all(|b| b.is_ascii_hexdigit()) {
                    return Err(());
                }
                let bytes = crate::private_account_file::read_record(&path, 4096)
                    .map_err(|_| ())?
                    .ok_or(())?;
                let text = std::str::from_utf8(&bytes).map_err(|_| ())?;
                let mut keys = std::collections::BTreeSet::new();
                for line in text.lines().filter(|line| !line.is_empty()) {
                    let (key, _) = line.split_once('=').ok_or(())?;
                    if !keys.insert(key) {
                        return Err(());
                    }
                }
                let record = parse_session_record(text).map_err(|_| ())?.ok_or(())?;
                if record.session_id != id {
                    return Err(());
                }
                if id == receipt.session_id() {
                    if record.canonical_username != receipt.account()
                        || record.account_epoch != Some(receipt.old_epoch())
                    {
                        return Err(());
                    }
                    initiator_present = true;
                }
                records.push(record);
            }
            if !initiator_present {
                return Err(());
            }
            for mut record in records.into_iter().filter(|record| {
                record.canonical_username == receipt.account()
                    && record
                        .account_epoch
                        .is_none_or(|epoch| epoch <= receipt.old_epoch())
                    && record.revoked_at.is_none()
            }) {
                if !current(&receipt, &self.time_provider, deadline) {
                    return Err(());
                }
                record.revoked_at = Some(self.time_provider.unix_timestamp());
                self.session_store.save_password_revocation(&record)?;
                count += 1;
            }
            if !current(&receipt, &self.time_provider, deadline) {
                return Err(());
            }
            Ok(())
        })();
        if result.is_err() || matches!(receipt.outcome(), Outcome::Contained) {
            BrowserRevocation::Contained { count }
        } else {
            BrowserRevocation::OldSessionsRevoked { count }
        }
    }
}

impl FileSessionStore {
    fn save_password_revocation(&self, record: &SessionRecord) -> Result<(), ()> {
        let path = self.session_path(&record.session_id);
        crate::private_account_file::read_record(&path, 4096)
            .map_err(|_| ())?
            .ok_or(())?;
        let temporary = self.session_dir.join(format!(
            ".password-revocation-{}-{}.tmp",
            std::process::id(),
            SESSION_TMP_COUNTER.fetch_add(1, Ordering::Relaxed)
        ));
        let result = (|| {
            let mut file = create_session_temp_file(&temporary).map_err(|_| ())?;
            file.write_all(serialize_session_record(record).as_bytes())
                .map_err(|_| ())?;
            file.sync_all().map_err(|_| ())?;
            drop(file);
            fs::rename(&temporary, &path).map_err(|_| ())?;
            fs::File::open(&self.session_dir)
                .map_err(|_| ())?
                .sync_all()
                .map_err(|_| ())
        })();
        if result.is_err() {
            let _ = fs::remove_file(temporary);
        }
        result
    }
}

#[cfg(all(test, unix))]
#[path = "session_password_cleanup_tests.rs"]
mod tests;
