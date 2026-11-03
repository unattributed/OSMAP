//! Session-bound personal-key operations. Sensitive inputs are borrowed binary
//! data, never Debug values, public inventory metadata or persistent settings.
use serde::{Deserialize, Serialize};

pub const CACHE_SECONDS: u64 = 28800;
pub const MAX_CERTIFICATE: usize = 65536;
pub const MAX_PASSPHRASE: usize = 1024;

#[derive(Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct PrivateSession {
    pub session_id: String,
    pub account_epoch: Option<u64>,
    pub expires_at: u64,
}
impl PrivateSession {
    pub(crate) fn valid(&self, now: u64) -> bool {
        self.session_id.len() == 64
            && self
                .session_id
                .bytes()
                .all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(&b))
            && self.expires_at > now
            && self
                .account_epoch
                .is_none_or(crate::account_admission::valid_epoch)
    }
}
pub enum PersonalAction<'a> {
    Status,
    Import {
        certificate: &'a [u8],
        passphrase: &'a [u8],
    },
    Unlock {
        passphrase: &'a [u8],
    },
    Lock,
}
#[derive(Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct PersonalState {
    pub primary_fingerprint: String,
    pub private_revision: String,
    pub installed: bool,
    pub protected_at_rest: bool,
    pub unlocked_for_session: bool,
    pub valid_until: Option<u64>,
    pub cache_seconds: u64,
}
impl PersonalState {
    pub(crate) fn valid_for(&self, session: &PrivateSession, now: u64) -> bool {
        self.primary_fingerprint.len() == 40
            && crate::openpgp_crypto::full_fingerprint(&self.primary_fingerprint)
            && self.private_revision.len() == 64
            && self
                .private_revision
                .bytes()
                .all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(&b))
            && self.cache_seconds == CACHE_SECONDS
            && (self.installed || (!self.protected_at_rest && !self.unlocked_for_session))
            && if self.unlocked_for_session {
                self.valid_until.is_some_and(|until| {
                    until > now
                        && until <= session.expires_at
                        && until <= now.saturating_add(CACHE_SECONDS)
                })
            } else {
                self.valid_until.is_none()
            }
    }
}
#[derive(Clone, Copy, Debug, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum PersonalError {
    Invalid,
    Unavailable,
    Locked,
    Conflict,
    Expired,
    Unsupported,
    Unconfirmed,
}

/// Best-effort clearing of request-local owned buffers. No secure-erasure claim
/// is made for allocator copies, swap or pre-existing caller-owned buffers.
pub(crate) fn clear(bytes: &mut [u8]) {
    bytes.fill(0);
    std::hint::black_box(bytes);
}
