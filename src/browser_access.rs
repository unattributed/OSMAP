//! Browser-only contracts for registered-account recovery and factor replacement.
//! These objects carry input and presentation, never native completion authority.
use crate::session::ValidatedSession;
use crate::totp_enrollment::PendingEnrollment;
use std::fmt;

pub const RECOVERY_COOKIE: &str = "__Host-osmap_recovery";
pub const RECOVERY_CSRF_COOKIE: &str = "__Host-osmap_recovery_csrf";

pub enum AccessAuthority<'a> {
    Unauthenticated,
    Grant(&'a str),
    Session(&'a ValidatedSession),
}
impl fmt::Debug for AccessAuthority<'_> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(match self {
            Self::Unauthenticated => "AccessAuthority::Unauthenticated",
            Self::Grant(_) => "AccessAuthority::Grant([REDACTED])",
            Self::Session(_) => "AccessAuthority::Session([REDACTED])",
        })
    }
}

pub enum AccessView {
    RecoveryEmail {
        csrf: String,
    },
    RecoveryCode {
        csrf: String,
        challenge_id: String,
    },
    RecoverySetup {
        csrf: String,
        enrollment: PendingEnrollment,
    },
    TotpResetStart {
        account: String,
        csrf: String,
    },
    TotpReplacement {
        account: String,
        csrf: String,
        enrollment: PendingEnrollment,
    },
    /// Returned only after independently confirmed native completion.
    Complete,
}
impl AccessView {
    pub fn csrf(&self) -> Option<&str> {
        match self {
            Self::RecoveryEmail { csrf }
            | Self::RecoveryCode { csrf, .. }
            | Self::RecoverySetup { csrf, .. }
            | Self::TotpResetStart { csrf, .. }
            | Self::TotpReplacement { csrf, .. } => Some(csrf),
            Self::Complete => None,
        }
    }
    /// Unauthenticated forms use the route's double-submit nonce. A nonempty native
    /// flow nonce must already match that nonce and is never silently replaced.
    pub(crate) fn bind_csrf(&mut self, nonce: &str) -> bool {
        let csrf = match self {
            Self::RecoveryEmail { csrf }
            | Self::RecoveryCode { csrf, .. }
            | Self::RecoverySetup { csrf, .. }
            | Self::TotpResetStart { csrf, .. }
            | Self::TotpReplacement { csrf, .. } => csrf,
            Self::Complete => return true,
        };
        if csrf.is_empty() {
            *csrf = nonce.into();
        }
        crate::http_support::constant_time_eq(csrf.as_bytes(), nonce.as_bytes())
    }
}
impl fmt::Debug for AccessView {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(match self {
            Self::RecoveryEmail { .. } => "AccessView::RecoveryEmail([REDACTED])",
            Self::RecoveryCode { .. } => "AccessView::RecoveryCode([REDACTED])",
            Self::RecoverySetup { .. } => "AccessView::RecoverySetup([REDACTED])",
            Self::TotpResetStart { .. } => "AccessView::TotpResetStart([REDACTED])",
            Self::TotpReplacement { .. } => "AccessView::TotpReplacement([REDACTED])",
            Self::Complete => "AccessView::Complete",
        })
    }
}

pub enum AccessAction<'a> {
    SendRecoveryCode {
        email: &'a str,
    },
    VerifyRecoveryCode {
        challenge_id: &'a str,
        code: &'a str,
    },
    ConfirmRecovery {
        enrollment_id: &'a str,
        revision: u64,
        new_password: &'a str,
        confirmation: &'a str,
        new_totp_code: &'a str,
    },
    BeginTotpReset {
        current_password: &'a str,
        current_totp_code: &'a str,
    },
    ConfirmTotpReset {
        enrollment_id: &'a str,
        revision: u64,
        new_totp_code: &'a str,
    },
}
impl AccessAction<'_> {
    pub fn kind(&self) -> &'static str {
        match self {
            Self::SendRecoveryCode { .. } => "send_code",
            Self::VerifyRecoveryCode { .. } => "verify_code",
            Self::ConfirmRecovery { .. } => "confirm_recovery",
            Self::BeginTotpReset { .. } => "begin_reset",
            Self::ConfirmTotpReset { .. } => "confirm_reset",
        }
    }
}
impl fmt::Debug for AccessAction<'_> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_tuple(self.kind()).field(&"[REDACTED]").finish()
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum AccessError {
    Refused,
    Expired,
    Conflict,
    Throttled,
    Unavailable,
    Unconfirmed,
}

pub enum AccessCookie {
    Unchanged,
    Set(String),
    Clear,
}
impl fmt::Debug for AccessCookie {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(match self {
            Self::Unchanged => "AccessCookie::Unchanged",
            Self::Set(_) => "AccessCookie::Set([REDACTED])",
            Self::Clear => "AccessCookie::Clear",
        })
    }
}

#[derive(Debug)]
pub struct AccessOutcome {
    pub view: AccessView,
    pub grant_cookie: AccessCookie,
}
