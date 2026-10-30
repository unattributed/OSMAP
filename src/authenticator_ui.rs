//! Account-owned authenticator summary for Settings.
use crate::authenticator::Snapshot;

pub(crate) fn authenticator_summary(state: Option<&Snapshot>) -> (String, String) {
    let Some(state) = state else {
        return (
            "Unknown".into(),
            "Authenticator state and last use are unavailable.".into(),
        );
    };
    let enrollment = if state.enrolled {
        "Enrolled"
    } else {
        "No active factor"
    };
    let last = state.last_accepted_counter.and_then(|v| v.checked_mul(30)).and_then(|at| at.checked_add(29).map(|end| (at, end))).map_or_else(
        || "Last use unknown; no accepted account TOTP time window is available.".into(),
        |(at,end)| format!("Last accepted account TOTP time window: {} to {}. This may predate the current factor; the exact verification time is not recorded.", crate::logging::format_unix_timestamp_utc(at), crate::logging::format_unix_timestamp_utc(end)),
    );
    (enrollment.into(), last)
}
