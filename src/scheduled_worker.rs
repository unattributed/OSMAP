//! Sequential persisted-job ownership. Transport lives in the shared send path.
use crate::private_account_file::PrivateAccountFile;
use crate::scheduled_send::{ClaimRecovery, ClaimedJob, Error, ScheduledStore, State};
use crate::send_journal::{AttemptOutcome, SendJournal};
use serde::{Deserialize, Serialize};
use std::path::Path;
use std::time::{Duration, Instant};

const MAX_ACCOUNTS_PER_PASS: usize = 8;
const ADMISSION_SECONDS: u64 = 90;
#[derive(Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct Cursor {
    version: u8,
    high_water: u64,
    after: Option<String>,
}

#[derive(Clone, Copy, PartialEq, Eq)]
pub(crate) enum DispatchDecision {
    Submitted,
    Blocked(crate::scheduled_send::BlockReason),
    Unknown,
}
#[derive(Default)]
pub(crate) struct PassResult {
    pub accounts_checked: usize,
    pub accounts_unavailable: usize,
}

/// One global nonblocking lease covers claim, dispatch and settlement. At most
/// eight accounts are admitted, one sequential attempt per account. Admission
/// stops after90seconds; an already admitted send retains its existing native
/// command bounds. No deadline cancels and retries an uncertain SMTP operation.
pub(crate) fn run_once(
    settings: &Path,
    clock: impl Fn() -> u64,
    mut dispatch: impl FnMut(&ClaimedJob) -> DispatchDecision,
) -> Result<PassResult, Error> {
    let deadline = Instant::now() + Duration::from_secs(ADMISSION_SECONDS);
    let file = PrivateAccountFile::new(
        settings.join("scheduled-worker"),
        "scheduled-worker-v1",
        4096,
    );
    let lease = file
        .lock("worker@osmap.invalid")
        .map_err(|_| Error::Unavailable)?;
    let now = clock();
    let mut cursor = match lease.read().map_err(|_| Error::Unavailable)? {
        Some(bytes) => serde_json::from_slice::<Cursor>(&bytes).map_err(|_| Error::Invalid)?,
        None => Cursor {
            version: 1,
            high_water: 0,
            after: None,
        },
    };
    if now == 0
        || cursor.version != 1
        || now < cursor.high_water
        || cursor
            .after
            .as_ref()
            .is_some_and(|account| crate::identity::CanonicalUsername::parse(account).is_err())
    {
        return Err(Error::ClockRollback);
    }
    let store = ScheduledStore::new(settings.join("scheduled-send"));
    let journal = SendJournal::new(settings.join("send-journal"));
    let accounts = store.discover_accounts_before(deadline)?;
    let mut result = PassResult::default();
    if accounts.is_empty() {
        return Ok(result);
    }
    let start = cursor
        .after
        .as_ref()
        .and_then(|last| accounts.iter().position(|account| account > last))
        .unwrap_or(0);
    for offset in 0..accounts.len().min(MAX_ACCOUNTS_PER_PASS) {
        if Instant::now() >= deadline {
            break;
        }
        let account = &accounts[(start + offset) % accounts.len()];
        cursor.after = Some(account.clone());
        let updated = clock();
        if updated < cursor.high_water {
            return Err(Error::ClockRollback);
        }
        cursor.high_water = updated;
        // Rotate before this account so a broken account cannot permanently
        // monopolize the next pass. An unconfirmed cursor write aborts dispatch.
        lease
            .write(&serde_json::to_vec(&cursor).map_err(|_| Error::Invalid)?)
            .map_err(|_| Error::Unconfirmed)?;
        match run_account(&store, &journal, account, &clock, &mut dispatch) {
            Ok(()) => result.accounts_checked += 1,
            Err(_) => result.accounts_unavailable += 1,
        }
    }
    Ok(result)
}
fn accepted(outcome: Option<AttemptOutcome>) -> bool {
    matches!(
        outcome,
        Some(AttemptOutcome::Accepted { .. } | AttemptOutcome::AcceptedWithoutSentCopy)
    )
}
fn run_account(
    store: &ScheduledStore,
    journal: &SendJournal,
    account: &str,
    clock: &impl Fn() -> u64,
    dispatch: &mut impl FnMut(&ClaimedJob) -> DispatchDecision,
) -> Result<(), Error> {
    let now = clock();
    let guard = journal
        .account_guard(account, now)
        .map_err(|_| Error::Unavailable)?;
    let list = store.list(&guard, now)?;
    // Unknown never rearms or starves Pending. A later authoritative acceptance
    // can settle metadata even after the separately bounded payload expires.
    for job in list.jobs.iter().filter(|job| job.state == State::Unknown) {
        let intent = job.intent.as_deref().ok_or(Error::Invalid)?;
        if journal
            .receipt_for_snapshot(account, intent, &job.digest)
            .is_ok_and(accepted)
        {
            store.recover_claimed(&guard, &job.id, intent, ClaimRecovery::Submitted, now)?;
        }
    }
    let recovery = list.jobs.iter().find(|job| job.state == State::Claimed);
    let claim = if let Some(job) = recovery {
        let intent = job.intent.as_deref().ok_or(Error::Invalid)?;
        // Atomic bounded receipt reads need no second journal lock. Only the
        // actual owned Ok(None) result permits resuming the SAME claimed intent.
        let disposition = match journal.receipt_for_snapshot(account, intent, &job.digest) {
            Ok(Some(outcome)) if accepted(Some(outcome)) => ClaimRecovery::Submitted,
            Ok(None) => ClaimRecovery::NoAttempt,
            _ => ClaimRecovery::Unknown,
        };
        store.recover_claimed(&guard, &job.id, intent, disposition, now)?
    } else {
        store.claim_next(&guard, now)?
    };
    // Existing send execution takes the same account coordination lock.
    drop(guard);
    let Some(claim) = claim else { return Ok(()) };
    let decision = dispatch(&claim);
    let guard = journal
        .account_guard(account, clock())
        .map_err(|_| Error::Unavailable)?;
    match decision {
        DispatchDecision::Submitted => store.submitted(&guard, &claim, clock()),
        DispatchDecision::Blocked(reason) => {
            store.block_unsubmitted(&guard, &claim, reason, clock())
        }
        DispatchDecision::Unknown => store.unknown(&guard, &claim, clock()),
    }
}

#[cfg(test)]
#[path = "scheduled_worker_tests.rs"]
mod tests;
