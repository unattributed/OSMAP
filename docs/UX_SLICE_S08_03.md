# S08-03 — Scheduled send and snooze

## Current scope — 2026-11-05

The owner directs completion of unfinished S08 after accepting the storage
sidebar correction. S08-02 remains accepted. S08-01 quota selection and installed
Documents integration remain separate. This specification prepares the next
independent slice; scheduled-send implementation/native results are NOT RUN.

Preserve the frozen S08-03/D05 requirements and controls UX08-008, UX08-011,
UX04-006, R2-03-006, R2-04-031 and R2-15-010. A disabled Schedule control does
not fulfil the requirement. Source-only completion is not installed acceptance.

## Simplest implementation route

Reuse `PrivateAccountFile` for one bounded, owner-bound versioned job index and
the existing `FileDraftStore` metadata/blob codec for captured payloads. Keep a scheduled message
independent of later draft edits or expiry. Apply20 jobs/account,30 days ahead
and50MiB/account. Completed/failed records retain metadata for30 days without
their plaintext payload. The dedicated payload store has a finite60-day lifetime,
covering the30-day due horizon plus at most30 days to resolve an unsubmitted
blocked job. At that boundary fail without submission and remove the payload.
Quota accounting includes staged/orphan payload allocations, not only published
index entries. An uncertain outcome retains what is needed for the
existing read-only recovery path; it is never automatically resubmitted.

Use the existing strict UTC parser and saved fixed-offset account display.
Show the exact UTC instant and local display offset; reject ambiguous local or
named-zone/DST input rather than guessing. Changing display offset cannot move
an existing job's UTC instant. A forward wall-clock jump can make a pending job
due; a backward jump cannot rearm a submitted job.

Create/list/inspect/edit/cancel use the existing authenticated session, CSRF,
same-origin and revision checks. Capture complete validated authoring intent,
including routing, attachments, sender identity and protection choices. Retire
the originating compose/draft send intent under the same account journal lock
as immediate Send and Save, preventing a stale form from also sending it.
Cross-file creation uses non-dispatchable staging, journal retirement bound to
the job and payload digest, then Pending publication. Every incomplete phase is
reconcilable and cannot dispatch; never undo a possibly published retirement.
Pending/blocked unsubmitted jobs can be changed explicitly; claimed/unknown/
submitted attempts cannot be portrayed as cancelled.

Add one sequential run-once entry to the existing Rust binary, using an exclusive
native worker lock for its bounded pass. Discover accounts only from canonical
account-bearing records in the dedicated owner-private job-index directory;
validate custody, schema and hashed filename against that account. Refuse an
exceeded global entry cap instead of silently dropping records. Sort eligible
accounts and persist a rotation cursor for fair bounded passes, independent of
filesystem iteration order. Existing account rollout eligibility applies; no
manual per-user registry is added. One sequential worker meets both the
one-per-account and two-total maxima. Persist a claim and one stable delivery
intent before submission. Reuse `SendJournal`, `SendRecovery`, throttling,
current sender authorization, current key/policy evaluation and its revision
fence, protected preparation, the existing SMTP backend and exact Sent-copy
path. No second SMTP implementation, retry ledger or generic job platform.

An authenticated schedule action grants narrow durable job authority bound to
the account epoch and immutable payload revision. At due time, recheck current
account/epoch and all send-time identity/key/policy facts. Never fabricate a
browser `ValidatedSession` to dispatch a job. Factor the existing prepared-send
path to accept explicitly validated browser or job authority.

Private signing access stays independent of job authority. Capture only the
actual authorizing session descriptor: ID, account epoch and expiry, without
its cookie, CSRF value, password, TOTP or key passphrase. Before a private
operation require a current matching nonrevoked/unexpired session and the
helper's actual unexpired grant. Expiry, lock or helper restart produces Blocked;
an authenticated explicit reauthorization can resume an unsubmitted job. A
scheduled job never extends the fixed eight-hour key grant or falls back to
plaintext. Ordinary/public-encrypted jobs may outlive the browser session only
under their durable job authority and current account admission.

Keep lock ordering explicit: send-journal account coordination before job
mutation, never the reverse. A persisted in-flight journal entry after restart
is Unknown until the existing read-only receipt can establish a result. Mint
and persist a delivery intent once when due, rather than retaining a compose
intent that expires at the30-day scheduling boundary.

Snooze already implements100 private markers/account, a30-day maximum,
native message identity checks, CAS, persisted clock high water and expiry on
read. Reuse it; no mail movement or background service is required to restore
visibility on the next load. Retest only changed interaction and necessary
restart/clock/stale-identity boundaries.

## T01–T09 and required observations

| Task | Work and essential proof | Starting state |
| --- | --- | --- |
| T01 | Inspect existing source, frozen budgets and actual deployment interfaces; identify submission reuse, worker coverage and payload/intent expiry seams | Read-only assessment complete; implementation pending |
| T02 | Durable job schema, captured payload, owner/revision validation, limits, reopen/edit/cancel and terminal retention; malformed/foreign records refuse unchanged | NOT RUN |
| T03 | Strict UTC/offset display, maximum horizon, forward/backward clock changes, snooze expiry/restart/UID reuse; no changed due instant or duplicate rearm | Existing snooze evidence reusable; scheduler NOT RUN |
| T04 | Actual authenticated create/list/inspect/edit/cancel routes, originating-intent retirement and stale Send/Save race; CSRF/origin/anonymous/foreign refusal | NOT RUN |
| T05 | Sequential native worker/global lock, durable claims, restart and competing workers; one submit callback, stable attempt identity and safe fault disposition | NOT RUN |
| T06 | Shared real prepared-send pipeline; current epoch/sender/recipient/key/policy fencing and private-grant expiry; Locked means Blocked and zero plaintext dispatch | NOT RUN |
| T07 | Existing SMTP/crypto/Sent native actor: exact controlled scheduled delivery and replay, ambiguous acceptance and Sent failure/reconciliation; factual job events only | NOT RUN |
| T08 | Independent source/security review, matching OpenBSD installation, actual bounded worker and service/account preservation; existing login readiness check | NOT RUN |
| T09 | Owner schedules one controlled message, sees its status, and exercises pending cancellation; usable snooze expiry check only if changed | NOT RUN |

Root owns the work order, host/native/Git queue and integration. Existing helper
engineers prepare file-owned changes; an independent reviewer checks source,
actual native results and recovery. No new Python tooling or dependency is
planned. Define exact native source/target, timeout and owned cleanup before
dispatch. One failed boundary retains diagnostics and stops an unchanged retry;
two failures require combined independent reassessment. Unknown SMTP state is
never retried automatically. No production mail-host or unsolicited external
message is authorized by integration testing.

Normal signed delivery gates, matching installed qualification and separate
owner acceptance remain required. Future S08-04 consumes factual job events
through the existing notification store; a new event bus is unnecessary.
