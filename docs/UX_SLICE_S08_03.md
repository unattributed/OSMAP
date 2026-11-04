# S08-03 — Scheduled send and snooze

## Current scope — 2026-11-05

The owner directs completion of unfinished S08 after accepting the storage
sidebar correction. S08-02 remains accepted. The selected 200 MiB obsd1 quota
has been applied and separately qualified; full installed Documents integration
remains open. S08-03 source and scoped native qualification pass. Normal signed
delivery, matching installation and owner acceptance remain in progress.

Preserve the frozen S08-03/D05 requirements and controls UX08-008, UX08-011,
UX04-006, R2-03-006, R2-04-031 and R2-15-010. A disabled Schedule control does
not fulfil the requirement. Source-only completion is not installed acceptance.

## Simplest implementation route

Reuse `PrivateAccountFile` for one bounded, owner-bound versioned job index and
the existing `FileDraftStore` metadata/blob codec for captured payloads. Keep a scheduled message
independent of later draft edits or expiry. Apply20 jobs/account,30 days ahead
and50MiB/account for payload metadata and unique attachment blobs. The separate
bounded job index is limited to1MiB. Completed/failed records retain metadata for30 days without
their plaintext payload. The dedicated payload store has a finite60-day lifetime,
covering the30-day due horizon plus at most30 days to resolve an unsubmitted
blocked job. At that boundary fail without submission and remove the payload.
Quota accounting includes staged/orphan payload allocations, not only published
index entries. An uncertain outcome retains what is needed for the
existing read-only recovery path; it is never automatically resubmitted.
Unknown-result job metadata, exact payload digest and delivery intent remain
available for reconciliation after payload expiry. Message bytes are not retained
forever: scheduled payloads expire after60 days and the existing independent
send-recovery store has its own30-day lifetime.

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

Run sequential passes inside the existing Rust Serve process, using an exclusive
native worker lock for each pass. The worker starts after the existing account-aware
confinement seal, checks at most eight accounts per pass and waits fifteen seconds
between passes. The90-second limit stops admitting new accounts; an already admitted
submission retains its existing bounded native operation and uncertainty handling.
Discover accounts only from canonical
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

## Progressive source qualification — 2026-11-05

The shared send path now accepts explicit browser or persisted-job authority;
it reuses preparation, the binding/inventory fence, current account admission,
SendJournal, SendRecovery, SMTP and exact Sent-copy handling. Browser and worker
submissions share an account limit. Browser remote-address limits remain intact;
the scheduler additionally has a separate bounded global bucket, without a
fabricated client address or user agent.

The changed-boundary results currently establish:

- 34 scheduler, worker, prepared-send, authority, throttle, HTTP and UI cases pass.
 These include exact snapshot receipt recovery, competing-worker exclusion,
 bounded account rotation, clock rollback, no Unknown rearm, CSRF/origin checks
 and saved-offset display.
- All six source-attachment route cases pass, including three new Schedule
 journeys. Schedule materializes verified selected bytes into the ordinary
 saved attachment payload and clears the external source reference. Foreign,
 changed and unavailable source messages refuse before saving. Combined saved,
 uploaded and selected files retain the existing limits.
- Four codec accounting cases pass. Recognized interrupted private writes are
 settled under the existing codec lock; complete payload bytes count without
 expiry cleanup. Invalid identities, unknown files and unsafe links refuse.

Preserved failures are part of this result: compilation exposed a DraftContent
versus ComposeRequest test-schema error; the date display initially passed ISO
text into a native-format formatter; Schedule initially entered the contact-action
parser and refused before attachment resolution; the accounting test initially
mistook normal first-save cleanup for process interruption. Corrections use the
existing full request conversion, formatter contract, exact action admission and
private publication seam. A separate compiler refusal occurred while an agent's
included native test file was still being written; no test executed in that run.

The matching OpenBSD scheduled actor now passes: one exact test in4.29seconds,
using test binary8a622a0ee80413118f55b4019a72fb317e320c962ea1e38e5cc5bc2a9ea9afb9
from archive6b6eec6f62876613df9845a5dba3ec9cec5dd5c07e451d8a7957f0bbf52c7591.
Actual helper unlock permits protected delivery; decryption, signature, authored
body, binary attachment and attached public certificate are checked. The existing
submission backend reaches a Rust loopback SMTP actor and the existing Sent backend
stores the same prepared message through scoped real Dovecot. Replay does not
submit or append again. Actual helper Lock refuses without another SMTP message;
loss of the final SMTP250 acknowledgement produces Unknown without retry;
the controlled epoch change refuses without another SMTP message. Six actual
peer/MAC/nonce admission exchanges, two SMTP DATA observations and one Sent message
are checked. The disposable agent cleanup passes independently.

The retained stage log hash is
fb9a5627177575d6089aa0b58f87a84e484a8a1ec0746603f230a25c78669270.
Independent review reconciles that result. Its controlled epoch responder does
not qualify the real account database, direct gateway dispatch does not qualify
the confined Serve worker, and no owner or provider message was sent. Actual confined Serve execution now passes the separately scoped test below.
Normal delivery gates, installed qualification and separate owner acceptance
remain open. The six-case UI suite also passes the
new Cancel-only recovery control for incomplete Staged entries.

## Confined Serve and ordinary-send regression — 2026-11-05

The matching actual OpenBSD enforce-mode Serve process passes its post-seal
worker test: one case in1.23seconds, binary
71cc17b0da7fa78e9cb231ca6144538511aa2119bef786ceb9fde7c29a21e4ef
from archive7f634858cf47cce85e4a04dca8e2094cd599708ef1b30ccf78d5f98f936c1d8d.
The actual background worker discovers a persisted future job, claims it and
settles Blocked(ServiceUnavailable) with no submission journal record or recovery
payload when account authority is unavailable. Health returns200 after the real
confinement seal; the exact-owned child is reaped and fixture removed. Log SHA
917c1afb69f4fd80a25035dc1baab2a5e209a23454dbe8b297dea81b4ad13a7a
and its typed witness were independently reconciled. This tests confined runtime
composition and refusal, not positive SMTP or the actual account database.

Because the shared prepared-send callback changed, the existing complete native
browser-send actor was run once on that same test binary with fresh disposable
keys. One case passes in6.11seconds, including existing cryptography, SMTP/Sent,
replay, stale binding, sign-only and encryption-only assertions. Cleanup passes.
Stage log SHAa02b4d1676ccd1bdea82386d5d883e124e5c169d5218b9753d3bc8d08a68664d.
No owner credential, key or external message was used. Strict Clippy, formatting
and existing V10 consistency checks pass. Native main build and Web-only install
are the next boundaries; installation must preserve the running mailbox helper,
account authority, crypto agents, configuration and public mail services.

## Delivery inventory correction — 2026-11-05

The first normal push refused publication because the five new scheduling routes
were missing from the existing WSTG attack-surface inventory. Full Rust2294PASS,
zero failures,89 explicit native/external ignores and preceding checks had passed.
The smallest correction adds the actual methods, query/form fields and existing
authorization/input/CSRF/business-logic test mappings to that inventory. No runner,
gate or product route changes. This inventory consistency result does not establish
a complete live WSTG security assessment. Original failure output is retained.
