2026-11-06 — **Trash selective-deletion UAT ACCEPTED / PASS.** Owner reports selective testing and explicitly approves UAT. The supplied result records seven confirmed deletions, zero refusals, zero unconfirmed results and zero unattempted messages, with absence confirmed for every deleted item. This records the owner-tested Trash correction; it does not assert that every new Trash action was individually exercised or close remaining S08 scheduling, cancellation, Snooze or Drafts acceptance. No further mailbox action accompanied this record.

### Trash correction qualification — 2026-11-06

Native35 passed in2.06s through the actual new Empty-trash HTTP routes,
RuntimeBrowserGateway, signed helper and disposable Dovecot mail. Review saw
all4 messages, Cancel dispatched nothing, and a deliberate retention flip
allowed exactly1 deletion then refused1 with2 not attempted. Remaining mail,
predeleted neighbour, other account/Inbox bytes, flags and GUIDs stayed intact;
owned scratch cleanup and standard host metadata checks passed. Tests34 SHA256
`153364e84f8f4b2a7b045744d391059d2f87427f221de0639c7a9e91a610d690`
comes from source34 archive
`71a9856d71d15b72d916fb4cad921c1c15485ad5c9efd7278ccee83f0b2fb360`.
The actual native log SHA256 is
`0fa3a4ef268f9d07e981f16e8a81dc8ff7def10fe187a07adfb3f156587e2290`.

Install33 passed: Web loaded main31 inode and SHA256 matched
`5f6b7d18dd76ba3de73bf435e593d92ac2f0f8f338fd2071a96dc58190456fd7`;
nine services and HTTPS login200 passed. Public mail, helper, account-service
and GPG PIDs plus checked configuration hashes were unchanged. No owner mail
was deleted. Independent source/security, recipe, Firefox browser and native
receipt review passed. Ordinary signed delivery hooks remain the publication
gate; this record does not convert owner Trash UAT into PASS.

## 2026-11-06 — Practical Trash controls and Empty trash

The owner rejected the general-purpose Bin toolbar. Trash now has a visible
**Empty trash** action, **Restore to Inbox**, **Delete permanently**, visible
selection/clear links and secondary **Move to folder** controls. Received dates
replace the misleading Archived/Unknown column in Trash; Archive keeps its
existing recorded-action date contract. The current selection limit remains
ten messages. Empty trash is independent of selection, filters and pagination.

Two POST routes, `/trash/empty/review` and `/trash/empty`, reuse the existing
Rust deletion handler and helper-owned per-message deletion. Review loads the
entire saved Trash through the native `mailbox ... all` listing. Its existing
2000-message/output bounds fail closed rather than truncate. A compact SHA256
snapshot covers sorted account/folder/UID/mailbox-GUID/message-GUID/policy
revision tuples; no new pending-job store or wildcard expunge was introduced.
Confirmation repeats account/session/Origin/CSRF, saved-folder, hierarchy,
complete inventory, identity and retention checks. A changed snapshot refuses
before mutation. Messages arriving after the final snapshot are not targeted.
The existing 30-second request bound and stop-first-refusal/unknown behavior
report exact confirmed/refused/unconfirmed/not-attempted counts; no automatic
retry or false whole-folder-empty claim is made. Larger/incomplete/unavailable
inventories refuse; this is not an unbounded mail-cleanup service.

Five new Rust regressions pass: 75-message inventory beyond the visible page;
Cancel and changed snapshot; new arrival/recreated mailbox GUID; authority,
metadata and duplicate refusal; empty/oversize inventories, GET/foreign Origin
and partial Unknown. Existing selected deletion tests remain unchanged. Actual
JavaScript-disabled Edge and independent Firefox desktop/mobile checks cover
whole-folder review/Cancel, selected deletion review/Cancel, pointer/Space
selection and selected Restore. Firefox reviewed all125 synthetic messages
from a filtered50-row view. Edge's final labels and Restore emptied two
synthetic Trash rows; Empty trash on the empty folder reported no messages.
No owner mail, real credential or external Send was used.

Failures retained: the first GET test constructed an invalid GET body twice
before app dispatch; independent reassessment corrected the request. The first
broad source run exposed three Archive assertions affected by presentation;
Archive title/date semantics were restored and its55 focused tests passed.
Native32 reached actual one-deleted/one-refused/two-unattempted behavior, then
failed a fixture-only expected-UID assertion inherited from selected deletion.
Whole-folder ordering includes the predeleted neighbour; independent review
approved expected UIDs from the full sorted inventory. Removal of the failed fixture’s scratch
and unchanged installed binary/public services were verified before test retry.
An earlier Edge tool timeout is retained separately from the successful fresh
final fixture. None of these failures was rewritten as an owner UAT pass.

Build31 archive SHA256:
`d89cbeec4addf7e9d8d4647fad4bb5ea1096899289c747d402df342eb0bc24c8`.
Native main31 SHA256:
`5f6b7d18dd76ba3de73bf435e593d92ac2f0f8f338fd2071a96dc58190456fd7`.
Native tests31 SHA256:
`1c843f6c5e2453f850d7c89c14063b0292fb1b531a8a0abc6a2665ee1a975771`.
The subsequent test-only correction does not change main31. Native35 results,
Web-only install33 and signed normal-hook delivery are reconciled below when
completed. Owner acceptance of the new Trash journey remains pending.

## 2026-11-06 — Repeated Drafts/Bin selection failure reopened

The repeated owner UAT failure at045d639 overrides the earlier readiness claim
for these controls. Scheduled-copy rows still rendered disabled checkboxes and
the bulk discard button counted only editable rows. The earlier per-row menu
correction did not complete the ordinary selection journey.

Confirmed scheduled source copies now use the existing revision-bound bulk
review/confirmation form. A visible **View scheduled message** link replaces the
need to find that link in a menu. Captured copies remain read-only; deleting
their Drafts copy preserves the scheduled message, consumed intent and delivery
status. Ordinary editable drafts retain their existing resume/edit workflow.
Unknown, attempted, stale, duplicate or invalid states remain restricted.

The original Bin checkboxes worked with a mouse and Space in Edge and Firefox;
no backend selection failure was reproduced. Its16-pixel targets and action
toolbar below all rows were independently observed usability defects. The
existing single action form now appears above the rows, with24-pixel checkboxes
and at least44-pixel selection labels. Retention, identity/revision, session,
Origin, CSRF and explicit permanent-deletion confirmation are unchanged.

Actual JavaScript-disabled Edge and independent Firefox desktop/mobile tests
selected two synthetic scheduled copies with pointer and Space, reviewed two,
confirmed discard and reloaded an empty list. Bin selected fields belonged to
one correct form and opened permanent-deletion review. Firefox360x800 had no
horizontal overflow; its Bin label was44pixels high. These browser tests used
the existing Rust loopback fixture and no owner account, Send POST or external
mail. Bin confirmation in the browser remained unsubmitted; native deletion
evidence is separate. Existing Rust tests cover mixed ten-item bounds, stale
and foreign revisions, missing auth/Origin/CSRF, partial failure, and retained
scheduled jobs after source discard.

Native archive27 SHA256
06b1ae7b6ca84d750c16bdd680ec7792004e425b36c2b8c70155a8fe3bb76f2e
built main27
ca4857951bf9b96636924476d9dd7ff65987009fcbea71906778bec83c92c1cb
and tests27
ae326703281ff4ac2f28f4afd42f732f5298278cddedd2695bfbb9153a757d43.
Eight focused native tests passed. Install28 verified Web's loaded text inode,
nine services and HTTPS login200. Helper, account, GPG and public-mail PIDs and
relevant configuration compared unchanged. No owner messages were deleted.
The helper intentionally retains its prior running binary for this UI-only
correction. Native29 single and bulk browser/helper/backend deletion passed in
2.47s and1.82s using disposable owned messages, including retention, stale and
foreign identity refusal and unchanged neighbouring mail. Readiness30 passed
current installed signed account admission and exact-account Trash allowed,
Inbox unavailable and foreign account unavailable in0.05s with no mutations.
Normal signed delivery remains a separate final check.

The first ordinary pre-push passed2340 Rust tests with0 failures and89 explicit
native/external ignores, hostile-content checks and strict Clippy, then refused
cargo fmt --check in three changed http_ui.rs sections. Required rustfmt changes
preserve literals/control flow; scanner inventories were refreshed for shifted
lines. This formatting-only follow-up and the test-only relocation do not alter
the native27 production implementation. The failed hook is retained; a second
ordinary push must complete its full security-check without bypass.

Preserved failures: the initial concat-based format needed an explicit named
argument and compiled after that correction. The default synthetic Bin fixture
denies deletion without retention; an explicit test-only allowed policy exercises
the positive review. The default Playwright Firefox path was missing; an existing
cached executable worked. A shared synthetic fixture had already been consumed;
independent QA used its own fresh fixture. The V14 R4 test incorrectly assumed
all real historical followups remained BLOCKED despite prior account-status
progress; its existing counterexample now uses an explicitly pending deepcopy.
All56 validator tests pass without changing the real acceptance register. No new
Python tooling, dependency or general testing framework was introduced.
The next legacy V14 scan treated hostile test strings in the runtime-template
file as runtime scripts. Move that unchanged test to the existing cfg(test)
http_ui_state_tests.rs module; retain the literal attack strings and assertions.
The relocated Rust test passes; native27 predates this test-only relocation,
whose production implementation is identical. Neither gate was weakened.
The aggregate historical V14 target subsequently stops at its unchanged reader
gate demanding the literal phrase "future decrypted content must still pass
protected rendering". That phrase is already absent at baseline045d639, after
actual OpenPGP rendering was implemented. This unrelated historical gate remains
FAIL and is not represented as passing. Its repair is outside this selection
correction. Normal mandatory commit/push security checks and actual Rust reader
regressions remain required; no gate is skipped or changed for publication.

Private evidence: osmap-ux-s08/completion-20261104/selection-controls-20261106.
Independent QA/security: /root/s08_selection_review. The earlier S08 inspection
matrix below remains applicable; Documents remains removed. Repeated failed
UAT, earlier native failures and prior scoped acceptance are preserved.

Engineering correction is ready for owner recheck after ordinary signed
publication succeeds. In **Drafts**, tick a scheduled copy, choose **Review
discard**, confirm and reload: that copy disappears while delivery status stays
intact. In **Bin**, tick an expendable message and use the permanent-deletion
review above the list; confirm and reload: only that item disappears. These two
owner checks remain NOT_RUN for the corrected deployment. Whole-S08 acceptance
also retains the local-time/cancel/Snooze checks below; existing accepted areas
need not be repeated unless another defect is observed.

## Earlier 2026-11-06 — Drafts/Trash correction and retained S08 inspection

The owner reported Drafts UAT FAILED after separately accepting scheduled delivery.
That failure is retained. The current correction removes the exact source draft
only after durable schedule capture and journal confirmation. A legacy confirmed
Scheduled copy has a **Delete source copy** action in its three-dot menu. Deletion
keeps the scheduled job, captured payload and consumed send intent; it cannot
cancel or resend the message. Reserved/uncertain attempts remain protected.
Source-cleanup failure preserves the confirmed job and a safely discardable copy.

The installed mailbox helper had no retention-policy input. Existing permanent-
delete routes correctly refused without that authority. The obsd1-only policy now
permits confirmed permanent deletion for the operator development account / Trash,
revision1. Inbox and other accounts remain unavailable to this policy. The
existing identity/revision, CSRF, review and explicit confirmation checks remain.
No owner message or retained source copy was deleted during agent QA.

A separate Sent-date defect was reproduced: native date.received was local time
without an offset, then interpreted as UTC and converted again. The existing
native executor now uses TZ=UTC; account display applies the saved offset once.
Snooze reuses the same fixed-offset parser/display as Schedule. Missing, forged
or changed form offsets refuse before mutation; Snooze cancellation still works
without a timezone preference. Existing due instants are unchanged. Named-zone
DST automation is outside the existing fixed-offset setting.

### Matching verification and preserved failures

- Local developer gate passed with2339 Rust tests,0 failures and89 explicit
  native/external ignores. Changed-source strict Clippy and commit-check passed.
  The final ordinary push gate separately rechecks the delivered source.
- OpenBSD production source archive21 SHA256
  d8a507566820d01947ad3650d7a3e8d27a7c867c61f5123332d8a9f505c6ef3d
  built main a57111d62d5315e6f63d4227a3e93ef7a28bf0e4aa7f25d7a288efb5fe61e08b.
  Native scheduling60, Snooze12 and executor-environment1 tests passed.
- Synthetic single-delete attempts21/22 failed before deletion while saving the
  test Bin preference. A diagnostic-only23 observation identified exit89:
  IMAP could not resolve its inherited inaccessible working directory. The
  existing test-only child-config isolation omission was also corrected, but
  that omission alone did not fix the failure. The native carrier now changes
  to /tmp before su. Original assertions were preserved; no product permission
  or public mail-service setting was weakened. Temporary fixture cleanup uses
  the existing owned namespace. Raw synthetic diagnostics remain private.
- Matching tests22 SHA256 fc4b9d22932d7ae469e5d2b409cc359abb65efcf44100f6b4a949ca236622f52
  passed actual single and bulk browser/helper/native deletion journeys in2.50s
  and1.87s. Assertions include current retention changes, stale/foreign tuples,
  explicit confirmation, exact expunge and unchanged neighbouring mail.
- Install21 stopped before live changes because its PID observation used the
  service name mysqld instead of the observed process name mariadbd. Reviewed
  install25 uses the observed daemon name. Both live Web/helper text inodes now
  match main21; HTTPS login200 and nine service checks pass. Public mail,
  account-service and GPG-agent processes and unrelated configuration compare
  unchanged. The installed read-only Runtime/helper test passes signed account
  admission, exact-account Trash allowed, Inbox unavailable and foreign-account
  unavailable in0.04s. It performs no owner-session or mailbox mutation.

Private receipts are retained under
osmap-ux-s08/completion-20261104/scheduled-drafts-trash-20261106. Production code
is archive21; the later reader-fixture change is test-only. Independent review
and ordinary signed synchronization are recorded separately from owner T09.

### All retained S08 functionality inspected

| Area | Result and remaining owner check |
| --- | --- |
| S08-01 Documents | Removed by owner; development and UAT excluded. Historical mailbox/quota cutover is not silently reversed. Accepted account storage reporting is retained. |
| S08-02 labels, finite menus and folder hierarchy | Existing accepted source/native/human evidence reused; current regression suite includes label assignment, folder create/rename/delete, protected folders, stale identity and account isolation. No changed implementation. |
| S08-03 scheduled send | Captured content, edit/cancel, due-worker/restart, account/key/policy fencing, uncertain-result nonretry and duplicate suppression retained. Prior composed native positive worker proof and owner scheduled-delivery PASS reused. New source cleanup, legacy discard and saved-time entry are checked; corrected owner UAT remains pending. |
| S08-03 Snooze | Saved local input/display, identity/CAS/CSRF, expiry/reopen, Inbox/dashboard suppression, search/direct access and cancellation checked. It does not move mail. |
| S08-04 notifications | Accepted inbox/badge/preferences, read/delete/delete-all and save feedback retained. Current regressions cover account isolation, replay suppression, mandatory security events, bounded retention and opt-in browser delivery. No claim of unreported audible/desktop presentation on every platform. |
| Trash follow-up | Installed exact-account authority plus real synthetic single/bulk deletion pass. Owner chooses expendable messages for final confirmation. |

### Short owner UAT

Sign in again after the OSMAP restart. (1) In Drafts, tick a Scheduled copy's
checkbox, choose **Review discard**, confirm discard, refresh and confirm it is absent;
the existing Sent message/job status stays intact. (2) In Bin, select one expendable
message, use **Review permanent deletion of selected** above the list, confirm, refresh and
confirm only that item is gone. (3) Set/confirm your OSMAP timezone, schedule a
new test for a future local time, confirm the displayed local time and that the
source no longer appears in Drafts, then cancel the job and confirm it stays
cancelled after refresh. (4) Snooze an Inbox test message to a future local time,
then cancel its snooze and confirm it returns. Previous notification and folder
acceptance need not be repeated unless a new problem is observed.

Whole S08 remains open for this final owner UAT; scheduled-delivery PASS and
previously accepted areas are preserved, not erased by the Drafts failure.

2026-11-06 scope refinement — user requests all S08 functions inspected for UAT. Reuse the existing fixed-offset conversion for Snooze entry/display too, with current-owned-offset binding and cancellation independent of timezone availability. Verify no mail movement, source-list suppression/expiry, search/direct access and CAS/CSRF. No new scheduler or named-zone/DST machinery.

2026-11-06 (Asia/Bangkok) — **Drafts UAT FAILED; engineering resumed.** Scheduled-delivery UAT remains PASS for the received test. Retained scheduled source copies must be safely removable without rearming delivery. Correct future exact-source cleanup and legacy explicit discard; investigate Trash retention and native date normalization. No owner message deletion during agent QA. Whole S08-03/S08 is not accepted.

# S08-03 — Scheduled send and snooze


## Owner acceptance update — 2026-11-05

2026-11-05 (Asia/Bangkok) — **S08-03 scheduled-delivery UAT PASS.** Owner explicitly states “Scheduled-delivery UAT: PASS” after showing the message “scheduled send for22h45” received in Proton Mail at23:45 local time, matching its original saved schedule. This accepts end-to-end scheduled delivery for that test. The corrected local-time input and separate cancellation checks remain pending; whole S08-03/S08 acceptance is not inferred. No code, deployed binary, schedule or mailbox data changes accompany this record.


## Current scope — 2026-11-05

Owner UAT follow-up: use the saved OSMAP fixed-offset timezone for scheduled-send input and primary display, converting to UTC only for persisted dispatch. Reject missing/changed timezone context rather than reinterpret stale forms. Existing job UTC instants remain unchanged. The first owner job was observed Pending before its16:33UTC due time; this does not establish dispatch failure. Correct the separately confirmed source-draft projection defect: confirmed schedule retirement becomes a read-only scheduled-copy link, while reserved/unconfirmed outcomes remain Paused. Preserve duplicate-send guards, cancellation and private-key requirements. Documents remains removed; owner T09 is pending.

The owner directs completion of unfinished S08 after accepting the storage
sidebar correction. S08-02 remains accepted. The selected 200 MiB obsd1 quota
has been applied and separately qualified. Documents was subsequently removed
by the owner and is not current scope. S08-03 T01–T08 pass within the source, native and installed
scopes below, and normal signed delivery has completed. Engineering is
UAT_READY; owner T09 remains pending.

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

Reuse the strict calendar parser with the saved fixed-offset account timezone.
Show local send times first and retain the exact UTC instant as secondary detail.
A hidden canonical offset must match the current account preference at submission;
missing, forged or changed context refuses instead of guessing. Named-zone/DST
automation is not introduced. Changing display offset cannot move
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

| Task | Work and essential proof | Current engineering result |
| --- | --- | --- |
| T01 | Inspect existing source, frozen budgets and actual deployment interfaces; identify submission reuse, worker coverage and payload/intent expiry seams | PASS — existing paths and requirements reviewed |
| T02 | Durable job schema, captured payload, owner/revision validation, limits, reopen/edit/cancel and terminal retention; malformed/foreign records refuse unchanged | PASS — Rust persistence/CAS/isolation/recovery tests |
| T03 | Strict UTC/offset display, maximum horizon, forward/backward clock changes, snooze expiry/restart/UID reuse; no changed due instant or duplicate rearm | PASS — time/clock/snooze source and route tests |
| T04 | Actual authenticated create/list/inspect/edit/cancel routes, originating-intent retirement and stale Send/Save race; CSRF/origin/anonymous/foreign refusal | PASS — authenticated route and refusal regressions |
| T05 | Sequential native worker/global lock, durable claims, restart and competing workers; one submit callback, stable attempt identity and safe fault disposition | PASS — source ownership tests and actual confined background-worker case |
| T06 | Shared real prepared-send pipeline; current epoch/sender/recipient/key/policy fencing and private-grant expiry; Locked means Blocked and zero plaintext dispatch | PASS — current-authority source tests and separate protected native grant/epoch refusals |
| T07 | Existing SMTP/crypto/Sent native actor: exact controlled scheduled delivery and replay, ambiguous acceptance and Sent failure/reconciliation; factual job events only | PASS — controlled SMTP/native Sent, replay and Unknown/reconciliation evidence |
| T08 | Independent source/security review, matching OpenBSD installation, actual bounded worker and service/account preservation; existing login readiness check | PASS — matching installation, composed qualification, independent review and normal delivery |
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

## Installed engineering result — 2026-11-05

S08-03 T01–T08 pass within their stated engineering scope. Owner T09 is pending.
Normal signed delivery completed through the enabled hooks at ba6c49b910d914befa834709d64ba5078cd50d22; fresh fetch proves exact local/origin equality and0/0. Full Rust2294PASS/0FAIL/89explicit native/external ignores and all remaining normal checks pass. The actual native main build matches all37 changed Rust files in source archive2.

Web-only installation loads93a167020df7e36b67007fbf39b7909dbf751004898232c33868d21f21191e91 in ServePID41439. The existing helper/account processes, crypto agents and configuration are unchanged. HTTPS200, nine healthy roles and both anonymous scheduling-page303-to-login checks pass. The matching installed credential-free signed-admission/Runtime/helper/owned-renderer/foreign-refusal test passes1case in0.12seconds, reporting172605611messagebytes and209715200configuredbytes. No owner session, password/TOTP, private-key operation, external mail or quota enforcement is inferred. Installation logSHA896a5600ad51d33cc7b3a4bfbb42af1c564fe6bd2ff041690a9f3ba7ce7edd99; readiness logSHA6a226577998ea563018466685b75244b379ba7f8981977aa0d07411edb3eaeb8. Independent result review confirms engineering readiness.

For owner UAT: compose a controlled test message, choose Schedule, review the saved text and choose a future Send at(UTC) time. Confirm the message appears in Scheduled messages and later shows its factual submission result. Schedule a second message farther ahead and cancel it while still Scheduled. Signing requires personal-key access to remain valid at send time; a blocked message waits for explicit review and reauthorization. This does not accept S08-03 or complete all S08. Independent S08-04 work may continue while owner acceptance is pending.

## Qualification reconciliation — 2026-11-05

Independent continuation review found that the positive scheduled native actor and actual Serve confinement were qualified separately. The positive actor used the actual signed fixture peer, controlled SMTP and native Sent path before Serve sealing; the actual confined Serve test proved persisted claim and safe ServiceUnavailable refusal with its authorities intentionally absent. Installed signed admission and renderer checks do not prove a due job can submit after the Serve seal. Consequently the earlier blanket T01–T08 PASS/engineering-ready claim is superseded: positive post-seal due-job dispatch remains PENDING, not an observed product failure. Owner T09 must follow that composed positive qualification. A bounded extension of the existing native Serve fixture is being prepared; no owner jobs, public MTA changes or external email are authorized by this test.

### Planned composed positive qualification

Reuse the existing disposable native Gateway actors with one exact native_crypto_gateway_scheduled_serve_roundtrip selector. Before the actual Serve seal, fixed OpenBSD test-only seams admit the existing controlled MAC clients and four exact transport executable leaves. Production constructors, qualification flags, pledge promises, seal/finalization/thread order and helper append guards stay unchanged. A due ordinary job must be consumed only by the actual confined Serve worker, settle Submitted with typed Accepted/Sent receipt, store one exact native Sent message and make one loopback SMTP acceptance. A later durable worker-cursor advance must leave counts unchanged and preserve the foreign future job. Health, current-owner custody, exact nonce, bounded synced private diagnostics and owned-child reap are required. This closes a worker-composition gap, not protected cryptography after seal, owner-account DB custody or external delivery.

Native test operation is bounded50seconds inside the existing300-second/15-second-termination disposable wrapper; matching one-job test compilation retains600/15seconds and the existing cache. Preserve the earliest failure and retained fixture before cleanup; two failures at one boundary stop for combined reassessment. No public service/configuration, owner job or external mail action is part of this qualification.

The first composed-positive source8 native compilation refused two E0603 module-visibility references from openbsd.rs before any runtime case. Private compiler8 output and immutable source76d384bef474ca1f83179abddb85fbb6e4243a0846ae6f629e23e5071b95b33f are retained. Independent review approved one test-only crate-visible fixture re-export from http.rs and correction of only those two external hook paths; http_runtime remains private and production code is unchanged. Local all-target checking and formatting pass; native recompilation and the actual case remain pending.

Native test9 built successfully (c11d35cb71b3e0aa5f123b67fd494a8bfab801313a49a496e7db4150904e2b0e). Its first actual composed case failed after healthy post-seal Submitted, two admission exchanges, one SMTP acceptance and one Sent save: exact byte comparison found231Sent bytes versus233SMTP bytes, with SMTP exactly Sent plus terminal CRLF. The synthetic input lacked that line ending and the existing SMTP actor explicitly adds it. Source review by author and independent reviewer approves only adding terminal CRLF to the fixture input, retaining the exact equality assertions and production formatter unchanged. The failed namespace/child streams/stage log and synced private copies remain retained. Its next-pass/no-duplicate check was NOT RUN; no complete native PASS or resubmission of that failed job is claimed. A new matching build and fresh namespace are required.

Source10 built successfully (16043a207a7dfa806de3bdf2b0f54ef1e28bfcdd2cbd9fdbb2579c8160d1c2f1) and was not run. Independent pre-execution review tightened the next-pass consumer: the worker writes its cursor before account processing, so a timestamp alone is insufficient. The test first observes the initial Bob cursor, then requires a later coherent Bob cursor at least15seconds higher. With the one isolated sorted Alice/Bob worker this proves subsequent Alice processing returned before Bob admission; it does not claim completion of Bob processing. No product worker/instrumentation change or additional runtime attempt occurred.

### Actual composed result — 2026-11-05

The corrected fresh case passes1test/0failures in17.15seconds with disposable cleanupPASS. Source11archive8b8d323bbf6cc055496763f115c1c6fca69e94d8d5a345658884e8d37d8a8909 produced libtest386c08ca34a8a858b9a649aaadc7260d5de3c77a8e0061a42dff4c5dbb021e9d. Actual enforced Serve and its background thread produce Submitted, two authenticated admission exchanges, one controlled SMTP acceptance, one exact native Sent and matching typed Accepted(sent_copy_stored=true) receipt. Initial Bob and later Bob cursor observations prove subsequent Alice processing completed before Bob admission; counts remain one and the foreign future job is unchanged. The owned child is reaped. Synced private child diagnostics retain382stdout/8385stderr byte accounting and whole-stream hashes before successful cleanup. Independently copied/read stage logSHA256907c23e09abb3d8c61479f202dda717d3a45eeb40e73c15b5bcecc770af28467 matches the runner readback. Independent review gives this scoped native result GO.

This closes the missing ordinary positive post-seal worker composition. Prior protected native preparation/SMTP/Sent/refusal and installed real signed-admission results remain separate reused evidence; this new controlled-peer/transport case does not establish actual DB custody, protected cryptography after seal, native off-list execution denial or owner T09. All new runtime-hook paths are cfg(test,OpenBSD); production behavior and installed Webdb383665 remain unchanged.

Final read-only service preservation confirms ServePID29963 loaded main db3836658799b75aa2d7d9549a4783cb0b03104df576053e980bd8d02ab89718, unchanged configuration/account/helper/crypto agents, HTTPS200 and nine healthy roles. The first read-only check stopped on shell quoting of the awk field selector before loaded-inode inspection; its metadata comparisons had passed. The existing literal recipe corrects that consumer, and final-service-check2 passes without any service or configuration mutation. Both outcomes remain private. Normal signed preservation/gates for this test-only continuation remain pending; owner T09 remains pending.

### Delivery classification correction — 2026-11-05

Normal push3 of signed5b24dc3 stopped at the existing CWE guard after2317RustPASS/0FAIL/89explicit ignores and the earlier delivery checks. The three findings were test-only self-execution and fixed shell-leaf declarations in two new native fixture files. Combined author/root/independent reassessment confirms these files are excluded from production, and moving code solely to avoid a scan would be inappropriate. The existing guard now checks the exact test-only registration for these two paths, including every cfg/include link for the nested fixture. All production rules and production allowlists remain unchanged. Five independent missing-link negative cases require the affected fixture to be scanned again; unrelated production Command/shell negatives remain enforced. The complete guard regressions and actual-tree scan pass. Rust bytes and native source11 qualification are unchanged and reused. The private push3 log remains retained; normal full delivery is pending.

Push4 of signed12160fa again passed2317Rust/0failures/89explicit ignores and the corrected CWE guard, then refused the same fixtures in the legacy shell scan. Combined reassessment identified its subsequent direct-process scan as the same missing counterpart. Only the two exact relevant file filters are aligned with the preceding mandatory full-chain CWE check; production patterns and unsafe scan remain unchanged. The existing regression now executes the actual downstream scan block with its guard, all five broken-chain cases, unrelated production shell/process negatives and the actual repository. Its first synthetic test incorrectly inserted both sink kinds into each file and was correctly refused; correction restricts each test input to its actual admitted sink, keeping the narrow filters. The corrected combined suite passes. Both push failures and the focused test failure remain private; Rust/native/installed bytes are unchanged. Full normal delivery remains pending.

## Engineering completion and owner UAT — 2026-11-05

T01–T08 are PASS within the documented source/native/installed boundaries. Normal push5 completed the full existing delivery path, including2317RustPASS/0FAIL/89explicit native/external ignores, strict Clippy, formatting, source/claims/supply-chain checks and the corrected combined weak-pattern guards. Signed source681ab5e818ed7ab21a40df413e773fe8f6741b06 is published on feat/ux-completion-20260929; fresh fetch confirms exact local/remote equality,0ahead/0behind and clean status at that checkpoint. Private push5 receipt SHA256d369b8d40e2cd8eb414759dc2a8158cce0b22d08f7de98426b34e09d90cb8785 is retained with both earlier classification refusals. The final guard changes affect no Rust bytes, so source11 native qualification and installed Webdb383665/service-preservation results remain applicable. Independent result review is GO.

Owner T09 remains NOT RUN. On obsd1, compose a controlled test message, choose Schedule and set a future Send at (UTC) time. Open Scheduled messages and confirm its eventual factual status. Schedule another message farther ahead and cancel it while still scheduled; confirm the cancellation is visible. Signing needs personal-key permission to remain valid at dispatch. Report the observed result; no log analysis or secret sharing is needed. This engineering closeout does not accept the slice on the owner's behalf. Whole S08 remains open while Documents activation and S08-04 owner acceptance are pending.


## 2026-11-05 — Saved-timezone scheduling follow-up qualification

The installed follow-up uses the authenticated account's saved fixed offset for
schedule create, edit and explicit reauthorization. Forms show the timezone,
current local time and local bounds. POST checks the current saved offset before
any scheduled mutation. UTC remains the persisted dispatch instant; existing jobs
were not changed. The read-only16:09:32UTC observation retained both owner jobs
Pending, with original due instants1793896380 and1793897100 (23:33 and23:45 at
UTC+07:00), unchanged created/updated timestamps and no refusal reason. Earlier
22:57 local screenshots therefore preceded their stored due times; they do not
establish a dispatch failure. The confusing UTC input is the corrected defect.

Confirmed journal transfers show Scheduled copy in Drafts and link to the job;
this source remains consumed/read-only after cancellation. Reserved or uncertain
transfers remain Paused. Native execution used disposable test state, not owner
authentication or owner message mutation. Source scheduler tests57PASS/0FAIL with
one explicit ignore, the additional HTTP timezone integration1PASS, strict
Clippy and format/diff checks pass. Native OpenBSD service-account tests58PASS,
0FAIL,3explicit native-fixture ignores in46.86seconds; the named timezone,
HTTP zero-dispatch and real Runtime/cancel/reopen checks are included.

Private receipts: `/home/foo/Downloads/osmap-ux-s08/completion-20261104/scheduled-timezone-20261105/`.
The reviewed source20 archive is1670d1192c5742b2c0a1b7557046384b7c413d5fc294612349887076ab49110c.
Native test receipt26c961e5283675cb7e23130b6369e8b138e6cfa9e3a715c5f50bdeaa16136e7f.
Installed Web binary20c2e1206ade2d149c08bd1c0df210e9f32d6ed9437be894497a322842978885
matches the running Serve executable. Web-only atomic install retains original
binary and rollback recipe. Configuration, account-helper, mailbox-helper and
crypto-agent readbacks are unchanged; nine checked roles run and HTTPS login200
passes. Independent source, recipe and result review GO. These are scoped
engineering observations; owner T09 remains pending, and no production-release
security acceptance is claimed. Existing unaffected snooze/worker/crypto/SMTP
qualification above is reused. Documents remains removed.

Owner UAT: sign in, retain UTC+07:00 in General settings, schedule a controlled
message five minutes ahead by entering that local time directly, and check the
scheduled list shows that same time first. Confirm submission after the due time.
Cancel a separate pending test and confirm it does not send. Earlier owner jobs
remain at their original saved times unless the owner explicitly changes them.

Normal developer security-check passes, including2335 Rust library tests with
zero failures and89 explicit native/external ignores, existing guard regressions
and WSTG pack validation. This is the developer gate, not a new authenticated
production WSTG assessment. Changed Rust source hashes match the native source20
build. Shopkeeper-signed source synchronization proceeds through normal hooks.

Delivery history: the first ordinary pre-push run stopped at a synthetic key-test
script launch with Linux ExecutableFileBusy (Text file busy), before the security
assertion:2334PASS/1FAIL/89explicitignores. Exact cause remains unconfirmed;
independent review supports a fixture execution-race hypothesis. The exact
genuine-session refusal test then passes isolated (1PASS/0FAIL). The bounded
changed execution is ordinary complete push hooks with RUST_TEST_THREADS=1; no
test/assertion/hook is disabled and no test retry/sleep is added to product code.
Original failure and isolated receipts remain in the private artifact directory.


## 2026-11-06 — S08-02 visible label controls correction

Owner UAT confirms label creation and the assigned label on a stored message.
The reader action wraps into three lines inside an icon-sized toolbar button in
both split and standalone views. Reuse the existing inert reader tag geometry;
show an icon with title and accessible name "Edit message labels", preserving
the exact message-bound URL and existing authorization. Exit: focused Rust
label regression, desktop/narrow browser layout and keyboard navigation in both
reader views, independent review, matching Web-only install and normal signed
publication. No owner-data writes. Two failures at the same boundary stop retries
for independent reassessment. Other accepted S08 outcomes remain unchanged.

Owner marks S08-02 FAILED because create/apply/delete controls are not discoverable. Existing Rust account-private label persistence, selection review/apply and exact native message identities are reused. Shared navigation now exposes Labels on every signed-in page. Inbox, Sent and stored-folder message lists show Label selected messages and Create or manage labels above their rows; the reader exposes Edit message labels directly. Drafts provides label management access and explicitly says that labelling unsent drafts is unavailable: local DraftRecord does not have the native message identity used by these label operations. This correction does not claim draft-label support or owner acceptance.

Local Rust label tests pass25/0, including create/persistence/attach/detach/delete, CSRF/CAS, foreign/stale identity refusal, atomic selected changes, filters and move reconciliation. Real synthetic Edge desktop testing performs create, selection while the old menu stays closed, review/apply, reload persistence, reader detach and confirmed label deletion, preserving both messages. Edge and Firefox390px checks pass visible controls and keyboard selection/review; Edge has no horizontal page overflow. Drafts and Folders navigation and the explicit Drafts limitation are checked. No owner label or mail mutation occurred.

Native source38 archive SHA256fbe1829d8e5d6ef914ee1f856665e42d891b28762a96f377664c576e5643d8d6 builds on obsd1. Its25 label tests pass0fail; libtest31bd06007a7fe04b17138861f9c5f752e9ec13eaf61fb5a204a62f28ad6888d2 and mainb0e80e24662221357fd553caa8c426c9b79d3ce5ef97d6784144e86c6322bb72 are retained. The outer build transport later returns143 despite the completed build PASS marker and artifact hashes; the installation independently verifies its exact candidate hash. No functional test is inferred from the transport result.

Private receipts and screenshots: /home/foo/Downloads/osmap-ux-s08/completion-20261104/labels-20261106/. Independent source/browser-scope review and existing bounded Web-only installation recipe review GO. Other owner PASS results for storage, actual scheduled delivery, selective Trash deletion and notification controls remain accepted. Documents remains removed. S08-02 reacceptance is pending.

Web-only install38 PASS: running ServePID15387 loads the exact b0e80e24 candidate; HTTPS login200 and nine checked roles healthy. Configuration, account/helper/GPG and public-mail process readbacks match before/after; no owner messages or labels changed. Previous binary and rollback record retained under /var/osmap-storage/labels-install38-20261106. Normal signed delivery checks remain pending.

Publication gate failure retained: the normal push security gate refused the18th inert shell SVG introduced by the Labels navigation icon because its fixture budget was17. Independent review confirms this measured shell-only mismatch. The finite budget and boundary regression now admit18 source-owned geometry-only icons and observe a19th; exact attribute/geometry validation, pre-main restriction and message SVG prohibition remain unchanged. Focused hostile-content integration retest passes2/0. Product source and installed binary are unchanged by this test correction. The original push failure is retained in push.log; ordinary full hooks will run again without bypass.

Installed signed account-admission readiness38 passes as the existing Web user using matching native tests38: no password submitted, no TOTP consumed, no credential write and epoch file unchanged. This independently checks the account-service admission path after the Web restart; HTTPS200 alone is not treated as authentication proof.

Second ordinary publication attempt retained in push-retest.log: changed label-test assertions advanced the V11 source-assumption inventory by four low-relevance test/fixture entries. The existing V10 generator refreshes only current inventory counts, digest and generation time; historical baseline, high-relevance count0 and medium count3 stay unchanged. V10/V11 focused gate passes. No assertion, product behavior or installed artifact changes. Independent combined reassessment precedes the next ordinary complete push gate; neither failed delivery attempt is treated as functional failure or silently omitted.

Independent combined reassessment GO confirms the four new label-test unwrap sites exactly explain inventory drift. The18/19 shell boundary remains strict, historical security baseline remains intact and matching installed product needs no rebuild. Proceed with the signed checkpoint and ordinary full hooks; owner label reacceptance remains pending.

Owner requests the master label controls embedded in an existing Settings page. Extend the same correction to Copies & Folders using the existing label form renderer and authenticated account store, unchanged CSRF/revision/delete-confirmation routes. Essential exit adds a real Settings-origin create/rename/delete browser check, account isolation and unavailable-storage rendering, plus matching native build/Web-only installation. No owner labels or mail mutations; a normal form submission may continue on the central Labels page.

Settings master controls completed in Copies & Folders, reusing the same escaped CSRF/revision forms and confirmed deletion; no new endpoint or store. Local Rust label suite26PASS0FAIL includes Settings create/rename/delete persistence, foreign-record refusal and message preservation. Actual synthetic browser Settings-origin create, rename and confirmed deletion pass desktop and390px keyboard checks, with no horizontal overflow. The result page intentionally reuses central Labels. Screenshot and settings-browser-results.json are retained under the existing private labels evidence directory; disposable browser tab is closed.

Matching OpenBSD source39 archive70142ff7a07c087f0e13910fce6396aa3ba35fcbee0669d2dbfda628c5cf6023 builds successfully:26PASS0FAIL; native tests a7b7bac520f349f87dba5822cfb242b6ea34d024a332388820c019afa6f450d7; main c31cf3c1ccb83d29be57501a050e32173892f49ebb2223991313e5ecca18a7fa. Reviewed Web-only install39PASS loads that exact candidate at ServePID39798. Nine checked services are healthy, HTTPS login200, public-mail/helper/account/GPG process and configuration snapshots unchanged; rollback original retained. Matching installed signed epoch-admission readiness39PASS submits no password, consumes no TOTP and writes no credentials; epoch unchanged. No owner labels or messages were changed. Independent source/browser/build/install review GO.

The optional pre-action validator invocation refused because its implementation accepts only active S04-02 work orders. It supplies no S08 admission proof; ordinary work-order-only scope validation passes for17 obligations. The exact reviewed source/build recipe bound the native dispatch. Existing V10 inventory generation refreshes three additional low-relevance test assumptions from the Settings regression; focused V11 gate passes without changing historical baseline or runtime protections. Final ordinary complete publication gates remain required. Owner S08-02 reacceptance remains pending.

Compact reader-label action correction: existing inert tag geometry replaces the wrapped visible action text; title and accessible name remain Edit message labels. Exact account/message-bound URL and all label authorization remain unchanged. Local and matching OpenBSD label regressions each pass26/0. Actual synthetic browser split/standalone desktop and390px checks confirm a34.39px square, no wrapped action text, tooltip/accessibility name and keyboard Tab/Enter navigation to the correct message editor. Assigned badges stay visible. Source and bounded native build/install review GO; no owner labels or messages changed.

Source40 archive ba3a579e0f3a6b33a1d44479a59e4acea1f79bf0f9bb3e69cfb1e804fc3e8f8d builds with normal exit0; native tests1624b319ac855582f7fce879d8328689eccbc1c4d716b007d0d613f3f052fee3 and Web mainafed32d4cbc9dcff0b993b7c8a5d91022322f7d5d7bd7cd03f4861c82a51ba51 retained. Reviewed Web-only install40 exits0 and loads exact candidate at ServePID90304. Nine checked services healthy, HTTPS login200; configuration and public-mail/helper/account/GPG process snapshots unchanged. Previous Web binary retained under /var/osmap-storage/labels-install40-20261106. Screenshots icon-split-desktop40.png and icon-split-narrow40.png retained in the existing private labels directory. Owner confirms creation/assignment; remaining S08-02 reacceptance stays pending.

Matching installed read-only readiness40 passes1/0: no password submitted, no TOTP consumed, no credential writes and account epoch unchanged. Independent final source, browser, native build, install and readiness receipt review GO. Ordinary signed commit/push gates remain required; no whole-S08 acceptance is claimed.

Normal signed icon commit7d8dac3 passes commit checks; ordinary push40 stops at V11 refined_current.inventory_sha256 drift after Rust library2337PASS0FAIL90ignored and integration checks. Independent reconstruction proves only existing scanner positions shifted: label_tests.rs entries+5 lines and http_ui.rs+1, without added assumptions. Existing generator refreshes only generation time and current digest to7ee13738778b99791b617951db8318f43c2ea3e6e0217b55100253b1e49879be; total13059, low13056, medium3, high0 and baseline remain unchanged. Combined independent reassessment GO; focused V10/V11 PASS. Gate logic and installed product are unchanged; full ordinary publication gates remain mandatory.


## 2026-11-07 — Unsaved Compose navigation correction

This S08 UAT blocker belongs to the original S03-02 interrupted-navigation and
safe-failure-preservation obligations (UX06-001, R2-04-030). It does not reopen
or requalify all historical S03 controls or accept the remaining S08 checks.

A dirty Compose page now offers Save draft, Discard changes and Keep editing
when leaving through a same-window link or another page form, including header
search and logout. Save uses the existing multipart Rust draft route and opens
the saved draft; the user can then continue to the intended destination.
Keep editing and Escape preserve text, selected files and focus. Discard leaves
without saving current edits and preserves any earlier saved draft version.
The existing native browser warning remains for reload, Back, tab close and
browsers without dialog support. Autosave pauses while the choice is open;
existing in-flight, uncertain-save, ownership, CSRF and revision checks remain.
No new endpoint, service, dependency or Python tooling was introduced.

Failure analysis: the baseline browser observed only beforeunload, without the
requested three choices. Search replay exposed a queued dialog-close/reopen
race; the close handler now ignores an obsolete close event while reopened.
Independent combined reassessment reviewed that correction. Retained later
failures were an expired synthetic fixture, an oversized ordinary-file test
whose file was rejected before submission, and a harness awaiting a deliberately
cancelled reload. Those harness conditions were corrected, without weakening
product validation. Earliest failures and subsequent passes remain separate.

Actual Rust synthetic-server/Edge browser retest5 passes all 14 journeys:
clean navigation; dirty Keep editing with file; Escape; Save draft including
file persistence; discard edited saved draft preserving its prior version;
clean saved-draft navigation; header search by Enter; queued-close/reopen race;
external form without submitter; invalid oversized-image save retaining work;
390px layout; native reload-warning cancellation; logout choice/replay; and
absence of script errors or unexpected browser warnings. This is synthetic
account QA, not an owner credential-backed browser session.

Local focused Rust enhancement tests: 2 PASS, 0 FAIL. Native obsd1 source41:
2 PASS, 0 FAIL; build exits successfully. The four product files match the
reviewed native archive. Main SHA256:
aefd27a5f2ce0a46b3e6e1a43b704ced7854b5b7e154377254a5691da8707176.
Tests SHA256:
b7a59908afdcf5e05c11828b0faf0a6094f8663af5d2f26ca8bba7da2480596c.
JavaScript SHA256:
5be2a69112921b300bfe28a36fa19f481dbe5caf50360db9a26f3465f0e37426.
The exact script CSP hash is updated; author content remains inert.

Web-only install41 PASS: running Serve PID58258 loads the exact candidate;
HTTPS login200 and nine service checks PASS. Helper, public-mail, account and
GPG processes and configuration are unchanged. No owner-message mutation.
Previous binary and bounded rollback retained; rollback was not executed.
Installed read-only admission readiness41: 1 PASS, 0 FAIL, no submitted password,
no consumed TOTP, no credential write and unchanged account epoch. Browser,
native, installation and readiness records are retained privately under
/home/foo/Downloads/osmap-ux-s08/completion-20261104/compose-navigation-20261107/.

Independent final product, browser, native build, installation, readiness and
document review GO from /root/s08_compose_review; no actionable findings.
Ordinary signed Git delivery is required before handoff. Owner UAT
of this correction is pending. Existing accepted labels, storage, scheduled
delivery, selective Trash deletion and notifications remain accepted. Documents
remains removed. The remaining Drafts discard, local-time schedule/cancel and
Snooze/cancel checks remain separate; whole S08 acceptance is not asserted.

## 2026-11-08 Outbox follow-up

User requirement: expose Outbox between Drafts and Sent, including scheduled
and retained submission attempts. Reuse the Rust scheduler, journal, recovery
and draft stores. Scheduled/blocked messages may be edited, sent now through
the existing worker checks, returned to Drafts, or cancelled/deleted. Returning
to Drafts durably stops dispatch before writing an exact editable copy; an
interrupted transfer can resume without overwriting an edited destination.
Claimed and unknown submissions remain read-only until their outcome is known;
no automatic resend. Submission acceptance does not prove delivery.

Essential verification: account/revision/CSRF refusals, exact transfer and
interruption recovery, capacity refusal without payload loss, worker-only
dispatch, retained-attempt distinctions, escaping and browser navigation/forms.
Use synthetic accounts without SMTP dispatch. Native matching build, Web-only
installation, read-only signed admission, independent review and ordinary
signed publication are required before readiness. Owner Outbox UAT remains
separate from whole S08 acceptance. No mail-stack configuration, owner job
mutation, new service, Python tooling or Documents functionality.

Failure record: initial focused compile failures (qualification/import and test
constructor mismatch) corrected; one UI assertion used the wrong existing Sent
shortcut URL and was corrected. Prior focused Outbox retest: 6 PASS, 0 FAIL;
additional recovery checks and full gates remain pending.

Final changed-boundary qualification (2026-11-08): the matching native43
OpenBSD build passes all ten Outbox tests (0 failures, 0 ignored). The real
synthetic Edge desktop/mobile journey passes eight checks: navigation order,
scheduling with a binary attachment, edit, exact return to Drafts, send-now
worker authorization, delete/cancel, narrow-screen layout and JavaScript errors.
These tests do not submit owner or external mail. The browser fixture initially
used a fixed clock against Runtime's real expiry clock; its existing opt-in
scheduled fixture now uses a matching clock, with the default fixture unchanged.

Installation43 is Web-only. The loaded Web executable SHA256 is
`0a6ad35afaab5c11a37118e5a426a07c4cc75eb73deb78dd8201452b50518ee7`;
the previous executable is retained for rollback. Nine role checks and HTTPS
login pass. Protected configuration and helper/public-mail/account/GPG process
identities remain unchanged. Installed read-only signed account admission passes
without a password, TOTP consumption, credential write or account-epoch change.
Owner messages and schedules were not mutated by this qualification.

Full-gate failures remain evidence: the new sidebar icon exceeded the existing
hostile-test finite icon allowance, corrected from 18 to 19 with the rejecting
20-icon boundary retained; two focused hostile tests pass. The existing V10
current inventory was regenerated (13112 entries: low13109, medium3, high0),
initially retaining its prior coarse scanner snapshot. Its current digest is
`b466a715809d3ccedc4e82f05d878d71d9b79d891b9b67f886975c4d67186d2e`.
The WSTG route inventory now includes Outbox and preserves an exact standalone
`/scheduled` router alternative so the existing extractor can see both aliases;
the focused route comparison passes. No Python program or dependency was added
or modified. Two later acceptance runs ended with signal143, sender UNKNOWN;
they are interrupted results, not passing gates or diagnosed product failures.
Independent combined review found no supported source correction for that
interruption. The isolated existing mail-backend suite passes47 tests, skips2,
exit0 in2.123s; the first diagnostic wrapper's missing `/usr/bin/time` failed127
and was corrected to the shell builtin. The isolated acceptance run completed its entire security-check successfully,
then stopped at V10 because the original assumption register (separate from the
refined register) was stale. The existing original-register generator refreshes
its current count to13112 and digest to
`25e4099a8a9a636c12042c780ab5b04d3138d1c2efef8f106ed2f1a7496065af`;
its carried-forward baseline712 remains unchanged. This original classifier
retains its production-adjacent high-relevance entries; only the separate refined
classification reports high0. Neither count proves runtime safety. Gate logic
and Python programs are unchanged. The next bounded V10-V13 run exposed the dependent refined-register baseline
summary as stale. Regenerating the refined register after the original register
updates the source snapshot to13112/coarse-high3154 without changing its current
refined digest or classifications. Both failed runs are retained; independent
combined reassessment precedes another gate run. Original historical snapshots
remain in Git. Remaining V10-V13 checks and ordinary signed delivery remain
required before the owner handoff.

Private evidence root:
`/home/foo/Downloads/osmap-ux-s08/completion-20261104/outbox-20261108`.
Matching source archive43 digest:
`2d8dc74e1092bbf6b50d280a4b22edf452e9e021023d1e8e3063c7f98475b851`.
Use `native43.log`, `browser2/result.json`, `install43.log`, `readiness43.log`,
the preserved `acceptance*.log` files and `mail-backend-isolated*.log` for the
separate results. Independent source, recovery, confinement-preservation and
installation review is GO. Owner Outbox acceptance remains NOT_RUN and does
not follow from previous scoped S08 passes.

Final bounded V10-V13 validation: `remaining-gates2.log` exits0 after independent combined reassessment GO. All four remaining gates pass, including the current original/refined assumption records and WSTG pack validation. The earlier failed and interrupted runs remain retained. Together with the completed isolated security-check, native43, browser2, install43 and readiness43 results, engineering validation is PASS. Ordinary signed commit/push hooks remain mandatory before publication; Git history and the final fresh-fetch receipt identify that outcome. Owner Outbox UAT remains NOT_RUN.


### 2026-11-08 — specific Outbox failure explanations

Owner UAT FAILED because “Needs your attention” did not explain the blocked
scheduled send. Read-only native metadata confirms personal-key access was
locked at the due-time check, before SMTP preparation or submission. This is
historical evidence, not a claim about the key's present state.

The smallest Rust presentation correction uses each recorded reason in both
the list and detail: locked personal-key access, expired send authorization,
changed account protection, unavailable service, failed key/policy checks,
invalid content or expired payload. Missing reasons remain explicitly unavailable;
stale reasons do not replace unrelated states. Fixed source-owned text provides
the relevant recovery action without exposing native output. Locked-key details
link to Settings and explain that unlocking alone does not restart the message;
Send now or a new authorized send time remains explicit. No scheduler, protocol,
authorization or submission-state behavior changed.

Local focused Rust tests:11 PASS,0 failed,0 ignored. Native45:12 PASS,0 failed,
0 ignored. Actual synthetic Edge browser45:9 PASS, covering Outbox actions, the
recorded locked-key cause/link/no-automatic-retry text, desktop and390px layout.
The first browser diagnostic used an incorrect harness filter; the corrected run
exposed mobile table overflow. Reusing the existing focusable table-wrap fixes
that defect. Both failures remain retained; independent reason and mobile review
GO. No owner messages or schedules were changed or resent during verification.

Matching source45 archive SHA256:
`f7084dc57ed3c36b118a0c44430627b91ebbf3f3c99172a5442e902cb6f169ff`.
Installed main45 SHA256:
`5659e3969d8f556991db1de14045184af04c0cf87147b03fc528a664ac2db87c`.
Web-only install45 verifies the loaded binary and HTTPS login200; nine service
checks and installed read-only epoch readiness45 PASS. Helper/public-mail PIDs,
account/GPG/configuration remain unchanged; rollback is retained. No password
submission, TOTP consumption or credential write occurred. Private evidence:
`/home/foo/Downloads/osmap-ux-s08/completion-20261104/outbox-20261108/reason-20261108`.
Normal publication gates remain mandatory. Owner reacceptance of this correction
is pending; the earlier failed UAT and other scoped passes remain recorded.
Whole S08 acceptance is not implied.

Final reason-correction V10-V13 checks PASS in `remaining-gates45b.log` (exit0).
The first run stopped at the generated inventory checksum register; the two
claims checksums now match the regenerated original/refined inventories. Counts
and classifications are unchanged; gate logic and generators are unchanged.
The original failure remains in `remaining-gates45.log`. Signed commit/push
hooks remain required; Git history and the fresh-fetch receipt establish final
publication. Owner reacceptance and whole-sprint acceptance remain separate.

### 2026-11-08 — owner Outbox recovery UAT PASS

The owner explicitly reports “UAT = PASS” after observing the recorded blocked
reason, “Not sent — personal key access was locked”, and explicitly rescheduling
the same message for 18:30 in the saved UTC+07:00 timezone. The Outbox then
showed Submitted, zero active messages and no retained attempts needing attention.
The Sent copy of “UAT - View message and controls (including edit original msg)”
shows 2026-11-08 18:30:07 UTC+07:00 to lvnv1966@protonmail.ch. The owner’s Proton
Mail screenshot shows receipt at 18:30, the edited readable text and the attached
openpgp-public-key.asc. These observations accept the cause-specific refusal and
explicit recovery/rescheduling path, submission, Sent copy and recipient receipt.
The screenshots do not independently establish cryptographic validity.

This acceptance supersedes the pending reacceptance above for this correction;
the earlier failed UAT remains retained. It does not accept all S08 functionality.
Remaining focused checks are leftover Scheduled-copy discard without removing
Sent mail, cancellation of a future schedule entered in the saved timezone, and
Inbox snooze followed by cancellation and return. No code, deployed service,
schedule or mailbox data is changed by this acceptance record.


### 2026-11-08 — owner whole-S08 acceptance / PASS

The owner confirms: “these have already been done, S08 is a UAT = Pass”.
This explicitly accepts the whole sprint and confirms completion of the previously outstanding checks:

- Scheduled-copy discard removes the source while preserving the Sent message.
- Future scheduling uses the saved OSMAP timezone, removes the source from Drafts, and cancellation remains effective after refresh.
- Snooze removes the test message from the normal Inbox view; cancellation returns it.

These are owner-confirmed UAT results, not newly executed agent tests. This closes S08 and supersedes earlier whole-sprint acceptance-pending statements. Existing engineering, installed QA and independent-review evidence is reused; historical failures remain preserved. Documents remains removed from scope.

This is a documentation-only acceptance record; no code, service, mailbox, schedule, quota, key or configuration changes accompany it. S09 integration, visual and accessibility work and production security review/WSTG remain separate.
