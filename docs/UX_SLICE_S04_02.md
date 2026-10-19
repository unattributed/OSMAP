# S04-02 delivery specification — authoritative own-password change

Status: IN PROGRESS (operator resumed 2026-10-19 with executable guardrails); engineering completion and human acceptance are OPEN.
Project coordination and sole canonical integration/host/Git executor: `/root`.
Independent current source/evidence and delivery-control review: `/root/delivery_controller`;
`/root/password_engineer` owns isolated product source preparation and
`/root/guardrails_engineer` owns the existing validator/tests and isolated HTTP/
backend-bootstrap producer preparation. Prior independent source
reviews remain provenance; authors do not clear their own changed code. This specification applies the operator's
2026-10-16 SOP to the slice already in flight; it does not claim that earlier work
followed this contract or that historical component passes closed the slice.

## Current bounded execution — 2026-10-19

The operator approved codifying environment-bound execution guardrails and
resuming only S04-02 with managed subagents. The existing active ledger's
execution_contract records actual environments, permitted recipes, demonstrated
gaps, exact next action, prerequisites and cumulative allowance. The checked
existing dispatcher invokes the validator with the exact attempt ID before host
execution. No frozen requirement or nine-scenario exit changes. Current T01/T02
source PASS evidence is reused only for its matching boundary; historical PARTIAL
prose below remains provenance. T03/T07 FAIL and all other unrun scenarios remain
open. Historical compiler failures and fresh observations remain retained.
Latest execution18 failed before password mutation at metadata recheck. Fresh
observation and exact owned recovery18 completed and independently passed.
The three-leaf typed contention deferral passes the same old-RED/new-PASS
regression and expiry refusal; native19 and installed workflow remain NOT RUN.
The original7200s allowance ends11:16:12UTC; no new native chain starts if its
full reserved producer/execution/disposition bounds do not fit. Record a revised
cumulative forecast before further execution, retaining all prior spend/failures.

PostfixAdmin is the installed functional reference, not an assumed source of
OSMAP's additional step-up/epoch/session guarantees. Record its observed fixed
hash/update path without reading operator credential material. Existing working
TOTP login is reused; action-bound reauthentication and exact installed password
workflow still require the defined evidence. No operator password mutation or
external provider message is authorized for engineering.

## Current Rust delivery contract — operator resumed 2026-10-18

The operator explicitly assigned subagents to complete S04-02 against the nine
existing scenarios. S04-01 remains accepted; no other stopped slice resumes.
All new workflow/backend application code is OSMAP-owned Rust. Reuse the existing
approved dependencies and fixed bounded MariaDB/Dovecot utilities; no new
third-party dependencies. Preserve the four outcomes,20 obligations and T01–T09
below. Earlier Python workers and HTTP fixture passes are historical references,
not the final Rust implementation or installed qualification.

Reuse the existing form, Rust step-up/rate/session/transport types and truthful
status consumers. Implement a narrow SQL/hash adapter, durable account authority
and fixed native service composition. S04_readiness owns integration/host/Git;
backend and durable-state developers own separate Rust paths; independent review
checks producer, cleanup and actual consumer. No generic SQL/command endpoint or
caller-selected authority. Exact fixed paths/configuration and the original
operation deadline are code/operator-owned, never browser fields.

The SQL adapter returns only a private database receipt. A verified zero-row CAS
refuses without replay. A dispatched write with uncertain result remains contained
and cannot retry or restore. Durable pending state precedes mutation and survives
restart; current authority is rechecked under the shared account lock. Final
success requires real account-specific IMAP/SMTP/cache and browser containment,
old-password rejection/new-password admission and Bob preservation. Dovecot
submission proxy list/kick is the existing utility candidate for TCP ownership;
its actual routing and ordinary-login lock participation require measured source/
host qualification, not a caller assertion or SASL-socket closure.

Testing remains exactly the nine scenarios below. Reuse matching T01/T02 and
unchanged Rust evidence. One successful installed controlled journey may supply
T03/T06/T07/T08 observations; T04 replay/races/limits and T05 interruption have
distinct checks. T09 owner usability follows all agent-owned passes. No operator
credential mutation or external provider email during engineering. No automatic
push/synchronization is authorized by this resumption.

The prior HTTP9/10 narrative and source-specific findings below are historical;
HTTP24 fixture PASS and HTTP25 Bob-login FAIL remain retained in the ledger.
Neither qualifies the replacement Rust service or the installed pair. This
contract does not reset investigation costs, native deadlines or failure history.

## Authority and scope

Preserve accepted R2 `6b3ce8fff27ca3dabf87039d54098bd9967a2e42`, signed R3
`f2a117c17dbd93b634f9914c5608473dc682d8e0`, the frozen slice catalogue,
D04 in `UX_DECISIONS.md`, 110 legacy cases and 403 approved controls. This is
an execution specification, not an amendment to product requirements.

The exact 20 obligations are UX11-002/003; R2-10-005/009;
R2-20-001/002; and R2-22-001 through R2-22-014. They remain mapped to the four
outcomes in the active `UX_EXECUTION_LEDGER.md` work order:

- **authoritative-native-password-workflow:** a verified own-account credential
  update with exact backend authority and mail containment.
- **fresh-stepup-and-session-containment:** current password plus fresh,
  replay-protected TOTP; action-bound authorization; shared lock/epoch and actual
  revocation of all the changing account's browser sessions.
- **password-form-and-navigation:** a working, accessible form, independent
  visibility controls, safe cancellation and truthful outcomes.
- **actual-password-status:** authoritative changed-at information, with absent
  or incomplete information explicitly Unknown or incomplete.

Recovery-contact management and TOTP enrolment/rotation belong to their existing
slice ownership. This slice consumes TOTP for step-up; it does not complete those
separate workflows. S08-02 remains accepted. No full S04 or epic closure follows.

## Design and observable behaviour

The user opens Change password from Security or Authentication & Recovery.
`GET /settings/password` displays the current-account form. Current password,
new password, confirmation and fresh TOTP are submitted by the existing
CSRF-protected `POST /settings/password`. Breadcrumbs and Cancel navigate without
submission. Each Show/Hide control changes only its associated field, preserves
accessible state and keyboard operation, and causes no network submission,
clipboard access or password persistence. Pasting a passphrase is supported.

The browser Runtime must delegate the actual operation through
`BrowserGateway::change_own_password`, the qualified admission/mutation clients
and `PreparedPasswordCoordinator` to the authoritative backend. A concrete
helper test does not establish Runtime delegation. The web process receives no
SQL credentials, arbitrary command capability or private backend files.
Unqualified backend capability stays disabled with an honest explanation; that
is an open implementation state, never a completed form.

The backend validates current password and fresh TOTP before authorizing an
own-account action. Its single-use permit binds request, account, session,
source, action and epoch; consumption rechecks current authority. A single-use step-up expires when its age reaches
300 seconds; validity never extends beyond 300 seconds. Durable independent limits are five failures/account and
ten/source in 15 minutes, with a 15-minute cooldown. Success or restart cannot
erase an active failure window. Login and session issuance use the same durable
account lock/epoch as mutation. Missing or stale authority refuses before write.

D04 password policy is 15–128 Unicode characters, at most 512 UTF-8 bytes, no
control characters, no silent truncation or mandatory composition rules; reject
unchanged input and mismatched confirmation. Use the supported authoritative
salted hash and one conditional credential update. OSMAP is not a second password
database. Verify changed credentials and authoritative changed-at information. When the
write is verified but containment is incomplete, retain the actual performed
write time together with explicit incomplete status; unknown timing stays Unknown.
A newly confirmed change requires a verified authoritative changed-at timestamp;
missing new timestamp keeps the status outcome and slice open. Only absent
historical/prior data may remain Unknown without inventing a timestamp. Generic
mailbox `modified` is not a password epoch or proof of a password change.

A successful outcome includes actual browser revocation, including the current
session, required account-specific IMAP/SMTP session and cache containment, old
credential rejection and new credential admission. Preserve Bob's credential,
epoch, sessions, connections and mail. A transport receipt, SQL write or health
check alone cannot report overall success. Lost or incomplete post-write effects
leave the account contained and the UI/audit explicitly incomplete, requiring
reconciliation. Never automatically repeat an ambiguous write or restore the
old password.

Current/new/confirmation passwords remain only in bounded request/helper memory;
never put them in arguments, environment, logs, evidence, drafts or persistent
browser storage. Retain only safe outcome metadata. Use the existing fixed peer,
source, command, loader, grant, original deadline and cleanup boundaries. Any
implementation adjustment is recorded with its reason, affected tests and actual
result in the existing decision log and ledger; changing product/security
requirements follows the existing amendment process.

## Test conditions and planned verification

Root prepares disposable Alice and Bob, temporary credentials and controlled
mail/connections. No agent changes Duncan's password, keys or policies. Frontend
validation is obsd1 `192.168.1.44`; authoritative backend validation is Toronto
`mail.blackbagsecurity.com` `216.128.179.75`. Label host evidence correctly.
Public provider delivery is not part of password qualification; issue no
MAIL/RCPT/DATA/BDAT or provider email. Keep operator accounts and unrelated
services/configuration/mail intact.

Pin assessed source, helper/app binaries, configuration and fixture projections.
Source, private native composition and matching installed-pair evidence are
separate. A disposable SQL/Dovecot fixture does not establish production grants,
configured paired transport or a working installed Runtime. Before installed QA,
qualify the actual trusted startup, paired service authority and containment
configuration; do not enable the form by setting qualification booleans.

The machine-readable `slice_contract.tests` in the active ledger is the execution
register for the following finite scenarios. It contains prerequisites, action,
expected result, preserved state, owner/reviewer, layer and retained result.
Every listed test is required. Existing exact evidence may be reused after
source/configuration/scope reconciliation; do not repeat unchanged whole suites.
Run changed-boundary checks and mandatory normal hooks, not 403 cases by default.

- **S04-02-T01 — form and field interactions (source):** exercise all three
  independent Show/Hide controls, keyboard/accessibility, paste, entry links,
  breadcrumb and Cancel. Expect only the selected field to change visibility;
  zero submission, clipboard reads or persistent password writes on local
  controls/navigation. Preserve unrelated fields and account state.
- **S04-02-T02 — form refusals (source):** wrong origin/CSRF/session/account,
  malformed form, policy boundaries, mismatch and unchanged password. Expect
  bounded truthful refusal, no credential/session mutation and no fabricated
  changed-at timestamp. Preserve other accounts and sensitive-value exclusion.
- **S04-02-T03 — real composed native change (native):** actual stored sessions,
  trusted admission, current-password/TOTP step-up, conditional update, epoch,
  IMAP/SMTP/cache containment, old rejection/new admission and Bob preservation.
  Expect one verified change, all required revocations, positive actual flush
  witnesses, exact completion/reap and owned disposition. This scenario currently
  FAILS; historical local component passes do not override that result.
- **S04-02-T04 — pre-write authority, replay and races (native):** age299/300 boundary (valid at299 only if all other checks pass; refused
  at300), consumed permit/TOTP, wrong binding/current password, durable
  account/source limits across success/restart, stale epoch and concurrent
  issuance/mutation. Expect refusal before write, no second dispatch and no
  authentication through a locked/stale epoch; preserve Bob and active limits.
- **S04-02-T05 — post-write uncertainty and recovery (native):** interrupt a
  required cleanup/response after the one controlled update. Expect contained,
  explicit incomplete outcome, old-cookie rejection, no automatic SQL replay
  or credential rollback, and independently verified safe reconciliation and
  owned cleanup/retention. Preserve the measured authoritative state and Bob.
- **S04-02-T06 — installed frontend-to-backend journey (deployed):** install the
  matching qualified pair through existing reversible gates and use the actual
  browser Runtime with controlled accounts. First verify the matching browser
  entry links, three independent Show/Hide controls, keyboard/paste and Cancel
  without unintended submission or password persistence; then complete the
  change. Expect the complete T03 behaviour through the configured paired
  services, truthful UI and persistent reload results. Preserve operator state and unrelated services; verify recovery.
- **S04-02-T07 — truthful status (deployed):** inspect Security and
  Authentication & Recovery before/after confirmed change and incomplete/refused
  outcomes. Expect authoritative changed-at for a verified credential write, including
  verified writes with incomplete containment; missing history/timing stays
  Unknown only for absent historical/prior data; a newly confirmed change needs
  a verified timestamp or the test fails. Incomplete effects remain explicit. Never
  derive password state from a generic mailbox timestamp or a receipt alone.
- **S04-02-T08 — installed isolation and secret exclusion (deployed):** exercise
  cross-account/stale/CSRF refusal, current/other Alice sessions and Bob's live
  sessions/mail; inspect bounded retained metadata. Expect no unauthorized
  update, no old-session authorization after confirmed change, Bob unchanged
  and no password values in logs, URLs, retained artifacts or browser storage.
- **S04-02-T09 — minimum owner usability acceptance (human):** only after all
  agent checks and independent audit pass, review navigation, field visibility,
  cancellation and the meaning of confirmed versus incomplete outcomes on the
  matching installation. Use one concise script and existing observations;
  no troubleshooting, repeated engineering QA or unnecessary real password
  mutation is assigned to the owner.

## Existing evidence to reuse, with its limits

The signed765446e normal gate log already records source PASS for
`password_change_tests::independent_password_policy_boundaries_unicode_confirmation_controls_and_unchanged`
and `password_change_tests::permit_rejects_exact_300_second_boundary_clock_rollback_and_changed_bindings`.
The same retained log includes stored-lease/worker completion and browser-cleanup
source controls. These are scoped source evidence available to reconcile with
T02/T04/T05; they do not establish the complete native/deployed scenarios.
Do not rerun unchanged tests merely to fill a new row or promote their aggregate
pass count to the slice's required integration results.

Read-only QA reconciliation classifies T01 and T02 as PARTIAL at source scope.
Rendering/CSP, mocked route refusals and selected policy/results assertions have
executed evidence; DOM/keyboard/paste/populated Cancel and some complete route
boundaries remain unexecuted. These scoped passes do not establish real backend
preservation or matching installed browser behaviour. Retain the gaps in the
ledger test rows; no aggregate pass is promoted to full scenario acceptance.

## Current findings and remaining work

Signed source checkpoint `765446e49210ffe9bddc7ca19e576828e7e8285d` is
synchronized; installed pair324b and production account-client/form activation
are unchanged. Actual native HTTP9 fails at an original proxy child terminating
with signal11 and 97 stderr bytes. HTTP10 fails earlier at Bob login response
handling. Neither unique cause is established. Both failures, independent
combined review3644742f and earlier failures remain retained. Required composed
native change, installed paired QA and parent-slice completion are OPEN.

A source-confirmed fixture TOTP scheduling gap is repaired in frozen source23,
with one forced-rollover discriminator and independent source review775c4a80.
It does not diagnose HTTP10 or repair HTTP9. Closed original-result diagnostics
and bounded carrier staging are qualification prerequisites, not user features.
Next: admit this slice contract and its executable checks, finish matching
changed native qualification, repair the actual backend failure, complete and
install the trusted Runtime/form/status path, then execute the remaining
applicable tests and independent audit. Never equate a checkpoint with closure.

## Definition of done

Engineering completion requires all 20 mapped obligations and four outcomes,
all required non-human scenarios, matching installed functional QA, independent
security/functional audit with no unresolved required findings, truthful
persistent status and verified recovery/disposition. Every PASS references
matching executed evidence. FAIL/PARTIAL/UNKNOWN/unrun required work keeps the
slice open. Generic builds, test totals, documents and service health do not
satisfy this definition.

Human acceptance is separately recorded only after that engineering gate. A
minimal owner usability PASS then permits S04-02 ACCEPTED and corresponding
issue updates. Other S04 slices and the epic retain their own closure criteria.
