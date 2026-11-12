# S04-04 — User access recovery and authenticator replacement

Started 2026-10-29 (America/Toronto) from accepted S04-03 source
`6c509a542dfc30129e23b838b1faf7cd01608f4e`.


## Owner acceptance — 2026-10-30 (America/Toronto)

**S04-04 positive browser UAT: PASS. Current revised slice: ACCEPTED.**

The owner explicitly confirms that the user completed the login recovery workflow,
received the registered-address recovery email, verified the one-use code, reset
the password, enrolled and validated the replacement TOTP, saw **Access updated**,
and signed in successfully to the mailbox with the new values. The eight supplied
screenshots and confirmation are preserved privately; raw images include setup
material and codes and are excluded from Git. No displayed secret was decoded or
used by an agent.

Read-only corroboration observes active epoch5 and the corrected native stages:
actual SQL receipt recorded, protected cache-zero recheck confirmed and new-password
authentication confirmed. This later successful browser journey is distinct from
the preserved earlier503 and its one-shot administrative repair at epoch4.

| Work package | Required scenarios | Actual evidence and completion |
| --- | --- | --- |
| Replacement enrollment | T02/T05/T07 | Source/native candidate, session and factor-reader controls; owner verified the replacement and logged in. Complete for accepted scope. |
| Login recovery | T01/T02/T04/T07 | Registered email receipt, proof, actual password/TOTP update and fresh login; native post-write stages confirmed. Complete. |
| Native commit and interruption | T03/T05/T06/T07 | 109 native component passes, root qualifier, actual retained partial-state failure and exact repair; later successful normal commit. Complete. |
| Installed browser journey | T08/T09 | Matching deployed5e3ebb5 code, eight private screenshots and explicit owner UAT PASS. Accepted. |

Acceptance is for the current selected-account local-development/UAT profile on
obsd1. Separate human execution of signed-in Settings replacement and a human
old-factor negative attempt is not shown in this screenshot set; source/native
controls remain their stated evidence. No such human execution is invented or
required as an additional acceptance ceremony. The functional UAT PASS does not
make the setup material shown in screenshots private again; replace that entry
privately through Settings. Automated onboarding remains a separate sprint;
S05-02 and the whole Sprint/epic remain outside this acceptance.

## Current operator-directed scope — 2026-10-30

The operator rejected the request-only Settings experience and the multi-terminal
fixture procedure. The following current contract supersedes the older
operator-only recovery, no-login-change and no-new-dependency restrictions below
for this slice. Historical results remain historical and are not reclassified.

Deliver two working browser journeys:

1. In Settings, freshly confirm the current password and TOTP, show a new secret
   and locally rendered QR, then validate the new six-digit code before replacing
   the active factor. An incomplete or invalid candidate preserves the old factor.
2. From a login-page recovery link, enter the account email, receive a one-use
   expiring code at its existing registered recovery email, and verify that code.
   Permit only password recovery and replacement-authenticator setup until the
   replacement code validates; finish with a fresh ordinary sign-in. A recovery
   request alone cannot change a credential or admit a mailbox session.

Onboarding is a **separate sprint**: initial TOTP enrollment, issuing saved
one-use backup codes and recovery-email verification are excluded here. New
accounts are onboarded manually for now. This slice must not introduce an
onboarding wizard, provision users or require newly issued backup codes.
Existing manually established account/factor/recovery-contact prerequisites
remain explicit. No S05-02 work is included.

Root owns integration, Git and any host action; recovery_engineer owns candidate
and native factor replacement; recovery_policy_review owns one-use recovery
proofs and protocol; recovery_qa owns browser forms/routes and independent
review. Reuse the existing account service, bounded private stores, factor
verification and password CAS writer. No new daemon or general command channel.
Use one small QR encoder instead of maintaining QR mathematics or an external
secret-rendering command pipeline; review and pin it through normal dependency
admission.

The revised packages and required scenarios are:

| Package | Required T0# scenarios | Completion evidence |
| --- | --- | --- |
| Replacement enrollment | T02/T05/T07 | Actual candidate store, current-factor reauthentication, valid new-code activation, stale/foreign/replayed candidate refusal; old factor preserved until success. |
| Login recovery | T01/T02/T04/T07 | Registered-destination delivery, generic account response, expiry/attempt/rate limits, one-use recovery proof, restricted setup, actual password reset and fresh sign-in. |
| Native commit and interruption | T03/T05/T06/T07 | Real epoch/factor/session boundary, durable attempt before effects, old sessions refused after completion, no automatic ambiguous write retry, unrelated accounts preserved. |
| Installed browser journey | T08/T09 | Matching signed artifacts and configuration, independent functional/security checks, concise human UAT; source-only tests cannot close it. |

Implement -> test -> preserve/analyse any failure -> smallest supported correction
-> retest the affected boundary -> advance. Revised-flow source/native/installed
results start NOT_RUN. Required negative checks include CSRF/origin, malformed or
cross-account fields, expired and replayed proofs, concurrency, delivery failure,
secret-free diagnostics and inability to use a recovery grant for mail.
Source work is authorized; live credential writes remain scoped actual actions.
No public mail daemon restart, configuration change or downtime is required.

### Existing-account prerequisites and installation

This revision uses accounts that already have a password, active TOTP and a
verified recovery contact. Initial onboarding remains manual. The privileged
service reads `/etc/osmap/account-runtime/access-recovery.json` (root-owned,
0600), containing version 1 and `contacts` entries with `account`, `email`,
`revision` and `verified_at`. The administrator registers destinations already
verified during manual setup; a browser cannot choose this address. The existing
Web contact record acts only as a veto: removal, mismatch or unsafe storage
prevents use of a stale destination. It cannot promote a new privileged address.
Updating this trusted registration is an administrator task until the separate
onboarding/contact integration sprint supplies its own qualified flow.

Prepare `/var/db/osmap-account/access-recovery` as root-owned 0700 and preserve
the configured runtime-owned 0700 session, factor and revoked-factor directories
before enabling that file. The native service checks them before sealing, uses
the actual Web environment paths, local account endpoint and rollout selection,
and refuses a changed frontend fence until configuration is reconciled.
Only the optional recovery profile adds fixed-loopback SMTP and ownership-change
syscalls; child execution promises and the ordinary no-recovery profile remain
unchanged. No public mail configuration or mail-service downtime is needed.

Recovery mail is submitted only to the existing `127.0.0.1:25` MTA, requires its
advertised DSN capability and requests `NOTIFY=NEVER`. A queue reply is distinct
from delivery to the recipient. The registered recipient must confirm actual
receipt in installed qualification. Source-native proof stores and replay
records have fixed capacity; throttled sources are rejected before the common
account-response delay. One recovery exchange leaves ordinary mutation/admission
capacity available.

Focused local evidence currently covers candidate8, native-adapter8, account
state9, physical session12 (plus one historical ignored native test), browser
routes9, authenticator4, actual Runtime/socket2, core17, protocol10, SMTP3,
read-only contact consistency2, capacity1, and composed service2. These are
source/temporary-file results, not installed recovery or UAT acceptance. The
single new ignored mixed-owner qualifier uses an actual OpenBSD pledge/unveil
seal and freshly owned synthetic files; its native execution is still NOT_RUN.
The two composed service tests initially exposed fixture errors: malformed code
outside the wire schema, inconsistent synthetic/current clocks and an absent
existing verified-contact record. Independent reassessment supported the
fixture-only corrections; the affected composed boundary then passed 2/2.
Normal mandatory delivery gates and installed qualification remain required.

The first full local delivery run exposed two test assumptions: a one-second
fixture deadline was exhausted before the intended peer check, and the old login
assertion forbade the newly required recovery link. The focused corrections
preserve production deadlines and all normal login requirements. The second run
observed 2,065 Rust passes, zero failures and 74 explicit ignores, then stopped
when the TLS guard enumerated an unstaged deleted route. Staging the reviewed
source inventory resolved that failure. Its next findings were the new authority
identifier matching the guard's global cipher-word rule; the unpublished protocol
now consistently calls that authority `Unauthenticated`. The unchanged TLS guard
and refreshed V10 registers pass. Original failed gate logs remain preserved;
these constituent results do not turn either failed aggregate into PASS.
The first normal push then stopped at the password SQL adapter's source-review
pin. Independent review confirmed that recovery reuses the same fixed programs,
query shapes, conditional write and uncertain-outcome handling; ordinary password
change retains its existing proof checks. Only the exact reviewed adapter digest
was renewed. That push failure remains distinct from source and native results.
The affected guard then identified the new external test module's fake SQL input.
Independent review confirmed its sole `cfg(test)` registration. Its exact
parent/marker coupling was added alongside existing external-test registrations;
the coupled regression also checks that losing `cfg(test)` restores rejection.
Production scanning and the guard algorithm remain unchanged.




### Current native qualification checkpoint

The first signed browser-recovery source checkpoint passed the normal commit and
push hooks and was preserved at `efd41d19cd9f3ef5a2ed9eb41afce009515c812b`
with fresh exact remote parity. Native compilation of all three binaries and the
seven affected component groups passed. The first sealed mixed-owner qualifier
then failed before effects at `snapshot_current_code` with `StateUnavailable`;
its synthetic fixture and fixed failure receipt were retained.

A read-only native discriminator observed successful libc `realpath`, direct
private-directory open and unchanged held-directory identities. Pathname stats
of the deliberately hidden ancestor directories returned ENOENT after unveil.
The supported correction uses the existing held custody witnesses for those
ancestor checks, preserving the callers' ownership and mode requirements and
refusing an uncaptured ancestor after sealing. The earlier Python realpath
probe also failed under unveil, but that implementation differs from libc and
is not the Rust failure's cause. Focused corrected-source checks pass 28 tests (two existing native-only ignores),
and all-target Clippy passes with warnings denied. Rebuilt native components and
the corrected sealed mixed-owner qualifier then passed on source
`4d00385ca49c4be8f60651dc2baf98e528d4f195`. Its normal delivery gate and fresh
remote equality passed. The first installation completed in 16.735 seconds:
matching three binaries, actual loaded Web/helper inodes and unchanged protected
state except the planned configuration/directories. Only the two OSMAP roles
were restarted; the Web environment and public mail services were preserved.

The first installed public HTTPS test passed login/recovery form, secure cookie,
unauthorized setup, origin and extra-field controls, then received 503 for the
synthetic unknown-account start before the response floor. No registered
recipient, normal session or credential operation was involved. Native proof
state remained empty. Independent source analysis and a read-only native probe
identified the recovery configuration reader's reused OpenPGP pathname-ancestor
checks as incompatible with the exact seal. The supported follow-up is a fixed,
recovery-local reader using held ancestor witnesses and the same protected leaf
contract, with an actual sealed reader proof before another public-boundary
execution. This installed failure remains separate from the earlier qualifier
failure and from accepted constituent controls. No live account operation
occurred.

The localized configuration reader and its callers pass 15 affected tests and
all-target Clippy. The existing ignored qualifier now exercises the actual
reader under the seal, including exact byte readback and a mode-0640 refusal.
Independent review approved the fixed path/custody reader and failure-only stage
diagnostics. Review also restored the existing service module's `cfg(unix)`
attribute after adding the new reader module. The rebuilt source
`2cdaf8c6d986cb47ed9f7af34ab94db31f4fce53` passed all eight
native component groups and the actual sealed configuration-reader/factor
qualifier. The ordinary push gate passed 2,069 Rust tests with zero failures and
74 explicit ignores, plus its remaining required checks; fresh remote parity
was exact. Source analysis does not retrospectively supply the original 503's
missing runtime-stage observation.

The binary-only refresh then passed in 16.682 seconds, preserving the existing
configuration, environment, state and archive. Its exact three artifact hashes
and loaded Web/helper inodes were read back. The affected installed HTTPS test
passed all eight controls: login link/fields, private recovery form/cookies,
restricted setup denial, origin refusal, extra account-field refusal, real native
generic unknown-account response, fake-code refusal and no ordinary mail session.
The original failed public run remains preserved separately. A final read-only
observation found all 17 service roles healthy and all 54 Web environment fields
loaded as configured.

This qualifies the installed public boundary and synthetic native effects on the
current selected-account local UAT profile. Actual receipt at the registered
recovery inbox, successful real-account password/factor recovery and fresh sign-in,
and signed-in authenticator replacement still require private browser UAT. The
operator has been given the concise browser journey. No owner acceptance or
whole-slice completion is recorded in its absence. Onboarding remains manual and
outside this sprint. The original checkout's deferred S05-02 HEAD, status and
seven file hashes were independently rechecked unchanged.

## Owner UAT failure and browser-origin correction — 2026-10-30

Owner UAT failed both journeys: the signed-in replacement submission was refused,
and the public recovery submission was refused without a received recovery email.
The previous authenticator still allowed normal login. The actual server trace
shows successful GETs followed by immediate POST 403 responses, rather than a
failed Settings GET. No replacement activation is evidenced by those requests.
The earlier UAT-ready assessment exceeded the anonymous test's coverage.

A fresh isolated browser reproduced the live recovery form's POST 403 with
`Origin: null`, ordinary URL-encoded content and no manually supplied headers.
The response used the global `Referrer-Policy: no-referrer`; the Fetch standard's
Origin serialization explains this browser behaviour. The strict recovery origin
check rejects the browser-generated value before native/email dispatch. The
previous Python probe supplied the HTTPS Origin itself, so its eight passes did
not qualify native browser form submission or either positive owner journey.

The supported correction is response-only `Referrer-Policy: same-origin` on
rendered recovery/TOTP form pages. Global defaults, errors, completion pages,
strict origin rejection and CSRF validation stay in force. Owner acceptance is
FAIL until affected browser and owner tests pass. Onboarding remains manual and
separate; S05-02 remains deferred.

Affected route tests pass 11/11, including a production-issued stored session's
GET/form/CSRF round trip and missing/null/foreign-origin refusal. SMTP transaction
and bounded audit tests pass 5/5. All-target Clippy passes after correcting an
explicit production import that a test-only parent import had masked; its initial
failure is preserved. Local POST refusal events now record a generated request
reference and static refusal reason. Native SMTP emits independent, non-authorizing
attempt/outcome references and fixed phase/disposition fields, without account,
recipient, code or message contents. Queue acceptance remains distinct from actual
recipient receipt. Logging or audit-reference failure cannot gate mail or retry it.
The correction is installed from signed source `a77bb9c`. A real isolated browser
now follows the login link and submits its native recovery form with the expected
HTTPS Origin, receiving HTTP 200 and the email-code page. No headers were forced.
This synthetic unknown-account check qualifies form submission only. All eight
native component groups pass (106 unique tests, including one audit-interleaved
pass corrected in an additive receipt), and the sealed root qualifier passes.
The normal push gate passes 2073 Rust tests with zero failures and 74 ignored.
The refresh preserves all 745 protected records byte-for-byte and restarts only
the two OSMAP roles. Onboarding and S05-02 remain unchanged.

The subsequent owner attempt confirms recovery email receipt, proof acceptance
and replacement setup display. Its final confirmation returns HTTP 503. Read-only
reconciliation finds `FactorReplaced` / `PasswordReset`, Pending at the original
epoch, 19 revoked browser sessions and an authoritative password modification
matching the dispatch time. The replacement factor matches the durable case.
This is a partial committed update, not a pre-dispatch refusal; no credential
operation is repeated. Source diagnosis finds that the new recovery callback
requested a cache flush through a stock primary role that intentionally cannot
execute that command. The ordinary stock password flow instead rechecks its
protected cache-zero witness. The correction now passes 3 focused service tests, 9 factor-adapter tests and
one actual stock command-mapper test. Production supplies the typed StockPeer;
no executor permission is widened. The actual verified SQL receipt is now saved
to both the case and Pending epoch before cache/authentication checks, and fixed
stage diagnostics preserve later failure boundaries. All-target/all-feature
Clippy passes after a logging-only `inspect_err` correction; the initial lint
failure remains retained. Signed source `5e3ebb5` passes the normal push gate
with 2076 Rust tests, zero failures and 74 ignored. The exact native artifacts
qualify 109 unique component tests plus the sealed root check. An initial native
job stopped before compilation because the temporary filesystem was full; three
completed PASS test copies were preserved on the home filesystem before removing
their old temporary copies. A subsequent socket fixture exceeded OpenBSD's path
limit under a long home TMPDIR. Its original failure is retained; only that
9-test group and the previously unrun mapper test were executed again, using the
same libtest and a short private home directory. The seven passed groups and
compilation were not repeated.

The corrected binaries are installed. Only the two OSMAP roles were restarted;
the refresh's protected records are byte-identical and no account operation was
performed by installation. A separate reviewed, one-shot administrative repair
then revalidated the exact failed case, marker, factor/archive hashes, original
19 revoked sessions, authoritative password row and protected cache-zero
configuration. It recorded the existing SQL timestamp, completed the same owned
epoch from 3 to 4, removed its exact marker and marked the same case and Processing
grant Complete. The repair performs no SQL credential, factor or session rewrite
and creates no grant or session. Independent readback confirms active epoch 4,
marker absence, unchanged password/factor and all original revoked records.
Original primary-password verification remains NOT_CAPTURED; the repair does not
retroactively claim it passed. At that checkpoint owner acceptance was still pending. The later complete
owner journey and explicit PASS are recorded in the acceptance section above;
the original failure and administrative repair remain historical evidence.


## Historical observable outcome and authority

Deliver the D04 controlled recovery coordinator: requested -> identity reviewed
-> contained -> sessions revoked -> factor replacement -> reconciled. The
operator explicitly authorized subagents, implementation and focused verification
using work package -> required T0# scenarios -> actual evidence -> completion.
Preserve accepted S04-02/S04-03, independent human identity/terminal decisions,
mail availability, existing OpenPGP bindings and unrelated account state.

The initial supported case is a lost authenticator with an existing canonical
mail account and active factor, without suspected password/account compromise.
Suspected compromise requires separate account/mail containment and manual
review. Existing tools require independently signed
identity authorization and private terminal confirmation. Agent custody of a
disposable account qualifies rehearsal only. Recovery-contact possession cannot
authorize recovery or replace identity verification. Missing-factor, already
partial and lost-password cases remain explicit manual reconciliation until an
actual reviewed adapter supports them. Do not weaken the current-password rule
of the accepted own-account password service to implement password recovery.

Source development and nonsecret controlled tests are authorized now, including
isolated obsd1 compiler/temporary-store tests needed to establish native API
behaviour. Such tests must not invoke configured live account operations.
Root owns Git and the single host/native queue. Native credential/factor effects
require an exact reviewed target/account/action and action-specific operator
authorization before dispatch; never mutate the owner's credentials on the
basis of this source-development instruction. Production/Vultr and external
mail are outside scope. Preserve the existing private-terminal requirement.

## Actual starting state and design

- Legacy SSH TOTP recovery verifies a signed operator attestation and requests
  private-terminal confirmation, but does not perform or independently verify
  account containment or session revocation.
- Its controlled rehearsal requires stopped Web and an older session schema;
  it is not a current no-downtime qualification path.
- The Rust account epoch store already enforces durable Pending/Contained
  admission refusal. Password completion requires a real verified password
  write; factor recovery must not fabricate one.
- Current SessionService supports account-scoped session revocation. The new
  coordinator must compose real operations, preserve a durable case before
  effects and retain uncertainty after interruption.
- The web process must gain no SQL credentials, general command channel or
  operator recovery authority. Use operator-side typed operations and existing
  private stores/tooling. No new dependency or general QA framework.
- Settings must show authoritative factor state/last use or explicit unknown,
  and direct Manage TOTP to the actual supported lifecycle. A help page or
  disabled control alone does not satisfy the slice.

Persistence uses bounded, account-scoped private records and existing atomic
locking primitives. Case/account/factor/epoch identity and revision must be
checked before every consequential transition. Persist an irreversible-attempt
state before factor effects. Failures before release retain containment; an
interrupted release has UNKNOWN actual containment until read-only reconciliation.
Neither condition permits automatic replay or
old-factor restoration. Export bounded source-owned diagnostics only, never
credentials, factor material, proof values or raw native output.
All unsafe OS interfaces stay in the existing reviewed `src/openbsd.rs` boundary;
recovery modules use its safe descriptor/identity/input wrappers.

## Ordered work packages and measurable exits

| Package | Owner / dependency | Required scenarios and exit |
| --- | --- | --- |
| WP01 — Cases and identity policy | root + independent policy reviewer | T01/T02 policy and actual tooling interfaces reviewed; supported and manual cases explicit; no fabricated human attestation. |
| WP02 — Request and authorization | recovery engineer; WP01 | T01/T02/T07: durable account-bound case admits only valid independent authorization; invalid/stale/replayed/foreign authorization has no recovery effects. |
| WP03 — Containment and sessions | root + recovery engineer; WP02 | T03/T07: actual admission refusal and account-scoped revocation, independent readback and unrelated-account preservation. |
| WP04 — Credential/factor integration | recovery engineer + root; WP03 | T04/T05: supported adapter performs actual factor transition with private human decision; no false password-reset claim or automatic restore. |
| WP05 — Interruption/reconciliation | engineer + independent QA; WP02–04 | T06/T07: interruption at changed effect boundaries has truthful durable state, no blind replay and explicit manual escalation. |
| WP06 — Installed journey/acceptance | root + independent QA/security; WP01–05 | T08 engineering and normal signed delivery pass before T09 human acceptance; all six original controls remain required. |

## T01–T09 scenario contract

Each scenario records source, native and installed evidence separately. A local
case/state test cannot make the integrated scenario PASS. Planned tests are
NOT_RUN. Scoped passing observations may be reused only with unchanged relevant
source/configuration. Subcases distinguish materially different boundaries.

| ID | Prerequisite and action | Expected and preserved result |
| --- | --- | --- |
| T01 | Supported controlled case and independently reviewed identity policy; admit a valid decision and reject absent/insufficient evidence. | Correct case proceeds; refusals leave account/factor/session state unchanged. Controlled custody is not real identity proof. |
| T02 | Bound account/case/epoch/factor and authorization; exercise foreign, stale and replayed decisions. | Only the exact current case admits; duplicate or mismatched operations do not dispatch. |
| T03 | Authorized case and actual account/session stores; contain and revoke account sessions. | Admission refuses during recovery, prior sessions are unusable and another account remains valid; incomplete effects stay contained. |
| T04 | Supported recovery case; verify password authority and the post-recovery password journey. | Factor-only recovery preserves authoritative password state. Existing own-password change remains usable after recovery. Lost-password reset remains unsupported/manual unless separately implemented and qualified. |
| T05 | Contained case, revoked sessions and human private-terminal decision; replace factor through actual adapter. | Replacement works, obsolete factor refuses and no old factor is automatically restored; password and other accounts remain preserved. |
| T06 | Changed persistence/effect boundaries; interrupt before and after dispatch and reopen the case. | Durable state distinguishes no dispatch from uncertain effects; no automatic repeat; read-only reconciliation and manual escalation remain explicit. |
| T07 | Changed coordinator/Settings boundaries; exercise isolation, malformed input, races, authorization and applicable HTTP protections. | No cross-account operation/disclosure or secret persistence/logging; errors are bounded and truthful. |
| T08 | Matching signed source, native artifact and installed configuration; exercise actual operator/application journey and Settings entries. | Actual factor state/last use or explicit unknown, working lifecycle entry, restart persistence, audit reconciliation and preservation; page assertions alone are insufficient. |
| T09 | All required engineering and independent review pass; authorized human judges identity and completes concise acceptance. | Exact human observation recorded separately; no agent-generated acceptance or production/general recovery claim. |

Original obligations: R2-10-004, R2-10-008, R2-20-003, R2-20-004,
R2-20-009 and R2-23-010. D04 coordinator and approved slice native/identity
requirements apply in addition to those visual-control mappings.

## Failure loop, delivery and effort

Implement -> test -> preserve/analyse failure -> smallest supported correction
-> affected-boundary retest -> advance. After two failures at one boundary,
root and independent reviewer reassess the actual cause before another changed
attempt. Preserve failures separately from cleanup and account-state certainty.
Use bounded local operations, focused tests and the normal delivery gates once
at the delivery checkpoint; no repeated unchanged broad suites. Initial source
integration checkpoint is 90 minutes of measured work, not an authority expiry;
record actual/UNKNOWN costs and concrete blockers rather than inventing budgets.

Retain sanitized evidence under `/home/foo/Downloads/osmap-ux-s04/`.
Root owns exact-owned cleanup; uncertain resources are retained. Verify required
checks, independent review, Shopkeeper signature and fresh remote parity before
source delivery claims. Native, installed, UAT_READY and ACCEPTED remain separate.

## Current results

WP01 policy/interface discovery is complete at source scope. Independent review
confirmed D04's existing lost-authenticator case and the separate human identity
decision. Read-only obsd1 observation confirmed the current account-runtime
configuration schema and active custom session/factor/settings directories under
`/var/lib/osmap-s04-02/state`. The adapter now reads literal path assignments
from the fixed root-owned service environment instead of assuming older defaults.
The measured environment is0640 root:runtime-group; the reader permits0600 or
0640 with that exact runtime GID, retains single-link/root ownership checks and
does not change installed permissions.

WP02–WP05 source implementation now includes a root-only `account-recovery`
binary, durable case/marker/epoch binding, actual account-scoped session
revocation and factor archive/replacement readback. `factor_replacement` is
durable before the irreversible attempt. `release_pending` precedes epoch release;
after an uncertain release, status reports the actual epoch separately from the
unfinished case rather than claiming the account must still be contained.
Factor-only recovery preserves the authoritative password-change timestamp.

The new signed `osmap-account-recovery-identity-v1` decision establishes initial
identity admission without pretending containment/revocation have already run.
Legacy recovery approval semantics remain unchanged. The workstation adapter
verifies the pinned signature, obtains private-terminal consent, invokes actual
native containment/revocation, prepares exactly once, uses existing guarded
factor tools, and obtains a separate final RECONCILE decision. It never signs
an approval. Controlled custody produces a distinct rehearsal result.

Both Settings destinations now link to authenticated authenticator management.
The ordinary Runtime reads actual factor metadata and the preserved account
replay counter. The counter is labelled a last accepted account time window
that may predate the current factor, never an exact verification timestamp.
An own-account CSRF-bound request writes untrusted Requested state only; native
publication supplies the actual operator case projection. Those UI records are
never consumed as recovery authority. Ordinary repeats are idempotent; after
matching reconciliation an explicit new request advances revision and case ID.

Focused source observations:

- Actual coordinator/epoch/session/factor files: 15 tests PASS, including
  irreversible/release interruption, foreign state/marker refusal and signed
  authorization lifetime. Existing password-state regressions: 8 PASS.
- Guarded real session store and token/epoch behaviour: 11 tests PASS.
- Actual BrowserApp, private stores, metadata publication and normal Runtime
  delegation: 12 focused observations PASS after repeat-request and privileged
  symlink-publication refusal corrections.
- Identity/signature/operator composition: 14 Python tests PASS, including
  actual serialized Rust Status through the real shell consumer and altered
  account/case/epoch/schema/digest refusals. Disposable signing keys only.
- After the architecture scan refused direct unsafe calls, the corrected FFI
  composition passed the affected coordinator15/session11/authenticator12 tests,
  one actual-socket byte/EOF/deadline discriminator, the exact unsafe predicate
  and warnings-denied Clippy. No scanner or lint exception was introduced.

Evidence resides under `/home/foo/Downloads/osmap-ux-s04/s04-04/` and the existing
`s04-04-session-source-qa-20261029/` and
`s04-04-authenticator-source-qa-20261029/` directories. Source tests do not
establish native or installed results. Earlier test-fixture and concurrent
integration failures, plus review findings and their corrections, remain
recorded in the execution ledger/evidence.

T01/T02/T03/T06/T07 have source observations only. Native T04/T05, installed T08
and human T09 remain NOT_RUN. No new recovery operation, factor/password change,
deployment or public mail-service mutation has occurred. The current containment
implementation fences OSMAP admission and browser sessions; it does not terminate
existing public IMAP/SMTP connections. Those boundaries must remain explicit in
native/identity-policy qualification; no whole-account mail-containment claim is
made. Original approved-control acceptance remains unchanged.

## Operator entry and remaining qualification

After the reviewed matching native binary is installed, the operator workflow is
`maint/live/osmap-coordinate-recovery-over-ssh.sh` with an explicit account,
`--host 192.168.1.44` and `--expected-hostname obsd1.blackbagsecurity.com`.
`--status` reads current native state. `--request` emits an unsigned identity
template, whose request ID can bind the existing browser request. A human must
independently establish identity and authorize/sign that decision; agent Git
commit-signing authority cannot supply it. `--dry-run` verifies the signed
decision without recovery effects. `--recover` requires private enrollment and
RECOVER confirmation before containment/factor effects, and RECONCILE confirmation
before release. After uncertainty use read-only status and explicit manual
reconciliation; never repeat `--recover` as a repair.

Native qualification must use an exact disposable/control account recipe,
reviewed source/artifact/configuration binding, required action-specific
authorization, preserved owner/account/key state, bounded operation and cleanup,
and independent readback. Native compilation, installation, actual old/new-factor
authentication, browser integration and human identity/acceptance are still
required; none can be inferred from this source checkpoint.

### Isolated native component recipe

Before any configured-account journey, root may compile the exact reviewed,
Shopkeeper-signed source in a fresh private obsd1 stage and run only the recovery,
session and authenticator temporary-store tests plus the bounded-input socket
discriminator. Fresh read-only checks confirmed
the expected hostname, installed compiler, and existing private operator-owned
dependency target cache at
`/home/foo/.osmap-credential-snapshot-build-20261025-01/target`. Compiler versions
are observations; required APIs/schema and tests determine compatibility.

Archive Cargo.toml/lock, all src, the five literal maint fixture includes and
tests/fixtures/mime from the signed tree. Verify archive/input hashes before and
after compilation. Build offline/locked, one job, debug information disabled,
with a short private TMPDIR and core dumps disabled. Preserve compiler DATA
limits as observed; any compiler-only adjustment stays within the existing hard
limit and does not change services or application policy. Bound each compilation
to600seconds and each filtered test group to60seconds, with an overall1500-second
operation/cleanup bound. Keep native binaries/test executables and source hashes
in the private stage; do not install them.

A separately named ignored root-only session test may exercise cross-owner
temporary-file revocation using the actual runtime UID/GID. Its reviewed binary
must be copied/hash-verified into an exact root-owned private stage before root
execution; it must never select live session/account paths. This qualifies only
the native ownership boundary. Configured-account recovery still requires its
exact action-specific authority, human-signed identity decision and private
terminal. On native failure retain the first cause and exact-owned resources,
make the smallest supported correction and retest that boundary.

### Native01 failure and causal correction — 2026-10-29

Signed source `3f8c2b3664561b1edca8e0cf031a33f815e7fbc5` built the native
operator binary and libtest successfully. The first recovery test group reported
4PASS/11FAIL with early StateUnavailable; the action stopped before later groups.
The aggregate remains FAIL. Numeric native observation found TMP/file GID0 while
the fixture configured effective GID1000. OpenBSD inherited the parent group;
the strict production factor metadata check correctly refused the mismatch.

One exact positive case then passed using the SAME signed native libtest with a
fresh owned0700 temporary directory explicitly assigned to GID1000 before any
fixture children. The production ownership checks were not relaxed. The corrected
compiler recipe now establishes and verifies the temporary UID/GID/mode.

The original expiry test's reported native pass did not establish lock waiting:
the whole group completed0.07seconds. Its source now first verifies actual
factor/active-epoch/empty-case status, then requires>=900ms of real waiting as
well as the existing<3-second bound for the signed one-second remainder. The
exact local test passed1.00second after independent review. A new signed native
candidate must execute that stronger test and the remaining groups before any
native-component completion claim. Evidence: `native01/` under the sprint root.

### Native02 and installed admission boundary — 2026-10-29

Signed test candidate `93cbb888595c9d36eec8176087c3d5843b7bb663` completed
the corrected isolated native action in 154 seconds: coordinator 15, session 11,
authenticator 12 and bounded input 1 PASS. Its matching native libtest then passed
the exact root-only cross-owner session test in 0.175 seconds, including explicit
fixture cleanup. Independent QA verified all 40 component observations and the
source/artifact bindings. The root evidence stage remains intentionally retained.
The new nonroot TMPDIR contains private synthetic fixture residue and is retained;
only the two older independently identified empty temporary directories were
removed. Native01 remains FAIL. The native02 launch observer's30-second SSH
timeout remains separate from the later same-stage successful result; no second
dispatch occurred. These results qualify components, not configured recovery.

Further source review found that helper allowlist membership does not establish
frontend epoch coverage: an explicitly selected rollout account leaves other
accounts on the legacy admission path, and a disabled profile has no epoch
authority. The operator now reuses the existing account-profile parser on the
same trusted service environment. Mutations require the exact local native
admission/mutation sockets, root helper peers and either the selected account or
a complete global native profile. Disabled, partial, malformed and foreign
profiles refuse before coordinator effects or status publication. Read-only
status remains available for reconciliation. This check does not activate or
widen frontend rollout; installed qualification still requires the matching
running process, environment and authority.

Fresh read-only obsd1 inspection found the accepted S04-03 Web executable still
installed, while the current environment has no account-runtime fields. The
recovery executable and case directory are absent. The reserved historical
rehearsal account is outside the current seven-account helper allowlist. The
environment differs from the accepted S04-03 evidence; the reason is UNKNOWN.
No environment restoration, account enrollment, factor operation, installation
or service change was performed.

The next installed qualification must identify a disposable local canonical
account and a frontend profile that actually enforces its epoch, preserve the
current owner environment and unrelated account/key/mail state, and bind the
reviewed source and native artifacts before installation. Prepare the helper
and Web binaries independently. Then verify actual admission refusal, account
session revocation, old/new-factor authentication, password preservation,
Settings status, restart persistence and cleanup. A human must independently
authorize/sign the identity decision and perform the private RECOVER and
RECONCILE confirmations. Do not substitute the owner's account, change global
rollout or manufacture identity evidence to satisfy this prerequisite.

Signed functional candidate `122b0b36c3d51d816e27e012862553743cb2cae7` then
passed the matching native03 action in 157 seconds: coordinator/operator 17,
session 11, authenticator 12 and bounded input 1, totalling 41 current nonroot
checks. The unchanged root ownership case above is explicitly reused as one
separate earlier observation. Independent QA verified the actual logs and
archive against the signed manifest. Native helper SHA-256 is
`421077d4b69256b0f00f0d88f281f93bea4df051cf6142a6e4cdf1d3a8edade5`;
Web SHA-256 is
`a1dd680d09d29b51cd5fe374757e629ad8810e0adc055968cc6d8d35b3b5fba2`.
These binaries are matching installation candidates; compilation does not
qualify their loaded runtime or the recovery journey.

### Installed executable boundary — 2026-10-29

Independently reviewed installer SHA-256
`339b32f06ccc64adec59a89107234aef3a27d972f892faefa23a9f8b353be358`
completed once in 4.234 seconds with exit 0. The matching native03 Web artifact is
actually loaded, established by executable inode and loopback listener readback;
the recovery helper is root-owned, mode 0700, with a single link at its fixed libexec path.
HTTPS login returned 200 and all 17 checked Web/helper/OpenPGP/mail services were
healthy. Only `osmap_serve` was stopped/started. The existing password helper
retained its exact inode/metadata/hash.

All 712 protected metadata/hash records were byte-identical before bootstrap,
after bootstrap, after Web quiescence and after installation. They cover fixed
configuration, account epoch/case paths, keys, sessions, factors/revoked factors,
settings, drafts and the four authentication/throttle cache subtrees. Ordinary
audit/general-cache activity is outside exact equality. The environment file
remained byte-identical; independent post-install process inspection matched
all 46 declared values, with no inherited account-runtime fields. Raw process
environment and credentials were not retained. No account/factor/case operation
or account-profile change occurred. The private root backup remains available.

The first installer recipe was rejected before execution because it published
an unverified privileged copy. Root-private descriptor-bound copying, expected
hash/readback checks before public installation and explicit supervised-role
proof on restoration corrected that boundary. Actual copy/refusal and snapshot
producer-to-comparison exercises passed before the final installer ran. The
original refused recipe remains preserved as review history.

A fresh browser request for `/settings/authenticator` correctly reached the
login page. No credentials were entered and authenticated Settings were not
qualified by that observation. Evidence is under `s04-04/install01/` and the
private install dispatch/review records. This proves installed executables,
readiness and the listed preservation checks. T04/T05 configured recovery,
the complete T08 journey and human T09 remain NOT_RUN; the current disabled
account-runtime profile and unprepared reserved test account still require the
bounded controlled preparation and independent human decisions above.

### Concrete controlled-case prerequisite

Read-only local SQL admission confirmed exactly one mailbox row for the reserved
`osmap-helper-validation@blackbagsecurity.com` account. Metadata-only inspection
found no factor in either the configured or legacy factor directory and no
account-epoch record. The helper allowlist excludes the account. Factor contents
were not read and no credential, factor, mailbox or epoch change was attempted.
This is an existing partial historical state, not a fresh fixture or the
supported lost-authenticator case. Its ownership/custody and permitted
disposition require a human decision before any one-shot fixture preparation.
Preserve the existing row; do not infer permission to reset/delete it or adopt
another account under the reserved custody policy.

After that prerequisite, bind one exact controlled setup and its recovery plan:
local canonical mailbox/password authority, initial active factor and epoch,
both native helper allowlists, a rollout selector covering only the controlled
account, and before/after owner/control-account preservation. Preserve the current
environment fields and unrelated accounts. Independently prove that the loaded
frontend refuses the controlled account while its epoch is Pending. Then the
independently signed identity/test-custody decision and private RECOVER/RECONCILE
steps can qualify the actual factor transition, password preservation and
installed Settings journey. This participation precedes the separate T09
acceptance decision; it is not a request for UAT of unfinished engineering.

Further read-only preparation confirmed the original local SQL instance at
`/var/run/mysql/mysql.sock`, port 3306, datadir `/var/mysql/`, hostname obsd1 and
server ID 1, with server read-only OFF. This is distinct from the replica/tunnel.
An observer initially required a numeric boolean; its failure is retained and
the explicit OFF interpretation uses the same returned data. A separate
nonsecret mailbox-routing metadata query was unavailable to the existing client;
its visible column set does not establish the full schema or Maildir route.
No grants were broadened. Actual loaded auth/mailbox relay processes still use
the existing Toronto endpoint selected by the current environment. No new remote
request was issued. A local SQL row therefore does not qualify the installed
mailbox route. Preserve the owner's current route; establish a reviewed controlled
route before any journey that could send this fixture to that backend.

### Operator-controlled fixture continuation — 2026-10-29

The operator confirmed disposable custody of the reserved account and availability
for the human recovery steps. Before initialization, its password was unavailable. This resolves
the custody question but does not authorize a credential write or constitute an
independent recovery identity attestation.

Read-only preparation established the actual local Dovecot SQL/userdb binding,
an existing local Maildir with UID/GID2000 and mode0700, and matching local mailbox
grant material without retaining key bytes. Root socket-authenticated metadata
confirmed the original mailbox table is InnoDB with17 physical columns, no triggers,
one unique username index and no other automatically updated columns. Private
opaque baselines cover the46 other rows and the target's noncredential fields.
The existing SQL principal permits SELECT on the five native account columns and
UPDATE on password/modified only; no grants were changed.

A concrete private credential-only actor is ready at SHA-256
`b190bc79db08dfe61a8d161c567d3e3e51dedcb87e426a6b7262a00bcf7e926c`.
Independent review, eight actual local producer/consumer cases, four custody
refusals and seven signal/deadline cases passed. A native synthetic hash probe
also passed without changing an account. The actor preserves a fresh credential
privately before its sole guarded UPDATE, records dispatch durably, disables
reconnect, requires a complete post-COMMIT readback and retains uncertainty without
retry or rollback. The whole operation and forced cleanup are bounded to90seconds.
The operator subsequently authorized exactly one execution. It settled in0.665s
with one guarded UPDATE; independent readback matched the new opaque password
digest and modified timestamp, all46 other complete rows and the target15
noncredential columns remained byte-identical. The fresh password remains only
in a root-private host file. This manual fixture setup does not qualify product
lost-password recovery. The user reported the separately reviewed private initial-factor enrollment
complete. The independent observer refused with a generic file-boundary error;
a narrower lstat-only discriminator established that the expected configured
factor is absent (ENOENT), with correct physical ancestors and runtime identity.
The first refusal is retained; the private final command status is requested
without repeating provisioning. No epoch/profile preparation or product recovery
has occurred at this checkpoint.

For the subsequent journey, the supported route is a temporary return of the
existing Web to the accepted local-development auth/mailbox profile, with native
account authority scoped to the reserved account. The current configuration guard
refuses native authority combined with either known Toronto bridge endpoint;
adding native fields to the current bridge profile is therefore invalid. During
the controlled local window, the whole Web mailbox/auth route uses local data and
owner credentials/content may differ from Toronto. Preserve public mail services
and all owner credentials/data, then restore the exact current bridge profile and
verify its loaded environment, HTTPS and supervised roles. This preparation is
separate from the later fresh identity signature and private RECOVER/RECONCILE.


### Enrollment diagnostic correction — 2026-10-29

The operator directed a retry, evaluation and correction. A fresh read-only
metadata observation again found the configured factor absent (ENOENT). The
actual maintained native dry-run then passed in0.491s with no stderr: the local
mailbox exists, the factor is absent and no-overwrite enrollment is eligible.
This does not establish the original private command's final outcome or cause;
that observation remains unavailable. No password initialization was repeated.

The supported change is limited to the private enrollment wrapper's diagnostic
boundary: retain a fixed phase, nonsecret primary reason, exit status and whether
factor dispatch was attempted in a private durable receipt. Preserve the existing
human QR/code and exact PROVISION checks, the maintained no-overwrite publication
and the stop on uncertain results. A corrected private enrollment attempt still
requires those human steps; native dry-run PASS is not installed-factor PASS.
No epoch/profile publication or complete recovery journey is claimed.

The read-only observer correction preserves the original checks and adds only a
fixed phase and numeric errno. Its two local affected-boundary cases passed.
Actual obsd1 execution now reports `factor_open`, errno2 and zero stderr in0.331s,
with no factor material emitted. This qualifies the diagnostic correction only;
the absent-factor refusal and product recovery remain unchanged.

Affected local wrapper QA preserved an additional failure before any real host
provisioning: merging stderr's no-newline private input prompt with stdout's
success marker caused exact-line verification to refuse a correct synthetic
code. The smallest correction separates private stderr capture from stdout
markers for enrollment and PROVISION, with both under existing private scratch
cleanup. The original native attempt's cause remains unknown; this local
failure does not explain it. The final wrapper retains one no-overwrite dispatch
and an uncertain-outcome stop.

The final private wrapper SHA-256 is
`2a186823fb732f84e3ca18fce5efe638a829862670c9f825ad1b548024e2cb1c`.
Independent QA passed seven affected whole-wrapper cases with the maintained
primitive and a synthetic private terminal: successful code/PROVISION, bad code,
denied confirmation, sensitive QR error suppression, uncertain remote response,
and receipt failures before and after provisioning. The pre-dispatch failure
made no provisioning call; the post-dispatch failure retained the simulated
factor and reported UNCONFIRMED without retry. Three real native-producer
consumer cases also passed, using the actual665-byte preflight response with
exit status and required-marker refusals. The preserved merged-stream failure
remains failed. These checks qualify only this execution correction, not the
installed factor or complete T04/T05/T08/T09. The already-authorized corrected
private human enrollment command has been provided; actual outcome is pending.


### Initial factor and native profile preparation — actual 2026-10-29

The corrected human run finished complete/PASS, remote dispatch recorded and
exit0. Independent native readback found the exact configured87-byte regular
factor, UID/GID1001, mode0600, single-link and correct account header. Its SHA-256
`8c2fc29dd948232cfc81e640799c445c0a77e162a6a9032fd0720e1085c5adab`
matches the final human receipt; no factor material was emitted. The earlier
IN_PROGRESS receipt remains history, superseded by the final complete receipt.

The reviewed root-private seven-file input publication passed exact hash/custody
readback. The unchanged profile actor then passed once in5.097s with zero stderr,
within its240s primary plus200s restoration bound. Native status is activeepoch0,
no recovery case and the same factor digest. Only the two OSMAP roles restarted;
the17-role before/active observations are identical and healthy. A fresh read-only
comparison of the actual Web process environment matched all54 candidate fields,
without retaining raw environment output. No additional credential or factor
write occurred in profile preparation. Full browser/recovery/T09 remain NOT_RUN;
this checkpoint establishes preparation only. The temporary whole-Web LOCAL
route remains active pending the controlled journey and guarded bridge restore.
Private actual receipts are under `continuation01/profile-activation01/` and
`active-profile-readback01.json`; their scalar observer is `profile-activation01.json`.


The operator selected the owner UAT account for later human review; its exact
identifier is retained in the private UAT selection record. This
selection does not mark T09 complete or change the disposable engineering target.
The actual bounded HTTPS readiness probe subsequently passed in0.882s, with
read-only native observations and HTTPS `/login`200; no login POST or credential/
factor material read occurred. The reviewed two-code private baseline command
has been provided, with its actual execution outcome pending.

T04 retains both required boundaries: factor-only recovery preserves the current
password authority, then a separately authorized ordinary password-change
transaction must remain usable. A fresh read-only original-local SQL observation
passed native producer/parser checks and still matches initialization; the
post-change policy correctly refused that unchanged credential as completion.
It supplies no ordinary password-change result. That future action-specific
authorization has not been requested, and its post-transaction config guard and
role driver still require independent admission before the fresh identity window.


The normal readiness-checkpoint push passed the Rust suite but was refused by
the publication guard because the draft included a real mailbox identifier.
The exact selection is now retained only in the private UAT record and public
wording uses an owner-account label. The rejected unpublished checkpoint was
preserved on a private local ref and verified Git bundle. A redacted replacement
starts from the last GitHub-saved checkpoint; no rejected ancestry is published,
no history is rewritten and no guard or normal hook is bypassed. The affected
publication, documentation and work-order checks passed after correction.


### Actual HTTPS baseline partial result and bounded reconciliation

The first real baseline produced two303 logins with distinct accepted counters
and actual epoch0 session bindings. Both Settings entries, qualified factor
metadata, five refusal controls, Requested-only state and stale revision refusal
passed their observations. The final idempotent POST returned200, then its
read-only SSH observation failed255 (zero stdout,91 stderr bytes). The raw
transport text was not retained; its underlying cause remains UNKNOWN. Preserve
the original aggregate UNCONFIRMED. A repeated full command refused existing
state before any HTTP request and did not repeat authentication.

The exact frozen read-only observer subsequently passed in0.342s. It confirmed
two active epoch0 sessions, current Requested revision1, unchanged replay and
preserved other-session controls. The original before/final request frames were
RAM-only, so historical byte equality remains NOT_OBSERVED. A separately defined
one-POST idempotency test of the CURRENT known record subsequently passed in
1.101s: HTTP200, durable exact request byte equality, unchanged revision/case,
factor/epoch/replay and other-account/session records. This is its own passing
measurement; it cannot rewrite that historical result.

The private enrollment material was pasted into chat. The disposable factor is
now flagged EXPOSED; no seed, QR or code is copied into project evidence or used
for OTP derivation/replay. The human classified isolated
fixture-factor exposure with no broader suspicion in the same existing private
controlled-custody case. Fresh human-signed recovery approval and private
RECOVER/RECONCILE decisions are still required before replacement/release;
no automatic rotation or release is authorized. The owner UAT selection is
unchanged. Broader password/account/mail compromise is not established by this
transcript, and whole-account safety is not inferred.

A separate input-timing discriminator reproduced early input echo and queued
consumption during the old wrapper's wait, using only public synthetic input.
This is not evidence of the human transcript's exact timing or the SSH cause.
A future-only entry wrapper preserves echo-off through waits, flushes queued
input before prompts and restores terminal state. It does not rerun this baseline.


The corrected future-only entry wrapper passed three local private-terminal
controls: early input remains hidden and is discarded before the next prompt,
signal interruption restores terminal state, and readiness refusal makes zero
authentication requests. This is wrapper evidence, not another native baseline.

The first recovery BEFORE probe refused an already idle-expired session before
HTTP. Read-only age reconciliation explained that refusal. T03 requires actual
account containment and session revocation; it does not require two currently
live sessions. The smallest supported probe correction preserves both original
records, presents only the still-live cookie before containment and labels the
expired record as metadata-only. Independent focused controls passed. Actual
retest then passed in1.164s: exactly one protected GET200, one live record and
one already idle-expired record, both still nonrevoked. The live200-to-denied
transition can supply causal revocation evidence after actual recovery; the
expired-cookie denial cannot. No timeout, session authority or account state
was rewritten to manufacture a baseline.

Next is one independently human-signed controlled recovery, paused at the
maintained private RECONCILE prompt for Pending-state observations. Replacement,
old-factor refusal, new-factor success, restart persistence, authoritative
password preservation, later separately authorized ordinary password change and
independent preservation/acceptance remain unfinished. Complete T04/T05/T08/T09
remain NOT_RUN. Public mail services and the deferred S05-02 checkout are outside
these actions.


Focused callback source qualification passed before any signature window began:
actual Rust marker bytes through the real consumer, Pending cookie/login refusal,
replay-admissible obsolete-factor refusal, replacement login/session binding,
unexpected HTTP200 cookie preservation, persistence readback and private-terminal
cleanup. These are source/local controls only. Actual Pending, factor replacement,
post-release authentication and restart observations are still NOT_RUN.


### First human recovery attempt: pre-begin refusal and path correction

The human created a fresh detached identity signature, passed the maintained
verifier/dry-run, verified a replacement candidate privately and entered RECOVER.
The command then returned UNCONFIRMED before RECONCILE. Its original precise
exit cause was not retained: only the generic outer command failure survived.
Independent native readback passed in0.778s: epoch0 Active, native case absent,
original factor unchanged. No durable native begin/effects were observed; this is consistent with a
pre-begin stop and does not establish containment or recovery completion. The exposed candidate is excluded from reuse; its
material was not copied or used and its unretained digest is not reconstructed.

A separate original-source read-only host discriminator failed in1.207s and
showed legacy factor directories selected instead of the trusted native paths.
The nested preflight sources the revoke helper, whose initialization previously
reset those paths. The later revocation has the same sourcing boundary. The
small source correction carries the selected paths and owner/group into both
isolated helper initializations. New pre-begin diagnostics retain a fixed phase,
cause, exit and observation count/hash without exporting raw native output.
The existing dry-run returns before this physical preflight and could not prove
that path binding. Two permanent actual sourced-helper regressions failed on
the old source and passed after correction; independent real-chain tests and
pre-begin diagnostic/privacy tests passed. The corrected actual read-only host
snapshot then passed in1.369s: native paths only and the expected original factor
digest, with no recovery mutation. This qualifies that physical path boundary
separately; it does not qualify the complete recovery.

Post-refusal preservation passed in1.070s with one existing-cookie protected
GET200 and zero login/OTP requests. Before/after observations preserved both
original nonrevoked session authorities, the Requested record, epoch, factor
metadata, replay and unrelated-session authority; only normal selected-session
last_seen and monotonic unrelated last_seen are allowed. No expired cookie was
presented and the immutable original before proof was not overwritten.

The next private user interface displays the QR in a separate local image
viewer, keeping QR/seed/URI out of terminal transcripts. It retains the existing
human signature, new-factor verification, RECOVER and paused RECONCILE contract.
Focused local tests passed actual display-body/maintained-verifier composition,
private PNG/stdin/argv handling, early-input flush, GUI refusal, signal and exact
terminal restoration/cleanup. The final failure-only adjustment preserves the
viewer exit and states why private diagnostic text was not retained. These are
source/local tests; the actual GUI/human recovery remains NOT_RUN.


### Manual procedure withdrawn; selected owner-account UAT configuration

The operator rejected the two-terminal fixture procedure. Its public entry
commands now stop without dispatch, with exact previous sources and failed
receipts retained privately. The Pending probe ran before a recovery case
existed and stopped with errno2 and zero HTTP requests. The remaining owned
QR viewer/test processes were stopped; readback confirmed fixture Active0,
original factor unchanged and no case. The additional guided-wrapper work was
interrupted and is not an approved execution path. No further fixture terminal
procedure is part of owner UAT.

On the operator's request to use the real owner account and ensure obsd1 can run
S04-04, fresh read-only inspection matched the installed Web/recovery/password
helper hashes and protected modes, actual loaded Web/account-helper inodes,
17 healthy roles, all54 loaded environment fields and public HTTPS login200.
Production Rust/Cargo bytes are unchanged from the signed122b build, so no
rebuild or binary replacement was needed. The operator-side path correction
remains in signed8e9045e.

Only OSMAP_ACCOUNT_ROLLOUT_ACCOUNT changed from the retired fixture to the
privately selected owner UAT account. The other53 environment fields and the
existing LOCAL auth/mailbox route are byte-identical. A root-private backup
precedes guarded atomic publication; only OSMAP Web restarted. Actual loaded
profile readback, HTTPS200 and all17 healthy roles passed afterward. Returned
native account-state fields before/after match: owner Active3, original factor,
no recovery case; fixture state also unchanged. No password/factor/recovery or
session-revocation operation was performed. Existing legacy cookies may need a
fresh login because selected-account native admission now applies.

This establishes installed/configured readiness for the owner's local browser
walkthrough. Complete recovery, restart-after-recovery, post-recovery password
change and human acceptance remain unqualified; T04/T05/T08/T09 stay NOT_RUN.
Current LOCAL development routing is not Toronto mailbox-sync qualification.
Old fixture-specific signing, preparation and restoration actors do not apply
to the owner account or its epoch. The exact owner identifier remains private.
