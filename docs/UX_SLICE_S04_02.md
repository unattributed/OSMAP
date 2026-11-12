# S04-02 delivery specification — authoritative own-password change

## Current team execution specification — 2026-10-24

**Purpose:** give a development lead, project manager and independent QA team
one executable handoff for completing S04-02. This section specifies work and
acceptance; it does not declare that unexecuted work passes. Progress, assignments,
action authorization and results remain in `UX_EXECUTION_LEDGER.md`.

**Authority:** preserve the accepted R2 plan anchor
`6b3ce8fff27ca3dabf87039d54098bd9967a2e42`, signed R3 supplement, D04 and
all 20 requirements below. Latest direct operator instructions take precedence.
This is a refinement of execution within the existing slice, not a product-scope
amendment. Earlier method/authority notes below are historical wherever superseded
by this section or the current operator rulings in `../AGENTS.md`.

**Delivery objective:** an authenticated user can change their own authoritative
mail password using their current password and fresh TOTP. The installed OSMAP
journey verifies the update and its required authentication/session effects,
preserves other users and public mail, and reports refusal or incomplete results
truthfully. A disabled form, source review, build or SQL write alone is not this
outcome. Documentation cannot guarantee success; the executed acceptance results
below determine it.

### 1. Starting point, facts and unresolved questions

Repository `unattributed/OSMAP`; approved branch `feat/ux-completion-20260929`.
The source baseline for this handoff is signed checkpoint
`a8aff9a83871bee795dfacb6c9fad3592413cad4`. Reconcile current source and evidence
before work; the baseline is a reference, not a permanent source pin for builds.
Use obsd1 `192.168.1.44`, expected hostname `obsd1.blackbagsecurity.com`, for
authorized native qualification. Production `mail.blackbagsecurity.com` is out
of scope. The selected topology is one host with OSMAP and the existing backend.

| Boundary | Established at the handoff baseline | What is not established |
| --- | --- | --- |
| Ordinary login | The operator reports successful installed password/TOTP login. A new local real-Runtime/file-TOTP/replay/session regression passes with mutation disabled and an accepting primary-auth fixture. | That fixture is not live Dovecot evidence, and does not qualify the reconstructed admission or password path. Preserve working login; do not assume either path is interchangeable. |
| Credential ordering | `Service::change` now reads its comparison snapshot before current-password authentication. Six focused tests cover the positive path, external-writer conflict, wrong current password/replay and containment. | Native Dovecot/SQL composition and authentication freshness remain unqualified. A conditional update does not by itself prove the authentication response refers to the same authoritative account/credential. |
| Backend metadata | Read-only obsd1 capture confirmed required mailbox columns, InnoDB, unique username key, and ARGON2ID/BLF-CRYPT availability. | Algorithm availability is not selected policy. Effective passdb mapping, hash compatibility and live cache behaviour remain unresolved. Inspect only settings consumed by the selected adapter; do not invent optional PostfixAdmin hooks as prerequisites. |
| Native helper | Earlier source-specific startup/admission milestones exist. Latest probe165 failed at `StockWorkerArgv / Denied / Unavailable`, before operational readiness. | Its precise native denied subphase/errno is unknown. Earlier milestones do not qualify the replacement helper or explain probe165. |
| Installed journey | T01/T02 are recorded PASS at their defined source scope; historical fixture results remain available with limits. | Current T03 and deployed T07 remain FAIL; T04/T05/T06/T08/T09 remain NOT_RUN in the ledger. No reconstructed helper, full session integration or S04-02 acceptance is claimed. |

PostfixAdmin supplies the reference method: authorized own-account request,
current-credential verification, compatible hash, account update and required
post-write handling. It does not establish OSMAP's additional step-up, replay,
epoch or session guarantees. The retained PostfixAdmin source capture comes
from historical Toronto evidence; it is not current obsd1 configuration proof.

### 2. Scope and non-negotiable product contracts

The browser remains a client of the local account service. The web process must
not receive SQL credentials, unrestricted SQL, caller-selected commands, doas
capability or private backend configuration. Use existing typed, authenticated
admission/mutation interfaces and fixed Rust-owned backend operations.

**Explicit operator constraint — no new Python scaffolding:** do not add Python
files, generated Python execution carriers, fixture/provisioning layers, cleanup
frameworks or replacement result consumers, and do not expand the existing
Python harness to support this reconstruction. Product changes and focused
regressions use the existing Rust modules, Rust tests and fixed backend utilities.
Existing mandatory checks may run their unchanged Python tests. If an execution
interface is incompatible, identify the exact gap and resolve the smallest
existing Rust/command interface; do not respond by building another harness.

Retain these exact contracts:

- **Authorization:** own account only; valid session, origin/Host and CSRF;
  current password plus fresh TOTP using the existing verifier/replay store.
  A single-use permit binds request, account, session, source, action and epoch.
  Recheck authority at consumption. At age 300 seconds it is expired; age 299
  is eligible only if all other checks pass. Preserve original product deadlines.
- **Abuse controls:** independent durable limits of five failures/account and
  ten/source within 15 minutes, with 15-minute cooldown. Success and restart must
  not erase an active window. Test account/source limits independently.
- **Password policy:** 15–128 Unicode characters and at most 512 UTF-8 bytes;
  no controls, silent truncation or mandatory composition rules. Support paste;
  reject unchanged input and unequal confirmation. Use an authoritative supported
  salted hash, not a second OSMAP password database or custom hash.
- **Concurrency:** all OSMAP authentication/session issuance and mutation share
  the account lock/epoch. Capture the SQL snapshot before authoritative credential
  verification and retain that snapshot for the conditional update. External
  credential/status changes must conflict rather than become a new comparison
  baseline. Zero affected rows is refusal, not success or permission to retry.
- **Write/result:** durable pending/intent handling precedes credential dispatch.
  Perform one conditional update for one authorized action; validate readback.
  Verify required authentication-cache effects, old-password rejection and
  new-password acceptance. Cache disabled is one possible verified mechanism,
  not a universal new product requirement.
- **Sessions and status:** confirmed completion includes revoking every affected
  OSMAP browser session, including the current session, and a verified authoritative
  changed-at timestamp. A general mailbox `modified` value alone is not password
  history. A verified write with incomplete effects retains its verified time
  and explicit incomplete/contained state. Absent historical timing stays Unknown.
- **Isolation and mail impact:** Bob's credential, epoch, browser sessions and
  mail/connections remain unaffected. Existing third-party SMTP/IMAP sessions may
  outlive the password change; disclose this limit and do not claim termination.
- **Secrets:** never place passwords, TOTP material, cookies, keys, tokens, raw
  private output or stored hashes in argv, environment, URLs, logs, browser
  storage or public evidence. Use bounded existing private transport/memory and
  the existing secret-handling rules for backend work.

Keep required locks, authorization, pending state and uncertainty protection in
the first native credential test. Decomposing the proof does not authorize a bare
SQL mutation, bypass endpoint, replacement runner or test-only success path.

Excluded: recovery-contact management, TOTP enrolment/rotation, other slices,
new dependencies, another TOTP/crypto implementation, Python harness development,
global mail-login epoch hooks, new SMTP proxies/PF redirection, forced termination
of all third-party mail connections, public Dovecot/Postfix/MariaDB service or
configuration changes, and production-host contact. OSMAP service operation is
subject to the exact current action authority; no mail downtime follows from it.

### 3. Responsibilities and working arrangement

The project manager records actual named assignees in the existing work order
before their assignment starts. Roles below define responsibilities, not a new
role-roster admission gate. One person may cover compatible roles; an author
cannot independently approve their own changed security boundary.

| Role | Accountable work and handoff |
| --- | --- |
| Project manager | Maintain the single S04-02 objective, ordered work packages, dependencies, named owners, effort forecast/actuals and blockers in the existing ledger. Prevent infrastructure tasks from replacing the functional exit. Obtain only operator decisions/actions actually required. |
| Technical/integration lead | Own the canonical source, host and Git queue; approve bounded designs; integrate changes; verify the exact executed path and prerequisites; own readiness/closure claims. Do not delegate enforcement responsibility to QA or the operator. |
| Backend developer | Establish the actual adapter contract; implement minimum Rust composition changes; preserve command/resource custody and transaction guarantees; supply source tests and exact interfaces for independent testing. |
| Frontend/session developer | Preserve working login; prove real Runtime delegation, step-up, epoch/session integration, accessible form behaviour and truthful persistent status. Coordinate shared files with the lead. |
| Independent QA lead | Prepare positive/negative tests and independent result oracles before native dispatch; execute or witness the authorized test; reconcile account/session/mail state and evidence; report PASS/FAIL/NOT_RUN/UNKNOWN by scenario. |
| Independent security reviewer | Review changed source, successful/refusal paths, authorization, custody/confinement, secret handling, cleanup and real producer/consumer compatibility. Resolve findings before delivery/activation. |
| Operator/product owner | Supply explicit live-action authority where required and final T09 usability acceptance after engineering/QA/review pass. The operator is not assigned unfinished engineering diagnosis. |

Parallel source tasks need explicit non-overlapping file ownership. Only the
lead dispatches native operations or integrates/pushes the canonical branch.
Historical agent names in the ledger are provenance, not proof of active owners.

### 4. Code map and permitted design freedom

These are current entry points to inspect, not a requirement to rewrite every
file. Verify the actual reachable producer, execution path and consumer.

| Boundary | Existing code to reuse or narrowly correct |
| --- | --- |
| Browser route/form | `src/http/routes_password.rs`, `src/settings_password_ui.rs`, `src/http/password_local.js`, `src/http/password_tests.rs` |
| Runtime and existing TOTP/login | `src/http_gateway_auth.rs`, `src/http_gateway_password.rs`, `src/account_admission_runtime.rs`, `src/password_change.rs`, `src/password_change_rate.rs` |
| Guarded request/step-up/session composition | `src/session_action.rs`, `src/account_mutation_client.rs`, `src/account_password_connection.rs`, `src/session_password_cleanup.rs` and existing runtime/session tests |
| Credential transaction | `src/account_password_service.rs`, `src/account_password_backend.rs`, `src/account_password_mail.rs` and their existing tests |
| Native construction/execution | `src/account_password_server.rs`, `src/account_password_runtime.rs`, `src/account_password_native.rs`, `src/account_password_peer.rs`, `src/account_password_confinement.rs`, custody/process/metadata modules |
| Durable authority | `src/account_password_state.rs`, `src/account_password_admission.rs`, existing shared lock/epoch and replay stores |

`StockPeer` is coupled into startup, runtime admission/effects, native profile
construction/preparation and parent confinement. Removing the initial failing
check alone is incomplete. Replace only the selected process-argv dependency
necessary for the credential operation, using actual fixed endpoint/backend
authority. Retain protected endpoint/ancestor and appropriate kernel-peer checks,
fixed commands/arguments, executable/library custody, separated child roles,
confinement, original deadlines, bounded I/O and cleanup. Do not weaken an
invariant merely to get startup PASS or fabricate a successful no-op.

In particular, `StockEffects::invalidate_cache` currently relies on StockPeer's
cache-zero contract. Removing that proof cannot leave an unjustified successful
no-op. Establish equivalent actual freshness/effects or the existing bounded
account-specific cache operation. Configuration text alone does not prove the
running daemon loaded it. Distinguish authentication refusal from unavailable
infrastructure and preserve existing fail-closed public errors.

The developer chooses the smallest supported design and documents its reason,
changed boundaries and distinguishing tests. A new architecture or generic
framework is not the default response to a refusal. Keep legacy login untouched
until the new composition is proved; do not turn explicitly configured unavailable
admission into a silent legacy fallback or upgrade an epoch-less session into
mutation authority.

### 5. Ordered work packages and measurable exits

These packages decompose the existing scenarios; they add no acceptance scenarios
or automatic live authority. Backend-only observations are partial evidence for
T03, never complete T03 or S04-02 PASS. Reuse matching evidence between packages.

| Package / lead | Dependencies and concrete task | Observable exit / independent check |
| --- | --- | --- |
| **A — Baseline; integration + QA** | Reconcile current source, accepted plan, ledger and operator boundaries. Preserve the recorded real-Runtime login/TOTP/session regression and no-downgrade/replay controls. Identify which evidence remains applicable. | Working baseline and its limitations are explicit; changed code cannot silently break login or create mutation state while disabled. No need to repeat unchanged broad suites. |
| **B — Backend contract; backend + QA** | Resolve exact canonical account/passdb mapping, actual SQL schema/grants/config consumed, supported generated hash and current-credential/cache semantics. Reuse the metadata capture; privately inspect missing facts through narrow authorized observations. Optional PostfixAdmin hooks matter only if the selected contract requires them. | QA can explain how this Dovecot check verifies this authoritative account and how stale acceptance is prevented. Unsupported/missing facts stop dependent implementation; availability/version/default text is not proof. |
| **C — Minimum adapter; backend + security review** | After B, change only the helper construction/execution required to run snapshot -> authoritative current-password check -> compatible hash -> original-snapshot conditional update/readback. Preserve existing authorization/lock/pending safeguards. Reuse the passing source race correction. | Actual changed functions pass focused positive/refusal/uncertainty tests; all affected construction and execution call sites use the reviewed authority. Independent review identifies no missing invariant. This is source readiness only. |
| **D — One native credential operation; lead + QA** | After reviewed C and exact live-action authorization, bind signed source/current matching artifacts, target, disposable account, control account, expected effects, runtime bounds and owned cleanup. Qualify minimum helper readiness/non-mutating exchange before the sole credential dispatch within the authorized recipe; stop if a prerequisite fails. | Actual Rust helper/client operation observes conditional write/readback and real old-password rejection/new-password acceptance. QA independently reconciles the exact account, control account, write certainty and required effects. Preserve incomplete outcomes; a direct SQL command, mocked auth, EOF or actor exit zero is insufficient. |
| **E — Step-up/epoch/session integration; frontend/session + QA** | Use the same qualified adapter through existing authenticated clients and real Runtime/TOTP/session stores. Preserve action binding and prove pending/ACK, replay, expiry, durable rate limits, concurrent issuance/mutation and failure containment. | Full T03 and required T04/T05 observations match actual installed semantics. At least two pre-change Alice browser sessions, including the submitting session, become unusable; Bob remains valid. No new native action inherits authority merely from D. |
| **F — Installed journey/status; frontend + QA** | After preceding native proof, use the matching configured Runtime/helper pair on obsd1. Reconcile T01/T02 and execute T06–T08, including both settings destinations and reload. A matching controlled journey may supply several observations. | Real form -> Runtime -> helper -> backend -> status/session result; accessible controls and safe cancellation; authoritative changed-at, truthful incomplete states, isolation and secret exclusion. No qualification-flag-only activation. |
| **G — Closeout; PM + independent review + operator** | Reconcile all 20 obligations and T01–T09 evidence, source/artifact/config applicability, findings, recovery and retained resources. Deliver signed source and matching installed QA. | Engineering definition of done satisfied first; then concise T09 usability acceptance. PM closes only S04-02, not other slices or the epic. |

Before each package, the lead records only the actual prerequisite, named owner,
expected observation, minimum test, expected preserved state and stop condition
in the existing work order. PM records an honest effort forecast and actuals;
unknown historical costs remain UNKNOWN. No invented calendar expiry, role
ceremony or renewed allowance is a substitute for technical progress. Existing
product deadlines and any explicit operator limits still apply.

### 6. QA execution specification and independent oracles

Alice is the disposable account being changed; Bob is the unaffected control.
Names denote roles, not authorization to adopt a retained fixture or guessed
resource. The exact identities, ownership, private credentials and initial state
must be established for each approved operation. Never use an operator's real
password/account or external provider delivery as the engineering test.

QA uses the existing scenario IDs and records prerequisites, action, expected
result, preserved state, actual result and evidence in the existing ledger.
Do not reset historical FAIL to NOT_RUN. The new candidate's unrun status is
recorded separately from historical outcomes.

| Scenario | Concrete actions and expected observations |
| --- | --- |
| **T01 — Form** | On the matching source/UI, test current/new/confirmation Show/Hide independently, keyboard/focus/accessible state, paste, both entry links, breadcrumb and Cancel. Only the selected field changes masking. These controls/navigation issue no password mutation and retain no secret. Reuse unchanged matching PASS. |
| **T02 — Refusals** | Wrong origin/CSRF/session/account, malformed or over-limit form, confirmation mismatch, unchanged password and exact D04 Unicode/byte/control boundaries. Observe refusal before credential/session mutation and no invented changed-at. Use local controls for exhaustive policy inputs, not repeated live writes. |
| **T03 — Native composed success** | Establish at least two stored Alice sessions and a valid Bob session/control state. Use current password and a fresh unused TOTP through actual trusted admission/guarded mutation, one conditional credential update, readback, required epoch/cache/browser revocation and verified changed-at. Observe old credential rejection, new admission, both old Alice sessions refused and Bob preserved. Use a fresh permitted verification context; a reused consumed TOTP cannot prove an old-password refusal. Independently reconcile authoritative state, not only the actor's success field. |
| **T04 — Pre-write/replay/races** | Exercise 299/300-second boundary, consumed TOTP/permit, wrong account/session/source/action/epoch binding/current password, account/source limits independently across restart/success, stale epoch and held mutation versus concurrent session issuance. Actual production lock/epoch paths must refuse unauthorized/stale issuance and second credential dispatch. Local deterministic controls plus matching native integration supply the required evidence; do not change host time or add public mail-login hooks. |
| **T05 — Post-write incomplete/uncertain** | Through the existing controlled failure seam, interrupt a required effect/response after an authorized write. Distinguish a verified write from unknown write state; retain verified timing where available. Observe contained/incomplete state, old-cookie rejection, no automatic second write/rollback, and authoritative reconciliation plus reviewed owned cleanup or retention. An uncertain operation ends further credential attempts. |
| **T06 — Installed journey** | Use actual installed matched services and BrowserGateway Runtime delegation; observe form -> authorization -> helper -> backend -> returned UI. Verify navigation/visibility/Cancel before the authorized change and persist/reload the result. A concrete helper test alone cannot pass this scenario. |
| **T07 — Status** | Inspect Security and Authentication & Recovery before/after confirmed, refused and incomplete outcomes, including reload. A new confirmed change needs verified authoritative changed-at. A verified write with incomplete effects retains its actual verified time and incomplete status. Missing historical data stays Unknown; a generic mailbox timestamp/transport receipt cannot fabricate password history. |
| **T08 — Isolation/secrets** | Reconcile Alice/Bob credential/epoch/session projections and existing control mail/connections; exercise cross-account/stale/CSRF refusal. Inspect safe diagnostics plus private outputs through approved handling for leakage to argv/environment/logs/URLs/browser storage/evidence. Bob remains unaffected and no public-service action occurs. No MAIL/RCPT/DATA/BDAT or provider message is needed. |
| **T09 — Operator usability** | Only after required engineering/QA/independent review passes, give the operator a short script covering navigation, independent visibility, cancellation and the meaning of confirmed/incomplete effects on the matched installation. Do not assign debugging, duplicate engineering QA or unnecessary real-account mutation to the operator. |

Independent oracles are the authoritative account result, durable epoch/pending/
intent state, actual authentication result, validation of stored sessions, actual
cache-effect mechanism, and unaffected control state. Reuse existing protected
readers and reconciliation. If the architecture makes an observation unavailable,
name the missing observation and resolve or report the gap; do not invent PASS.

### 7. Requirement traceability — all 20 retained obligations

The following table maps the existing acceptance catalogue, not new requirements.
Detailed positive/negative cases remain in `../maint/ux/acceptance.json` and the
active ledger. Test evidence must cover each obligation even when one journey
supplies several observations.

| Requirement | Required behaviour | Principal scenarios |
| --- | --- | --- |
| UX11-002 | Authoritative last-changed information | T03/T07 |
| UX11-003 | Working own-account Change password | T01/T02/T03/T06 |
| R2-10-005 | Security password status and changed time | T07 |
| R2-10-009 | Security Change password entry | T01/T06 |
| R2-20-001 | Authentication & Recovery changed-at status | T07 |
| R2-20-002 | Authentication & Recovery Change password entry | T01/T06 |
| R2-22-001 | Breadcrumb navigates without submitting | T01/T06 |
| R2-22-002 | Current password handled only for authorized verification | T02/T03/T04/T08 |
| R2-22-003 | Independent current-password Show/Hide | T01/T06 |
| R2-22-004 | Valid new password under D04 policy | T02/T03/T06 |
| R2-22-005 | Independent new-password Show/Hide | T01/T06 |
| R2-22-006 | Exact new-password confirmation | T02/T06 |
| R2-22-007 | Independent confirmation Show/Hide | T01/T06 |
| R2-22-008 | Fresh action-bound reauthentication/TOTP | T03/T04/T06 |
| R2-22-009 | Cancel without mutation or secret persistence | T01/T06/T08 |
| R2-22-010 | Authorized Change password submission | T02/T03/T06 |
| R2-22-011 | All affected OSMAP browser sessions revoked | T03/T04/T05/T08 |
| R2-22-012 | Actual backend old rejection/new admission and truthful mail impact | T03/T06/T08 |
| R2-22-013 | Explicit partial-failure reconciliation | T05/T07 |
| R2-22-014 | No password logging or retained secret evidence | T02/T03/T05/T08 |

### 8. Prevent recurrence of observed engineering mistakes

| Earlier mistake or demonstrated limitation | Required prevention in this execution |
| --- | --- |
| Advancing a long integration chain before its smallest native operation works | C/D deliver one real Rust/backend credential result before expanding epoch/session/browser qualification. Bound helper work by that result. |
| Treating architecture as a product requirement: worker argv, global mail hooks, two hosts, shutdown, fixed free-RAM or exact release predicates | Retain required security outcomes, justify selected mechanisms against actual contracts, use one host, semantic capabilities and no public downtime. Do not reintroduce retired prerequisites under another name. |
| A known unsupported Dovecot configuration was lost between readiness and execution | Carry unresolved consumed configuration/passdb facts into B and dependent tasks. Lead and QA inspect the actual fact and executed path; declarations do not prove it. |
| Synthetic/fixture/SQL/cleanup PASS promoted to product readiness | Label source, build, native credential, integrated native, installed, cleanup and human results separately. Only matching whole-scenario observations pass that scenario. |
| Concrete backend passed but Runtime inherited a default or selected another path | Prove a distinguishing call through the actual BrowserGateway/Runtime delegation and configured clients in E/F. |
| A stale TOTP was reused for a password-negative check | Use an unused permitted factor/context so old-password rejection is attributed to the credential, not replay refusal. |
| Consumer/schema/source-pin mismatch, or assuming a subprocess/cleanup contract from a fake | Exercise actual producer output through actual consumer, including failure/cleanup, before host use. Verify changed OS command/API semantics first; no replacement QA framework. |
| Child signal-mask/cleanup errors or uncertain process ownership | Review the changed launch/child chain and existing custody rules. Preserve earliest failure separately; do not signal historical PIDs, guess ownership or infer absence from one PID/session query. |
| Native Denied collapsed to a generic category; evidence removed during cleanup | Preserve fixed source-owned metadata detail, bounded real errno where legitimately observed, phase/outcome and stream accounting. Read back/hash durable evidence before removing its sources; retain unknown cause as unknown. |
| Wrong library alphabet or exact installed-library pins rejected legitimate updated host dependencies | Verify actual required loader/custody semantics; correct demonstrated predicates narrowly. Do not disable OS protections, weaken ownership checks, roll back stable updates or repeat broad builds to diagnose unrelated failures. |
| Authenticate before snapshot adopted an external credential change | Retain the corrected snapshot-before-authentication order and distinguishing real Service/Backend regression; prove freshness/mapping separately. |
| Local work left uncommitted/ahead of GitHub; clocks/renamed attempts reset history | Complete signed normal delivery and fresh parity proof. Preserve cumulative failure/cost history. Agent-created elapsed-clock fields do not expire direct authority; explicit operator expiry and technical bounds still bind. |

### 9. Execution authority, evidence, stop rules and retention

This documentation task dispatches no host operation. Source work/local tests and
normal signed preservation are distinct from live execution. Before any new
native startup/authentication/provisioning or credential operation, identify the
exact current authority. Fresh credential/native qualification authority must be
explicit and operation-specific; this specification is not that authorization.
An authorization is consumed by its stated action, not reusable for another try.
Do not ask for renewal solely because an agent-created accounting clock advanced.

The lead binds actual source/artifacts, target, fixed recipe, prerequisites,
runtime/I/O/cleanup limits and exact action ID using the existing dispatcher and
`maint/ux/validate_acceptance.py --work-order-only --pre-action --attempt-id ...`.
The validator is a consistency check, not evidence truth or an authority oracle.
No new carrier/approval layer is required merely because a milestone advanced.

For each authorized action retain one concise existing dispatch/result record:
source/artifact identity, operation/stage reached, actual elapsed time, result,
credential submission/write certainty, independent state checks, control account
preservation, earliest sanitized failure, cleanup disposition and retained-resource
reference. Preserve bounded private streams only under existing private handling;
public evidence contains fixed codes and safe projections, never arbitrary native
output or exception text. Verify durable evidence by readback/hash before source
cleanup. Cleanup PASS is not functional PASS.

Stop on prerequisite mismatch, wrong target, unexpected account/service effects,
uncertain credential submission/write or lost required custody. No blind retry,
automatic old-password restore, weakened confinement, extended product deadline
or qualification Boolean is an accepted correction. Two failures at the same
functional boundary stop further workflow retries for combined independent
reassessment of the failed assumption, smallest changed action and distinguishing
test. Renaming packaging/review does not reset failure or effort history.

Probe165 retained two disposable SQL account rows, one SQL principal, two locked
OS users/groups, 33 runtime paths and new protected diagnostic/recovery stages.
Original cleanup remains UNCERTAIN; later independent no-write evidence does not
authorize deletion. Preserve historical execution160 stages. Prepare exact-owned
inventory and independent disposition separately; no wildcard deletion, guessed
identity, historical PID signalling or new Python cleanup framework. Any required
safe retained-state disposition remains a real open closure item, with its own
authority; it is not a reason to stop independent source work.

Store retained sprint artifacts under `/home/foo/Downloads/osmap-ux-s04/` using
private permissions as appropriate. Existing evidence roots and receipts in the
ledger remain authoritative references. Reuse them; do not create a parallel
status system. PM tracks measured actuals and UNKNOWN costs honestly, without
inventing a finish date or replenishing an exhausted explicit allowance.

### 10. Source delivery and completion decision

For each completed source unit, independently review the actual changed boundary,
run minimum affected tests and normal mandatory commit/push hooks, inventory all
tracked/untracked work and include eligible public-safe changes. Sign with
Shopkeeper `F55E404E91A0753701F91B01A7228D3FB5084B34`, verify the signature,
push normally to the approved branch, fetch origin and prove exact local/remote
SHA equality with zero ahead/behind. Preserve unrelated work and excluded secrets;
do not bypass hooks, force, amend or rewrite history. Do not run unchanged broad
suites between every small milestone; normal delivery gates remain required.

The lead and QA may declare **engineering complete** only when all four outcomes,
all 20 mapped obligations and required T01–T08 scenarios have matching applicable
passing evidence; installed Runtime/helper integration and authoritative timing
are verified; no required independent finding is unresolved; and owned recovery/
cleanup or expressly accepted safe retention is established. A FAIL, required
NOT_RUN or unresolved UNKNOWN keeps the slice open. Required release evidence
must match any release claim; this handoff does not claim full release readiness.

The operator then performs T09 usability acceptance. Only its recorded PASS after
engineering completion permits **S04-02 ACCEPTED**. Final delivery identifies the
signed commit/remote parity, installed artifact/config scope, T01–T09 results,
authoritative credential/epoch/session/cache/control-account observations,
remaining retained resources and their accepted disposition, and actual limits.

**Immediate next engineering assignment:** package B's missing current-backend
mapping/freshness/hash facts, followed by C's minimum Rust composition correction
and its concrete D native recipe. Do not substitute another generic readiness
proposal for those deliverables, and do not dispatch D without its exact authority.

## Retained specification and execution history

The sections below preserve earlier specification and execution context. Read
their method/authority statements with the supersession rules above; they do not
renew an action, reverse an operator ruling or change current ledger results.

## Approved reconstruction direction, 2026-10-24

The operator approved preserving successful login, reusing the existing TOTP
verifier, implementing the credential-change operation using PostfixAdmin's
method, and proving helper/epoch/session integration before routing working
functionality through it. This supersedes the ps-based worker-attestation
engineering route. It does not waive the four outcomes,20 obligations or T01–T09.
Existing implementation and local/historical passes do not establish working
step-up, race or session behavior in the reconstructed path.

Start by proving ordinary Runtime primary authentication, real file-backed TOTP
and session issuance with password mutation disabled. Preserve explicit admission
no-downgrade and stale-epoch refusal; unavailable mutation is a different capability
from explicitly configured unavailable admission. Reuse the same TOTP secret and
replay store. No second TOTP implementation is required.

The next credential boundary is a private account snapshot read, authoritative
Dovecot current-password verification, compatible hash generation, existing
conditional update/readback and truthful result. Capture the comparison snapshot
before authentication and retain it through the CAS. Establish exact canonical
identity, the authoritative passdb and cache freshness; do not invent a second
cryptographic implementation merely to mirror PostfixAdmin internals.
Separately prove real old-password rejection/new-password acceptance, required
epoch/session effects and the final browser journey. Every such milestone remains
unqualified until its matching functional evidence exists.

Before dependent implementation establish the current backend's actual schema,
hash policy/capabilities and applicable hook/cache contract. Historical Toronto
PostfixAdmin source is a method reference only. No new dependencies, unsafe
stored-hash exposure, public-service changes, automatic retry or qualification
flag changes follow from this direction. Python harness development is frozen;
use existing Rust fixtures and minimum changed-boundary checks plus normal
mandatory delivery hooks. The existing ledger records the concrete next action.

## Current topology correction, 2026-10-21

The operator confirms that development and production target a single-host
OSMAP plus mail-backend configuration. See
[S04.02 single-host execution](UX_S04_02_SINGLE_HOST_EXECUTION.md).
Existing two-host obsd1/Toronto SSH wiring remains historical fixture
evidence, not a required production mode or S04.02 completion gate.
Reuse existing native local Unix clients and the fixed Rust account
service sockets. The 20 obligations, four outcomes, D04, T01 through T09,
historical failures, and disabled native qualification gates remain
unchanged. No source/build/installed/human PASS follows this correction.

2026-10-21 prerequisite105 evidence reviewed: archive SHA256
9c2f2d957d8132d5cfaae4808a3810871bff73d229ea0a13e8cbaa3834612cc3,
portable sidecar and all archived/local member bytes verified. Capture PASS;
AUTH_GRAPH=MISMATCH, exactly3/22 checked objects. libc.so.103.0 and ld.so have
changed inode/mtime/ctime AND SHA256; ld.so.hints has changed inode/mtime/ctime
but identical SHA256. All other checked files/directories match. Recorded owner,
group, mode and size did not differ for these three. Remote0.126s, SSH/action
4.481s, exit0/no stderr/transport cleanup confirmed. No server writes, login,
password change or public service action. This proves the compiled helper's
HASH graph prerequisite rejects the observed installed state; it does not prove
that this was the sole104 failure or that SQL's additional graph matches.
OpenBSD upstream etc/rc reorder_libs intentionally relinks libc/libcrypto/ld.so;
this explains why persistent exact binary/inode pins are operationally brittle.
Actual cause of this host's replacements remains unverified. Do not disable OS
randomization, roll back system libraries, blindly repin or retry credentials.
Next source correction must handle trusted installed-library lifecycle while
retaining fixed paths, root ownership/DAC, bounded reads and per-operation
continuity; review the existing shared HASH/SQL checks before selecting its
smallest implementation. S04-02 remains OPEN; no product source or host change.


2026-10-21 source-first prerequisite comparison prepared (105), NOT RUN.
Research traced Authenticate -> NativeProfile::from_stock -> observe(Hash)
-> exact public HASH files/module/search-directory checks. Startup's metadata
check does not establish this later prerequisite. Literal pins match the helper90
compiled source; no actual mismatch or unique failure cause is yet established.
One operator-executed read-only comparison replaces another login retry. Reports
exact metadata/hash differences; a captured report and MATCH remain distinct
from authentication/password success. No repinning, credentials, provisioning,
public-service operations, build or production activation. Local focused and
existing pre-action declaration checks PASS; no native claim. Bundle:
/home/foo/Downloads/osmap-ux-s04/auth-prerequisite-20261021/VERIFY_AND_EXECUTE.sh
Archive SHA256 34d5e2b9f205521ce125ef677d73c7185799f15eaf50a9e701c4788651bce659.
Next review input: run/EVIDENCE.tar.gz and portable sidecar. S04-02 OPEN.


Current2026-10-21: capture103 observed primary_backend_unavailable(id2),401/no
cookie, prior to TOTP/password change; both-node cleanup confirmed. Diagnostic
capture PASS is not T03/workflow PASS. Underlying cause UNKNOWN. Next104 captures
only relay progress and existing helper error via cleanup receipts, reusing
compiled frontend102/helper90 and stopping after request2. Local checks PASS;
operator execution NOT_RUN. No added acceptance scenario or product scope.
Details and exact artifact references: docs/CURRENT_PROJECT_STATUS.md.


Actual diagnostic frontend build102 PASS (109.053s operator run),461 inputs
unchanged and owned cleanup confirmed; source/binary/evidence hashes reviewed.
Next is one diagnostic-only initial login capture, stopped at request2 before
a password route, using that binary. Capture-bundle local checks PASS, actual
capture NOT_RUN. This does not pass T03 or any full workflow scenario. Exact
current evidence and bundle are in docs/CURRENT_PROJECT_STATUS.md.

Operator-approved next action,2026-10-21: one frontend diagnostic compile-only
bundle on obsd1, with post-execution review of run/EVIDENCE.tar.gz. Independent-
agent pre-build review is replaced only for this action by the operator-accepted
recipe; no independent audit or native pass is claimed. Local preparation PASS;
OpenBSD build NOT_RUN; authentication branch still UNKNOWN. No password workflow
or production activation. See current delivery note and exact artifact checksum
in docs/CURRENT_PROJECT_STATUS.md. Nine acceptance scenarios remain unchanged.

Latest execution, 2026-10-21: signed d23092e helper build90 PASS74.165s,
460-input parity; capture90 PASS0.661s and fresh publication90 PASS24.924s.
Native90 FAIL9.027s at fixture stage3 before helper/HTTP/password submission.
The first absent shared directory was created0700 by umask0077 while its fixture
requested/asserted0750. One-line private0700 staging candidate has a local
counterexample PASS, not native qualification. Observation91 confirms the public
mail/SQL services and original configuration/master preserved. Backend cleanup92
PASS6.674s removes the two rows/principal/two roles/six files/two directories.
Frontend cleanup93 FAIL0.470s before mutation leaves four purpose files/nonce
directory retained behind its unresolved process-baseline guard. Original failed
artifacts are immutable. No journey
retry, installed activation, human UAT or parent acceptance follows this run.
Exact evidence: `/home/foo/Downloads/osmap-ux-s04/prototype-d23092e-20261021/`.

Current outcome, 2026-10-20: S04-02 remains incomplete; production password
form, ordinary production setup, installed QA and UAT are not qualified. Actual
workflow85 FAIL101.297s: request11 (fresh password form) began with1624ms of the
fixture's90s aggregate budget remaining, timed out reading after1635ms with zero
bytes, and total sequence elapsed90010ms. Ten prior HTTP exchanges and four
backend snapshots completed, including the password-change response/new-password
login. This proves aggregate test-budget starvation, not a unique product/page
fault or its underlying88.376s cost. Actual80 FAIL is retained. Independent
combined reassessment stops automatic workflow retries and deadline increases.
Read-only86 PASS4.3284s confirms backend RESTORED, synthetic rows/principal/roles/
runtime/producers absent, original authorized bytes restored, and public mail/
SQL/master preserved. Frontend purpose-only87 PASS0.544s confirms the known purpose slots/nonce are absent;
other HTTP scratch remains UNKNOWN retained. Two narrow canonical corrections are admitted: the installer's observed
ten-column FSTAT header (NAME), and deferred StockPrimary construction only
for authenticated Authenticate requests; readonly Admit retains runtime peer,
account, signed request, Store lock and epoch checks. The existing real-Store
current/stale/readonly-auth-refusal test PASS1/0failed; source/security review CLEAR.
No measured speed improvement or native/full-workflow PASS is inferred. The new
Rust source has not been rebuilt on OpenBSD; old75helper/63client evidence remains
limited to its earlier exact source. No flags or installed activation. Current
approval ends05:38:47UTC (01:38:47Toronto); no further full action plus disposition
and normal gate fits. Finish owned disposition, normally sign reviewed work and
stop without an automatic extension or push.

Current operator authorization, 2026-10-20 04:38:47UTC: one hour through
05:38:47UTC is explicitly approved. Continue the existing full password workflow
79/80 using signed3cad60, actual76 startup proof and existing reviewed artifacts;
then the smallest remaining integration justified by actual outcomes. Prior
passes/failures/idle intervals remain retained. No public mail lifecycle/config
change, lease renewal, new QA framework or inferred push authority.


Current verified outcome, 2026-10-20 03:55UTC: reviewed source normally committed
as3cad60f10a7fb9093f1075c874cbf7b8ec5f0922, Good Shopkeeper signature. Normal
mandatory gate PASS274.793681s (1861 library passes/0failed/50 explicitignores;
existing account Python620 PASS). All460 current compiler inputs match actual75
helper build manifest04607c05; no Rust rebuild. Actual capture75 PASS0.78s with
raw/gzip parity. Actual backend startup76 PASS50.565709s: StockPeer completed,
then expected ServiceFiles operation4/Unavailable with account material absent.
Temporary helper/stage/producers removed, SQL/auth/roles/rows/publicservice/config
operations zero. This is scoped startup proof, not helperREADY or password CAS.
Five first native component checks67 PASS0.738095s (fivepasses, zero failures or
ignored), native file/TOTP/rate/flock/ACK+EOF only, scripted backend dependencies.
No literal concurrent issuance, full T04/T05, installed workflow or UAT claim.

The existing full workflow79/80 is prepared and independently reviewed, with
signedHEAD3cad60 and actual76 bound. Its650-second functional plus560-second
conditional disposition reserve no longer fits the current04:08:38 phase.
No generator/profile mint, publication79 or native80 occurred. A15-minute
extension request is pending; elapsed time or its preselected option is not
approval. Do not lower existing bounds, reuse expired profiles or change public
mail services. Source remains unpushed; only subsequent progress documents are
locally changed. S04-02 remains open and the live password control stays disabled.


Current operator authorization, 2026-10-20 03:38:38UTC: a new30-minute
continuation through04:08:38UTC permits the normal signed reviewed-source gate,
then existing startup/password-workflow checks. GPG-agent readiness is operator
reported; actual signing must verify. All earlier failures/idle intervals remain
recorded. Source/native/install/UAT outcomes remain separate; public mail
services/configuration remain untouched. No push is authorized by this approval.


Current blocker, 2026-10-20 00:01UTC: S04-02 remains incomplete and UAT is
not ready. The reviewed executable-cap correction and actual OpenBSD build75
PASS are preserved. Source77 and77a were both refused by the pre-action validator
before Git/hooks/signing (0.061963s and0.061786s). The first declared paths beyond
its demonstrated gap; the second corrected its own recipe but left invalid77
in the active recipe set. Independent combined reassessment clears retirement
of that unexecuted invalid recipe only, with its exact proposal and both failures
retained. The corrected whole contract must pass static validation. No third
signed attempt fits the remaining300-second mandatory gate allowance before
00:04:32UTC; no gate has run or new commit been created. Ten owned changed files
remain staged for review; HEAD remains67711. Capture75/diagnostic76, native full
workflow, durable deployment, installed QA and owner UAT remain unexecuted/open.
No public mail service/configuration action or synchronization was performed.


Current disposition, 2026-10-19 23:57UTC: changed helper-only OpenBSD build75
PASS70.105s, all460 source inputs/parity and owned build cleanup confirmed.
Manifest04607c05 binds signed67711 plus exactly three cumulative source leaves;
new helper20598cfffab1b747b9748ba5039651277f962d5a99f46176a9e09dff2d4c6f74.
The63 client was not rebuilt and retains separate provenance. Capture75 and the
prepared no-account startup diagnostic76 are HELD/NOT RUN so their full bounds
and the300-second normal signed-source gate fit the current phase honestly.
No startup PASS is inferred from this build. Next functional action requires
matching ordinary-helper startup proof, then a fresh controlled full workflow;
production qualification flags, durable deployment and installed QA remain open.
Source77 pre-action FAIL0.061963s refused an overbroad recipe path list before
Git/hooks/signing. Successor77a changes only that declaration to the three Rust
gap paths, retaining all ten independently reviewed staged files and normal
hooks. Its actual result is external at resume63/source-preservation77a/result.json;
no PASS is predeclared. S04-02 is
not complete, no UAT is invited, and no synchronization is authorized.


Current actual source outcome, 2026-10-19 23:52UTC: S04-02 remains open and
not ready for UAT. Diagnostic73 collected StockCachePin/Unavailable, with its
owned helper/stage removed and no SQL, account or public-service action.
Read-only metadata74 PASS3.856324s measured the fixed doveconf executable at
209,968 bytes, above the generic128KiB reader limit. The reviewed correction
uses the existing64MiB executable bound for only that fixed path and the existing
authentication executable; all configuration/SQL/passwd/other paths remain128KiB.
Custody, hashing, deadlines and operation order remain intact. One focused
production-limit regression PASS1/0failed/0ignored (compile6.88s; whole wall time
UNKNOWN); one assertion formatting correction follows. No qualification flag,
production installation or password workflow PASS is claimed. Changed native
build is pending; no source checkpoint closes T03 or the nine-scenario slice.


Current operator resumption, 2026-10-19 23:04UTC: complete S04-02 with managed subagents. Signed local source67711 and mandatory gate62 PASS278.959099s are complete; native changed-source workflow and installed QA remain NOT RUN. Root owns the one host/Git queue. Prepare changed compiler63/capture64, current55-bound publication65 and one fresh controlled journey66, with independent producer/cleanup/consumer review. Public mail services/configuration remain unchanged. One prospective3600-second phase ends2026-10-20T00:04:32Z; preserve prior costs/failures and never renew expired fixture leases. No push is inferred.

Local source gate61 actually failed after57.28046seconds: Rust tests passed,
but all-target clippy identified one remaining retained legacy Startup::native
constructor unused in the non-test library. Root adds one function-local
dead_code annotation, with exact byte parity after removing that line. No
function body, authority predicate, visibility, cfg or mandatory check changes.
The seven retained legacy annotations are now explicit; earlier six-annotation
records remain historical. Existing V10 scanners refresh only shifted current
inventory/hash links (count9558 and refined high0 unchanged). The failed hook
and zero-commit result remain retained. One changed normal-hook retry62, actual
signing and verification must finish within the same approved fifteen minutes.
Actual retry outcome is source-preservation62/result.json under the existing
stock-helper-start51 evidence root; no PASS is predeclared.

Operator-authorized local source preservation, 2026-10-19 18:36:53 Toronto
(22:36:53UTC), fifteen minutes through18:51:53 Toronto. The operator explicitly
approved the normal gate, signing and commit presentation. This supersedes the
previous allowance blocker only for that local task; it does not reopen native
execution, deployment, qualification flags or synchronization. Root verified
all seven reviewed Rust source hashes unchanged. Reuse the independent source
reviews, pure control58 and historical held-host prerequisite59 without reruns.
One normal signed commit runs existing mandatory hooks, then signature/current
state verification; failure stays failure and no hook is waived. S04-02, native
workflow, installed QA and UAT remain incomplete. The actual gate/commit/signature
outcome is recorded at stock-helper-start51/source-preservation61/result.json
under the existing sprint root. No prospective source entry predeclares PASS.

Current finite-phase blocker, 2026-10-19 20:15UTC: S04-02 is incomplete.
The285-second normal signed-source action was refused at20:12:42 before Git,
hooks or signing because only about260.5seconds remained to20:17:03. The latest
matching normal gate took262.306868seconds, so root will neither shrink the cap
on inference nor extend the allowance automatically. Seven reviewed Rust source
leaves, current documentation and derived V10 records remain preserved but
uncommitted and undeployed. HEAD remains5561df229bd438d5da2f72b7bdeb2e82bd522c3b.
Current changed source: pure test/typecheck PASS13.107661s; actual held public
authentication contract59 PASS3.968568s; independent source reconciliation CLEAR.
Changed OpenBSD artifact, full password workflow and installed QA remain NOT RUN;
flags remain false and UAT is not invited. All owned53 effects were disposed by
55/56; protected root evidence stages/failed receipts remain provenance.
Next bounded proposal is the normal signed local source gate and signature/
state verification, then operator review before synchronization under AGENTS.
A later changed native artifact/fresh controlled journey is still required.

Current source intake20:11UTC: the selected password service now uses a typed
stock-backend authority instead of the optional persistent FSTAT observer.
Legacy constructors remain unchanged. The same stock authority binds protected
configuration/SQL writer/cache0, master identity, held auth-client/kernel root
peer and direct auth child to SQL/hash/primary profiles. One changed pure control
and typecheck PASS13.107661s. Six function-local legacy dead-code annotations
are mechanical; no body/guard was suppressed. Existing V10 generators refreshed
only derived current inventory/hash links; total9558/refined high0 unchanged.

Actual public contract59 PASS3.968568s: a held zero-frame socket connection
observed one direct auth child UID/GID518 with exact one-token/no-overrides
argv, matching master/birth and protected socket/root-peer custody.57's idle
absence remains true historical evidence; it did not establish a UID mismatch.
Actual53 backend55 PASS6.574204s and frontend56 PASS0.513s disposed all current
owned operational effects, preserving original public25/master/authbytes/security
and failed flags. Root evidence stages remain provenance.

Release/WSTG boundary: authentication/authorization/session controls remain
qualified only to their recorded source or native evidence. Historical53 is
FAIL, changed-source native workflow and installed QA are NOT RUN, and human
T09 is not invited. Both qualification flags stay false; source/gate/commit
results never close S04-02. One normal signed local source admission is pending;
its actual result/signature live at reduced-stock-path/signed-source-result.json
under stock-helper-start51. No new native build, fixture, deployment, password
operation, public service/configuration change or synchronization is included.

Superseding19:32UTC resumption: the operator requests completion of Sprint S04,
starting with this slice. Signed source baseline is5561df229bd438d5da2f72b7bdeb2e82bd522c3b;
normal mandatory gate and signature PASS. The current45-minute root-chosen
phase retains all prior costs/failures and closes at20:17:03UTC. The minimal
helper-start source correction passed focused actual-method controls and
independent source/whole-chain review; exact new publication/admission remains
required. Reuse the actual compiler38 artifacts with their original manifest,
separate from current publisher identity; do not rebuild unchanged Rust or
replay an expired profile. S04-02 and UAT remain open pending actual workflow
and installed qualification. Earlier no-retry statements below describe their
expired phases and do not override the current admitted work order.

Current18:34UTC outcome: S04-02 is IN_PROGRESS and UAT NOT READY. The stock
adapter's changed command control and matching460-input OpenBSD compilation
passed. Actual workflow46 failed at the helper-start stage, before HTTP/password
processing. Its exact exit/stderr were not retained; unique cause UNKNOWN.
No further functional retry or production native-flag activation is authorized
in the current phase. Retain all20 obligations and nine scenario IDs.

Actual read-only observation47 confirms current helper/owned-role/actor/fixed
utility absence, zero helper-inode references and absent private sockets, while
preserving the original failed receipt/flags. This is not fixture cleanup PASS.
Backend disposition48 subsequently passed6.071819s, preserving original
public25/master/authbytes/security and original failed receipt/flags. Complete
only normal source preservation. Actual frontend50 passed0.601s, removing
all four owned files and the empty nonce root, preserving the shared key
directory/historical bridge processes. The earlier local49 registration typo
refused before SSH in0.011s and remains retained. Current operational effects
are disposed; retained root evidence stages/receipts remain provenance. Earlier backend/frontend effects35/41 and42/43 are disposed;
their results do not qualify the failed46 fixture or the installed product.
The operator rejected the outage-dependent test design: no selected test may
control public Dovecot/Postfix/MariaDB lifecycle or public configuration.

Current17:50UTC clarification: stock adapter source is integrated and its one
changed-command test passed. Actual disposition35 removed the old backend's
two synthetic rows/principal/runtime files/six roles; original evidence and
public mail configuration were preserved. Frontend purpose-file disposition
is separate. The original459-input compiler packet failed for a missing existing
literal SQL-template include; changed package38 includes460 inputs with identical
Rust bytes. No installed/native workflow pass or UAT readiness is claimed.
Earlier retained-state and hold descriptions below are historical when superseded
by the active ledger and exact later result; no failed test is rewritten.

Status: IN_PROGRESS, source-only resumption under the operator's explicit correction at16:55UTC on2026-10-19. OSMAP is the web frontend; retire the test/cold-cutover design that needs public mail downtime. No new test may stop/start/restart/reload public Dovecot/Postfix/MariaDB or change their public configuration. Review the smallest existing account-operation path before any changed native action. Earlier functional29 failed before HTTP; restoration32 restored original mail access. Its precise outage cause remains UNKNOWN and will not be investigated by replaying the unsafe setup. Source31 is isolated and not native qualified; retained SQL/runtime/roles/frontend material remains explicitly protected, not full cleanup PASS. Engineering completion and human acceptance remain OPEN; UAT NOT READY. Original costs, failures and expired allowances remain preserved.
Project coordination and sole canonical integration/host/Git executor: `/root`.
Independent current source/evidence and delivery-control review: `/root/delivery_controller`;
`/root/password_engineer` owns isolated product source preparation and
`/root/guardrails_engineer` owns the existing validator/tests and isolated HTTP/
backend-bootstrap producer preparation. Prior independent source
reviews remain provenance; authors do not clear their own changed code. This specification applies the operator's
2026-10-16 SOP to the slice already in flight; it does not claim that earlier work
followed this contract or that historical component passes closed the slice.

## Current bounded execution — 2026-10-19

Superseding actual outcome14:43UTC: corrected action22 FAILED7.457s in backend
provision before HTTP/password mutation. Fresh observation PASS4.113s confirms
the retained partial setup (two synthetic rows, three purpose identities,
fifteen files and three borrowed directories), not successful cleanup. Original
configuration/master and untouched bootstrap targets match recorded custody.
The final fragment-reload operation is localized; its precise guard is UNKNOWN.
An independently reviewed narrow partial disposition remains NOT RUN because
its complete action ceased to fit the cumulative14:46:12 deadline. Dispatch is
held; no third workflow or agent-only allowance increase. All nine scenarios
and twenty obligations remain; T03/T07 and installed readiness are not closed.
The universal SOP in AGENTS/framework now makes root explicitly accountable
for enforcing real prerequisite checks and the cost/failure stops. Policy
codification is not password-feature completion.

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
regression and expiry refusal. Actual native19 then passed the admission-only
prerequisite in26.401s with confirmed owned disposition, independent30af33e9;
the complete installed password workflow is still unqualified. Root/controller
explicitly recorded2400s additional allowance, cumulative9600/global11:56:12UTC,
retaining original7200 and all spend/failures. After actual C04 and material
observations, root/controller explicitly approved1800s further source-only
integration, cumulative11400/global12:26:12UTC. No native/build is admitted by
that source window. Its exit is the executable two-host node producer using the
existing HTTP journey, four fixed snapshots, one mail witness and ordered
producer-stop/backend-restore/frontend-dispose cleanup. Wire-only source does
not qualify this exit or any scenario.
The actual current474 composition then compiled successfully on obsd1 without
running an application/account/service action. Subsequent Python-only custody
changes need their own exact source review and unchanged compiler/include
closure proof; they do not justify rebuilding identical Rust. Concrete actors
and SMTP/IMAP witnesses are source-only. Root/controller explicitly approved
the next1800s fixed-recovery source window, cumulative13200/12:56:12UTC, because
original metadata/current publication leases and service/purpose restoration
authority must survive connection loss. Whole paired native execution remains
HOLD until that specific producer/consumer closure and exact owned synthetic
maildir scope pass independent review. No product requirement or test is waived.
Actual two-host observations prove purpose keys/forced entries/connectors absent
and identify the current frontend drop. Complete those concrete producers;
never promote admission or source mechanisms to a complete password scenario.

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
success requires actual account-specific authentication-cache handling, all
OSMAP browser-session revocation, old-password rejection/new-password admission
and Bob preservation. The later global submission-proxy/IMAP-plugin design is
superseded by the adapter-scope correction below; it is not a frozen product
requirement and its failed tests are not reclassified as passes.

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

## Qualified adapter scope correction — 2026-10-19

Independent requirements review reconciles the selected implementation with
the accepted controls. R2-22-011 requires revoking every browser session,
including the current one. R2-22-012 requires actual new-password admission and
old-password rejection by the authoritative mail backend. Accepted D04 explicitly
warns that existing SMTP/IMAP connections may outlive credential changes and
requires truthful reporting of the qualified adapter's actual impact.

The selected adapter therefore owns the authenticated user's conditional SQL
credential update, current-password/fresh-TOTP checks, account authentication
cache handling, durable OSMAP epoch/login-issuance lock and browser-session
revocation. Existing third-party SMTP/IMAP connections are outside its termination
scope and may remain authenticated. The UI and audit must state that limit;
neither an authentication-cache flush nor old-password rejection proves those
connections were terminated. OSMAP-owned resources must still be disposed safely.
Bob's credentials, browser sessions and mail connections must remain unaffected.

Global public-mail epoch hooks, a new SMTP proxy topology, PF redirection,
cold-generation retirement and public-service shutdown are selected architecture,
not additional acceptance requirements. Retire those tests from the next method.
Preserve their original FAIL/UNKNOWN evidence. The same nine scenarios and20
obligations remain, with OSMAP login races and actual backend authentication
impact tested at their correct boundaries. No missing native authority may be
replaced by a qualification Boolean. This is an execution-method correction,
not a frozen-plan amendment or a claim that the adapter has been implemented.

## Authority and scope

Preserve accepted R2 `6b3ce8fff27ca3dabf87039d54098bd9967a2e42`, signed R3
`f2a117c17dbd93b634f9914c5608473dc682d8e0`, the frozen slice catalogue,
D04 in `UX_DECISIONS.md`, 110 legacy cases and 403 approved controls. This is
an execution specification, not an amendment to product requirements.

The exact 20 obligations are UX11-002/003; R2-10-005/009;
R2-20-001/002; and R2-22-001 through R2-22-014. They remain mapped to the four
outcomes in the active `UX_EXECUTION_LEDGER.md` work order:

- **authoritative-native-password-workflow:** a verified own-account credential
  update with exact backend authority and verified mail-authentication impact.
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
session, required account-specific authentication-cache handling, old credential
rejection and new credential admission. Disclose that existing third-party
SMTP/IMAP connections may remain authenticated; do not claim their revocation.
Preserve Bob's credential,
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
validation and authoritative backend qualification use the local single-host
stack on obsd1 `192.168.1.44`, expected hostname
`obsd1.blackbagsecurity.com`. Toronto is the later independent production
installation target; do not contact it for this development phase. Label host
evidence correctly and retain historical two-host results as historical only.
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
  OSMAP browser revocation and authentication-cache handling, old rejection/new
  admission and Bob preservation. Expect one verified change, all browser
  revocations, actual cache-handling witnesses (source-bound cache-disabled
  evidence for the selected stock adapter; no invented flush), exact
  completion/reap and owned disposition. This scenario currently
  FAILS; historical local component passes do not override that result.
- **S04-02-T04 — pre-write authority, replay and races (native):** age299/300 boundary (valid at299 only if all other checks pass; refused
  at300), consumed permit/TOTP, wrong binding/current password, durable
  account/source limits across success/restart, stale epoch and concurrent
  issuance/mutation. Expect refusal before write, no second dispatch and no
  OSMAP authentication/session issuance through a locked/stale epoch; preserve
  Bob and active limits. This does not require adding epoch hooks to third-party
  public mail login.
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

The current ledger records T01 and T02 as PASS at their defined source scope.
The later October16 T01 evidence includes actual Edge155 independent visibility
controls, keyboard, trusted paste and populated Cancel/navigation with no
submission, clipboard API, storage or network effects. T02 adds actual stored
session refusal and the targeted malformed/policy cases. The independent
controller reconciled these later records on October19; the earlier PARTIAL
assessment is superseded only at source scope. Reuse these matching passes.
They do not establish matching installed browser/backend behaviour required by
T06–T08.

## Historical findings and remaining-work provenance

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
