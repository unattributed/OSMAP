# S04-04 — Governed account recovery

Started 2026-10-29 (America/Toronto) from accepted S04-03 source
`6c509a542dfc30129e23b838b1faf7cd01608f4e`.

## Observable outcome and authority

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
