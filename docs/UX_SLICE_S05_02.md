# S05-02 — Practical public-key and email-policy management

**Current 2026-11-01: owner confirms ASC import, automatic email recognition and Off default work. The owner has now reported `UAT = PASS` for the installed People-style Contacts and Compose handoff. Historical failures are retained.**

Started 2026-10-31 (America/Toronto) from signed S05-01 closeout
`279df22e6ceb384410b151a4acc9134e67dc3e25`. The operator acknowledged the
infrastructure closeout and authorized this slice using the same failure-analysis
method. This slice has a real visual/functional browser UAT.

## Owner correction — optional fingerprint, 2026-11-11

Outcome: a signed-in user can import one public .asc certificate without knowing
or entering its fingerprint. “Expected full primary fingerprint (optional)” may
be blank; OSMAP derives the internal primary identifier from the uploaded file.
When supplied, the expected full fingerprint must still match exactly. The
existing authoritative inventory displays the imported full fingerprint in
Details. Import alone does not verify identity, approve a binding or enable
encryption. Password and fresh authenticator verification remain required.

Implementation stays in the existing Web key-management path. For blank input,
a bounded v4 public-primary packet identifier is calculated per RFC 9580 section
5.5.4.2 using the existing SHA-1 library. It feeds both the in-use guard and exact
native import target. The same certificate bytes reach the unchanged native
worker, whose public-only, one-primary, exact-match and import-result checks and
keybox CAS remain authoritative. No native protocol, helper, dependency, trust,
private custody, recipient policy or autosave change is included.

Minimum checks: independently known primary fingerprint, blank/omitted field,
explicit matching/mismatching value, malformed/oversize/secret/multiple-primary/
unsupported certificate refusal, in-use refusal before RPC, unchanged account
and revision/fresh-authentication controls. Exercise the actual multipart HTTP
Runtime/native import using disposable keys on obsd1; never replay owner
credentials or perform an owner key import. Native source is unchanged; qualify
the changed Web composition, then install only the reviewed Web candidate with
existing backup, rollback, protected-state and mail-availability checks. Owner
retests import with their own authentication after engineering readiness.

Root owns integration, Git, native queue and documentation; /root/s08_scrum owns
the bounded key-management correction; /root/s08_delivery_review independently
reviews source, QA, security and delivery. Use the failure -> analysis -> smallest
correction -> distinguishing retest method. Two failures at the same boundary
stop retries for combined reassessment. This new owner-directed correction has
an initial cumulative investigation allowance of 14400 seconds; historical S05
and S08 failures/costs remain retained. Native builds/fixtures/install retain
existing fixed technical bounds. No calendar expiry is invented. Token and
monetary costs are UNKNOWN. Private retained artifacts remain under
`/home/foo/Downloads/osmap-ux-s05/optional-fingerprint-20261111/`.

Original accepted S05-02 journeys and pending S08-06 owner review are preserved;
this follow-up does not reopen or declare whole-sprint/release acceptance.

### Optional-fingerprint owner acceptance — 2026-11-11

Owner reports **UAT = PASS** for the installed optional-fingerprint correction.
This follow-up is **PASS / ACCEPTED / CLOSED**. Matching source/native/installed
evidence below is reused; no further import test or deployment is required.
Prior S05 acceptance and the separate pending S08-06 review remain unchanged.

### Optional-fingerprint engineering result — 2026-11-11

Signed source `4a6eae5fa2991186c6f7be53bddd3dede0fbc0df` passed normal
security-check publication (2362 Rust PASS, zero FAIL, 91 ignored) and fresh
GitHub equality. Focused source results retain the original unsupported-fixture
failure (33 PASS/1 FAIL/1 ignored), corrected exact case PASS and six route PASS.
Actual obsd1 omitted-fingerprint HTTP/Runtime/native import and optional-form
cases each PASS; explicit mismatch leaves the keybox unchanged. All 598 archive
source/fixture/Cargo inputs and seven native logs matched by readback/hash.
Native execution took 260.785 seconds; functional case 72.91 seconds. Disposable
resources were cleaned only after durable evidence readback/hash.

Web-only installation took 3.111 seconds. Loaded binary
`d39a4a4876b465084315d09df39f2f711f229980a4e9fedaff4be7179bd639d8`
passed service/loaded-inode, protected-state and HTTPS checks. Public mail,
helper/account/GPG processes and four configurations were preserved. No owner
key import, credential replay, message operation or policy mutation occurred.
Independent source/native/installed-record review GO.
Owner acceptance of this correction is PASS as recorded above; original S05
acceptance and pending S08-06 review remain unchanged. No full
release qualification is asserted.

## User outcome and design

Settings -> OpenPGP -> Manage Keys shows imported public keys, their usable email
identities and the policies actually applied. ASC upload extracts those identities
without a separate manual address-binding step. New unique matches default Off;
saved policies retain precedence and ambiguous matches require correction. Email
identities and policies are visible without expanding cryptographic details.
Full fingerprints, algorithms, dates and subkeys remain available under Details.
A certificate without a usable email identity is shown unassigned. Selecting an
address does not enable encryption or grant private-key operations.

The latest operator direction makes the practical list primary, superseding the
old diagnostic-heavy presentation while retaining full-fingerprint authority,
explicit approval and the existing no-JavaScript interface. Preserve the frozen
reference files and all original functional/security obligations.

- Frontend: existing server-rendered keys/settings pages, responsive CSS, clear
  native links/forms/details. Prefilled email/key/policy editing uses existing
  strict action fields; no browser script or new dependency.
- Backend: reuse Rust key-management actions, private revisioned binding store,
  authenticated public-admin/inventory helpers and GPGME public-key worker.
  Fresh current-password/TOTP authorization and an actual stored-session guard
  protect effects; no caller-provided account or private-key path.
- Policies: Optional encryption is labelled **Off by default**; importing or
  associating a key does not enable encryption. Required is **Require encryption**;
  Disabled is **Do not encrypt**. Show account-wide overrides and conflicts so a
  recipient's optional policy cannot conceal required encryption. Signing remains
  a separate setting. Existing explicit policies and compose preferences persist.
- Persistence: current bounded account-owned stores and helper keybox CAS, no
  migration/new database. Removal preserves private-key material and trustdb;
  bound keys must be unbound before public deletion.
- Security: exact primary fingerprints, account isolation, escaping, strict
  fields/CSRF/origin, current session authority, fresh factor/replay, stale-write
  refusal and bounded public-only import. Unknown capability stays unavailable.
- Failure/recovery: preserve working settings and unsent work, no ambiguous
  automatic mutation retry, safe secret-free notices and exact-owned native
  fixture disposition. Reuse matching S05-01 native/security evidence.

Retained email-binding renderer work in `/home/foo/Workspace/OSMAP` is reused
without overwriting that checkout. Its earlier focused evidence is historical,
not installed acceptance of this expanded slice.

## T01–T09 verification

| Test | Required result |
| --- | --- |
| T01 inventory/identity | Readable imported-key list with exact owned email associations, missing/unassigned/unavailable/expired/revoked states; foreign and hostile metadata refused/escaped. |
| T02 public import | Existing public-only import works with actual native keybox, bounded input and fresh authorization; secret/malformed/wrong-fingerprint/stale imports preserve state. Import leaves encryption choice off by default. |
| T03 binding/policy | Actual revisioned account/recipient changes and policy persistence; visible global/per-recipient effects and conflicts; reauthentication/replay/session checks enforced. |
| T04 removal/rotation | Actual public remove/import and binding replace/unbind; in-use/private-key/stale removal refused with existing private/trust bytes preserved. |
| T05 isolation/admission | Wrong/expired/revoked sessions, CSRF/origin, foreign account and stale fields cannot reach authorized effect; current stored-session lease covers mutation. |
| T06 failures/preservation | Unavailable helper/store, invalid input and interrupted operations give truthful bounded notices without automatic retries or existing-state loss. |
| T07 persistence/custody | Native store/helper replay/CAS and private-key guard, unchanged real owner bindings/profile; reviewed operator-only private-key custody/unlock procedure and disposable native evidence. |
| T08 installed/browser QA | Source/native engineering reviewed; actual browser keyboard/mobile/light/dark/errors checked, matching Web candidate installed on obsd1 with protected-state/service/readiness readback. No public mail-service restart or owner key/policy write. |
| T09 owner UAT | Owner sees expected real email/key/policy list and completes selected public-key/binding/policy actions with their own fresh authentication after engineering/installed QA. No credentials requested in chat. |

All 34 original mapped obligations (three frozen legacy records and 31 approved
controls) remain in scope. Results advance only with actual matching evidence;
frozen legacy bytes remain unchanged. Key-management UI readiness is separate
from S05-03/04 completion, outbound provider delivery and production release.

## Execution and custody

Root owns integration, ledger, signing, Git and the single native/deployment
queue. UI and bounded Runtime correction have separate file owners; independent
review covers source and actual outcomes. Native verification uses fresh private
disposable homes and existing Rust tests/helpers, then cleans exact-owned agents
and scratch. Owner private keys, credentials, account/recipient approvals and
mail-service configuration are preserved.

The installed update is Web-only with a hashed backup, environment/state
preservation and a verified rollback route. No helper replacement or public
Dovecot/Postfix/MariaDB restart is required. Compile with the already successful
S04/S05-01 per-process profile; do not create a RAM floor or service-policy change.
Essential changed-boundary tests precede normal delivery gates; retain failures,
diagnose and make the smallest correction before retrying.

Private evidence root:
`/home/foo/Downloads/osmap-ux-s05/s05-02-20261031/`.
Engineering, installed readiness, signed synchronization and owner acceptance
remain separate. Native and source results below record actual execution; installed and owner acceptance remain separate.

## Bounded results and downstream limits

Focused rendering, route and Runtime authorization tests pass. The actual
synthetic Rust HTTP browser journey shows the imported list, exact approved
identity/policy rows, initially collapsed technical details, keyboard editing,
empty fresh-authentication fields and public-only import guidance. Desktop1440,
tablet768 and mobile360 widths have no horizontal overflow. Light/dark theme
saves, account-required override/conflict, missing-key identity retention,
unavailable inventory and foreign-account exclusion pass. A new compose draft
remains unencrypted. These browser observations do not substitute for native
mutation or owner UAT.

The native crypto worker retains an operator-configured recipient-fingerprint
allowlist. Public import plus an approved OSMAP association does not extend that
list or prove a protected send for an arbitrary new correspondent. Qualify that
downstream integration in S05-03/S07; this slice does not grant new crypto-service
authority. Public-key readiness also does not prove private-key availability.
The existing private-key custody/unlock SOP is reviewed; no owner private-key
import/export or unlock operation is performed here.

Failure history is retained in the private evidence root: revoked-session and
cached-admin-read regressions were reproduced and corrected; an obsolete route
expectation was updated to the visible inventory contract; a native fixture
field typo was fixed before host use. The first browser launcher lacked the
optional Playwright module, so the existing Rust preview and CUA were used.
An expired preview and an incorrect theme-control locator are QA failures, not
product failures. A fresh bounded preview completed the actual browser checks.


## Native execution — 2026-10-31

Signed source `fa26102d5c2603cc5c298c845910a01ae072766c` was archived and
built on obsd1 with the previously qualified one-job/private-home-TMP/4GiB DATA
profile. Actual native libtest and Web compilation passed in164.63seconds.
Web SHA256 is
`179342ac1db9eb7043db5be7ee933249533c13ca785111e50096c731e2d96f16`;
libtest SHA256 is
`97f9db144d2c8b26c18e3ef0478647d5f314fea83f82e4701497f76e91e8b88b`.

The exact native public-admin store transaction and Runtime key-management
journey both passed. The runner verifies exact test listing before selection,
so a zero-test execution cannot count. Fresh authorization/replay/policy state
was used for Runtime after the store transaction restored its correspondent
certificate. Actual Runtime mutations, TOTP replay refusal, policy preflight,
recipient removal, public removal/reimport and revoked-session refusal passed.
Private/trustdb bytes were preserved; disposable agents and scratch were cleaned,
with a fresh absence check. Primary password verification used the real process
adapter with a synthetic credential backend, not an owner Dovecot credential.
Per-test private logs were removed with successful disposable cleanup; the fixed
stage summary, binary/runner hashes, root dispatch record and absence readback
remain. Unchanged separate-principal confinement evidence is reused from S05/S04;
this fixture does not claim a new cross-UID qualification.

The current installed read-only helper probe also passed: two public keys,
confirmed account binding, one Proton recipient, binding revision5, account
signing/encryption Optional and the preserved Proton recipient Required.
Actual native encryption of fixed synthetic RAM data passed without SMTP or
key/policy/credential mutation. This is current helper/state compatibility;
matching new Web installation remains separate.

Full source tests passed2,091/0failed/75explicit ignores. The initial security
gate identified the new cfg(test) fixture's process calls as unregistered. After
the existing CWE test-only mapping was updated, the redundant shell scanner
reported the same omitted test-file entry. Both failures remain preserved.
Combined independent review checked the exact test-only registration and
negative controls before the matching existing scanner lists were corrected;
production rules and process admission are unchanged. Normal gates run again
against the final correction; passing Rust tests alone did not close that gate.


## Owner T09 walkthrough after installed readiness

1. Sign in normally at `https://obsd1.blackbagsecurity.com` and open
   `/settings/keys`. Check that the first visible section is Imported keys,
   showing the expected own-account and Proton email associations.
2. Confirm the existing policy values: the account remains Off by default and
   the previously saved Proton recipient remains Require encryption. Default
   applies to new unset choices; existing explicit policies are preserved.
3. Expand Details and key actions to inspect/select the complete fingerprint.
   The primary fingerprint remains the trust identity; technical metadata is
   secondary. Keyboard expansion and a narrow viewport should remain usable.
4. Open Edit policy or replace key for an existing recipient. The current key
   and policy must be selected, with empty current-password/authenticator fields.
   For a deliberately selected functional change, use the owner's current
   password and a fresh code in the browser, submit once, and confirm the saved
   identity/policy after reload. An uncertain result requires reconciliation.
5. Confirm a new compose draft begins Not encrypted when no saved policy or
   explicit message choice requires protection. This walkthrough sends no mail.

Owner feedback closes T09; the engineering/native tests do not fabricate that
human result. No private-key import/export or broad binding reset is required.


## Inherited status gap corrected before installation

The complete mapped-control review found that Welcome still displayed hardcoded
Unknown for five OpenPGP controls. An authenticated configured-state route test
reproduced that failure. Welcome now projects the existing owned key-management
state and saved composition defaults. Full saved fingerprints remain visible;
unavailable/foreign/missing/adverse key states and private readiness are distinct.
The change uses existing Gateway reads and preserves their audit events, with no
new store or effect path. New configured/negative/composition-persistence route
checks pass. A narrow timestamp-expiry check complements reported key flags.
The missing explicit discovery-Off notice was restored and a real recipient
rotation/CAS test added; neither required changing key effect semantics.

Actual CUA Welcome navigation now shows configured status, complete saved
fingerprint, Optional/off-by-default signing/encryption and self default, the
Required variant and truthful unavailable/foreign variants. Desktop and mobile
have no horizontal overflow. Double-click selection visibly highlights the full
fingerprint in the saved screenshot. CUA's unsupported DOM selection observation
and failed copy-shortcut dispatch are retained as QA-tool limitations; no
clipboard-API success or clipboard read is claimed. Final installed owner UAT
remains the browser acceptance boundary.


## Engineering and installed closeout — 2026-10-31

**S05-02 is ready for owner T09.** Engineering T01–T08 pass at their recorded
source/native/browser/installed levels; T09 is NOT_RUN and human acceptance is
pending. All31 mutable mapped controls are QA_VERIFIED with scoped evidence;
all403 obligations and the110 original legacy case bytes remain preserved.

Final production source is signed `831516bff45677411f7622b05a299a8ae928d40a`.
The matching obsd1 Web build passed in48.858seconds; installed/loaded SHA256 is
`fe44b3d20b4f518eccd6ad6a829b74459f6f66681b404b8b514bd91ded54f1a7`.
Only Web was replaced/restarted. Loaded inode129966, loopback listener, public
CA-verified HTTPS login200 and all eight checked service roles pass. Actual
protected manifests before/after are byte-identical, SHA256
`d9f3a0ceef1799355e1dae6d0bb21e58eeb45130359395159f64fdc5bf12f43a`.
Environment, account/PGP helper binaries, sessions, factors/revoked factors,
replay, recovery, settings, drafts and key homes remain preserved. Verified old
Web backup and reviewed guarded restoration are retained; rollback was not
needed. No public mail-service restart or database/owner credential change ran.

Post-install helper/state/preflight/RAM-encryption results are byte-identical to
pre-install: two public keys, binding revision5, owned account and Proton
association, account Optional policies and Proton recipient Required. No SMTP
submission, key/policy write or owner browser credential use occurred. Exact
probe and native scratch absence were freshly checked.

Current normal acceptance passes2,095Rust tests/0failures/75explicit ignores,
security and V10–V13; final V14/UI/accessibility and full validator checks pass.
Native key-effect proof remains bound to unchanged qualified fa26102 inputs;
only the final Welcome/read-only UI required the subsequent Web rebuild.
Independent final review is GO_ENGINEERING_AND_INSTALLED_QA, receipt SHA256
`45ddce76abdbe1d3c13d8028103c0ceae9a5a3a4076bc2dd60b64430e07b70b9`.

The browser observations use a disposable authenticated synthetic account.
The actual installed owner-state read uses authenticated helper clients as the
Web principal; it does not fabricate an owner Web session. The owner's live
login, view and selected authenticated save are the remaining T09 walkthrough.
Original source/gate/fixture/observer failures stay retained. Preview outer
execution reported143 despite successful libtest logs and fresh listener
absence; its parent signal cause is UNKNOWN without a captured signal trace.
Actual CUA observations stand independently; overall preview-carrier PASS and
clipboard-API success are not claimed. Arbitrary new-correspondent crypto-service
authorization, private-key provisioning/unlock execution and production release
remain outside this closeout. Signed branch synchronization will be separately
verified by the final delivery receipt.


## Owner import failure and measured correction — 2026-11-01

Owner reports public certificate02B34119C22074FC68B10E23E3294DF8DE68C834
was refused with generic key-management Unavailable. Actual live audits for both
POSTs04:02:50/04:06:34UTC show primary and TOTP accepted before HTTP503.
Fresh authenticated inventory/admin reads succeed; the live keybox has only
its two original keys, original bindings/policy and revision5. No owner
credential, factor, grant, binding or key import was replayed by the agent.
Healthy service status alone was not treated as import proof.

The exact661-byte public file (SHA256
`a2e0df77497fd625df11c4e4774cfa898d1d5a8ae9803d77e300c7ca522ef690`)
imports successfully through current Rust PublicAdminStore with the installed
C worker/engine on a private public-only clone. Browser CRLF armor also passes.
A separate fresh MAC/synthetic-account service using the exact installed
public-admin helper47cccbf9 also imports it successfully: two->three keys,
target present, trustdb unchanged. Each diagnostic preserves live keybox/trustdb
hashes; the disposable helper is stopped. This is not a live owner import or
fresh cross-principal qualification.

A leading blank/space variant is accepted by the old Rust validator but fails
native Store import with Unavailable in59ms, preserving the clone. The validator
trimmed input only for checking while mutation forwarded original bytes; native
armor admission requires BEGIN at byte zero. The smallest correction now shares
the validated trimmed ASCII slice with dispatch. Raw64KiB/ASCII/public framing,
full fingerprint, fresh factors, session authority, CAS and native private-packet
checks remain unchanged; interior CRLF and base64 '+' bytes are preserved.
Actual mutate/backend contract test reproduces RED then GREEN, with all9 focused
tests passing and strict Clippy passing. Oversized padding/private/non-ASCII/
malformed input still refuses before backend dispatch. The existing native
Runtime journey now imports padded armor through its real RPC path.

The owner request's certificate bytes were not logged or retained, so its exact
past payload cause remains UNKNOWN. This fixes a demonstrated paste defect;
it does not retrospectively prove that whitespace caused the owner failure.
The exact certificate's installed-helper clone success and subsequent current
native Runtime test qualify the correction before a single owner fresh-browser
retest. Existing owner inventory, policies, private keys and mail services remain
preserved. T09 remains failed pending that retest; no acceptance is fabricated.

Private diagnostics and failed/zero-selected test invocations are retained under
`/home/foo/Downloads/osmap-ux-s05/s05-02-import-20261101/`; zero-test selection is
not counted as verification. Existing test/worker mechanisms are reused, with no
new daemon, parser framework, database or public mail-service change.


## Correction installed; owner import retest pending — 2026-11-01

Signed correction80585eccc31c3b7d45e2864413060becf4c347c6 built on obsd1
in163.771seconds with the qualified compiler profile. Actual native libtest
SHA1118f710425b9fadc4f8243f631b59afb2e64927c997161febf2783f4d6749d3
ran both exact public-admin/Runtime cases successfully, including padded armor
through current Runtime/session/factors/RPC/Cworker. Fixed runner listing and
pre-dispatch hash guards prevent zero-test or stale-binary qualification; fresh
artifact readback and native scratch absence passed. Source acceptance passes
2,096Rust/0failed/75explicit ignores, security/V10–V13 and V14; strict Clippy
and focused nine-test suite pass.

Matching Web SHA256
`89b36d29b076d770c05e3bf47f6b1c49d793986d44901564f1677bc054334f70`
is installed/loaded (PID34969/textinode129979); loopback/HTTPSlogin200/eight
checked roles pass. Only Web restarted. Environment8edd312f and all seven
account/OpenPGP helper binaries remain unchanged. Protected before/after
manifests match SHA256
`f4a623e21f6eac8692d07242005e9c139ae577d26169362e48cdb429e53368ab`.
Post-install readback still has the two original keys, binding revision5,
account Optional policies and Proton Required policy; actual RAM-only encryption
passes. No owner import, credential/factor change, key/binding/policy write,
SMTP submission or mail-service restart was performed by the agent.

Four exact public-only diagnostic clone roots were removed only after durable
sanitized evidence readback, with no remaining sockets. The installed helper
used by the RPC clone had been stopped/reaped by its actor. The real helper
was never restarted. Original failure and differential evidence remain private.
Independent correction/installed review is GO, receipt SHA256
`6aa441c48c075454f95dda4815a19a5da333d86f1188ab99ab22d7bd4954deaf`.

The correction is ready for ONE owner fresh-browser import: reload
`/settings/keys?panel=import`, paste only the public armor block, confirm full
fingerprint02B34119C22074FC68B10E23E3294DF8DE68C834 and use the current obsd1
password plus a fresh unused authenticator code. Submit once and check for the
third imported key/full fingerprint. Import alone does not approve an email
association or enable encryption. Do not repeat an unavailable/unconfirmed
response; reconcile the new result first. The old submitted payload remains
unknown; this correction does not retrospectively prove its exact cause.
T09 and the owner import control remain unaccepted until that ordinary browser
path succeeds. Final GitHub preservation is verified separately by delivery receipt.


## Owner retry reconciliation and selected credential routing — 2026-11-01

Live sign-in at05:25:24UTC accepted both factors. Import requests at05:26:13
and05:26:42UTC were rejected at primary verification (403), before factor or
key effect. The owner confirmed both hosts intentionally use the same password.
The subsequent05:33:35UTC import accepted both primary and TOTP, then returned
503 in326ms. This later failure must not be attributed to the earlier primary
refusals or declared fixed by the routing correction.

Source inspection found sign-in selects `authenticate_account_primary`, including
the configured account-runtime admission service, whereas key-management step-up
unconditionally called the legacy Dovecot backend. Active obsd1 configuration
selects Duncan for the native-local account pair; the legacy auth path remains
`/var/run/osmap-auth`. Reuse the existing selector for fresh key authorization,
bind its captured authenticated account/epoch to the guarded session before
factor verification, and preserve no-fallback, replay, session and CAS checks.
No new daemon, dependency, credential storage or authentication bypass is needed.

Expected correction evidence: a distinguishing selected-accept/legacy-refuse
regression is RED before and GREEN after; unavailable and epoch mismatch refuse
before factor/effect; the existing native Runtime key journey uses selected
MAC-bound synthetic primary admission, real stored epoch session and TOTP plus
the actual public-admin/C import effects. Synthetic primary is not owner Dovecot
qualification. Reuse unchanged existing helper evidence and normal delivery gates.
Per native build remains bounded600s, fixture240s and Web-only install360s. Stop
on uncertain owner mutation; no repeated owner import is dispatched by agents.
Retain failures and actual elapsed history; a second same-boundary engineering
failure requires combined independent reassessment before a changed test.

Fresh readback after the primary refusals still reported two public keys,
binding revision5, Optional account policies and the original Proton Required
recipient policy. Existing RAM-only encryption passed, with no SMTP submission.
The latest503 requires another state reconciliation before any owner retry.
Private sanitized retry evidence is retained under the existing sprint root in
`s05-02-import-20261101/owner-retry-auth-reconciliation.json`. T09 remains FAIL.


The current correction also records only fixed result/native-error enums and
normalized public-certificate byte counts in the existing key-change audit event.
It does not retain certificate bodies, credentials, factors, grants or arbitrary
native diagnostics. Full HTTP percent decoding is covered in the existing native
journey rather than assumed from direct Runtime tests.

The latest public block supplied by the owner is byte-for-byte the original
661-byte `.asc` file, SHA256
`a2e0df77497fd625df11c4e4774cfa898d1d5a8ae9803d77e300c7ca522ef690`;
disposable public inspection confirms the expected primary and encryption subkey.
This still does not establish the bytes of the earlier HTTP submissions. The
latest live helper's durable mutation nonce was written at05:33:35UTC, so its503
occurred after authenticated helper mutation admission. Its loaded executable
inode matches disk; configured worker/engine/mapping files predate helper startup.
No automatic helper restart or owner mutation is justified by these observations.

A further discriminator may use the existing controlled `osmap-test` account
through the actual running admin daemon as Web UID1001. Prerequisites are exact
operator mapping, two original public keys, no target key or binding, and an
existing native removal guard proven before import. A homespecific temporary
GPG agent may supply the controlled public-only test home's guard prerequisite;
record and stop only that newly created agent. One confirmed import of the
normalized660-byte certificate may be followed by one removal of that newly
added test key, then readback of original inventory and unchanged trust/private
state. Any negative or uncertain reply is reconciled read-only; no mutation
retry or speculative cleanup is allowed. Bound the whole probe to90seconds,
retain failures, expected test nonce/keybox history and exact cleanup disposition.
Owner keybox, bindings, policy and credentials are excluded from mutation.


## Native permission failure reproduced — 2026-11-01

The isolated actual-daemon test accepted the known normalized660-byte public
certificate for the controlled test account, then returned Unavailable. A
read-only reconciliation showed its original two keys and no target; the owner
key/binding manifest, test trustdb/backup and agent cleanup were independently
verified unchanged. Metadata-only trace shows native worker and GPG success,
then helper refusal at staged-keybox file metadata admission, before publication.

A two-case direct test of the unchanged installed worker confirmed the cause:
ambient022 produced0644 `pubring.kbx`, while077 produced0600. Both native calls
returned0 with exactly the same three public keys and unchanged trustdb. The
actual launcher omitted an explicit mask; earlier native/clone fixtures used077.
The strict private-file predicate correctly refuses group/world permission bits.
The correction sets0077 at the isolated worker entry, before GPG children, and
adds077 to the generated launcher. It does not weaken file admission or change
the multithreaded Rust process's global mask. The existing native runner now
uses ambient022 immediately before its two effect tests, after private fixture
creation, to qualify the worker's ownership of its permission policy.

Actual old-worker differential evidence is private
`umask-differential.actual.log`; actual daemon refusal is `live-test.actual.log`.
The controlled probe's combined exit1 reflects functional refusal; cleanup was
checked separately through manifests, original test inventory and absence of
its homespecific agent/private directory, temporary client and certificate.
No automatic import/remove retry or live owner key mutation occurred.

Fixed-worker native qualification, atomic installation, actual-daemon retest and
owner browser acceptance remain pending. Only the admin worker and its launcher
need native replacement; the running helper can retain its process and load the
new isolated worker on its next call. Web routing/diagnostics candidate comes
from signed03eb8ad; later changes to that Rust module are confined to its test
fixture. Public Dovecot, Postfix and MariaDB remain outside restart/config scope.


## Permission and credential-route corrections installed — 2026-11-01

Signed03eb8ad supplies the installed Web5a325daa69dbeb2577f104cf222c5778fdaee845b547f30d62e92c5936a6aae8.
Signed617e11f supplies native-worker sourcec6b54f14 and launcher generation.
The Rust production path is unchanged between those commits; the later Rust
diff is inside the account module's test fixture, replacing its rejected shell
fixture with `/usr/bin/false` without a checker exception.

- Current normal acceptance:2098Rust PASS,0failed,75explicit ignores, security
  andV10–V13 PASS; V14 PASS. Strict Clippy/formatting PASS. An earlier shellscan
  refusal and a parallel stale-RPC fixture result remain retained; the latter's
  precise cause is UNKNOWN. The same exact isolated case passed, followed by
  the full unchanged assertions with standard `RUST_TEST_THREADS=1`.
- Actual native two-case runner PASS with ambient022, including selected
  MAC-bound synthetic primary, genuine epoch session, real TOTP/replay, parsed
  HTTP form and native public-admin/C effects. This is a same-UID synthetic
  primary fixture, not the owner's Dovecot/browser authentication.
- New admin workerab1da8bb1b50e75805916f8927818e548f128a90ab3ccd8c1cffa36262a36e14
  and launcherb83b127db084a3d6155f0825989ec650dc55442e5aa024ec8991f49217a7f4f2
  installed atomically. Running helper PID34710 stayed unchanged, retaining the
  failing ambient mask; no helper or public mail-service restart was needed.
- The same actual running helper, WebUID1001 and controlled test account now
  import the exact normalized660-byte target successfully:2→3keys, exact target
  present, original metadata unchanged. One confirmed removal restores the two
  original keys; trustdb, backup, empty binding record and owned-agent cleanup
  pass. This is the changed-worker live RED→GREEN discriminator.
- Matching Web installed, loaded PID93496/textinode129966/loopback/CA-verified
  HTTPSlogin200/eightroles PASS. Only Web restarted. Its protected before/after
  manifests match893534a76314e04e4cfaea20d165324867d44f91c468cedcef3c5f9873cb9c39;
  worker installation manifests matchf94ae0d951f425c4a6c5259458e544201dc830d6bdc8656b72479478993abbcb.
- Post-install owner readback still has the two original public keys and revision5,
  Optional account policies and the original Proton Required policy. RAM-only
  encryption passes. No owner key/binding/policy/password/factor mutation or SMTP
  submission was performed. The two public-only umask clones were removed after
  durable sanitized readback; native scratch, test agent and temporary clients
  are absent. Old binaries/launcher and guarded rollback are retained; no rollback
  was executed.

Current private actual evidence is bound by `routing-umask-evidence.json`, including
`fixed-native-functional.log`, `worker-and-live-fixed.actual.log`,
`routing-install.actual.log` and `routing-post-install-read.log`. Independent
review and final normal signed GitHub delivery are reconciled separately.

Owner retest: reload `/settings/keys?panel=import`, paste only BEGIN…END armor
from the original `.asc`, set full expected02B34119C22074FC68B10E23E3294DF8DE68C834,
use current OSMAP password and a fresh unused TOTP, and submit once. The expected
result is a third imported key with no approved email association yet; its Details
show the full fingerprint. Import alone does not bind email or enable encryption.
An unavailable or unconfirmed result requires read-only reconciliation before
another attempt. Owner T09 remains FAIL from the prior attempts until this
ordinary browser journey passes; import control stays PARTIALLY_VERIFIED and
the slice remains open.


Independent final correction/installed review is GO for agent-owned engineering,
with owner T09 still failed pending a fresh result. New private review receipt
`routing-umask-independent-review.json` has SHA256
`47a60aa20750ea0846b52239664f45cb91f3cc34bf20ec7905c71579a7f96186`.
Its precise scope distinguishes the historical primary-refusal JSON from the
later accepted-factor503, and explicit mask differential from the unmeasured
original live inherited mask. Prior review/evidence files remain unchanged.


## Owner-requested ASC file upload — 2026-11-01

The owner explicitly requests selecting the exported `.asc` file instead of
printing/copying armor into a textarea. Replace only the import form with a
bounded multipart file upload. Reuse the existing multipart parser, one-file
64KiB policy, strict action/CSRF/origin/revisions and the same fresh primary/TOTP
and native public-packet/full-fingerprint transaction. Filename/MIME are metadata
only; no browser filename becomes a server path, and no uploaded file or credential
is persisted by the web process. Other key/policy actions stay URL encoded.

Required tests: actual supplied filename and661-byte public file are accepted by
file transport; missing/empty/multiple/oversized/private or mixed text/file inputs
fail without effect; existing selected Runtime/full HTTP native journey uses
multipart and the previously qualified private-mask worker. Reject legacy pasted
imports to keep one ordinary UI route. Existing attachment filename policy rejects
`@` in the owner's exported filename; permit this ordinary metadata character
while retaining all path/control/header/length restrictions, verified by the exact
filename regression. No new parser, dependency, service or credential storage.

The newest owner attempt is a separate failure boundary: sign-in at06:44:35UTC
accepted both factors, then06:45:34/06:45:52UTC import confirmations were rejected
at primary verification, before factor/native dispatch. The owner confirms manual
clipboard transfer from the correct Proton Pass entry. Current account epoch6 is
Active with unchanged Oct30 state/changed-at and no uncertainty marker; the owner
keybox is unchanged. The file-upload change does not establish resolution of that
primary refusal. Preserve it as UNKNOWN pending a successful ordinary browser
confirmation; do not capture/replay owner secrets or reset credentials.

Root owns one native/deployment queue, matching signed source and Web-only
installation. Native build retains proven4GiB/jobs1/debug0/private-home TMP with
600s per build; native fixture240s; Web-only installer360s with guarded rollback.
Two same-boundary failures require combined independent reassessment before a
changed test. Existing native worker077/atomic keybox/policy/credential/mail
availability boundaries remain. Owner T09 and S05-02 remain open.

## ASC upload installed; owner confirmation remains open — 2026-11-01

Signed source7fd9c424a425f3d916c00fc72021d42090051390 replaces the armor
textarea with one required `.asc` file chooser. Root's actual CUA check selected
the supplied original filename, confirmed the enabled control and zero armor
textareas, and stopped/reaped its synthetic fixture with fresh listener absence.
No owner credentials or import submission were used. Two Python fixture-import
preparation failures and a zero-test selection remain excluded from browser PASS.

Normal acceptance passes2,101 Rust tests/0failed/75explicit ignores, strict
Clippy/formatting/security/V10–V13; V14 passes separately. The exact OpenBSD
public-admin transaction and Runtime journey now pass actual multipart file
transport into the existing native consumer under ambient022. Disposable state
cleanup and a separate fresh absence check pass. Native build took163.987s.

Matching Web049d17c1e8bd16290c148175883a37e3713170582f8514ab42d4aa31e12ba14e
is loaded on obsd1 (PID60249/textinode129979), HTTPSlogin200 and all eight roles
healthy. Only Web restarted. Environment/helpers and protected file manifests
are unchanged (before/after328a9ba2ba62195862a1503d225c082a01280f370b27e530261f0bf805866c95).
Post-install helper readback confirms the original two public keys, revision5,
Optional account policy and Required Proton recipient policy; RAM-only native
encryption passes without sending mail. The readonly probe is removed.

Private `asc-upload-installed-evidence.json` SHA256
06ba6936d8d6e39da965003361214da692a607ca59166cfa633548f3886c71db
binds retained source/native/browser/install/normal-gate evidence. Source review
`asc-upload-independent-review.json` SHA256
ed0ad612295558374da316fb3f1ec05989c7ccdf7a2ca5323ba93cc5e101b622
is GO; final actual-result independent review is recorded separately.
The latest owner primary-confirmation refusal remains UNKNOWN, not repaired by
file transport. Owner T09 remains FAIL pending one successful ordinary browser
file import; import control remains PARTIALLY_VERIFIED and S05-02 IN_PROGRESS.

Final installed independent review `asc-upload-installed-independent-review.json`
SHA256 bc4ca497d9e7f86e5c21795a1bcba1873fcc0c2bacc379aaa861cf12856b9d3d
is GO for agent-owned ASC engineering/native/installed QA, with owner primary
UNKNOWN and acceptance still open. No production-release assurance is inferred.

## Automatic certificate email associations — owner direction, 2026-11-01

The owner directs removing separate manual email binding after ASC import.
Observable exit: upload certificate once with existing fresh authorization; its
usable certificate email addresses appear and resolve in actual compose without
a SetRecipient step, default Optional/encryptionOff. Existing explicit policies
and selected keys remain unchanged. Native GPGME supplies bounded email claims;
no filename/display-name/armor parser determines identity. A shared Rust resolver
deduplicates same-key addresses; different primaries claiming one address are
Ambiguous, never selected by order or expiry. No-email keys show a clear state.
Policy controls use certificate-derived pairs, validated against fresh inventory;
resetting saved policy returns to automatic/default behaviour. Account private
key selection and inbound verified-sender trust remain separate.

Use derived associations rather than a second durable binding write after
keybox publication. Final protected-send dispatch must detect an inventory
change as well as stored policy revision, using the existing account lock and
bounded reader. Optional metadata supports old workers; upgrade strict helper
consumers before activating identity-emitting workers. Only OSMAP services may
restart; public Dovecot/Postfix/MariaDB services and configuration are preserved.

Root owns resolver/integration/ledger/Git/native queue; runtime engineer owns
metadata/native-worker and native journey; scope QA owns practical UI/adapters;
protocol reviewer independently reviews actual source, rollout and results.
Required source tests cover exact UID association, multiple/no/invalid/revoked
UIDs, cross-primary ambiguity, saved policy precedence, tampered policy pair,
default plaintext/explicit encrypted use, stale inventory final dispatch and
old-worker compatibility. Existing native multipart journey must import a real
key and resolve/RAM-encrypt without a separate recipient binding mutation.
Reuse current failure history and matching passes; run normal gates at delivery.
Native build600s per phase/4GiB/jobs1/debug0, fixture240s and reviewed bounded
OSMAP-only rollback/install remain. Two same-boundary failures require combined
independent reassessment, no automatic uncertain credential/key retry.

Actual installed crypto mapping has two static recipient fingerprints and does
not authorize the newly imported02B34119 primary. Complete the practical import
route with trusted per-account allow_imported_recipients(defaultfalse), bypassing
only static Encrypt-list membership. Existing native worker requires the exact
usable full primary already in the mapped account's local public keyring, offline
with auto-retrieval/import disabled; it retains account confinement, MAC/replay,
signer/decrypt/private limits. No C crypto relaxation or extra inventory race.
Native journey must use actual authenticated crypto service with true and empty
static list: other-home/missing/subkey/private authority negatives and post-import
RAM encrypt positive. Coordinated rollout includes Web, inventory/admin/crypto
helpers and two inventory workers; enable the flag only for Duncan's development
mapping, preserving all other config fields/keys/bindings and mail services.
Atomic backups and guarded whole-set rollback must include crypto helper/config
pair. New post-install reader must use current metadata parser (old readonly
probe is incompatible with identity-emitting workers). No live owner import or
credential replay is required; existing imported identities need no migration.

Actual source6c799d92 native public-admin and Runtime multipart/UID/crypto-RPC
journeys PASS with exact cleanup. Root CUA then caught an own-account-only
spurious recipient chooser; the single HTML projection guard is corrected,
13UI tests and fresh CUA pass (no editable email inputs/ordinaryassociationlink).
Native effect inputs and native journey remain byte-identical to6c799d92; reuse
that executed qualification while rebuilding matching final Web/helpers/probe
from the reviewed UI checkpoint. No native transaction retry is warranted by
this HTML-only guard. Retain earlier compile/test/lint/visual failures separately.

Installed readback caught a real mixed-case identity defect before readiness:
GPGME address normalized cBwZTCpU to lowercase, conflicting with the existing
case-preserving mailbox matcher. Preserve first TARGET_CERTIFICATE_EMAIL_MISSING
probe failure and metadata observation. Prefer supported parsed uid.email, with
parsed address fallback; never use display UID or filename. Private actual-C
case regression is RED then GREEN. The existing native runner now includes a
mixed-case Alice UID and asserts its literal spelling through real GPGME output.
Qualify the C-only correction with the current Rust libtest, controlled native
journeys and actual target readonly worker read; then atomically update only
the two same-schema inventory workers without restarting the loaded helpers.
Re-run the identical installed Rust RPC/actual-policy/RAM-encryption probe. No
new owner import, credential operation or public mail change is involved.

## Automatic email workflow installed — 2026-11-01

The owner-directed ordinary flow is now ASC upload with fresh authorization,
then automatic certificate-email recognition and recipient resolution. No free
email entry or separate association action remains. Multiple valid identities
are supported, duplicate same-key claims deduplicate and cross-key conflicts
require a deliberate existing per-email key choice. New matches default Optional
(encryptionOff); saved choices/Required/Disabled policies retain precedence.
Existing imported certificates need no reimport or binding migration.

Final Rust Web/helpers/probe use signed5e8f44c; case-preserving inventory worker
and durable mixed-case native regression use signed160652b7c5ad93202b99e5b423ed482d6663fc6a.
Loaded Web91a0c8b8239c9ac848d4f973553f5c04b2fe0f2ab28d0c8b2a0529ce2931a557
and both workers710485f5d0901531bffc81e2f2a5ca82fc5fa3cb3ed2c72fb3f7cfaf3c7abcec
are qualified. Coordinated4OSMAP-role install preserves public mail services;
C-only correction preserves all four running PIDs. Protected worker-update
manifests both66d29b95ee4f7cfce686304d14eb5feea72b20ca7dc2f251f946ee1c6047c842.
The crypto config changes only Duncan's trusted local-import recipient option;
its new SHAe20954f584c872ca93c8ff5d5b13fcc0b74723e9fc3794ea1b5ea0daddee7670.
Signer/decryption grants and static entries remain unchanged.

The identical installed Rust probe that first refused the normalized case now
passes: BOTH Inventory/Admin RPCs return exactcBwZTCpU identity; virtual empty
record derives the correct primary/Optional default without a binding write;
actual saved record selects that same key; installed crypto helper encrypts to
it in RAM despite absence from the static recipient list. No SMTP/key/policy
mutation. Three public keys, revision6, two saved recipient policies, Optional
account protection and ProtonRequired are preserved; owner keybox40b478 unchanged.
Readonly probe and both native fixtures are confirmed absent.

Current focused/CUA and frozen V10–V13 checks pass. Earlier broad gate ran
2,113Rust/0fail/75ignored before generated drift during the final UI correction;
that failure remains a failure. Final normal signed pre-push must run complete
current-source Rust/security checks before delivery. Unchanged V14 evidence is
reused with current13UI/CUA results. Source/native review and installed review
are independent; installed reviewd09b261a9c0f44d51a131c1301303f04c51479f5d2e19a97976a53a3b877d3b2
binds root evidence4b3c9f4b7f2638b4218ecc46c5c7671b06c8f661ed1b3052c7af8562bb18b555.
Owner acceptance of the new workflow remains NOT_RUN; prior T09FAIL and primary
refusal history are retained, not treated as new-workflow success. S05-02 remains
IN_PROGRESS/importPARTIALLY_VERIFIED pending owner result.

## Compose imported-recipient integration — owner report, 2026-11-01

Owner confirms a fresh public key import, automatic certificate email and Off
default succeeded (user4-6pO@protonmail.com screenshot). Record positive human
evidence for that import journey; previous failures remain historical. Owner
then reports Compose's contact picker shows only saved contacts. This is the
S03-01B/S05-02 integration seam, not another key-import failure.

Observable exit: Compose offers saved contacts plus owned certificate-derived
recipient emails, deduplicated with saved labels preferred. Selecting one adds
its address to To/Cc/Bcc through existing draft-save, retaining protection flags
and content/uploads. No persistent ContactBook synchronisation or second import
write. Same common compose renderer covers initial/reply/resume/refusal views.
Use an account-owned bounded choice snapshot in existing ComposeProtectionView;
opaque domain-separated tuple hash IDs are selection handles, not authority.
POST rebuilds fresh owned membership; reject forged/foreign/removed/rebound/
ambiguous choices before draft mutation. Saved contact revision checks stay
unchanged. Independent source availability: imported choices work without a
contact book; saved choices work without inventory. No encryption toggle/trust
change from selecting an address. Tests cover these outcomes and existing
session/CSRF/origin safeguards; synthetic browser and installed readonly picker
projection checks precede a matching Web-only update. Reuse unchanged native
key/crypto/helper qualification. Root owns routes/integration/Git/host; runtime
engineer owns snapshot/core/view/fixtures; QA owns renderer and visual tests;
protocol reviewer independently reviews source/results/recipe. Normal signed
checks/preservation apply, no owner drafts/contacts/messages are mutated.

## Compose picker installed — 2026-11-01

Contacts belong to S03-01, specifically the S03-01B account-private contacts
checkpoint. S05-02 supplies imported OpenPGP identities; this correction joins
those existing functions. S09-03 retains final approved-reference reconciliation.
The `/contacts` page remains the saved address book. Compose's **Choose a
recipient** control groups saved contacts and imported public-key emails, with
saved labels preferred for duplicate addresses. No second contact-store write or
persistent synchronization is introduced. Selecting a recipient saves the draft
through the existing To/Cc/Bcc path and preserves content and protection choices.

Signed production source `e08068a4fa55c8990b6c68b24b681f75b41eb4e6` builds Web
`39f374975117b05eb3d5a54797c057dd3db75c54ed415af4207237a0e1e98b34`.
Focused source checks cover core7, routes9, rendering4, Runtime13, preflight3,
draft16, send-journal7 and send-result2; strict Clippy/fmt pass. Actual CUA at
1264px confirms imported selection alongside an existing recipient, saved draft,
retained subject/body and all three protection flags Off. The initial long-label
overlap was corrected with one short summary string and retested visually.

Actual native core7/UI4/contact9 and MAC Runtime projection1 pass. The initial
native contact fixture used ambient0755 and correctly failed private-store
admission after its draft assertions passed. Signed test-only correction
`a7343798e07d6817a85df14258bcdec05778babd` makes that fixture root0700; corrected
native libtest SHA305dc9ca46d07528f9e559571d324f73a36a76bac612aa638394a0c6b3c8ea53
passes9/0. Production sources remain identical, so the Web/observer builds are
reused. A zero-test exact selector is excluded; actual native `--list` and
one-match guard select the MAC projection test, which then executes1/0.
Earlier route-shadow and lazy-store cleanup failures remain retained separately.

The Web-only update is loaded on obsd1 as PID44195/inode129979. CA-verified HTTPS
login returns200 and eight roles are healthy. Environment8edd312f, both inventory
workers710485f5, all three Rust helpers and crypto configuratione20954f5 remain
unchanged. Protected before/after manifests both hash9e72c1387ea9832a168b38b203230ee3ba51d1416af271c9f7fe89142d16aaa5.
The current `_osmap` native-RPC/owned-record observer confirms four keys, four
imported choices and one saved contact; both recent imported recipients are
selectable, foreign selection is refused, and contacts/bindings remain unchanged.
No owner session was fabricated and no owner draft, contact, key/policy or mail
mutation ran. The observer is absent; failed public fixture cleanup is exact and
separate from its failed test. Rollback binary remains retained; no rollback was
needed. No public mail service was restarted or reconfigured.

Independent review108465a22e5339d498c8b14fb13bd55af24f4d44d7b9e057aca033ebcaf3706a
checks actual source/native/installed evidence and retained failures. Private
`compose-picker-installed-evidence.json` hashes every matching record. The normal
push hook and fresh signed GitHub equality remain final delivery prerequisites,
recorded in the final delivery receipt after execution. They are not inferred
from these component results.

Owner's fresh import/automatic-email/Off-default confirmation is PASS for that
journey. The new picker usability check remains PENDING: refresh Compose, open
**Choose a recipient**, choose an imported public-key address and save the draft;
confirm the selected To/Cc/Bcc address and retained content/protection choices.
Sending mail is unnecessary. S05-02 remains separate from whole-epic acceptance
and production release.

## Contacts directory revision — owner Outlook People reference, 2026-11-01

Owner rejects the plain form-first Contacts page and explicitly requests a
people icon and table-style listing that shows the added contact, email address
and encryption policy, similar to the supplied Outlook People screenshot.
This is a directly requested S03-01B/S05-02 integration correction; preserve the
frozen plan/reference bundle, with this new visual direction recorded here.

Exit: Contacts opens a practical, searchable table of saved contacts and current
imported-key email identities, with Name, Email address, Encryption policy and
Actions columns. Show actual current key readiness and policy; no inferred
private-key readiness. A people icon and Contacts navigation make it discoverable.
New contact/edit/remove forms retain existing authenticated revision-checked
storage and confirmation; the list is primary. Write opens a new owned composer
with the selected address, using fresh opaque-choice/revision validation, without
saving a draft or sending mail on GET. Selecting an address never changes policy.

Reuse existing contact store, authenticated key-management read, public inventory,
recipient resolver and policy evaluator. Read-only merged projection: bounded
200 saved plus200 imported identities, saved labels preferred; duplicate domain
case collapses while local-part case is preserved. Ambiguous keys remain visible
with attention status and cannot supply an imported selection handle. Effective
Required/Disabled policy conflicts are explicit. Foreign/unavailable sources do
not leak identities or conceal the other valid source. No new persistence,
protocol, dependency, external discovery, mail operation or credential mutation.

Root owns management, ledger, routes, shared navigation, compilation, Git and
obsd1 deployment. Runtime engineer owns contacts.rs directory model; UX developer
owns new contacts_ui.rs/contacts.css; protocol reviewer independently reviews
source, tests and installed results. Minimum checks: directory merge/default/
conflict/ambiguity/owner/quota; route search/filter/strictquery and contact CRUD;
Write fresh owner/member/revision checks, no GET writes, preserved compose
preferences; hostile text escaping, semantic table/accessibility, responsive
browser at360/768/1440 and both themes. Native changed-boundary checks, existing
normal gates, Web-only installation and actual owned-data readback follow source
review/signing. Reuse unchanged native helpers/crypto qualification. No public
Dovecot/Postfix/MariaDB restart or configuration change. Preserve current owner
keys, contacts, policies, sessions and drafts; only OSMAP Web may restart.

Use progressive failure→analysis→small correction→retest; retain every failed
result distinctly. Two same-boundary failures require independent reassessment
before a changed attempt. Local focused checks have120s technical bounds,
native build600s per compiler action and Web-only install360s; preserve bounded
cleanup and old-binary rollback. Cumulative whole-task elapsed/cost is UNKNOWN;
prior failures/passes are reused only where inputs remain matching. Owner
acceptance is pending this revision, and public-key import success remains PASS.

Contacts Add name opens a fresh-key-ID checked, prefilled contact editor. Only the
existing Save-contact POST persists a user-chosen name/email; imported metadata
itself remains read-only and there is no automatic duplicate contact write.
Initial CUA passes Add name/save/merge/search/Write-prefill/edit-cancel. Desktop
clock/New-contact overlap was retained and corrected by scoped heading spacing.
Current CUA passes360/768/1440 in light/dark without overflow or clock overlap,
restart persistence and Remove-confirmation/Keep. Initial180s fixture expired
before that confirmation; current bounded300s fixture covers it, exits0 and its
listener is absent. Current tab/media/viewport are closed/reset. One initial
expired error tab remains blocked by browser URL policy; no bypass was attempted,
and its eventual automatic disposal is not yet observed. No owner state or SMTP
operation is part of these synthetic checks. Final native/install qualification
and normal delivery gates remain pending.


## People-style Contacts installed — 2026-11-01

The owner rejected the old form-first Contacts page and supplied Outlook People
as the practical reference. Signed source `2e1ddb551586cb6db9b894693acdc2e83a0a94c5`
adds a compact people icon in the existing sidebar and a dedicated `/contacts`
page with Name, Email address, Encryption policy and Actions columns. Search and
Saved/Imported filters operate on the bounded owned directory. Imported public
key emails appear immediately alongside saved contacts; matching rows merge and
saved names win. Add name prefills the current imported address and requires an
explicit existing contact save. New contact, edit and confirmed removal use the
existing store, session, Origin, CSRF and revision checks. Write revalidates the
current saved revision or imported identity before in-memory Compose prefill;
GET does not save a draft or send mail. Public-key readiness and the combined
account/recipient policy are shown separately. Missing policy stays unavailable.

No new dependency, helper protocol, database, synchronization job or private-key
authority is added. The actual installed readonly directory reports four rows
from four public keys and one saved contact. The known cBw recipient is Required;
the recent user4 recipient is OffByDefault. Saved labels survive and foreign
records are refused; contacts and bindings are unchanged after readback.

Focused source checks pass: core12, routes14, UI4, Runtime13 and preflight3;
strict Clippy and formatting pass. Native OpenBSD execution passes core12,
routes14 and UI4 with actual count guards. The current signed archive built
libtest, Web and the readonly observer in166.762seconds. Browser checks use
controlled synthetic data: Add name/save/merged row/search/Write To with Off
flags/edit cancel, saved-name persistence across restart, and actual Remove
confirmation/Keep. All six360/768/1440 dark/light layouts have no overflow or
clock/control overlap. The initial overlap and TrustedHtml compilation failure
are retained with their corrections. The initial180-second preview expiry is a
QA limitation; final fixture/listener/tabs and viewport/media reset pass. One
initial expired error tab remains URL-policy blocked and is not claimed closed.

Web `fe193cdf6296c9d9c78475d94de9a4e1df3f286f44446573880590e7fbb36c8e`
is loaded on obsd1, PID31119/text inode130022, with loopback listener, CA-verified
HTTPS login200 and all eight roles healthy. Only OSMAP Web restarted. Environment,
helpers, inventory workers and crypto configuration are unchanged; protected
before/after manifests both hash `0062e1c872f085e86bac0ac3712e03a4fadea58ace19955d42cec2a350af6994`.
The verified readonly observer is removed; the hashed old-Web rollback backup is
retained and rollback was not needed. Actual-data readback is not an owner HTTP
session or owner contact mutation. Prior owner import/identity/default-Off PASS
remains; owner acceptance of this new directory and Compose usability is pending.

Private evidence uses the existing `s05-02-import-20261101/contacts-directory-*`
prefix: source/installed independent reviews, build receipt, native log, actual
installation and readonly readback, browser result/layout and final screenshot.
The final ordinary push runs normal full delivery gates; GitHub equality and
those actual outcomes are retained in the final delivery receipt. No whole-epic
acceptance or production release is claimed. Minimal owner check: open Contacts
from the people icon, inspect real address/policy rows, search for an import,
and use Write or explicitly save a name if desired.

Independent installed review `9eab993390767e4d813ba1de4bc8521b0b747d059a36e94ce2a0f7c6c8edfcf3`
confirms the engineering/native/installed outcome and retained limits. A closeout
editor indentation error and missing README scope entry were corrected before
validation; no product/runtime bytes changed. Traceability and work-order checks
pass403 approved controls/110 unchanged legacy cases/34 current obligations.


The first current ordinary push gate passed all2139 Rust unit tests (75 explicit
ignores) but stopped at V4 hostile-content assurance: the added inert People
navigation SVG raised the actual pre-main shell count from16 to17. The test
adapter’s fixed16-icon ceiling left one validated application icon visible to
its hostile-content counter. Independent actual-HTML inspection confirmed17
geometry-only shell SVGs. An initial diagnostic extraction accidentally split
on a CSS left property, stopped before editing, and the outer shell then reran
the unchanged failing integration test; both failures are retained. Combined
reassessment approved the smallest test-only correction: cap17 plus explicit
17-positive/18th-observable assertions. Existing geometry/attribute checks and
message-content SVG refusal are unchanged. Corrected focused V4 integration
passes both cases, including the actual hostile corpus. Production source and
installed Web remain byte-identical; no native rebuild or reinstall is needed.
The corrected ordinary full gate and GitHub parity remain final delivery checks.

The next normal gate passed2139/0/75 and the V4 integration, then refused the
stale refined source-inventory hash: the test-only assertions shifted two existing
`expect` locations by16 lines. Refreshing the existing three assurance records
changes only those locations, timestamps and coupled hashes; counts and runtime
classifications are unchanged. Focused V11 and V10 governance checks pass.
The full gate is retried only after this demonstrated metadata correction.


## Contacts and Compose owner acceptance — 2026-11-01

Following the completed installed Contacts/Compose handoff, the owner replied
exactly **`UAT = PASS`**. Record PASS for that final walkthrough: the People
sidebar entry, dedicated contact/name/email/policy table, imported and saved
recipients, search and the linked Compose flow. The earlier explicit successful
ASC import/automatic identity/default-Off result remains preserved, as do all
historical failed attempts and their corrected engineering evidence.

This closes the requested Contacts/Compose human acceptance step and accepts
Contacts-selection control R2-04-009. It does not bulk-promote the other mapped
S05 controls, accept the whole epic or approve production release. No new product
code, host action or credential-backed test is needed to record the owner result.
The existing four signed delivery commits through121b39f and installed Webfe193
remain the functional basis; this update changes acceptance records only.
