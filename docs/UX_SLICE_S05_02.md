# S05-02 — Practical public-key and email-policy management

**Current 2026-11-01: credential routing and native private-file creation corrections are installed. Full HTTP/native and actual running-helper import/remove checks pass. Owner T09 remains FAIL pending a fresh browser retest; S05-02 is open.**

Started 2026-10-31 (America/Toronto) from signed S05-01 closeout
`279df22e6ceb384410b151a4acc9134e67dc3e25`. The operator acknowledged the
infrastructure closeout and authorized this slice using the same failure-analysis
method. This slice has a real visual/functional browser UAT.

## User outcome and design

Settings -> OpenPGP -> Manage Keys shows imported public keys, the email addresses
they are approved for, and the policies actually applied. Email identities and
policies are visible without expanding cryptographic details. Full fingerprints,
algorithm/creation/expiry/subkeys remain available under Details. An imported
certificate without an approved email association is clearly unassigned; its
certificate user IDs cannot establish OSMAP trust.

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
