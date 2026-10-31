# S05-02 — Practical public-key and email-policy management

Started 2026-10-31 (America/Toronto) from signed S05-01 closeout
`279df22e6ceb384410b151a4acc9134e67dc3e25`. The operator acknowledged the
infrastructure closeout and authorized this slice using the same failure-analysis
method. This slice has a real visual/functional browser UAT.

## User outcome and design

Settings -> Encryption and keys shows imported public keys, the email addresses
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
