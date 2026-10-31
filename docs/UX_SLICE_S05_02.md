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
remain separate. Current source/native/installed results begin NOT_RUN.

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
