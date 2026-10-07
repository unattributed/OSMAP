# UX engineering decisions

Original decisions: 2026-09-29. Source: S00 intake against
`2a6993fe7df42a57f0cbb5fe3e33e331b400fef9`. Revision 1 is preserved in signed
history. The following original decisions implement the
operator's explicit autonomous engineering mandate recorded in the ledger.
They are delegated engineering decisions, not evidence of independent human
usability review, real-user recovery identity proof, or production acceptance.

## Revision-2 precedence — 2026-09-30 UTC

The operator's final-approved image correction and `UX_PLAN_AMENDMENT_R2.md`
supersede incompatible older visual/functional choices below. In particular:

- D01's narrow desktop rail is replaced by the approved labelled sidebar;
  settings has section search. Required Show/Hide, clipboard, auto-save and
  desktop notification controls remain open until a bounded first-party
  interaction work order and its CSP/isolation tests are recorded. Existing
  no-script behaviour does not qualify those controls as complete.
- D05 navigation places Security within Settings. All 27 approved pages and
  their controls are tracked, including independent Settings sections and
  cross-category search. Old finite menus do not erase new pictured controls.
- D05 Documents must consume authoritative mailbox/storage quota. The old
  100 MiB cap is an additional upper bound, not an independent account allowance.
  Quota authority and concurrent mail/document accounting must be qualified.
- D05 folder operations add protected subfolder lifecycle and hierarchy.
  Permanent deletion remains separate, confirmed and retention-policy-bound;
  unavailable policy never permits implicit expunge. Existing reversible Bin
  behaviour is retained and is not proof of permanent-delete capability.
- Compose initial defaults are Unsigned, Not encrypted, Encrypt-to-self Off;
  mandatory policy still blocks incompatible send. Example enabled settings
  are not default policy. Recipient availability is separate; green/orange
  preflight follows the exact bundle requirements.
- Login and TOTP retain the current implementation; no new auth mockup.

The original records below remain historical decision evidence. The amendment
controls where they differ; security and resource bounds continue to apply.

## D01 — Native HTML interactions and explicit navigation

Decision: retain server-rendered HTML, native forms/details, local inline SVG,
CSS and the current CSP. Do not add scripts or a frontend dependency. Message
selection, filter/sort and mutations navigate to a full response with stable
mailbox/query/sort/selected-message context. Browser Back restores a prior URL;
all authorization is rechecked on each request. State in a URL is a bounded
request, never authority. Folder/account changes clear incompatible selection.

This resolves the reference's contradictory pane-only/no-reload and no-script
requirements by choosing the latter and retaining equivalent workflow context.
The explicit engineering mandate delegates this interaction amendment. The
accepted deviation is full navigation, not omission of selection preservation.
Fingerprint copying uses selectable full text with an accessible label; no
false clipboard-success action. Native details disclosures provide bounded
menus and rail expansion. Compose formatting uses explicit server form actions
and preview under D05, without claiming caret-aware WYSIWYG behavior.

Appearance: system is the default. An authenticated account's saved preference
is authoritative when signing in and when opening/updating appearance settings.
A host-only, non-secret preference cookie can carry the active browser choice
across navigation, errors, redirects and logout; it never grants authority or
alters protected rendering. A later account login replaces it with that
account's own saved choice. Missing/invalid/duplicate cookie values select
system. HTTP parsing errors that occur before a request exists use system CSS.
Authenticated preference writes require session, CSRF and same-origin checks.
Keep appearance state separate from security preferences so old binaries can
roll back without rejecting a new key in their settings record. An isolated
atomic sidecar under the existing settings directory is the preferred migration.

Tests: account A/B login precedence, missing/malformed cookie, navigation and
reload, logout, all HTML/error routes, light/dark/system, forced colours,
keyboard, no script or external resources, no changes to rendering preference.

## D02 — Host-side isolated cryptography and bounded transient plaintext

Decision: extend V12 through a separately versioned runtime helper contract.
Preserve the historical scaffold and its refusal of cryptographic operations.
Browser handlers never run gpg, choose arbitrary helper paths or read a key
home. The trusted helper maps an authenticated, grant-bound canonical account
to operator-owned configuration and exact full fingerprints. Caller-supplied
account strings or key IDs alone do not authorize operations.

Data path: bounded fetched ciphertext/signed bytes -> authenticated helper
request -> per-account GPGME worker -> bounded result metadata plus transient
content -> existing MIME parser and renderer -> authenticated no-store HTML or
forced download. No decrypted body is written to state, drafts, logs, evidence,
temporary files or caches. Source viewing defaults to original ciphertext for
encrypted mail; decrypted source is not exposed by an ambiguous View Source
label. Replies/forwards require explicit authoring consent before quoting
decrypted text into a persisted draft; never auto-persist decrypted content.

The actual label is "Decrypted on mail host". The reference's device/browser-
only statement is not compatible with V12 and is superseded for this engineering
track. OSMAP makes no zero-access or zero-knowledge claim. The authenticated
browser necessarily receives displayed plaintext over TLS. Process memory,
browser memory, kernel buffers and privileged-host access cannot be promised
erased. Disable core dumps for workers, verify native confinement and encrypted
swap posture before enabling production decryption, and document residuals.

Bounds: 16 MiB crypto input and 16 MiB output, 64 KiB metadata, at most 50
explicit recipients, one operation/account and two global concurrent workers,
10-second worker deadline and fail-fast admission. Account identifiers are
canonical and bounded; unknown/duplicate JSON fields, unexpected status or
oversized output fail closed. Partial results never become usable plaintext.
Pipe/descriptor transport has explicit lengths; neither commands nor paths
are protocol fields. Separate process groups allow timeout cancellation and
reaping of descendants; no automatic retry after uncertain submission.

GPGME runs OpenPGP operations in offline mode with automatic key retrieval
disabled and no browser-triggered Pinentry. The library's documented offline
mode disables Dirmngr network use for OpenPGP with supported GnuPG versions.
See [GPGME offline mode](https://www.gnupg.org/documentation/manuals/gpgme/Offline-Mode.html)
and [Pinentry modes](https://www.gnupg.org/documentation/manuals/gpgme/Pinentry-Mode.html).
OS restrictions are additional controls, not a substitute for library settings.

## D03 — Explicit key custody, policy and interoperability profile

Decision: private keys are provisioned and unlocked by an operator outside the
web process. No private-key upload/export, passphrase form, callback or browser
key generation. Each account has a separate restricted key home and binding
record; helper workers cannot access another account's key home. The Shopkeeper
key and its agent are never mail keys. Tests generate disposable keys in an
owner-only scratch directory and retain only public fingerprints/statuses.

Mailbox agent unlock is an operator action with maximum 300-second cache for
the initial profile. A request uses error-on-Pinentry and reports locked-key
state without prompting or retrying. Production key backup is operator-owned,
encrypted and outside OSMAP state; loss of a private key cannot be repaired by
password/contact recovery. Rotation explicitly rebinds a new fingerprint;
old decryption keys may be retained only as separately authorized decrypt-only
bindings. Revocation disables signing/encryption immediately, invalidates any
cached capability and blocks delayed sends until policy is resolved. No
automatic fallback to an old key or cleartext.

Public-key UI accepts at most 1 MiB per import, 32 primary keys/account,
8 subkeys/key, 200 recipient bindings/account and one exact primary fingerprint
per recipient purpose. Reject secret-key material, ambiguous imports, expired,
revoked, unsupported or non-capable keys for the requested operation. Import
does not establish trust. A full fingerprint must be explicitly confirmed with
fresh password/TOTP step-up before a binding or required-send policy changes.
Capability reports crypto availability, account binding and user trust separately.

Initial qualified profile: RFC 3156 PGP/MIME multipart/signed detached
signatures and multipart/encrypted, ASCII-armoured outbound OpenPGP. Preserve
the exact signed MIME entity and canonical CRLF boundary rules. Restrict
generation initially to RSA keys of at least 3072 bits, SHA-256/SHA-512
signatures and AES-256 integrity-protected encryption supported by the installed
engine. Missing integrity protection, weak hashes, unsupported algorithms,
multiple/ambiguous signatures or unsupported packet versions fail closed;
no custom cryptographic primitives. SHA-1 fingerprint identifiers for legacy
v4 keys do not authorize SHA-1 message signatures. Full v6/RFC 9580 support
requires separate interoperability results before being claimed.

References: [RFC 3156](https://www.rfc-editor.org/rfc/rfc3156.html) defines
PGP/MIME and canonical signed entities; [RFC 9580](https://www.rfc-editor.org/rfc/rfc9580.html)
is the current OpenPGP specification. The initial deliberately bounded engine
profile is not universal support for every format in those specifications.
Independently inspect emitted MIME and verify/decrypt with disposable receiver
key homes; where possible use a second mail implementation. Record an engine-
only interoperability limit if an independent implementation is unavailable.

Qualification must demonstrate positive and wrong-account/key, revoked/expired,
locked-agent, tamper, malformed, timeout, cancelled and crash cases on native
OpenBSD. Installed libraries and compilation alone do not enable capability.
Rollback disables the runtime feature, restores the prior binary/configuration
and leaves private key stores preserved; it never substitutes a different key.

### D03 interoperability extension — 2026-10-01

The operator selected an existing v4 Ed25519/CV25519 counterpart and explicitly
delegated engineering decisions for completing that round trip. Support these
exact existing curves through GPGME/GnuPG in addition to RSA at least 3072 bits;
the initial RSA key-generation default stays unchanged. Preserve strong hashes,
AES-256 integrity protection, full fingerprint/account/recipient bindings,
offline operation and error-on-Pinentry. Qualify both profiles with actual
disposable native operations and negative tests before enabling runtime crypto.
This does not claim full v6 support or change private-key custody. The execution
and test result are recorded in the ledger; the decision is also indexed in
`DECISION_LOG.md`.

## D04 — Authoritative identity changes and governed recovery

Decision: Dovecot remains authentication authority and its configured SQL account
backend remains the password authority. Read-only obsd1 inspection confirmed
a SQL passdb and running mysqld; no connection credentials were exported. OSMAP state is not a parallel password
database. Introduce an independently confined, typed account helper only when
the exact host backend adapter and rollback have been qualified. The web
process receives no database credentials, arbitrary SQL, doas capability or
general administrative command channel. Until then UI status is unknown or
unavailable and mutation routes refuse safely; this is incomplete capability,
not a passed identity slice.

Password change is own-account only, authenticated with current password and
fresh TOTP, same-origin, CSRF-bound and serialized. Step-up is action-bound,
single use, expires after 300 seconds and cannot change target account. Rate
limit to five failures/account and ten/source in 15 minutes with a 15-minute
cooldown. New password policy: 15–128 Unicode characters, at most 512 UTF-8
bytes, no controls, no silent truncation or mandatory composition rules; reject
unchanged input. Accept pasted passphrases. The helper uses the authoritative
backend's supported salted hash and conditional update, never an OSMAP custom
hash. Passwords exist only in bounded request/helper memory, never arguments,
logs, persisted drafts or evidence.

Successful change requires backend verification, an authoritative changed-at
timestamp, revocation of browser sessions including current, and the exact
mail-stack session containment/revocation required by the qualified adapter.
Concurrent login must check the same account epoch/lock. If the password update
has happened but revocation is incomplete, contain the account and report
manual reconciliation; do not restore the previous password or announce full
success. Existing SMTP/IMAP connections may outlive credential changes: never
claim they were revoked without tested host-specific evidence.

Recovery contacts: one verified address and one pending replacement/account;
syntax does not prove control. Add/change/remove requires the same step-up.
Verification uses 256-bit random single-use tokens, stores only a domain-
separated SHA-256 digest, expires after 30 minutes and allows five attempts.
Resend delay is 60 seconds, maximum three/hour and ten/day/account. A replacement
does not remove the old verified contact until proof succeeds. Notify the old
contact of a successful replacement/removal, without disclosing mail contents
or credentials. Pending state expires after 24 hours. No account enumeration
through anonymous routes or tokens in logs/Referer/third-party requests.

Recovery contact possession never resets TOTP or substitutes for independent
identity verification. The recovery coordinator records requested -> identity
reviewed -> contained -> sessions revoked -> factor replacement -> reconciled
states. Existing operator tools retain their independent human-approval and
private-terminal requirements. An agent cannot attest a real person's identity,
sign recovery approval on its own authority or claim production recovery from
synthetic custody. Interrupted mutation stays contained and requires explicit
reconciliation. Production contact messages and real-user recovery remain off
until separately authorized human-backed qualification. Controlled local sink
tests can qualify code without contacting real recipients.

## D05 — Finite actions, private stores and concrete budgets

Decision: implement only the following pictured ancillary functions. Every
store is canonical-account scoped, owner-only, bounded and versioned. Mutations
require session/CSRF/same-origin and serialized revision checks; opaque IDs do
not confer ownership. Names are display metadata, never filesystem paths.

| Area | Exact behavior | Limits and failure policy |
| --- | --- | --- |
| Navigation/menu | Compose, Inbox, Sent, Drafts, available Archive/Trash, Documents, Security, Settings, Sessions, Sign out; expand/collapse through native disclosure | No arbitrary command entry. Missing folder/capability yields explicit unavailable state, not a broken success link |
| Reader more | Reply, Reply all, Forward, Move, Archive, Move to Trash, Restore from Trash, mark read/unread, star/unstar, View Source, labels, snooze | Single messages or at most 50 selected UIDs. No permanent delete or implicit expunge; report partial success precisely |
| Contacts | Explicit account-private address selection for compose; user-entered display name and address | At most 200 entries, 100-byte display name and existing address parser bounds; no automatic harvesting from mail or trust inference |
| Labels | Create/rename/delete label, attach/detach to current or selected messages | 32 labels/account, 32 Unicode characters/128 bytes each, 8 labels/message; folder + UIDVALIDITY + UID identity; reconcile move results rather than attach to a reused UID |
| Documents | Private upload/list/forced-download/move to bin/restore/delete after explicit confirmation | 100 documents, 10 MiB/file, 100 MiB/account including bin; opaque storage IDs, 200-byte names; no inline preview. Bin retained 30 days then eligible for bounded cleanup |
| Notifications | Account event inbox and read state for actual password/contact/key/session/policy/job events | 200 events or 90 days, whichever is smaller; no message bodies, fake scores or automatic external notices |
| Drafts/uploads | Save, resume, save-and-close, minimize to saved draft, CSS expand, confirm discard; stale revision refused | 50 drafts/account, 30-day expiry, 50 MiB/account; existing stricter per-request/per-file limits remain in force; temporary uploads expire after one hour |
| Formatting | Explicit server actions for bold, italic, underline, numbered/bullet lists, links, emoji and local image attachment; preview | Constrained source notation with visible syntax and deterministic sanitized HTML + plain alternative. No scripts, arbitrary HTML/CSS, remote-image fetch or caret-aware WYSIWYG promise |
| Image action | Select/upload a local image as an attachment; constrained embedded CID output only after delivery/rendering tests prove parity | PNG/JPEG/GIF by content signature, 5 MiB cap within attachment quota; never fetch a URL or imply image malware safety |
| Send menu | Send now, pre-send check, schedule; crypto choices capability/policy-bound | Canonical or operator-allowed From identities only; ordinary To/Cc/Bcc and existing recipient caps. Bcc absent from visible headers and Sent metadata according to explicit policy |
| Scheduled send | Save bounded send job, inspect/cancel/edit pending job, dispatch once at/after explicit UTC instant | 20 jobs/account, at most 30 days ahead, 50 MiB/account, one worker/account and two total. Show exact UTC plus browser-independent account timezone text; reject ambiguous local/DST input rather than guess |
| Snooze | Account-private hide-until marker, restore to original visible context at expiry | 100 markers/account, at most 30 days, never deletes/moves mail secretly; stale UID is removed as a marker, never retargeted |

Formatting actions preserve existing form fields and explicitly append or wrap
user-selected source text through a server form; preview shows the exact
sanitized outgoing alternative. They are real operations, not decorative
toolbar buttons. Unicode emoji can also be entered normally. A missing feature
stays listed as incomplete in acceptance coverage.

Send/Sent policy: deduplicate recipient envelope addresses while preserving
To/Cc display intent; exclude the current sender from Reply All. Bind In-Reply-
To/References to validated original headers; never accept injected new headers.
Store the final emitted message in Sent. Encrypted Sent storage uses the same
ciphertext with encrypt-to-self when selected/required; no plaintext duplicate.
Bcc envelope copies do not reveal Bcc addresses in headers. Hidden-recipient
key IDs and per-recipient envelope requirements must be tested before claiming
Bcc privacy for encrypted messages; otherwise protected Bcc send refuses.

Scheduled jobs preserve the explicit authoring intent and serialized revision.
At dispatch revalidate account, sender, recipients, key bindings, expiry,
revocation and required policy. If a required private key is locked, mark
blocked and notify in-app; never send cleartext. Persist transitions before
submission. A crash/timeout after submission begins produces an unknown state
requiring read-only reconciliation, never automatic resubmission. Pending jobs
can be cancelled; submitted/unknown jobs cannot be portrayed as cancelled.
Forward wall-clock jumps dispatch a job at most once; backward jumps never
resubmit. Retain completed/failed metadata for 30 days, without plaintext body.

## D06 — Exact development and host authority

The operator grants full engineering authority on parrot-2TB and
obsd1.blackbagsecurity.com in this task's work window, with check-in at
2026-10-01 00:00 America/Toronto (04:00 UTC). Use this for local source changes,
test-only tooling, isolated native builds, synthetic fixtures and reversible
OSMAP changes needed for qualification. Preserve unrelated host services and
worktrees. No Vultr action is included. GitHub publication is distinct from
local signed deliveries; no remote push has been performed.

Read-only preflight on 2026-09-29 confirmed strict known-host SSH to
192.168.1.44 as foo, exact hostname, OpenBSD 7.9, clean `~/OSMAP` at
`2a6993fe7df42a57f0cbb5fe3e33e331b400fef9`, Rust 1.94.1, GPGME 2.0.1p0,
GnuPG 2.5.18 and nginx 1.30.4. Both `osmap_serve` and
`osmap_mailbox_helper` were running. This observation is not qualification of
future changes and does not establish any real-account recovery fact.

Native source transfer uses a signed reviewed source snapshot in a task-specific
work directory before any installation; no blind reset of `~/OSMAP`. Synthetic
accounts use `.test` identities or a separately frozen reserved validation
account in the exact live work order. Deliveries go to a local sink; external
mail is excluded. No existing personal password, factor or private mailbox key
is replaced. Recovery approvals retain their human requirements.

Before deployment record old/new source and binary digests, native gates,
service configuration, state schema and reversible backup. Rehearse restore.
Install only the narrowly required OSMAP binary/helper/configuration; health,
Host rejection, loopback binding and representative synthetic workflows must
pass. Roll back on service failure, new boundary regression or unreconciled
state migration. Never use an assumed Roundcube fallback. Preserve failing
evidence, reconcile changes once, restore temporary accounts/secrets/jobs and
confirm health. Keep obsd1 evidence explicitly separate from Vultr production.

## Threat and migration map

October 1 public-inventory checkpoint: the separately versioned protocol carries
only authenticated canonical-account requests and bounded public metadata.
It does not invoke the historical V12 crypto scaffold or enable mail cryptography.
The V12 HTTP source checks retain their prohibition on crypto/runtime helper
references, with exact reviewed presentation-literal/symbol exceptions shared
by `maint/security/openpgp_http_boundary.py`. Its negative controls reject old
helper invocation, inventory runtime/process access, unreviewed files and nested
file-name substitutions. Synthetic parser access is limited to its test fixture.
Command construction stays in `src/auth.rs`; process tests use a Rust child
fixture without shell execution. Native production activation remains disabled.


| Threat / authority | Required control and negative evidence |
| --- | --- |
| Unauthenticated/cross-account caller | Existing canonical session and grant boundary on every route/helper; wrong-account IDs denied before body/key access |
| Hostile mail or key metadata | Escape template data; sanitizer/MIME bounds apply again after decryption; status is typed metadata, never trusted HTML |
| Forged browser state | Same-origin/Host/CSRF checks; stale revision and tampered UID/fingerprint refused; theme cookie has no security effect |
| Compromised web worker | No database credential, private key home, passphrase or arbitrary helper command; bounded grants and worker isolation |
| Resource exhaustion | Enforced request/record/aggregate quotas, deadlines and concurrency limits; oversized input rejected before expensive work |
| Interrupted privileged mutation | Write-ahead intent and explicit unknown/contained state; no automatic password/factor/send retry |
| Old binary/state rollback | Additive versioned sidecars; bounded parse, unknown schema refusal, migration backup and tested old-version behavior |
| Concurrent updates | Account-store locks, revision preconditions and atomic rename; no lost unrelated settings or silently overwritten draft |
| Retained sensitive data | No credential/key/body capture; private scratch cleaned within its own scope; public evidence only statuses, hashes and synthetic visuals |

New state stores require versioned schemas, unknown-field refusal where
authority is involved, strict record/byte limits and owner-only atomic writes.
No existing record is silently rewritten merely by reading it. Destructive
migration requires an individually tested restore path. D01 appearance uses a
separate sidecar; later modules must explicitly record their migration before
runtime wiring. A discovered incompatibility remains open in the ledger.

## S00-02 current D01–D03 reconciliation — 2026-10-03

This append assesses source `66117e7e7aa299f27cd5d8760ea709290a1a597d` against the existing accepted R2 plan and
recorded direct engineering authority. It distinguishes original declarations,
subsequent bounded implementation and unresolved qualification. It neither
reopens already delegated decisions for repetitive approval nor accepts the
user's failed mail journeys. Later implementation must correct gaps in their
owning slices while preserving current security boundaries.

### D01 — bounded Compose enhancement; native server workflows remain

The original no-script declaration is historical, rather than an accurate
statement about every current response. The later ledger work orders **S03-01C
local composer controls** and **S03-02 / PAGE15 automatic draft saving** record
the operator-authorized Compose-only extension. The latter explicitly supersedes
the earlier local-only/no-network Compose allowance for bounded same-origin draft
saving; it does not permit external requests or scripts on Reader/authentication
pages.

`src/http/compose_enhancement.rs` includes one fixed repository script, admits its
exact SHA-256 in `script-src`, uses `connect-src 'self'` and denies event-attribute
scripts with `script-src-attr 'none'`. No message content is interpolated into
script bytes. `src/http/compose_local.js` submits only finite draft fields to
`/drafts/autosave` and reads `/drafts/autosave/config` with same-origin credentials,
redirect refusal and no-store semantics. Automatic saving is opt-in, defaults
Off, and uses only the configured 30/60/120-second interval while the page is
visible; pending files/source attachments require manual saving. Saves have one
in-flight operation and a 15-second client abort; uncertain results pause rather
than retry. Confirmed
responses update verified draft identity/revision and browser history. Client
abort is not proof that a backend write did not occur.

Native Save, formatting/preflight and explicit stale-key review remain separate
server actions. Existing fallback/CSP tests and bounded browser evidence are
reused for their recorded scope, not rerun merely to reconcile these decisions.
This does not establish every required clipboard, Show/Hide, notification,
no-reload pane or keyboard interaction. Unmapped or unexercised controls remain
open in their owning slices. Preserve Login/TOTP and the approved design; no
framework dependency or broader CSP exception is authorised by this append.

### D02 — distinguish crypto execution, authoritative mailbox and browser

The current integration separates three trust/data paths: the development web
and configured crypto execution are on **obsd1.blackbagsecurity.com**; mailbox/auth
operations and authoritative Sent use **mail.blackbagsecurity.com** through the
existing authenticated relay; the browser receives rendered plaintext over TLS.
Outbound transport remains the separate obsd1 sendmail/relay path. These are
source/retained-configuration findings, not a new inspection of host state or a
claim that transport delivered a message.

`src/http_gateway_protected.rs::render_protected_snapshot` assembles an owned
stored source and calls the authenticated crypto processor. `src/protected_message.rs`
reparses resulting MIME and uses the existing validated-session renderer; it
clears plaintext compose quoting so this reader cannot automatically feed decrypted
content into an autosaved draft. Original encrypted source remains distinct.
`maint/openpgp-runtime/crypto.c` sets offline/local-key operation, denies automatic
retrieval/import and uses error-on-Pinentry. The web process is not a private-key
or passphrase interface.

Source bounds remain 16 MiB content, 64 KiB metadata and 50 explicit recipients, with
length-delimited authenticated frames, a 10-second deadline and bounded admission
(one operation per account, two global workers). Source resource/confinement
controls and prior native results retain their assessed scope. Compilation,
source checks or this append do not establish current encrypted swap, complete
memory erasure or fresh native qualification.

The current reader text **Decrypted on mail host** does not identify a hostname.
In this topology it must not be interpreted as browser-only execution or proof
that the authoritative storage host performed decryption. Accurate execution-
location presentation and author-consented protected reply/forward remain
explicit review items for their owning S06/S07 workflows. No zero-access,
zero-knowledge or universal plaintext-erasure claim is supported.

### D03 — public browser operations and private custody are different

Browser management imports public certificates and changes explicit account/
recipient bindings and policy through typed, account-isolated, revision-checked
operations with fresh password/TOTP step-up. Import alone establishes no trust.
There is no web secret-key import/export, passphrase entry or private-key
creation interface. Private custody, provisioning, encrypted backup and private
unlock remain operator operations outside the web process; Shopkeeper signing
and its workstation agent are separate from mailbox keys and the host agent.

`maint/openpgp-runtime/deployment_unlock.py` records a 300-second isolated host
cache and uses the operator's real terminal/Pinentry. `crypto.c` requires agent
access for Sign/Decrypt, while Encrypt/Verify use public material without private
unlock. A Locked result can also reflect failed confinement/socket admission,
not merely cache expiry. Public-only encryption and fully permitted ordinary
sending must not be assigned an unnecessary private unlock prerequisite. Current
required policies still refuse incompatible requests without downgrade.

The operator's later terminal output reports revision5, signing/decryption warmup,
helper restart, sign/verify, tamper refusal, self-encrypt/decrypt and selected
Proton public encryption PASS with no binding write and no external delivery.
Its timestamp was not supplied: it proves that checkpoint, not present cache
availability or a successful browser Send. Earlier locked and all-Send failures
remain open; no unknown refusal is attributed universally to cache expiry.

The existing interoperability extension authorises the bounded v4 profile:
RSA at least 3072 bits and exact Ed25519/CV25519 material; SHA-256/SHA-512 signatures;
AES-256 with the worker's accepted integrity-protection status; detached signed
and encrypted PGP/MIME with exact canonical bytes. Current 40-hex fingerprint
checks and v4 signature checks do not establish general v6/RFC 9580 support.
Unsupported/ambiguous capable subkeys, weak algorithms and failed integrity are
refused. Existing disposable native operations qualify only their recorded
profiles and conditions. Independent Proton receipt/signature, readable encrypted
Sent, protected return, and human fresh-auth key lifecycle remain unaccepted.
Backup/rotation/revocation and missing/locked/tampered/timeout/crash handling must
be checked through their existing owning cases; a custody declaration is not
execution evidence.

### Advancement and remaining scope

S00-02 completion requires this reconciliation, exact source/authority/evidence
references and independent outcome review, not another live mail or crypto probe. Required repository delivery hooks remain
authoritative.
Carry unresolved controls/runtime limits into the existing ledger and owning
slices. S00-03 next reconciles D04–D06 against actual implementation and standing
authority. Preserve the ordered epic, existing code and valid earlier evidence;
known ordinary and protected Send failures cannot be erased by this append.

## S00-03 D04–D06 reconciliation — 2026-10-03

Append-ready technical-writer draft, prepared read-only from source
`66117e7e7aa299f27cd5d8760ea709290a1a597d` and the current standing user direction.
Root integrates this only after the predecessor delivery. This draft neither
modifies the accepted plan nor accepts S00-03 or any application journey.
Retain the original dated D04–D06 records above; the following distinguishes
their intended rules, current source capabilities and unresolved qualification.

### D04: authoritative account changes remain distinct from presentation

Dovecot and the authoritative mail-account backend remain the authentication
and password authorities. OSMAP presentation preferences do not grant another
From identity or become a parallel password database. The older September 29
obsd1 SQL/mysqld observation is historical; it does not establish the current
Toronto backend's exact password-write adapter, account epoch, changed-at
source or session-containment capability.

Current source facts:

- `src/settings_identity_ui.rs:41–48` and
  `src/http/routes_identity_preferences.rs::handle_identity_preferences_update`
  provide display-name/Reply-to preferences for the canonical account. The
  email field is read-only; additional sender identities are unavailable.
  `src/identity_preferences.rs:1–10,26–63` supplies bounded presentation data,
  not account/password administration.
- `src/http_gateway_auth.rs:6–35` builds Dovecot authentication and the separate
  file-backed TOTP verifier. `maint/mail-backend/relay.py::ssh_argv` supplies the
  bounded development transport for the auth/mailbox purposes. Successful
  authentication through that transport does not supply a password mutation
  capability.
- `src/settings_security_ui.rs:40–55` still renders disabled password/TOTP
  management and unavailable recovery-contact status/management. The current
  dispatcher has no password-change or recovery-contact browser mutation route.
  These are missing required capabilities, not passed identity/recovery slices.
- `docs/TOTP_OPERATOR_RECOVERY_SOP.md:3–24,28–48` describes separate interim
  operator-assisted factor recovery and a fixed-account controlled rehearsal.
  It does not authenticate a real claimant, provide a browser recovery workflow,
  recover mail identities or allow an agent to attest someone's identity.

The original D04 own-account step-up, bounded password handling, authoritative
conditional write/verification, changed-at result and session impact remain the
design requirements for their assigned slices. Contact verification must prove
control before replacement; it must not bypass MFA or independent recovery
identity proof. The exact current backend writer/epoch/containment integration,
password and contact workflows, interrupted-result reconciliation and real-user
recovery evidence remain **open**. Do not treat a saved display name, valid
session or synthetic recovery rehearsal as their acceptance.

### D05: finite ancillary functions, quotas and migration remain bounded

Preserve the original finite action inventory and stricter existing limits.
Revision 2 supersedes incompatible presentation choices and requires Documents
to consume authoritative mailbox/storage quota; the historical 100 MiB document
cap is an additional ceiling, not an independent storage entitlement. No new
general command, arbitrary administrative API or unbounded groupware is implied.

| Area | Current inspected source | Existing semantics and remaining gap |
| --- | --- | --- |
| Contacts | `src/contacts.rs:1–27`, `src/http/routes_contacts.rs` | Explicit private contacts, 200 entries and 100-byte display names; no harvesting or OpenPGP trust inference. Account-private address selection is separate from recovery-contact proof. Current functional/UAT acceptance is not inferred here. |
| Labels | `src/labels.rs:14–19,211–212,239–275`, `src/http/routes_labels.rs` | 32 labels/account, 8/message, bounded revision-checked private records and source-defined current message identity handling. The 8 MiB record bound explicitly is not mailbox/storage quota. Correct move/stale-identity outcomes need their focused evidence. |
| Snooze | `src/snooze.rs:15–17`, `src/http/routes_snooze.rs` | 100 markers and 30-day maximum; a private visibility marker rather than silent mail movement/deletion. Expiry, missing identities and current browser outcomes retain their own tests/UAT. |
| Notifications | `src/notifications.rs:11–26`, `src/http/routes_notifications.rs` | Source supports 200 events/90 days and only SessionIssued/SessionRevoked kinds. The broader approved password/contact/key/policy/job/delivery event scope is incomplete; no invented score, fake event or implicit desktop permission. |
| Drafts and intent | `src/draft.rs:32–37`, `src/send_journal.rs:378–388` | Existing 50 drafts, 30-day age and 50 MiB draft cap; versioned send-attempt state. Storage/result preservation is separate from current successful Send, authoritative Sent and recipient receipt. Unknown dispatch is not an automatic retry. |
| Folder lifecycle | `src/http/routes_folder_create.rs:40–90`, `src/settings_copies_ui.rs:114–116` | An authenticated/CSRF-bound creation route exists. Rename/move/delete remain unavailable; mailbox summaries and virtual size do not establish shared quota or disk consumption. Required protected-folder, non-empty disposition and lifecycle outcomes remain assigned acceptance work. |
| Documents/storage | `src/http_ui.rs:278–279`, `src/settings_copies_ui.rs:115`, `src/welcome_ui.rs:147` | Documents navigation and usage/quota remain unavailable; no Documents dispatch/store was established in S00-01. Authoritative concurrent mail/document quota accounting, bin/retention and upload/download lifecycle remain missing/open. |
| Scheduling/permanent deletion | `src/http_ui.rs:2114`, `src/http/archive_ui.rs::page` | Schedule and permanent deletion are disabled; archive dates and retention management are unavailable. No scheduler/retention backend is established by these controls. Reversible Bin/restore must not be relabelled permanent delete. |

The original resource budgets and their revised shared-quota constraint remain
requirements, not measured current runtime guarantees. In particular document,
scheduled-storage and global quota concurrency cannot be demonstrated by local
record caps. A missing quota or retention authority must not permit implicit
expunge or provide a false “space available” result.

Reuse the source's private-record machinery rather than introducing another
store framework: `src/private_account_file.rs:1–4,49–78` provides namespaced
account records and a held file lock; callers own bounded versioned schemas.
Contacts/labels/notifications retain revision checks. Composition preferences
already have source-defined legacy v1/v2 reading and v3 serialization
(`src/composition_preferences.rs:83–131`). This is source capability, not proof
of every rollback or live migration. Each future state change must record its
own existing schema, compatibility/unknown-version behaviour and restore path
in the current work order, without destructive rewriting on read.

Controlled `.test` fixture identities and isolated local sink namespaces remain
the default for bounded engineering tests. Their coverage must be labelled
synthetic and cleaned by the assigned owner. Duncan's authoritative account and
the selected Proton recipient are the agreed real UAT scope; do not replace
their passwords, factors, private keys or saved policy to make fixtures pass.
Synthetic or reserved-account recovery does not become real-user proof.

### D06: current standing scope supersedes the expired window

The user's renewed full engineering authority and explicit epic resumption
supersede the September 29 record's October 1 check-in window. Current AGENTS.md
and the user's October 1 instruction also supersede the old “no remote push”
restriction: completed contextual Shopkeeper-signed commits are verified and
promptly synchronized to the current GitHub UX branch. Source synchronization
is separate from deployment, functional qualification and human acceptance.
No additional routine approval checkpoint or parallel status board is added.

The development frontend and native validation target remain
`obsd1.blackbagsecurity.com` at `192.168.1.44`. The authoritative account/mailbox
data are on `mail.blackbagsecurity.com`. This existing backend integration is
in scope; the historical blanket “no Vultr action” cannot be used to prohibit
the explicitly requested authoritative auth/mailbox connection. It does not
grant unrelated production administration or recovery identity attestations.

The exact paths are distinct:

- Authentication: Dovecot auth test uses the configured auth socket
  (`src/http_gateway_auth.rs:6–20`); the bounded relay has fixed auth/mailbox
  purposes, peer checks, static configured destination and SSH authority
  (`maint/mail-backend/relay.py:29–34,56–59,81–128`). Remote forced-connector
  authorization is a deployment prerequisite, not newly measured here.
- Mailbox reads and Sent append: helper/direct selection is configuration-bound
  (`src/http_mailbox_backends.rs::build_mailbox_list_backend` and
  `build_message_append_backend`, lines 203–218). The intended deployed helper
  route uses the authoritative mail backend. Current configured paths, grants,
  peer identity and data authority must be checked before live qualification.
- Submission: the runtime constructs the local sendmail service
  (`src/http_gateway_mail.rs:208–218`). Previous deployment evidence describes
  obsd1's existing SMTP/Brevo path; this draft does not inspect or certify its
  current configuration, accepted handoff or delivery.

Native source/binary identity, relevant gates, bounded installation and recovery
remain required within standing authority. Preserve unrelated state and retained
failures; use no assumed Roundcube fallback. A known failed required journey
reopens readiness. Keep exact build/configuration/account evidence with its
actual scope instead of carrying September 29 host observations forward.

The operator controls the next actual external Send. Do not submit a parallel
agent message or run an obsolete probe. An ambiguous submission is reconciled
read-only before retry; preparation, transport acceptance, authoritative Sent,
provider receipt/decryption/signature and human acceptance remain separate.
All reported Send failures remain unresolved by this draft. Current policy,
private-agent availability, backend identity and destination outcomes are not
live-verified here; no keys/policy/service changes or email operations occurred.

### 2026-10-06 — bounded active-peer admission and diagnostic precision

Admit only the reviewed five active Search/Move/Flag peer paths over signed
93016e6. Preserve grants, request/response limits and postwrite uncertainty;
no policy expansion or unused-route work. Match native and installed source
before claiming delivery. Preserve S07's seven native source tests separately
from operator acceptance.

A retained qualifier failure must identify a closed stage and first failed
predicate on its initial result, without exporting private values. Apply this
small rule to existing qualifiers rather than adding a diagnostic framework.
A current operation baseline cannot retroactively clear an older failure.
Continue independent UX/backend work while SDK module preparation proceeds;
never broaden a quota build into whole-server bootstrap or activate a limit
that would block the operator's over-limit existing mailbox.
