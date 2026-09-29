# UX engineering decisions

Date: 2026-09-29. Source: S00 intake against
`2a6993fe7df42a57f0cbb5fe3e33e331b400fef9`. Frozen plan revision 1 and its
signature-anchored hashes remain intact. These decisions implement the
operator's explicit autonomous engineering mandate recorded in the ledger.
They are delegated engineering decisions, not evidence of independent human
usability review, real-user recovery identity proof, or production acceptance.

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
