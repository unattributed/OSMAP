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
