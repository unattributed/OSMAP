# S04-03 — Recovery contact lifecycle

Started 2026-10-26 (America/Toronto), following accepted S04-02 at signed
`b94eacb9a583f0cc1a999504285dbd813763202e`.

## Observable outcome

An authenticated own-account user can add, verify, replace, resend proof for,
and remove a recovery contact. Settings shows actual missing, pending, verified,
expired or unavailable state and the verified timestamp. Replacement preserves
the old verified address until the new address is proved; completed replacement
or removal notifies the old address. Delivery refusal and uncertainty remain
explicit and cannot be turned into a successful message or blindly retried.

The approved D04 policy applies: current password and fresh TOTP for contact
administration; account/session/source/CSRF binding; serialized revision checks;
256-bit random proof, purpose-separated stored digest only, 30-minute single-use
proof, five attempts, 24-hour pending lifetime, 60-second resend interval and
three/hour plus ten/day. Recovery-contact possession cannot bypass MFA or prove
identity. S04-04 account recovery and password reset remain outside this slice.

## Existing boundaries and smallest implementation

Discovery found disabled Unknown/Manage controls and no contact lifecycle store
or route. Reuse the ordinary Runtime's native primary verification, file TOTP
replay protection, account-scoped private atomic records and fixed mail transport.
The web process receives no SQL credentials or general administrative command.
Tokens and credentials never enter URLs, logs, browser storage, argv or retained
evidence. Enter the emailed proof in an authenticated CSRF-protected POST form;
GET navigation never verifies or changes a contact. Secret fields return empty.
A valid, bounded email remains in its input after an authenticated submission
error so the user can correct it; it is escaped and retained only in that response.
GET and Cancel start blank, and this behaviour never retains a password or code.

Development and installed qualification target local obsd1 only. Use disposable
accounts and controlled local mail delivery; preserve the owner's account,
working password journey, mail services and unrelated settings/session state.
No production-recipient test mail, production account mutation or mail-service
restart/configuration change is part of this work order. Root owns Git/host
dispatch; the existing team supplies implementation, QA and independent review.

## Essential tests and failure loop

- T01: persistent add/prove/replace/remove, accurate status/timestamp, old-contact
  notice, all approved Page 23 and Settings entry controls.
- T02: bad/expired/replayed proof, attempt and resend budgets, old-token
  invalidation, stale revisions, concurrent operations and account isolation.
- T03: refusal/uncertain send and interrupted persistence, bounded safe
  reconciliation without duplicated automatic delivery or false success.
- T04: normal BrowserApp/Runtime path through current-password/fresh-TOTP,
  session/epoch authority, CSRF/origin checks and private store; old/stale/replayed
  authorization refuses before effects. No factor or password change.
- T05: installed native stale/replayed/incorrect authorization and CSRF refusal,
  with owner and control state preserved.
- T06: installed local delivery, proof, old-contact notices and restart persistence;
  actual browser navigation, responsive light/dark and approved Page 23 comparison.
- T07: installed invalid proof, empty/unavailable status and secret exclusion.
- T08: concise owner acceptance only after all required engineering checks pass.

At each boundary retain the actual failure, analyze its cause, make the smallest
supported correction and retest that boundary. Two failures at one boundary
require combined root/independent reassessment. Ambiguous delivery or account
state stops replay while read-only reconciliation continues. Use bounded
operations and record actual elapsed time; an artificial wall clock does not
expire the user's instruction. Reuse unchanged passing evidence and run broad
checks at delivery, not after each local correction.

Independent source/evidence review and normal repository delivery gates are
required delivery stages in addition to the named functional scenarios.

## Delivery and acceptance

Engineering readiness requires matching source, native installed workflow,
actual browser QA and independent review, with sanitized evidence under
`/home/foo/Downloads/osmap-ux-s04/`. Preserve the frozen plan, 110 legacy cases,
403 control designs and accepted S04-02. Use reviewed Shopkeeper-signed commits,
normal hooks/push and fresh exact remote parity. Record human acceptance
separately; never declare it from an agent test or a structural validator.

## Installed qualification checkpoint — 2026-10-26

Signed source `3c11641…` produced installed Web `558a165e…`; the ordinary account
helper remains `be7c6b40…`. Later UI formatting is semantically identical. The
native04 positive journey used the actual HTTPS route, native admission service,
file TOTP, genuine stored session, contact store, fixed mail submission and local
LMTP mailbox witnesses. Nine HTTP requests completed add, resend with token
rotation, proof, pending replacement while preserving the verified contact,
replacement proof and old-contact notice, removal and old-contact notice.
Three proof messages and two notices were observed. Verification timestamps were
bounded by independent host clock reads and matched rendered status. All proof
values remained private and absent from response pages.

Functional, restoration, preservation and persistence all passed in 176.237
seconds. Exact original policies were restored and existing SQL rows, protected
files and stored-session authority passed preservation checks. The final removed
record survived the helper/Web restart. Disposable fixture resources remain
retained outside policy enrollment; no owner password, factor or contact changed.
The repaired OpenPGP environment and original binding remained byte-identical
through this qualification. No external recipient or production mail-service
restart/configuration change was used.

Native04 result SHA256:
`1c78ce23278f1649a2fc25ee05c4d881aff033d3352941cfbeae2f0c21828a69`.
Earlier native01/02/03 failures remain failed and retained, separately from their
successful restoration. They exposed test-preparation assumptions: literal pipe
parsing in Ksh, an absent standalone base64 utility, and glob expansion left
disabled after splitting generated hashes. The corrected test uses native
OpenSSL encoding, restores globbing immediately and checks static routing/Sieve
before creating fixtures. Its real Rust notifier/Node consumer checks include
valid partial mail delivery and immediate malformed/foreign/extra-message refusal.

Source tests cover 14 persistence/lifecycle cases, five ordinary Runtime cases,
local-domain configuration and four route/security cases. Actual Edge exercised
five presentation states across 15 viewport/theme captures; these are synthetic
presentation evidence, not installed mail evidence. Full Rust regression passed
1,959 tests with 72 explicitly ignored native/fixture cases. Normal push security
checks and V10–V14 gates passed at checkpoint `94b9895…`, with a verified signature,
clean checkout and exact fetched branch parity.

The remaining installed negative contact-route checks are tracked separately:
CSRF, incorrect and replayed step-up, stale revision/session, invalid proof and
unavailable storage. Source and synthetic browser results do not substitute for
these declared native/deployed checks. Human acceptance remains pending.

## Engineering qualification and owner review — 2026-10-26

The required T01–T07 engineering observations are qualified for local obsd1 UX
development. T08 owner acceptance remains pending; S04-03 is not ACCEPTED.
The current installed Web is `c9729671…`, built from signed `6a83828…`; the
ordinary account helper remains `be7c6b40…`. This Web adds only validated,
escaped email retention after an authenticated form refusal. Secret fields stay
empty; GET and Cancel start blank. The focused route regression first failed,
then all five route tests passed. Current actual Edge QA passed all five states
and 16 captures, including the refused form on mobile. Source/visual review:
`83b5d4d7a8e3ff938844246c58fe4e31df217ece5d2a6dd08cfc61a4c3f740ec`.

Native05 supplied the remaining installed contact-specific negative observations:
invalid CSRF, incorrect password and replayed TOTP each returned 403 without a
contact record; stale revision returned 409 without changing stored bytes;
invalid proof returned 400 with revision 2/one failed attempt; unreadable storage
returned 503 with accurate unavailable text and disabled controls. Valid email
survived confirmation errors, while secrets and actual proof values were absent
from the responses. One legitimate proof was observed in the local mailbox.

The **native05 aggregate remains FAIL**: an SSH255 transport interruption after
those six controls prevented the final logged-out-session check and original
restoration. The original SSH cause is UNKNOWN because the observer retained
only bounded stream accounting/hash, not the original transport text. A fresh
read-only connection succeeded. The first residue-only restoration restored the
original policies/services, then refused the fixture marker's padded OpenBSD
`wc -l` representation. The exact marker, inode, owner and byte hash matched.
Changing that guard to numeric comparison allowed the separate residue-only
restoration to complete in 436 ms, with restoration and preservation PASS.
No credential or contact workflow was replayed.

The final readback confirmed the exact 467-byte pending record at revision 2,
one failed proof attempt, mode 0600, no remaining permission marker, original
policies, unchanged restored OpenPGP environment/binding and eight healthy
services. Independent actual review:
`d054acf6de122367f2a8463dc979f244f2141bc0bddafb9348222ff14ee6cbba`.
The failed aggregate result is retained as
`7b8fd228453969085a5c893cce521d21de9b85896738ca7e7e1d9eef49076e85`;
final readback is
`f74d329e4ca3e48bf036c2d2f0869b6e412019cd89630aa464f5af95e259ee68`.

The seventh, generic logged-out-session check was NOT RUN in native05. Existing
accepted S04-02 logout, revocation and session-denial evidence is reused with an
empty diff from accepted `b94eacb…` for `routes_auth.rs`, `http_gateway_auth.rs`
and `session.rs`. It is not attributed to native05. Native04 proves the installed
positive contact workflow; native05's six observed controls and separately
verified reconciliation prove the contact-specific negative and recovery
requirements. The aggregate failures remain separate from these observations.

The development profile permits contact delivery only to the explicitly
configured local obsd1 mail domain. External delivery and S04-04 password/factor
recovery are not enabled by this slice. Owner review can open Settings →
Authentication & Recovery → Manage recovery contact, inspect the form and
status, and verify navigation/Cancel. A full owner mail-proof trial requires an
owner-controlled eligible local mailbox. No owner credential or factor reset is
needed for this review.

## External-recipient requirement change — 2026-10-27

The owner superseded the local-only delivery boundary and requires an external
recovery contact, specifically an owner-controlled Proton Mail address. The
installed `c9729671…` Web truthfully persisted the new pending address but
returned `Refused` before invoking `/usr/sbin/sendmail`, because the recipient
domain did not equal `OSMAP_RECOVERY_CONTACT_LOCAL_DOMAIN`. The corresponding
request was recorded at 2026-10-27 06:19:06 UTC and produced no Postfix queue ID.
The repeating `2A2F13CEA87` Brevo error is an older null-sender DSN addressed to
Brevo's bounce service; it is unrelated to this recovery-contact submission.
Read-only prerequisite inspection confirmed obsd1 OpenBSD 8.0 with Postfix
3.11.7: `/usr/sbin/sendmail` resolves through mailwrapper to the installed
Postfix sendmail implementation, whose installed manual defines `-N never` as
requesting no delivery-status notifications.

Observable exit: an explicitly enabled deployment accepts a supported external
mailbox address through the ordinary authenticated recovery route, submits it
once with the authenticated account as the relay-verifiable envelope sender,
requests no delivery-status notification, preserves proof secrecy, and retains
all existing step-up, CSRF, revision, resend, expiry, attempt and uncertainty
controls. The default remains local-only. The change must not alter Postfix,
Dovecot, MariaDB, OpenPGP helpers, passwords, TOTP factors, or existing contact
state. Owner verification remains separate from relay acceptance.

Source tests must cover exact opt-in parsing, default local-domain refusal,
external recipient acceptance, bounded `sendmail -N never -f <account>` argv,
proof only on standard input, and the complete BrowserApp/Runtime external
roundtrip. Installed qualification requires an exact-source OpenBSD build,
configuration-only opt-in, restart of OSMAP Web only, readback of the preserved
pending record, healthy service checks and one owner-initiated resend. A queue
acceptance or relay `status=sent` is not proof that Proton delivered the message;
the owner's receipt and one-use code verification remain the UAT observation.
