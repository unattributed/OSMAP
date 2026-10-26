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
GET navigation never verifies or changes a contact. Fields return empty.

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
- T05: installed native local delivery, reload/restart persistence, independent
  witnesses, preserved control account and working login/password functionality.
- T06: actual browser navigation, empty/error/pending/verified states, responsive
  light/dark presentation, keyboard labels and approved Page 23 comparison.
- T07: independent source/evidence review and normal repository delivery gates.
- T08: concise owner acceptance only after all required engineering checks pass.

At each boundary retain the actual failure, analyze its cause, make the smallest
supported correction and retest that boundary. Two failures at one boundary
require combined root/independent reassessment. Ambiguous delivery or account
state stops replay while read-only reconciliation continues. Use bounded
operations and record actual elapsed time; an artificial wall clock does not
expire the user's instruction. Reuse unchanged passing evidence and run broad
checks at delivery, not after each local correction.

## Delivery and acceptance

Engineering readiness requires matching source, native installed workflow,
actual browser QA and independent review, with sanitized evidence under
`/home/foo/Downloads/osmap-ux-s04/`. Preserve the frozen plan, 110 legacy cases,
403 control designs and accepted S04-02. Use reviewed Shopkeeper-signed commits,
normal hooks/push and fresh exact remote parity. Record human acceptance
separately; never declare it from an agent test or a structural validator.
