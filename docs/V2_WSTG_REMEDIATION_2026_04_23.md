# Version 2 WSTG Remediation Note, 2026-04-23

## Source And Scope

This note records the Version 2 remediation disposition for the April 2026
OWASP WSTG-style browser-slice assessment against
`https://mail.blackbagsecurity.com`.

The WSTG report is treated as the authoritative baseline for this pass. This
document does not re-audit the browser slice; it records how the confirmed
findings map into Version 2 implementation, Version 3 backlog, or
not-applicable status.

## Applicability Matrix

| Finding | Disposition | Rationale |
| --- | --- | --- |
| Invalid archive mailbox values accepted and persisted | Version 2 now | Archive shortcuts are an exposed Version 2 browser workflow, so logically invalid destinations must be rejected at settings save time. |
| Tampered invalid message UID receives a success-style move redirect | Version 2 now | One-message move is an exposed Version 2 workflow, so success redirects must only follow a real authorized move. |
| Authenticated search returns `503 Message Search Unavailable` while search UI is exposed | Version 2 now | Search across one mailbox and all visible mailboxes is in the Version 2 acceptance boundary. |
| TLS 1.2 CBC suites remain enabled | Version 3 defer | This is real edge hardening work, but it is outside the bounded browser workflow defects fixed in this Version 2 slice and needs compatibility review. |
| Multiple concurrent active sessions are allowed | Version 3 defer | The report identifies a policy choice, not a confirmed vulnerability; Version 2 already provides session visibility and self-service revocation. |
| Session revoke race behavior was mixed | Version 3 defer | The evidence used a shared client cookie jar and is explicitly not a confirmed server-side flaw. |
| Client-side injection, CORS, clickjacking, XSSI, template injection, HTML injection, CSS injection, websocket, web messaging, browser storage, reverse tabnabbing, obvious API surface checks | Not applicable for this pass | The tested slice was broadly clean, and no Version 2 remediation change intentionally widens those surfaces. |

## Version 2 Remediation Requirements

The Version 2 code and test changes must satisfy the following:

- `POST /settings` validates `archive_mailbox_name` against the authenticated
  user's current mailbox list before saving.
- Invalid archive shortcut destinations receive a clear 400-class response and
  are not persisted.
- Message and mailbox pages do not render archive shortcut forms when the
  stored destination no longer appears in the user's mailbox list.
- `POST /message/move` validates request syntax, source mailbox, destination
  mailbox, and the source mailbox plus UID tuple at action time.
- Invalid, unavailable, or mismatched move tuples return clean 400 or 404
  responses and never emit a `moved_to` success redirect.
- Browser search remains exposed because it is in Version 2 scope, but invalid
  search inputs fail deterministically and all-mailboxes search is limited to
  browser-visible mailboxes.

## Version 2 Status

Version 2 addresses the confirmed vulnerabilities and workflow defects that are
in the current Version 2 browser scope:

- archive mailbox validation is enforced before persistence
- archive shortcuts are hidden when the configured destination cannot be
  resolved
- message move re-resolves mailbox and UID state before reporting success
- exposed browser search routes return deterministic validation responses for
  invalid input and avoid searching backend-only mailbox names in the
  all-visible-mailboxes path

These changes preserve the secure-by-default posture: the browser runtime still
depends on validated sessions, CSRF and same-origin checks for state-changing
routes, the mailbox helper boundary, bounded request parsing, and Dovecot as
the authoritative mailbox backend.

## Version 3 Backlog

The following real observations are intentionally not closed in Version 2:

- remove TLS 1.2 CBC suites after compatibility review
- decide whether to cap active browser sessions, evict older sessions, or keep
  concurrent sessions as an explicit supported policy
- retest the session revoke race scenario with isolated cookie jars before
  treating it as a server-side issue
- improve search ergonomics beyond ordinary one-mailbox and all-visible-mailbox
  retrieval
- add archive mailbox discovery, richer folder ergonomics, general bulk move,
  or move-history UI only after pilot workflow evidence requires them

## Regression Coverage

The Version 2 regression coverage for this remediation includes route tests for:

- successful message move still redirecting only after success
- invalid UID move rejection without a success redirect
- mismatched mailbox/UID move rejection
- non-numeric UID rejection
- empty destination rejection
- non-existent archive mailbox settings rejection
- stale archive shortcut target suppression in message view
- unknown mailbox search rejection

The live-host validation target remains the Version 2 readiness wrapper and the
targeted archive/search/move proof scripts under `maint/live/`.
