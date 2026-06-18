# V6 Acceptance Criteria

## Release Claim

V6 is accepted only when a selected OpenBSD-hosted cohort completes its
required browser-mail workflows without normal Roundcube fallback and the
evidence proves that V4 and V5 security boundaries remain intact.

## Mandatory Carry-Forward

- The V4 hostile-content gates pass for the assessed V6 source.
- V5 boundary-hardening evidence is carried forward and the current source
  tests for canonical identity, configured Host and same-origin policy,
  response-header validation, strict HTTP framing, plain-text responses, and
  typed HTML boundaries pass.
- `_osmap` and `vmail` remain separate runtime identities.
- Production mailbox access remains helper-backed; direct `doveadm` access is
  not accepted as a production fallback.
- CSRF, `OSMAP_ALLOWED_HOSTS`, forced-download attachments, bounded parsing,
  and no-remote-load rendering remain enforced.

## Mandatory V6 Evidence

- The V6 production readiness validator passes and produces a sanitized report.
- A V6 no-Roundcube-fallback rehearsal report exists, is sanitized, and is
  marked passed for the selected cohort.
- The V6 observability validator proves required security events, operator
  reviewability, and redaction.
- The V6 resource resilience validator proves bounded behavior under pressure
  and recovery.
- V6 closeout evidence exists, is checksummed, and is safe to commit.
- Live evidence comes from `mail.blackbagsecurity.com` or an explicitly
  documented equivalent OpenBSD target.

## Session Store

Cross-process session-store locking must be implemented for file-backed
operations, or a documented single-process invariant must be validated on the
production target and enforced by the V6 release gate. Lock or invariant
failure must fail closed.

## Source-Attachment Draft Resume

If V6 adds source-attachment draft-resume behavior:

- only attachments explicitly selected by the user may be persisted as source
  references
- original message attachments must never be reattached automatically
- draft metadata must not persist source attachment bytes or raw MIME content
- source mailbox, UID, and selected part paths must be bounded and validated
- selected source attachments must be refetched and revalidated at send time
- missing, changed, unauthorized, stale, duplicate, or unresolved references
  must fail visibly without sending
- selected source attachments count against existing compose limits
- forced-download and no-preview behavior remain unchanged

## Selected-Cohort Workflow Rule

The rehearsal must explicitly classify each workflow as `passed`,
`not_required_for_selected_cohort`, or `failed`. Every selected required
workflow must pass. Any use of Roundcube for normal fallback makes the
rehearsal fail. The authoritative procedure and recorder are
`V6_ROUNDCUBE_RETIREMENT_REHEARSAL.md` and
`maint/live/osmap-live-record-v6-retirement-rehearsal.ksh`.

## Fail-Closed Rule

No criterion may be waived by a developer-mode report, an absent tool, a
skipped authenticated path, or an unsanitized operator note. Such conditions
must be recorded as blockers and V6 remains incomplete.
