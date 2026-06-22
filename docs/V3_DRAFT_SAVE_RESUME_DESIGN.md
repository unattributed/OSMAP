# Version 3 Draft Save And Resume Design

## Purpose

This document defines the Version 3 draft save and resume boundary before any
draft persistence is added to the runtime.

The goal is to let authenticated users save, list, resume, update, send, and
delete bounded compose drafts without weakening the existing session, CSRF,
same-origin, state-path, resource, evidence, or `_osmap` plus `vmail`
confinement model.

## Status

This remains the design gate for the feature.

The current runtime supports server-generated reply and forward compose
prefills through `ComposeDraft`. It now also has file-backed draft persistence
primitives in `src/draft.rs` and authenticated browser routes for list, resume,
save, delete, and send-success cleanup.

Browser draft persistence remains incomplete for the full Version 3 acceptance
gate until WSTG/ASVS coverage and live or fixture release evidence are updated.

## Non-Goals

The draft slice must not add:

- browser-local draft storage
- rich-text compose
- attachment preview
- inline image rendering
- remote content loading
- original-message attachment reattachment
- automatic background save behavior that bypasses explicit state-changing
  route checks
- broad mailbox-management or Roundcube-parity behavior

Original-message attachment handling belongs to the separate reply/forward
attachment slice. Draft save and resume may persist newly uploaded compose
attachments, but only under the bounded rules below.

## User Workflow

The intended Version 3 workflow is:

1. An authenticated user opens compose, reply, or forward.
2. The user explicitly saves the current compose fields as a draft.
3. The user can list their own drafts.
4. The user can resume one of their own drafts into the compose form.
5. The user can update or delete that draft.
6. Sending a draft submits it once through the existing send path and then
   removes the persisted draft state after successful handoff.

If submission fails before accepted handoff, the draft remains available for a
later retry. If the draft is deleted or successfully sent, later resume attempts
must fail deterministically without exposing whether another user owns the
identifier.

## Storage Boundary

Drafts are server-side state under the configured OSMAP state root.

The implementation derives a draft root equivalent to:

- `<OSMAP_STATE_DIR>/drafts`

`OSMAP_DRAFT_DIR` can override that default. Bootstrap validation requires it to
be absolute and under the validated state root. The draft implementation must
not write drafts under mailbox storage, web static assets, temporary upload
directories shared with unrelated processes, or browser-accessible paths.

The storage layout should be:

- one owner directory per canonical username hash
- one draft directory per generated draft id
- one metadata file for validated compose fields
- zero or more attachment body files for newly uploaded compose attachments

Directory permissions must be restrictive, preferably `0700` on Unix-like
systems. Draft metadata and attachment files must be `0600` on Unix-like
systems. The implemented file store serializes complete operations with one
store-local advisory lock. Saves write a complete private staging directory
before replacing the visible draft directory, and restore the prior draft when
replacement finalization fails. This keeps quota checks and attachment plus
metadata replacement inside one cooperating-process transaction.

Canonical usernames may be stored in the record for ownership verification, but
path names must be derived from a stable hash with a draft-specific
domain-separation prefix, matching the existing settings-state style. Draft ids
must be high-entropy generated values. User-supplied draft ids must never be
used as path fragments without strict parsing.

## Ownership And Authorization

Every draft operation is scoped to the canonical username from the validated
session.

The implementation must:

- validate the browser session before listing, resuming, saving, sending, or
  deleting drafts
- treat revoked, expired, or idle-expired sessions as unauthenticated
- load drafts only from the authenticated user's owner directory
- verify that the draft record owner matches the validated session owner before
  returning or mutating a record
- return a generic not-found response for unknown, malformed, deleted, expired,
  or cross-owner draft ids

Draft ids do not grant authority. They are only selectors inside the already
authenticated user's draft namespace.

## Browser Routes

The implementation should keep the route surface small:

| Route | Method | Behavior |
| --- | --- | --- |
| `/drafts` | `GET` | List the authenticated user's bounded draft summaries. |
| `/draft` | `GET` | Resume one authenticated user's draft into the compose form. |
| `/drafts/save` | `POST` | Create or update a draft from validated compose fields. |
| `/drafts/delete` | `POST` | Delete one authenticated user's draft. |
| `/send` | `POST` | When `draft_id` is present, revalidate and submit the draft once, then delete it only after successful accepted handoff. |

All state-changing draft routes must require the existing per-session CSRF token
and same-origin request metadata. `Origin` remains preferred, with the existing
same-origin fallback behavior preserved. Route tests must cover missing CSRF,
bad CSRF, missing same-origin metadata where required, cross-origin metadata,
and the accepted same-origin path.

The implementation should prefer ordinary server-rendered forms over
client-side draft logic. No browser local storage or remote content fetch is
needed for this slice.

## Validation And Limits

Draft validation must reuse the existing compose policy unless the
implementation documents a stricter draft-specific cap:

- `DEFAULT_MAX_RECIPIENTS`
- `DEFAULT_RECIPIENT_MAX_LEN`
- `DEFAULT_SUBJECT_MAX_LEN`
- `DEFAULT_BODY_MAX_LEN`
- `DEFAULT_MAX_ATTACHMENTS`
- `DEFAULT_ATTACHMENT_MAX_BYTES`
- `DEFAULT_TOTAL_ATTACHMENT_MAX_BYTES`
- `DEFAULT_ATTACHMENT_FILENAME_MAX_LEN`
- `DEFAULT_ATTACHMENT_CONTENT_TYPE_MAX_LEN`

Draft save must reject the same invalid recipients, subject line breaks,
oversized body text, oversized attachments, excessive attachment count,
excessive aggregate attachment bytes, path-like attachment names,
control-bearing attachment names, and invalid attachment content-type values
that the send path rejects.

The implementation should also define operator-visible caps for:

- maximum drafts per user
- maximum draft age
- maximum draft summary rows rendered in one response
- maximum metadata file size before parse rejection
- maximum attachment files per draft directory

Drafts that exceed the age limit should be removed by opportunistic cleanup on
list, save, and resume. A later scheduled cleanup tool is allowed, but release
readiness must not depend on a scheduler being present.

## Attachment Handling

Persisted draft attachments are limited to newly uploaded compose attachments.
They must stay forced-download or send-only data and must not become a preview
surface.

The implementation must:

- validate attachment names, content types, per-file size, aggregate size, and
  count before writing attachment bodies
- revalidate persisted draft attachments before submission
- use generated internal file names rather than browser-supplied names for
  stored attachment body paths
- keep browser-supplied attachment names only as bounded metadata
- avoid logging attachment names or attachment body content
- delete draft attachment files when the draft is deleted or successfully sent

Reply and forward source-message attachment reattachment remains out of this
slice. A draft created from a forward may preserve the current text metadata
notice, but it must not silently persist or resend source-message attachments
until the separate reply/forward attachment gate is implemented.

## Failure Behavior

Failure handling must be deterministic and low-detail:

- malformed draft ids return a generic bad-request or not-found response
- unknown, deleted, expired, and cross-owner draft ids return generic not found
- invalid compose fields return the same class of user-readable validation
  errors as the send path
- quota and size failures return bounded 4xx responses
- storage unavailable, atomic replace failure, and cleanup failure return a
  generic temporary-unavailable response
- send backend failures keep the draft available unless the message was already
  accepted by the submission surface

Audit logs may include event type, canonical username, draft operation, result,
error class, draft count, attachment count, and byte counts. They must not
include full recipients, subject, body text, attachment names, attachment body
content, CSRF tokens, cookies, raw session identifiers, passwords, TOTP codes,
or TOTP secrets.

## Evidence Hygiene

Draft evidence may include:

- command name
- assessed commit
- route status codes
- authenticated path proof
- CSRF and same-origin rejection proof
- ownership-isolation proof
- draft count and attachment count
- redacted draft id shape proof
- pass or fail result

Draft evidence must not include:

- plaintext passwords
- reusable TOTP seeds
- current TOTP codes
- active session cookies
- CSRF tokens
- raw session identifiers
- full recipient lists
- full subject lines
- full draft bodies
- full attachment bodies
- private mailbox content

## WSTG And ASVS Disposition

Draft routes are authenticated browser routes and remain mapped to ASVS as the
primary secure-web-application standard. The WSTG testing pack now includes
`OSMAP-WSTG-BUSL-002`, a release-required authenticated dynamic test with
ASVS 5.0.0 mappings and OWASP Top 10 2025 reporting. That check covers:

- access control and ownership isolation
- session expiry and revocation
- CSRF and same-origin rejection
- injection through recipients, subject, body, attachment filename, content
  type, and draft id
- upload and storage limits
- business-logic checks for save, resume, update, send-once, and delete
- security logging and evidence redaction

The OWASP Top 10 2025 crosswalk remains a secondary reporting layer over the
ASVS-backed checks.

Host-safe authenticated evidence for `OSMAP-WSTG-BUSL-002` passed against
`mail.blackbagsecurity.com` on 2026-05-07 in
`maint/wstg-testing-pack/output/osmap-wstg-20260507-173210/`. The generated
report and evidence redaction scan did not expose stored session cookies, raw
session ids, CSRF tokens, TOTP values, passwords, raw draft ids, full draft
bodies, or validation draft body markers.

## Implementation Closeout Gate

The later implementation slice is complete only when all of the following are
true:

- unit tests cover draft id parsing, owner path derivation, metadata parsing,
  attachment metadata validation, atomic replacement behavior, cleanup, and
  oversized input rejection
- route tests cover list, resume, create, update, delete, send-success cleanup,
  send-failure preservation, CSRF rejection, same-origin rejection, stale
  sessions, and cross-owner draft ids
- WSTG coverage is updated with ASVS mappings and OWASP Top 10 2025 reporting
- release evidence remains redacted and safe to archive
- `docs/V3_ACCEPTANCE_CRITERIA.md`, `docs/V3_SECURITY_GATES.md`, and
  `docs/PILOT_WORKFLOW_INVENTORY.md` accurately describe the implemented
  workflow disposition
