# V3 Reply And Forward Attachment Handling Design

## Purpose

This document is the Version 3 design gate for explicit original-message
attachment handling in reply and forward compose flows.

The goal is to close the daily-driver gap where users need to carry selected
source-message files into a reply or forward without weakening the existing
forced-download posture, helper boundary, CSRF model, or compose limits.

This is not a broad attachment preview or rich webmail feature. It is a narrow
server-side selection and revalidation path for attachments already surfaced by
the bounded MIME layer.

## Current State

OSMAP currently supports:

- reply and forward draft generation through `ComposeDraft`
- surfaced original-message attachment metadata in message view
- forced-download retrieval through the existing attachment route
- bounded new attachment uploads during compose
- persisted draft attachments for newly uploaded compose files
- explicit source-attachment checkboxes on reply and forward compose pages
- send-time re-fetch of selected source attachments through the existing
  bounded attachment-download path
- draft metadata persistence of only the source mailbox, source UID, and
  explicitly selected source part paths
- draft-resume revalidation of the source message before selected controls are
  rendered

OSMAP still does not automatically reattach original-message attachments during
reply, forward, or draft resume. Source attachment bodies and raw MIME content
are never copied into draft metadata. Resume preselects only the explicit
part paths that remain surfaced by the current source message.

Current route regression coverage includes duplicate selections, missing source
mailbox metadata, stale or missing selected source parts, and aggregate
attachment count overflow when selected source attachments are combined with
new uploads.

Credential-backed live/WSTG coverage for the send-time selected source
attachment path is mapped as `OSMAP-WSTG-BUSL-003`. The live validator performs
a real password-plus-TOTP login on `mail.blackbagsecurity.com`, injects
controlled source messages, proves positive selected-source attachment
inclusion, rejects duplicate/tampered/stale selections, and checks report
redaction.

## User Workflow

The Version 3 target workflow is:

1. User opens a message.
2. User chooses `Reply` or `Forward`.
3. The compose page shows surfaced original attachments from the source
   message with explicit include checkboxes.
4. Defaults remain conservative:
   - reply does not preselect original attachments
   - forward may offer explicit selection but must not silently include files
5. User can upload new attachments as today.
6. On send, OSMAP revalidates every selected original attachment against the
   source mailbox, UID, and part path.
7. OSMAP submits the message only if the aggregate new and selected-original
   attachment set passes the existing compose attachment count and byte limits.
8. If a selected original attachment cannot be revalidated or included, the
   send fails visibly. OSMAP must not silently drop a confirmed selection.

## Browser Route Boundary

The implementation slice may touch only these browser routes:

- `GET /compose`
- `POST /send`
- `POST /drafts/save` only if draft persistence needs to remember pending
  original-attachment selections

No new unauthenticated routes are needed.

State-changing behavior remains on POST routes and must keep the existing
session, CSRF, and same-origin checks.

## Source Attachment Selection Model

Selection state should use bounded, server-validated fields:

- source mailbox name
- source UID
- surfaced attachment part path
- expected filename, content type, and size metadata for user display only

The source mailbox, UID, and part path are authoritative for revalidation.
Display metadata is not trusted at send time.

The route layer must reject:

- missing source mailbox for selected original attachments
- missing source UID for selected original attachments
- invalid part paths
- selections that exceed the configured attachment count
- duplicate selections
- selections for attachments not surfaced by the current MIME policy
- selections whose decoded body exceeds the attachment download or compose
  aggregate limits

## Helper And Mailbox Boundary

Selected original attachments must be fetched through the existing
helper-backed message-view and attachment-download path where production serve
mode uses the mailbox helper.

The browser runtime must not gain direct mailbox storage authority, direct IMAP
access, direct SMTP access, or privileged host access.

## Compose Limit Boundary

The implementation must reuse the existing compose policy unless a later
reviewed change deliberately adjusts it:

- `DEFAULT_MAX_ATTACHMENTS`
- `DEFAULT_ATTACHMENT_MAX_BYTES`
- `DEFAULT_TOTAL_ATTACHMENT_MAX_BYTES`
- `DEFAULT_ATTACHMENT_FILENAME_MAX_LEN`
- `DEFAULT_ATTACHMENT_CONTENT_TYPE_MAX_LEN`

Selected original attachments and newly uploaded attachments share the same
aggregate count and byte limits before sendmail receives the message.

## Draft Boundary

Draft save/resume should not copy original-message attachment bodies into draft
state in the first implementation.

If the user saves a draft with pending original-attachment selections, the draft
stores only bounded source mailbox, UID, and part-path references. It does not
store source display metadata, attachment bytes, or raw MIME content. Resume
revalidates the source message and send re-fetches every selected part through
the attachment path.

If the source message changes or disappears before send, the send fails
visibly and the draft remains available for user correction.

## Failure Behavior

The browser must receive deterministic failures:

- invalid selection: `400 Bad Request`
- stale or missing source message: generic compose failure
- missing or unsupported selected attachment: generic compose failure
- aggregate attachment limit exceeded: `400 Bad Request`
- helper/backend unavailable: `503 Service Unavailable`
- sendmail failure after successful attachment revalidation: existing send
  failure behavior

Failures must preserve the composed text and pending draft where possible.
Confirmed original-attachment selections must not be silently dropped.

## Logging And Evidence Hygiene

Audit events may record:

- route class
- canonical username after session validation
- source mailbox
- source UID
- selected part path
- selected attachment count
- aggregate attachment byte count
- public failure class

Audit events and evidence must not record:

- session cookies
- CSRF tokens
- passwords
- TOTP codes or seeds
- raw message bodies
- attachment bodies
- unbounded filenames or content types
- private message content beyond bounded metadata

## WSTG And ASVS Disposition

The implementation slice must update the WSTG testing pack or record a
non-applicability decision for each relevant class. Expected applicable areas:

- authenticated access control for source mailbox and UID references
- CSRF rejection for selected original attachments on send
- same-origin rejection for state-changing sends
- business-logic rejection of tampered mailbox, UID, part path, and duplicate
  selections
- upload and aggregate size-limit behavior
- audit redaction for selected original attachments

`OSMAP-WSTG-BUSL-003` is the release-required authenticated dynamic WSTG lane
for the send-time selected source-attachment path. It produces a redacted live
report plus static boundary and evidence-redaction files. It is credential and
TOTP gated because the proof depends on the real browser login path, even though
the host validator uses a temporary validation mailbox password and isolated
TOTP state.

The primary acceptance source remains `docs/V3_ACCEPTANCE_CRITERIA.md`.

## Required Tests

Implementation evidence must include tests for:

- reply default behavior with no original attachments selected
- forward default behavior without silent original-attachment inclusion
- successful selected original attachment inclusion
- selected original plus newly uploaded aggregate count limit
- selected original plus newly uploaded aggregate byte limit
- tampered mailbox rejection
- tampered UID rejection
- tampered part path rejection
- duplicate selection rejection
- stale source message failure
- helper/backend failure
- draft save/resume of source references if implemented
- send failure preserving the draft or compose state where possible

## Explicit Non-Goals

This slice does not add:

- inline attachment preview
- inline image rendering
- remote external content loading
- JavaScript-heavy compose behavior
- automatic original-message attachment reattach
- broad MIME client behavior
- arbitrary mailbox management
- OpenPGP attachment handling
