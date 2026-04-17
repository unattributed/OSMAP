# Pilot Workflow Inventory

## Purpose

This document records the current repo-owned workflow inventory for Version 2
pilot planning.

It is not a claim that every intended pilot user has already been interviewed.
It is the baseline operator artifact used to decide:

- which users are good Version 2 pilot candidates now
- which daily workflows OSMAP already supports credibly
- which workflows still require Roundcube fallback or should defer pilot entry

## Inventory Status Meanings

Use these status labels consistently:

- `supported`: OSMAP already implements the workflow and the Version 2 gate
  expects it to be proven on the validated host
- `supported_with_limits`: OSMAP supports the workflow, but users must accept
  the narrower browser behavior described in the notes
- `roundcube_fallback`: the workflow is not yet a credible OSMAP Version 2
  pilot workflow and still needs Roundcube fallback if it is required daily
- `out_of_scope`: the workflow is intentionally outside OSMAP Version 2

## Current Pilot-Candidate Profile

The current best-fit Version 2 pilot user is someone who needs:

- password-plus-TOTP browser login
- routine mailbox read, search, and attachment download
- straightforward compose, reply, forward, and send
- light folder organization through one-message move or archive
- simple session self-management

The current repo state is not yet a good fit for users who depend daily on:

- draft persistence
- bulk message organization
- original-message attachment reattachment during reply or forward
- ManageSieve-style mail filtering UI
- rich HTML convenience behavior such as inline remote resources or inline image
  rendering
- OpenPGP browser workflows

## Workflow Inventory

| Workflow | Current status | Pilot disposition | Notes |
| --- | --- | --- | --- |
| Password-plus-TOTP login | `supported` | admit | Core Version 2 browser-auth workflow. |
| Mailbox listing and message list navigation | `supported` | admit | Helper-backed and already part of the validated browser slice. |
| Message view | `supported` | admit | Conservative browser rendering only. |
| Attachment download | `supported` | admit | Forced-download posture remains deliberate. |
| Search in one mailbox | `supported` | admit | Current bounded search is sufficient for ordinary pilot use. |
| Search across all visible mailboxes | `supported` | admit | Included in the Version 2 readiness proof set. |
| Compose new message | `supported` | admit | Plain browser compose only. |
| Reply | `supported_with_limits` | admit | No automatic original-attachment reattach. |
| Forward | `supported_with_limits` | admit | No automatic original-attachment reattach. |
| Upload new attachment and send | `supported` | admit | Bounded upload path only. |
| One-message move | `supported` | admit | Narrow organization workflow, not bulk triage. |
| Archive shortcut | `supported_with_limits` | admit | Depends on configured archive mailbox rather than discovery-heavy UX. |
| Session list, revoke, logout | `supported` | admit | Included in current browser security surface. |
| Safe HTML view | `supported_with_limits` | admit | Sanitized HTML only; no active content or remote loads. |
| Plain-text preference for message display | `supported` | admit | Small bounded settings surface only. |
| Draft save and resume later | `roundcube_fallback` | do not admit if required daily | Not implemented. |
| Reply or forward with original attachments preserved automatically | `roundcube_fallback` | do not admit if required daily | Not implemented. |
| Bulk move or other bulk mailbox actions | `roundcube_fallback` | do not admit if required daily | Not implemented. |
| Rich mailbox-management ergonomics | `roundcube_fallback` | admit only if unnecessary | OSMAP Version 2 intentionally stays narrower than Roundcube. |
| ManageSieve filter editing in browser | `roundcube_fallback` | do not admit if required daily | No OSMAP UI for this. |
| Contacts, calendar, or groupware | `out_of_scope` | exclude | Not part of OSMAP Version 2. |
| OpenPGP signing, encryption, decryption, or key management | `out_of_scope` | exclude | Explicitly deferred beyond Version 2. |
| Inline external resources or inline image rendering in message body | `out_of_scope` | exclude | Rejected to preserve browser trust boundaries. |

## Pilot Admission Rule

Do not enroll a user in the first Version 2 pilot if their ordinary daily
workflow depends on any item currently marked `roundcube_fallback` or
`out_of_scope`.

Users can still be reasonable pilot candidates if they:

- mainly need read, search, send, and light folder organization
- can tolerate conservative HTML handling
- do not rely on browser draft persistence or bulk mailbox actions

## Per-User Confirmation Checklist

Before moving a real user into the pilot, confirm explicitly:

- whether they need browser draft persistence
- whether they need reply or forward with original attachments preserved
- whether they rely on bulk mailbox actions
- whether they rely on Roundcube-only filtering or preference features
- whether they expect rich HTML convenience behavior that OSMAP intentionally
  will not provide

If any of those are required for ordinary use, keep that user on Roundcube
until either the need is reclassified as unnecessary or a later version closes
the gap without widening OSMAP beyond its mission.
