# Pilot Workflow Inventory

## Purpose

This document records the current repo-owned workflow inventory for Version 2
pilot planning and closeout.

It is the baseline operator artifact used to decide:

- which users are good Version 2 pilot candidates now
- which daily workflows OSMAP already supports credibly
- which workflows still require Roundcube fallback or should defer pilot entry
- whether the completed Version 2 pilot cohort fit the bounded V2 workflow set

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
- light folder organization through one-message move, archive, or bounded
  selected-message archive from a mailbox list
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
| One-message move | `supported` | admit | Narrow organization workflow, not broad mailbox management. |
| Archive shortcut | `supported_with_limits` | admit | Depends on configured archive mailbox rather than discovery-heavy UX. |
| Selected-message archive from mailbox list | `supported_with_limits` | admit | Bounded archive-only selection reuses the existing move path once per selected UID. |
| Session list, revoke, logout | `supported` | admit | Included in current browser security surface. |
| Safe HTML view | `supported_with_limits` | admit | Sanitized HTML only; no active content or remote loads. |
| Plain-text preference for message display | `supported` | admit | Small bounded settings surface only. |
| Draft save and resume later | `roundcube_fallback` | do not admit if required daily | Not implemented. |
| Reply or forward with original attachments preserved automatically | `roundcube_fallback` | do not admit if required daily | Not implemented. |
| General bulk move or other bulk mailbox actions | `roundcube_fallback` | do not admit if required daily | OSMAP supports bounded selected archive, not arbitrary bulk mailbox operations. |
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

## Version 2 Pilot Closeout Confirmation

The final Version 2 pilot cohort fit the workflow inventory for the bounded
scope tested:

| Trial user | Workflow fit | Completed actions | Result |
| --- | --- | --- | --- |
| `duncan@blackbagsecurity.com` | V2 fit | retrieve mail; send mail; send mail with attachments | Functions presented in the current code base worked as expected. |
| `ops@blackbagsecurity.io` | V2 fit | retrieve mail; send mail; send mail with attachments | Functions presented in the current code base worked as expected. |
| `duncan@redactedsecurity.ca` | V2 fit | retrieve mail; send mail; send mail with attachments | Functions presented in the current code base worked as expected. |

All three trial users want additional functionality in Version 3. All three
also want a more polished user experience, ideally closer to Thunderbird. That
feedback is explicitly deferred to Version 3 or later and does not widen the
Version 2 closeout scope.

## Per-User Confirmation Checklist

Before moving an additional real user into a future pilot, confirm explicitly:

- whether they need browser draft persistence
- whether they need reply or forward with original attachments preserved
- whether they rely on general bulk mailbox actions beyond bounded selected
  archive
- whether they rely on Roundcube-only filtering or preference features
- whether they expect rich HTML convenience behavior that OSMAP intentionally
  will not provide

If any of those are required for ordinary use, keep that user on Roundcube
until either the need is reclassified as unnecessary or a later version closes
the gap without widening OSMAP beyond its mission.

## Version 3 Daily-Driver Target

Version 3 changes the future admission target, not the completed Version 2
closeout result. A Version 3 daily-driver candidate is someone who still fits
the OSMAP security model but needs the following workflows for ordinary
browser-mail use:

- draft save and resume
- explicit reply and forward attachment handling
- richer search refinement and result clarity
- bounded selected-message folder cleanup beyond archive-only behavior
- clearer session and device policy
- more reliable MIME and HTML correctness for common mail received from
  outside senders

The Version 3 target remains a focused browser-mail access layer. The following
users are still not good Version 3 candidates if these workflows are daily
requirements:

- contacts, calendar, or groupware users
- plugin-dependent webmail users
- mobile-app-dependent users
- users requiring remote external content loading in messages
- users requiring browser OpenPGP implementation rather than design-only
  investigation
- users requiring broad admin-console workflows

## Version 3 Gap Map

| Workflow gap | Version 3 disposition | Acceptance gate |
| --- | --- | --- |
| MIME and HTML correctness | in scope | `docs/V3_ACCEPTANCE_CRITERIA.md` |
| Draft save and resume later | in scope | `docs/V3_ACCEPTANCE_CRITERIA.md` |
| Reply or forward with original attachments preserved explicitly | in scope | `docs/V3_ACCEPTANCE_CRITERIA.md` |
| Richer search ergonomics | in scope | `docs/V3_ACCEPTANCE_CRITERIA.md` |
| Bounded bulk folder actions | in scope | `docs/V3_ACCEPTANCE_CRITERIA.md` |
| Concurrent-session and device policy | in scope | `docs/V3_SECURITY_GATES.md` |
| TLS 1.2 CBC disposition | in scope | `docs/V3_SECURITY_GATES.md` |
| WSTG regression evidence | in scope | `docs/V3_SECURITY_GATES.md` |
| Contacts, calendar, groupware, plugins, mobile app, broad admin console | out of scope | `docs/V3_DEFINITION.md` |
| Remote external content loading | out of scope | `docs/V3_DEFINITION.md` |
| OpenPGP implementation | out of scope except design-only investigation | `docs/V3_ROADMAP.md` |
