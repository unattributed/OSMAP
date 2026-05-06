# V3 Live MIME And HTML Proof Plan

## Purpose

This document defines the safe live-host proof plan for the Version 3 MIME and
HTML correctness work.

The goal is to prove the current MIME parsing, header decoding, sanitized HTML,
inline image metadata, and attachment metadata behavior on
mail.blackbagsecurity.com without making the validator or its evidence files a
source of sensitive material.

This plan must be reviewed before adding a combined live validation script.

## Scope

The live proof should validate these Version 3 slices together:

- MIME and HTML regression corpus behavior
- encoded Subject, From, and Date header summary behavior
- sanitized HTML behavior
- inline image metadata behavior without inline rendering
- attachment metadata behavior
- forced-download attachment behavior for selected safe parts
- audit redaction behavior

The live proof must not introduce:

- draft persistence
- attachment preview
- inline image rendering
- remote content loading
- broad HTML layout support
- new trusted URL schemes
- message body audit logging
- attachment body audit logging

## Host Model

The proof is intended for the current validated OpenBSD host shape:

- OSMAP repository present on mail.blackbagsecurity.com
- doas -u _osmap available for the browser runtime
- doas -u vmail available for the mailbox helper and Dovecot validation
- dedicated helper socket path available inside an isolated work root
- isolated OSMAP state tree for sessions, settings, audit, cache, and TOTP data
- controlled validation mailbox, defaulting to osmap-helper-validation@blackbagsecurity.com

The proof should follow the existing live validation style already used by the
encoded-header, inline-image metadata, login-send, and resource-control
validators.

## Evidence Safety Rules

The validator must never print, store in repository evidence, or intentionally
copy:

- mailbox passwords
- TOTP codes
- TOTP secret material
- browser session cookies
- CSRF tokens
- raw persisted session identifiers
- full message bodies
- full attachment bodies
- authorization headers

Evidence may include:

- test subject identifiers
- HTTP status lines
- bounded route names
- selected non-secret header summary strings
- boolean pass or fail checks
- counts of matching audit fields
- counts of matching attachment rows
- redacted audit excerpts
- SHA-256 hashes of generated evidence files
- generated work-root path when OSMAP_KEEP_WORK_ROOT=1

Audit evidence must confirm that session correlation uses session_ref and does
not reintroduce raw session_id fields.

## Validation Account And Cleanup

The script should default to:

OSMAP_VALIDATION_USER=osmap-helper-validation@blackbagsecurity.com

The script must inject only synthetic, non-private messages with unique subjects.
Every injected subject must include a timestamp and process identifier.

Cleanup must expunge only messages matching the exact synthetic subject values
created by the script.

Cleanup must run through trap on EXIT, INT, and TERM.

If OSMAP_KEEP_WORK_ROOT=1 is set, temporary files may remain on the host for
operator review. The work root must still avoid credentials, TOTP codes, cookies,
CSRF tokens, raw session identifiers, full message bodies, and full attachment
bodies in any report intended for the repository.

## Recommended Proof Strategy

The first implementation should use synthetic validated sessions, not a real
password plus TOTP login.

This keeps the proof focused on MIME and rendering behavior. The existing
login-send validator continues to prove real password plus TOTP login.

A later optional mode may run after a real login, but only after the synthetic
proof is stable.

## Synthetic Message Set

The combined live validator should inject a small controlled message set.

### 1. Encoded Header Plain Text Message

Purpose:

- prove encoded Subject summary
- prove encoded From summary
- prove bounded encoded Date extraction where the browser surface uses it
- confirm Dovecot date_received remains the authoritative mailbox timeline field

Expected evidence:

- message view returns HTTP/1.1 200 OK
- decoded subject marker is present
- decoded sender marker is present
- synthetic body marker is present only as a bounded visible proof
- audit evidence does not contain the body marker

### 2. Sanitized HTML Hostile Link Message

Purpose:

- prove sanitized HTML strips unsafe link schemes
- prove relative, protocol-relative, cid, data, and javascript hrefs are not trusted navigation targets
- prove style attributes, event handlers, forms, metadata refresh, remote CSS,
  image tags, SVG, iframe, object, embed, template, and comments are stripped or neutralized

Expected evidence:

- message view returns HTTP/1.1 200 OK
- safe visible text remains
- safe HTTPS link may remain with rel no opener, noreferrer, and nofollow
- unsafe URL and active-content markers are absent
- remote host marker is absent from rendered response
- audit evidence does not contain hostile body markers

### 3. Multipart Related Inline Image Message

Purpose:

- prove cid image references do not render inline
- prove inline image metadata is surfaced as attachment metadata
- prove Content-ID metadata is shown as metadata only
- prove the browser notice explains that inline or remote content is blocked

Expected evidence:

- message view returns HTTP/1.1 200 OK
- inline image notice is present
- Content-ID metadata marker is present
- img tags do not appear in the rendered message body
- attachment download route exists for the surfaced part

### 4. Attachment Metadata Message

Purpose:

- prove suspicious filenames are not trusted as paths
- prove forced-download metadata remains the only attachment retrieval behavior
- prove calendar, delivery-status, and original-message style parts stay downloadable only as attachments
- prove attachment bodies do not appear in audit logs

Expected evidence:

- message view returns HTTP/1.1 200 OK
- attachment metadata row is present
- attachment link points to /attachment
- attachment download returns Content-Disposition: attachment
- response Content-Type is safe or falls back to application/octet-stream
- audit log contains metadata counts, not attachment bodies

## Pass Criteria

The live proof should pass only when all of the following are true:

- current tree builds on the host
- helper runtime starts under vmail with OpenBSD confinement in enforce
- browser runtime starts under _osmap with OpenBSD confinement in enforce
- /healthz returns HTTP/1.1 200 OK
- each injected message is located by exact subject
- each message view returns HTTP/1.1 200 OK
- hostile HTML unsafe markers are absent from rendered output
- inline images are not rendered inside the message body
- attachment metadata is surfaced without preview
- selected attachment downloads return forced-download headers
- audit log contains no raw session_id field
- audit log contains no cookie, CSRF token, TOTP code, password, message body, or attachment body markers
- cleanup removes injected messages unless OSMAP_KEEP_WORK_ROOT=1 is set for temporary operator review

## Fail Criteria

The live proof must fail closed if any of the following occur:

- required tools are missing
- target validation mailbox is missing
- build fails
- helper runtime fails to start
- browser runtime fails to start
- a synthetic message cannot be injected or located
- any expected safe marker is missing
- any unsafe marker appears in rendered output
- any raw session_id audit field appears
- any known synthetic attachment body marker appears in audit logs
- cleanup cannot be attempted

## Expected Script Name

The future script should be added as:

maint/live/osmap-live-validate-v3-mime-html-proof.ksh

The script should write a redacted host report to:

maint/live/latest-host-v3-mime-html-proof-report.txt

The report should contain:

- host name
- repository commit
- build result
- helper runtime result
- browser runtime result
- message view status checks
- sanitized HTML pass or fail checks
- inline image metadata pass or fail checks
- attachment metadata pass or fail checks
- forced-download header checks
- audit redaction checks
- cleanup result
- no secrets
- no full message bodies
- no full attachment bodies

## Current Decision

Slice 5 starts with this proof plan first.

The combined live validation script should only be implemented after this
document is reviewed and accepted.
