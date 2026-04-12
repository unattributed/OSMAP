# OWASP ASVS Baseline

## Purpose

This document records the current repository-grounded OSMAP alignment posture
to the OWASP Application Security Verification Standard (ASVS) for the
implemented Version 1 browser and helper surfaces.

It exists to make the repo's already-stated OWASP posture concrete without
turning Version 1 closeout into a broad compliance program.

This baseline is intentionally narrow:

- it focuses on the OSMAP Version 1 surfaces that actually ship
- it maps those surfaces to the ASVS-style control families most relevant to
  the current implementation
- it includes a short OWASP Top 10 crosswalk where that helps reviewers reason
  about risk
- it does not claim full ASVS compliance, certification, or coverage of future
  Version 2 scope

## Review Basis

This baseline is grounded in:

- the current Rust implementation under `src/`
- the current browser routes, helper boundary, and OpenBSD confinement model
- the current repo-owned validation and regression scripts
- the current release-facing docs, including
  `ACCEPTANCE_CRITERIA.md` and `V1_CLOSEOUT_SOP.md`
- the successful April 12, 2026 current-tip closeout rerun and supplemental
  real-user browser walkthrough on `mail.blackbagsecurity.com`

## Current Version 1 Scope Boundary

The relevant Version 1 browser-visible surface is:

- mailbox-password-plus-TOTP authentication
- session issuance, listing, revocation, and logout
- mailbox listing, message listing, message view, and bounded search
- browser compose/send
- one-message move plus archive shortcut behavior
- safe HTML rendering, plain-text fallback, and attachment handling
- settings limited to bounded user-facing mail-display preferences

This baseline should not be read as covering:

- self-service MFA enrollment or recovery
- broader account-management workflows
- public internet exposure without the surrounding operator controls already
  described elsewhere in the repo
- broader Version 2 UX, admin, or device-management work

## ASVS-Aligned Control Areas

### Authentication and Second Factor

The current V1 implementation is aligned with the ASVS-style requirement that
browser authentication be explicit, bounded, and multi-step rather than
password-only:

- mailbox credentials are validated against the existing Dovecot authority
- successful primary credentials do not become an authenticated browser session
  until TOTP verification succeeds
- TOTP secrets remain operator-managed and outside committed configuration
- login input sizes are bounded before backend use
- login throttling exists for both credential-plus-remote and remote-only
  buckets

This is a meaningful alignment point for OWASP Top 10 concerns around weak
authentication and brute-force resistance, but it is not a claim that OSMAP
already includes every possible MFA recovery or enrollment control.

### Session Management

The current session layer aligns with the ASVS-style requirement that sessions
be explicit, bounded, revocable, and visible:

- session issuance happens only after successful second-factor completion
- persisted session records include bounded metadata for user visibility and
  operator review
- session lifetime is explicit in configuration
- logout and self-service revocation are implemented as real state transitions
- session cookies are validated conservatively and stale sessions are rejected

This materially supports OWASP Top 10 concerns around broken authentication and
session misuse.

### Access Control and Trust Boundaries

The current Version 1 architecture aligns with ASVS-style least-privilege and
access-control expectations:

- the browser-facing runtime is kept at `_osmap`
- mailbox reads are mediated through the dedicated local helper boundary rather
  than broad direct mailbox authority in production `serve`
- production `serve` rejects configurations that omit that helper boundary
- helper and browser responsibilities are separated deliberately in code and in
  the OpenBSD confinement plan

This is especially relevant to OWASP Top 10 concerns around broken access
control.

### Input Validation and Request Handling

The current browser boundary aligns with ASVS-style conservative request
validation:

- HTTP parsing is explicit and bounded
- request targets, headers, cookies, and form inputs are validated narrowly
- duplicate parameters and malformed inputs are rejected
- CSRF protection exists on state-changing browser routes
- current browser mutation paths are guarded by bounded input validation before
  touching backend mail behavior

This materially supports OWASP Top 10 concerns around injection-style input
abuse and request forgery.

### Output Encoding and Browser Safety

The current rendering model aligns with ASVS-style output-safety expectations:

- HTML output is escaped by default for browser-visible values
- Content Security Policy remains default-deny and narrow
- HTML message rendering goes through a narrow sanitizer
- plain-text fallback remains available as the conservative user-facing option
- active content, unsafe URLs, and external fetch behavior are stripped from
  rendered HTML

This materially supports OWASP Top 10 concerns around XSS and content-driven
browser abuse.

### File and Attachment Handling

The current attachment and upload behavior aligns with ASVS-style file-handling
controls in a bounded first-release form:

- attachment-path selection is validated narrowly
- download responses force browser download behavior
- attachment metadata is surfaced conservatively
- uploaded attachments are size-bounded and filename-validated
- attachment convenience behavior remains intentionally smaller than a general
  webmail platform's broader trust model

This materially supports OWASP Top 10 concerns around unsafe file handling.

### Error Handling, Logging, and Operational Verification

The current runtime aligns with ASVS-style observability and safe-failure
expectations:

- auth, session, HTTP, mailbox, and send paths emit structured operator-visible
  events
- user-facing error messages stay bounded and avoid backend-detail leakage
- the repo carries a shared `make security-check` gate and targeted live-host
  proof scripts
- closeout and operator reruns use one authoritative wrapper path and one
  documented SOP

This does not replace human review or incident handling, but it does keep the
current OSMAP release posture grounded in repeatable evidence.

## OWASP Top 10 Crosswalk

For Version 1, the most relevant OWASP Top 10-style categories and current
OSMAP answers are:

- Broken access control:
  helper-mediated mailbox access, validated sessions, bounded mailbox/message
  operations, explicit revocation
- Cryptographic and credential handling:
  operator-managed TOTP secrets, no committed secrets, bounded auth flow, no
  password-on-command-line auth path
- Injection:
  no shell-based command execution in the Rust backend, narrow reviewed command
  boundaries, strict request parsing and validation
- Insecure design:
  explicit trust boundaries, frozen Version 1 scope, OpenBSD-first least
  privilege, documented non-goals
- Security misconfiguration:
  conservative defaults, production helper requirement, explicit state root and
  socket paths, documented OpenBSD confinement plan
- Identification and authentication failures:
  password-plus-TOTP login, session controls, login throttling
- Software and data integrity failures:
  signed releases and supply-chain expectations are already stated elsewhere in
  the repo, though this remains an SDLC discipline area rather than a runtime
  browser feature
- Security logging and monitoring failures:
  structured events, operator-visible auth/session/runtime logs, repeatable
  closeout validation
- SSRF and related server-side request abuse:
  the current browser runtime intentionally keeps browser-driven external fetch
  behavior out of scope

## What This Baseline Does Not Claim

This baseline does not claim:

- that OSMAP is fully ASVS compliant
- that the current Version 1 repo satisfies every OWASP control family
- that the current release is production-ready for every deployment posture
- that this baseline replaces targeted code review, live validation, or
  operator judgment

It does claim that the repo now has a concrete, reviewable OWASP-oriented
verification artifact to complement `CWE_TOP25_REVIEW_BASELINE.md` and the
existing SDLC/security-model documents.
