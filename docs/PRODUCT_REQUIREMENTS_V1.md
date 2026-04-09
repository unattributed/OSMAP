# Product Requirements V1

## Status

This document defines the target Version 1 product boundary for OSMAP based on:

- Phase 0 project charter and program baseline
- Phase 1 current-system analysis
- private PKCB planning notes distilled into public-safe requirements

It is a planning document only. It does not imply architecture lock or
implementation completion.

## Current Implementation Status

As of April 2, 2026, the repository already implements a substantial subset of
the Version 1 boundary:

- secure browser login with password plus TOTP
- bounded browser sessions with revocation and persisted session metadata
- mailbox browsing, message-list retrieval, message view, and attachment
  download
- compose, reply, forward, bounded attachment upload, and local submission
- server-rendered browser flows with CSRF protection and explicit HTTP
  hardening
- OpenBSD confinement controls plus a least-privilege mailbox-helper path for
  read operations

The current implementation also includes first bounded slices for:

- mailbox-scoped backend-authoritative search
- browser-visible session self-management
- one-message move between existing mailboxes
- safe HTML email rendering through a narrow allowlist sanitizer with
  plain-text fallback
- a bounded first-release user settings surface for HTML display preference

The current implementation should therefore be treated as:

- functionally beyond the original mailbox-read prototype baseline
- still incomplete against the full Version 1 product contract
- still carrying active security and hardening gaps around broader auth-abuse
  resistance, bounded-runtime posture, and live mutation-path proof

This document remains the target product contract, but implementation planning
and status reporting should now treat broader folder ergonomics, richer search
behavior, bounded-runtime hardening, and broader live mutation-path proof as
the clearest remaining gaps rather than continuing to describe HTML rendering,
first-release settings, or the first request-abuse slices as absent.

## Overview

Version 1 of OSMAP is a secure, browser-based mail access application for an
existing OpenBSD mail environment. It is intended to replace Roundcube's core
user-facing webmail role without replacing the underlying mail transport stack.

Version 1 must remain intentionally narrow. The product is successful if it
delivers the essential workflows needed to retire Roundcube while remaining
materially easier to reason about, audit, and operate.

## Product Goals

- Replace Roundcube for core browser-based mail use
- Preserve compatibility with the existing IMAP and SMTP submission model
- Provide strong authentication and safer session behavior
- Minimize attack surface and avoid legacy webmail sprawl
- Remain realistic for a small operator team to maintain
- Coexist with native clients such as Thunderbird instead of trying to replace
  them

## Target Users

Version 1 is intended for:

- a small, trusted user population
- self-hosters and small teams with elevated security expectations
- users who may use both browser and native mail clients
- operators who value auditability and predictable operations over feature depth

Version 1 is not intended for:

- mass consumer deployment
- feature-maximal collaboration suites
- multi-tenant public SaaS hosting

## Product Assumptions

- The existing OpenBSD mail stack remains in place
- Postfix, Dovecot, MariaDB, nginx, and adjacent services continue to exist
- Thunderbird and other native clients remain supported
- SOGo remains separate and out of scope for version 1
- Migration may initially preserve the current VPN-first exposure model

## User Workflows

Version 1 must support the following primary user workflows.

### Authentication And Session Entry

The user can:

- reach the web interface through the approved deployment path
- sign in with mailbox credentials
- complete multi-factor authentication, initially with TOTP
- establish a bounded authenticated session

### Mailbox Navigation

The user can:

- view mailbox and folder lists
- browse message lists
- open and read messages
- navigate between common mail folders

### Search And Retrieval

The user can:

- search for messages with enough capability to replace normal Roundcube usage
- retrieve message details and attachments safely

### Compose And Send

The user can:

- compose a new message
- reply and forward
- attach files
- send mail through the existing submission path

### Basic Mail Organization

The user can:

- move mail between folders
- use required folder operations
- access archive behavior if it remains a required migration workflow

### Session And Device Awareness

The user can:

- log out explicitly
- view active or recent sessions/devices if the chosen design supports it
- perform basic session self-management

### Basic User Settings

The user can:

- manage a limited set of user-facing settings necessary for normal use

Version 1 should avoid turning settings into a broad preference platform.

The current first-release settings slice now includes two such settings:

- HTML display preference between sanitized HTML and plain-text fallback
- one optional archive mailbox shortcut destination for the bounded
  folder-organization path

## Required Features

The first release must include:

- secure login
- TOTP-based multi-factor authentication
- mailbox browsing
- message reading
- message search
- compose, reply, and forward
- attachment upload and download
- folder operations required for ordinary use
- session management
- visibility into sensitive session activity or device activity
- audit logging of sensitive actions
- safe HTML email rendering
- a bounded first-release user settings surface
- compatibility with the existing IMAP and SMTP submission services

## Compatibility Requirements

Version 1 must:

- remain compatible with the existing mail stack rather than replacing it
- work with the current IMAP-based mailbox access model
- use the established SMTP submission path or a compatible equivalent
- avoid breaking Thunderbird and other native client workflows
- coexist with SOGo and other current control-plane applications during the
  migration period
- fit the OpenBSD-centered deployment and operations model

## Non-Functional Requirements

### Security Requirements

Version 1 must:

- treat security as a primary design constraint
- provide stronger session behavior than the legacy Roundcube path
- minimize public-facing functionality to the essential feature set
- avoid plugin ecosystems, custom scripting surfaces, and embedded third-party
  extensibility
- generate audit-relevant logs for sensitive actions and auth events
- be designed for hostile or semi-hostile environments, not implicitly trusted
  networks

### Performance Expectations

Version 1 should provide acceptable responsiveness for the intended small-user
deployment. The goal is not internet-scale throughput. The goal is predictable,
stable performance for normal mailbox use, search, compose, and attachment
handling.

### Availability Goals

Version 1 should support stable operation appropriate for a small production
mail environment. It must fail in operationally understandable ways and must
not degrade the underlying mail services when the web layer has problems.

### Operational Constraints

Version 1 must be:

- maintainable by a small operator team
- auditable in deployment and behavior
- compatible with reproducible build and release discipline in later phases
- supportable without hidden local-only magic
- designed with enough operational restraint that future OpenBSD-oriented
  packaging and maintenance would remain plausible

## Constraints

Version 1 is constrained to a mail-only web access product. It must not expand
into a second collaboration suite during the first release cycle.

Specific constraints:

- no plugin system in version 1
- no theming engine or broad customization framework in version 1
- no mixed user/admin mega-interface
- no dependence on opaque third-party hosted security services for core
  operation
- no promises of privacy properties that the architecture cannot actually prove
- no dependency or toolchain growth that turns routine OpenBSD maintenance into
  a packaging nightmare

## Explicit Exclusions

The following are out of scope for version 1 unless explicitly approved later:

- calendar and groupware features
- contact synchronization services
- mobile apps
- plugin ecosystems
- multi-tenant hosting
- public SaaS ambitions
- advanced identity federation
- automated large-scale provisioning integrations
- end-to-end encrypted or Proton-style zero-access workflows
- replacement of Postfix, Dovecot, nginx, MariaDB, or SOGo
- broad admin features inside the end-user mail interface
- complex self-service recovery chains without a mature identity design

## Migration Assumptions

- Roundcube should remain available until Version 1 covers the required user
  workflows
- Migration should initially optimize for low disruption rather than novelty
- Native client support must remain intact throughout rollout
- Existing account credentials and mail storage patterns remain authoritative
  unless a later phase explicitly changes them

## Acceptance Shape

Version 1 should be considered product-complete when:

- users can perform the required Roundcube replacement workflows in the browser
- the product remains within the defined mail-only scope
- strong authentication is enforced
- operational logging and session visibility are sufficient for a small-team
  environment
- the existing mail backend remains stable
- operators can describe exactly what Version 1 does and does not do without
  ambiguity

## Open Product Questions

These questions remain for later phases rather than blocking the PRD itself:

- how much settings/configuration surface is genuinely necessary
- whether archive and sieve workflows must be in the first launch or shortly
  after
- whether first release exposure remains VPN-restricted or moves toward public
  exposure
- how session and device visibility should be presented without adding excess
  complexity
