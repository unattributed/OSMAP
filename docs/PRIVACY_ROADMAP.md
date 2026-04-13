# Privacy Roadmap

## Purpose

This document records the current privacy posture for OSMAP and the limited
privacy roadmap that follows from the implemented Version 1 design.

OSMAP is a mail-access application. It therefore handles sensitive user data,
but the project does not claim a zero-access or operator-blind privacy model.
The roadmap should stay honest about that boundary.

## Current Privacy Baseline

The current implementation and documentation already define several privacy
properties that should now be treated as baseline requirements:

- no hidden telemetry or third-party analytics
- no repository-stored runtime secrets
- no claim that the server cannot access user mail
- no external-resource loading in the current safe-HTML browser flow
- structured logs that carry security context without mirroring message bodies
  or secret values
- operator-managed configuration, TOTP secret storage, and closeout validation
  secrets outside the repository

Privacy in the present OSMAP model comes primarily from operator control,
minimal data sharing, least-privilege host design, and disciplined logging
rather than from cryptographic separation between the operator and user data.

## Sensitive Data Classes

The current system handles or mediates access to:

- mailbox credentials
- TOTP secrets and MFA-related state
- session identifiers and persisted session metadata
- user settings such as HTML display preference and archive shortcut mailbox
- message metadata, message bodies, and attachments
- audit and security event records

These classes do not all require the same retention or exposure policy. The
current roadmap should therefore avoid a generic "privacy" label and instead
treat credentials, session state, mail content, and audit records separately.

## Current Protective Posture

The current repo state supports the following privacy-preserving behavior:

- committed env examples remain non-secret
- the browser-facing runtime no longer treats direct mailbox-read authority as
  acceptable production posture
- the helper boundary keeps mailbox-read privilege out of the web-facing
  process
- the browser session cookie uses strict browser-side protections already
  documented in the HTTP hardening baseline
- the settings surface remains intentionally small rather than growing into a
  broad preference or telemetry platform
- the safe-HTML slice prefers sanitized rendering and preserves plain-text
  fallback rather than loading remote content

## Near-Term Roadmap

The next privacy work should stay practical and documentation-driven.

### 1. Retention Baseline

Define explicit retention expectations for:

- persisted session records
- audit logs
- throttle-cache state
- user settings state
- temporary validation artifacts produced by closeout reruns

Those expectations do not need to become a complex policy engine, but operators
should be able to answer what is kept, for how long, and why.

### 2. Backup And Secret-Handling Clarity

The deployment and migration materials should make it clearer:

- which OSMAP state must be backed up
- which data is reconstructible and should not be treated as authoritative
- how TOTP secrets and validation credentials are provisioned and rotated
- how rollback and host replacement avoid accidental secret sprawl

### 3. Pilot-Phase User Transparency

Before any real pilot, operators should prepare a short user-facing privacy
statement that accurately reflects the current design:

- OSMAP operators can access mail content through the server
- the service stores bounded session and settings state locally
- logs are security-focused and intentionally not content mirrors
- the pilot remains a security-focused replacement effort, not a privacy
  product with novel cryptographic guarantees

### 4. Post-Pilot Reassessment

If OSMAP moves beyond the current trusted-user pilot shape, revisit:

- whether audit retention remains proportionate
- whether session/device labeling needs more privacy review
- whether broader search and organization features change metadata exposure
- whether any new browser convenience feature introduces unnecessary data
  retention or third-party exposure

## Explicit Non-Goals

The privacy roadmap does not currently include:

- zero-access or end-to-end encrypted server-blind mail storage
- third-party tracking, analytics, or behavioral profiling
- public-cloud telemetry backends
- broad user-profile collection
- automatic import of legacy Roundcube preference or tracking data unless a
  later migration decision proves it necessary

## Current Decision Rule

Privacy work should continue to follow one simple rule: do not promise privacy
properties that the deployed architecture cannot actually prove.

That means the correct near-term path is smaller and clearer retention,
logging, and secret-handling policy around the existing OpenBSD-focused design,
not marketing language about privacy guarantees the system does not provide.
