# Identity And Authentication

## Status

This document defines the Phase 3 identity and authentication baseline for
Version 1. It does not yet define implementation details, but it establishes
the constraints that later architecture and identity-hardening phases must
follow.

## Authentication Methods

Version 1 browser access should use:

- mailbox credentials as the primary identity input
- MFA as a required second factor for the browser login path
- TLS-protected communication for all auth-related traffic

The initial MFA target is TOTP. The design should preserve a path to stronger,
more phishing-resistant methods later without blocking Version 1.

## MFA Strategy

Version 1 MFA policy:

- require TOTP for the browser product
- design enrollment and verification flows to be understandable for a small
  trusted user base
- avoid pretending that TOTP solves every phishing risk
- keep the design compatible with future improvement toward stronger factors

Version 1 should not promise:

- full phishing-resistant MFA from day one
- broad enterprise identity federation
- complicated self-service recovery chains

## Credential Handling

The identity model must assume:

- the browser app is one consumer of a broader mail identity surface
- mailbox credentials may also be used by native clients
- any auth change can affect IMAP and SMTP compatibility expectations

Credential-handling expectations:

- never treat network location as sufficient proof of trust
- avoid unnecessary credential persistence
- keep auth secrets out of public documentation and repository history
- minimize the number of components that need direct access to sensitive auth
  material

## Session Model

Version 1 browser sessions should be treated as a first-class security system.

The session model should provide:

- bounded session lifetime
- explicit logout
- session invalidation on relevant security events
- visibility into active or recent sessions
- ability to revoke sessions
- CSRF-aware and replay-aware design

High-risk actions should be evaluated for reauthentication or stronger session
checks later in design.

## Account Recovery

Account recovery is intentionally constrained in Version 1.

Guidance:

- avoid complex self-service recovery chains until identity design is mature
- prefer operator-controlled recovery processes over weak automated shortcuts
- do not add recovery features that silently undermine MFA or session security

This is one of the clearest places where feature restraint is a security
requirement, not a missing convenience.

## Abuse Protections

Identity-related abuse protections should eventually include:

- rate limiting and anti-automation measures on login flows
- visibility into repeated failures and suspicious session creation
- detection-oriented logging for likely credential attacks
- the ability to investigate unusual session proliferation
- coordination with submission-abuse monitoring when account compromise is
  suspected

## Compatibility With Native Clients

Native clients remain supported in Version 1, which creates an important
constraint: the project cannot design browser auth as if it were the only
identity consumer in the environment.

Implications:

- browser MFA requirements must be designed without accidentally breaking normal
  IMAP and submission usage patterns
- future auth hardening may require a differentiated strategy for browser access
  versus legacy protocol clients
- architecture work must map where stronger auth can be enforced cleanly and
  where app-password or other compatibility patterns might eventually be needed

## Risks

Key identity and authentication risks include:

- designing browser auth in isolation from the wider mail identity model
- overpromising recovery or federation features too early
- assuming TOTP alone is sufficient against phishing-assisted compromise
- introducing auth friction that operators or users route around unsafely
- making session visibility too weak to detect account takeover quickly
