# Proof Of Concept Plan

## Purpose

This document defines what the Phase 6 prototype must prove and how that proof
should be evaluated.

The goal is not to ship a production product during Phase 6. The goal is to
validate feasibility with a narrow, controlled implementation.

## Required Prototype Scope

The proof of concept must cover the core behaviors named in the Phase 6 control
block:

- minimal login flow
- mailbox access
- message viewing
- message sending
- session tracking

If a prototype omits one of these areas, it is incomplete for Phase 6 even if
the omitted behavior seems easy to add later.

## Environment Assumptions

The prototype should run:

- in an isolated or controlled environment
- behind the existing trusted access posture rather than broad public exposure
- against the existing mail substrate or a faithful staging equivalent
- with test accounts and testable mailbox content

The prototype should not require risky production shortcuts just to appear more
"real."

## Prototype Constraints

The proof of concept should remain intentionally small:

- no plugin system
- no broad settings platform
- no mixed user and administrator interface
- no attempt to replace Dovecot or Postfix behavior
- no dependency growth without explicit value

The prototype is successful when it proves the narrow architecture, not when it
imitates every legacy feature.

## Validation Questions

Phase 6 should answer at least these questions:

- can browser authentication and MFA be integrated cleanly with the current
  stack assumptions
- can the app retrieve and present mailbox data without fragile coupling
- can safe message rendering be enforced in a realistic path
- can outbound sending use the existing submission model without inventing a new
  transport layer
- can session issuance, validation, and revocation be tracked in a way that
  fits later security requirements
- can the application remain small enough for meaningful review

## Test Scenarios

The prototype validation should include:

### Login Scenarios

- valid login with MFA
- invalid credential rejection
- MFA failure handling
- logout and session invalidation

### Mailbox Scenarios

- folder list retrieval
- message list retrieval
- message open and navigation
- attachment metadata and download path behavior

### Send Scenarios

- new message composition
- reply or forward flow
- authenticated submission handoff
- failure behavior when submission is unavailable

### Session Scenarios

- repeated authenticated requests with the same active session
- session expiry or forced invalidation behavior
- audit visibility for session-relevant events

## Performance Observations To Capture

Phase 6 is not a final performance phase, but it should still record:

- login responsiveness
- mailbox navigation responsiveness
- message open latency
- send-path responsiveness
- obviously dangerous memory or CPU patterns

The project needs enough performance evidence to detect bad architectural
choices early.

## Evidence To Record

The prototype should produce:

- integration notes
- a concise validation report
- a list of observed risks or friction points
- follow-up implementation priorities

These records should be stored in public-safe form so later phases can build on
them.

## Failure Conditions

Phase 6 should be treated as unsuccessful if:

- the prototype requires architecture-breaking exceptions
- the dependency graph becomes disproportionate to the feature scope
- the application cannot preserve compatibility with the existing mail stack
- the service shape resists practical isolation or confinement on OpenBSD
- the implementation path becomes too complex for a small operator team to
  maintain confidently

## Success Shape

Phase 6 is successful when the project can honestly say:

- the architecture is implementable
- the required core flows are viable
- the next phases can refine security, mail behavior, and deployment from a
  demonstrated base rather than from theory alone
