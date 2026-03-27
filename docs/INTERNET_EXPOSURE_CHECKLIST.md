# Internet Exposure Checklist

## Purpose

This checklist defines the minimum questions that should be answered before
OSMAP moves from a VPN-first posture toward broader internet exposure.

It is not a launch authorization by itself. It is a control document used to
decide whether exposure is justified.

## Defense Readiness

Before broader exposure:

- the Version 1 scope must already be stable
- the Phase 3 security model must be accepted
- the architecture must show explicit trust boundaries and least-privilege
  behavior
- the application must not include out-of-scope high-risk features added for
  convenience
- session controls and access control behavior must be validated

## Monitoring Validation

Before broader exposure:

- authentication events must be logged meaningfully
- sensitive user actions must produce usable audit events
- operators must be able to distinguish normal failures from likely attack
  behavior
- alerting or review processes must exist for suspicious login and session
  activity
- submission abuse and anomalous account behavior must be visible enough to act
  on

## Abuse Controls

Before broader exposure:

- login rate limiting or equivalent anti-automation protections must exist
- session abuse scenarios must have detection and response paths
- submission abuse controls must be coordinated with the existing mail stack
- incident-response expectations must be documented for likely account takeover
  cases

## TLS Configuration

Before broader exposure:

- TLS-only access must be enforced
- certificate management must be reliable and reviewable
- insecure fallback behavior must be absent
- hostnames and certificate validation behavior must align with deployment
  reality

## Rate Limiting

Before broader exposure:

- login paths must have defensible rate limiting or equivalent controls
- abuse of expensive endpoints must be considered
- brute-force and spray-style attacks must be operationally visible

## Incident Readiness

Before broader exposure:

- operators must know how to contain a suspected account takeover
- session revocation and user-impacting response actions must be understood
- evidence preservation expectations must be clear
- rollback or temporary re-restriction to the VPN-only model must remain
  available

## Approval Sign-Off

Public exposure should require explicit operator approval after review of:

- the active security model
- current monitoring capability
- known residual risks
- rollback readiness

If those conditions are not met, the safer default is to keep the service
within the existing VPN-first model.
