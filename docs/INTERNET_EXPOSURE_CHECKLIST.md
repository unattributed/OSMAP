# Internet Exposure Checklist

## Purpose

This checklist defines the minimum questions that should be answered before
OSMAP is treated as ready for direct public browser access over the internet.

It is not a launch authorization by itself. It is the control document used to
decide whether public exposure is justified for the current OSMAP snapshot.
For the standard operator review flow and the current assessed result on the
validated host, see `INTERNET_EXPOSURE_SOP.md` and
`INTERNET_EXPOSURE_STATUS.md`.
The current repo-owned host-side evidence collection entrypoint is
`maint/live/osmap-live-assess-internet-exposure.ksh`.

## Defense Readiness

Before direct public exposure:

- the Version 1 scope must already be stable
- the Phase 3 security model must be accepted
- the architecture must show explicit trust boundaries and least-privilege
  behavior
- the application must not include out-of-scope high-risk features added for
  convenience
- session controls and access control behavior must be validated

## Monitoring Validation

Before direct public exposure:

- authentication events must be logged meaningfully
- sensitive user actions must produce usable audit events
- operators must be able to distinguish normal failures from likely attack
  behavior
- alerting or review processes must exist for suspicious login and session
  activity
- submission abuse and anomalous account behavior must be visible enough to act
  on

## Abuse Controls

Before direct public exposure:

- login rate limiting or equivalent anti-automation protections must exist
- session abuse scenarios must have detection and response paths
- submission abuse controls must be coordinated with the existing mail stack
- incident-response expectations must be documented for likely account takeover
  cases

## TLS Configuration

Before direct public exposure:

- TLS-only access must be enforced
- certificate management must be reliable and reviewable
- insecure fallback behavior must be absent
- hostnames and certificate validation behavior must align with deployment
  reality
- the canonical HTTPS route change and rollback path must be defined concretely
  in `EDGE_CUTOVER_PLAN.md`

## Rate Limiting

Before direct public exposure:

- login paths must have defensible rate limiting or equivalent controls
- abuse of expensive endpoints must be considered
- brute-force and spray-style attacks must be operationally visible

## Incident Readiness

Before direct public exposure:

- operators must know how to contain a suspected account takeover
- session revocation and user-impacting response actions must be understood
- evidence preservation expectations must be clear
- rollback or temporary re-restriction to the VPN-only model must remain
  available
- the public HTTPS rollback path must restore Roundcube or the narrower staged
  posture without widening OSMAP authority

## Approval Sign-Off

Public exposure should require explicit operator approval after review of:

- the active security model
- current monitoring capability
- known residual risks
- rollback readiness
- whether the public OSMAP root is independently safe and correct even when
  control-plane or operator-only routes remain separately restricted

Control-plane allowlists for `/postfixadmin/`, `/pf/`, `/dr/`, and similar
operator routes are expected to remain narrower than the public OSMAP root.
That narrower control-plane posture should be recorded, but it should not by
itself block approval of the public OSMAP browser surface when the public root,
listener shape, PF `443` posture, rollback plan, and Version 2 readiness gate
are all already satisfied.

If those conditions are not met, the safer default is to keep the service on a
narrower staged posture until the public-exposure gate is actually satisfied.
