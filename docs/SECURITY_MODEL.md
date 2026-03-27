# Security Model

## Status

This is still a planning-phase security model, not a completed threat model.
It now includes Phase 1 observations from the current environment.

## Security Posture

OSMAP is intended for environments where browser-based mail access is necessary
but high-risk. Security is therefore a primary design driver, not a late-stage
hardening exercise.

## Primary Objectives

- Reduce attack surface relative to the current Roundcube-based path
- Limit privilege and blast radius of every new component
- Protect credentials, sessions, and message access
- Keep trust boundaries explicit and reviewable
- Preserve visibility for operations, detection, and recovery

## Current-State Observations

The current environment already demonstrates several security-positive patterns:

- VPN-first access for user-facing web and mail ports
- PF default deny posture
- explicit nginx control-plane allowlisting
- localhost and VPN-only bindings for sensitive services
- layered support services such as sshguard, Suricata, Rspamd, Redis, and
  ClamAV

These are strengths that the replacement should preserve or improve, not bypass.

## Trust Boundaries

Current and future work should treat these boundaries as first-class:

- public internet to the WAN edge
- WireGuard clients to VPN-only service surfaces
- browser to nginx
- nginx and runtime services to application code
- application code to IMAP, submission, and persistence layers
- operator SSH and `doas` access to the host

## Security Principles

- Least privilege by default
- Minimal exposed functionality
- Defense in depth
- Identity and session controls treated as core design elements
- Strong separation of public docs from secrets and private notes
- Observability sufficient for incident response and operator confidence

## Near-Term Security Questions

- Whether version 1 should remain VPN-restricted initially
- Which auth improvements are compatible with native clients
- What session and reauthentication model is appropriate for browser access
- Which controls must exist before broader internet exposure is acceptable

## Deferred Details

Full adversary modeling, abuse scenarios, and control selection belong in Phase
3, but the current project already has enough evidence to say that network
segmentation alone should not be the long-term security story.
