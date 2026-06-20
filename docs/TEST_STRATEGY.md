# Test Strategy

## Purpose

This document defines the testing posture OSMAP should follow once
implementation begins.

The goal is not maximal test theater. The goal is enough evidence to justify
confidence in a high-risk mail access service.

## Testing Objectives

Testing should show that:

- required user workflows work
- integration with the existing mail stack is preserved
- security-sensitive behaviors are not casually broken
- regressions are caught before release

## Functional Testing

Functional coverage should include:

- login and MFA flow
- mailbox browsing
- message read behavior
- search
- compose, reply, and forward
- attachment handling
- session visibility and logout

## Security Testing

Security testing should prioritize:

- authentication behavior
- session lifecycle and revocation
- authorization boundaries
- CSRF and replay-relevant flows
- HTML mail and attachment handling
- parser and rendering safety
- abuse-related event generation and logging

## Integration Testing

Integration coverage should include:

- IMAP interaction
- submission path compatibility
- edge-to-app routing assumptions
- state storage behavior
- logging and audit output that later operational docs depend on

## Performance Testing

Performance testing should focus on realistic operator concerns:

- normal mailbox usage responsiveness
- behavior under repeated login activity
- search and attachment-path responsiveness
- identifying obviously dangerous resource usage patterns

This is not an internet-scale benchmark exercise.

## Regression Testing

Regression testing should be maintained for:

- previously fixed security defects
- auth and session edge cases
- integration failures found during staging or rollout

## Compatibility Testing

Compatibility testing should confirm:

- the browser product does not break the existing mail substrate
- expected native-client coexistence assumptions remain valid
- deployment assumptions hold on OpenBSD

## Release Gate Use

Tests are part of release governance.

A release candidate should not be treated as credible if:

- required workflow coverage is missing
- critical auth or session paths are untested
- integration behavior changed without corresponding validation

For Version 3, `make security-check` remains the developer and CI-oriented
partial validation path. `make release-check` is the strict release path and
must fail on skipped Cargo, clippy, rustfmt, supply-chain, dependency
inventory, host-readiness, V2 carry-forward, sanitized evidence archive, or
credential and TOTP-backed WSTG coverage.

## V7 rendering regression close-out

V7 rendering regression close-out is a stabilization gate, not feature work. The gate exists because the message-view daily-driver path regressed for real-world multipart HTML mail after earlier testing discipline weakened.

The required gate is `maint/security/osmap-v7-rendering-regression-gate.sh`. It is invoked by `make v7-rendering-regression-check`, `make v7-check`, and `make security-check`.

This gate is intentionally not grep-only. It performs structural checks for durable coverage names and then executes targeted Rust tests for MIME selection, charset and RFC 2047 decoding, sanitized HTML rendering, hostile HTML containment, malformed MIME fail-closed behavior, and truthful message-view UI labels.

Cargo and rustc are required for this close-out gate. A host that cannot run the Rust tests is not a valid close-out environment for this incident.

