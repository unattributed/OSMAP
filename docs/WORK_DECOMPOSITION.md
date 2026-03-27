# Work Decomposition

## Purpose

This document breaks the Phase 6 execution plan into concrete work packages that
sysadmins and collaborating developers can reason about.

The goal is to keep implementation small, reviewable, and dependency-aware.

## Delivery Model

Work should be delivered as narrow vertical slices whenever possible. Each slice
should leave the repository in a state that is easier to reason about than the
state before it.

Large unfocused branches are discouraged.

## Work Packages

### WP0: Toolchain And Repository Skeleton

Goal:
Establish the repository structure, build entrypoints, lint hooks, and local
development ergonomics needed for disciplined implementation.

Status on March 27, 2026:

- completed as the first implementation slice
- recorded in `TOOLCHAIN_AND_REPOSITORY_BASELINE.md`

Done means:

- the chosen implementation language and build tooling are recorded
- the repository has a clear source layout
- developers can build and run the service in a controlled local mode
- CI expectations are mapped to the Phase 5 governance baseline

### WP1: Configuration And State Model

Goal:
Define how the application reads configuration and stores local state without
mixing secrets, code, and mutable runtime data.

Status on March 27, 2026:

- completed with the first typed configuration parser and explicit state layout
- recorded in `CONFIGURATION_AND_STATE_MODEL.md`

Done means:

- configuration paths are explicit
- secret-bearing fields are separated from committed examples
- local state boundaries are documented
- the app can start with conservative defaults

### WP2: Logging And Error Model

Goal:
Establish a logging and error-handling model that supports security review and
operator troubleshooting.

Status on March 27, 2026:

- completed with a dependency-light structured logger and explicit bootstrap
  error types
- recorded in `LOGGING_AND_ERROR_MODEL.md`

Done means:

- auth and session events have a defined log shape
- operator-visible errors are bounded and non-leaky
- internal errors can be correlated during testing

### WP3: Authentication Flow

Goal:
Implement the browser login path against the approved backend assumptions.

Status on March 27, 2026:

- completed as the runtime authentication foundation
- bounded credential input, primary-auth decision handling, and audit-quality
  auth events are implemented
- a real `doveadm auth test` primary-backend path and a second-factor
  verification stage are implemented
- a real TOTP backend and secret-store model are implemented
- project-local QEMU validation wrappers now exist under `maint/qemu/`
- recorded in `AUTHENTICATION_SLICE_BASELINE.md`

Done means:

- credential handling exists
- MFA challenge flow exists
- auth success and failure are logged
- failure behavior matches the security model

### WP4: Session Management

Goal:
Implement session issuance, validation, invalidation, and visibility behavior.

Status on March 27, 2026:

- completed as the first runtime session-management baseline
- bounded opaque token issuance is implemented
- validation, revocation, and per-user session listing are implemented
- session events are emitted as structured audit-quality log lines
- recorded in `SESSION_MANAGEMENT_MODEL.md`

Done means:

- sessions are bounded
- logout works
- invalid sessions are rejected cleanly
- session-relevant events are auditable

### WP5: Mailbox Listing

Goal:
Demonstrate safe retrieval and presentation of mailbox and message-list data.

Done means:

- folder and message-list retrieval works
- per-user access assumptions are preserved
- application behavior remains compatible with the existing mail stack

### WP6: Message Viewing And Rendering

Goal:
Demonstrate message retrieval and conservative browser rendering.

Done means:

- message view works for normal mail
- HTML rendering follows the project safety posture
- attachment access behavior is defined

### WP7: Compose And Send

Goal:
Demonstrate outbound message composition and handoff through the existing
submission path.

Done means:

- compose and submit flow exists
- reply or forward behavior exists
- failure handling is understandable
- outbound actions are logged appropriately

### WP8: OpenBSD Runtime Integration

Goal:
Shape the prototype into something that can run cleanly on OpenBSD with minimal
privilege and clear filesystem boundaries.

Done means:

- runtime user assumptions are explicit
- config, code, and state paths are separated
- reverse-proxy and listener assumptions are documented
- `pledge(2)` and `unveil(2)` feasibility has been evaluated against the real
  code shape

### WP9: Integration Validation

Goal:
Verify the prototype against the real or faithfully staged mail environment.

Done means:

- login, mailbox, send, and session flows are exercised
- integration findings are recorded
- known incompatibilities are documented

### WP10: Performance And Risk Review

Goal:
Record the prototype's obvious resource and maintainability risks before later
phases expand it.

Done means:

- performance observations are written down
- risky implementation shortcuts are identified
- follow-up priorities are clear

## Dependency Order

The recommended dependency order is:

1. WP0
2. WP1 and WP2
3. WP3
4. WP4
5. WP5
6. WP6
7. WP7
8. WP8
9. WP9
10. WP10

This order keeps the security-critical path ahead of polish and keeps OpenBSD
runtime concerns close to the implementation rather than as a cleanup phase.

## Review Expectations Per Package

Each work package should:

- update relevant docs when assumptions change
- include tests or validation notes appropriate to its risk
- avoid silent dependency expansion
- leave a clear operator story for any new runtime behavior

High-risk packages such as authentication, session handling, and message
rendering should receive the strongest review discipline.
