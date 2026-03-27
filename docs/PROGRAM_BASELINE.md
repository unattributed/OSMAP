# Program Baseline

## Phase

This document captures the Phase 0 planning baseline for OSMAP.

## Evidence Sources

This baseline was validated from:

- the private PKCB notes for the project
- the repository Phase 0 and Phase 1 control blocks
- the public repository README and current docs
- read-only inspection of `mail.blackbagsecurity.com` on March 27, 2026

Sensitive values observed during inspection were intentionally excluded from the
public documentation set.

## Validated Understanding

The current environment already operates a serious self-hosted mail platform on
OpenBSD. Roundcube is not an isolated app. It is one browser-facing component
inside a wider stack that includes Postfix, Dovecot, MariaDB, nginx, PHP-FPM,
Rspamd, Redis, ClamAV, PostfixAdmin, and SOGo.

The operator's stated intent is not to cosmetically reskin Roundcube. It is to
replace Roundcube with a smaller, security-first, maintainable application that
fits the existing mail architecture and can eventually support safer
internet-facing use.

## Boundary Of The Program

In scope:

- replacement of the Roundcube browser mail experience
- preservation of compatibility with the existing mail stack
- definition of trust boundaries, deployment assumptions, and migration paths
- production of documentation and engineering controls needed for safe
  implementation

Out of scope for the current program baseline:

- replacement of Postfix, Dovecot, MariaDB, nginx, or SOGo
- unrelated operating system redesign
- speculative feature expansion beyond version 1 mail access needs
- shipping implementation code before the current stack is understood

## Current Operating Assumptions

- The existing host remains the source of truth during analysis
- Native clients remain first-class and must not be broken by the replacement
- Current web control-plane applications are treated as higher-risk assets than
  protocol-native access paths
- The current exposure model relies heavily on WireGuard and PF segmentation
- Public docs must stay sanitized even when private notes are more detailed

## Initial Risk Assumptions

- Browser-facing mail access remains a high-value attack surface
- Identity, session, and recovery design will likely dominate security outcomes
- Migration risk is not limited to feature parity; it also includes subtle auth,
  TLS, storage, and operator workflow dependencies
- Small-team maintainability is a hard constraint, not a preference
- A replacement that becomes a second complex platform would fail the project
  goal even if it is more modern

## Execution Strategy

The project will proceed phase by phase:

1. Charter and planning baseline
2. Current system analysis
3. Product definition
4. Security model
5. Architecture
6. Secure SDLC
7. Implementation planning and build
8. Validation and deployment
9. Migration and Roundcube retirement

Each phase should leave behind reviewable artifacts before the project moves
forward.

`DECISION_LOG.md` is a required living artifact. Significant scope, boundary,
assumption, and execution decisions should be recorded during the phase work
that produces them, not deferred until afterward.

## Unknowns That Must Be Resolved After Phase 0

- Which current Roundcube workflows are essential versus merely convenient
- Which authentication controls can be tightened without breaking client access
- Whether the replacement should proxy existing protocols or implement a
  narrower application-specific model
- Which observability and incident-response hooks are mandatory for safe public
  exposure
- How much of the current administrative surface should remain colocated on the
  same host

## Phase 0 Exit Assessment

Phase 0 is complete enough to proceed because:

- the project purpose is stable
- the intended environment is clear
- the immediate next step is evidence-based current-system analysis
- there is operator approval to continue into Phase 1
