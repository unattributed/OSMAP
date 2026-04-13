# Secure SDLC

## Purpose

This document establishes the secure software development expectations for
OSMAP. The project is security-led, so SDLC discipline is not optional and
should begin before implementation.

## External Reference Posture

When the repository must choose between convenience and stronger current
practice, project judgment should prefer the most defensible guidance available
from:

- OpenBSD manual pages for confinement and privilege-boundary behavior,
  especially `pledge(2)` and `unveil(2)`
- Rust community guidance for reviewable APIs, linting, formatting, and
  dependency hygiene, especially the Rust API Guidelines and RustSec advisory
  ecosystem
- established application-security guidance for web behavior and verification,
  especially OWASP ASVS
- current GitHub code-scanning guidance when choosing between GitHub default
  CodeQL setup and repository-owned CI gates

Those sources should inform project decisions without replacing repository-local
verification, tests, or design review.

The current repo-grounded OWASP verification artifact for Version 1 is
`OWASP_ASVS_BASELINE.md`. It should be kept narrow, tied to the implemented
surface, and updated when the shipped browser/auth/session/mail boundary
changes materially.

## Development Principles

OSMAP development should prioritize:

- small, reviewable changes
- explicit design boundaries
- security over feature growth
- maintainability over novelty
- documentation that stays current with meaningful changes
- engineering choices compatible with OpenBSD operational culture
- the strongest defensible practice available from the relevant security, Rust,
  and OpenBSD communities when convenience and best practice conflict

## Code Quality Direction

The project should favor code that is:

- small enough to audit
- understandable to systems-oriented maintainers
- conservative in its use of dependencies
- amenable to privilege separation and runtime confinement
- realistic to package and maintain over time

Where practical, security-sensitive components should prefer memory-safe
implementation strategies and avoid unnecessary dynamic behavior.

## Coding Standards

The codebase should follow these standards:

- explicit interfaces over implicit behavior
- no casual use of unsafe language features where memory-safe alternatives exist
- parser, auth, and session code written for clarity before cleverness
- no hidden fallback behavior that silently weakens security
- concise comments where security intent or non-obvious behavior must be
  preserved for future maintainers

If Rust is used for any component:

- `unsafe` must be minimized and justified explicitly
- security-sensitive modules should avoid `unsafe` entirely unless there is a
  documented reason and review path

## Review Requirements

High-risk areas require heightened review, including:

- authentication and MFA logic
- session handling
- parser and renderer behavior for messages and attachments
- authorization boundaries
- process and filesystem boundary logic
- cryptographic operations

Meaningful changes in those areas should update `DECISION_LOG.md`.

Review expectations:

- every dependency addition must have an owner and a reason
- auth, session, crypto, and parser changes require explicit security-minded
  review
- documentation changes must accompany material design shifts
- all associated status, operator, and boundary documents must be kept aligned
  in the same change stream when shipped behavior changes materially

## Testing Requirements

The project should eventually include:

- functional tests for required user workflows
- integration tests for IMAP and submission compatibility
- security tests for auth, session handling, access control, and input handling
- regression tests for previously fixed defects
- practical verification of confinement and privilege assumptions where used
- checks that build artifacts and configuration outputs match documented
  expectations

## Static Analysis Expectations

The implementation should use static analysis appropriate to the chosen
language/toolchain.

Guidance:

- enable compiler warnings aggressively
- prefer toolchain-native linting and analysis first
- add focused security-oriented analysis for high-risk code paths where useful
- treat analysis findings in auth, session, parser, and privilege code as high
  priority
- keep a repo-owned security gate for the current Rust backend, including the
  shared `make security-check` workflow and the current CWE Top 25 review
  baseline
- keep repo-owned local hook backstops available so the same security gate can
  run before commit and before push when maintainers enable the shared hook path
- keep the current OWASP-oriented verification posture concrete through the
  Version 1-scoped `OWASP_ASVS_BASELINE.md` crosswalk rather than leaving OWASP
  and ASVS as ungrounded aspiration text
- keep GitHub default CodeQL setup or a consciously chosen advanced CodeQL
  replacement aligned with the repository's actual GitHub scanning posture

## Dependency Controls

The dependency graph should remain intentionally small.

Guidance:

- prefer mature, understandable libraries
- avoid abandoned or opaque projects
- avoid framework sprawl added for convenience
- minimize large transitive dependency chains
- avoid forcing Linux- or cloud-specific ecosystems into the build and runtime
  model unless the value is clear and defensible

Dependency additions should be review events, not casual convenience decisions.

## Vulnerability Management

The project should maintain a repeatable process for:

- identifying security-relevant dependencies
- tracking high-value upstream issues
- prioritizing fixes for auth, parser, and exposure-related defects
- documenting explicit risk acceptance when a fix must be deferred

## Change Management

Meaningful changes should be:

- scoped deliberately
- reviewed before release
- documented when they affect trust, exposure, dependencies, or operator
  expectations
- committed with signed commits so repository history remains attributable
  and reviewable
- reversible where practical

## Configuration Management

Configuration should be treated as controlled project state.

Expectations:

- defaults should be conservative
- changes to security-sensitive configuration must be reviewable
- secrets must remain separate from committed configuration
- deployment docs must reflect configuration assumptions that matter to security

## Secret Management Rules

- secrets must never be committed to the repo
- secret ownership should be clear
- runtime secrets should be readable only by the processes that need them
- release and deployment guidance should assume secret rotation is possible

## Release Governance

Before any release should be treated as credible:

- required documents must be current
- security-relevant changes must be reviewed
- supply-chain expectations must be satisfied
- known severe issues must be triaged explicitly
- rollback and deployment guidance must exist
- a test and review story appropriate to the change set must exist
- release artifacts should be signed
- the release should carry an SBOM or equivalent dependency inventory

## Documentation Requirements

Documentation is part of the SDLC.

At minimum, the project should maintain:

- a live decision log
- current architecture and security documents
- OpenBSD deployment guidance
- operator-facing notes for rollback, exposure, and incident handling

Change closeout should also leave one explicit next-best development step so
follow-on work is easier to prioritize and resume.

Phase progression docs should remain useful, not ceremonial. If a section becomes
stale or misleading, it should be corrected during the work that invalidated it.

## OpenBSD Credibility Goal

If the project eventually hopes to be taken seriously by OpenBSD-oriented
maintainers, it should behave like software that respects that ecosystem:

- no systemd assumptions
- no unnecessary root runtime model
- small dependency chains
- auditable build steps
- predictable behavior on OpenBSD
- packaging and operational choices that do not create avoidable maintainer pain

This does not guarantee future ports-tree acceptance, but it materially
improves the odds that the software would be considered credible.
