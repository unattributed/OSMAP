# Secure SDLC

## Purpose

This document establishes the secure software development expectations for
OSMAP. The project is security-led, so SDLC discipline is not optional and
should begin before implementation.

## Development Principles

OSMAP development should prioritize:

- small, reviewable changes
- explicit design boundaries
- security over feature growth
- maintainability over novelty
- documentation that stays current with meaningful changes
- engineering choices compatible with OpenBSD operational culture

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
