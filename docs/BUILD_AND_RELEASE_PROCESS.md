# Build And Release Process

## Purpose

This document defines the expected build and release discipline for OSMAP. It is
written early so implementation does not drift into ad hoc release habits.

## Build Steps

The build process should:

- start from versioned source
- resolve only approved dependencies
- produce deterministic or at least repeatable artifacts where practical
- fail clearly when required tooling, tests, or generated assets are missing

The build should avoid hidden network-time side effects wherever possible.

## Artifact Generation

Release artifacts should eventually include:

- application binaries or packages as appropriate to the chosen implementation
- static frontend assets if the architecture requires them
- configuration templates or examples needed for deployment
- an SBOM or equivalent manifest
- release notes or operator-facing change information

## Signing Requirements

Release artifacts should be signed before being treated as trusted for
deployment.

Expectations:

- use a repeatable signing process
- make signature verification feasible for operators
- do not treat unsigned production artifacts as acceptable by default

## Versioning Scheme

The project should use a versioning approach that:

- is understandable to operators
- supports rollback and comparison
- distinguishes pre-release work from stable release candidates

The exact scheme can be finalized later, but it should remain conservative and
predictable.

## Deployment Flow

The release flow should eventually look like:

1. Source and dependency review
2. Shared security gate such as `make security-check`
3. Build
4. Static analysis and required tests
5. SBOM generation
6. Artifact signing
7. Staged deployment validation
8. Controlled production rollout

## Rollback Strategy

Every release process should assume rollback may be necessary.

Rollback expectations:

- previous known-good artifacts remain identifiable
- deployment steps are reversible where practical
- release notes describe any data or configuration considerations
- operators are not forced to improvise rollback during an incident

## OpenBSD-Friendly Release Posture

If the project aims for OpenBSD credibility, the build and release process
should remain:

- simple enough to understand
- hostile to unnecessary dependency growth
- compatible with packaging and redistribution expectations
- free of Linux-first release assumptions
