# Phase Roadmap

## Purpose

This roadmap keeps OSMAP phase-disciplined. It is intentionally concise and is
meant to prevent implementation from outrunning understanding.

## Phase 0

Objective:
Define project purpose, boundaries, assumptions, risks, and execution strategy.

Primary outputs:

- `PROJECT_CHARTER.md`
- `PROGRAM_BASELINE.md`
- `ACCEPTANCE_CRITERIA.md`

## Phase 1

Objective:
Produce an evidence-based understanding of the current mail platform and the
existing role of Roundcube.

Primary outputs:

- `CURRENT_SYSTEM_ARCHITECTURE.md`
- `MAIL_STACK_ANALYSIS.md`
- `NETWORK_AND_EXPOSURE_ANALYSIS.md`
- `ROUNDCUBE_DEPENDENCY_ANALYSIS.md`
- `RISK_REGISTER.md`

## Phase 2

Objective:
Define what version 1 must do and what it will intentionally omit.

Primary outputs:

- `PRODUCT_REQUIREMENTS_V1.md`
- `ACCEPTANCE_CRITERIA.md`
- `KNOWN_LIMITATIONS.md`

## Phase 3

Objective:
Define adversaries, trust boundaries, security objectives, and required
protections.

Primary outputs:

- `SECURITY_MODEL.md`
- `IDENTITY_AND_AUTHENTICATION.md`
- `INTERNET_EXPOSURE_CHECKLIST.md`

## Phase 4

Objective:
Design the replacement architecture with explicit component boundaries and
deployment constraints.

Primary outputs:

- `ARCHITECTURE.md`
- `DEPLOYMENT_OPENBSD.md`
- `OBSERVABILITY_AND_MONITORING.md`

## Phase 5

Objective:
Define how the project will be built, tested, reviewed, released, and supplied
safely.

Primary outputs:

- `SECURE_SDLC.md`
- `BUILD_AND_RELEASE_PROCESS.md`
- `SUPPLY_CHAIN_POLICY.md`
- `TEST_STRATEGY.md`

## Phase 6

Objective:
Translate the selected architecture into a controlled proof-of-concept plan and
workable implementation slices without outrunning the project's security and
OpenBSD constraints.

Primary outputs:

- `IMPLEMENTATION_PLAN.md`
- `PROOF_OF_CONCEPT_PLAN.md`
- `WORK_DECOMPOSITION.md`

## Later Phases

Later phases cover implementation, validation, pilot deployment, migration, and
Roundcube retirement. Those phases should not be treated as active until the
current phase outputs are genuinely reviewable.
