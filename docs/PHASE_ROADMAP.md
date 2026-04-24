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

## Version 1 And Version 2 Closeout

Objective:
Validate the bounded browser-mail implementation on the real OpenBSD host
shape, prove rollback and limited public browser exposure, and close the
initial real-user pilot without widening the product scope.

Primary outputs:

- `V1_CLOSEOUT_SOP.md`
- `V2_DEFINITION.md`
- `V2_ACCEPTANCE_CRITERIA.md`
- `V2_PILOT_CLOSEOUT.md`
- `V2_PILOT_STATUS.md`
- `PILOT_WORKFLOW_INVENTORY.md`
- `PILOT_DEPLOYMENT_PLAN.md`
- `MIGRATION_PLAN_ROUNDCUBE.md`
- `EDGE_CUTOVER_PLAN.md`
- `INTERNET_EXPOSURE_STATUS.md`

## Later Phases

Later phases cover Version 3 workflow refinement, broader migration rollout,
packaging or ports integration, deeper hardening, and eventual Roundcube
retirement. They should build on the closed Version 2 evidence instead of
reopening Version 2 as a feature-expansion phase.
