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


## Version 3 Through Version 13 Closeout

Objective:
Preserve phase discipline while recording that the project has moved beyond the
original early planning phases into versioned hardening, deployment, assurance,
and OpenPGP foundation work.

Primary outputs:

- `V3_*` WSTG, workflow, and daily-driver assurance records
- `V4_*` hostile-content safety release records
- `V5_BOUNDARY_HARDENING_EVIDENCE.md`
- `V6_*` controlled Roundcube retirement readiness records
- `V7_*` rendering and availability closure records
- `V8_*` stabilization and regression matrix records
- `V9_PRODUCTION_CONVERGENCE.md`
- `V9_RELEASE_CANDIDATE_CLOSEOUT.md`
- `V10_*` governance, claims, documentation, and fail-closed assumption records
- `V11_RUNTIME_FAIL_CLOSED_CLOSURE.md`
- `V12_OPENPGP_*` non-cryptographic OpenPGP foundation records
- `V13_WSTG_ASSURANCE_INTEGRITY_AND_ADVERSARIAL_VALIDATION.md`
- `CURRENT_PROJECT_STATUS.md`

Current boundary:
V13 is the latest WSTG assurance and deployment closeout. V12 is an OpenPGP
foundation only and does not enable runtime cryptography. V9 remains a
selected-cohort release-candidate decision, not broad Roundcube parity or a
general hostile-mail safety claim.

## Future Phases

Future phases should be opened only when they have a bounded definition, tests,
security gates, evidence archives, rollback expectations, and documentation
updates in the same change stream.

Likely future work includes runtime OpenPGP cryptography, broader UX polish,
packaging or ports integration, additional selected-cohort expansion, and
further Roundcube retirement work. None of those are current claims until a
later version definition and evidence chain explicitly bring them into scope.
