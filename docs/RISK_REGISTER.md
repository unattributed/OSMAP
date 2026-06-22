# Risk Register

## Purpose

This is the current public-safe risk register for the OSMAP program.

## Scale

- Likelihood: Low, Medium, High
- Impact: Medium, High, Critical

## Current Risks

| ID | Risk | Likelihood | Impact | Current Response |
| --- | --- | --- | --- | --- |
| R-001 | Scope expands toward broad Roundcube parity and widens the trust boundary | Medium | High | Keep feature work inside explicit version definitions and non-goals |
| R-002 | Selected-cohort Roundcube retirement occurs before V6 no-fallback closeout | Medium | Critical | Keep Roundcube as a rollback unit until all V6 live reports pass |
| R-003 | Browser availability regresses during or after authentication | Medium | Critical | Keep V7 production approval reopened until real-login hold proof passes |
| R-004 | The multi-purpose mail host limits safe pressure testing and isolation | High | High | Use bounded validation, confinement, rollback artifacts, and adjacent controls |
| R-005 | Request or backend resource exhaustion exceeds current bounded worker controls | Medium | High | Preserve connection, route, helper, output, timeout, and throttle limits |
| R-006 | Secrets, private messages, or host-private evidence enter the public repository | Medium | Critical | Enforce publication guards, redaction, ignored evidence, and review |
| R-007 | TOTP enrollment, recovery, or factor lifecycle remains operator-dependent | Medium | High | Keep provisioning out of the browser and document rotation and recovery work |
| R-008 | Documentation or release evidence drifts from the deployed source and binary | High | High | Require assessed commits, binary hashes, dated reports, and doc governance |
| R-009 | Dependency, advisory, or Rust toolchain changes break reproducible validation | Medium | High | Pin release tools and run audit, deny, lockfile, and inventory gates |
| R-010 | Small-team operational capacity is exceeded by evidence and maintenance burden | High | High | Prefer narrow components, automated gates, and reviewable slices |

## Current Assessment

The dominant current risks are production availability, controlled retirement,
resource exhaustion, evidence drift, and small-team operational load. Security
work should continue as narrow implementation slices with executable tests and
explicit deployment evidence.
