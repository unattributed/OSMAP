# Documentation

This directory holds the public-safe documentation set for OSMAP.

The repository deliberately separates:

- Public, reviewable planning and architecture documents under `docs/`
- Private operator notes and working material under ignored paths such as
  `PKCB/` and `AGENTS.md`

As of March 27, 2026, the project has a documented Phase 0 and a started Phase
1 baseline built from:

- private PKCB planning notes
- repository phase control blocks
- read-only inspection of `mail.blackbagsecurity.com`

The documents in this folder are written for two audiences:

- sysadmins who need to understand the current mail stack and migration impact
- collaborating developers who need phase boundaries, constraints, and
  integration facts before implementation begins

Current primary documents:

- `PROJECT_CHARTER.md`
- `PROGRAM_BASELINE.md`
- `ACCEPTANCE_CRITERIA.md`
- `PHASE_ROADMAP.md`
- `CURRENT_SYSTEM_ARCHITECTURE.md`
- `MAIL_STACK_ANALYSIS.md`
- `NETWORK_AND_EXPOSURE_ANALYSIS.md`
- `ROUNDCUBE_DEPENDENCY_ANALYSIS.md`
- `RISK_REGISTER.md`
- `ARCHITECTURE.md`
- `SECURITY_MODEL.md`
- `DECISION_LOG.md`

Other files remain in place as placeholders so the intended documentation map is
visible without publishing private notes prematurely.
