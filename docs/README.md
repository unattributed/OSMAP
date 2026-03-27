# Documentation

This directory holds the public-safe documentation set for OSMAP.

The repository deliberately separates:

- Public, reviewable planning and architecture documents under `docs/`
- Private operator notes and working material under ignored paths such as
  `PKCB/` and `AGENTS.md`

As of March 27, 2026, the project has substantive public-safe documentation
through Phase 6. The current baseline was built from:

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
- `PRODUCT_REQUIREMENTS_V1.md`
- `ARCHITECTURE.md`
- `SECURITY_MODEL.md`
- `SECURE_SDLC.md`
- `SUPPLY_CHAIN_POLICY.md`
- `TEST_STRATEGY.md`
- `BUILD_AND_RELEASE_PROCESS.md`
- `IMPLEMENTATION_PLAN.md`
- `PROOF_OF_CONCEPT_PLAN.md`
- `TOOLCHAIN_AND_REPOSITORY_BASELINE.md`
- `CONFIGURATION_AND_STATE_MODEL.md`
- `LOGGING_AND_ERROR_MODEL.md`
- `AUTHENTICATION_SLICE_BASELINE.md`
- `SESSION_MANAGEMENT_MODEL.md`
- `MAILBOX_LISTING_SLICE_BASELINE.md`
- `MAILBOX_READ_HELPER_MODEL.md`
- `MESSAGE_LIST_SLICE_BASELINE.md`
- `MESSAGE_VIEW_SLICE_BASELINE.md`
- `RENDERING_POLICY_BASELINE.md`
- `MIME_AND_ATTACHMENT_POLICY_BASELINE.md`
- `ATTACHMENT_DOWNLOAD_SLICE_BASELINE.md`
- `HTTP_BROWSER_SLICE_BASELINE.md`
- `COMPOSE_AND_SEND_SLICE_BASELINE.md`
- `HTTP_HARDENING_BASELINE.md`
- `OPENBSD_RUNTIME_CONFINEMENT_BASELINE.md`
- `LEAST_PRIVILEGE_AUTH_SOCKET_MODEL.md`
- `TOTP_SECRET_MANAGEMENT_MODEL.md`
- `WORK_DECOMPOSITION.md`
- `DECISION_LOG.md`

The intent of these documents is operational usefulness, not ceremony. Phase 0
through Phase 6 documents should stay populated, current, and reviewable as the
project moves through implementation, mailbox-helper refinement, attachment
handling, and OpenBSD hardening.

Some later-phase or deferred documents remain placeholders so the intended
documentation map is visible without publishing private notes prematurely.

Repository-level collaboration files such as `CODE_OF_CONDUCT.md`,
`CONTRIBUTING.md`, `SECURITY.md`, `SUPPORT.md`, and the `.github/` issue and
pull request templates are intentionally kept at the repository root rather than
inside `docs/` so GitHub can detect them as community-standard files.
