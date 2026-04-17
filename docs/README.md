# Documentation

This directory holds the public-safe documentation set for OSMAP.

`docs/` is the source-of-truth location for project, architecture, security,
operational, and implementation documents unless a file needs to live
elsewhere for repository-platform reasons.

The repository deliberately separates:

- Public, reviewable planning and architecture documents under `docs/`
- Private operator notes and working material under ignored paths such as
  `PKCB/` and `AGENTS.md`

As of April 2, 2026, the project has substantive public-safe documentation
through active Phase 6 implementation. The current baseline was built from:

- private PKCB planning notes
- repository phase control blocks
- read-only inspection of `mail.blackbagsecurity.com`
- current in-repo Rust implementation and validation evidence

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
- `SETTINGS_SURFACE_BASELINE.md`
- `MIME_AND_ATTACHMENT_POLICY_BASELINE.md`
- `ATTACHMENT_DOWNLOAD_SLICE_BASELINE.md`
- `FOLDER_ORGANIZATION_SLICE_BASELINE.md`
- `HTTP_BROWSER_SLICE_BASELINE.md`
- `COMPOSE_AND_SEND_SLICE_BASELINE.md`
- `HTTP_HARDENING_BASELINE.md`
- `OPENBSD_RUNTIME_CONFINEMENT_BASELINE.md`
- `LEAST_PRIVILEGE_AUTH_SOCKET_MODEL.md`
- `TOTP_SECRET_MANAGEMENT_MODEL.md`
- `CWE_TOP25_REVIEW_BASELINE.md`
- `OWASP_ASVS_BASELINE.md`
- `V1_CLOSEOUT_SOP.md`
- `V1_CLOSEOUT_WORK_RULES.md`
- `V2_DEFINITION.md`
- `V2_ACCEPTANCE_CRITERIA.md`
- `V2_PILOT_REHEARSAL_SOP.md`
- `MAIL_HOST_BINARY_DEPLOYMENT_SOP.md`
- `MAIL_HOST_SERVICE_ENABLEMENT_SOP.md`
- `EDGE_CUTOVER_PLAN.md`
- `EDGE_CUTOVER_REHEARSAL_SOP.md`
- `INTERNET_EXPOSURE_CHECKLIST.md`
- `INTERNET_EXPOSURE_SOP.md`
- `INTERNET_EXPOSURE_STATUS.md`
- `PILOT_WORKFLOW_INVENTORY.md`
- `WORK_DECOMPOSITION.md`
- `DECISION_LOG.md`

The intent of these documents is operational usefulness, not ceremony. Phase 0
through Phase 6 documents should stay populated, current, and reviewable as the
project moves through implementation, mailbox-helper refinement, attachment
handling, safe HTML rendering, bounded user settings, OpenBSD hardening,
GitHub-side security gating, and the remaining hardening and workflow work
around broader abuse resistance, live mutation-path proof, and
folder-organization refinement beyond the now-implemented first
login, send, and message-move throttle slices. They should also stay current with behavior-preserving
internal refactors that reduce review hotspots in the Rust implementation,
especially around the HTTP and mailbox boundaries, including the ongoing
decomposition of `http.rs`, `mailbox.rs`, and `mailbox_helper.rs` into smaller
reviewable modules.

Some later-phase or deferred documents remain placeholders so the intended
documentation map is visible without publishing private notes prematurely.

Repository-level collaboration files such as `CODE_OF_CONDUCT.md`,
`CONTRIBUTING.md`, `SECURITY.md`, `SUPPORT.md`, and the `.github/` issue and
pull request templates are intentionally kept at the repository root rather than
inside `docs/` so GitHub can detect them as community-standard files.

In practice, the repository should follow this policy:

- keep project and technical documentation under `docs/`
- keep the repository root limited to the main `README.md`, build metadata,
  licensing, and GitHub/community-standard files
- keep workflow definitions and issue or pull-request templates under `.github/`
- add new narrative or design documents under `docs/` by default unless there
  is a clear platform-specific reason not to

For repeat live-host validation on `mail.blackbagsecurity.com`, the standard
host-side checkout is now `~/OSMAP`. The repo-owned wrapper
`maint/live/osmap-host-validate.ksh` should be used there for `make
security-check` and similar runs so Rust temp, cargo-home, and target paths
stay under the operator home directory instead of consuming `/tmp`.

For the short operator procedure around the authoritative Version 1 host
closeout rerun, including the repo-owned helper that now performs the
temporary validation-password override used by the real `login-send` step and
the expected report artifact, see `V1_CLOSEOUT_SOP.md`.
