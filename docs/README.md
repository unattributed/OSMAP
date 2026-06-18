# Documentation

This directory holds the public-safe documentation set for OSMAP.

`docs/` is the source-of-truth location for project, architecture, security,
operational, and implementation documents unless a file needs to live
elsewhere for repository-platform reasons.

The repository deliberately separates:

- Public, reviewable planning and architecture documents under `docs/`
- Private operator notes and early project notebooks outside the tracked public
  documentation set
- Agent-facing collaboration guidance in the tracked repository root file
  `AGENTS.md`

As of June 18, 2026, the project has substantive public-safe documentation
through the Version 5 production boundary-hardening deployment. The current
baseline was built from:

- private early project planning notes, distilled into public-safe docs
- repository phase control blocks
- read-only inspection of `mail.blackbagsecurity.com`
- current in-repo Rust implementation and validation evidence
- repo-owned Version 2 readiness, public-exposure, rollback, and pilot
  closeout records
- repo-owned Version 3 release carry-forward evidence
- repo-owned Version 4 hostile-content live proof, closeout evidence, and
  release handoff records
- repo-owned Version 5 boundary-hardening evidence and production deployment
  record

The documents in this folder are written for two audiences:

- sysadmins who need to understand the current mail stack and migration impact
- collaborating developers who need phase boundaries, constraints, and
  integration facts for maintenance, validation, and future scoped work

Current public documentation map:

- `PROJECT_CHARTER.md`
- `PROGRAM_BASELINE.md`
- `ACCEPTANCE_CRITERIA.md`
- `PHASE_ROADMAP.md`
- `GLOSSARY.md`
- `CURRENT_SYSTEM_ARCHITECTURE.md`
- `MAIL_STACK_ANALYSIS.md`
- `NETWORK_AND_EXPOSURE_ANALYSIS.md`
- `ROUNDCUBE_DEPENDENCY_ANALYSIS.md`
- `RISK_REGISTER.md`
- `KNOWN_LIMITATIONS.md`
- `FAQ_OPERATORS.md`
- `PRODUCT_REQUIREMENTS_V1.md`
- `ARCHITECTURE.md`
- `SECURITY_MODEL.md`
- `IDENTITY_AND_AUTHENTICATION.md`
- `SECURE_SDLC.md`
- `SUPPLY_CHAIN_POLICY.md`
- `TLS_STANDARD.md`
- `TEST_STRATEGY.md`
- `BUILD_AND_RELEASE_PROCESS.md`
- `IMPLEMENTATION_PLAN.md`
- `PROOF_OF_CONCEPT_PLAN.md`
- `TOOLCHAIN_AND_REPOSITORY_BASELINE.md`
- `CONFIGURATION_AND_STATE_MODEL.md`
- `DEPLOYMENT_OPENBSD.md`
- `HARDENING_GUIDE.md`
- `INCIDENT_RESPONSE_PLAN.md`
- `OBSERVABILITY_AND_MONITORING.md`
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
- `CWE_TOP25_AND_WSTG_REVIEW_2026_06_13.md`
- `OWASP_ASVS_BASELINE.md`
- `OSMAP_HELPER_SECURITY_REVIEW_2026_05_13.md`
- `PRIVACY_ROADMAP.md`
- `V1_CLOSEOUT_SOP.md`
- `V1_CLOSEOUT_WORK_RULES.md`
- `V2_DEFINITION.md`
- `V2_ACCEPTANCE_CRITERIA.md`
- `V2_PILOT_CLOSEOUT.md`
- `V2_PILOT_EXECUTION.md` (superseded; retained for provenance only)
- `V2_PILOT_STATUS.md`
- `V2_WSTG_REMEDIATION_2026_04_23.md`
- `V2_PILOT_REHEARSAL_SOP.md`
- `V3_DEFINITION.md`
- `V3_ACCEPTANCE_CRITERIA.md`
- `V3_ROADMAP.md`
- `V3_SECURITY_GATES.md`
- `V3_AUTHENTICATION_APPLICABILITY_EVIDENCE.md`
- `V3_AUTHORIZATION_ACCOUNT_ISOLATION.md`
- `V3_CLIENT_SIDE_BROWSER_SECURITY.md`
- `V3_CONFIG_DEPLOYMENT_EVIDENCE.md`
- `V3_CRYPTO_TRANSPORT_EVIDENCE.md`
- `V3_DRAFT_SAVE_RESUME_DESIGN.md`
- `V3_ERROR_INFO_DISCLOSURE_EVIDENCE.md`
- `V3_FORM_ROUTE_STATE_TRANSITIONS.md`
- `V3_HTTP_HOST_SMUGGLING_EVIDENCE.md`
- `V3_HTTP_INPUT_TAMPERING_EVIDENCE.md`
- `V3_IDENTITY_LIFECYCLE_EVIDENCE.md`
- `V3_INJECTION_APPLICABILITY_EVIDENCE.md`
- `V3_LIVE_MIME_HTML_PROOF_PLAN.md`
- `V3_REPLY_FORWARD_ATTACHMENT_HANDLING_DESIGN.md`
- `V3_SESSION_LIFECYCLE_EVIDENCE.md`
- `V3_WEBMAIL_INPUT_VALIDATION_EVIDENCE.md`
- `V3_WSTG_COVERAGE_GATE.md`
- `V3_WSTG_DUE_DILIGENCE_PLAN.md`
- `V4_DEFINITION.md`
- `V4_ACCEPTANCE_CRITERIA.md`
- `V4_ROADMAP.md`
- `V4_SECURITY_GATES.md`
- `V4_AUDIT_REMEDIATION_REPORT.md`
- `V4_CLOSEOUT_EVIDENCE.md`
- `V4_RELEASE_OPERATOR_HANDOFF.md`
- `V4_MIME_AMBIGUITY_EVIDENCE.md`
- `V4_HOSTILE_CONTENT_SAFETY_GOALS.md`
- `V4_HOSTILE_CONTENT_TEST_MATRIX.md`
- `V4_SECURITY_CLAIM_MATRIX.md`
- `V5_BOUNDARY_HARDENING_EVIDENCE.md`
- `V5_PRODUCTION_DEPLOYMENT_COMPLETE.md`
- `V6_DEFINITION.md`
- `V6_ACCEPTANCE_CRITERIA.md`
- `V6_ROADMAP.md`
- `V6_SECURITY_GATES.md`
- `V6_TRACES/`
- `REQUEST_WORKER_BUDGET_MODEL.md`
- `MAIL_HOST_BINARY_DEPLOYMENT_SOP.md`
- `MAIL_HOST_RUNTIME_GROUP_PROVISIONING_SOP.md`
- `MAIL_HOST_SERVICE_ARTIFACTS_SOP.md`
- `MAIL_HOST_SERVICE_ACTIVATION_SOP.md`
- `MAIL_HOST_SERVICE_ENABLEMENT_SOP.md`
- `EDGE_CUTOVER_PLAN.md`
- `EDGE_CUTOVER_REHEARSAL_SOP.md`
- `INTERNET_EXPOSURE_CHECKLIST.md`
- `INTERNET_EXPOSURE_SOP.md`
- `INTERNET_EXPOSURE_STATUS.md`
- `MIGRATION_PLAN_ROUNDCUBE.md`
- `PILOT_DEPLOYMENT_PLAN.md`
- `PILOT_WORKFLOW_INVENTORY.md`
- `WORK_DECOMPOSITION.md`
- `DECISION_LOG.md`

The intent of these documents is operational usefulness, not ceremony. Phase 0
through Version 5 documents should stay populated, current, and reviewable as
the project moves through maintenance, migration planning, broader hardening,
and future scoped work. The Version 4 documentation set records a bounded
hostile-content safety release, not broad production readiness, rich-mail
rendering, malware prevention, or Roundcube parity. Version 5 records deployed
identity, Host/origin, and response-boundary hardening without changing those
product-scope limits. Version 6 defines controlled Roundcube retirement
readiness for a selected cohort and remains incomplete until its sanitized
live-evidence and closeout gates pass. Requested additional functionality and
Thunderbird-like UX polish remain future-version work unless a later
definition explicitly brings them into scope.

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
