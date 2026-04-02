# Acceptance Criteria

## Phase 0 Acceptance Criteria

Phase 0 is acceptable when all of the following are true:

- The project purpose is explicitly documented
- Version 1 scope and non-goals are written down
- Environmental constraints and security principles are recorded
- A documented execution strategy exists for later phases
- Key risks and unknowns are identified rather than deferred implicitly
- The operator can approve progression to current-system analysis

## Phase 1 Acceptance Criteria

Phase 1 is acceptable when all of the following are true:

- The existing host layout and major services are documented from evidence
- The current mail stack components and their responsibilities are mapped
- Network exposure and access boundaries are documented
- Roundcube's current role, dependencies, and integration points are captured
- Trust boundaries and migration-sensitive dependencies are identified
- The analysis is detailed enough to support Product Definition and Security
  Model work without guessing

## Phase 2 Acceptance Criteria

Phase 2 is acceptable when all of the following are true:

- Version 1 capabilities are described concretely enough for design work to
  proceed
- Required user workflows are enumerated
- In-scope and out-of-scope features are explicit
- Compatibility requirements with the existing mail stack are stated
- Security, operational, and maintainability constraints are captured as
  product requirements, not just implementation wishes
- The operator can answer "what exactly does Version 1 include" without
  ambiguity

## Phase 3 Acceptance Criteria

Phase 3 is acceptable when all of the following are true:

- adversary assumptions are stated explicitly
- trust boundaries are documented clearly enough to constrain architecture work
- abuse scenarios are identified for account takeover, submission abuse, and
  content-driven attack paths
- identity and session expectations are written down as design requirements
- public exposure is treated as a controlled decision with prerequisites, not an
  assumption
- residual risks are acknowledged rather than hand-waved away

## Phase 4 Acceptance Criteria

Phase 4 is acceptable when all of the following are true:

- the component architecture is clear enough to guide implementation planning
- service boundaries are explicit
- data flows and integration paths with IMAP and submission are defined
- the OpenBSD deployment model is concrete enough for operators to understand
- observability expectations exist for the chosen architecture
- technology rationale is documented honestly, including portability and
  packaging risks

## Phase 5 Acceptance Criteria

Phase 5 is acceptable when all of the following are true:

- secure development expectations are documented as enforceable project rules
- dependency approval, SBOM, and signing requirements are stated
- testing expectations are defined in a way that matches the system's risk
  profile
- build and release expectations form a plausible path from source to deployable
  artifact
- change management, configuration management, and documentation standards are
  captured clearly enough to guide implementation work

## Phase 6 Acceptance Criteria

Phase 6 is acceptable when all of the following are true:

- the proof-of-concept scope is explicitly bounded
- implementation work is broken into small, reviewable packages
- the planned sequence proves login, mailbox, send, and session behavior before
  broad feature expansion
- OpenBSD runtime and confinement concerns are incorporated into the work plan
  rather than deferred indefinitely
- the project can begin implementation without ambiguity about what should be
  built first

## Current Status On April 2, 2026

Phase 0:

- Charter, constraints, success criteria, and planning baseline are documented
- A formal Phase 0 exit baseline now exists in public-safe form

Phase 1:

- Read-only inspection has confirmed the current host, active services,
  listening sockets, network policy shape, nginx control-plane model, Dovecot
  bindings, and Roundcube integration points
- The resulting current-state documents in `docs/` should now be treated as the
  baseline for Phase 1 review and refinement

Phase 2:

- Version 1 product scope, workflows, non-goals, and compatibility assumptions
  are now defined in `PRODUCT_REQUIREMENTS_V1.md`
- The remaining work for later phases is to validate those requirements against
  the security model and architecture rather than continue product-scope drift

Phase 3:

- the repository now contains a formal security-model baseline, an identity and
  authentication baseline, and an internet-exposure gate checklist
- later phases should treat these as constraints to design against rather than
  restarting threat-model debates from scratch

Phase 4:

- the repository now contains an architecture baseline, an OpenBSD deployment
  direction, and an observability baseline suitable for implementation planning
- the remaining uncertainty is mostly in detailed implementation choices rather
  than in the top-level system shape

Phase 5:

- the repository now contains an SDLC baseline, supply-chain policy, test
  strategy, and build/release process suitable for implementation governance
- implementation can now be evaluated against explicit engineering and release
  rules instead of ad hoc judgment

Phase 6:

- the repository now contains a concrete implementation plan, proof-of-concept
  scope, and work decomposition baseline
- WP0 toolchain selection and repository skeleton are now in place
- WP1 and WP2 now define the configuration/state boundary and the structured
  logging/error model for the prototype runtime
- WP3 now includes a real primary-backend verification path and a second-factor
  stage, plus a real TOTP backend and secret-store boundary
- WP4 now includes a real session-management baseline with bounded issuance,
  validation, revocation, and operator-visible session metadata
- WP5 now includes a real mailbox-listing primitive behind the validated-session
  gate using the existing Dovecot surface
- WP5 now includes a real message-list retrieval primitive behind the
  validated-session gate using the existing Dovecot surface
- WP6 now includes a real bounded message-view retrieval primitive behind the
  validated-session gate using the existing Dovecot surface
- WP6 now includes a plain-text-first rendering policy layer for fetched
  messages
- WP6 now includes a dependency-light MIME-aware classification layer and an
  attachment-metadata surface for common mail layouts
- WP6 now includes a dependency-light HTTP/browser slice with login, mailbox,
  message-list, message-view, logout, and health routes
- WP7 now includes a first compose/send browser slice with bounded input
  validation, local submission handoff, and submission audit events
- WP7 now includes server-side reply and forward draft generation with
  attachment-aware notices
- the browser slice now includes CSRF protection on current state-changing form
  routes
- nginx-facing deployment details and an implemented OpenBSD confinement mode
  now exist as implementation controls
- the browser slice now includes bounded attachment download behavior alongside
  reply/forward behavior and bounded attachment upload
- successful live authenticated read flows are now proven under `enforce`,
  including real password-plus-TOTP login, helper-backed mailbox reads, and
  attachment download
- the selected next least-privilege mailbox-read path is now a dedicated local
  helper boundary rather than broader authority for the web-facing runtime
- the current mailbox-helper slice now covers mailbox listing, message-list
  retrieval, message-view retrieval, and helper-backed attachment downloads;
  live-host validation through that helper now exists under `enforce`
- the browser layer now includes a first self-service session-management page
  backed by the existing persisted session metadata and revocation primitives
- the browser-visible session-management slice is now also proven on
  `mail.blackbagsecurity.com` under `enforce` with the web runtime kept as
  `_osmap` and the helper kept at the `vmail` boundary
- the browser layer now includes a first mailbox-scoped backend-authoritative
  search path plus a first one-message move path between existing mailboxes
- the browser auth path now includes a first bounded application-layer login
  throttling slice backed by explicit runtime configuration and file-backed
  cache state
- the implementation still does not satisfy all Version 1 product goals: safe
  HTML mail rendering and a bounded settings surface remain active product
  gaps, while broader ergonomics for folder organization remain later
  refinements rather than blockers for the first move slice
- the actual prototype now exists and Phase 6 execution is materially underway,
  but the implementation is still prototype-grade rather than production-ready
