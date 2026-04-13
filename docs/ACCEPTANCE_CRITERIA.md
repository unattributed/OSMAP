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
  `_osmap` and the helper kept at the `vmail` boundary, including
  `/sessions`, `POST /sessions/revoke`, `POST /logout`, and stale-session
  rejection after logout
- the browser layer now includes a bounded backend-authoritative search path
  across one mailbox or all visible mailboxes plus a first one-message move
  path between existing mailboxes
- the browser auth path now includes a bounded dual-bucket application-layer
  login throttle backed by explicit runtime configuration and file-backed cache
  state
- the first one-message move path now also includes a bounded dual-bucket
  application-layer move throttle backed by explicit runtime configuration and
  file-backed cache state
- the browser layer now includes a conservative safe-HTML rendering path plus a
  first bounded settings page for HTML display preference and a settings-backed
  archive shortcut destination, which closes the previous top-level Version 1
  product gaps around HTML handling and end-user settings in first-release form
- the safe-HTML rendering and settings slice is now also live-proven on
  `mail.blackbagsecurity.com` under `enforce` against a controlled HTML-bearing
  mailbox message and a settings update through the browser route
- the first live browser mutation proof now also exists on
  `mail.blackbagsecurity.com` under `enforce`: a controlled one-message move
  and a bounded send flow both succeeded end to end through the browser routes
- the bounded browser send-throttle path is now also live-proven on
  `mail.blackbagsecurity.com` under `enforce`: one accepted `POST /send`
  followed by `429 Too Many Requests` and `Retry-After` on the second matching
  submission
- the bounded browser message-move throttle path is now also live-proven on
  `mail.blackbagsecurity.com` under `enforce`: one accepted
  `POST /message/move` followed by `429 Too Many Requests` and `Retry-After`
  on the second matching move
- the bounded all-mailboxes browser search flow is now also live-proven on
  `mail.blackbagsecurity.com` under `enforce`: the global search form rendered
  on `/mailboxes`, the all-mailboxes toggle rendered on `/mailbox?name=INBOX`,
  and one bounded `/search?q=...` request returned controlled hits from both
  `INBOX` and `Junk`
- the bounded inline-image metadata browser path is now also live-proven on
  `mail.blackbagsecurity.com` under `enforce`: a controlled multipart/related
  HTML message rendered through `/message` and surfaced both the `cid:`-aware
  inline-image notice and the attachment `Content-ID` metadata on the
  server-rendered page
- broader ergonomics for folder organization remain later refinements rather
  than blockers for the first move slice
- the current repo-grounded reassessment also confirms that the remaining
  closeout work is now mostly release-gate honesty and documentation
  discipline, with bounded-runtime correctness or availability fixes only if
  repo evidence still exposes a blocker
- the actual prototype now exists and Phase 6 execution is materially underway,
  but the implementation is still prototype-grade rather than production-ready

## Current Version 1 Release Gate

`docs/ACCEPTANCE_CRITERIA.md` is the authoritative Version 1 closeout gate.
Version 1 should not be declared complete until all of the following are true:

- the shipping boundary is frozen consistently across `README.md`,
  `PRODUCT_REQUIREMENTS_V1.md`, `KNOWN_LIMITATIONS.md`,
  `IMPLEMENTATION_PLAN.md`, `OPENBSD_RUNTIME_CONFINEMENT_BASELINE.md`, and the
  latest closeout entries in `DECISION_LOG.md`
- production `serve` requires `OSMAP_MAILBOX_HELPER_SOCKET_PATH`, and the
  helper/OpenBSD confinement plan is documented as the deliberate Version 1
  stopping point rather than as an unfinished direction
- the folder-organization and search workflows remain accepted as sufficient
  first-release baselines rather than being reopened as active blockers
- the bounded-concurrency HTTP runtime has no remaining repo-evidenced
  correctness or availability issue that outweighs closeout
- the following repo-owned proof set has passed for the current closeout
  snapshot on `mail.blackbagsecurity.com`:
- `./maint/live/osmap-host-validate.ksh make security-check`
- `ksh ./maint/live/osmap-live-validate-login-send.ksh`
- `ksh ./maint/live/osmap-live-validate-all-mailbox-search.ksh`
- `ksh ./maint/live/osmap-live-validate-archive-shortcut.ksh`
- `ksh ./maint/live/osmap-live-validate-session-surface.ksh`
- `ksh ./maint/live/osmap-live-validate-send-throttle.ksh`
- `ksh ./maint/live/osmap-live-validate-move-throttle.ksh`

The repo-owned wrapper
`ksh ./maint/live/osmap-live-validate-v1-closeout.ksh` now runs this exact
closeout proof set, and it still expects `OSMAP_VALIDATION_PASSWORD` when the
real login-plus-send step is included directly. The repo-owned host helper
`sh ./maint/live/osmap-run-v1-closeout-with-temporary-validation-password.sh`
now provides the standard guarded path for those host-side reruns, while the
SSH wrapper delegates to that same helper automatically when `login-send` is
part of the selected step set. The closeout wrapper also supports `--list`
plus `--report <path>` so operators can capture one small summary artifact for
the exact closeout steps they ran.
Operators who are not already on `mail.blackbagsecurity.com` should use
`./maint/live/osmap-run-v1-closeout-over-ssh.sh` to trigger that same
host-side closeout path and fetch the resulting report.

## Supplemental Browser Proof On April 12, 2026

The authoritative Version 1 release gate above passed on the current pushed
snapshot on April 12, 2026. A supplemental manual browser walkthrough on that
same date also succeeded against a temporary review instance launched from the
standard `~/OSMAP` checkout on `mail.blackbagsecurity.com`, exposed locally
through an SSH tunnel to `127.0.0.1:18080`.

That supplemental proof used the real mailbox user
`duncan@blackbagsecurity.com` with an operator-provisioned OSMAP TOTP secret.
The operator held the mailbox credentials in Proton Pass, enrolled the OSMAP
TOTP secret in Proton Authenticator, and generated the expected six-digit TOTP
codes there for browser login.

The successful manual walkthrough covered:

- real mailbox-password-plus-TOTP browser login
- mailbox listing on `/mailboxes`
- session visibility on `/sessions`
- real message viewing on `/message?...`
- browser compose/send with successful outbound delivery confirmed in Proton
  Mail
- safe HTML rendering on a real mailbox message

This supplemental walkthrough does not replace the frozen repo-owned closeout
gate. It exists to record that the current pushed snapshot has both the
authoritative scripted closeout proof and one successful real-user browser
review on the validated OpenBSD host.

On April 11, 2026, this full seven-step wrapper was rerun successfully on
`mail.blackbagsecurity.com`, including the real password-plus-TOTP
`login-send` step. On April 12, 2026, after the helper-driven gate regression
was fixed and pushed as commit `763e644`, the same full seven-step wrapper was
rerun successfully again from the standard `~/OSMAP` checkout on that current
pushed snapshot. That current-tip host rerun again used a controlled
one-session validation password override and restored the original mailbox
password hash afterward, so the repo still does not carry mailbox credentials.

The current repo snapshot already satisfies these closeout-gate preconditions:

- serve-side OpenBSD auth and sendmail dependency narrowing is implemented
- the repo-owned real password-plus-TOTP login-plus-send harness exists under
  `maint/live/osmap-live-validate-login-send.ksh`
- production `serve` already rejects configs without the local mailbox helper
  boundary
- live-host proof already covers login, mailbox read, attachment download,
  search, archive, session surface, send, send throttle, and move throttle

The current remaining closeout work is therefore administrative rather than
architectural:

- keep the authoritative gate and status docs aligned with the successful
  April 12, 2026 current-pushed-snapshot host rerun
- rerun the affected repo-owned proof scripts through the closeout wrapper only
  when closeout-facing behavior changes
- take additional implementation work only if a later failing proof or repo
  inconsistency reveals a narrower blocker

The following should not block Version 1 unless a narrower first-release need
is proven:

- broader OpenBSD ABI independence beyond the current conservative library
  fallbacks
- finished packaging or ports integration beyond the current repo-owned
  split-runtime scaffolding
- richer search behavior beyond ordinary daily-use needs
- broader folder ergonomics beyond the first practical baseline
- richer session or device intelligence
- broader settings surface
- deeper runtime redesign beyond the current bounded-concurrency model
