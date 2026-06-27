# OSMAP: OpenBSD Secure Mail Access Platform

OSMAP is a security-focused, server-rendered webmail platform for hardened
OpenBSD mail systems. It provides browser access to an existing mail stack
without replacing Postfix, Dovecot, Rspamd, nginx, PF, TLS, or native mail
clients.

The project favors a small trust boundary, least privilege, bounded behavior,
safe mail rendering, auditable operations, and reversible deployment over
feature breadth or Roundcube parity.

## Current posture

| Area | Status |
|---|---|
| Source | Current `main` is post-V9 documentation reconciliation; the V9 selected-cohort release-candidate decision is anchored at `a8915c0993b96a9d53de083dc84cb7520aef0097` |
| Formal tagged release evidence | `v4.0.0`, the hostile-content safety release |
| V5 | Boundary hardening deployed; later typed HTML source hardening is documented separately |
| V6 | Production readiness passed, and V9 Slice 6 accepted the selected-cohort/no-Roundcube closeout criteria for the bounded V9 release-candidate scope |
| V7 | Production availability reopening is closed for the tested selected-user path by V9 Slice 5 evidence |
| V8 | Regression matrices and CI enforcement are complete; V8 does not by itself claim a new production deployment |
| V9 | Release-candidate gate is PASS for selected-cohort operation under documented limitations; production runtime code remains `49c9f23` with documentation-only drift at the V9 gate |

The current release evidence is anchored by `v4.0.0`, with evidence bundle commit `59da020`
and assessed V4 code commit `09a95b7`. V4 does not claim rich-mail safety, malware prevention, attachment preview
safety, or URL reputation. The release rule is that any later code change must refresh V4 evidence
before inheriting the V4 claim.

V9 production convergence intake on 2026-06-22 recorded `main`, the production
checkout, and the live OpenBSD binary converged at `49c9f230d7865f01deadbc6a5a0f6e876c63e89b`. The deployed
binary hash is `411c976cccb0687f1a6e840470584fd8921eb5469e68905e457cf3edfe0cdea3`. The PR #19 deployment evidence archive
`osmap-forward-body-binary-deploy-20260622-133538Z.tar.gz` has SHA256 `21a2d3b97808fe6bc971974ef46a42d27216f31f04cefe7cf4894c1f667a7800` and replaced prior live
binary hash `500cdd839be9c70297d33cbce6661815ebfb4740ba8b607f63a6cdf98ac7dca7`. The post-deployment forward/send retest reached
OSMAP `/send` with HTTP `303` and Postfix/Brevo delivery queue `DDEA73CE8C4` was
sent and removed.

The final V9 gate on 2026-06-24 accepted `a8915c0993b96a9d53de083dc84cb7520aef0097`
as a selected-cohort release candidate. That acceptance depends on the
documented scope and limitations in
`docs/V9_RELEASE_CANDIDATE_CLOSEOUT.md`; it is not a claim of complete
Roundcube feature parity, general hostile email safety, unbounded mailbox
parsing safety, or release readiness outside the selected-cohort scope.

Start with:

- [Documentation index](docs/README.md)
- [Project charter](docs/PROJECT_CHARTER.md)
- [Program baseline](docs/PROGRAM_BASELINE.md)
- [Known limitations](docs/KNOWN_LIMITATIONS.md)
- [Decision log](docs/DECISION_LOG.md)
- [Internet exposure status](docs/INTERNET_EXPOSURE_STATUS.md)

## Project boundary

OSMAP is intended for self-hosted OpenBSD environments that need public
webmail access with a narrow and reviewable browser surface.

Core goals:

- strong password plus TOTP authentication
- bounded sessions with expiry and revocation
- CSRF and same-origin enforcement
- least-privilege mailbox access through a helper boundary
- safe MIME analysis, HTML sanitization, and forced attachment downloads
- bounded parsing, worker budgets, and throttling
- public HTTPS through nginx while application services remain private
- reproducible validation, evidence, rollback, and release governance

The project does not currently target calendars, groupware, plugins, SaaS,
multi-tenant hosting, broad JavaScript application behavior, attachment
preview, or replacement of the underlying mail stack.

Detailed scope:

- [Product requirements](docs/PRODUCT_REQUIREMENTS_V1.md)
- [Security model](docs/SECURITY_MODEL.md)
- [Architecture](docs/ARCHITECTURE.md)
- [Risk register](docs/RISK_REGISTER.md)
- [Roundcube dependency analysis](docs/ROUNDCUBE_DEPENDENCY_ANALYSIS.md)

## Developer entry points

```sh
cargo build
cargo test
make security-check
```

Important gates:

```sh
make v6-check
make v7-check
make v8-check
OSMAP_SECURITY_PROFILE=release make release-check
```

`make security-check` is the developer and CI gate. The strict release gate
requires current live, authenticated, supply-chain, WSTG, TLS, resource, and
sanitized evidence. See:

- [Contributing](CONTRIBUTING.md)
- [Test strategy](docs/TEST_STRATEGY.md)
- [Secure SDLC](docs/SECURE_SDLC.md)
- [Build and release process](docs/BUILD_AND_RELEASE_PROCESS.md)
- [Supply-chain policy](docs/SUPPLY_CHAIN_POLICY.md)
- [Toolchain baseline](docs/TOOLCHAIN_AND_REPOSITORY_BASELINE.md)

## Project element map

| Element | Primary documents |
|---|---|
| Existing host and mail stack | [Current architecture](docs/CURRENT_SYSTEM_ARCHITECTURE.md), [mail stack analysis](docs/MAIL_STACK_ANALYSIS.md), [network analysis](docs/NETWORK_AND_EXPOSURE_ANALYSIS.md) |
| Application architecture | [Architecture](docs/ARCHITECTURE.md), [configuration and state](docs/CONFIGURATION_AND_STATE_MODEL.md), [mailbox helper model](docs/MAILBOX_READ_HELPER_MODEL.md) |
| Identity and authentication | [Identity and authentication](docs/IDENTITY_AND_AUTHENTICATION.md), [TOTP secret model](docs/TOTP_SECRET_MANAGEMENT_MODEL.md), [auth socket model](docs/LEAST_PRIVILEGE_AUTH_SOCKET_MODEL.md) |
| Browser and HTTP security | [HTTP hardening](docs/HTTP_HARDENING_BASELINE.md), [browser slice](docs/HTTP_BROWSER_SLICE_BASELINE.md), [TLS standard](docs/TLS_STANDARD.md) |
| MIME, rendering, and attachments | [Rendering policy](docs/RENDERING_POLICY_BASELINE.md), [MIME policy](docs/MIME_AND_ATTACHMENT_POLICY_BASELINE.md), [attachment download](docs/ATTACHMENT_DOWNLOAD_SLICE_BASELINE.md) |
| Runtime and capacity | [OpenBSD confinement](docs/OPENBSD_RUNTIME_CONFINEMENT_BASELINE.md), [worker budgets](docs/REQUEST_WORKER_BUDGET_MODEL.md), [logging model](docs/LOGGING_AND_ERROR_MODEL.md) |
| Deployment and operations | [OpenBSD deployment](docs/DEPLOYMENT_OPENBSD.md), [hardening guide](docs/HARDENING_GUIDE.md), [observability](docs/OBSERVABILITY_AND_MONITORING.md), [incident response](docs/INCIDENT_RESPONSE_PLAN.md) |
| Public exposure | [Exposure checklist](docs/INTERNET_EXPOSURE_CHECKLIST.md), [exposure SOP](docs/INTERNET_EXPOSURE_SOP.md), [current exposure status](docs/INTERNET_EXPOSURE_STATUS.md) |
| Migration and retirement | [Roundcube migration](docs/MIGRATION_PLAN_ROUNDCUBE.md), [pilot deployment](docs/PILOT_DEPLOYMENT_PLAN.md), [pilot workflows](docs/PILOT_WORKFLOW_INVENTORY.md) |
| Security assurance | [ASVS baseline](docs/OWASP_ASVS_BASELINE.md), [CWE and WSTG review](docs/CWE_TOP25_AND_WSTG_REVIEW_2026_06_13.md), [WSTG due diligence](docs/V3_WSTG_DUE_DILIGENCE_PLAN.md) |

## Functional slices

The implementation is documented as small security and workflow slices:

| Slice | Document |
|---|---|
| Authentication | [Authentication slice baseline](docs/AUTHENTICATION_SLICE_BASELINE.md) |
| Session lifecycle | [Session management model](docs/SESSION_MANAGEMENT_MODEL.md) |
| Browser routing | [HTTP browser slice](docs/HTTP_BROWSER_SLICE_BASELINE.md) |
| Mailbox listing | [Mailbox listing slice](docs/MAILBOX_LISTING_SLICE_BASELINE.md) |
| Message listing | [Message list slice](docs/MESSAGE_LIST_SLICE_BASELINE.md) |
| Message viewing | [Message view slice](docs/MESSAGE_VIEW_SLICE_BASELINE.md) |
| Rendering | [Rendering policy](docs/RENDERING_POLICY_BASELINE.md) |
| Attachments | [Attachment download slice](docs/ATTACHMENT_DOWNLOAD_SLICE_BASELINE.md) |
| Compose and send | [Compose and send slice](docs/COMPOSE_AND_SEND_SLICE_BASELINE.md) |
| Folder organization | [Folder organization slice](docs/FOLDER_ORGANIZATION_SLICE_BASELINE.md) |
| User settings | [Settings surface slice](docs/SETTINGS_SURFACE_BASELINE.md) |

## Development versions

| Version | Purpose and status | Authoritative documents |
|---|---|---|
| V1 | Narrow browser-mail baseline and closeout | [Acceptance criteria](docs/ACCEPTANCE_CRITERIA.md), [closeout SOP](docs/V1_CLOSEOUT_SOP.md), [work rules](docs/V1_CLOSEOUT_WORK_RULES.md) |
| V2 | Migration-capable pilot and operator readiness | [Definition](docs/V2_DEFINITION.md), [acceptance criteria](docs/V2_ACCEPTANCE_CRITERIA.md), [pilot closeout](docs/V2_PILOT_CLOSEOUT.md), [pilot status](docs/V2_PILOT_STATUS.md) |
| V3 | Daily-driver hardening and WSTG due diligence | [Definition](docs/V3_DEFINITION.md), [roadmap](docs/V3_ROADMAP.md), [security gates](docs/V3_SECURITY_GATES.md), [WSTG plan](docs/V3_WSTG_DUE_DILIGENCE_PLAN.md) |
| V4 | Hostile-content safety release | [Definition](docs/V4_DEFINITION.md), [acceptance criteria](docs/V4_ACCEPTANCE_CRITERIA.md), [security gates](docs/V4_SECURITY_GATES.md), [closeout evidence](docs/V4_CLOSEOUT_EVIDENCE.md), [operator handoff](docs/V4_RELEASE_OPERATOR_HANDOFF.md) |
| V5 | Identity, Host, origin, response, and trusted HTML boundaries | [Boundary evidence](docs/V5_BOUNDARY_HARDENING_EVIDENCE.md), [production deployment](docs/V5_PRODUCTION_DEPLOYMENT_COMPLETE.md) |
| V6 | Controlled Roundcube retirement readiness | [Definition](docs/V6_DEFINITION.md), [acceptance criteria](docs/V6_ACCEPTANCE_CRITERIA.md), [roadmap](docs/V6_ROADMAP.md), [security gates](docs/V6_SECURITY_GATES.md), [closeout evidence](docs/V6_CLOSEOUT_EVIDENCE.md) |
| V7 | Boundary hardening, rendering recovery, and availability invariants | [Due diligence](docs/V7_BOUNDARY_HARDENING_DUE_DILIGENCE.md), [rendering closeout](docs/V7_RENDERING_REGRESSION_CLOSEOUT.md), [browser availability invariant](docs/V7_BROWSER_AVAILABILITY_INVARIANT.md), [throttle locking](docs/POST_V7_THROTTLE_TRANSACTION_LOCKING.md) |
| V8 | Source stabilization through mandatory regression matrices | [Program](docs/V8_STABILIZATION_PROGRAM.md), [final closeout](docs/V8_FINAL_REGRESSION_GATE_CLOSEOUT.md) |
| V9 | Production convergence and selected-cohort release-candidate decision | [Production convergence](docs/V9_PRODUCTION_CONVERGENCE.md), [release-candidate closeout](docs/V9_RELEASE_CANDIDATE_CLOSEOUT.md), [V7 production availability closeout](docs/V7_PRODUCTION_AVAILABILITY_CLOSEOUT.md) |
| V10 | Governance, acceptance, and fail-closed assumption triage | [Governance status](docs/V10_GOVERNANCE_STATUS.md), [claims and limitations](docs/V10_CLAIMS_AND_LIMITATIONS.md), [targeted remediation](docs/V10_TARGETED_FAIL_CLOSED_REMEDIATION.md) |
| V11 | Runtime fail-closed closure for refined high-relevance assumptions | [Runtime fail-closed closure](docs/V11_RUNTIME_FAIL_CLOSED_CLOSURE.md) |
| V12 | OpenPGP secure foundation and helper boundary | [OpenPGP requirements and claims](docs/V12_OPENPGP_REQUIREMENTS_AND_CLAIMS.md), [closeout readiness audit](docs/V12_OPENPGP_CLOSEOUT_READINESS_AUDIT.md) |
| V13 | WSTG assurance integrity and adversarial validation | [V13 sprint](docs/V13_WSTG_ASSURANCE_INTEGRITY_AND_ADVERSARIAL_VALIDATION.md) |


### V3 assurance workstreams

V3 divides WSTG and daily-driver assurance into focused records covering:

- [authentication applicability](docs/V3_AUTHENTICATION_APPLICABILITY_EVIDENCE.md)
- [identity lifecycle](docs/V3_IDENTITY_LIFECYCLE_EVIDENCE.md)
- [authorization and account isolation](docs/V3_AUTHORIZATION_ACCOUNT_ISOLATION.md)
- [session lifecycle](docs/V3_SESSION_LIFECYCLE_EVIDENCE.md)
- [webmail input validation](docs/V3_WEBMAIL_INPUT_VALIDATION_EVIDENCE.md)
- [HTTP input tampering](docs/V3_HTTP_INPUT_TAMPERING_EVIDENCE.md)
- [Host and request smuggling](docs/V3_HTTP_HOST_SMUGGLING_EVIDENCE.md)
- [cryptography and transport](docs/V3_CRYPTO_TRANSPORT_EVIDENCE.md)
- [form routes and state transitions](docs/V3_FORM_ROUTE_STATE_TRANSITIONS.md)
- [client-side browser security](docs/V3_CLIENT_SIDE_BROWSER_SECURITY.md)
- [error and information disclosure](docs/V3_ERROR_INFO_DISCLOSURE_EVIDENCE.md)
- [configuration and deployment](docs/V3_CONFIG_DEPLOYMENT_EVIDENCE.md)

### V6 implementation traces

V6 records each controlled-retirement slice separately:

| Slice | Trace |
|---|---|
| 00 | [Baseline](docs/V6_TRACES/SLICE_00_BASELINE.md) |
| 01 | [Scope](docs/V6_TRACES/SLICE_01_SCOPE.md) |
| 02 | [Gates](docs/V6_TRACES/SLICE_02_GATES.md) |
| 03 | [Production readiness](docs/V6_TRACES/SLICE_03_PRODUCTION_READINESS.md) |
| 04 | [Retirement rehearsal](docs/V6_TRACES/SLICE_04_RETIREMENT_REHEARSAL.md) |
| 05 | [Observability](docs/V6_TRACES/SLICE_05_OBSERVABILITY.md) |
| 06 | [Session locking](docs/V6_TRACES/SLICE_06_SESSION_LOCKING.md) |
| 07 | [Source attachment drafts](docs/V6_TRACES/SLICE_07_SOURCE_ATTACHMENT_DRAFTS.md) |
| 08 | [Resource resilience](docs/V6_TRACES/SLICE_08_RESOURCE_RESILIENCE.md) |
| 09 | [Closeout](docs/V6_TRACES/SLICE_09_CLOSEOUT.md) |

### V8 regression matrices

V8 protects existing behavior without adding product features:

- [Mail workflow matrix](docs/V8_MAIL_WORKFLOW_MATRIX.md)
- [Attachment safety matrix](docs/V8_ATTACHMENT_SAFETY_MATRIX.md)
- [Mailbox operation matrix](docs/V8_MAILBOX_OPERATION_MATRIX.md)
- [Session integrity matrix](docs/V8_SESSION_INTEGRITY_MATRIX.md)
- [Resource robustness matrix](docs/V8_RESOURCE_ROBUSTNESS_MATRIX.md)

All V8 gates run through `make v8-check`, which is enforced by
`make security-check` and the repository CI workflow.

## Operations

Production changes should follow the reviewed, reversible OpenBSD procedures:

- [Binary deployment SOP](docs/MAIL_HOST_BINARY_DEPLOYMENT_SOP.md)
- [Runtime group provisioning](docs/MAIL_HOST_RUNTIME_GROUP_PROVISIONING_SOP.md)
- [Service artifacts](docs/MAIL_HOST_SERVICE_ARTIFACTS_SOP.md)
- [Service activation](docs/MAIL_HOST_SERVICE_ACTIVATION_SOP.md)
- [Service enablement](docs/MAIL_HOST_SERVICE_ENABLEMENT_SOP.md)
- [Edge cutover plan](docs/EDGE_CUTOVER_PLAN.md)
- [Edge cutover rehearsal](docs/EDGE_CUTOVER_REHEARSAL_SOP.md)

## Security, support, and community

Report security issues through [SECURITY.md](SECURITY.md). General support
guidance is in [SUPPORT.md](SUPPORT.md).

Contributions must preserve the narrow trust boundary and include appropriate
tests, documentation, and evidence. See [CONTRIBUTING.md](CONTRIBUTING.md) and
[CODE_OF_CONDUCT.md](CODE_OF_CONDUCT.md).

OSMAP is licensed under the [ISC License](LICENSE).
It is provided without warranty. Operators remain responsible for deployment,
configuration, monitoring, backup, recovery, legal compliance, and risk
acceptance.

<!-- OSMAP:V9-SLICE5-V7-CLOSEOUT:START -->

## V7 production availability closeout

V9 Slice 5 closes the V7 production availability reopening based on current evidence.

**Verdict:** `V7_PRODUCTION_AVAILABILITY_CAN_BE_CLOSED`

Evidence basis:

- V9 Slice 5 evidence archive: `osmap-v9-slice-5-v7-production-closeout-20260624-131645Z.tar.gz`
- V9 Slice 5 archive SHA256: `2a2514ca62028bb1d444802b2f614014e7dae92e52864517caebdfadd39b7076`
- V9 Slice 3 hold-period archive SHA256: `18c3710a109d8d5152e11d2cebafacae4c8047be9587a5d5ef691d462bba6b0d`
- V9 Slice 4 hostile-content carry-forward archive SHA256: `0a67c1e254a7277003253d26fc5b3d5700072fe53c453a6dc890374ae53c2ac1`
- Current documented main head: `fcf360587daeda57f2de515ef8f85fc69d016f4e`
- Production runtime source head remains the PR #19 source point: `49c9f230d7865f01deadbc6a5a0f6e876c63e89b`
- Production runtime binary SHA256 remains: `411c976cccb0687f1a6e840470584fd8921eb5469e68905e457cf3edfe0cdea3`

What is proven:

- V7 rendering regression gate passed against current `origin/main`.
- V7 rendering gate wrapper passed against current `origin/main`.
- V7 boundary hardening gate passed against current `origin/main`.
- V9 Slice 3 proved real browser login, mailbox listing, message view, sanitized HTML rendering, send submission, and Postfix/Brevo delivery during a production hold window.
- The production snapshot showed `osmap_mailbox_helper(ok)` and `osmap_serve(ok)` with no crash, panic, or restart markers in the bounded scan.
- V9 Slice 4 proved the V4 hostile-content containment gate still passes against current `origin/main`.

Limits of the claim:

- This closes the V7 production availability reopening only for the tested selected-user production path and the current rendering policy.
- Slice 5 was not by itself a general release-candidate decision; Slice 7 later accepted the bounded V9 selected-cohort release candidate.
- This does not claim complete Roundcube replacement.
- Production was not rebuilt for Slice 2 documentation-only changes, and no rebuild is required for that documentation merge.
- V6 selected-cohort/no-Roundcube closure and the final V9 release-candidate gate are reconciled by `docs/V9_RELEASE_CANDIDATE_CLOSEOUT.md`.

<!-- OSMAP:V9-SLICE5-V7-CLOSEOUT:END -->

<!-- OSMAP:V9_STATUS:START -->

## Current V9 status

V9 release-candidate gate: PASS. Current main `a8915c0993b96a9d53de083dc84cb7520aef0097` is accepted as a selected-cohort release candidate under the documented limitations. The live production binary remains `411c976cccb0687f1a6e840470584fd8921eb5469e68905e457cf3edfe0cdea3` from production runtime source `49c9f230d7865f01deadbc6a5a0f6e876c63e89b`, with current main differing by documentation-only files.

See `docs/V9_RELEASE_CANDIDATE_CLOSEOUT.md`.

<!-- OSMAP:V9_STATUS:END -->
