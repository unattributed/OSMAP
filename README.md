# OSMAP: OpenBSD Secure Mail Access Platform

OSMAP is a security-focused, server-rendered webmail platform for hardened
OpenBSD mail systems. It provides browser access to an existing mail stack
without replacing Postfix, Dovecot, Rspamd, nginx, PF, TLS, or native mail
clients.

The project favors a small trust boundary, least privilege, bounded behavior,
safe mail rendering, auditable operations, and reversible deployment over
feature breadth or Roundcube parity.

## Current V13 status

V13 is the current reviewed production and assurance closeout. It supersedes
earlier post-V9 status summaries as the description of the present project
state.

| Current record | V13 evidence |
|---|---|
| Status | WSTG assurance integrity, adversarial validation, and production deployment closeout completed |
| Final reviewed commit | `7009b15322c4e7795c797c1387b403e0f4935adb` |
| Live and staged binary SHA256 | `333a417bf435ae74bfc2b7a9eebedeca1ad541cb527e2555fed408e11e24d963` |
| Credentialed release run | `osmap-wstg-20260627-204207` against `https://mail.blackbagsecurity.com` |
| Credentialed result | `42 pass`, `0 fail`, `0 warning`, `0 skip`, and `4` justified not-applicable results |
| WSTG matrix | `97` scenarios: `64` automated and `33` not applicable, with no invalid or missing dispositions |
| Browser edge | `GET /`, `GET /login`, and `GET /healthz` passed; invalid Host was rejected with HTTP `421` |

V13 also records passing live checks for CSP, Host and request
desynchronization, reflected and stored XSS, cross-account authorization
isolation, attachment containment, Rspamd and ClamAV detection, dependency and
CycloneDX validation, and security-event logging with redaction.

The current project status summary is maintained in
`docs/CURRENT_PROJECT_STATUS.md`. Historical version documents remain valid as
provenance for the slices that produced them, but the current README,
`docs/CURRENT_PROJECT_STATUS.md`, `docs/README.md`, and the latest version
closeout records control the present release posture.

### Capability boundary

V12 remains a non-cryptographic OpenPGP foundation. It provides requirements,
diagnostics, account fingerprint binding, helper protocol and client
scaffolding, GPGME readiness gates, and capability policy models. It does not
enable decrypt, verify, sign, encrypt, PGP/MIME parsing, passphrase handling,
private-key access, browser OpenPGP controls, key discovery, or decrypted
rendering.

The current release evidence is still bounded. V4 remains the historical tagged
hostile-content safety release, and V9 remains historical selected-cohort
release-candidate provenance. The current V13 record does not claim complete
Roundcube replacement, general hostile-email safety, unbounded MIME or mailbox
safety, full ASVS verification, endpoint safety after attachment download, or
OpenPGP runtime cryptographic operation.

Start with:

- [Documentation index](docs/README.md)
- [Project charter](docs/PROJECT_CHARTER.md)
- [Program baseline](docs/PROGRAM_BASELINE.md)
- [Current project status](docs/CURRENT_PROJECT_STATUS.md)
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

Debian-family collaborators, including Parrot OS users, should begin with the
[development environment bootstrap](docs/DEBIAN_DEVELOPMENT_BOOTSTRAP.md):

```sh
bash maint/development/bootstrap-debian.sh
make verify-debian
```

Build and validation entry points:

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
make v10-check
make v11-check
make v12-check
make v13-check
make acceptance-check
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

Versions are listed newest first. Historical entries remain evidence provenance,
not competing descriptions of the current V13 state.

| Version | Purpose and status | Authoritative documents |
|---|---|---|
| V13 | WSTG assurance integrity, adversarial validation, and production deployment closeout | [V13 sprint and closeout](docs/V13_WSTG_ASSURANCE_INTEGRITY_AND_ADVERSARIAL_VALIDATION.md), [current project status](docs/CURRENT_PROJECT_STATUS.md) |
| V12 | Non-cryptographic OpenPGP secure foundation through Slice 14 closeout readiness | [OpenPGP requirements and claims](docs/V12_OPENPGP_REQUIREMENTS_AND_CLAIMS.md), [closeout readiness audit](docs/V12_OPENPGP_CLOSEOUT_READINESS_AUDIT.md), [known limitations](docs/KNOWN_LIMITATIONS.md) |
| V11 | Runtime fail-closed closure for refined high-relevance assumptions | [Runtime fail-closed closure](docs/V11_RUNTIME_FAIL_CLOSED_CLOSURE.md) |
| V10 | Governance, acceptance, and fail-closed assumption triage | [Governance status](docs/V10_GOVERNANCE_STATUS.md), [claims and limitations](docs/V10_CLAIMS_AND_LIMITATIONS.md), [targeted remediation](docs/V10_TARGETED_FAIL_CLOSED_REMEDIATION.md) |
| V9 | Historical production convergence and selected-cohort release-candidate decision | [Production convergence](docs/V9_PRODUCTION_CONVERGENCE.md), [release-candidate closeout](docs/V9_RELEASE_CANDIDATE_CLOSEOUT.md) |
| V8 | Source stabilization through mandatory regression matrices | [Program](docs/V8_STABILIZATION_PROGRAM.md), [final closeout](docs/V8_FINAL_REGRESSION_GATE_CLOSEOUT.md) |
| V7 | Boundary hardening, rendering recovery, and availability invariants | [Due diligence](docs/V7_BOUNDARY_HARDENING_DUE_DILIGENCE.md), [rendering closeout](docs/V7_RENDERING_REGRESSION_CLOSEOUT.md), [production availability closeout](docs/V7_PRODUCTION_AVAILABILITY_CLOSEOUT.md) |
| V6 | Controlled Roundcube retirement readiness | [Definition](docs/V6_DEFINITION.md), [acceptance criteria](docs/V6_ACCEPTANCE_CRITERIA.md), [closeout evidence](docs/V6_CLOSEOUT_EVIDENCE.md) |
| V5 | Identity, Host, origin, response, and trusted HTML boundaries | [Boundary evidence](docs/V5_BOUNDARY_HARDENING_EVIDENCE.md), [production deployment](docs/V5_PRODUCTION_DEPLOYMENT_COMPLETE.md) |
| V4 | Hostile-content safety release | [Definition](docs/V4_DEFINITION.md), [security gates](docs/V4_SECURITY_GATES.md), [closeout evidence](docs/V4_CLOSEOUT_EVIDENCE.md) |
| V3 | Daily-driver hardening and WSTG due diligence | [Definition](docs/V3_DEFINITION.md), [security gates](docs/V3_SECURITY_GATES.md), [WSTG plan](docs/V3_WSTG_DUE_DILIGENCE_PLAN.md) |
| V2 | Migration-capable pilot and operator readiness | [Definition](docs/V2_DEFINITION.md), [pilot closeout](docs/V2_PILOT_CLOSEOUT.md) |
| V1 | Narrow browser-mail baseline and closeout | [Acceptance criteria](docs/ACCEPTANCE_CRITERIA.md), [closeout SOP](docs/V1_CLOSEOUT_SOP.md) |

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
