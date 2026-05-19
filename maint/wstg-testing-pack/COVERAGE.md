# OSMAP WSTG, ASVS, And Top 10 Coverage

Generated from `wstg-asvs-mapping.json` and the WSTG due-diligence matrix.

## Standards

| Standard | Current repository use |
| --- | --- |
| OWASP WSTG v4.2 | Current implemented matrix and mapped runner tests. |
| OWASP WSTG latest | Required for V3 latest-track due diligence when pinned to an upstream commit. |
| OWASP ASVS 5.0.0 | Control mapping for implemented tests where applicable. |
| Project Top 10 crosswalk | Risk grouping for release-required WSTG tests and explicit gaps. |

## Current Matrix Summary

| Item | Count |
| --- | ---: |
| Implemented OSMAP WSTG tests | 27 |
| Explicit existing gaps | 3 |
| WSTG v4.2 scenario rows | 97 |
| WSTG v4.2 rows mapped by current pack | 28 |
| WSTG v4.2 rows not mapped by current pack | 69 |

## WSTG v4.2 Section Coverage

| Section | Total | Mapped | Gap |
| --- | ---: | ---: | ---: |
| 4.1 Information Gathering | 10 | 3 | 7 |
| 4.10 Business Logic Testing | 9 | 3 | 6 |
| 4.11 Client-side Testing | 13 | 3 | 10 |
| 4.12 API Testing | 1 | 0 | 1 |
| 4.2 Configuration and Deployment Management Testing | 11 | 5 | 6 |
| 4.3 Identity Management Testing | 5 | 1 | 4 |
| 4.4 Authentication Testing | 10 | 4 | 6 |
| 4.5 Authorization Testing | 4 | 2 | 2 |
| 4.6 Session Management Testing | 9 | 4 | 5 |
| 4.7 Input Validation Testing | 19 | 2 | 17 |
| 4.8 Testing for Error Handling | 2 | 1 | 1 |
| 4.9 Testing for Weak Cryptography | 4 | 0 | 4 |

## V3 Due-Diligence Gap Slices

| Area | WSTG section | Priority | Main remaining gap | V3 disposition |
| --- | --- | --- | --- | --- |
| Information Gathering | 4.1 | high | application discovery, entry points, execution paths, framework and architecture mapping | Required before V3 close, or not applicable with evidence where the surface does not exist. |
| Configuration and Deployment Management | 4.2 | high | file handling, old files, file permissions, subdomain takeover, cloud storage disposition, path confusion, broader headers | Required before V3 close, or not applicable with evidence where the surface does not exist. |
| Identity Management | 4.3 | high | role definitions, provisioning, registration disposition, username policy | Required before V3 close, or not applicable with evidence where the surface does not exist. |
| Authentication | 4.4 | critical | default credential disposition, auth bypass, remember-password disposition, weak methods, password reset or change, MFA depth | Required before V3 close, or not applicable with evidence where the surface does not exist. |
| Authorization | 4.5 | critical | authorization bypass, privilege escalation, cross-user object access, OAuth disposition | Required before V3 close, or not applicable with evidence where the surface does not exist. |
| Session Management | 4.6 | critical | session schema, exposed session variables, timeout, session puzzling, hijacking, JWT disposition, concurrent sessions | Required before V3 close, or not applicable with evidence where the surface does not exist. |
| Input Validation | 4.7 | critical | HTTP verb tampering, parameter pollution, SQL and NoSQL disposition, IMAP/SMTP injection, command injection, request smuggling, Host header, SSTI, SSRF, mass assignment, CSV injection | Required before V3 close, or not applicable with evidence where the surface does not exist. |
| Error Handling | 4.8 | high | stack traces, raw panic output, backend output disclosure, filesystem and secret disclosure | Required before V3 close, or not applicable with evidence where the surface does not exist. |
| Weak Cryptography | 4.9 | critical | weak TLS protocol and cipher rejection, HTTPS-only sensitive routes, plaintext cookie rejection, primitive review | Required before V3 close, or not applicable with evidence where the surface does not exist. |
| Business Logic | 4.10 | high | forged workflows, replay, duplicate submit, use limits, misuse defenses, payment not-applicable proof | Required before V3 close, or not applicable with evidence where the surface does not exist. |
| Client-side Testing | 4.11 | high | DOM XSS, HTML/CSS injection, redirect, browser storage, CORS, clickjacking, reverse tabnabbing, WebSocket and web messaging disposition | Required before V3 close, or not applicable with evidence where the surface does not exist. |
| API Testing | 4.12 | high | endpoint inventory, BOLA, BFLA, excessive data exposure, method and content-type tampering, GraphQL disposition | Required before V3 close, or not applicable with evidence where the surface does not exist. |

## Top 10 Crosswalk

| Category | Name | Release-required tests | Explicit gaps |
| --- | --- | --- | --- |
| `A01:2025` | Broken Access Control | `OSMAP-WSTG-SESS-003`, `OSMAP-WSTG-SESS-004`, `OSMAP-WSTG-INPV-001`, `OSMAP-WSTG-CLNT-001`, `OSMAP-WSTG-CONF-005`, `OSMAP-WSTG-BUSL-002`, `OSMAP-WSTG-BUSL-003`, `OSMAP-WSTG-BUSL-004` | `OSMAP-WSTG-GAP-001` |
| `A02:2025` | Security Misconfiguration | `OSMAP-WSTG-CONF-001`, `OSMAP-WSTG-CONF-002`, `OSMAP-WSTG-CONF-003`, `OSMAP-WSTG-SESS-005`, `OSMAP-WSTG-CONF-004`, `OSMAP-WSTG-INFO-001`, `OSMAP-WSTG-INFO-002`, `OSMAP-WSTG-CLNT-001`, `OSMAP-WSTG-CONF-005`, `OSMAP-WSTG-CONF-006` | none |
| `A03:2025` | Software Supply Chain Failures | `OSMAP-WSTG-CONF-007` | none |
| `A04:2025` | Cryptographic Failures | `OSMAP-WSTG-CONF-001`, `OSMAP-WSTG-CONF-002`, `OSMAP-WSTG-ATHN-001`, `OSMAP-WSTG-SESS-001` | none |
| `A05:2025` | Injection | `OSMAP-WSTG-CONF-003`, `OSMAP-WSTG-INPV-001`, `OSMAP-WSTG-INPV-002`, `OSMAP-WSTG-CLNT-002` | none |
| `A06:2025` | Insecure Design | `OSMAP-WSTG-CLNT-002`, `OSMAP-WSTG-BUSL-001`, `OSMAP-WSTG-BUSL-002`, `OSMAP-WSTG-BUSL-003`, `OSMAP-WSTG-BUSL-004` | `OSMAP-WSTG-GAP-001`, `OSMAP-WSTG-GAP-002` |
| `A07:2025` | Authentication Failures | `OSMAP-WSTG-ATHN-001`, `OSMAP-WSTG-ATHN-002`, `OSMAP-WSTG-ATHN-003`, `OSMAP-WSTG-ATHN-004`, `OSMAP-WSTG-SESS-001`, `OSMAP-WSTG-SESS-002`, `OSMAP-WSTG-SESS-003`, `OSMAP-WSTG-SESS-005`, `OSMAP-WSTG-BUSL-002`, `OSMAP-WSTG-BUSL-003` | none |
| `A08:2025` | Software or Data Integrity Failures | `OSMAP-WSTG-SESS-004`, `OSMAP-WSTG-BUSL-001`, `OSMAP-WSTG-CONF-007`, `OSMAP-WSTG-BUSL-002`, `OSMAP-WSTG-BUSL-003`, `OSMAP-WSTG-BUSL-004` | `OSMAP-WSTG-GAP-001`, `OSMAP-WSTG-GAP-002` |
| `A09:2025` | Security Logging and Alerting Failures | `OSMAP-WSTG-BUSL-002`, `OSMAP-WSTG-BUSL-003`, `OSMAP-WSTG-LOGG-001` | none |
| `A10:2025` | Mishandling of Exceptional Conditions | `OSMAP-WSTG-ATHN-003`, `OSMAP-WSTG-CONF-004`, `OSMAP-WSTG-INFO-002`, `OSMAP-WSTG-INPV-001`, `OSMAP-WSTG-BUSL-002`, `OSMAP-WSTG-BUSL-003`, `OSMAP-WSTG-BUSL-004` | none |

## Mapped Tests

| Test ID | Test | WSTG | ASVS | Type | Release required | Auth required | TOTP required | Severity |
| --- | --- | --- | --- | --- | --- | --- | --- | --- |
| `OSMAP-WSTG-CONF-001` | WSTG-v42-CONF-01 Test Network Infrastructure Configuration - TLS and HTTP exposure | `WSTG-v42-CONF-01` | `v5.0.0-9.1.1`, `v5.0.0-9.1.2` | unauthenticated, dynamic test | true | false | false | high |
| `OSMAP-WSTG-CONF-002` | WSTG-v42-CONF-07 Test HTTP Strict Transport Security - browser header baseline | `WSTG-v42-CONF-07`, `WSTG-v42-CLNT-09` | `v5.0.0-3.4.5`, `v5.0.0-3.4.6`, `v5.0.0-14.4.3`, `v5.0.0-14.4.4` | unauthenticated, dynamic test | true | false | false | medium |
| `OSMAP-WSTG-CONF-003` | WSTG-v42-CONF-12 Testing for Content Security Policy - OSMAP CSP regression | `WSTG-v42-CONF-12` | `v5.0.0-3.4.6`, `v5.0.0-14.4.3` | unauthenticated, dynamic test | true | false | false | high |
| `OSMAP-WSTG-ATHN-001` | WSTG-v42-ATHN-01 Testing for Credentials Transported over an Encrypted Channel - login form | `WSTG-v42-ATHN-01`, `WSTG-v42-ATHN-10` | `v5.0.0-6.2.6`, `v5.0.0-6.2.7`, `v5.0.0-6.3.3` | unauthenticated, dynamic test | true | false | false | medium |
| `OSMAP-WSTG-ATHN-002` | WSTG-v42-IDNT-04 Testing for Account Enumeration and Guessable User Account - login failure normalization | `WSTG-v42-IDNT-04`, `WSTG-v42-ATHN-03` | `v5.0.0-6.3.1`, `v5.0.0-6.3.8` | unauthenticated, dynamic test | true | false | false | high |
| `OSMAP-WSTG-ATHN-003` | WSTG-v42-ATHN-03 Testing for Weak Lock Out Mechanism - bounded login throttle probe | `WSTG-v42-ATHN-03` | `v5.0.0-6.1.1`, `v5.0.0-6.3.1` | unauthenticated, dynamic test | true | false | false | medium |
| `OSMAP-WSTG-ATHN-004` | WSTG-v42-ATHN-10 Testing for Weaker Authentication in Alternative Channel - TOTP login flow | `WSTG-v42-ATHN-10` | `v5.0.0-6.3.3`, `v5.0.0-6.5.5`, `v5.0.0-6.5.8` | authenticated, dynamic test | true | true | true | high |
| `OSMAP-WSTG-SESS-001` | WSTG-v42-SESS-02 Testing for Cookies Attributes - OSMAP session cookie | `WSTG-v42-SESS-02` | `v5.0.0-3.2.1`, `v5.0.0-3.2.2`, `v5.0.0-7.2.1` | authenticated, dynamic test | true | true | true | high |
| `OSMAP-WSTG-SESS-002` | WSTG-v42-SESS-03 Testing for Session Fixation - pre-login cookie replacement | `WSTG-v42-SESS-03` | `v5.0.0-7.2.3`, `v5.0.0-7.2.4` | authenticated, dynamic test | true | true | true | high |
| `OSMAP-WSTG-SESS-003` | WSTG-v42-SESS-05 Testing for Cross Site Request Forgery - logout enforcement | `WSTG-v42-SESS-05` | `v5.0.0-3.5.1`, `v5.0.0-3.5.3`, `v5.0.0-7.4.1` | authenticated, dynamic test | true | true | true | high |
| `OSMAP-WSTG-SESS-004` | WSTG-v42-SESS-05 Testing for Cross Site Request Forgery - authenticated mutations | `WSTG-v42-SESS-05` | `v5.0.0-3.5.1`, `v5.0.0-3.5.3` | authenticated, dynamic test | true | true | true | high |
| `OSMAP-WSTG-SESS-005` | WSTG-v42-ATHN-06 Testing for Browser Cache Weaknesses - authenticated pages | `WSTG-v42-ATHN-06`, `WSTG-v42-SESS-06` | `v5.0.0-3.4.2`, `v5.0.0-7.4.1` | authenticated, dynamic test | true | true | true | medium |
| `OSMAP-WSTG-CONF-004` | WSTG-v42-CONF-06 Test HTTP Methods - OPTIONS and TRACE | `WSTG-v42-CONF-06` | `v5.0.0-4.1.4`, `v5.0.0-4.2.1` | unauthenticated, dynamic test | true | false | false | high |
| `OSMAP-WSTG-INFO-001` | WSTG-v42-INFO-03 Review Webserver Metafiles for Information Leakage | `WSTG-v42-INFO-03`, `WSTG-v42-INFO-05` | `v5.0.0-14.3.1` | unauthenticated, dynamic test | true | false | false | low |
| `OSMAP-WSTG-INFO-002` | WSTG-v42-INFO-02 Fingerprint Web Server - unauthenticated disclosure and error handling | `WSTG-v42-INFO-02`, `WSTG-v42-ERRH-01` | `v5.0.0-14.3.1`, `v5.0.0-8.2.1` | unauthenticated, dynamic test | true | false | false | medium |
| `OSMAP-WSTG-INPV-001` | WSTG-v42-ATHZ-01 Testing Directory Traversal File Include - safe endpoint probes | `WSTG-v42-ATHZ-01` | `v5.0.0-2.2.1`, `v5.0.0-4.2.5`, `v5.0.0-8.2.2` | unauthenticated, dynamic test | true | false | false | high |
| `OSMAP-WSTG-INPV-002` | WSTG-v42-INPV-01 Testing for Reflected Cross Site Scripting - safe parameters | `WSTG-v42-INPV-01` | `v5.0.0-1.1.2`, `v5.0.0-1.2.1`, `v5.0.0-2.2.1` | unauthenticated, dynamic test | true | false | false | high |
| `OSMAP-WSTG-CLNT-001` | WSTG-v42-CLNT-07 Testing Cross Origin Resource Sharing | `WSTG-v42-CLNT-07` | `v5.0.0-14.4.4`, `v5.0.0-3.5.8` | unauthenticated, dynamic test | true | false | false | high |
| `OSMAP-WSTG-CLNT-002` | WSTG-v42-INPV-02 Testing for Stored Cross Site Scripting - HTML email rendering policy | `WSTG-v42-INPV-02`, `WSTG-v42-CLNT-01` | `v5.0.0-1.3.1`, `v5.0.0-1.2.1`, `v5.0.0-3.4.6` | host assisted, dynamic test, static boundary review | true | false | false | high |
| `OSMAP-WSTG-BUSL-001` | WSTG-v42-BUSL-08 Test Upload of Unexpected File Types - attachment handling policy | `WSTG-v42-BUSL-08`, `WSTG-v42-BUSL-09` | `v5.0.0-10.1.1`, `v5.0.0-10.2.1`, `v5.0.0-14.4.4` | host assisted, dynamic test, static boundary review | true | false | false | high |
| `OSMAP-WSTG-CONF-005` | WSTG-v42-CONF-05 Enumerate Infrastructure and Application Admin Interfaces - host bindings | `WSTG-v42-CONF-05`, `WSTG-v42-CONF-01` | `v5.0.0-14.3.1`, `v5.0.0-14.4.1` | host assisted, static review | true | false | false | high |
| `OSMAP-WSTG-CONF-006` | WSTG-v42-CONF-01 Test Network Infrastructure Configuration - pf posture | `WSTG-v42-CONF-01` | `v5.0.0-14.3.1`, `v5.0.0-14.4.1` | host assisted, static review | true | false | false | high |
| `OSMAP-WSTG-CONF-007` | WSTG-v42-CONF-02 Test Application Platform Configuration - SBOM and dependency alignment | `WSTG-v42-CONF-02` | `v5.0.0-14.2.1`, `v5.0.0-14.2.2`, `v5.0.0-14.2.3` | tool execution, static boundary review | true | false | false | medium |
| `OSMAP-WSTG-BUSL-002` | WSTG-v42-BUSL-04 Test Process Timing - authenticated draft route lifecycle | `WSTG-v42-BUSL-04`, `WSTG-v42-BUSL-08`, `WSTG-v42-SESS-05`, `WSTG-v42-ATHZ-04` | `v5.0.0-2.2.1`, `v5.0.0-2.3.2`, `v5.0.0-3.5.1`, `v5.0.0-3.5.3`, `v5.0.0-7.4.1`, `v5.0.0-8.2.1`, `v5.0.0-10.1.1`, `v5.0.0-10.2.1` | authenticated, dynamic test | true | true | true | high |
| `OSMAP-WSTG-BUSL-003` | WSTG-v42-BUSL-08 Test Upload of Unexpected File Types - authenticated selected source attachments | `WSTG-v42-BUSL-08`, `WSTG-v42-BUSL-09`, `WSTG-v42-SESS-05`, `WSTG-v42-ATHZ-04` | `v5.0.0-2.2.1`, `v5.0.0-2.3.2`, `v5.0.0-3.5.1`, `v5.0.0-3.5.3`, `v5.0.0-7.4.1`, `v5.0.0-8.2.1`, `v5.0.0-10.1.1`, `v5.0.0-10.2.1`, `v5.0.0-14.4.4` | authenticated, dynamic test | true | true | true | high |
| `OSMAP-WSTG-BUSL-004` | WSTG-v42-BUSL-04 Test Process Timing - bounded bulk folder actions | `WSTG-v42-BUSL-04`, `WSTG-v42-SESS-05`, `WSTG-v42-ATHZ-04` | `v5.0.0-2.2.1`, `v5.0.0-2.3.2`, `v5.0.0-3.5.1`, `v5.0.0-3.5.3`, `v5.0.0-7.4.1`, `v5.0.0-8.2.1` | host assisted, dynamic test, static boundary review | true | false | false | high |
| `OSMAP-WSTG-LOGG-001` | OWASP Top 10 2025 A09 Security Logging and Alerting Failures - audit event and redaction posture | `WSTG-v42-ERRH-01` | `v5.0.0-8.2.1` | evidence validation, static boundary review | true | false | false | high |

## Explicit Existing Gaps

| Gap ID | Area | WSTG | ASVS | Top 10 | Reason |
| --- | --- | --- | --- | --- | --- |
| `OSMAP-WSTG-GAP-001` | Authenticated destructive business workflows | `WSTG-v42-BUSL-04`, `WSTG-v42-BUSL-08` | `v5.0.0-2.3.2`, `v5.0.0-8.2.2` | `A01:2025`, `A06:2025`, `A08:2025` | Tests that send real mail, move real messages, or alter durable settings require controlled validation accounts and fixtures. The runner skips these unless explicitly credential-enabled. |
| `OSMAP-WSTG-GAP-002` | Full attachment upload malware/content scanning | `WSTG-v42-BUSL-08`, `WSTG-v42-BUSL-09` | `v5.0.0-10.2.1` | `A06:2025`, `A08:2025` | The pack validates OSMAP browser boundaries and source controls. Mail-stack content filtering belongs to the mailstack validation tooling and is not broadened here. |
| `OSMAP-WSTG-GAP-003` | Full ASVS compliance | n/a | `v5.0.0` | n/a | This pack validates OSMAP-relevant browser, auth, session, rendering, attachment, host-binding, and deployment controls. It is not a complete ASVS verification program for the full mail platform. |

## V3 Release Interpretation

The current mapped tests remain valuable regression coverage. They do not close V3 WSTG due diligence by themselves.

Before V3 closeout, each row in the active WSTG matrix must have one reviewed disposition: `automated`, `manual`, `not_applicable`, `covered_by_other_evidence`, `deferred`, or `blocked`. Critical blocked or deferred rows block V3 closeout. High-priority deferred rows require a decision-log entry, owner, risk statement, and expiry or trigger.

