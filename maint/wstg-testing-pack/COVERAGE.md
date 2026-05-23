# OSMAP WSTG, ASVS, And OWASP Top 10 Coverage

Generated from `wstg-asvs-mapping.json` and the active WSTG due-diligence matrix.

## Standards

| Standard | Current repository use |
| --- | --- |
| OWASP WSTG v4.2 | Current implemented matrix and mapped runner tests. |
| OWASP WSTG latest | Required for V3 latest-track due diligence when pinned to an upstream commit. |
| OWASP ASVS 5.0.0 | Control mapping for implemented tests where applicable. |
| Project Top 10 crosswalk | Risk grouping for release-required WSTG tests and explicit gaps. |

## Active Matrix Summary

| Item | Count |
| --- | ---: |
| Active matrix rows | 97 |
| Automated dispositions | 50 |
| Manual dispositions | 0 |
| Not-applicable dispositions | 13 |
| Covered-by-other-evidence dispositions | 0 |
| Deferred dispositions | 0 |
| Blocked dispositions | 34 |
| Missing dispositions | 0 |
| Invalid dispositions | 0 |

## OWASP Top 10 2025 Crosswalk

| Category | Name | Release-required tests | Explicit gaps |
| --- | --- | --- | --- |
| `A01:2025` | Broken Access Control | `OSMAP-WSTG-SESS-003`, `OSMAP-WSTG-SESS-004`, `OSMAP-WSTG-INPV-001`, `OSMAP-WSTG-INPV-005`, `OSMAP-WSTG-INPV-006`, `OSMAP-WSTG-CLNT-001`, `OSMAP-WSTG-ATHZ-001`, `OSMAP-WSTG-CONF-005`, `OSMAP-WSTG-BUSL-002`, `OSMAP-WSTG-BUSL-003`, `OSMAP-WSTG-BUSL-004`, `OSMAP-WSTG-BUSL-005` | `OSMAP-WSTG-GAP-001` |
| `A02:2025` | Security Misconfiguration | `OSMAP-WSTG-CONF-001`, `OSMAP-WSTG-CONF-002`, `OSMAP-WSTG-CONF-003`, `OSMAP-WSTG-SESS-005`, `OSMAP-WSTG-SESS-006`, `OSMAP-WSTG-CONF-004`, `OSMAP-WSTG-INFO-001`, `OSMAP-WSTG-INFO-002`, `OSMAP-WSTG-INPV-006`, `OSMAP-WSTG-CLNT-001`, `OSMAP-WSTG-CONF-005`, `OSMAP-WSTG-CONF-006`, `OSMAP-WSTG-CRYP-001` | none |
| `A03:2025` | Software Supply Chain Failures | `OSMAP-WSTG-CONF-007` | none |
| `A04:2025` | Cryptographic Failures | `OSMAP-WSTG-CONF-001`, `OSMAP-WSTG-CONF-002`, `OSMAP-WSTG-ATHN-001`, `OSMAP-WSTG-SESS-001`, `OSMAP-WSTG-CRYP-001`, `OSMAP-WSTG-CRYP-002` | none |
| `A05:2025` | Injection | `OSMAP-WSTG-CONF-003`, `OSMAP-WSTG-INPV-001`, `OSMAP-WSTG-INPV-002`, `OSMAP-WSTG-INPV-003`, `OSMAP-WSTG-INPV-004`, `OSMAP-WSTG-INPV-005`, `OSMAP-WSTG-INPV-006`, `OSMAP-WSTG-INPV-007`, `OSMAP-WSTG-CLNT-002`, `OSMAP-WSTG-APIT-001` | none |
| `A06:2025` | Insecure Design | `OSMAP-WSTG-INPV-004`, `OSMAP-WSTG-INPV-005`, `OSMAP-WSTG-INPV-006`, `OSMAP-WSTG-INPV-007`, `OSMAP-WSTG-CLNT-002`, `OSMAP-WSTG-BUSL-001`, `OSMAP-WSTG-ATHZ-001`, `OSMAP-WSTG-BUSL-002`, `OSMAP-WSTG-BUSL-003`, `OSMAP-WSTG-BUSL-004`, `OSMAP-WSTG-CRYP-002`, `OSMAP-WSTG-BUSL-005`, `OSMAP-WSTG-APIT-001` | `OSMAP-WSTG-GAP-001`, `OSMAP-WSTG-GAP-002` |
| `A07:2025` | Authentication Failures | `OSMAP-WSTG-ATHN-001`, `OSMAP-WSTG-ATHN-002`, `OSMAP-WSTG-ATHN-003`, `OSMAP-WSTG-ATHN-004`, `OSMAP-WSTG-SESS-001`, `OSMAP-WSTG-SESS-002`, `OSMAP-WSTG-SESS-003`, `OSMAP-WSTG-SESS-005`, `OSMAP-WSTG-SESS-006`, `OSMAP-WSTG-ATHZ-001`, `OSMAP-WSTG-BUSL-002`, `OSMAP-WSTG-BUSL-003`, `OSMAP-WSTG-CRYP-001` | none |
| `A08:2025` | Software or Data Integrity Failures | `OSMAP-WSTG-SESS-004`, `OSMAP-WSTG-BUSL-001`, `OSMAP-WSTG-CONF-007`, `OSMAP-WSTG-BUSL-002`, `OSMAP-WSTG-BUSL-003`, `OSMAP-WSTG-BUSL-004`, `OSMAP-WSTG-BUSL-005` | `OSMAP-WSTG-GAP-001`, `OSMAP-WSTG-GAP-002` |
| `A09:2025` | Security Logging and Alerting Failures | `OSMAP-WSTG-SESS-006`, `OSMAP-WSTG-INPV-003`, `OSMAP-WSTG-INPV-004`, `OSMAP-WSTG-ATHZ-001`, `OSMAP-WSTG-BUSL-002`, `OSMAP-WSTG-BUSL-003`, `OSMAP-WSTG-LOGG-001` | none |
| `A10:2025` | Mishandling of Exceptional Conditions | `OSMAP-WSTG-ATHN-003`, `OSMAP-WSTG-SESS-006`, `OSMAP-WSTG-CONF-004`, `OSMAP-WSTG-INFO-002`, `OSMAP-WSTG-INPV-001`, `OSMAP-WSTG-INPV-003`, `OSMAP-WSTG-INPV-004`, `OSMAP-WSTG-INPV-005`, `OSMAP-WSTG-INPV-006`, `OSMAP-WSTG-INPV-007`, `OSMAP-WSTG-ATHZ-001`, `OSMAP-WSTG-BUSL-002`, `OSMAP-WSTG-BUSL-003`, `OSMAP-WSTG-BUSL-004`, `OSMAP-WSTG-CRYP-002`, `OSMAP-WSTG-BUSL-005`, `OSMAP-WSTG-APIT-001` | none |

## Mapped Tests

| Test ID | Test | WSTG v4.2 | ASVS 5.0.0 | OWASP Top 10 2025 | Type | Release Required | Auth Required | TOTP Required | Safe For Release | Severity |
| --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- |
| `OSMAP-WSTG-CONF-001` | WSTG-v42-CONF-01 Test Network Infrastructure Configuration - TLS and HTTP exposure | `WSTG-v42-CONF-01` | `v5.0.0-9.1.1`, `v5.0.0-9.1.2` | `A02:2025`, `A04:2025` | unauthenticated, dynamic test | true | false | false | true | high |
| `OSMAP-WSTG-CONF-002` | WSTG-v42-CONF-07 Test HTTP Strict Transport Security - browser header baseline | `WSTG-v42-CONF-07`, `WSTG-v42-CLNT-09` | `v5.0.0-3.4.5`, `v5.0.0-3.4.6`, `v5.0.0-14.4.3`, `v5.0.0-14.4.4` | `A02:2025`, `A04:2025` | unauthenticated, dynamic test | true | false | false | true | medium |
| `OSMAP-WSTG-CONF-003` | WSTG-v42-CONF-12 Testing for Content Security Policy - OSMAP CSP regression | `WSTG-v42-CONF-12` | `v5.0.0-3.4.6`, `v5.0.0-14.4.3` | `A02:2025`, `A05:2025` | unauthenticated, dynamic test | true | false | false | true | high |
| `OSMAP-WSTG-ATHN-001` | WSTG-v42-ATHN-01 Testing for Credentials Transported over an Encrypted Channel - login form | `WSTG-v42-ATHN-01`, `WSTG-v42-ATHN-10` | `v5.0.0-6.2.6`, `v5.0.0-6.2.7`, `v5.0.0-6.3.3` | `A04:2025`, `A07:2025` | unauthenticated, dynamic test | true | false | false | true | medium |
| `OSMAP-WSTG-ATHN-002` | WSTG-v42-IDNT-04 Testing for Account Enumeration and Guessable User Account - login failure normalization | `WSTG-v42-IDNT-04`, `WSTG-v42-ATHN-03` | `v5.0.0-6.3.1`, `v5.0.0-6.3.8` | `A07:2025` | unauthenticated, dynamic test | true | false | false | true | high |
| `OSMAP-WSTG-ATHN-003` | WSTG-v42-ATHN-03 Testing for Weak Lock Out Mechanism - bounded login throttle probe | `WSTG-v42-ATHN-03` | `v5.0.0-6.1.1`, `v5.0.0-6.3.1` | `A07:2025`, `A10:2025` | unauthenticated, dynamic test | true | false | false | true | medium |
| `OSMAP-WSTG-ATHN-004` | WSTG-v42-ATHN-10 Testing for Weaker Authentication in Alternative Channel - TOTP login flow | `WSTG-v42-ATHN-10` | `v5.0.0-6.3.3`, `v5.0.0-6.5.5`, `v5.0.0-6.5.8` | `A07:2025` | authenticated, dynamic test | true | true | true | true | high |
| `OSMAP-WSTG-SESS-001` | WSTG-v42-SESS-02 Testing for Cookies Attributes - OSMAP session cookie | `WSTG-v42-SESS-02` | `v5.0.0-3.2.1`, `v5.0.0-3.2.2`, `v5.0.0-7.2.1` | `A04:2025`, `A07:2025` | authenticated, dynamic test | true | true | true | true | high |
| `OSMAP-WSTG-SESS-002` | WSTG-v42-SESS-03 Testing for Session Fixation - pre-login cookie replacement | `WSTG-v42-SESS-03` | `v5.0.0-7.2.3`, `v5.0.0-7.2.4` | `A07:2025` | authenticated, dynamic test | true | true | true | true | high |
| `OSMAP-WSTG-SESS-003` | WSTG-v42-SESS-05 Testing for Cross Site Request Forgery - logout enforcement | `WSTG-v42-SESS-05` | `v5.0.0-3.5.1`, `v5.0.0-3.5.3`, `v5.0.0-7.4.1` | `A01:2025`, `A07:2025` | authenticated, dynamic test | true | true | true | true | high |
| `OSMAP-WSTG-SESS-004` | WSTG-v42-SESS-05 Testing for Cross Site Request Forgery - authenticated mutations | `WSTG-v42-SESS-05` | `v5.0.0-3.5.1`, `v5.0.0-3.5.3` | `A01:2025`, `A08:2025` | authenticated, dynamic test | true | true | true | true | high |
| `OSMAP-WSTG-SESS-005` | WSTG-v42-ATHN-06 Testing for Browser Cache Weaknesses - authenticated pages | `WSTG-v42-ATHN-06`, `WSTG-v42-SESS-06` | `v5.0.0-3.4.2`, `v5.0.0-7.4.1` | `A02:2025`, `A07:2025` | authenticated, dynamic test | true | true | true | true | medium |
| `OSMAP-WSTG-SESS-006` | WSTG-v42-SESS lifecycle, timeout, and stale-cookie controls | `WSTG-v42-SESS-01`, `WSTG-v42-SESS-04`, `WSTG-v42-SESS-06`, `WSTG-v42-SESS-07`, `WSTG-v42-SESS-08`, `WSTG-v42-SESS-09` | `v5.0.0-3.2.1`, `v5.0.0-3.4.2`, `v5.0.0-7.1.2`, `v5.0.0-7.2.1`, `v5.0.0-7.4.1`, `v5.0.0-7.4.4`, `v5.0.0-8.2.1` | `A02:2025`, `A07:2025`, `A09:2025`, `A10:2025` | authenticated, dynamic test, static boundary review | true | true | true | true | high |
| `OSMAP-WSTG-CONF-004` | WSTG-v42-CONF-06 Test HTTP Methods - OPTIONS and TRACE | `WSTG-v42-CONF-06` | `v5.0.0-4.1.4`, `v5.0.0-4.2.1` | `A02:2025`, `A10:2025` | unauthenticated, dynamic test | true | false | false | true | high |
| `OSMAP-WSTG-INFO-001` | WSTG-v42-INFO-03 Review Webserver Metafiles for Information Leakage | `WSTG-v42-INFO-03`, `WSTG-v42-INFO-05` | `v5.0.0-14.3.1` | `A02:2025` | unauthenticated, dynamic test | true | false | false | true | low |
| `OSMAP-WSTG-INFO-002` | WSTG-v42-INFO-02 Fingerprint Web Server - unauthenticated disclosure and error handling | `WSTG-v42-INFO-02`, `WSTG-v42-ERRH-01` | `v5.0.0-14.3.1`, `v5.0.0-8.2.1` | `A02:2025`, `A10:2025` | unauthenticated, dynamic test | true | false | false | true | medium |
| `OSMAP-WSTG-INPV-001` | WSTG-v42-ATHZ-01 Testing Directory Traversal File Include - safe endpoint probes | `WSTG-v42-ATHZ-01` | `v5.0.0-2.2.1`, `v5.0.0-4.2.5`, `v5.0.0-8.2.2` | `A01:2025`, `A05:2025`, `A10:2025` | unauthenticated, dynamic test | true | false | false | true | high |
| `OSMAP-WSTG-INPV-002` | WSTG-v42-INPV-01 Testing for Reflected Cross Site Scripting - safe parameters | `WSTG-v42-INPV-01` | `v5.0.0-1.1.2`, `v5.0.0-1.2.1`, `v5.0.0-2.2.1` | `A05:2025` | unauthenticated, dynamic test | true | false | false | true | high |
| `OSMAP-WSTG-INPV-003` | WSTG-v42-INPV-12 Testing for Command Injection - safe OSMAP command-boundary due diligence | `WSTG-v42-INPV-12` | `v5.0.0-1.2.1`, `v5.0.0-2.2.1`, `v5.0.0-5.2.4`, `v5.0.0-8.2.1` | `A05:2025`, `A09:2025`, `A10:2025` | authenticated, dynamic test, host assisted | true | true | true | true | critical |
| `OSMAP-WSTG-INPV-004` | WSTG-v42-INPV-10 Testing for IMAP SMTP Injection - webmail input validation | `WSTG-v42-INPV-10` | `v5.0.0-1.2.1`, `v5.0.0-1.3.1`, `v5.0.0-4.2.4`, `v5.0.0-5.2.4`, `v5.0.0-8.2.1`, `v5.0.0-10.2.1` | `A05:2025`, `A06:2025`, `A09:2025`, `A10:2025` | authenticated, dynamic test, static boundary review | true | true | true | true | high |
| `OSMAP-WSTG-INPV-005` | WSTG-v42-INPV-03/04 Testing HTTP Verb Tampering and HTTP Parameter Pollution | `WSTG-v42-INPV-03`, `WSTG-v42-INPV-04` | `v5.0.0-1.2.1`, `v5.0.0-4.1.4`, `v5.0.0-5.2.4`, `v5.0.0-8.2.1` | `A01:2025`, `A05:2025`, `A06:2025`, `A10:2025` | unauthenticated, dynamic test, static boundary review | true | false | false | true | high |
| `OSMAP-WSTG-INPV-006` | WSTG-v42-INPV-15/16/17 Testing HTTP Host Header and Smuggling Inputs | `WSTG-v42-INPV-15`, `WSTG-v42-INPV-16`, `WSTG-v42-INPV-17` | `v5.0.0-1.2.1`, `v5.0.0-4.1.4`, `v5.0.0-5.2.4`, `v5.0.0-8.2.1` | `A01:2025`, `A02:2025`, `A05:2025`, `A06:2025`, `A10:2025` | unauthenticated, dynamic raw HTTP test, static boundary review | true | false | false | true | high |
| `OSMAP-WSTG-INPV-007` | WSTG-v42-INPV-05/06/07/08/09/11/13/14/18/19 Injection Applicability Review | `WSTG-v42-INPV-05`, `WSTG-v42-INPV-06`, `WSTG-v42-INPV-07`, `WSTG-v42-INPV-08`, `WSTG-v42-INPV-09`, `WSTG-v42-INPV-11`, `WSTG-v42-INPV-13`, `WSTG-v42-INPV-14`, `WSTG-v42-INPV-18`, `WSTG-v42-INPV-19` | `v5.0.0-1.2.1`, `v5.0.0-5.2.4`, `v5.0.0-8.2.1` | `A05:2025`, `A06:2025`, `A10:2025` | static applicability review | true | false | false | true | high |
| `OSMAP-WSTG-CLNT-001` | WSTG-v42-CLNT-07 Testing Cross Origin Resource Sharing | `WSTG-v42-CLNT-07` | `v5.0.0-14.4.4`, `v5.0.0-3.5.8` | `A01:2025`, `A02:2025` | unauthenticated, dynamic test | true | false | false | true | high |
| `OSMAP-WSTG-CLNT-002` | WSTG-v42-INPV-02 Testing for Stored Cross Site Scripting - HTML email rendering policy | `WSTG-v42-INPV-02`, `WSTG-v42-CLNT-01` | `v5.0.0-1.3.1`, `v5.0.0-1.2.1`, `v5.0.0-3.4.6` | `A05:2025`, `A06:2025` | host assisted, dynamic test, static boundary review | true | false | false | true | high |
| `OSMAP-WSTG-BUSL-001` | WSTG-v42-BUSL-08 Test Upload of Unexpected File Types - attachment handling policy | `WSTG-v42-BUSL-08`, `WSTG-v42-BUSL-09` | `v5.0.0-10.1.1`, `v5.0.0-10.2.1`, `v5.0.0-14.4.4` | `A06:2025`, `A08:2025` | host assisted, dynamic test, static boundary review | true | false | false | true | high |
| `OSMAP-WSTG-ATHZ-001` | WSTG-v42-ATHZ authorization account-isolation negative evidence | `WSTG-v42-ATHZ-02`, `WSTG-v42-ATHZ-03`, `WSTG-v42-ATHZ-04` | `v5.0.0-2.2.1`, `v5.0.0-2.3.2`, `v5.0.0-7.4.1`, `v5.0.0-8.2.1`, `v5.0.0-8.2.2` | `A01:2025`, `A06:2025`, `A07:2025`, `A09:2025`, `A10:2025` | authenticated, host assisted, dynamic test, static boundary review | true | true | true | true | high |
| `OSMAP-WSTG-CONF-005` | WSTG-v42-CONF-05 Enumerate Infrastructure and Application Admin Interfaces - host bindings | `WSTG-v42-CONF-05`, `WSTG-v42-CONF-01` | `v5.0.0-14.3.1`, `v5.0.0-14.4.1` | `A01:2025`, `A02:2025` | host assisted, static review | true | false | false | true | high |
| `OSMAP-WSTG-CONF-006` | WSTG-v42-CONF-01 Test Network Infrastructure Configuration - pf posture | `WSTG-v42-CONF-01` | `v5.0.0-14.3.1`, `v5.0.0-14.4.1` | `A02:2025` | host assisted, static review | true | false | false | true | high |
| `OSMAP-WSTG-CONF-007` | WSTG-v42-CONF-02 Test Application Platform Configuration - SBOM and dependency alignment | `WSTG-v42-CONF-02` | `v5.0.0-14.2.1`, `v5.0.0-14.2.2`, `v5.0.0-14.2.3` | `A03:2025`, `A08:2025` | tool execution, static boundary review | true | false | false | true | medium |
| `OSMAP-WSTG-BUSL-002` | WSTG-v42-BUSL-04 Test Process Timing - authenticated draft route lifecycle | `WSTG-v42-BUSL-04`, `WSTG-v42-BUSL-08`, `WSTG-v42-SESS-05`, `WSTG-v42-ATHZ-04` | `v5.0.0-2.2.1`, `v5.0.0-2.3.2`, `v5.0.0-3.5.1`, `v5.0.0-3.5.3`, `v5.0.0-7.4.1`, `v5.0.0-8.2.1`, `v5.0.0-10.1.1`, `v5.0.0-10.2.1` | `A01:2025`, `A06:2025`, `A07:2025`, `A08:2025`, `A09:2025`, `A10:2025` | authenticated, dynamic test | true | true | true | true | high |
| `OSMAP-WSTG-BUSL-003` | WSTG-v42-BUSL-08 Test Upload of Unexpected File Types - authenticated selected source attachments | `WSTG-v42-BUSL-08`, `WSTG-v42-BUSL-09`, `WSTG-v42-SESS-05`, `WSTG-v42-ATHZ-04` | `v5.0.0-2.2.1`, `v5.0.0-2.3.2`, `v5.0.0-3.5.1`, `v5.0.0-3.5.3`, `v5.0.0-7.4.1`, `v5.0.0-8.2.1`, `v5.0.0-10.1.1`, `v5.0.0-10.2.1`, `v5.0.0-14.4.4` | `A01:2025`, `A06:2025`, `A07:2025`, `A08:2025`, `A09:2025`, `A10:2025` | authenticated, dynamic test | true | true | true | true | high |
| `OSMAP-WSTG-BUSL-004` | WSTG-v42-BUSL-04 Test Process Timing - bounded bulk folder actions | `WSTG-v42-BUSL-04`, `WSTG-v42-SESS-05`, `WSTG-v42-ATHZ-04` | `v5.0.0-2.2.1`, `v5.0.0-2.3.2`, `v5.0.0-3.5.1`, `v5.0.0-3.5.3`, `v5.0.0-7.4.1`, `v5.0.0-8.2.1` | `A01:2025`, `A06:2025`, `A08:2025`, `A10:2025` | host assisted, dynamic test, static boundary review | true | false | false | true | high |
| `OSMAP-WSTG-CRYP-001` | WSTG-v42-CRYP-01/03 TLS and cleartext transport evidence | `WSTG-v42-CRYP-01`, `WSTG-v42-CRYP-03` | `v5.0.0-6.2.6`, `v5.0.0-7.2.1`, `v5.0.0-9.1.1`, `v5.0.0-9.1.2` | `A02:2025`, `A04:2025`, `A07:2025` | unauthenticated, dynamic test, static boundary review | true | false | false | true | critical |
| `OSMAP-WSTG-CRYP-002` | WSTG-v42-CRYP-02/04 Crypto Primitive Applicability Review | `WSTG-v42-CRYP-02`, `WSTG-v42-CRYP-04` | `v5.0.0-1.2.1`, `v5.0.0-6.2.6`, `v5.0.0-8.2.1` | `A04:2025`, `A06:2025`, `A10:2025` | static applicability review | true | false | false | true | high |
| `OSMAP-WSTG-BUSL-005` | WSTG-v42-BUSL-01/02/03/05/06/07 Form Route State-Transition Review | `WSTG-v42-BUSL-01`, `WSTG-v42-BUSL-02`, `WSTG-v42-BUSL-03`, `WSTG-v42-BUSL-05`, `WSTG-v42-BUSL-06`, `WSTG-v42-BUSL-07` | `v5.0.0-1.2.1`, `v5.0.0-2.2.1`, `v5.0.0-3.5.1`, `v5.0.0-5.2.4`, `v5.0.0-8.2.1` | `A01:2025`, `A06:2025`, `A08:2025`, `A10:2025` | static boundary review | true | false | false | true | high |
| `OSMAP-WSTG-APIT-001` | WSTG-v42-APIT-01 GraphQL Applicability Review | `WSTG-v42-APIT-01` | `v5.0.0-1.2.1`, `v5.0.0-4.1.4`, `v5.0.0-8.2.1` | `A05:2025`, `A06:2025`, `A10:2025` | static applicability review | true | false | false | true | medium |
| `OSMAP-WSTG-LOGG-001` | OWASP Top 10 2025 A09 Security Logging and Alerting Failures - audit event and redaction posture | `WSTG-v42-ERRH-01` | `v5.0.0-8.2.1` | `A09:2025` | evidence validation, static boundary review | true | false | false | true | high |

## Explicit Gaps

| Gap ID | Area | WSTG | ASVS | OWASP Top 10 2025 | Reason |
| --- | --- | --- | --- | --- | --- |
| `OSMAP-WSTG-GAP-001` | Authenticated destructive business workflows | `WSTG-v42-BUSL-04`, `WSTG-v42-BUSL-08` | `v5.0.0-2.3.2`, `v5.0.0-8.2.2` | `A01:2025`, `A06:2025`, `A08:2025` | Tests that send real mail, move real messages, or alter durable settings require controlled validation accounts and fixtures. The runner skips these unless explicitly credential-enabled. |
| `OSMAP-WSTG-GAP-002` | Full attachment upload malware/content scanning | `WSTG-v42-BUSL-08`, `WSTG-v42-BUSL-09` | `v5.0.0-10.2.1` | `A06:2025`, `A08:2025` | The pack validates OSMAP browser boundaries and source controls. Mail-stack content filtering belongs to the mailstack validation tooling and is not broadened here. |
| `OSMAP-WSTG-GAP-003` | Full ASVS compliance | n/a | `v5.0.0` | n/a | This pack validates OSMAP-relevant browser, auth, session, rendering, attachment, host-binding, and deployment controls. It is not a complete ASVS verification program for the full mail platform. |
