# OSMAP WSTG and ASVS Coverage

Generated from `wstg-asvs-mapping.json`.

| Test ID | Test | WSTG v4.2 | ASVS 5.0.0 | Type | Severity |
| --- | --- | --- | --- | --- | --- |
| `OSMAP-WSTG-CONF-001` | WSTG-v42-CONF-01 Test Network Infrastructure Configuration - TLS and HTTP exposure | `WSTG-v42-CONF-01` | `v5.0.0-9.1.1`, `v5.0.0-9.1.2` | unauthenticated, dynamic test | high |
| `OSMAP-WSTG-CONF-002` | WSTG-v42-CONF-07 Test HTTP Strict Transport Security - browser header baseline | `WSTG-v42-CONF-07`, `WSTG-v42-CLNT-09` | `v5.0.0-3.4.5`, `v5.0.0-3.4.6`, `v5.0.0-14.4.3`, `v5.0.0-14.4.4` | unauthenticated, dynamic test | medium |
| `OSMAP-WSTG-CONF-003` | WSTG-v42-CONF-12 Testing for Content Security Policy - OSMAP CSP regression | `WSTG-v42-CONF-12` | `v5.0.0-3.4.6`, `v5.0.0-14.4.3` | unauthenticated, dynamic test | high |
| `OSMAP-WSTG-ATHN-001` | WSTG-v42-ATHN-01 Testing for Credentials Transported over an Encrypted Channel - login form | `WSTG-v42-ATHN-01`, `WSTG-v42-ATHN-10` | `v5.0.0-6.2.6`, `v5.0.0-6.2.7`, `v5.0.0-6.3.3` | unauthenticated, dynamic test | medium |
| `OSMAP-WSTG-ATHN-002` | WSTG-v42-IDNT-04 Testing for Account Enumeration and Guessable User Account - login failure normalization | `WSTG-v42-IDNT-04`, `WSTG-v42-ATHN-03` | `v5.0.0-6.3.1`, `v5.0.0-6.3.8` | unauthenticated, dynamic test | high |
| `OSMAP-WSTG-ATHN-003` | WSTG-v42-ATHN-03 Testing for Weak Lock Out Mechanism - bounded login throttle probe | `WSTG-v42-ATHN-03` | `v5.0.0-6.1.1`, `v5.0.0-6.3.1` | unauthenticated, dynamic test | medium |
| `OSMAP-WSTG-ATHN-004` | WSTG-v42-ATHN-10 Testing for Weaker Authentication in Alternative Channel - TOTP login flow | `WSTG-v42-ATHN-10` | `v5.0.0-6.3.3`, `v5.0.0-6.5.5`, `v5.0.0-6.5.8` | authenticated, dynamic test | high |
| `OSMAP-WSTG-SESS-001` | WSTG-v42-SESS-02 Testing for Cookies Attributes - OSMAP session cookie | `WSTG-v42-SESS-02` | `v5.0.0-3.2.1`, `v5.0.0-3.2.2`, `v5.0.0-7.2.1` | authenticated, dynamic test | high |
| `OSMAP-WSTG-SESS-002` | WSTG-v42-SESS-03 Testing for Session Fixation - pre-login cookie replacement | `WSTG-v42-SESS-03` | `v5.0.0-7.2.3`, `v5.0.0-7.2.4` | authenticated, dynamic test | high |
| `OSMAP-WSTG-SESS-003` | WSTG-v42-SESS-05 Testing for Cross Site Request Forgery - logout enforcement | `WSTG-v42-SESS-05` | `v5.0.0-3.5.1`, `v5.0.0-3.5.3`, `v5.0.0-7.4.1` | authenticated, dynamic test | high |
| `OSMAP-WSTG-SESS-004` | WSTG-v42-SESS-05 Testing for Cross Site Request Forgery - authenticated mutations | `WSTG-v42-SESS-05` | `v5.0.0-3.5.1`, `v5.0.0-3.5.3` | authenticated, dynamic test | high |
| `OSMAP-WSTG-SESS-005` | WSTG-v42-ATHN-06 Testing for Browser Cache Weaknesses - authenticated pages | `WSTG-v42-ATHN-06`, `WSTG-v42-SESS-06` | `v5.0.0-3.4.2`, `v5.0.0-7.4.1` | authenticated, dynamic test | medium |
| `OSMAP-WSTG-CONF-004` | WSTG-v42-CONF-06 Test HTTP Methods - OPTIONS and TRACE | `WSTG-v42-CONF-06` | `v5.0.0-4.1.4`, `v5.0.0-4.2.1` | unauthenticated, dynamic test | high |
| `OSMAP-WSTG-INFO-001` | WSTG-v42-INFO-03 Review Webserver Metafiles for Information Leakage | `WSTG-v42-INFO-03`, `WSTG-v42-INFO-05` | `v5.0.0-14.3.1` | unauthenticated, dynamic test | low |
| `OSMAP-WSTG-INFO-002` | WSTG-v42-INFO-02 Fingerprint Web Server - unauthenticated disclosure and error handling | `WSTG-v42-INFO-02`, `WSTG-v42-ERRH-01` | `v5.0.0-14.3.1`, `v5.0.0-8.2.1` | unauthenticated, dynamic test | medium |
| `OSMAP-WSTG-INPV-001` | WSTG-v42-ATHZ-01 Testing Directory Traversal File Include - safe endpoint probes | `WSTG-v42-ATHZ-01` | `v5.0.0-2.2.1`, `v5.0.0-4.2.5`, `v5.0.0-8.2.2` | unauthenticated, dynamic test | high |
| `OSMAP-WSTG-INPV-002` | WSTG-v42-INPV-01 Testing for Reflected Cross Site Scripting - safe parameters | `WSTG-v42-INPV-01` | `v5.0.0-1.1.2`, `v5.0.0-1.2.1`, `v5.0.0-2.2.1` | unauthenticated, dynamic test | high |
| `OSMAP-WSTG-CLNT-001` | WSTG-v42-CLNT-07 Testing Cross Origin Resource Sharing | `WSTG-v42-CLNT-07` | `v5.0.0-14.4.4`, `v5.0.0-3.5.8` | unauthenticated, dynamic test | high |
| `OSMAP-WSTG-CLNT-002` | WSTG-v42-INPV-02 Testing for Stored Cross Site Scripting - HTML email rendering policy | `WSTG-v42-INPV-02`, `WSTG-v42-CLNT-01` | `v5.0.0-1.3.1`, `v5.0.0-1.2.1`, `v5.0.0-3.4.6` | static review | high |
| `OSMAP-WSTG-BUSL-001` | WSTG-v42-BUSL-08 Test Upload of Unexpected File Types - attachment handling policy | `WSTG-v42-BUSL-08`, `WSTG-v42-BUSL-09` | `v5.0.0-10.1.1`, `v5.0.0-10.2.1`, `v5.0.0-14.4.4` | static review | high |
| `OSMAP-WSTG-CONF-005` | WSTG-v42-CONF-05 Enumerate Infrastructure and Application Admin Interfaces - host bindings | `WSTG-v42-CONF-05`, `WSTG-v42-CONF-01` | `v5.0.0-14.3.1`, `v5.0.0-14.4.1` | host assisted, static review | high |
| `OSMAP-WSTG-CONF-006` | WSTG-v42-CONF-01 Test Network Infrastructure Configuration - pf posture | `WSTG-v42-CONF-01` | `v5.0.0-14.3.1`, `v5.0.0-14.4.1` | host assisted, static review | high |
| `OSMAP-WSTG-CONF-007` | WSTG-v42-CONF-02 Test Application Platform Configuration - SBOM and dependency alignment | `WSTG-v42-CONF-02` | `v5.0.0-14.2.1`, `v5.0.0-14.2.2`, `v5.0.0-14.2.3` | static review | medium |

## Explicit Gaps

| Gap ID | Area | WSTG | ASVS | Reason |
| --- | --- | --- | --- | --- |
| `OSMAP-WSTG-GAP-001` | Authenticated destructive business workflows | `WSTG-v42-BUSL-04`, `WSTG-v42-BUSL-08` | `v5.0.0-2.3.2`, `v5.0.0-8.2.2` | Tests that send real mail, move real messages, or alter durable settings require controlled validation accounts and fixtures. The runner skips these unless explicitly credential-enabled. |
| `OSMAP-WSTG-GAP-002` | Full attachment upload malware/content scanning | `WSTG-v42-BUSL-08`, `WSTG-v42-BUSL-09` | `v5.0.0-10.2.1` | The pack validates OSMAP browser boundaries and source controls. Mail-stack content filtering belongs to the mailstack validation tooling and is not broadened here. |
| `OSMAP-WSTG-GAP-003` | Full ASVS compliance | n/a | `v5.0.0` | This pack validates OSMAP-relevant browser, auth, session, rendering, attachment, host-binding, and deployment controls. It is not a complete ASVS verification program for the full mail platform. |
