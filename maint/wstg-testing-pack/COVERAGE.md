# OSMAP WSTG and ASVS Coverage

Generated from `wstg-asvs-mapping.json`.

| Test ID | Test | WSTG v4.2 | ASVS 5.0.0 | Type | Severity |
| --- | --- | --- | --- | --- | --- |
| `OSMAP-WSTG-CONF-001` | TLS availability and HTTP-to-HTTPS redirect | `WSTG-v42-CONF-01` | `v5.0.0-9.1.1`, `v5.0.0-9.1.2` | unauthenticated, dynamic test | high |
| `OSMAP-WSTG-CONF-002` | Browser security headers and HSTS | `WSTG-v42-CONF-07`, `WSTG-v42-CLNT-09` | `v5.0.0-3.4.5`, `v5.0.0-3.4.6`, `v5.0.0-14.4.3`, `v5.0.0-14.4.4` | unauthenticated, dynamic test | medium |
| `OSMAP-WSTG-CONF-003` | CSP regression check | `WSTG-v42-CONF-12`, `WSTG-v42-CLNT-01` | `v5.0.0-3.4.6`, `v5.0.0-14.4.3` | unauthenticated, dynamic test | high |
| `OSMAP-WSTG-ATHN-001` | Login form behavior | `WSTG-v42-ATHN-01`, `WSTG-v42-ATHN-10` | `v5.0.0-6.2.6`, `v5.0.0-6.2.7`, `v5.0.0-6.3.3` | unauthenticated, dynamic test | medium |
| `OSMAP-WSTG-ATHN-002` | Invalid login failure normalization | `WSTG-v42-ATHN-03`, `WSTG-v42-ATHN-04` | `v5.0.0-6.3.1`, `v5.0.0-6.3.8` | unauthenticated, dynamic test | high |
| `OSMAP-WSTG-ATHN-003` | Safe brute-force throttle probe | `WSTG-v42-ATHN-03` | `v5.0.0-6.1.1`, `v5.0.0-6.3.1` | unauthenticated, dynamic test | medium |
| `OSMAP-WSTG-ATHN-004` | Authenticated TOTP login flow | `WSTG-v42-ATHN-10` | `v5.0.0-6.3.3`, `v5.0.0-6.5.5`, `v5.0.0-6.5.8` | authenticated, dynamic test | high |
| `OSMAP-WSTG-SESS-001` | Session cookie flags | `WSTG-v42-SESS-02`, `WSTG-v42-SESS-05` | `v5.0.0-3.2.1`, `v5.0.0-3.2.2`, `v5.0.0-7.2.1` | authenticated, dynamic test | high |
| `OSMAP-WSTG-SESS-002` | Session fixation resistance | `WSTG-v42-SESS-03` | `v5.0.0-7.2.3`, `v5.0.0-7.2.4` | authenticated, dynamic test | high |
| `OSMAP-WSTG-SESS-003` | Logout CSRF enforcement | `WSTG-v42-SESS-05` | `v5.0.0-3.5.1`, `v5.0.0-3.5.3`, `v5.0.0-7.4.1` | authenticated, dynamic test | high |
| `OSMAP-WSTG-SESS-004` | Authenticated mutation CSRF enforcement | `WSTG-v42-SESS-05` | `v5.0.0-3.5.1`, `v5.0.0-3.5.3` | authenticated, dynamic test | high |
| `OSMAP-WSTG-SESS-005` | Authenticated cache-control | `WSTG-v42-SESS-06` | `v5.0.0-3.4.2`, `v5.0.0-7.4.1` | authenticated, dynamic test | medium |
| `OSMAP-WSTG-CONF-004` | OPTIONS and TRACE method behavior | `WSTG-v42-CONF-06` | `v5.0.0-4.1.4`, `v5.0.0-4.2.1` | unauthenticated, dynamic test | high |
| `OSMAP-WSTG-INFO-001` | robots.txt and security.txt behavior | `WSTG-v42-INFO-03`, `WSTG-v42-INFO-05` | `v5.0.0-14.3.1` | unauthenticated, dynamic test | low |
| `OSMAP-WSTG-INFO-002` | Information disclosure on unauthenticated surfaces | `WSTG-v42-INFO-02`, `WSTG-v42-ERRH-01` | `v5.0.0-14.3.1`, `v5.0.0-8.2.1` | unauthenticated, dynamic test | medium |
| `OSMAP-WSTG-INPV-001` | Path traversal probes against known safe endpoints | `WSTG-v42-ATHZ-01`, `WSTG-v42-INPV-05` | `v5.0.0-2.2.1`, `v5.0.0-4.2.5`, `v5.0.0-8.2.2` | unauthenticated, dynamic test | high |
| `OSMAP-WSTG-INPV-002` | Reflected input handling | `WSTG-v42-INPV-01`, `WSTG-v42-INPV-02` | `v5.0.0-1.1.2`, `v5.0.0-1.2.1`, `v5.0.0-2.2.1` | unauthenticated, dynamic test | high |
| `OSMAP-WSTG-CLNT-001` | CORS behavior | `WSTG-v42-CLNT-07` | `v5.0.0-14.4.4`, `v5.0.0-3.5.8` | unauthenticated, dynamic test | high |
| `OSMAP-WSTG-CLNT-002` | HTML email rendering policy static alignment | `WSTG-v42-INPV-02`, `WSTG-v42-CLNT-01` | `v5.0.0-1.3.1`, `v5.0.0-1.2.1`, `v5.0.0-3.4.6` | static review | high |
| `OSMAP-WSTG-BUSL-001` | Attachment handling static alignment | `WSTG-v42-BUSL-09`, `WSTG-v42-INPV-11` | `v5.0.0-10.1.1`, `v5.0.0-10.2.1`, `v5.0.0-14.4.4` | static review | high |
| `OSMAP-WSTG-CONF-005` | Host nginx and service binding verification | `WSTG-v42-CONF-01`, `WSTG-v42-CONF-05` | `v5.0.0-14.3.1`, `v5.0.0-14.4.1` | host assisted, static review | high |
| `OSMAP-WSTG-CONF-006` | Host pf posture verification | `WSTG-v42-CONF-01` | `v5.0.0-14.3.1`, `v5.0.0-14.4.1` | host assisted, static review | high |
| `OSMAP-WSTG-CONF-007` | SBOM and dependency security alignment | `WSTG-v42-CONF-12` | `v5.0.0-14.2.1`, `v5.0.0-14.2.2`, `v5.0.0-14.2.3` | static review | medium |

## Explicit Gaps

| Gap ID | Area | WSTG | ASVS | Reason |
| --- | --- | --- | --- | --- |
| `OSMAP-WSTG-GAP-001` | Authenticated destructive business workflows | `WSTG-v42-BUSL-04`, `WSTG-v42-BUSL-08` | `v5.0.0-2.3.2`, `v5.0.0-8.2.2` | Tests that send real mail, move real messages, or alter durable settings require controlled validation accounts and fixtures. The runner skips these unless explicitly credential-enabled. |
| `OSMAP-WSTG-GAP-002` | Full attachment upload malware/content scanning | `WSTG-v42-BUSL-09` | `v5.0.0-10.2.1` | The pack validates OSMAP browser boundaries and source controls. Mail-stack content filtering belongs to the mailstack validation tooling and is not broadened here. |
| `OSMAP-WSTG-GAP-003` | Full ASVS compliance | n/a | `v5.0.0` | This pack validates OSMAP-relevant browser, auth, session, rendering, attachment, host-binding, and deployment controls. It is not a complete ASVS verification program for the full mail platform. |
