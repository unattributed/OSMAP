# V13 WSTG Assurance Integrity and Adversarial Validation

## Purpose

V13 turns the WSTG testing pack from a broad regression checklist into a
fail-closed assurance system whose claims distinguish dynamic proof, static
evidence, manual review, and not-applicable decisions.

V13 is intentionally isolated from the concurrently developed V12 OpenPGP
work. It is based on the reviewed `origin/main` V11 baseline and does not
modify V12 files or make OpenPGP claims.

## Audit Findings and Closure

The code and security audit confirmed these material assurance defects and
closed them in V13:

| Finding | Risk | V13 closure |
| --- | --- | --- |
| Transport failures and truncated responses could still support a passing assertion | False assurance | Every mapped test now fails on incomplete target evidence, except the explicit closed cleartext-port case |
| Matrix input and evidence references were not release-authoritative | Coverage drift | Release mode validates matrix structure, dispositions, references, provenance, and source pins |
| Static review and not-applicable decisions were counted as dynamic proof | Inflated assurance | Reports classify dynamic, hybrid, tool, static, and not-applicable evidence separately |
| The runner rewrote hostile raw Host headers to the canonical host | False-negative Host-header testing | Adversarial Host values are preserved while only target paths are mount-scoped |
| Current To, Cc, Bcc, draft, settings, sorting, and source-attachment inputs were incomplete | Missed production attack surface | A canonical route and field inventory now gates current coverage |
| CSP checks covered one response and accepted weak variants | Browser policy regression | Login, root, and error responses must carry one consistent enforced default-deny policy |
| XSS checks searched response strings without executing a browser | Missed DOM or stored execution | Checksum-pinned geckodriver and headless Firefox execute reflected and stored hostile fixtures |
| MFA evidence proved only a successful login | Authentication bypass blind spots | Missing and incorrect factors are rejected and replay plus concurrent-consumption regressions execute |
| Session timeout and race claims were static | Session lifecycle blind spots | Timeout, logout race, and revoke-all race regressions execute and live stale-cookie reuse is rejected |
| Request-smuggling evidence lacked pipelined response-count checks | Desynchronization blind spots | CL.TE, TE.CL, obfuscated transfer encoding, duplicate framing, and pipelined response counts are tested through the public edge |
| Business-logic claims were source-marker checks | Workflow misuse blind spots | CSRF, cross-origin, duplicate-field, tamper, limit, failure-preservation, and session-revoke regressions execute |
| Malicious-file, dependency, SBOM, and logging claims lacked operational proof | Operational control blind spots | Safe EICAR detection, Rspamd to ClamAV reject configuration, advisory and policy gates, CycloneDX generation, and triggered host event inspection execute |

## Governing Outcome

The sprint is complete only when:

1. Transport failures and truncated responses cannot produce passing tests.
2. Release mode validates matrix existence, structure, evidence references,
   dispositions, and pinned latest-track provenance.
3. Reports do not count static or not-applicable evidence as dynamic proof.
4. Current browser routes and input fields have explicit adversarial coverage.
5. Browser, session, MFA, HTTP desynchronization, business-logic, upload,
   dependency, and logging tests exercise real security behavior.
6. The runner has behavioral regression tests for its own failure modes.
7. Signed slice commits pass repository gates, merge through protected `main`,
   and the reviewed result is deployed and validated on
   `mail.blackbagsecurity.com`.

## Slices

### Slice 1, Fail-Closed Runner Core

- Centralize incomplete-evidence handling.
- Fail tests on unavailable or truncated target responses.
- Preserve the explicit closed-cleartext-port exception.
- Honor configured ports, application mount paths, and same-origin authority.
- Add behavioral runner tests.

### Slice 2, Matrix and Reporting Integrity

- Fail release mode on missing, empty, malformed, inconsistent, or incomplete
  matrices.
- Separate dynamic proof, static evidence, and not-applicable results.
- Correct stable and latest WSTG identifiers.
- Refresh the pinned latest-track source.
- Make tracked coverage regeneration explicit.

### Slice 3, Current Attack-Surface Coverage

- Inventory routes, methods, query fields, and form fields.
- Cover To, Cc, and Bcc validation, aggregate limits, persistence, and Bcc
  privacy.
- Cover settings, session revocation, sorting, search filters, and source
  attachment selectors.

### Slice 4, Adversarial Protocol and Browser Depth

- Add browser-execution evidence for reflected and stored XSS and CSP.
- Add real session timeout and MFA negative-path evidence.
- Add two-hop HTTP request desynchronization testing.
- Expand context-aware payload and encoding coverage.

### Slice 5, Operational and Business Assurance

- Exercise workflow misuse, replay, limit, and concurrency cases.
- Reconcile malicious-file coverage with the mail-stack boundary.
- Execute dependency advisory and SBOM checks.
- Trigger and inspect security logging and alerting behavior.

### Slice 6, Closeout and Deployment

- Run `make security-check`, V13 gates, and release validation.
- Verify every slice commit signature.
- Publish through the protected-main pull-request workflow.
- Deploy the exact reviewed commit with retained rollback artifacts.
- Validate browser-facing GET paths, invalid Host handling, service health,
  logs, and deployed binary identity.

## Status

- Slice 1: implemented and validated.
- Slice 2: implemented and validated.
- Slice 3: implemented and validated.
- Slice 4: implemented and validated. It adds real Firefox execution for
  reflected and stored XSS, consistent enforced-CSP checks, MFA negative paths
  plus replay regressions, executable session timeout and race evidence, and
  two-hop request desynchronization probes that reject multiple responses.
- Slice 5: implemented and validated. It adds executable business workflow
  misuse regressions, safe EICAR detection through the configured Rspamd and
  ClamAV boundary, advisory and dependency-policy execution, CycloneDX SBOM
  generation, and host inspection of triggered security events.
- Slice 6: completed. Pull requests 33 through 37 passed their required
  repository and CodeQL checks, then merged to protected `main`. The final
  credentialed release run exercised the deployed application and exact
  host-side validation source.

## Release Closeout

- Final reviewed commit:
  `7009b15322c4e7795c797c1387b403e0f4935adb`.
- Production deployment session:
  `/home/foo/osmap-binary-deployment/v13-auth-availability-20260627T161226Z`.
- Production activation rollback session:
  `/home/foo/osmap-service-activation/v13-auth-availability-20260627T161336Z`.
- Live and staged binary SHA256:
  `333a417bf435ae74bfc2b7a9eebedeca1ad541cb527e2555fed408e11e24d963`.
- Rollback script:
  `/home/foo/osmap-binary-deployment/v13-auth-availability-20260627T161226Z/scripts/restore-binary-deployment.sh`.
- Authentication-timeout configuration restore script:
  `/home/foo/osmap-binary-deployment/v13-auth-availability-20260627T161226Z/config/scripts/restore-auth-timeout-config.sh`.
- Browser-facing validation passed for `GET /`, `GET /login`,
  `GET /healthz`, and invalid Host rejection with HTTP 421.
- Final deployed operational evidence passed for CSP, Host and request
  desynchronization, real-browser reflected and stored XSS, attachment
  containment, Rspamd and ClamAV malware detection, dependency and CycloneDX
  validation, and triggered security logging with redaction.

### Credentialed Release Evidence

- Release run: `osmap-wstg-20260627-204207`.
- Target: `https://mail.blackbagsecurity.com`.
- Result counts: 42 pass, 0 fail, 0 warning, 0 skip, and 4 justified
  not-applicable results.
- Release errors: none.
- Stable WSTG matrix: 97 scenarios, with 64 automated and 33
  not-applicable dispositions, 0 invalid or missing dispositions, and 0
  validation errors.
- Credential-backed proof observed successful TOTP validation, login, session
  issuance, protected-route access, logout, and post-logout invalidation.
- Live evidence included real-browser reflected and stored XSS execution
  checks, cross-account authorization isolation, source-attachment positive
  and tamper cases, draft and bulk mailbox workflows, safe EICAR detection,
  public-edge protocol probes, and host audit-event inspection.
- Summary JSON SHA256:
  `7f60024c71b9ff223bffa065357b0a6da28d5faf05cdfccabca7bdaeeffe44c8`.
- Markdown report SHA256:
  `748d5f817f52d7af1b5619fe53a0cfee9659559c34140b326757f58102915e63`.
- The authenticated response corpus remains local and is not committed to
  source control. The report and summary contain redacted evidence references,
  and every runner redaction check passed.

The release report retains explicit limitations for complete ASVS
verification, archive-recursion and document-sanitization testing, and
endpoint safety after attachment download. These are scope declarations, not
passing claims.
