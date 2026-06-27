# V13 WSTG Assurance Integrity and Adversarial Validation

## Purpose

V13 turns the WSTG testing pack from a broad regression checklist into a
fail-closed assurance system whose claims distinguish dynamic proof, static
evidence, manual review, and not-applicable decisions.

V13 is intentionally isolated from the concurrently developed V12 OpenPGP
work. It is based on the reviewed `origin/main` V11 baseline and does not
modify V12 files or make OpenPGP claims.

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
- Slices 4 through 6: pending.
