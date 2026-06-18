# V6 Slice 03 Trace: Production Readiness Validator

## Scope trace

- intended change: Add a fail-closed, sanitized live validator for selected
  cohort production readiness on the known OpenBSD host or an equivalent
  target.
- non-goals: The validator does not deploy, restart, reconfigure, or pressure
  the live service, and this local slice does not create a passing host report.
- files inspected:
  - existing service-enablement, exposure, and edge validators
  - `docs/DEPLOYMENT_OPENBSD.md`
  - `docs/MAIL_HOST_BINARY_DEPLOYMENT_SOP.md`
  - `docs/MAIL_HOST_SERVICE_ENABLEMENT_SOP.md`
  - `docs/V5_PRODUCTION_DEPLOYMENT_COMPLETE.md`
  - `docs/V6_SECURITY_GATES.md`

## Implementation trace

- files changed:
  - `maint/live/osmap-live-validate-v6-production-readiness.ksh`
  - `maint/security/test-osmap-live-validate-v6-production-readiness.sh`
  - `maint/security/osmap-security-check.sh`
  - `docs/DEPLOYMENT_OPENBSD.md`
  - `docs/MAIL_HOST_BINARY_DEPLOYMENT_SOP.md`
  - `docs/MAIL_HOST_SERVICE_ENABLEMENT_SOP.md`
  - `docs/V6_SECURITY_GATES.md`
  - `docs/DECISION_LOG.md`
  - `docs/V6_TRACES/SLICE_03_PRODUCTION_READINESS.md`
- behavior changed: Operators can produce a sanitized readiness report;
  developer security checks now exercise positive and fail-closed parser paths.
- security boundaries preserved: No secret env values or logs are copied;
  backend ports must remain non-public; configured Host and `421` rejection are
  mandatory; rollback includes both binary and environment.

## Test trace

- commands run:
  - `sh -n maint/live/osmap-live-validate-v6-production-readiness.ksh`
  - `sh -n maint/security/test-osmap-live-validate-v6-production-readiness.sh`
  - `sh maint/security/test-osmap-live-validate-v6-production-readiness.sh`
  - `make security-check`
- local results:
  - Validator and regression harness passed shell syntax checks.
  - Regression checks passed for a complete report and failed closed for
    missing service health, invalid-host status other than `421`, and a missing
    rollback artifact.
  - The generated positive fixture report passed the forbidden secret-marker
    scan.
  - `make security-check` passed with the V6 production readiness regression
    harness integrated.
- live results, if applicable: Not run on the OpenBSD target in this slice.
- skipped or blocked checks: A real passing report remains blocked on
  host-side operator execution.

## Evidence trace

- evidence files produced: Validator, regression harness, and this trace.
- redaction checks: The regression harness verifies the good report excludes
  password, TOTP, CSRF, OSMAP cookie, and cookie-header markers.
- archive or checksum paths: Deferred to V6 closeout.

## Commit trace

- commit hash: The commit containing this trace is identified by the exact
  message below and will be indexed with its immutable hash in V6 closeout
  evidence.
- commit message: `add v6 production readiness validator`

## Residual risk

- remaining limitation: The repository does not yet contain a current passing
  report from the selected OpenBSD target.
- next recommended action: Add the selected-cohort no-Roundcube-fallback
  rehearsal recorder.
