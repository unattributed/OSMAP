# V6 Slice 05 Trace: Operational Observability

## Scope trace

- intended change: Convert existing logging and incident-response expectations
  into a sanitized, fail-closed V6 evidence validator.
- non-goals: This slice does not add a telemetry framework, copy raw logs into
  the repository, or trigger unsafe production pressure.
- files inspected:
  - auth, session, send, helper, and HTTP event call sites
  - the existing auth observability validator
  - `docs/OBSERVABILITY_AND_MONITORING.md`
  - `docs/INCIDENT_RESPONSE_PLAN.md`
  - `docs/LOGGING_AND_ERROR_MODEL.md`

## Implementation trace

- files changed:
  - `maint/live/osmap-live-validate-v6-observability.ksh`
  - `maint/security/test-osmap-live-validate-v6-observability.sh`
  - `maint/security/osmap-security-check.sh`
  - `docs/V6_OBSERVABILITY_EVIDENCE_MODEL.md`
  - `docs/OBSERVABILITY_AND_MONITORING.md`
  - `docs/INCIDENT_RESPONSE_PLAN.md`
  - `docs/LOGGING_AND_ERROR_MODEL.md`
  - `docs/V6_SECURITY_GATES.md`
  - `docs/DECISION_LOG.md`
  - `docs/V6_TRACES/SLICE_05_OBSERVABILITY.md`
- behavior changed: Operators can validate minimum security event visibility,
  safe log metadata, redaction, and reviewability as a V6 closeout input.
- security boundaries preserved: Reports contain no raw log excerpts or private
  content; session correlation remains `session_ref`; no new telemetry
  dependency is added.

## Test trace

- commands run:
  - `sh -n maint/live/osmap-live-validate-v6-observability.ksh`
  - `sh -n maint/security/test-osmap-live-validate-v6-observability.sh`
  - `sh maint/security/test-osmap-live-validate-v6-observability.sh`
  - `make security-check`
- local results:
  - Validator and regression harness passed shell syntax checks.
  - A complete normalized event fixture produced all required passed markers.
  - Removing session revocation evidence failed closed.
  - Adding a raw password marker to the serve log failed redaction.
  - The adjusted production-readiness log-permission check still passed its
    regression harness.
  - `make security-check` passed with the V6 observability harness integrated.
- live results, if applicable: Not run against current OpenBSD logs locally.
- skipped or blocked checks: A passing report requires current host logs and
  explicit operator review.

## Evidence trace

- evidence files produced: Evidence model, validator, regression harness, and
  trace.
- redaction checks: The validator scans both logs and the tests prove a raw
  password marker fails closed.
- archive or checksum paths: Deferred to V6 closeout.

## Commit trace

- commit hash: The commit containing this trace is identified by the exact
  message below and will be indexed with its immutable hash in V6 closeout
  evidence.
- commit message: `prove v6 operational observability`

## Residual risk

- remaining limitation: Current live event coverage and operator review are not
  yet recorded for the V6 assessed deployment.
- next recommended action: Implement cross-process session-store locking.
