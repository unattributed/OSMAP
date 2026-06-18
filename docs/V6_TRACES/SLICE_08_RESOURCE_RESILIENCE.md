# V6 Slice 08 Trace: Resource Resilience Proof

## Scope trace

- intended change: Add a fail-closed V6 validator for bounded failure,
  redaction, health availability, and recovery using live-safe methods.
- non-goals: No unsafe production saturation, async rewrite, worker-pool
  redesign, or broad denial-of-service claim.
- files inspected:
  - `maint/live/osmap-live-validate-v3-resource-controls.ksh`
  - `maint/live/osmap-live-validate-v6-observability.ksh`
  - `docs/REQUEST_WORKER_BUDGET_MODEL.md`
  - `docs/V6_SECURITY_GATES.md`

## Implementation trace

- files changed:
  - `maint/live/osmap-live-validate-v6-resource-resilience.ksh`
  - `maint/security/test-osmap-live-validate-v6-resource-resilience.sh`
  - `maint/security/osmap-security-check.sh`
  - `docs/V6_RESOURCE_RESILIENCE_EVIDENCE.md`
  - `docs/REQUEST_WORKER_BUDGET_MODEL.md`
  - `docs/KNOWN_LIMITATIONS.md`
  - `docs/V6_SECURITY_GATES.md`
  - `docs/DECISION_LOG.md`
  - `docs/V6_TRACES/SLICE_08_RESOURCE_RESILIENCE.md`
- behavior changed: The V6 validator requires production readiness, prior live
  evidence, health before and after the run, current capacity/budget/malformed/
  oversized/timeout regressions, and redaction before emitting passed markers.
- security boundaries preserved: The default does not saturate the multi-purpose
  production host; transient test output is scanned and discarded; reports
  contain no credentials, cookies, CSRF values, mailbox bodies, or attachment
  bodies. Dry-run reports are never closeout eligible.

## Test trace

- commands run:
  - `sh -n maint/live/osmap-live-validate-v6-resource-resilience.ksh`
  - `sh -n maint/security/test-osmap-live-validate-v6-resource-resilience.sh`
  - `sh maint/security/test-osmap-live-validate-v6-resource-resilience.sh`
  - `cargo test http_runtime`
  - `cargo test throttle`
  - `make security-check`
- local results:
  - both shell syntax checks passed.
  - the validator regression harness passed its positive, dry-run
    non-eligibility, and missing-production-evidence cases.
  - `cargo test http_runtime` completed successfully but matched 0 tests; the
    targeted `cargo test over_capacity_connections_receive_service_unavailable`
    passed 1 test and is the validator's capacity check.
  - `cargo test throttle` passed 19 matching tests.
  - `make security-check` passed 479 library tests with 4 documented live-host
    tests ignored, clippy, formatting, supply-chain checks, V4 assurance, V5
    carry-forward, all V6 validator harnesses including resource resilience,
    WSTG mapping, and the nested V3 fail-closed release test.
- live results, if applicable: No production pressure or V6 deployment was
  performed.
- skipped or blocked checks: The passed host report remains an operator action
  after deployment of the assessed V6 candidate.

## Evidence trace

- evidence files produced:
  - `docs/V6_RESOURCE_RESILIENCE_EVIDENCE.md`
  - validator regression fixtures generated only under a temporary directory
  - this trace
- redaction checks: Regression coverage proves dry-run non-eligibility and the
  validator scans transient output for secret and content markers.
- archive or checksum paths: Deferred to V6 closeout.

## Commit trace

- commit hash: The commit containing this trace is identified by the exact
  message below and will be indexed with its immutable hash in V6 closeout
  evidence.
- commit message: `add v6 resource resilience proof`

## Residual risk

- remaining limitation: The known host must run the validator after the V6
  candidate is deployed; deliberate saturation remains limited to isolated
  safe targets.
- next recommended action: Assemble closeout docs and the sanitized evidence
  archive while keeping V6 incomplete until all live reports pass.
