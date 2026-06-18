# V6 Slice 02 Trace: Carry-Forward And Closeout Gates

## Scope trace

- intended change: Add executable V5 carry-forward and V6 retirement-readiness
  closeout gates without changing the historical V4 release tuple.
- non-goals: This slice does not create passing V6 live reports or claim V6
  completion.
- files inspected:
  - `Makefile`
  - `maint/security/osmap-security-check.sh`
  - `maint/security/osmap-release-check.sh`
  - `maint/security/osmap-v4-hostile-assurance-gate.sh`
  - `maint/security/osmap-v4-security-claim-matrix-gate.sh`
  - V5 evidence and typed HTML source files
  - `docs/BUILD_AND_RELEASE_PROCESS.md`
  - `docs/V6_SECURITY_GATES.md`
  - `docs/DECISION_LOG.md`

## Implementation trace

- files changed:
  - `Makefile`
  - `maint/security/osmap-security-check.sh`
  - `maint/security/osmap-v5-boundary-gate.sh`
  - `maint/security/test-osmap-v5-boundary-gate.sh`
  - `maint/security/osmap-v6-retirement-readiness-gate.sh`
  - `maint/security/test-osmap-v6-retirement-readiness-gate.sh`
  - `maint/security/test-osmap-install-hooks.sh`
  - `docs/BUILD_AND_RELEASE_PROCESS.md`
  - `docs/V6_SECURITY_GATES.md`
  - `docs/DECISION_LOG.md`
  - `docs/V6_TRACES/SLICE_02_GATES.md`
- behavior changed: `make v6-check` now fails closed unless V5 carry-forward
  and all V6 closeout evidence pass. Developer security checks exercise the
  gate parsers with synthetic fixtures.
- security boundaries preserved: The frozen V4 release tuple remains unchanged;
  V4 assurance is invoked by V6 closeout; V5 boundaries are independently
  checked; secret-bearing evidence is rejected.

## Test trace

- commands run:
  - `sh -n maint/security/osmap-v5-boundary-gate.sh`
  - `sh -n maint/security/test-osmap-v5-boundary-gate.sh`
  - `sh -n maint/security/osmap-v6-retirement-readiness-gate.sh`
  - `sh -n maint/security/test-osmap-v6-retirement-readiness-gate.sh`
  - `sh maint/security/test-osmap-v5-boundary-gate.sh`
  - `sh maint/security/test-osmap-v6-retirement-readiness-gate.sh`
  - `make security-check`
- local results:
  - All four new shell files passed syntax validation.
  - V5 boundary gate regression checks passed.
  - V6 retirement readiness gate regression checks passed.
  - The first full `make security-check` run exposed that the hook-install
    fixture did not copy the two new gate files. The fixture was updated and
    its focused regression test passed.
  - The final `make security-check` passed, including 472 library tests with 4
    existing live-host tests ignored, V4 hostile assurance, clippy, formatting,
    supply-chain checks, publication and documentation guards, and the new V5
    and V6 gate regression checks.
- live results, if applicable: No live report is produced by this slice.
- skipped or blocked checks: `make v6-check` is expected to fail until later
  slices and live-host evidence are complete.

## Evidence trace

- evidence files produced: Gate scripts, regression harnesses, and this trace.
- redaction checks: Synthetic secret fixtures are generated only under a
  temporary directory and removed by the test trap.
- archive or checksum paths: Deferred to V6 closeout.

## Commit trace

- commit hash: The commit containing this trace is identified by the exact
  message below and will be indexed with its immutable hash in V6 closeout
  evidence.
- commit message: `add v6 closeout gates`

## Residual risk

- remaining limitation: The required V6 live validators and reports do not yet
  exist, so the closeout gate cannot pass.
- next recommended action: Add the production readiness live validator and its
  parser regression tests.
