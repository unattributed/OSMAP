# V6 Slice 00 Trace: Baseline Review

## Scope trace

- intended change: Record the repository, toolchain, evidence, and known-gap
  baseline for the controlled Roundcube retirement readiness milestone without
  changing runtime behavior.
- non-goals: No product behavior, deployment artifact, release gate, or live
  host state is changed by this slice.
- files inspected:
  - `README.md`
  - `docs/KNOWN_LIMITATIONS.md`
  - `docs/MIGRATION_PLAN_ROUNDCUBE.md`
  - `docs/OBSERVABILITY_AND_MONITORING.md`
  - `docs/INCIDENT_RESPONSE_PLAN.md`
  - `docs/V4_CLOSEOUT_EVIDENCE.md`
  - `docs/V4_SECURITY_CLAIM_MATRIX.md`
  - `docs/V5_BOUNDARY_HARDENING_EVIDENCE.md`
  - `docs/V5_PRODUCTION_DEPLOYMENT_COMPLETE.md`
  - `Makefile`
  - `maint/security/osmap-release-check.sh`
  - `maint/security/osmap-security-check.sh`
  - `src/session.rs`
  - `src/draft.rs`
  - `src/http.rs`
  - `src/http/routes_compose.rs`
  - `src/http/routes_draft.rs`

## Implementation trace

- files changed: `docs/V6_TRACES/SLICE_00_BASELINE.md`
- behavior changed: None.
- security boundaries preserved:
  - The V4 hostile-content evidence and gate remain unchanged.
  - The V5 canonical identity, configured Host, same-origin, response-header,
    strict framing, plain-text response, and typed HTML boundaries remain
    unchanged.
  - The `_osmap` and `vmail` split-runtime and helper-backed production posture
    remain unchanged.
  - The baseline confirms the file-backed session service currently uses a
    process-local mutex and therefore does not yet close the cross-process
    locking limitation.
  - The baseline confirms draft persistence stores uploaded attachment bytes
    but does not yet preserve explicit source-attachment references across
    resume.

## Test trace

- commands run:
  - `git status --short`
  - `find docs -maxdepth 1 -type f -name 'V6*' -print`
  - `wc -l src/*.rs src/http/*.rs tests/*.rs | sort -nr | head -60`
  - `rustc --version`
  - `cargo --version`
  - `cargo test`
- local results:
  - Starting branch state was clean at
    `93de442c0615a186d6487f29fc606c005c3844be`.
  - The dedicated branch is
    `feature/v6-controlled-retirement-readiness`.
  - No pre-existing top-level V6 documentation was present.
  - The inspected Rust and integration-test files total 45,029 lines.
  - `rustc 1.94.1` and `cargo 1.94.1` are available.
  - `cargo test` passed: 472 library tests passed and 4 host-dependent tests
    were ignored; 1 main test passed; 1 V4 hostile-assurance integration test
    passed; 1 compile-fail doctest passed.
- live results, if applicable: No live-host action was required or performed.
- skipped or blocked checks:
  - Four existing tests requiring a configured live Dovecot host were ignored
    by their existing test annotations.
  - V6 live evidence is intentionally deferred to the live-validator slices.

## Evidence trace

- evidence files produced: `docs/V6_TRACES/SLICE_00_BASELINE.md`
- redaction checks: The trace contains no credentials, TOTP values, cookies,
  CSRF values, mailbox content, raw private logs, or private host-only
  configuration.
- archive or checksum paths: Not applicable to the baseline slice.

## Commit trace

- commit hash: The commit containing this trace is identified by the exact
  message below and will be indexed with its immutable hash in V6 closeout
  evidence.
- commit message: `record v6 baseline review`

## Residual risk

- remaining limitation:
  - V6 scope and acceptance gates are not yet authoritative repo documents.
  - Cross-process session-store locking remains open.
  - Explicit source-attachment selections do not survive draft resume.
  - Production readiness, retirement rehearsal, observability, and resource
    resilience still require sanitized live evidence.
- next recommended action: Define the authoritative V6 scope, acceptance
  criteria, roadmap, and security gates in Slice 01.
