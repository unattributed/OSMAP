# V6 Slice 01 Trace: Scope And Security Gates

## Scope trace

- intended change: Establish the authoritative V6 controlled Roundcube
  retirement readiness definition, acceptance criteria, roadmap, and security
  gates, and align the project status documents.
- non-goals: No runtime behavior, live host state, V4 evidence tuple, V5
  deployment record, or Roundcube service state is changed.
- files inspected:
  - `README.md`
  - `docs/README.md`
  - `docs/KNOWN_LIMITATIONS.md`
  - `docs/MIGRATION_PLAN_ROUNDCUBE.md`
  - `docs/DECISION_LOG.md`
  - `docs/V4_DEFINITION.md`
  - `docs/V4_SECURITY_GATES.md`
  - `docs/V5_BOUNDARY_HARDENING_EVIDENCE.md`
  - `docs/V5_PRODUCTION_DEPLOYMENT_COMPLETE.md`
  - `maint/security/osmap-doc-governance-guard.sh`
  - `maint/security/osmap-publication-guard.sh`

## Implementation trace

- files changed:
  - `README.md`
  - `docs/README.md`
  - `docs/KNOWN_LIMITATIONS.md`
  - `docs/MIGRATION_PLAN_ROUNDCUBE.md`
  - `docs/DECISION_LOG.md`
  - `docs/V6_DEFINITION.md`
  - `docs/V6_ACCEPTANCE_CRITERIA.md`
  - `docs/V6_ROADMAP.md`
  - `docs/V6_SECURITY_GATES.md`
  - `docs/V6_TRACES/SLICE_01_SCOPE.md`
- behavior changed: Documentation now defines V6 as selected-cohort
  no-Roundcube-fallback readiness rather than feature parity.
- security boundaries preserved: V4 hostile-content assurance, V5 identity and
  browser boundaries, helper-backed production access, split runtime, CSRF,
  configured Host policy, forced downloads, and typed HTML remain mandatory.

## Test trace

- commands run:
  - `sh -n maint/security/osmap-doc-governance-guard.sh`
  - `sh maint/security/osmap-doc-governance-guard.sh`
  - `sh maint/security/osmap-publication-guard.sh`
- local results:
  - Shell syntax validation passed.
  - Documentation governance guard passed, including oldest-to-newest decision
    log chronology.
  - Publication guard passed.
  - `git diff --check` passed.
- live results, if applicable: No live-host action was required or performed.
- skipped or blocked checks: None expected for this documentation slice.

## Evidence trace

- evidence files produced:
  - `docs/V6_DEFINITION.md`
  - `docs/V6_ACCEPTANCE_CRITERIA.md`
  - `docs/V6_ROADMAP.md`
  - `docs/V6_SECURITY_GATES.md`
  - `docs/V6_TRACES/SLICE_01_SCOPE.md`
- redaction checks: The documentation contains no credentials, TOTP values,
  cookies, CSRF values, mailbox content, raw private logs, or private host-only
  material.
- archive or checksum paths: Deferred to V6 closeout.

## Commit trace

- commit hash: The commit containing this trace is identified by the exact
  message below and will be indexed with its immutable hash in V6 closeout
  evidence.
- commit message: `define v6 controlled retirement readiness scope`

## Residual risk

- remaining limitation: The V5 carry-forward gate, V6 closeout gate, and live
  validators do not yet exist.
- next recommended action: Add the fail-closed V5 and V6 release-governance
  gates in Slice 02.
