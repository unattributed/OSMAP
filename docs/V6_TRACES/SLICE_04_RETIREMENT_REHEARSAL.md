# V6 Slice 04 Trace: Retirement Rehearsal Recorder

## Scope trace

- intended change: Add the selected-cohort human rehearsal procedure and a
  sanitized recorder that fails closed on missing workflows, failed workflows,
  or Roundcube fallback.
- non-goals: The recorder does not automate credentials, TOTP, mailbox actions,
  or live user workflows and does not retire the rollback installation.
- files inspected:
  - V3 pilot rehearsal recorder and tests
  - `docs/MIGRATION_PLAN_ROUNDCUBE.md`
  - `docs/PILOT_WORKFLOW_INVENTORY.md`
  - V6 acceptance and security gates

## Implementation trace

- files changed:
  - `docs/V6_ROUNDCUBE_RETIREMENT_REHEARSAL.md`
  - `maint/live/osmap-live-record-v6-retirement-rehearsal.ksh`
  - `maint/security/test-osmap-live-record-v6-retirement-rehearsal.sh`
  - `maint/security/osmap-security-check.sh`
  - `docs/MIGRATION_PLAN_ROUNDCUBE.md`
  - `docs/PILOT_WORKFLOW_INVENTORY.md`
  - `docs/V6_ACCEPTANCE_CRITERIA.md`
  - `docs/V6_SECURITY_GATES.md`
  - `docs/DECISION_LOG.md`
  - `docs/V6_TRACES/SLICE_04_RETIREMENT_REHEARSAL.md`
- behavior changed: Operators can record a complete sanitized no-fallback
  rehearsal after the actual human walkthrough.
- security boundaries preserved: No credentials or mailbox content are
  accepted; aliases are sanitized; unsupported workflows remain cohort
  exclusions rather than pressure to widen OSMAP.

## Test trace

- commands run:
  - `sh -n maint/live/osmap-live-record-v6-retirement-rehearsal.ksh`
  - `sh -n maint/security/test-osmap-live-record-v6-retirement-rehearsal.sh`
  - `sh maint/security/test-osmap-live-record-v6-retirement-rehearsal.sh`
  - `make security-check`
- local results:
  - Recorder and regression harness passed shell syntax checks.
  - A complete mixed `passed` and `not_required_for_selected_cohort` fixture
    produced the required sanitized report.
  - Missing workflow confirmation, a failed workflow, Roundcube fallback, and
    an email-shaped cohort identifier all failed closed.
  - The report secret-marker scan passed.
  - `make security-check` passed with the recorder harness integrated.
- live results, if applicable: No selected-user rehearsal was performed locally.
- skipped or blocked checks: A passing closeout report requires an operator-run
  selected-cohort walkthrough on the deployed target.

## Evidence trace

- evidence files produced: Procedure, recorder, regression harness, and trace.
- redaction checks: Tests reject email-shaped cohort identifiers and scan the
  report for common credential, TOTP, cookie, and CSRF markers.
- archive or checksum paths: Deferred to V6 closeout.

## Commit trace

- commit hash: The commit containing this trace is identified by the exact
  message below and will be indexed with its immutable hash in V6 closeout
  evidence.
- commit message: `add v6 retirement rehearsal recorder`

## Residual risk

- remaining limitation: Human workflow truth cannot be inferred from local
  fixtures; the selected cohort must perform and attest the real rehearsal.
- next recommended action: Add operational observability and incident-evidence
  validation.
