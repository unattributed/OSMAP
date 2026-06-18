# V6 Slice 06 Trace: Cross-Process Session Store Locking

## Scope trace

- intended change: Serialize file-backed session operations across processes
  sharing one session directory with a restrictive advisory lock.
- non-goals: No distributed, cross-host, database, remembered-device, or
  anomaly-scoring system is introduced.
- files inspected:
  - `src/session.rs`
  - `src/openbsd.rs`
  - `src/lib.rs`
  - `Cargo.toml`
  - `docs/SESSION_MANAGEMENT_MODEL.md`
  - `docs/KNOWN_LIMITATIONS.md`

## Implementation trace

- files changed:
  - `src/session.rs`
  - `src/openbsd.rs`
  - `maint/security/osmap-v6-retirement-readiness-gate.sh`
  - `docs/SESSION_MANAGEMENT_MODEL.md`
  - `docs/KNOWN_LIMITATIONS.md`
  - `docs/DECISION_LOG.md`
  - `docs/V6_TRACES/SLICE_06_SESSION_LOCKING.md`
- behavior changed: File-backed save, load, list, issue, validate, revoke,
  revoke-all, and timeout-update paths acquire one store-local exclusive
  advisory lock around complete operations.
- security boundaries preserved: Lock failure fails closed; lock mode is
  `0600`; raw tokens and CSRF values remain unlogged; atomic record replacement
  and V5 identity validation remain intact.

## Test trace

- commands run:
  - `cargo test session`
  - `cargo test auth::tests::`
  - `cargo test identity`
  - `make security-check`
- local results:
  - `cargo test session` passed 47 matching tests, including restrictive lock
    permissions, lock acquisition failure, validation/revocation races, and
    cross-store revoke-all/validation serialization.
  - `cargo test auth::tests::` passed 22 tests with 1 existing live-host test
    ignored.
  - `cargo test identity` passed 3 tests.
  - `make security-check` passed, including clippy, formatting, V4 assurance,
    supply-chain checks, unsafe-boundary enforcement, and all V6 regression
    harnesses.
- live results, if applicable: No overlapping live process was started.
- skipped or blocked checks: Current deployment evidence must still prove the
  assessed binary was installed normally.

## Evidence trace

- evidence files produced: Source tests and this trace.
- redaction checks: No bearer token, cookie, CSRF value, credential, or mailbox
  content is added to logs or evidence.
- archive or checksum paths: Deferred to V6 closeout.

## Commit trace

- commit hash: The commit containing this trace is identified by the exact
  message below and will be indexed with its immutable hash in V6 closeout
  evidence.
- commit message: `add cross process session store locking`

## Residual risk

- remaining limitation: Advisory locking coordinates only cooperating
  processes that share one local session directory; it is not distributed.
- next recommended action: Preserve explicit source-attachment draft references
  without persisting source bytes.
