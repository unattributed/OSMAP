# V6 Slice 07 Trace: Explicit Source-Attachment Draft References

## Scope trace

- intended change: Preserve only explicit source-attachment selections across
  draft save and resume while retaining send-time re-fetch and validation.
- non-goals: No automatic reattachment, attachment preview, source-byte
  persistence, raw MIME persistence, or broader compose behavior.
- files inspected:
  - `src/draft.rs`
  - `src/send.rs`
  - `src/http_browser.rs`
  - `src/http_gateway_draft.rs`
  - `src/http/routes_compose.rs`
  - `src/http/routes_draft.rs`
  - `src/http_ui.rs`
  - `docs/V3_REPLY_FORWARD_ATTACHMENT_HANDLING_DESIGN.md`

## Implementation trace

- files changed:
  - `src/draft.rs`
  - `src/http.rs`
  - `src/http_browser.rs`
  - `src/http_gateway_draft.rs`
  - `src/http/routes_compose.rs`
  - `src/http/routes_draft.rs`
  - `src/http_ui.rs`
  - `docs/V3_REPLY_FORWARD_ATTACHMENT_HANDLING_DESIGN.md`
  - `docs/PILOT_WORKFLOW_INVENTORY.md`
  - `docs/KNOWN_LIMITATIONS.md`
  - `docs/DECISION_LOG.md`
  - `docs/V6_TRACES/SLICE_07_SOURCE_ATTACHMENT_DRAFTS.md`
- behavior changed: Draft version 2 metadata can store a bounded source mailbox,
  positive UID, and unique dotted numeric part paths. Save and resume require
  the selected paths to remain surfaced by the authenticated message view.
  Resume renders all current source controls but checks only saved selections;
  send re-fetches selected parts through the existing attachment gateway.
- security boundaries preserved: Source bytes and raw MIME are absent from
  metadata; owner-scoped draft loading, mailbox visibility, CSRF, same-origin,
  helper-backed retrieval, compose limits, forced download, and no-preview
  behavior remain intact.

## Test trace

- commands run:
  - `cargo test draft`
  - `cargo test send`
  - `cargo test http::`
  - `make security-check`
- local results:
  - `cargo test draft` passed 24 matching tests.
  - `cargo test send` passed 32 matching tests.
  - `cargo test http::` passed 176 matching tests.
  - `make security-check` passed 479 library tests with 4 documented live-host
    tests ignored, the main and V4 integration tests, clippy, formatting,
    supply-chain checks, V4 assurance, V5 carry-forward, V6 regression
    harnesses, WSTG mapping checks, and the nested V3 fail-closed release test.
- live results, if applicable: No V6 source code was deployed.
- skipped or blocked checks: Live selected-cohort proof remains a later
  operator action.

## Evidence trace

- evidence files produced: Source tests and this trace.
- redaction checks: Tests verify draft metadata contains references only and no
  source attachment bytes or MIME headers.
- archive or checksum paths: Deferred to V6 closeout.

## Commit trace

- commit hash: The commit containing this trace is identified by the exact
  message below and will be indexed with its immutable hash in V6 closeout
  evidence.
- commit message: `preserve explicit source attachment draft references`

## Residual risk

- remaining limitation: A moved, deleted, changed, or newly unauthorized source
  message intentionally blocks resume or send until the user corrects the
  draft.
- next recommended action: Add the V6 live-safe resource resilience validator.
