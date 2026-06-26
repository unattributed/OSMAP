# V11 Runtime Fail-Closed Closure

## Purpose

V11 closes the refined high-relevance runtime assumption queue carried forward by V10 Slice 5.

This is a runtime hardening sprint. It does not add product surface, widen the V9 selected-cohort release-candidate claim, change production deployment state, or claim broad public release readiness.

## Assessed Source

- Branch: `codex/compose-cc-bcc`
- Baseline gate: `make v10-check`
- Baseline Rust tests: `cargo test`
- V10 refined high-relevance files before V11 code changes:
  - `src/http_gateway_mail.rs`
  - `src/http_mailbox_backends.rs`
  - `src/rendering.rs`

## Slice 1, Evidence Reconciliation

V10 prose records were reconciled with the refreshed machine registers:

- current scanner count: `722`
- high-relevance assumptions before refinement: `644`
- refined high-relevance assumptions after V11 remediation: `0`
- source test-module assumptions classified as test or fixture assumptions: `645`
- refined test or fixture assumptions: `721`

The authoritative machine records are:

- `maint/security/v10-rust-assumption-audit.json`
- `maint/security/v10-fail-closed-remediation.json`
- `maint/security/v10-claims-boundary.json`

## Slice 2, Helper Grant Key Fail-Closed Runtime Behavior

The helper-backed browser runtime no longer assumes that a helper socket implies a grant key path.

When a helper socket is configured without a grant key path, mailbox backends now return an explicit `MailboxBackendError` with:

- backend: `mailbox-helper-config`
- reason: `mailbox helper socket configured without grant key path`

This applies to:

- mailbox listing
- message listing
- message search
- message view
- message move
- Sent append

The attachment-download helper path now fails closed with public reason `temporarily_unavailable` and audit reason `mailbox_helper_grant_key_path_missing`.

## Slice 3, Rendering Header Decode Assumption Removal

The RFC 2047 encoded-header fallback loop no longer uses a runtime assertion for character-boundary progress. The fallback is explicit and safe if an empty suffix is ever observed.

Existing rendering regression coverage remains responsible for hostile HTML, malformed MIME, unsupported charset, encoded header, and selected HTML/plain rendering behavior.

## Gate Evidence

V11 closure requires:

1. `make v10-check` passes.
2. `cargo test helper_grant_key_path_is_missing` passes.
3. `cargo test decodes_q_encoded_header_summary_values` passes.
4. `python3 -B maint/security/osmap-v10-fail-closed-remediation.py --check maint/security/v10-fail-closed-remediation.json` passes.
5. `maint/security/v10-fail-closed-remediation.json` records `high_relevance_after` as `0`.

## Non-Claims

V11 does not claim:

- broad public release readiness,
- complete Roundcube replacement,
- general hostile-email safety,
- malware prevention,
- production deployment change,
- live-host validation refresh,
- panic-free test code,
- removal of all low or medium relevance test, fixture, startup, or control-flow assumptions.
