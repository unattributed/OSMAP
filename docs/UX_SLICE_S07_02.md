# S07-02: PGP/MIME signing and independent verification of emitted message

The owner authorizes independent completion of every S07 slice with later review. Reuse the existing Rust product path, current native worker, disposable synthetic keys/accounts, existing private Dovecot fixture and controlled Rust loopback transport. No new cryptography, dependency, generic QA framework or production mail-system changes.

Inspect and reuse current code and matching evidence; reproduce the demonstrated missing boundary; make the smallest correction; verify the actual composed result and deliver signed source through normal hooks. Functional assertions and actors use Rust. Existing shell orchestration and repository metadata validators remain.

- T01: Inspect/reuse actual signing path.
- T02: Verify disposable-key detached signature independently.
- T03: Reject tampered signed entity.
- T04: Preserve UTF-8 binary attachment and line endings.
- T05: Refuse missing signer without successful signed claim.
- T06: Keep wire and Sent protected; authored recovery draft remains private.
- T07: Qualify current native crypto worker.
- T08: Consolidated native and installed review.
- T09: Owner acceptance after normal signed delivery.

Source, native, installed and owner acceptance remain separate. Scope: private fixture account/key/config/message state only. Never replay owner credentials or passphrases; do not alter owner account, policy, keys, mail or sessions. Never stop/reload or configure public Dovecot, Postfix or MariaDB. No production mailbox synchronization or external recipient send.

The existing signed/encrypted native gateway case previously captured Sent in a test file and preloaded its reader fixture. S07 extends that exact fixture so the production gateway append performs actual scoped doveadm save before independent retrieval. Outer storage CRLF-to-LF normalization is expected; ciphertext payload must remain identical. Editable/recovery authored drafts are an existing private policy, not a claim of no plaintext application state.

Independent protocol review precedes native dispatch. Preserve original failures separately from cleanup. After two failures at one boundary stop retries for combined independent reassessment. Existing exact-owned process and agent cleanup remains; no owner private operation.

## Engineering qualification — 2026-11-03

The existing signing and MIME construction were reused. Actual disposable-key signing and independent verification pass on OpenBSD, including tamper refusal, UTF-8, binary attachment bytes and canonical line endings. A refused signing operation cannot produce successful signed-send evidence. The selected test capture actor now uses Rust; no new cryptography or runtime backend was introduced.

Engineering source/native verification passes; shared Web-only installation is pending signed admission and owner T09 acceptance is pending later review. The exact consolidated build/native hashes, actual test results, preservation, failure history and remaining limits are recorded once in [S07-04](UX_SLICE_S07_04.md#engineering-qualification--2026-11-03). No production-release or full approved-control acceptance is inferred.
