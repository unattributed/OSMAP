# S07-02: PGP/MIME signing and independent verification of emitted message

## Owner acceptance — 2026-11-03

**S07-01–04 ACCEPTED; T01–T09 PASS within the delivered sprint scope.** Owner reported personal-key unlock success and supplied Sent evidence of a cryptographically valid signature/public certificate, followed by Hotmail receipt with readable content and openpgp-public-key.asc. Owner explicitly states: Record your successful UAT = PASS “S07 accepted” (2026-11-03, Asia/Bangkok).

The earlier signing failure is resolved. Existing scoped native proofs remain the evidence for encryption, self, Bcc, policy, Sent and negative cases; the screenshots do not independently retest all those cases. Sprint functional acceptance only; earlier failures retained. No new full visual/keyboard/reference-matrix, cross-platform or production-release security qualification. Optional 24-hour unlock remains proposed; current eight-hour policy unchanged.

Accepted engineering source: signed e99455d84a253bc301364f9fe48a27eb6880fda8. Installed delivery record: signed 12b3da5c19af31be3e73cc8b3252a269cba2397c. This is a records-only closeout; no host/account/key/session/message/service changes. Pending/failure statements below remain historical checkpoints.

## Current owner UAT followup

Signed-send owner UAT is unaccepted after a Locked sender-private-key refusal. Public binding alone does not establish signing availability. This followup adds the missing sender public certificate within signed MIME and clarifies the public-only pre-check. Current focused Rust/native qualification and coordinated helper/worker/Web delivery pass. Installed account-bound public export/readback under the actual Web principal passes. Owner private-key unlock and successful signed-send acceptance remain pending; the300-second cache policy is unchanged. Existing earlier evidence below is historical and retains its narrower scope. See the signed-send followup in S07-04.

## Current delivery result — installed, owner review pending

This slice's agent-owned engineering and matching shared Web deployment are complete. T01–T08 pass within the documented scope; owner T09 and broader visual/keyboard/final-reference acceptance remain pending. The qualified Web8d2e2813 is installed on obsd1 after complete normal signed source publication. See [S07-04 current delivery](UX_SLICE_S07_04.md#current-delivery-result--installed-owner-review-pending) for exact source/build identities, actual installation and preservation evidence. Earlier pending statements below remain historical; no separate owner acceptance is invented.

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
