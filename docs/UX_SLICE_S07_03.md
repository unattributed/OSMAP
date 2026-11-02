# S07-03: Encryption and sign-then-encrypt, encrypt-to-self and privacy-aware Bcc envelope handling

The owner authorizes independent completion of every S07 slice with later review. Reuse the existing Rust product path, current native worker, disposable synthetic keys/accounts, existing private Dovecot fixture and controlled Rust loopback transport. No new cryptography, dependency, generic QA framework or production mail-system changes.

Inspect and reuse current code and matching evidence; reproduce the demonstrated missing boundary; make the smallest correction; verify the actual composed result and deliver signed source through normal hooks. Functional assertions and actors use Rust. Existing shell orchestration and repository metadata validators remain.

- T01: Inspect/reuse existing encryption and envelope path.
- T02: Decrypt for visible recipient and hidden recipient.
- T03: Refuse excluded sender with signing positive control.
- T04: Add explicit self and prove successful decryption.
- T05: Independently verify inner signature and attachment.
- T06: Inspect public ciphertext PKESK IDs; no Bcc header leak.
- T07: Refuse missing helper or stale inventory without downgrade.
- T08: Consolidated native and installed review.
- T09: Owner acceptance after normal signed delivery.

Source, native, installed and owner acceptance remain separate. Scope: private fixture account/key/config/message state only. Never replay owner credentials or passphrases; do not alter owner account, policy, keys, mail or sessions. Never stop/reload or configure public Dovecot, Postfix or MariaDB. No production mailbox synchronization or external recipient send.

The existing signed/encrypted native gateway case previously captured Sent in a test file and preloaded its reader fixture. S07 extends that exact fixture so the production gateway append performs actual scoped doveadm save before independent retrieval. Outer storage CRLF-to-LF normalization is expected; ciphertext payload must remain identical. Editable/recovery authored drafts are an existing private policy, not a claim of no plaintext application state.

Independent protocol review precedes native dispatch. Preserve original failures separately from cleanup. After two failures at one boundary stop retries for combined independent reassessment. Existing exact-owned process and agent cleanup remains; no owner private operation.

## Engineering qualification — 2026-11-03

The existing encryption, sign-then-encrypt, self and envelope code were reused. OpenBSD proof decrypts for visible and hidden recipients, refuses the excluded sender with paired signing/self positive controls, and verifies the signed inner entity. Public packet inspection confirms two PKESK packets with zero recipient key IDs, while no Bcc header is emitted. This does not claim traffic-analysis anonymity. Current policy/key/helper refusals do not downgrade.

Engineering source/native verification passes; shared Web-only installation is pending signed admission and owner T09 acceptance is pending later review. The exact consolidated build/native hashes, actual test results, preservation, failure history and remaining limits are recorded once in [S07-04](UX_SLICE_S07_04.md#engineering-qualification--2026-11-03). No production-release or full approved-control acceptance is inferred.
