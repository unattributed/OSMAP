# S06-03: bounded transient decryption and accurate failure states

## Current consolidated result — 2026-11-03

The engineering, matching native qualification and installation for this slice
are complete in the consolidated S06 delivery. The final integrated reader,
exact attachment download and original encrypted-source view passed the owner
check; the owner explicitly accepted S06-04 on2026-11-03. See the
[accepted integrated closeout](UX_SLICE_S06_04.md#accepted-closeout--2026-11-03).
Engineering checkpoint0866340 and accepted-closeout commitef41693 are signed
and synchronized to the approved UX branch. The installed Web is
`c569fbc4eeeb284911ed683fc73fc659c5a52d7610e8da3969d92f61c92f6a53`.

The earlier pending-install, locked-key, owner-check and publication statements
below describe historical checkpoints; they are superseded by the completed
consolidated result. Preserve their failures and evidence. No additional S06
engineering, native run, deployment or owner technical check is identified.
This records the accepted integrated result without inventing a separate
individual owner acceptance for this foundational slice. Broader epic visual,
keyboard, network and production-release obligations remain separately tracked.


Continue the owner's 2026-11-02 instruction through S06. S06-01/02 source/native corrections are qualified; their final installation is carried into the consolidated S06 deployment. Use the existing authenticated Rust client/Processor, isolated GPGME worker and renderer. No new cryptography, mailbox protocol or private-key interface.

## Practical result and eventual owner check

The source/native result preserves useful decryption: supported self-encrypted mail yields readable Unicode text and exact binary attachment bytes through safe rendering, while its original source stays encrypted and no automatic plaintext quote is retained. Malformed and truncated ciphertext now reach an unsupported-format explanation instead of an unavailable-service explanation. Proven missing private material remains a distinct refusal. For recipient-hidden ciphertext, an opaque `Unavailable` result remains uncertain and releases no content; OSMAP does not invent a more specific cause.

After consolidated installation and agent-owned installed checks, the owner must unlock the existing protected key through the operator-controlled workflow and open a real encrypted message in Inbox or Sent. The practical acceptance is readable expected content, a working expected attachment, accurate decryption-location/status text and no unexpected plaintext carry-over into a reply or forward. The operator supplies any passphrase privately; the agent does not capture it. The observed unavailable owner agent means this body test remains pending. Synthetic decryption success, public-key inventory and ordinary login do not replace it.

Required outcome: correct bounded plaintext reaches transient safe processing only for the authenticated account and permitted key. Missing/wrong/locked keys, malformed or truncated ciphertext and cancellation/timeouts release no partial body, attachment or automatic draft quote. Plaintext never enters persistent application state, logs, evidence or a cache. Actual decryption occurs in the local isolated helper on the OSMAP server; the browser receives displayed plaintext over HTTPS. Preserve the approved summary label while explaining that execution location accurately.

Reuse matching S05 actual decrypt/verify/hostile-HTML/binary/wrong-key/Locked and owned-cancellation proofs. Add the smallest real malformed/truncated-ciphertext discriminator and positive self-decryption control in the existing Rust native actor. A source-grounded format/error mapping may change only after an actual failure. Keep valid plaintext/binary/UTF8 support and no downgrade. Exercise a real owned locked-agent negative if the existing fixture supports it without changing the cleanup architecture; otherwise retain the matching prior proof explicitly.

| Test | Required observation |
| --- | --- |
| T01 Profile/prerequisites | Reconcile actual helper, mailbox/body bounds, matching prior proofs and current owner key readiness without assuming public inventory proves private readiness. |
| T02 Real decryption | Valid self-encrypted MIME decrypts and safely processes; wrong account/key cannot release it; UTF8 and binary content remain exact. |
| T03 Invalid ciphertext | Actual malformed/truncated input releases no content and reaches a truthful typed refusal; preserve RED/correction/GREEN if a gap is found. |
| T04 Locked/missing key | Actual locked and missing-private-key results remain distinct from missing public signer and invalid format; no prompt or automatic warm-up. |
| T05 Bounded lifecycle | Preserve current size/time/IPC cancellation bounds and exact owned cleanup; reuse matching actual proofs rather than repeat unchanged broad suites. |
| T06 Execution/privacy | Reader explains decryption on this OSMAP server and HTTPS delivery; no browser-only/zero-access claim or persistent decrypted quote. |
| T07 Native preservation | Existing fixed principals/synthetic keys, no OS account changes, owned cleanup, source/public/private/trust and installed/public-mail preservation. |
| T08 Installed boundary | Qualify final installed worker/helper/Runtime and real public/private readiness boundary with no owner secret entry or external send. |
| T09 Review/delivery/owner | Independent results/source review, normal signed delivery and distinct owner acceptance, including required owner body test after operator unlock. |

Root owns production correction, UI copy, integration and one compiler/native/host/Git queue. Runtime engineer owns the minimal existing native actor/Processor test extension; QA owns focused reader-copy regression; independent auditor reviews actual producer/consumer, failure release, cleanup and results. No system account administration, Python principal actors, UID-wide signals, owner credentials/keys/policy mutation or public mail-service management. No passphrase is captured, supplied or guessed.

Read-only installed evidence identifies the configured signing/decryption subkeys and confirms their private files are passphrase protected, helper-owned0600; the existing agent is unavailable. D03/R3 reserve private passphrase entry to the operator. This is an actual owner-readiness dependency, not a reason to halt independent engineering or invent permission gates. Keep it explicit and do not replace owner-body success with fixture success.

Proven compiler profile: jobs1/debug0/privateTMP/core0/DATAsoft4GiB,600seconds per compiler action. Native action360seconds plus15termination with cleanup inside; short runtime paths, exact owned resources, no release-string predicate/RAM floor/elapsed-authority expiry/new QA framework. Preserve cumulative failures and independently reassess after two failures at one functional boundary. Evidence: /home/foo/Downloads/osmap-ux-s06/s06-03/.

## Actual source/native result, 2026-11-02

The first actual native run failed in 8.66 seconds: malformed and truncated ciphertext returned `Unavailable`, while positive decryption/privacy checks and owned cleanup passed. The worker error-mapping correction then ran in 8.63 seconds: both invalid-ciphertext cases correctly returned `Unsupported` / `UnsupportedCrypto`, but the test still failed because it expected a proven missing private key from an opaque hidden-recipient failure. Preserve both failed runs (`native-red*` and `native-green*`); the latter is not an overall GREEN.

Combined root/independent reassessment retained production recipient-identity hiding and added a fixture-only visible-recipient control in the existing Alice home. Its explicit RFC4880/AES256 ciphertext first decrypted byte-exactly for Alice, then produced actual `MissingKey` in both the native crypto service and Bob's Processor. The existing production-style hidden-recipient case remained `Unavailable` with safe refusal; neither the result nor its cause is promoted to missing-key certainty. A wrong requested key was refused by Client outcome validation (`Invalid`), not by a new server authorization rule.

The final exact `openpgp_principal_native_tests::native_decryption_classification` run passed in 9.07 seconds: one actual test, zero failures, owned cleanup PASS and no unconfirmed owned PIDs. Actual self-decryption, UTF8 rendering, sanitization, binary attachment bytes, preserved original ciphertext and empty automatic compose quote passed. Malformed/truncated inputs returned `Unsupported` / `UnsupportedCrypto` with safe refusal. Public/private/trust fixture manifests and account/installed/public-mail preservation were qualified within this synthetic fixed-principal scope. Matching S05 Locked and lifecycle proofs are reused; this run did not manipulate an owner agent or prove secure erasure.

| Qualified artifact | SHA-256 |
| --- | --- |
| Final Rust build input | `77dff06ebe5ac10eed4ae2e22d82aafd1aabbe3d82c0ccf537701129e01317a5` |
| Final native library-test executable | `99b3941342f0b48dd147033867789e49b8fd3576f63bfb4fb23ff1ac65dc10a2` |
| Corrected worker source (`crypto-green.c`) | `021ca1d4973d5ab769c2142a640fd7025df7d6d0cbf7741569d8343b7fd3ac6f` |
| Actual crypto worker | `adab695fe2f8d6dab8d687ee92eb74bed1ae2d493756f11a48947c6afb9a9052` |
| Reused authenticated crypto helper | `f020b4f7d7e16fc387589993f82e7ad0efea404cf705e73e6056fb8046f6b952` |

The private evidence root above retains `native-final-observation.json`, `native-final-receipt.json`, `native-final.actual.log` and the producer/dispatch pins. Independent review (`native-independent-review.json`, SHA-256 `7a8e9f1177ff215215e962747e262255600d2033c29bf2759dbad672fccf0c00`) concludes scoped source/native qualification. Consolidated installation, final normal signed delivery and owner acceptance remain pending. The owner's configured private key remains passphrase protected with its agent unavailable; operator-controlled passphrase entry and a subsequent real owner-body test remain necessary. Synthetic fixture success does not discharge that dependency.

## Consolidated qualification checkpoint, 2026-11-02

The final matching native reader/signature/decryption cases and guarded obsd1 Web/worker installation pass. Actual installed public encryption and current signed epoch admission pass; private operation returns typed `Locked`, so owner private readiness and body UAT remain unperformed. The earlier pending-install wording above describes its historical source/native checkpoint. See [S06-04 actual results and minimal owner UAT](UX_SLICE_S06_04.md#observed-engineering-and-installed-result) for artifact identities, preservation, independent review, failed attempts and scope. Normal signed delivery is in progress; no human acceptance or production release is inferred.
