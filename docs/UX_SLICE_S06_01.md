# S06-01: bounded PGP/MIME and stored signed-byte integrity

Authorised 2026-11-02 (Asia/Bangkok), after accepted S05-04. The owner authorises thorough S06 engineering in frozen slice order while away. Continue signed engineering checkpoints under the plan's autonomous mandate; preserve separate human acceptance and do not infer it from tests.

## Practical result and eventual owner check

The source/native correction prevents OSMAP from labelling a transformed stored message as verified. Supported encoded signed mail still verifies, including the exercised Unicode/binary parts, folded headers and newline cases. Ordinary Unicode mail, Unicode outer headers and decrypted Unicode content continue to work. An unsupported protected body is refused with an explanation and no protected-content display.

After consolidated installation, the practical owner check is to open an existing supported signed message and ordinary Unicode mail, confirm readable content and the appropriate protection status, and inspect the source view's limits on reconstructed source. The agent-owned malformed-byte fixture proves the refusal case; the owner need not alter a mailbox, key or credential to recreate it. This supports the current bounded encoded-message profile, not arbitrary binary protected-body transport or a claim to preserve the original SMTP wire. Installed qualification and owner acceptance remain separate and pending.

## Observable outcome and source boundary

OSMAP recognises supported protected MIME within its actual mailbox-fetch limits and passes the correct canonical signed entity to verification. Unsupported or altered transport cannot produce a successful protected-reader assessment. Original stored representation stays distinct from the allocated canonical verification input; no full SMTP wire-fidelity claim is made from reconstructed header/body Strings. Original obligation UX15-002 remains covered; immutable legacy cases and all unrelated controls remain unchanged.

Reuse pgp_mime, protected_message, protected_message_gateway, native helper clients and the existing disposable Dovecot reader. At slice entry, relevant core/reader sources were byte-identical to retained S05-03 native proof, and the delivered baseline suite had 2155 PASS / 0 FAIL / 79 ignored. Repeat only changed or uncovered boundaries. Application header/body limits (including 512 KiB body) remain; the core's 16 MiB limit is not the mailbox allowance.

Native discriminator: a supported encoded signed entity with folded headers, QP/base64 Unicode/binary data, significant trailing/final-newline cases and LF storage must survive actual Dovecot fetch and real verification. A raw invalid-UTF8 signed-body case must expose the producer's actual behaviour and be refused before a trusted assessment if transformation occurs. A narrow stored-protected-body profile gate is a candidate only after a reproduced failure. Ordinary UTF8 mail, UTF8 outer headers, decrypted UTF8 MIME and byte-oriented library tests remain working. Do not alter global authentication output or introduce a new mailbox protocol without demonstrated need.

RFC3156 sections3–5 define encoded signed content and canonical verification bytes: https://datatracker.ietf.org/doc/html/rfc3156 . Its generated signed-data seven-bit constraint is not a restriction on decrypted plaintext that was only encrypted. No custom cryptography or plaintext fallback.

## T01–T09

| Test | Required observation |
| --- | --- |
| T01 Baseline/profile | Reconcile frozen scope, current source, accepted S05 proofs and actual mailbox profile before dependent execution. |
| T02 Bounded framing | Reuse matching parser malformed/truncated/duplicate/depth/part/size and canonical-byte checks; add only missing cases. |
| T03 Stored signed-byte positive | Actual disposable Dovecot fetch preserves supported canonical entity; real signature verifies without changing stored source. |
| T04 Unsupported transport negative | Actual raw-invalid source cannot be silently repaired into a verified assessment; preserve RED, correct smallest proven boundary, retest. |
| T05 Ordinary/inner UTF8 preservation | Normal UTF8 mail and decrypted UTF8 remain usable; protected gate cannot hijack ordinary classification or byte-oriented parser. |
| T06 Identity/privacy/refusal | Preserve account/message/version binding, fixed errors, no plaintext persistence/logging and no downgrade/extra crypto work on refusal. |
| T07 Native execution/cleanup | Reviewed Rust actors, existing fixed identities, synthetic state, actual producer/consumer, finite owned cleanup and preserved failures. |
| T08 Installed/preservation | Qualify and install only changed OSMAP artifact if needed; check owner-state/authority preservation and public mail availability without credential retries. |
| T09 Independent delivery/owner | Independently reconcile source/native/installed results, normal signed Git delivery and separate owner infrastructure acceptance. |

## Owners, bounds and preservation

Root owns one compiler/native/host/Git queue, work order and integration. Runtime engineer owns native reader corpus and its minimal existing Rust fixture integration; scope QA owns focused protected-gateway regression tests; protocol reviewer independently checks source, real dispatch/cleanup/consumer and results. Source ownership is assigned before edits.

No system user/group creation/deletion, account database changes, UID-wide signals, Python principal/test actors, owner password/TOTP reset/replay, key/contact/policy mutation or external message send. Use existing identities and synthetic controlled fixtures. Public Dovecot/Postfix/MariaDB services/configurations must remain available and unchanged. A private Dovecot fixture configuration is separate from public service management. Owner key-custody/unlock and actual owner reading remain explicit dependencies if needed; do not invent attestations or erase the outstanding owner protected-body failure.

Native compilation reuses jobs1, debug0, private TMP, core0 and DATAsoft4GiB,600seconds per compiler action; record actual profile/artifacts. Native functional actions use existing bounded process machinery, maximum360seconds plus15termination, with cleanup inside the action. No release-string predicates, invented memory floor, clock authority expiry, new QA framework or permissive fallback. Investigation14400seconds is accounting; retain actual elapsed or UNKNOWN. Two failures at one outcome stop unchanged retries for combined independent reassessment. Private evidence root: /home/foo/Downloads/osmap-ux-s06/.

## Reproduced stored-transport defect and correction

The first native corpus (source archive fff4ab5e, libtest bdf0865b) reproduced a real false assessment. All three supported encoded signed entities preserved their producer canonical bytes and passed actual verification; ordinary UTF8, decrypted UTF8 and outer UTF8 headers also passed. A raw invalid byte in a stored entity was transformed by the current String-based fetch path. A detached signature over the transformed representation then yielded HTTP200, a verified assessment and visible changed content. The original and observed entities had different SHA256 values. This is a verification-of-the-wrong-representation defect, not a claim that the signature algorithm was bypassed.

The existing stored gateway now requires seven-bit protected body transport, while positively classified ordinary UTF8 mail remains supported. The same small check runs before Runtime rendering and protected downloads and in OwnedSnapshot processing. UTF8 outer headers, encoded Unicode/binary parts and decrypted inner UTF8 remain supported; the generic byte-oriented Processor, MIME parser and global command executor are unchanged. Generated protected OSMAP text/attachments already use MIME base64 and ASCII-safe MIME fields. The eight focused gateway tests and the unchanged real native corpus pass; the matching actual GREEN is recorded below.

The native RED completed in11.30seconds with functional FAIL and separate cleanup PASS, two owned helpers and no unconfirmed PIDs. System account databases, installed binaries/configuration and the account authority process remained unchanged; mail and relevant OSMAP services stayed healthy. Raw observations and bounded child failure are retained under /home/foo/Downloads/osmap-ux-s06/s06-01/. Initial test-edit compile failures and one SSH banner timeout are retained as setup/transport failures, never product results. The SSH check was corrected by batching metadata reads; no server configuration change was needed. Installed qualification and owner acceptance remain pending.

## Matching GREEN and retained delivery boundary

The unchanged native corpus passes in11.05seconds with source851510a9 and libtest58681235. The same transformed93-byte raw entity now produces the specific protected-format refusal with no verified claim or body display. All three supported canonical/signature positives and ordinary/decrypted/outer UTF8 remain successful. Focused source checks also pass: eight stored-gateway cases, eighteen MIME cases and thirteen Processor cases. Independent review f761bf2a binds the actual RED/GREEN observations and source/artifact pins.

Owned helper/agent cleanup passes separately. Both exact scratch roots were hash-read back, checked for live process/descriptor references and removed; matching RED/GREEN libtests remain retained in their build stages. Account databases, installed artifacts and the authority process remain unchanged. Source/native qualification permits the next ordered S06 engineering slice; this is not installed or owner acceptance. Final installed T08 qualification and normal signed delivery are consolidated with the dependent S06 changes, with T09 left to the owner.

## Consolidated qualification checkpoint, 2026-11-02

The final matching native reader/signature/decryption cases and guarded obsd1 Web/worker installation pass. Actual installed public encryption and current signed epoch admission pass; private operation returns typed `Locked`, so owner private readiness and body UAT remain unperformed. The earlier pending-install wording above describes its historical source/native checkpoint. See [S06-04 actual results and minimal owner UAT](UX_SLICE_S06_04.md#observed-engineering-and-installed-result) for artifact identities, preservation, independent review, failed attempts and scope. Normal signed delivery is in progress; no human acceptance or production release is inferred.
