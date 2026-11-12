# S07-04: Wire compose/send/Sent/reply/forward with transaction and failure reconciliation

## Owner acceptance — 2026-11-03

**S07-01–04 ACCEPTED; T01–T09 PASS within the delivered sprint scope.** Owner reported personal-key unlock success and supplied Sent evidence of a cryptographically valid signature/public certificate, followed by Hotmail receipt with readable content and openpgp-public-key.asc. Owner explicitly states: Record your successful UAT = PASS “S07 accepted” (2026-11-03, Asia/Bangkok).

The earlier signing failure is resolved. Existing scoped native proofs remain the evidence for encryption, self, Bcc, policy, Sent and negative cases; the screenshots do not independently retest all those cases. Sprint functional acceptance only; earlier failures retained. No new full visual/keyboard/reference-matrix, cross-platform or production-release security qualification. Optional 24-hour unlock remains proposed; current eight-hour policy unchanged.

Accepted engineering source: signed e99455d84a253bc301364f9fe48a27eb6880fda8. Installed delivery record: signed 12b3da5c19af31be3e73cc8b3252a269cba2397c. This is a records-only closeout; no host/account/key/session/message/service changes. Pending/failure statements below remain historical checkpoints.

## Current owner UAT followup

Owner signed-send acceptance remains pending. The sender public-certificate and personal private-key followups are installed on obsd1. Personal key import, transient passphrase Unlock and account-wide Lock are separate from contacts' public keys. Existing personal keys use Unlock; import admits only the currently configured matching account key and cannot overwrite installed material. No private-key export or arbitrary key rotation is added.

The existing Rust Runtime, authenticated crypto protocol, native GPGME worker and helper-owned account store provide import/unlock/account-wide lock. Passphrases are transient unlock inputs rather than persisted beside keys. Protected inputs retain native passphrase protection; unprotected inputs receive truthful restricted-storage wording. Private-operation permission is bound to the actual session, account epoch, private revision and expiry, capped at eight hours and the browser session expiry. Server custody is explicit. Contacts remain public-only.

The failure-analysis record is retained in the active ledger and private S07 evidence root. A native receipt check incorrectly assumed one import-status record; actual GPGME emitted two successful records for one primary. A separate syscall trace proved ordinary worker cleanup could kill an intentional agent daemon before it detached. The narrow fixes preserve single-primary/identity checks, require exact successful import receipts and actual private proofs, and add a real agent reply before Start-only group cleanup. Native protected lifecycle and four invalid-upload controls pass. The ordinary HTTP journey passes import/unlock/sign verification/decryption/display privacy/lock/replay in107.75s. Existing real SMTP/Sent Gateway passes in6.05s after an isolated native fixture session-format correction; all test prerequisite/expectation failures remain preserved. Independent source/native QA GO, full2187 Rust passes/0 failures/87 skips, normal security gates and signed source publication pass. The native cases were executed separately rather than inferred from ignored tests.

Loaded Web0d70f98b and cryptohelper1cd78ec6 match the source-bound build; tested worker7ab4facd/engine12d7b21b and the Duncan-only configuration opt-in are installed. HTTPS200, nine roles, owner agent and protected account/key/session/settings/draft/config preservation pass. Actual Web-principal Status confirms the existing protected Duncan key and eight-hour policy without creating a session grant or performing an owner private cryptographic operation. Installed logs89fc77aa/08f54a48 and full hashes are retained in the ledger. Only Web and crypto helper restarted; production mail services were unchanged. Owner UAT remains: open Settings/keys, Unlock the existing personal key, then Sign on send to a new recipient with encryption off. No reimport, SSH or service restart is required. This delivery does not claim owner T09 or production-release security acceptance.

## Current delivery result — installed, owner review pending

All agent-owned S07 engineering, source, scoped native and Web-deployment checks pass. T01–T08 are complete within the recorded scope; owner T09 and broader visual/keyboard/final-reference acceptance remain PENDING. The work orders remain IN_PROGRESS for that remaining acceptance, and the23 mapped approved-control results remain PARTIALLY_VERIFIED. No owner acceptance is inferred.

Signed engineering checkpoint29fd7f491f144b9c3dfcc451d10c4298b2021f88 passed the complete normal security/push gate and reached GitHub feat/ux-completion-20260929; a fresh fetch proved exact local/remote equality,0/0 and clean source. The reviewed Web-only installer then passed. Loaded Web SHA2568d2e2813ea96b391978104a3a2ed7b6f85463f84ef3a161be17734b99f965e48, PID54930/inode130022; HTTPS login200; nine service roles healthy. Only Web restarted. Protected account/key/config/session/settings/draft files, environment, worker/helper artifacts and account-authority PID checks pass. Previous Web c569fbc4 is retained at /var/backups/osmap-s07-install-20261103-01/web.before. No public mail-service configuration or restart, owner private-key operation or external recipient delivery occurred.

Independent source/native/installed-result review passes. Native qualification retains the current scoped three-case result and final source manifest; ordinary Rust2165/0/85, strict Clippy, formatting, repository metadata and complete normal delivery checks pass. Source/native failures and their smallest corrections remain in the following history. Retained actual delivery evidence: /home/foo/Downloads/osmap-ux-s07/completion-20261103-62oBKV/format-corrected-push.log, install.actual.log (SHA256a75f7b68aa890a1944ca0f7e501b49e0d897c6d936afcdd26f329dcd48385ab3), qualified-source-final.sha256 and S07_DEPLOYMENT_COMPLETION.json. This final deployment-record update changes documentation/evidence only and follows normal signed publication.

Practical later review: open Compose and inspect the off/requested protection choices, then use the normal protected-send and Sent-reading workflow. The agent has already checked signatures, ciphertext, exact binary bytes, source isolation and failure replay; no packet-decoding exercise is assigned to the owner. The later Daybreak Blue code review and OWASP WSTG release work remain separate from this S07 engineering result.

The owner authorizes independent completion of every S07 slice with later review. Reuse the existing Rust product path, current native worker, disposable synthetic keys/accounts, existing private Dovecot fixture and controlled Rust loopback transport. No new cryptography, dependency, generic QA framework or production mail-system changes.

Inspect and reuse current code and matching evidence; reproduce the demonstrated missing boundary; make the smallest correction; verify the actual composed result and deliver signed source through normal hooks. Functional assertions and actors use Rust. Existing shell orchestration and repository metadata validators remain.

- T01: Review current composed send journal and recovery.
- T02: Actual gateway sends to controlled Rust local sink.
- T03: Real scoped Dovecot append stores protected prepared message.
- T04: Read decrypt verify Sent and download binary attachment.
- T05: Source remains encrypted; current source selection protected.
- T06: Stale policy helper interruption and Sent-store failure do not downgrade or auto duplicate.
- T07: Actual authenticated HTTP and draft transaction checks.
- T08: Consolidated native build installed preservation and independent review.
- T09: Owner acceptance after normal signed publication.

Source, native, installed and owner acceptance remain separate. Scope: private fixture account/key/config/message state only. Never replay owner credentials or passphrases; do not alter owner account, policy, keys, mail or sessions. Never stop/reload or configure public Dovecot, Postfix or MariaDB. No production mailbox synchronization or external recipient send.

The existing signed/encrypted native gateway case previously captured Sent in a test file and preloaded its reader fixture. S07 extends that exact fixture so the production gateway append performs actual scoped doveadm save before independent retrieval. Outer storage CRLF-to-LF normalization is expected; ciphertext payload must remain identical. Editable/recovery authored drafts are an existing private policy, not a claim of no plaintext application state.

Independent protocol review precedes native dispatch. Preserve original failures separately from cleanup. After two failures at one boundary stop retries for combined independent reassessment. Existing exact-owned process and agent cleanup remains; no owner private operation.

## Engineering qualification — 2026-11-03

The S07 engineering changes are implemented and the consolidated native workflow passes. Owner T09 acceptance is PENDING. Production Web installation is PENDING signed admission. No production-release or full visual/keyboard acceptance is inferred.

Only the configured composer needed a product change: it now states Unsigned / Not encrypted / Off and changes those labels to requested intent with native checkbox CSS. Existing policy, PGP/MIME, recipient routing, journal and private draft/recovery paths are reused. The exact configured HTTP regression failed first on missing Unsigned, then all10 preference/HTTP tests passed. Existing focused Rust checks pass: policy21, protected submission18, preflight13, exact gateway2, journal25, journal routes7, recovery UI5, Sent receipt1. A zero-selected shorthand gateway filter is preserved and superseded by the exact2-test selection. Full ordinary Rust suite:2165 PASS,0 FAIL,85 opt-in ignored.

The OpenBSD build consumes source archive70f02adfa51c384448eca400001ef3f808186711a14f5875b342a3c888f8e8fa. Three selected native tests each actually execute1 PASS with0 failures/skips: authenticated helper roundtrip; emitted sign/encrypt/Bcc; and composed Gateway/HTTP/local SMTP/real Dovecot Sent. Native signing is independently verified, tampering refuses, UTF-8 and binary bytes00 01 ff survive, intended recipients decrypt, excluded sender refuses with paired positive controls, self-encryption works, and both public PKESK key IDs are zero. This privacy claim concerns recipient key IDs and absence of a Bcc header, not traffic-analysis anonymity.

Gateway Sent copies now originate in actual scoped doveadm save before readback. Expected outer CRLF-to-LF storage normalization and identical decoded ciphertext packets are checked. Actual authenticated reader routes decrypt and verify stored Sent, download the binary attachment, retain encrypted source, and refuse a locked synthetic agent. Stale policy/helper refusal submits zero; selected protection never falls back to plaintext. Eight controlled local SMTP acceptances and seven actual Sent-save calls include one accepted-submission/Sent-refusal result. After removing the scoped refusal, replay of that intent sends/appends nothing again. Authored editable/recovery drafts remain existing private application state; no claim of no plaintext state is made.

Every key/account/message/process is disposable fixture state. Owned listeners join and scratch removal is explicitly checked; all three fixture GPG agents stop, and postflight finds no fixture agents. Nine existing service roles remain healthy. Public Dovecot/Postfix/MariaDB and owner keys/accounts/policy/messages/sessions are unchanged by native qualification. No external recipient delivery or owner private-key operation occurs.

The two selected native tests no longer generate Python transport/capture actors: fixed Rust actors and the existing native GPG/GPGME/Dovecot utilities exercise the boundary. Existing shell build orchestration and required Python repository metadata validators remain. Independent source review corrected a fixture cleanup omission, a hardcoded temporary directory, and armored-text comparison before dispatch. Native qualification passed on its first run. Current libtest SHA256 b7cce1495427ca9d379771533e5cc5b9faaaeb2e027c80251b940cd126a9fd09; candidate Web SHA2568d2e2813ea96b391978104a3a2ed7b6f85463f84ef3a161be17734b99f965e48.

Retained private evidence: /home/foo/Downloads/osmap-ux-s07/completion-20261103-62oBKV/native-build.actual.log and native/{AUTHENTICATED_RUST_ROUNDTRIP,OUTBOUND_SIGN_ENCRYPT_BCC,PRODUCTION_GATEWAY_ROUNDTRIP}.log; s07-source-final-build.log; s07-rust-full.log; qualified-source.sha256; native-postflight.actual.log. The local-file browser-render attempt was refused by the tool URL policy and was not worked around. Computed visual/keyboard acceptance remains for later owner review. The110 immutable legacy cases and403 approved controls remain, with only scoped evidence appended; older failed owner observations stay in history and are not relabelled as current owner success.

## Normal delivery gate correction and current-source recheck

The first signed engineering checkpoint ef9ba7cb05a6df8e9420f819276a31f5f6f4dee2 passed ordinary tests but its normal push gate refused Clippy too_many_arguments on the new test-only readback method. No hook or warning was bypassed. Grouping the existing two fingerprint parameters into a tuple corrects the interface without changing product code, assertions or key mapping. The exact two-file delta archive855581336df8d82dc4ad98de52c8d2806599533966ad1f9d47d6bcff2de67140 is applied only after old-source hashes match. Local all-target Clippy now passes with warnings denied.

The matching current native libtest is1f8f633b0313cb920489b1c334ffca5058a4862dff4ff2f6797f05c45a30456a. Its three actual native cases pass again with0 failures/skips, explicit cleanup and postflight preservation. The selected final executable is retained at /home/foo/.osmap-s07.rtJMDTRK/osmap-native-tests. Current actual logs are native-recheck.actual.log, native-recheck.log, native-recheck/*.log and native-recheck-postflight.log under the same private S07 root. The qualified Web remains exactly8d2e2813ea96b391978104a3a2ed7b6f85463f84ef3a161be17734b99f965e48; no production change is introduced by this test-only correction. Earlier pass/failure logs remain separate. Web installation and owner acceptance are still pending.

## Paired delivery reassessment — documentation index

Two normal push failures are retained separately: source-push.log refused the test-only Clippy8/7 interface, then correction-push.log passed strict Clippy/regression/publication and refused the missing literal backticked S07 filename in the documentation index. Root, independent protocol reviewer and independent QA jointly reassessed both actual failures before another push. The first is corrected by the qualified tuple-only fixture delta; the second is corrected by four index entries using the existing filename/link style and a title-first heading. The exact unchanged documentation guard now passes in documentation-index-corrected.log. No gate/source requirement is relaxed. Reuse current native/strict Clippy qualification; next action is a signed documentation-only checkpoint and the full ordinary enabled push, then exact fresh remote parity. No new native run or product change is justified by the index formatting correction. Installation/owner acceptance remain pending.

## Portable read-only fixture correction

A later ordinary push run retained2164 PASS/1 FAIL/85 ignored. The read-only inventory fallback test failed with ExecutableFileBusy26 while the broad shared fixture tried to execute an unused authentication script, before reaching KeyBackend.read. The exact concurrent open-file holder was not captured at failure and remains UNKNOWN; no credential or product failure is inferred. Independent root/protocol/QA review confirmed that this test uses only its private directory. Its setup now creates one unique0700 directory directly, preserving the same stale admin socket, live authenticated inventory RPC, grant/socket permissions, server join and result assertions, then explicitly removes/checks the directory on success. No retries, skips or new test framework are added; a failed test retains its private fixture.

The focused actual case passes1/0/0, and the full parallel Rust suite then passes2165/0/85 in29.81s. Current evidence is readonly-inventory-fixture-corrected.log and rust-full-after-readonly-fixture.log. Three generated maps now contain11485 findings, refined high0/medium4; the three added assumptions are confined to this test setup. Selected S07 native fixture/production input bytes and qualified Web8d2e remain unchanged, so their scoped native proof is reused. No native result is claimed for this unrelated portable fixture. Ordinary publication/installation/owner acceptance remain separate.

## Formatting-only delivery correction

The subsequent readonly-corrected-push.log proves2165 PASS/0 FAIL/85 ignored and strict Clippy PASS, then records the formatter refusal for one missing line break in the new private-directory format call. Root missed the direct formatter check before that fixture checkpoint. Applying the exact newline changes no behavior. The direct cargo fmt --check now exits0; existing documentation/V10 guards pass with11485/refined high0/medium4 and updated positional fingerprints. Root, protocol reviewer and QA jointly reassessed this refusal with the preceding ETXTBSY setup failure. Both remain distinct; no checks are weakened and no additional native run is justified. Next action remains the complete ordinary enabled publication path and then the already-reviewed Web-only installation.

## Signed-send UAT followup — 2026-11-03

Owner signing to a new unregistered recipient failed with Locked. This is not an encryption-policy refusal. Public binding does not prove private-key readiness; the existing native unlock utility sets a five-minute cache bound. Actual live cache expiry is unobserved. Separately, signed MIME does not yet attach the sender public certificate expected by the owner.

Reuse authenticated public-admin read RPC, fixed public-only GPGME export, current account binding and public revision. Attach the exact own public certificate transiently before signing; keep it inside sign-then-encrypt. No browser certificate authority, secret export, new key cache/service, private-key web prompt, TTL change or owner private operation. Ordinary/encryption-only behavior and authored request/draft remain unchanged.

Focused Rust tests cover new-recipient sign-only, export identity/revision/authentication/size failures, exact signed certificate and independent recipient verification, Locked zero submission, existing exact Sent/replay and encryption invariants. Native OpenBSD proof precedes installation; source, native, deployment and owner acceptance stay separate. Root owns compiler/native/host/Git queue; runtime engineer owns helper export, protocol reviewer owns UX copy, scope QA independently reviews. Two boundary failures require combined reassessment. Engineering bound four hours with bounded individual operations; elapsed prior investigation UNKNOWN.

### Followup engineering qualification

Current native three exact selections1PASS each0FAIL0ignored; actual GPGME public-only exact-primary export preserving keybox/trust/private state; fresh recipient imports attached certificate only and independently verifies; HTTP sign-only unregistered recipient succeeds with exact public certificate and real Dovecot Sent; Locked zeroSMTP/Sent and restoredsameintent/replay200 no duplicate. Native cleanup and nine-role postflight PASS. Owner unlock/Hotmail/acceptance and installation remain separate.

Retained evidence: /home/foo/Downloads/osmap-ux-s07/signed-send-followup-20261103/native-replay.actual.log, native-replay/{AUTHENTICATED_RUST_ROUNDTRIP,OUTBOUND_SIGN_ENCRYPT_BCC,PRODUCTION_GATEWAY_ROUNDTRIP}.log, qualified-source.sha256 and native-postflight-corrected.log. Native prepared artifacts: Web667898ad5d751c56f2f7ee81e3e866ddfba469045447a7bcc0c68862dc95176c; public-admin helper70aa94b0fcacd16a7f4f63e9bc2b67064534b42dbe277255371a605e3a806067; exact tested inventory worker8532130c77c0708a6340bf69aea2ed68d2f36bbd5fcb0cb6f9c1f6d5c8f82dbd. These are not yet installed.

Failures remain retained: incomplete source archive caused compile101 before native dispatch; corrected complete archive adds existing fixtures with unchanged functional code and refreshed V10 metadata. New replay assertion incorrectly expected303 where the existing AlreadyRecorded contract returns200; corrected test adds recorded heading, original-intent receipt and no-Sendform assertions without product change. First cleanup guard matched its own inline command and refused before deletion; stdin-dispatched correction checked absence and removed only the owned synthetic failed fixture after durable failure-log hash readback. No gate was bypassed. Independent source/native/installer review passes; installer b66fe287 targets only Web/public-admin helper/admin inventory worker, preserves crypto agent and public mail, and includes bounded child drain/whole-set rollback. Normal signed preservation precedes installation.

Normal source push refused a test-classification omission: public-admin Runtime tests are an actual external cfg(test) module but were absent from the guard registration. The exact parent-marker classification is now registered, including the existing negative control that removes cfg(test) and exposes hostile code to normal production rules. The subsequent shell-only scan uses that same exact verified child exclusion; no directCommand exception or production rule changed. Focused guard/regressionPASS; ordinary fullpush remains required. Product/native artifacts are unchanged. The optional installed read-only Rust probe initially failed generic type inference; a redundant conversion was removed and the probe compiled. No probe has run against an owner key yet.

### Followup actual installed result

Source8b1107bb15542673268399f351a222aa15ff962f passed ordinary signed publication and freshlocal/remote equality0/0 before deployment. The reviewed installer b66fe287 loaded Web667898ad (PID18281/inode130023), public-admin helper70aa94b0 (PID94645/inode3758814) and exact tested worker8532130c. HTTPS200, nine roles, protected state and otherworker/config/environment checks PASS. Only Web/public-admin restarted; private agent PID34227 remains unchanged. Previous artifacts are retained under /var/backups/osmap-s07-sign-install-20261103-01.

The minimal ephemeral Rust Client probe ran as the actual Web principal, loaded the owned account binding and performed installed snapshot/export/readback. It confirmed public revision unchanged, no private operation, protected file equality, nine healthy roles and exact temporary cleanup. Retained /home/foo/Downloads/osmap-ux-s07/signed-send-followup-20261103/install.actual.log, installed-public-read.actual.log and S07_SIGNED_SEND_DEPLOYMENT.json with its portable SHA256 sidecar bind the actual result. Independent source/native/installed review passes.

The owner Locked UAT remains FAIL/not accepted. No owner private-key unlock/signature, external Hotmail send or delivery was performed. The300-second operator-managed cache is an open ordinary-use limitation; this public-certificate fix does not change passphrase handling or establish current private-key readiness. Native synthetic successful signing is not owner UAT. Broader visual acceptance and Daybreak Blue/OWASP WSTG release work remain separate.

### Owner-approved eight-hour UAT native-unlock policy

The owner explicitly selected eight hours after a native unlock. This supersedes the earlier decision to preserve300seconds for this narrow obsd1/Duncan development utility. Both agent cache limits become28800seconds per key; native Pinentry, encrypted key files, external-cache prohibition and all identity/socket/terminal/service guards remain. The new policy takes effect only at the next successful native unlock; installing a utility does not unlock or restart the current agent.

Reuse the existing Rust same-service native lifecycle test: execute the real operator utility function on a disposable home, inspect the actual agent PID/argv for both28800limits and nativePinentry, then verify real recovered signing. Existing Python utility guard expectations are corrected rather than kept falsely at300; authoritative functional proof remains Rust/native. No newcrypto/daemon or eight-hour sleep. Utility-only installation preserves owner keys/config/session/mail and the current agent. Ordinary users still need a future in-app unlock flow; eight-hour infrastructure UAT does not implement that feature.

Eight-hour UAT policy native qualification PASS: five exact existing native cases execute1PASS/0FAIL/0ignored each, including Rust actual PID/argv checks for both28800limits and recovered signing/verification. Source lifecycle5PASS/1nativeopt-inignored; actual native run exercises the ignored case. CleanupPASS. This proves configured native policy and synthetic operation, not eight hours elapsed retention or owner unlock. Evidence /home/foo/Downloads/osmap-ux-s07/signed-send-followup-20261103/eight-hour/native.actual.log and native-eight-hour phase logs. Utility-only installer09c50f5e replaces exact root-owned55583b01source with7ebeaac6 after a signed source checkpoint; owner keys/config/current agentPID remain unchanged. Actual result record and source will then be preserved together through one normal fullyenabled push/freshparity before handoff. No production Web secret flow or Rust broker is implemented by this policy change.

Eight-hour UAT policy actual installation PASS after signed sourcef1b88759ce6bb5203fc48d3079859ad19a7763a0/signature verification. Exact utility7ebeaac6 is installed root:wheel555 at /usr/local/libexec/osmap/deployment_unlock.py; previous83b01source retained under /var/backups/osmap-s07-eight-hour-20261103-01. Installer09c50f5e, actual install logSHAa7fc0b660e146e639f1183c8478862d35903d66df4651466c7a8a153e56155ed, private-key/config preservationPASS and nine healthy roles. Agent34227 unchanged; no private unlock or service restart. The eight-hour limits apply at the next successful native warm; the existing live agent still has its earlier policy.

Retained /home/foo/Downloads/osmap-ux-s07/signed-send-followup-20261103/eight-hour/UAT_POLICY_DEPLOYMENT.json/portable sidecar, install.actual.log and native.actual.log bind the observed scope. Independent source/native/installed review passes. Final record and source use one normal fully enabled push/fresh0/0 before handoff. No final browser Unlock/Lock flow, session-bound private-operation grants, owner signed-send success or T09 acceptance is inferred.

## Remembered personal-key follow-up — 2026-11-04

Owner-approved optional remembered-browser access preserves the existing normal
email/password/TOTP login. In Settings → Keys → Your personal key → Unlock,
select the initially unchecked “Remember key access on this browser for eight
hours” only on a personal device. After one successful unlock, later fresh MFA
sign-ins on that browser may restore access until the original fixed deadline;
use/sign-in never slides that deadline. Sign out removes remembered permission.
Account Lock and explicit session-management revocation clear key permissions;
key-service restart requires unlocking again. Web restart clears remembered
sign-in restoration. No permanent passphrase storage, private-key export or
change to contacts' public keys. Agent-owned regression/native/installation and
owner functional acceptance remain separate; the earlier S07 acceptance is
preserved. Current implementation/QA progress is recorded in the execution ledger.


### Remembered-key follow-up installed — 2026-11-04

The owner-approved optional remembered-browser access is installed on obsd1.
Remember is unchecked by default. The original eight-hour unlock deadline is
fixed; new email/password/TOTP sign-ins and signing do not extend it. Ordinary
Sign out clears remembered access. Remember/Resume require an authoritative
credential epoch. Session-only unlock remains available to legacy accounts.

Full Rust 2204/0/87 explicit native ignores, strict Clippy, all six exact native
cases, disposable cleanup and independent review pass. Installed Web/helper
hashes 0d5c520f/5bf3bf8e match the qualified build; HTTPS, nine roles and protected
state preservation pass. First unlock after the helper update is required.
Owner UAT remains pending; the short workflow is recorded in the execution ledger.
This follows the previously accepted S07 scope and does not imply production
release, broad WSTG completion or new owner acceptance.


### Remembered-key owner UAT acceptance — 2026-11-04

**UAT PASS; ACCEPTED and APPROVED.** The owner states:

> UAT is PASS
> UAT accepted, and approved

The owner first supplied the fresh email/password/TOTP sign-in result showing
current-session and remembered access with the same original deadline:
2026-11-04 18:29:58 UTC. The final acceptance follows the requested ordinary
Sign out, fresh sign-in and locked-key check. Record the complete proposed UAT
workflow as accepted by the owner; do not infer an independently observed
eight-hour wall-clock wait from the screenshot. Fixed expiry is additionally
covered by the retained Rust/native tests.

This closes the remembered-key follow-up to S07. The installed code and its
qualification are unchanged. Broader epic, cross-platform and production-release
security-review/WSTG obligations retain their existing scope. This closeout
changes only mutable documentation and normal signed Git delivery records.
