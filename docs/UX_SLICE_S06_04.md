# S06-04: practical protected reader, source and downloads

Continue the owner's 2026-11-02 authorisation through S06. S06-01–03 source/native results are reconciled, including the visible-recipient missing-key discriminator and both earlier failed classification runs. The final combined native reader, signature and decryption tests pass. The qualified Web and crypto worker are installed on obsd1; normal signed delivery is the remaining agent-owned publication step. Owner protected-message reading and T09 acceptance remain pending.

Reuse the current Rust Processor, MIME renderer, Runtime and checked content routes. Extend the existing disposable Dovecot/BrowserApp native corpus: one encrypted MIME with known UTF8/hostile HTML and a binary attachment, then follow its actual rendered download/source links. Assert exact processed bytes, account/message/version selectors, no-store/sandbox/nosniff protections, source remaining ciphertext and no plaintext application-state persistence. Preserve valid encoded signed MIME and ordinary/decrypted UTF8 from S06-01. No new parser, service, framework, mailbox transport, key API or external send.

Correct only observed presentation gaps: Refused reader state cannot carry an assessed machine-state attribute; an ordinary/unassessed message cannot imply account OpenPGP is unavailable or refer to an obsolete UI-only/future implementation. Keep cryptographic validity separate from identity and key validity, preserve the approved decryption summary and accurate server/HTTPS explanation, and render explicit uncertainty when a hidden-recipient failure does not establish a missing key.

| Test | Required observation |
| --- | --- |
| T01 Scope/dependencies | Carry actual S06-01/02/03 proofs, failed attempts, remaining classifier result and owner protected-key readiness forward. |
| T02 Real protected reader | Actual Dovecot→helper→Runtime safely displays supported decrypted UTF8/HTML; hostile script/remote content stays absent. |
| T03 Processed download | Follow actual protected download link; exact binary bytes and isolated no-store/nosniff/sandbox headers, never outer ciphertext collision. |
| T04 Source | Follow actual source link; original encrypted MIME/armor, escaped bounded source, no decrypted body; source remains available without a crypto client. |
| T05 Ownership/failures | Stale/foreign/invalid selectors and unavailable crypto release no protected bytes, body, attachment or automatic quote; budgets recover. |
| T06 Truthful UI | Refused/assessed/unassessed states are distinct; no false capability/future/browser-only/safe-content claim; scoped source checks and final browser UAT stay separate. |
| T07 Privacy/native cleanup | No plaintext application-state persistence; fixed identities, bounded exact-owned cleanup and unchanged owner/account/public-mail state. |
| T08 Consolidated install | Install only qualified changed OSMAP artifacts with preservation/rollback, actual installed SDK public/private boundary and signed epoch admission; retain owner-unlock dependency. |
| T09 Delivery/owner | Complete independent review and normal signed GitHub delivery, then owner accepts practical protected reading/source/download and infrastructure with explicit limits. |

Root owns production fixes, integration, one compiler/native/host/Git queue and final delivery. File-owned developers extend existing native test files; independent reviewer checks source, real producer/consumer, privacy/cleanup and results. Existing S05/S06 passes are reused where code and claims match. No system account administration, Python principal actors, UID-wide signals, owner credentials/keys/policy mutation, public mail-service change or operator-secret handling. The owner keys are protected and their agent is unavailable; only the human can enter a private passphrase. Do not confuse that actual prerequisite with an invented approval barrier or claim owner-body UAT from fixtures.

Use the same bounded compiler/native profiles, short runtime paths and exact-owned cleanup as S06-01/03. Two failures at one boundary require combined independent reassessment; preserve all failures and actual elapsed or UNKNOWN accounting. Evidence root: /home/foo/Downloads/osmap-ux-s06/s06-04/.

## Observed engineering and installed result

The practical result is a reader that preserves signature-byte integrity, distinguishes cryptographic verification from sender identity, renders supported decrypted MIME through the existing sanitizer, downloads the processed attachment, and shows the original encrypted source. A refusal releases no automatic quote or protected attachment. It does not promise browser-only decryption, private-key readiness from a public certificate, or a specific missing-key diagnosis from an opaque hidden-recipient failure.

| Verification | Actual result and scope |
| --- | --- |
| Reader presentation | Source RED/GREEN: four reader-state tests and one unassessed-message test pass. Refused/assessed/unassessed are distinct; successful decryption explains this OSMAP server and HTTPS. |
| Native Dovecot → Runtime → HTTP | One test PASS, 12.33 s. Sanitized UTF8, exact binary `[0,1,255]`, isolated download headers, exact escaped ciphertext source, source without crypto, invalid/stale/session refusals, recovered budgets and absent plaintext marker in application state. |
| Final native signature regression | One test PASS, 8.74 s. Real valid/tampered/duplicate/missing-public-key outcomes and separate unconfirmed identity. |
| Final native decryption regression | One test PASS, 9.13 s. Exact transient processing; visible missing private key, invalid format and uncertain hidden-recipient refusal remain distinct. |
| Native preservation/recovery | Internal cleanup PASS, no unconfirmed owned PIDs; four exact retained fixture roots removed only after hashed evidence readback and process/descriptor checks. Account databases, installed artifacts and live account authority remained unchanged. |
| Consolidated installation | Web and crypto worker only, guarded replacement with both original binaries retained for rollback. Loaded Web identity, exact new hashes, HTTPS200, all eight roles and protected account/key/configuration/state comparisons PASS. Only OSMAP Web/crypto restarted; no public mail-service change. |
| Actual installed SDK | Public encryption PASS. Private operation returned typed `Locked`, with no content, Pinentry, automatic unlock, credential/key/policy mutation or mail send. This is a successful refusal-boundary check, **not private decryption readiness**. |
| Actual installed account admission | Current Duncan epoch6 signed read-only admission PASS, one test, 0.07 s; no password submitted, TOTP consumed or credential write. |
| Independent review | Source, native witnesses, installed observations, preservation and failure history GO; private review SHA-256 `239550649ccc05ed35c30da1bac46c4c91a2ed7d4e77cd91aba14b8d5c96c932`. Normal Git gates and owner acceptance remain separate. |

The first expanded native reader run failed because its nonexistent attachment selector `99` was itself invalid: the existing route requires a dotted path beginning `1.`. The corrected test uses `1.99`, retaining the expected404. Its child failed at that assertion after2.87 s; the ten-second child bound was not increased. This fixture failure is preserved separately from the product results. The initial standalone SDK probe build also failed because the build consumer assumed a nonexistent top-level rlib alias; consuming Cargo's actual reported artifact path corrected it without rebuilding the successful Web candidate. A malformed generated installer draft was rejected by shell syntax checking before host execution; the corrected bound installer was independently reviewed before use.

| Final artifact | SHA-256 |
| --- | --- |
| Web build input | `28235ffef4dc42b24ffed6971de1c21014df8f050bc5c2051fafee24102e4da1` |
| Installed Web | `ec4ac037db2e32a5c93644703b8804495cb82f4068d612bfccab964b4044c716` |
| Installed crypto worker | `adab695fe2f8d6dab8d687ee92eb74bed1ae2d493756f11a48947c6afb9a9052` |
| Corrected native test input | `d99bea32e8b140e8ac0404e83c86f23308f987ac5842f92c510be40e60ebf4d0` |
| Corrected native test executable | `fdfe58924d5510cb2cdd120652d8c4502ff560f385f621d069579dba50a67d3a` |

The only source difference requiring the second test executable was the fixture selector; all five production Rust files match the Web build archive. The C worker was independently built and qualified on obsd1. Evidence is retained as `native-corrected-*-observation.json`, matching actual logs, `native-final-cleanup.log`, `install.actual.log`, `installed-probe.actual.log` and `native-independent-review.json` under the private root above. These files contain scoped observations, not owner acceptance or a general production-release audit.

## Normal delivery regression and operator entrypoint

The first normal pre-push gate refused publication: the main Rust suite recorded2160 PASS,1 FAIL and85 ignored in112.30 s. An older component assertion expected the previous `Decrypted on mail host` heading for a message with no OpenPGP assessment. Its correction retains the negative security and source-view checks, asserts `Decryption: not produced` and explicitly requires the `unassessed` machine state. This changes only the existing test; the independently qualified production bytes and installed artifacts remain identical. The failed gate remains in `normal-push.log`; matching corrected delivery evidence is recorded separately.

Readback also found that the installed operator unlock utility still had the older assertion-based guards, whereas its already tracked source used explicit checks that survive Python optimization. Only that existing root-owned entrypoint was atomically refreshed from the already qualified source, with an old-file backup and unchanged runtime binaries, process identities, protected state and eight healthy roles. It was **not executed**; no agent was started, service restarted or key unlocked by this refresh. This is separate from the two-artifact runtime installation. Its actual receipt is `operator-entrypoint-refresh.actual.log`; installed source SHA-256 is `94a43346f6ebc3db1334af849a64bfeff8f05bfa02f2749d120ea516f460de22`.

The existing terminal workflow requires Web admission to be quiesced and the crypto, public-inventory and public-administration helpers stopped before privately replacing/warming the mailbox agent. Restore those OSMAP helpers and Web afterward. Public mail and account authority stay running. The real entrypoint is `/usr/local/libexec/osmap/deployment_unlock.py`; a bare invocation while its helper prerequisites are unmet correctly refuses. The agent has not performed this owner-secret operation.

This is the immutable pre-push source checkpoint. The final completion record must identify the verified signed commit, successful normal gate and fresh exact remote parity; prose in this checkpoint does not prove publication. T09 and owner-body acceptance remain pending regardless of source publication.

## Minimal owner T09 journey

1. Use the existing operator terminal/Pinentry workflow to unlock the configured mailbox key privately. D03 and R3 reserve private passphrase entry to the operator. Do not send a passphrase to Codex or enter it into OSMAP. The observed `Locked` response alone does not distinguish cache, agent/socket or confinement causes; protected-key files and an unavailable owner agent were separately observed.
2. Sign in normally and open an existing supported encrypted message addressed to the configured Duncan key. Confirm the expected readable body and the explanation that decryption ran on this OSMAP server. Confirm any signature result agrees with the message; valid cryptography does not by itself confirm sender identity.
3. Download its attachment and check the expected file. Open **View source** and confirm encrypted MIME/armor rather than the readable decrypted body. No new email, key import, policy edit or saved draft is required.

Keep the October14 failed owner body observation for `R2-03-022`. The disposable native success and installed locked refusal do not supersede it; only an actual successful OSMAP body observation can settle that owner result. The eight legacy acceptance rows remain frozen, and nine approved controls carry scoped partial engineering evidence until their remaining acceptance criteria are met. S06 is not accepted or production-approved by this record.
