# S06-04: practical protected reader, source and downloads

## Accepted closeout — 2026-11-03

**S06-04 ACCEPTED. T01–T09 PASS.** The owner explicitly replied **“accepted”**
after the completed slice was presented with successful body, exact attachment
and encrypted-source observations and no remaining technical test requested
from the owner. This closes the completed protected-reader/source/download
slice and its infrastructure result.

The qualified engineering checkpoint is
`0866340cc55c54cb660018e50ce3959a8a0ed536`, signed and synchronized to
`feat/ux-completion-20260929` with fresh exact remote parity and a clean
worktree. Installed Web SHA-256 is
`c569fbc4eeeb284911ed683fc73fc659c5a52d7610e8da3969d92f61c92f6a53`.
Five matching OpenBSD component tests pass without skips; normal delivery
passes2164 main Rust tests with0 failures and85 ignored, plus the required
repository checks. The installed loaded identity, HTTPS200, nine service
roles and protected-state preservation passed. Independent source, native,
installed and owner functional evidence is retained under the existing
private evidence root. Explicit acceptance is retained in
`S06_04_OWNER_ACCEPTANCE.json`.

This is an acceptance-record update only. Earlier failures and historical
pending statements below remain provenance. The110 immutable legacy cases
and403 approved-control statuses are preserved; scoped acceptance evidence
is appended to the mapped approved controls. Broader visual, keyboard and
network criteria remain in the epic register. No production release,
mailbox synchronization, private-key change or new host action is authorized
or claimed by this closeout.

## Owner functional result and size hint — 2026-11-03

The owner has now exercised the installed reader successfully. The screenshot
of UID780 shows **Decryption works on obsd1.**, **UTF-8 check: café.**,
**Decrypted on mail host**, an unsigned result and one downloadable attachment.
The supplied download is exactly three bytes `00 01 ff` with SHA-256
`26a66b061e8f48f39927c312f25293959729eee95978e2892d49d3512a5cc092`.
The supplied source-page screenshot shows the original `multipart/encrypted`
message and complete PGP armor rather than the decrypted body. The owner
initially described the technical source page as an error; inspection shows
the expected source view. These are scoped owner body/download/source PASS
observations, preserved in `owner-functional-observation.json` under the
existing private evidence root. They supersede the current failed-body
observation without deleting its history. Formal whole-slice infrastructure
acceptance is not inferred. No more technical checks are requested from the
owner for this test.

That successful download also exposed a small presentation defect: the reader
showed the four-byte encoded MIME hint as the file size, while the actual
download is three bytes. One format-string change moves the existing number
into collapsed **File details**, explicitly labelled **Encoded size hint**.
The main attachment row presents the filename and isolated download. The MIME
parser, decoding, metadata model and downloaded bytes are unchanged. The
existing positive test first fails on the misleading label, then all five
component tests pass with both reader layouts covered. Matching OpenBSD
qualification passes all five tests with zero failures or skips. The qualified
Web `c569fbc4eeeb284911ed683fc73fc659c5a52d7610e8da3969d92f61c92f6a53`
is installed and its loaded inode verified. HTTPS200, nine healthy roles and
protected account/key/configuration/state comparisons pass; only Web is
restarted. The old Web is retained under
`/var/backups/osmap-s06-size-install-20261103-01`. The existing generated
audit maps are refreshed together, with unchanged counts/risk classifications;
the complete V10 consistency check passes. Evidence is retained as
`attachment-size-*.log`, `attachment-size-source-review.json` and the owner
functional proof under the same private root. No new service or framework is
introduced. Normal signed delivery for this final correction is separate.

## Attachment visibility correction — 2026-11-03

The owner's UID780 screenshot establishes a locked-key refusal, not an absent
attachment: the reader reported zero while the list counted two outer encrypted
MIME parts. The owner subsequently reported
`mailbox_signing_and_decryption_agent_warmed=PASS`; all four OSMAP services were
restored and HTTPS returned200 after startup. Actual owner body, download and
source observations are still pending. The fixture is preserved without another
save, private operation, credential submission or key/policy change.

The smallest Rust presentation correction distinguishes unavailable attachment
processing from a successfully inspected empty message. Both reader layouts show
**Attachments unavailable** on protected-processing refusal and expose no
attachment link. Encrypted list/public-metadata views show attachment details as
unknown until decrypted, instead of counting the outer OpenPGP wrapper. A
successfully processed reader keeps its actual decoded attachment count and
download link. The backend parser, attachment filters, helper protocol and
cryptographic processing remain unchanged.

Focused source tests first reproduced two failures, with three passing controls.
The correction passes all five component tests. Independent review proposed a
possible coordinated-reader contradiction; an additional positive assertion
passed before any further production change. Inspection confirmed the cited
legacy toolbar branch is unreachable through both current public entrypoints,
and the reviewer withdrew that finding. The assertion remains as coverage;
`attachment-coordinated-red.log` records an actual PASS despite its diagnostic
filename. No extra implementation was added for that speculative path.

Evidence: `/home/foo/Downloads/osmap-ux-s06/controlled-local-uat-20261103/`,
`attachment-ui-red.log`, `attachment-ui-green.log`,
`attachment-coordinated-red.log`. Matching OpenBSD verification passed all five
component tests (zero failures or skips,0.02s); the test build took2m00s and the
Web build49.32s. The reviewed input archive is
`61dabe2743502b5751c58b47009247f7729f09977727ddacf0ecbc54cbbb7b99`;
the installed Web is
`04786dcc26455b63d84b9faa673c54aa9e1e6f3f8c43862351c89b73b8d37b43`.
A guarded Web-only installation passed exact file/loaded-inode checks, HTTPS200,
nine service checks and protected account/key/configuration/state preservation.
Only Web was restarted; no helper, owner agent or public mail restart was
requested. The prior Web and root-owned installation witnesses are retained under
`/var/backups/osmap-s06-attachment-install-20261103-01` on obsd1. No continuity
claim for every helper PID is inferred. Existing exact binary-download/ciphertext-source,
ownership, sanitization and privacy proofs are reused for the unchanged backend.
Owner T09 is not inferred from a successful unlock, fixture import or component
test.

The first normal push for this correction passed the full Rust regression
(2164 passed,0 failed,85 ignored;31.80s) and then stopped at the existing V10
generated-inventory check. The new tests add nine test/fixture assumptions, so
the recorded current count and fingerprint were stale. The existing generators
refresh the coupled current audit, remediation register and claims fingerprints.
The original snapshot remains preserved in Git. Only nine low-relevance
test/fixture assumptions are added; the generic audit's production categories
and the refined register's zero high-relevance count/four medium invariants
remain unchanged. A first partial refresh passed its narrow register check.
The broader consistency check then caught an authoring error: a new
`total_count` field had been used instead of the existing claims field
`current_scanner_count`. That failed check is retained separately; the correction
updates the existing field and removes the extra one. The failed push is retained as
`attachment-normal-push.log`; this metadata-only correction requires normal
signed delivery again, with no native rebuild or repeat installation.

## Current local UAT result — 2026-11-03

The operator explicitly resumed S06 using controlled messages on obsd1 and
deferred production mailbox synchronization. No production-mailhost action,
replication service, account/key/policy change or new application transport is
required. The abandoned, uninstalled synchronization drafts are privately
archived and removed from active source. Matching passing S05/S06 evidence is
reused; this continuation does not rebuild unchanged production code.

The owner previously reported the corrected private-terminal unlock succeeded
and all OpenPGP/Web services restarted. The later copied Proton reply displayed
readable signed MIME and a cryptographically valid signature in OSMAP. Those are
useful scoped observations, not an encrypted-body acceptance result. A private
agent cache may expire independently of that earlier successful unlock.

One local-only public-key-encrypted test message is now in **INBOX UID780**:
**S06 UAT: encrypted reader, attachment and source**. Its recipient is the
already provisioned and currently authorized mailbox key. No secret key,
passphrase, signature, SMTP submission or key/policy edit was used to prepare it.
The message contains safe HTML with expected text **Decryption works on obsd1.**
and **UTF-8 check: café.** Its attachment is `s06-attachment.bin`, exactly the
three bytes `00 01 ff`, SHA-256
`26a66b061e8f48f39927c312f25293959729eee95978e2892d49d3512a5cc092`.
It is encrypted but unsigned; a verified-signature claim would be incorrect.

Native storage qualification explicitly observed Dovecot's CRLF-to-LF outer
storage conversion: the canonical wire message is2024bytes, SHA-256
`df78c17c013d89e4ea5cb2fc2964eea7de053e450ee70fecce15528f883f1e35`;
the stored form is1983bytes, SHA-256
`fe2bb9adb877735b201056ef7e1a1fe4f31d747ebd94fe112c4abd6996590424`.
The decoded binary PGP payload is identical; encrypted inner MIME retains its
canonical CRLF bytes. This conversion does not rewrite any existing signed mail.

The one save completed, then a new SSH connection timed out during banner
exchange. Its cause is UNKNOWN. The initial failed observation is retained in
`import-result.private.json`; the save was not repeated. Independent-reviewed
read-only reconciliation found exactly one matching Message-ID/UID780, exact
stored bytes, unchanged original UID779/content/persistent flags, identical
protected account/key/configuration hashes and nine healthy service roles.
Evidence is under `/home/foo/Downloads/osmap-ux-s06/controlled-local-uat-20261103/`.
Web `ec4ac037…`, crypto worker `adab695f…` and unlock utility `83b01e98…` still
match the qualified installed artifacts. No unchanged native suite was repeated.

The remaining owner T09 check is to open UID780, confirm the expected decrypted
UTF-8 body and server-side decryption explanation, download the exact attachment,
and inspect **View source** for encrypted MIME/PGP armor without the readable body.
Use the existing private terminal unlock only if OSMAP reports a locked key.
Fixture preparation and import do not promote the retained FAILED body result
or complete S06 on the owner's behalf. Normal signed record delivery remains a
separate observation below; production release is not authorized by this work.

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

The next normal gate passed all2161 main Rust tests, with0 failures and85 ignored in112.85 s, plus the hostile-content assurance, Clippy, formatting, supply-chain and rendering/workflow gates. It then refused publication because the documentation index omitted the four new S06 records. All four links were added to the existing index; the narrow documentation guard passes. Both full failed publication attempts remain retained, and combined root/independent reassessment requires the next ordinary complete pre-push gate rather than bypassing it. This index correction changes no production or test code and does not require another native build or installation.

Readback also found that the installed operator unlock utility still had the older assertion-based guards, whereas its already tracked source used explicit checks that survive Python optimization. Only that existing root-owned entrypoint was atomically refreshed from the already qualified source, with an old-file backup and unchanged runtime binaries, process identities, protected state and eight healthy roles. It was **not executed**; no agent was started, service restarted or key unlocked by this refresh. This is separate from the two-artifact runtime installation. Its actual receipt is `operator-entrypoint-refresh.actual.log`; installed source SHA-256 is `94a43346f6ebc3db1334af849a64bfeff8f05bfa02f2749d120ea516f460de22`.

The existing terminal workflow requires Web admission to be quiesced and the crypto, public-inventory and public-administration helpers stopped before privately replacing/warming the mailbox agent. Restore those OSMAP helpers and Web afterward. Public mail and account authority stay running. The real entrypoint is `/usr/local/libexec/osmap/deployment_unlock.py`; a bare invocation while its helper prerequisites are unmet correctly refuses. The agent has not performed this owner-secret operation.

This is the immutable pre-push source checkpoint. The final completion record must identify the verified signed commit, successful normal gate and fresh exact remote parity; prose in this checkpoint does not prove publication. T09 and owner-body acceptance remain pending regardless of source publication.

## Minimal owner T09 journey

1. Use the existing operator terminal/Pinentry workflow to unlock the configured mailbox key privately. D03 and R3 reserve private passphrase entry to the operator. Do not send a passphrase to Codex or enter it into OSMAP. The observed `Locked` response alone does not distinguish cache, agent/socket or confinement causes; protected-key files and an unavailable owner agent were separately observed.
2. Sign in normally and open an existing supported encrypted message addressed to the configured Duncan key. Confirm the expected readable body and the explanation that decryption ran on this OSMAP server. Confirm any signature result agrees with the message; valid cryptography does not by itself confirm sender identity.
3. Download its attachment and check the expected file. Open **View source** and confirm encrypted MIME/armor rather than the readable decrypted body. No new email, key import, policy edit or saved draft is required.

Keep the October14 failed owner body observation for `R2-03-022`. The disposable native success and installed locked refusal do not supersede it; only an actual successful OSMAP body observation can settle that owner result. The eight legacy acceptance rows remain frozen, and nine approved controls carry scoped partial engineering evidence until their remaining acceptance criteria are met. S06 is not accepted or production-approved by this record.

## Owner unlock failure and Python tooling repair, 2026-11-02

The owner followed the terminal procedure after updating the host and reported a failed unlock. The detailed trace contains an earlier Bad Passphrase prompt, then GPG's `error creating '/dev/null.part': Permission denied` during the decryption challenge. The fatal output-path error does not establish a wrong saved mailbox credential or explain every private-key prompt. Signing success alone does not confirm decryption warming. The owner reported retries; the agent did not replay an owner passphrase, replace a key or reset credentials.

The source defect was a named `--output /dev/null` for the private operations. GPG attempted a sibling temporary file which the helper UID could not create. Both signing and decryption now use `--output -`; the existing subprocess wrapper sends noncaptured stdout directly to `DEVNULL`. No named plaintext file or captured owner plaintext is introduced. The existing custody, account, TTY, Pinentry, cache, privilege and timeout rules remain unchanged. The warm sequence is extracted into a small callable for direct argument/failure tests, with success printed only after both challenges return successfully.

Services were restored and checked before further engineering. The repaired operator utility was then installed atomically as root-owned0555, with the previous file retained. That installation did not execute the owner launcher, warm a private key or restart services; runtime binaries, service PIDs and protected account/key/configuration state were unchanged, all eight original roles were healthy and HTTPS returned200. Installed utility SHA-256: `83b01e98adca6c6a880f6f7264b2eb3bf93e0bd263a5e5d43558b69eddcf78b3`.

| Changed boundary | Actual verification |
| --- | --- |
| Unlock argument/output handling | Genuine source RED expected stdout but observed named `/dev/null`; matching GREEN15tests,2native-only skips, under normal and optimized Python. Both private-operation outputs are discarded, failures stop the sequence, and the caller restores terminal ownership/mode and signal handlers without reporting warm success. An initial PTY test used the caller's default group rather than the PTY's original group; that fixture error is retained separately and corrected before the clean behavioural RED. |
| Actual obsd1 Python interpreter | The same portable unlock suite passed on the installed interpreter:15run,2explicit native skips,0failures,0.094s. No owner key operation or provisioning entrypoint ran. |
| Actual GPG producer/consumer | Existing Rust fixed-UID native case PASS9.21s. Named-output decryption refused with0stdout; the same ciphertext decrypted through stdout to the exact81-byte synthetic plaintext; stdout signing returned265-byte valid armor. `/dev/null.part` was absent before and after. No plaintext stream was retained. |
| Preparation guards | Two retained operator provisioning scripts used optimization-sensitive operational `assert` statements. Explicit checks now preserve every original condition under ordinary Python, `-O` and `PYTHONOPTIMIZE`. Before the correction four optimized subcases reached an effect trap; afterward all six mode/tool subcases refused before effects. Neither provisioner was executed against live state. The complete existing preparation suite passed5/5. |
| Routine regression coverage | The normal security gate now discovers the unlock and preparation test modules. Native unlock tests are explicitly disabled in this portable gate; the observed native result uses the existing Rust actor, without creating OS accounts. The retired Python principal runners remain absent and unused. |
| Preservation/recovery | Native internal cleanup PASS, one owned child and no unconfirmed PIDs. Account databases, live account authority and installed binaries were unchanged during native qualification. Exact retained scratch removal follows hashed evidence readback. Failure/cancellation service-restoration instructions are now explicit in the deployment guide. |

The bounded Python entrypoint review covered installed unlock, socket recovery, the active auth/mailbox relay source, the two preparation tools and normal test dispatch. `service_socket_recovery.py` matches installed source, uses explicit refusals and fixed sockets, and sends no protocol data. The active account authority is the Rust native-local implementation; retained Python mutation/broker workers are not the selected backend. Preparation tools are repository/operator commands, not installed root-libexec entrypoints. This is not an exhaustive audit of every retained Python fixture.

Two separate relay observations remain outside this repaired unlock boundary. Installed relay source lacks the repository's later typed Documents-read allowance: it retains1MiB replies while the Documents profile supports10MiB binary files. No owner Documents failure was observed; qualify the same typed exchange against the installed and candidate pumps before changing the working bridge. The source also does not join daemon request threads on service termination; actual survival of an SSH child has not been measured, so it is an unqualified lifecycle follow-up, not a claimed live failure. Neither finding explains `/dev/null.part`, and no relay update or public mail-service change was made by this repair.

Evidence root: `/home/foo/Downloads/osmap-ux-s06/unlock-output-incident-20261102/`. It retains the restoration log, source RED/GREEN/optimized logs, actual installed-interpreter suite, exact native input/build/executable/receipt, output-sink and decryption observations, installed Python inventory and relay diff, guarded installation and independent review. Output-sink witness SHA-256: `70f86f91a785f52e4c7e803c0bfdfe10a4b1bfeb8f83acd7b658b993c77d5d3b`. Native build input SHA-256: `492b5a9435c1323ec2bab27b913b22a4ce59e3e88f6468bccdaa057ec48fc518`; executable: `e83769ddca8c9df5a19e0b87437bd13448b71b2579e60f65d9d05ce01aeac46c`.

The preparation author's initial fixture failure and first RED/GREEN outputs were retained only in chat tool results, not independent raw files. That retention gap is explicit; no raw log was reconstructed. A new, separately identified baseline reproduction uses the original `e82b12b` preparation sources and the final regression, with effects trapped before mutation. Its retained `prepare-baseline-reproduction-red.log` records exactly four optimized failures in0.504s. The independently retained current complete preparation suite records5PASS in0.621s. The original chat-only observations and the fresh reproduction are distinct evidence.

Independent actual source/native/installed review is retained in `native-independent-review.json`, SHA-256 `01d4367b11126e4d0c063cefc198f6497c9e64ce6094216878ea7a2776381ff6`. External exact scratch/publication removal subsequently passed in `native-exact-cleanup.actual.log`; the reviewed libtest and source remain retained privately. These observations establish the repaired tooling boundary, not owner key warmth.

The agent-owned output-path correction is qualified and installed; normal signed publication remains a separate delivery observation. Actual owner private unlock and protected-body/source/download UAT remain open. Use the existing private terminal procedure, restore OSMAP after the command returns even on refusal/cancellation, and accept warming only on the explicit success line. The earlier owner failures remain retained after any later successful result.
