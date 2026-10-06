# OSMAP WSTG v4.2 Scenario Matrix

This document summarizes `maint/wstg-testing-pack/wstg-scenario-matrix.v42.json`.

The matrix is a due-diligence control, not a test result. A scenario is not complete until it has either executed evidence or a documented not-applicable proof.

## Current coverage summary

| Category | WSTG v4.2 scenario entries | Mapped by current OSMAP pack | Needs applicability or evidence decision |
| --- | ---: | ---: | ---: |
| INFO | 10 | 10 | 0 |
| CONF | 11 | 11 | 0 |
| IDNT | 5 | 5 | 0 |
| ATHN | 10 | 10 | 0 |
| ATHZ | 4 | 4 | 0 |
| SESS | 9 | 9 | 0 |
| INPV | 19 | 19 | 0 |
| ERRH | 2 | 2 | 0 |
| CRYP | 4 | 4 | 0 |
| BUSL | 9 | 9 | 0 |
| CLNT | 13 | 13 | 0 |
| APIT | 1 | 1 | 0 |

## Interpretation

- `mapped_in_current_pack` means the current OSMAP mapping references the WSTG ID.
- `not_mapped_in_current_pack` means the current OSMAP mapping does not reference the WSTG ID.
- `not_applicable_candidate_but_requires_repo_or_live_proof` means the scenario may not apply to OSMAP, but release due diligence still needs evidence.
- `candidate_gap_for_v3_wstg_due_diligence_backlog` means the scenario should become a manual or automated due-diligence item.

## Supplemental mapping note

The current OSMAP mapping includes these WSTG identifiers that were not present in the retrieved OWASP v4.2 stable table of contents used for this matrix:

- `WSTG-v42-CONF-12`

For those identifiers, keep the OSMAP test if it is valuable, but add a source note that explains whether it comes from latest WSTG content, an OWASP mirror, or an OSMAP-specific supplemental control.

## UX S02-01 search-helper development delta

The authenticated all-folder search operation is a new helper protocol boundary.
Its bounded component evidence supplements the existing mappings; it does not
mark a full WSTG scenario or credential-backed release run complete.

| Existing mapping | Concrete component check |
| --- | --- |
| WSTG-v42-ATHZ-02 / ATHZ-04 | Canonical account and ordered scope grants; foreign/mismatched identities refused; owned native paired accounts and exact mailbox GUID scope |
| WSTG-v42-INPV-12 | Typed search field and literal argument vector; no client-selected program or shell command; pattern-shaped names resolved to exact GUIDs |
| WSTG-v42-BUSL-03 / BUSL-05 | Operation/account/count/order/query/field-bound HMAC, in-process replay refusal, byte/row/result bounds, absolute transport deadline and worker release |
| WSTG-v42-ERRH-01 | Whole-result refusal for malformed/out-of-scope/late replies; finite gateway error codes exclude private queries and native diagnostics |

Executed attempts, source pins and matching deployment outcomes belong in
`docs/UX_EXECUTION_LEDGER.md` and the S02 sprint root. Helper replay remains
in-memory; restart/clock-rollback protection, human password/TOTP, SMTP delivery,
OpenPGP and broad hostile-email or strict-release assurance are not established
by these Search tests.

## Git commit comment

The S02 Manual/On Open repair adds two finite authenticated native POST routes:
`/settings/mark-read` saves the account-owned CAS preference; `/message/open`
verifies the current owned GUID pair and reuses the established Seen action.
Local integrated cases exercise missing/wrong CSRF, foreign/stale identity,
unavailable preference/view, ambiguous flag outcome and worker admission.
GET, reload and Back never change flags; Unread reader retention does not waive
the other original filters or search membership. Existing ATHZ, SESS, BUSL and
INPV scenario mappings cover these component checks. Native and browser results
are recorded in the UX ledger; they do not close full WSTG scenarios, human UAT,
SMTP/OpenPGP or the strict release gate.

The S02 conversation-order component carries optional bounded public thread
headers through the existing authenticated message codec. ATHZ account/GUID
checks remain in the actual routes and reader; INPV/BUSL checks cover strict
typed metadata, bounded references/results/frames, ambiguous duplicate and cycle
refusal, current filtered membership and explicit-sort precedence. Unknown native
headers retain usable independent rows, while malformed helper metadata is
refused. This adds no helper command, body fetch, authorization or sender trust.
Actual model, disposable native and no-script browser outcomes belong in the
ledger and do not establish full WSTG or human Send acceptance.

```text
add wstg due diligence matrix
```

The S02 configurable Bin component adds authenticated `/settings/bin-folder`
with exact CSRF, revision, folder and return-section fields. Current account
LIST and a unique private selectable native namespace are checked before CAS;
stale/corrupt/foreign/unselectable states refuse without a Trash fallback.
Existing ATHZ/SESS/BUSL/INPV mappings cover these bounded checks. Reversible
Bin/Restore still uses the established message GUID-bound move path, one worker
and current owned folder facts. The disposable OpenBSD proof moves exactly one
synthetic record to Deleted and back, preserving GUID/flags, neighbours and a
second account; it performs no append, expunge, SMTP or cryptography. Actual
results and signed deployment pins belong in the UX ledger. This does not close
whole WSTG scenarios, human UAT, strict release or permanent-deletion authority.

The saved reader-presentation repair adds no route or download permission.
Existing account/session authority selects current persisted source/attachment
display preferences; stale cookie hints do not override them. ATHZ/SESS checks
cover account isolation and response-scope reset, while BUSL/INPV component
regressions preserve corrupt state, finite presentation defaults, identical
escaped source text and decoded attachment bytes. Native disposable mixed-value
saves/readers restore fixture state; installed validation is GET-only. Current
executed proof and deployed binary pins belong in the ledger. These component
checks do not close entire WSTG scenarios, strict release, human UAT or Send.

Native Source/Download component execution now follows actual renderer GUID
links through Runtime gateway, signed helper and disposable Dovecot. ATHZ/SESS
controls include foreign same-UID, stale GUID and unauthenticated refusals;
INPV/BUSL controls retain selector rejection before native reads, escaped stored
source, exact decoded bytes, forced-download isolation and reusable budgets.
This extends executable bounded evidence, not routes, permission or whole WSTG
scenario/release acceptance. Actual source/binary/outcomes remain in the ledger.


## UX S04-02 private mutation and SMTP-control development delta

The disabled account-mutation components add command and private-descriptor
boundaries. Existing ATHZ/SESS mappings cover canonical account scope, current
kernel peer admission and channel-generation isolation; BUSL/INPV cover the
source-derived cutoff, account lock prerequisite, finite frame grammar, one-use
cancellation, original absolute budget and uncertainty latch. CRYP component
checks exercise actual native ARGON2ID full-tail positive/negative verification;
CONF component checks cover closed client configuration and disposable kernel
write restrictions. These are bounded component results recorded in the UX
ledger, not completed WSTG scenarios or release evidence. Local UID admission
does not prove unique supervised-worker ownership, installed module custody,
all authentication ingress, native factory activation or human password/Send
acceptance. The password form and native qualification gates remain disabled.

The next disabled control composition adds distinct-purpose password-free MAC
delegation and a durable consumed-grant journal to ATHZ/SESS/BUSL/CRYP component
coverage. Original receive-time budget and current source listener custody are
rechecked; complete grant publication precedes terminal acknowledgement. Late
acknowledgement failure remains unconfirmed after possible cutoff consumption.
Native key/issuer custody, worker/flock continuity, production ingress and TCP
absence remain unqualified. This does not close a WSTG scenario or password UAT.


The adjacent disabled integration requires original receipt provenance rather
than equal-expiry budgets (BUSL/SESS) and mandatory typed command custody plus
irreversible child confinement for SQL/hash/primary transport (CONF/ATHZ).
Normal regression discovery now includes command authority, original phase,
owned-child cleanup and strict ELF full-mapping/cap negatives. Kernel/custody
calls are mocked in the portable fixtures; installed graph/profile/native
factory and the composed authoritative password workflow remain unqualified.
No completed WSTG scenario, release claim or human password UAT follows.

Bounded grant retention adds BUSL/SESS component controls: completed expired
authorizations retire only under the durable journal lock/time high-water;
replay, rollback, unresolved and legacy records refuse. Entry/byte limits stay
fixed. These private-file controls do not qualify native key provisioning or
the actual password workflow.


Guarded worker-builder integration adds source-level BUSL/SESS/ATHZ controls:
locally verified original frame and receipt, distinct-purpose minimal broker
MAC, mandatory issuer ACK before pending capture, source-owned descriptor/group,
held intent lock, invalid proof/nonce/EOF refusal and final descriptor cleanup.
Five actual local worker children exercise this ordering; SQL/primary and
external TCP/IMAP remain projected. Existing supervisor peer equality is not
browser issuer custody. Native factory/listener/complete mail containment and
human password UAT remain OPEN; no completed WSTG or release claim follows.


Persistent control-listener BUSL/SESS source controls preserve one owned inode,
independent account grants and original captured-operation budgets. Two actual
queued kernel-accept countercases now refuse trusted stop or uncertainty before
frame/journal/cutoff dispatch. Replay/terminal loss halt admission without grant
or quarantine reset, and foreign namespace replacements remain untouched.
Installed native startup, complete ingress and full password UAT remain OPEN.


Hash-child configuration/authorization source controls require fixed public role
records, unique IDs, exact nologin/home, bounded nofollow custody, unchanged
original phase, empty supplemental groups and saved/real/effective GID/UID drop
before irreversible child sealing. Unrelated UTF8 public fields remain accepted;
public placeholders provide no private credential-lock evidence. Shared born
worker tests add original issuer/intent/broker ordering, proof/nonce/deadline
negatives and cleanup with actual local children. IDs/kernel APIs and native
SQL/current-primary/Rust issuer and external mail remain projected.

Actual native13 PASS11 qualifies bounded public metadata inventory and lossless
report reconstruction, not a kernel profile, loader completeness, installed
worker/factory or human password workflow. All production activation remains
disabled; these entries establish no completed authenticated WSTG or release.

- Hash/shared-worker normal commit attempt1 refused at the unchanged TLS policy guard: the Python identifier `NULL` for the fixed existing `/dev/null` device matched its prohibited-cipher token scanner. No commit was created. Earlier Rust library stage passed1577/0failed/38explicit native ignores; later gate stages are not inferred. The two-path identifier-only repair uses `NULL_DEVICE`, preserving fixed device metadata, custody, public-record and drop behavior; no scanner exclusion or policy waiver. Original failed log SHA256 1e3cc32b578431fdda1a1d8e5eec10b95c75866c1955c82b18c98add9844a5cf. Matching focused/source review and superseding normal gates remain separately required. No native identity provision, profile or form activation.

### 2026-10-06 — S04-02 fixed hash graph and native logger compatibility

- Source checkpoint `dfecbc454d3eaf88fd272eecdefa6c8a9a8ee150` Good Shopkeeper signed and normally synchronized; actual both normal gates1577 Rust PASS/0failed/38explicit native ignores,457 account Python PASS/0skip,22 mail cases/one local native skip. Fresh fetch proves HEAD/origin equality clean0/0. Proof `hash-identity-shared-worker-integration-attempt1/signed-sync-proof.json` SHA91856c1c2c2dc0e09b67cdf89f15bd7b971b2795ed9f50672db185a6323d8b8f. Original TLS identifier refusal retained. New source-only standard mail sync SSH255/8.274s connection timeout before remote dispatch; last successful observation was b12; current host HEAD after the timeout is UNKNOWN and dfec synchronization is not established. No service/binary/config/form or identity activation.
- Root integrates exactly reviewed hash graph five-path source plus native logger two-path repair. Hash review69e3de10d9a72cca6043fd40779d41fe2bbb24932dc7f447a30c80967fbcf2c8 binds original inventory13 exact public bytes:19 ELF objects plus hints/22fixed rows, full hash/nine leaf metadata/ancestry, same original budget parent and child rechecks before private-identity drop and locked kernel. Only one compiled module directory receives read, with stronger ALL-five-entry check still native unmeasured; no account database grants. Loader effective resolution, native saved-ID/DAC/null lifetime and full production graph remain unqualified; profiles stay empty. Logger review82226453d5e3a01048566015701ea03d5ff5dedf88206e659ce0aaacc3c15208 admits only required eight-token postlog/unix-dgram/postlogd without extra options as non-SMTP, retaining unknown/duplicate/AUTH negatives.
- Matching canonical graph attempt1 FAILED1error/20passes because the test-only reconstruction referred to an uncommitted external prior-evidence report. Root makes the test self-contained using exact sanitized public metadata fixture `fixtures/hash-installed-inventory13.json` SHA16e5526f6a175c33380fdd116def99212d99f0d12a3752aba09a39a881bb21b9,142821 pretty-file bytes;80461 canonical expanded-byte measurement remains distinct. Both test path references change, original full-report hash/closure/node assertions stay unchanged; no product logic or assertion relaxation. Superseding matching graph21 PASS and logger3 PASS; original failure retained. Normal combined gates/sign/sync separately pending.
- Separate composed SMTP/IMAP native package2 remains unexecuted/CHANGES_REQUIRED: deterministic root staging-prefix mismatch refuses before imports; exact wrapper-name correction is under review. Independent unchanged3s positive failed twice, scalar diagnostic later passed2.921s with237 custody checks consuming2.632s and57 fixed dispatches. Those observations do not prove a unique failure cause or native performance. Adjacent source3 reduces redundant transport-only custody work while preserving fresh authority at every actual dispatch and post-command, original deadline and independent closure; full source/custody review still required. No provider Send, SQL/operator-password mutation, factory/form activation, S04/UAT or epic acceptance.


### 2026-10-06 — S04-02 bounded private proxy-file substitution regression

Actual predecessor6PASS/2FAIL reproduces both configuration/certificate writerless-FIFO substitutions at open. Exact two O_NONBLOCK additions produce8PASS, affected53PASS and independent8PASS/0skip with original custody, FD/name continuity and operation limits unchanged. Source reviewbc87e544a145bcc856561437badf804c6761c2d5cfa2d73ed92317c5d9794dba; evidence `proxy-config-preopen-increment2`. Owned blocked children are reaped/group absent before parent-owned scratch cleanup. This is source regression assurance only, not authenticated WSTG, full filesystem deadline coverage, native3 cause, password factory, release or human UAT qualification. All production profiles/form activation stay disabled.

- Normal proxy commit attempt1 was refused before signing. Initial account489PASS was followed by a later nested release regression489cases/1FAIL: replaced socket test thread alive after its original one-second join. Rust1577PASS/0fail/38native ignores and mail22cases/one local native skip had passed, but the full gate did not. Logcf1f25419e7658b661eeb46d7ed7ddf3cc623b3506c085ca35bbef086cd7f62a is retained; the actual failure's unique cause remains UNKNOWN. Separately demonstrated fixture readiness gap: path existence is visible before listener inode capture, grant publication and listen. A delayed real bind discriminator fails on the predecessor; the repaired fixture waits for completion of actual listen on its fixed owned path. Matching10 focused controls PASS; original one-second joins, replacement-inode assertions and production source/deadlines remain unchanged. No unchanged retry or test assertion weakening. Final candidate review and superseding normal gates/sign/sync remain required. Full workflow and UAT stay OPEN.


### 2026-10-06 — S04-02 disabled role-bound mint composition

The actual MaterialExecutor constructor now passes role, typed material, account and original receipt-backed budget to the source mint; returned foreign bindings refuse. The installed registry remains empty and public native construction remains unavailable before reads/spawn. Nine changed and two affected local controls include actual owned-child transport and a genuine predecessor constructor failure; installed graph/ID/kernel/SQL/primary are projected. This is a source composition prerequisite, not completed authenticated WSTG, native password workflow, provider delivery or release qualification. Later composed7 and hash5 failures remain retained in the execution ledger and exact evidence roots; all workflow/UAT acceptance remains OPEN.


S04-02 hash graph increment: actual authoritative fixed fixture PASS20 (result02234155, scopeee70e6ce) establishes six installed synthetic ARGON2ID operations, long-tail negatives and closed identity/kernel/cleanup controls only. Exact matching five-path source/ordinary-fixture candidate retains current role-bound kernel while adopting the qualified graph. Ordinary source11/graph3/ownedguard2 and affected role9 tests pass; profiles remain empty. Recursive public directory read/prot_exec reachability is disclosed, not complete recursive byte/module or production-null qualification. No authenticated application WSTG, full SQL/primary/issuer/password workflow, provider delivery, human UAT or S04/epic acceptance is claimed.


### 2026-10-06 — S04-02 composed authority remains unqualified after delivered source

Signed source65772b116ad023a788428c9c8621bda31b08392d passes both ordinary1577 Rust/510 account/22 mail gates, fresh GitHub equality and authoritative standard-mail source-only synchronization. Source9's two matching original-root continuity countercases repair the rejected source8 paired-root seam; source8 was not executed. These are bounded source/custody controls, not authenticated application WSTG completion.

Actual composed9 obsd1 execution FAILED unexpected_Invalid before issuer ACK/held-intent/capture after original5s startup completed and11 execution-server requests returned. The underlying worker/frame outcome is UNKNOWN; historical timing fields overlap and no recorded inner server failure supplies a cause. SMTP3AUTH/2OK and startup IMAP2LOGIN/1BobNOOP remain partial native witnesses; supplemental relay diagnostic overflow prevents complete logging qualification. All four owned groups, both scratch roots and runtime root gone, standard metadata preserved; root code stage retained. Exact resultdb0480bd347e71e9189ab91643abc73a5b937829b6aa9c48bebc5be7c6fedf94/scopef9276daf7fab16f360c791b4e89c90699b6b2908222a72265ab81d4d480c0690. No provider mail or SQL/operator-password mutation. Native factory, current Rust issuer/ingress, SQL/primary composition, password form, human UAT and S04/epic acceptance remain OPEN/disabled.

Branch equality/upstream preservation and the operator-reported manual Redmi fallback are operational context only; neither constitutes a security scenario, automated failover test, release qualification or slice acceptance.


### 2026-10-06 — S04-02 fixed SQL producer source controls

Seven-path disabled SQL source review073744ddf2c23b068de062819d165ed9fdb81204c27e8bfbfb264785d144cf2f and matching canonical10 tests establish bounded role/account/material/budget/public-byte and child transport controls. Actual OpenBSD kernel, loader, database grants, full factory/current issuer/primary/containment and password workflow remain unqualified. The fixed13-ELF/hints/17-row SQL graph does not inherit hash permissions. Profiles remain empty and password form disabled; authenticated application WSTG, release qualification and human UAT remain OPEN.


### 2026-10-06 — retained native11 composition outcome

WSTG continuation evidence — Independent native composition11 outcome: the single admitted obsd1 fixture run failed (full result SHA256 b12e13eaddf15785c88fa21ec4c790edf0d8c61bbb9b85704b5a4fa6198f00c2; independent scope 523acdb96377c955e856ce664c673e9b9b31f6fdf8e234dc8fd05fb982591014). All 124 source manifest files, 42 package files and 38 result input pins remained exact. Its first issuer frame was an authenticated early terminal known_refused, rejected by the unchanged challenge-only verifier before issuer ACK or capture. After confirmed owned worker closure, the bounded advisory report recorded the first preflight failure at proxy_run as ValueError/codeunknown, readiness false, SQL calls 0 and capture false. This narrows the current refusal stage; the exact returned-result validation term and unique underlying cause remain unknown, and native9/native7 are not retrodiagnosed. The server completed 11 requests and normal channel EOF without an exported inner failure; that completion is not mutation success. Overlapping fixed/current timing samples do not establish deadline expiry. Startup completed under its original five-second cap; two private IMAP logins and one Bob NOOP and three SMTP AUTH attempts/two completions were measured. Relay diagnostic overflow remained true and logger diagnostics remained unqualified. All four owned groups, both private scratch roots and the separate runtime root were absent after cleanup; standard metadata matched and cleanup reasons were empty. The failed root stage /tmp/osmap-pxp-stage-fd1e5cb52462190d was retained. MAIL/RCPT/DATA/BDAT and provider counts remained zero. Every composed acceptance flag stayed false; production factory, form, full workflow, D04 UAT and S04 acceptance remain open. No unchanged native retry is justified by this result.


### 2026-10-06 — S04-02 real stored-session issuer qualification source

Source checkpoint692497650bdea5b4cc52e0becbb28cf0ad30fde6 is Good Shopkeeper signed and normally synchronized; commit/push gates1577 Rust/0failed/38explicit native ignores,518account Python/0skip,22mail cases/one local native skip. Fresh GitHub equality and all three local OSMAP branch heads match their corresponding origin references. Actual authoritative standard checkout clean source-only fast-forward657→692 completedSSH0/4.764s. Proof `native-sql-role-producer-increment1/canonical-integration-attempt1/signed-sync-proof.json` SHA18424be3f1dbb056cabf1e2c42784253a92f3fe070d8590dbfc2cb64403ea798; no binary/service/configuration/form activation.

Admit four test-only real stored-session issuer paths over that exact checkpoint. Real FileSessionStore, GuardedSessionLease and typed Prepared/StoredSession issue and verify the challenge/ACK exchange with the real PythonWorker for Alice while independently preserving Bob stored state. Controls exercise current/revoked/wrong-account/wrong-proof leases, changed challenge without ACK, missing ACK containment, terminal without EOF uncertainty with zero reconnect, anonymous descriptor identity/type and named/nonstream refusal. The native entrypoint remains compiled but explicitly ignored until the matching root-held binary, anonymous descriptors, born process, namespace and role-key custody are qualified. Registration is test-only; no production Rust issuer, session implementation or account profile is changed. Whole source review85ae80bff18817b6e01cc94d8ca5fa0f817314894f7b02c8872b9633b5ba5f24 CLEAR. Actual matching canonical eleven controls PASS11/0failed/one explicitly ignored native case in3.21s; `rust-stored-issuer-composition-increment1/canonical-integration-attempt1/focused-matching11.log` and `source-admission-pins.json` SHA fef8e5a4c658a61d3231f10b2467930dcbf60bd5cb9d078fb1ef97705610ebd8 retain exact source. Browser, primary credential check, TOTP, current policy, SQL, mail topology and whole D04 ingress remain unqualified by these controls.

One independently admitted changed native12 diagnostic run on obsd1 still FAILED. Resulta80b768739e89febf0d9863802c208bcc386de3ce27216bb8fc2a2c21bcd1b57/nested driver3a091248f04ee5ede99051e1a83a8fd89a699fbe918325458e975b6a7bb17b72 records the first proxy_list result: exit-11, stdout0bytes and stderr97ASCIIbytes/nonempty with Error label. Tuple, integer, byte types and original size caps pass; the unchanged proxy guard refuses nonempty stderr. This measures abnormal CLI child termination, not a benign warning; the underlying crash cause is still UNKNOWN and earlier native11/9/7 causes remain independently UNKNOWN. Startup completed with2343ms of the original5s remaining; early authenticated known_refused was rejected before issuer ACK, SQL0 and capturefalse. Eleven execution requests completed with normal channel EOF, which is not workflow success. All four owned groups, both scratch roots and runtime were gone, standard metadata preserved and cleanup reasons empty; rootstage `/tmp/osmap-pxp-stage-e5f61b62c6d5b769` retained. Zero provider/MAIL/RCPT/DATA/BDAT; full composed acceptance remains false. Evidence `native-smtp-worker-composition-increment12/native-attempt1`. No unchanged retry, stderr tolerance or deadline widening follows.

Production profiles remain empty, Runtime account client None and password form disabled. Normal final integrated review, gates, signed commit and synchronization remain required for this source increment. Full S04-02 workflow, human ALLSEND/protected provider receipt/signature/return/readable encrypted Sent/key lifecycle and epic acceptance remain OPEN.


Normal signed commit attempt1 was refused before signing by the unchanged strict clippy gate: six unnecessary casts in the new test-only bootstrap descriptor fixture. Earlier matching11 controls had passed; they were insufficient for that lint gate. The four-line portable-stat repair uses libc dev_t/ino_t/mode_t and same-typed socket constants, preserving the raw native fstat equality instead of normalized casts. Pinned libc0.2.183 OpenBSD ABI has signed32-bit dev_t,64-bit ino_t and32-bit mode_t. Independent repair review7a28251e2e0e96d944fe765bf56cbbb3becf6861239e077150ca9c7b2e2dba22 CLEAR; actual matching two affected descriptor controls PASS2/0failed and unchanged strict clippy all-targets -D warnings PASS. No warning allowance or check bypass. Refused commit log and matching repaired results are retained under `rust-stored-issuer-composition-increment1/canonical-integration-attempt1`; a superseding normal signed commit/push remains separately required.


Superseding normal commit attempt2 was refused before signing by V11's unchanged generated V10 inventory check after the added test fixture changed source assumption counts. The existing `osmap-v10-fail-closed-remediation.py` generator refreshes only its derived register: timestamp, test counts and inventory hash. Scanner, generator, hooks and acceptance predicates remain unchanged; no waiver. Exact outgoing candidate now includes that generated register as an eighth path and requires independent final review and superseding normal gates/sign/sync.

Changed native13 endpoint-role source repairs the independently demonstrated administrative CLI listener mismatch, without attributing native12's underlying crash instruction. Its actual first proxy_list returns exit0/stdout216/stderr0, expected header and two canonical backend-matching rows. The full run still FAILS later: first worker topology_recheck Refused/topology_continuity, outer unexpected_TimeoutError,21 execution requests/resultsFailure with no exported inner cause. Original5s startup had2184ms left; current/fresh timing counters overlap and do not establish expiry. No issuer ACK/held-intent/capture/SQL; all four owned groups, both scratch roots and runtime gone, standard metadata preserved, cleanup reasons empty; rootstage `/tmp/osmap-pxp-stage-f89a3609d7f8e246` retained. Result0e5e4c1fe763b9b479b6bfd49800a8878cd1fabf1bab24df941402d0d2bf82a9/nested63e51ec1331e25a4091d91b7dfe240027bbd3e3cbbdb66ceb4bcfb4e23591284/independent scopef992a79dd5f57f19c9b69280854b635cb1745afab60124da5573004ae17fc2ea under `native-smtp-worker-composition-increment13`. Earlier failures retain separate UNKNOWN causes; partial SMTP/IMAP primitive success does not qualify current whole factory or human UAT.


Normal signed commit attempt3 was refused before signing by the unchanged CWE Top25 guard. Six test-only issuer patterns crossed its reviewed boundaries: direct process construction and five unsafe descriptor/FFI calls. The repair moves the same fixed synthetic process construction into `src/auth.rs` and the same socket type, identity, peer and owned-descriptor checks into the reviewed Unix FFI boundary `src/openbsd.rs`. The fixture invokes those bounded helpers; neither the guard nor its allowlist changed. Actual affected descriptor controls PASS2/0failed and the unchanged CWE guard PASS. Full matching issuer controls and strict clippy remain the final source gates. This is a defensive boundary repair, not production issuer activation; native browser/account/mail UAT remain OPEN. The refused attempt3 gate log and corrected checks are retained under `rust-stored-issuer-composition-increment1/canonical-integration-attempt1`.
