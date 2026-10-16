# OSMAP WSTG v4.2 Scenario Matrix

S08-02 leaf disposition source increment, 2026-10-15: the attack surface adds
the actual Deleted folders, empty Delete, Bin, Restore and original-result
check routes with exact bounded fields. POST retains current session, CSRF,
account role, identity and typed signed helper authority. Purpose-versioned
grants preserve legacy None bytes. Private bounded receipt reservations,
terminal-before-role-clear ordering and explicit no-redispatch recovery cover
the independently found predispatch gap. Focused local controls PASS; matching
native, installed lifecycle and independent delivery review remain required.
No whole WSTG, release, parent slice or human acceptance is inferred.

The route extractor now expands explicit Get|Post tuple alternatives, rejects
unsupported method grammar and retains exact missing/stale set checks. Actual
gate refusal exposed this blind spot and the previously omitted Move GET/POST
rows; the inventory now includes their exact accepted fields. Fifteen focused
runner controls pass, including removed-method and unsupported-grammar refusal.
This is corrected static evidence extraction, not live target WSTG acceptance.

S08-02 Folders navigation increment: authenticated GET `/folders` accepts only
the bounded account-owned folder selection and reuses existing metadata/status
and reviewed Create/Rename/Move routes. Alice/Bob, malformed selection and
no-mutation-on-GET controls pass locally. One synthetic browser journey passes
keyboard Create/review/confirm, persisted hierarchy, existing edit forms, mailbox
opening, Bob isolation and light/dark wide/narrow layout with no scripts or
external/Send requests. This is frontend evidence, not authoritative installed
folder mutation, whole WSTG or slice acceptance. The attack surface declares the
actual new route/query; authentication, CSRF, helper and existing route checks
remain unchanged.

S08-02 private leaf Move source/native increment, 2026-10-14: exact helper grant
binds current source/destination parent identities and existing account/current
role/session/request authority. Matching native-attempt2 binaryd1b9c73b passes
populated Move GUID/full-summary/exact-body/Label/Snooze continuity, Bob isolation,
lost-result/no-redispatch reconciliation, protected/stale/authority refusals and
actual confinement/current-fixture cleanup. Earlier failed-fixture cleanup
remains unknown. This is bounded disposable native evidence, not installed
operator UAT, recursive-folder or full WSTG/sprint qualification. New Folders
navigation engineering request78 retains the same account-bound backend checks.

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

### 2026-10-06 — approved ordinary Send recovery and refusal correlation

The operator-approved priority exception is recorded in
`UX_MAIL_DELIVERY_REFOCUS_20261006.md`; frozen R2 requirements are unchanged.
The actual Runtime Compose→Send regression reproduces a revisionless ordinary
request refused as stale despite Optional account policy. Removing that
redundant preparation clause changes the controlled route from HTTP503 to
HTTP303 with one owned local submission. Explicit stale revisions, selected
protection without a revision, Required-recipient plaintext and final binding
locking remain enforced. Normal generated Compose includes its revision, so
this regression does not diagnose the operator's historical fifteen503s.

The real pre-dispatch preparation refusal now emits one allowlisted reason,
request ID and hashed session reference; arbitrary error text, address,
subject, message, key and credential material are excluded. The denied Runtime
gateway test records exactly one event and zero submission/append; the HTTP
route test checks the event and no additional owned sendmail invocation. This
is diagnostic evidence, not acceptance of a Send journey. The local library
regression before the final native-test reordering/path quoting passed1591/zero
failed/39 explicit native ignores; focused route/compile checks passed after.
Independent
increment3 review cleared the six changed source/test paths; native HTTP
tests run before the fixture deliberately stops its crypto helper. First
obsd1 compilation failed its inherited1.5GiB data limit, not a measured
application defect. A process-local8GiB compilation is separate from runtime
budgets. Matching native execution, deployment, authoritative Sent/provider
receipt and human UAT remain separately required. No provider Send or operator
key/policy change is authorized by these test results.

Superseding exact increment5 OpenBSD native attempt3 PASS1/zero failed/skipped:
binary `ce8b6a7ebd887f0a30a2f2f58df007f9f8b2767958a2d49cac84bcd745d58389`,
log SHA256 `332f4a0b52d2ad3de2fee4e94ab7871d229465a472ae29cd3c8799c99aec07f7`.
Seven owned loopback submissions/controlled Sent saves include generated
ordinary/encryption-only HTTP routes, exact decoded body, Required plaintext
refusal, replay/stale/missing-helper negatives and ordinary submission with
the private helper stopped. The two prior fixture failures remain retained:
SMTP transport adds exactly one final CRLF for the unterminated plain body;
decrypted MIME needs transfer decoding before comparing authored content.
This is not authoritative mailbox/provider or human acceptance; matching
normal signed synchronization and web-only activation remain separately required.


Normal signed commit attempt3 was refused before signing by the unchanged CWE Top25 guard. Six test-only issuer patterns crossed its reviewed boundaries: direct process construction and five unsafe descriptor/FFI calls. The repair moves the same fixed synthetic process construction into `src/auth.rs` and the same socket type, identity, peer and owned-descriptor checks into the reviewed Unix FFI boundary `src/openbsd.rs`. The fixture invokes those bounded helpers; neither the guard nor its allowlist changed. Actual affected descriptor controls PASS2/0failed and the unchanged CWE guard PASS. Full matching issuer controls and strict clippy remain the final source gates. This is a defensive boundary repair, not production issuer activation; native browser/account/mail UAT remain OPEN. The refused attempt3 gate log and corrected checks are retained under `rust-stored-issuer-composition-increment1/canonical-integration-attempt1`.

### 2026-10-06 — S06/S07 protected reading, disposable native controls

Two source-matched OpenBSD runs each PASS one existing native case and zero
failures/ignores. The protected Sent reader runs on reviewed patch
`44ed0066ed6bd413328d89cfdccd77bf35429339769a25bfe699a86befc5e16d`
(log SHA256 `b7b60a244c17561a9b7e547a599a4dfeb5eb0644a2bf6bc8be8882ee4b492fa0`).
The three-test-path inbound-return extension runs on full patch
`7ccc3df07acfef1e67702c4d995c93417168f3eebf4f54519ac050346628b22b`
(385 compiler inputs/zero mismatches; log SHA256
`bd58e18c4bfeecc1d432bae443a097ccf4fe61c8706c1ad438a5288d3dc3bd21`).

Controls: exact encrypted wire is stored only in a private Dovecot Sent or
Inbox fixture; the authenticated helper and Runtime `/message` route decrypt,
MIME-decode and verify the signed body and Bob's approved fingerprint. A
withheld disposable agent socket yields Locked and suppresses decoded content;
source ciphertext is unchanged. The read and return probes add zero SMTP
submissions and zero Sent saves beyond the harness's existing seven controlled
loopback submissions and seven disposable saves. Fixture cleanup and standard
metadata preservation are asserted. This does not test provider receipt,
authoritative Dovecot mailbox state, operator keys, or human UAT. Signed source
`23e5feee16ebfae73656f35ec8b8863c9fc54594` and deployed obsd1 binary
`c305e5283a9d6631ee1032a07fcf67304489c287a7c4e29935ab932cfd1f0263`
remain unchanged by the overlay; S07 and full epic acceptance remain OPEN.

Normal commit attempt1 refused the test-only bridge placement under Clippy
items_after_test_module; no commit was created. The byte-identical bridge was
moved before the test module without a lint allowance or runtime change.
Focused Clippy passed. A changed native build, 385-source parity and final
return attempt2 then PASS one exact case/zero failures, binary
1f22e94ba30db10cf4d912b75d653fc414b6b5e40af5e60a5ee9e25bed9f1016,
log SHA256 bc9f53fcfa671a2d3a3d1b1f3280820a2498db9ff065b8dacb9dda9dcf50aced.
Final bridge source SHA256938c404257e1c02d8319a1bbe64d7636250c1facf5b12771c0eb9dfefd67fc82;
retain earlier native passes and the refused commit. Normal signed admission
and synchronization remain required; provider/human acceptance stays OPEN.


## 2026-10-06 — S08 Documents source controls; native and human acceptance open

S08/PAGE07 adds source controls for account isolation, opaque document IDs,
CSRF-bound writes, same-origin attachment downloads with original-name
escaping, bounded 10 MiB body/response handling, helper peer/HMAC/replay
checks, exact byte digest validation, and fail-closed unconfirmed mutations.
The unconfigured synthetic page returns 503 with no upload/file input;
existing Bin cleanup is separately testable when quota is unavailable.
Local library controls and the first-upload native refusal are bounded
development evidence. They do not close authenticated WSTG scenarios, native
helper/Dovecot quota enforcement, configured-runtime UI, provider transport,
or human UAT. Record separate exact native/browser results before promoting
PAGE07 or whole-sprint status.

## 2026-10-14 — startup custody, sanitizer patch and ordinary preflight

Four required development helpers were restored after exact abandoned-socket
identification. The fixed-service root startup helper has 18 local and 18
OpenBSD controls for live/foreign/replaced path refusal and zero-byte recovery;
installed rc_pre qualification remains pending. This does not qualify host
reboot recovery, authentication or mail delivery.

The mandatory audit refused ammonia 4.1.4 under RUSTSEC-2021-0157/0158.
The compatible 4.1.7 update preserves OSMAP's style/SVG exclusions. Fresh
matching OpenBSD source tests passed nine sanitizer and 59 MIME cases, with
one separate fixture explicitly ignored; no installed release claim follows.

Actual installed allOff Pre-send review returned 503 on missing unused public
inventory, before any Send. The three-path repair evaluates authoritative
binding policy against explicitly unavailable inventory; it grants no public
key capability or private-client authority. Source RED3 to GREEN12 covers
ordinary default/existing revisions, Required account/recipient protection,
selected protection, stale Send pins, corrupt policy and zero crypto dispatch.
Eighteen protected-submission and three stale-recovery controls also pass;
one protected native fixture is explicitly ignored. Current Send preparation
and locked revision checks are unchanged. Matching native and installed
ordinary-mail qualification remain required; authenticated WSTG, protected
provider delivery, original slice acceptance and full release remain OPEN.

Signed90461aa is now installed as image11085bca on the authoritative helper
and obsd1 web. Real controlled A/B password/TOTP login, ordinary Pre-send,
original/reply/forward submission and six authoritative Inbox/Sent MIME copies
pass, including exact attachment bytes and reply threading. Zero provider Send.
The retained Draft survived the actual application upgrade. One installed
auth-relay stale-socket recovery passes with all six required services healthy
and unchanged application/configuration; full reboot and other installed stale
cases remain unqualified. Later harness flag-navigation timeouts dispatched no
flag mutation and remain retained. These bounded results do not close the
complete authenticated WSTG, core baseline, protected-provider or release scope.

## 2026-10-14 — bounded native encrypted-Bcc privacy

S07-03 removes only the blanket runtime Bcc refusals after existing trusted
recipient/policy/revision checks and one changed native privacy qualification.
The three-home outgoing fixture proves visible/hidden recipient decryption,
excluded-sender no plaintext with usable-key positive controls, exactly two
hidden recipient packet IDs, no Bcc header/address in emitted or Sent-request
bytes, and exact real-backend envelope capture. Native test
0ca6370e6f95339162dcaec0ae868be6b0538d6125d5f032d4f8a8a9665c0059 passes with
matching464 compiler/three qualification inputs and disposable cleanup markers.
The measured outsider Unavailable error has no established underlying cause.
Retained invocation/MIME/assertion failures are superseded only within their
corrected test scopes. Evidence is under osmap-ux-s07/encrypted-bcc-20261014.
No browser, SMTP, authoritative Sent storage, provider receipt, full WSTG or
release acceptance follows from this disposable envelope/ciphertext proof.

## 2026-10-14 — stale native private-agent endpoint

Exact source9a5b79e0 and launcher2d3df2b3 pass one changed outgoing native fixture
with existing Rust binary0ca6370e. A deliberately abandoned owned socket returns
Locked with no body for Sign; public Encrypt and Verify pass unchanged. Exact
stale recovery through the existing bounded launcher is followed by real Sign.
The prior Bcc, recipient, self-decryption, signature/tamper and cleanup controls
remain passing. All five source inputs match, including the imported launcher.
This does not qualify a full restart, operator private unlock or installed reader.
Actual operator Proton-first and Thunderbird-second delivery outcomes are kept
separate in the UAT records. No broad WSTG/release or full sprint claim is made.

## 2026-10-14 — Crypto service ownership and inherited signal disposition

The retained startup/rollback failure exposed lost wrapper supervision. Native
metadata and failed bounded TERM show the current orphan ignores TERM. Reviewed
three-path repair makes RC own the foreground helper and restores SIGTERM's
default before serving; strict owned dead-socket recovery remains unchanged.
Matching native464+3 source parity, inherited-signal PASS1 and wrapper/recovery
PASS4 establish bounded source/native behavior, not installed lifecycle or
functional rollback. Current-role forced restoration of the old service is
separate operational evidence. No private agent, provider mail, broad WSTG,
release or full-sprint acceptance is claimed.

Superseding FFI correction: the normal CWE gate rejected a libc call outside
src/openbsd.rs. Four-path ac88ca98 uses the existing safe boundary; unchanged
CWE guard PASS and matching native signal PASS1/helper build/source parity.
The earlier three-path native build is historical, and unchanged wrapper
PASS4 is reused. Installed lifecycle remains pending; no scanner waiver.

## 2026-10-15 — explicit bounded folder repair and retained uncertainty

S08-02 adds authenticated GET review and CSRF-confirmed POST at
`/settings/folders/rename/recover`; the only fields are `csrf_token`, `confirm`
and an account/original-operation-bound `recovery_nonce`. Existing configured
helper peer/grant checks, finite GUID-bound descendants, consumed nonces and
original native budgets govern one explicit child repair. Generic executor
errors never supply settlement. Original Check requires the authoritative
`Renamed` witness as well as current parent/tree identities before success.
Missing settlement retains nonsuccess, mail/indexes and the original reference
for engineering-owned reconciliation; neither snapshots nor a lock prove
child quiescence. The existing native fixture labels its partial-placement and
settlement setup as injected; this does not qualify an actual process crash.
Superseding a391/945f source and helper-first pair installation pass their
recorded gates. Injected native partial placement repairs signed owned children
without replaying the root. Actual installed Create/Rename/Move and label
relocation pass; the later read-only Bin entry exceeds the10s client bound,
before any Bin POST. Preserve its failed interval and retained current state.
Repair read amplification without reusing pre-dispatch facts after a mutation,
weakening fresh helper authority or extending the failed deadline. Remaining
Bin/Restore/reloaded-badge qualification is pending.

The same-slice typed `folder_facts` helper operation is read-only and binds its
account plus ordered literal names/count in the existing HMAC grant. Configured
peer, nonce and bounded EOF remain required; exact missing/extra/duplicate/foreign
snapshot/status replies refuse. Eleven names/4096 decoded bytes and bounded
metadata/status/reply projections remain inside global transport caps. Native
metadata plus multi-name STATUS share the original command deadline. Independent
fresh pre/post observations do not reuse proposal or pre-dispatch facts; native
mutation checks and completion witness remain separate. Source negative tests
and independent review pass. Corrected actual nativecase passes all12 markers
under original budgets; installed exact five-name signed facts passes3812ms<5s.
Matching a902/f472 helper-first installation preserves the recorded boundaries.
The remaining workflow passes entry/review, then Apply3 client reply is unobserved
(server attempted303 at12223ms); immutable journal640123f1 and exact lease
cleanup remain retained. No Bin retry or full workflow/release claim follows.
Read-only authoritative receipt/native-completion reconstruction must preserve
the unretained HTTP-payload nonce limitation. Further native Rename pre/post
read batching is a concrete source repair, with elapsed success still unproved.
No broad WSTG, release, human or whole-slice completion claim follows.


The subsequent two-path native Rename repair reuses typed facts independently
within each native pre/post phase, reducing measured local command count12→5
for the same successful controlled subtree case. Shared original10s command
deadline,5s helper transport, exact parent/descendant/source-absence validation
and mutation argv/settlement remain unchanged. Source negatives and independent
review pass. This does not prove full HTTP Apply elapsed success; the current
unobserved Bin result cannot be automatically replayed.

The distinct Restore10 also loses its Apply response at10s; server attempts303
after12463ms. Its exact pre-dispatch typed request/nonce has independently
observed native completion and restored placement, but the HTTP failure is not
retrospectively passed. All seven journals and private state remain preserved.
The actual HTTP Runtime wrapper omitted folder_facts forwarding and inherited
serial metadata/status requests; the minimal one-path fix delegates unchanged
Direct/Helper implementations and preserves Unavailable errors. A real-wrapper
signed socket counterfactual fails on old metadata dispatch, then the complete
runtime module passes11 cases with existing peer/caps/refusal checks. No new
protocol, deadline, HMAC authority, completion semantics or live mail permission
is introduced. Fresh native wrapper tests and matching installed response remain
required; unchanged backend native evidence is reused only in its exact component
scope. Original provider/human/release and complete-slice acceptance stay open.

Actual fresh native wrapper buildb4d3fe93 passes61.354s/all481 input parity;
both exact Runtime signed-batch/unavailable controls pass0.037s. Matching
application324b1cb9 builds27.245s with complete current481 parity. No operator
mail/services are touched by these regressions. Unchanged native backend proof
is component evidence, not a repeated whole-workflow run. Normal signed delivery
and installed current response are still required before acceptance.

Actual matching c4e/324b installed fresh public13 now passes13 complete replies
in60.695s, independent auditd64a8890: explicit populated BinApply3937ms and
receipt-bound Restore4007ms return303 within unchanged10s, all3GUIDs/message/
decoded attachment/current selected facts and reloaded labels agree; own label
logical baseline and exact qualification lease are cleaned. Both fresh typed
requests are recorded before dispatch. Earlier failed responses remain failed;
no historical nonce/operation is replayed. Original17 engineering reconciliation
483e664c composes this result with unchanged executed authority/refusal/recovery/
menu evidence. No new blanket WSTG campaign, process-crash proof, provider mail,
human/final-reference acceptance or whole-release/sprint claim follows.

October15 source-only S04-02 startup composition1bb54d49/independent6c09 closes
the missing exact guarded SMTP binding edge. Old-factory RED1 and15 local passes
cover purpose-key separation, real private Linux file/socket custody, replacement
refusals and original-budget recheck. Native gates remain closed: this does not
qualify root/OpenBSD broker/topology/SQL/password workflow or enable a form.
S08-02's later prescribed human usability/attachment PASS and independent closure
review permit functional slice acceptance; S09 visual/accessibility and broader
WSTG/release acceptance remain separate. No unchanged test campaign is repeated.

S04-02 paired account capability99d1a44c/source reviewf2b6e7a8 independently passes
three exact fresh-binary controls23614873: configured-unavailable primary refuses
an accepting legacy executable, legacy stored session refuses without rewriting,
and real admission/TOTP/captured-epoch issuance preserves changed-epoch refusal.
Three-purpose-key pairing and original completion guards have focused source
evidence; this is not native/helper/SQL/installed password or release acceptance.
The initial stale shared artifact selected zero tests and earned no PASS; one
candidate-only rebuild establishes matching test execution without weakened tests.

S04-02 primary producer patch77fc1598/source audit2ba379cf independently passes
18 focused local controls527e184b with exact eight changed-file/all99 Python
input parity. Account-bound original-budget/kernel construction, mandatory graph
and private identity, unknown-peer refusal and local synthetic auth/socket
controls are covered. OpenBSD loader/UID-drop/kernel/selected-listener authority
remain projected, profiles empty and native authentication NOT RUN. This source
evidence is not authoritative password mutation, installed form or release proof.

S04-02 browser source307269ba/successor7e82bffc registers GET/POST
`/settings/password` with authenticated session/account/source, CSRF, strict
five fields and one original deadline. Actual source controls cover pre-dispatch
refusal, Runtime delegation, conservative post-dispatch uncertainty/cookie cleanup,
no credential echo, exact script CSP and Unicode policy boundary. Four original
controls plus one successor control pass; local DOM projection and three changed
script-guard negatives remain source evidence only. Native/installed authoritative
password change and full WSTG/release acceptance remain OPEN. Primary transport
attempt1 FAIL is retained without claiming root dispatch or cleanup.

S04-02 shared control-startup source dba2e057/audit7ea7ad43 preserves existing
private bootstrap/account/purpose-key/replacement/race checks while removing the
loader's prerequisite live endpoint. Five focused local methods PASS5c7cbf95;
the mutation binding separately rechecks its endpoint. Fixed two loader-cache
pin rows match readonly29-leaf observationb5e42793/auditb2a1172a, other28 unchanged.
No custody/permission/graph/promise/deadline waiver or native activation follows.
Actual fresh retained cleanup PASS6ab7 is separate from primary3 authentication
FAILc692 and SQL metadata FAIL696f9bab. Their original failures, uncertainty and
retained root/namespaces remain recorded. No full workflow, installed browser,
credential-backed WSTG or release acceptance is inferred.

S04-02 SQL-only tty compatibility source readiness1454a317/auditd76d2878 has
actual focused RED1/three passes. Fixed command, private material, original
budgets, graph and no native activation are unchanged. tty's broader ioctl/revoke
and hidden libc /dev/tty surface is explicitly acknowledged; ordinary unveil
denial is not universal terminal denial. Native born-session/pipe custody,
original27 controls/mask63 and separate compatibility/session proof remain
required. Primary5 logcf864687 measures first-input EPIPE32/zero bytes after
one confined child, with no pre-kill terminal diagnosis. No installed workflow,
operator password change, credential-backed WSTG or release claim follows.

SMTP peer/per-channel/broker/acceptor source CLEAR3226a617 and mandatory native
gate successor CLEARcdcdd797 retain fixed identity/custody, original per-AUTH
budget, register-before-forward, shared epoch publication and exact stop/EOF
ownership. Their focused synthetic controls do not qualify installed backend
peer/chroot access, native framing/timing/confinement, complete ingress or actual
password containment. All activation flags stay false and dedicated peer None.

Primary fixed-null source42926377/audit257c0c0c has focused RED1/three passes.
Tagged startup requires O_WRONLY and O_CREAT|APPEND opens; only fixed existing
nullrwc and wpath/cpath are added. Leaf mutation risk is bounded by irreversible
private IDs/empty groups and root-directory DAC, not dismissed by the c grant.
Native original7/mask7 and separate nullmask3/device514/strict40 proof remain
required. No actual null mutation, primary5 retrodiagnosis or installed claim.

S04-02 restricted SQL native3 resultdb8238ac passes actual27controls/14strict48
receipts/50reaps/sourceparity and complete root+namespace cleanup on disposable
restricted role. Column and other forbidden operations retain actual1143/1142
negatives; no operator SQL/authentication or full factory qualification follows.
Earlier envelope and output-bound failures remain retained. Lossless wire
metadata factoring preserves the original16KiB cap and original root validator.

Primary8 confirms one private-ID/mask7/null3 proof before first-input EPIPE,
without establishing authentication; original earlier identity cause remains
unknown. Product input-close reconciliation must retain incomplete-credential
success refusal while draining/reaping on the original deadline. Account
admission endpoint/worker changes preserve fixed peer/MAC/replay, shared epoch
lock, original parent deadline and quarantine; native confinement, complete
ingress/session/mail containment and installed workflow remain unqualified.
No credential-backed WSTG, release, sprint or epic acceptance is inferred.

Admission source now selects the existing strict owned-group cleanup branch,
with one actual disposable closed-output/running-child discriminator and exact
fixed interpreter alias/target custody. Primary9 reaches original output drain
and strict parser (55 stderr bytes/library_load, source kill0/terminal-9), but
specific library/termination cause and authentication remain unqualified.
Corrected-version broker startup still refuses; no AUTH counter is fabricated.
All native activation and complete installed workflow obligations remain open.

Primary10 identifies the fixed public libdovecot.so.5.0 loader token. The
reviewed fixed search-directory read repair adds no executable/writable grant
or promise and retains the original private-ID/outside/null controls. Recursive
read and immediate-only custody are explicit; native compatibility and whole
workflow security remain pending, with no earlier termination retrodiagnosis.

Signed source065 normally passes 1741 Rust and 564 account Python tests in both
commit/push gates, with fresh equality and clean standard-mail source parity.
Two refused test-only FFI placement attempts remain retained. Actual metadata
shows exact target custody but only unrelated ancestor size/timestamp changes;
the reviewed five-field ancestor correction preserves fixed identity/permissions,
full target/member metadata and hashes. Primary12 reaches private-child proof
and full input, but not authentication; primary13 receives no daemon greeting.
Neither failure is accepted or used to diagnose older cases.

The admission parent policy uses exact endpoint/interpreter grants, empty
ancestors, checked root cwd and server-owned sealing before credential reads.
Native semantics and the separate exec'd worker confinement remain pending;
the unused finite entry permanently refuses. Broker8 passes its 20 metadata
observations then fails the final original-budget inventory. No ownership check
or deadline is relaxed. No installed workflow, credential-backed WSTG, release,
slice, sprint or epic acceptance follows from these source/component outcomes.
<!-- 2026-10-15 account private-primary qualification addendum -->

Actual private-primary successor16 passes the original seven identity/kernel/
authentication controls and all owned cleanup. Three typed outcomes distinguish
correct password, changed password and foreign canonical identity; source flags
remain false. Evidence is password-change/primary-search-custody-repair-20261015/
receipt-compaction-successor5/execution-custody/native-primary-attempt16;
log SHA256681b079f9580f835137331ec30f302ea72ac48388e079eb108df290532d009d9.
The separate admission-parent native case fails101 with retained scratch, and
broker9 fails AUTH454 after ready topology. These are not full workflow passes.


<!-- 2026-10-15 actual sealed-path and SMTP publication correction -->

Actual same-policy public observer proves empty-permission ancestors deny
pathname metadata with ENOENT, while exact target/retained-FD/hash prerequisites
remain usable. Full protected ancestry checks now precede sealing; the parent
requires a private token minted only after actual locked native policy success.
The worker's typed state reaches sealed only after locked unveil and final
pledge both succeed; partial failure stays terminal before password IO with
owned cleanup. Kernel directory binding is not continuous owner/mode attestation.
No directory-listing grant or metadata-only descriptor claim is introduced.
Parent source reviewf5d84491 and worker reviewdcbb0051 are source scope only;
matching original complete parent and finite composed worker native tests remain
required. Runtime client/form/native activation remain disabled.

Real singular-PID ps queries fix the unsupported comma-selector contract; the
old fake's permissive semantics are retained as a discriminating failed control.
Broker14 then measures Bob publication and Alice backend verification, followed
by original TimeoutError at the final child fstat in the existing0.5s phase.
Original-context scope518fdc1d records complete owned fixture cleanup and zero
mail/provider. Preserve all metadata/TCP/birth/epoch fences and absolute budget;
a changed execution schedule needs matching native proof. No credential-backed
WSTG, release or complete password workflow acceptance is claimed.

Actual matching final sealed-ancestry parent5 now passes the original complete
outer native case on obsd1, with exact binary04b4/source custody, owned group
gone, empty scratch and rootstage removed; no forced stop or stderr. Original
case assertions cover real policy and denial/unlink boundaries. This supersedes
only the parent's pending component status above; worker/factory/installed
password/credential-backed WSTG remain unqualified and activation stays closed.

Broker15 paired scheduling retains all seven current metadata observations and
actually passes two native AUTH publications, exact idle termination and Bob
isolation. Pending signed-control capture/cancel still FAILS Unconfirmed; its
inner cause is unknown. Both daemon groups are gone and standard metadata
preserved, while broker cleanup/private scratch/runtime remain unconfirmed.
Independent scope511fd670 applies; no complete broker/factory acceptance,
service enablement or credential-backed WSTG claim follows.

The fixed managed native broker entry/rc has source audit294bd12b and two
essential source controls. It establishes own PID=PGID=SID before native factory
work, core0 and bounded startup, with restored signal handlers. Source flags
remain closed; no managed service is installed/enabled or natively qualified.

Signed4f20 passes normal commit/push1744Rust/579accountPython and fresh clean
source-only standard-mail parity. Actual worker17 four-role/eight-control actor
and owned-disposition positives remain separate from overall strictstderr FAIL;
lost216-byte content stays UNKNOWN. Its thread-before-fork fixture defect is
being corrected without suppression, widened limits or repeated assurance runs.
Actual control17 fixed-code observation identifies registry quarantine while
client capture times out; initiating writer/order remains UNKNOWN. Keep
retained broker runtime/scratch and all safety latches. No full native factory,
installed password workflow, authenticated WSTG or release acceptance follows.

Actual composed admission worker18 now passes strict8 with zero stderr, both
source-parity checks and complete owned cleanup. Independent006ca0ad retains
material/profile/binder/controlled-epoch/unsigned-envelope projections. Real
worker sealing, private-primary acceptance and fault/no-password-IO boundaries
are proven in that component scope; full native factory/authenticated Rust
ingress/managed broker/installed password workflow remain OPEN and flags closed.
Parent5 and worker18 are reused without unchanged assurance reruns.


Reviewed native peer scheduling repair34da2d3e/4640b22d retains both initial
process rows, all seven metadata observations, master-birth/child-TCP interval
checks and final custody. Child PS-after alone may overlap master FSTAT; the
other cross-process barriers remain. Original0.5s/0.01s reserve/two-child/output/
cleanup-quarantine boundaries remain. Local real-child oldRED/newPASS and owned
spawn-fault/PCB refusals qualify the changed scheduler only. Matching native
compatibility/performance, full factory and installed password remain pending;
no authenticated WSTG/release/activation claim follows.


Matching actual19 source42/result87305853/auditca1b2ec5 passes three native
registrations/verifications, two publications and idle/Bob boundaries; pending
capture remains FAIL. Observed cleanup quarantine follows client timeout;
unique cost/old17 cause unknown. Standard metadata and daemon stops pass, but
broker runtime/scratch cleanup is unconfirmed and retained. Next qualification
uses actual factory executors/current product guards and explicit private paths,
not extra substituted metadata inventories. No full workflow/WSTG/release claim.

### 2026-10-15 — configured account Serve confinement and composed password limits

The S04-02 source increment adds only the configured account admission/mutation
socket rw leaves, three purpose-key r leaves and the existing helper Unix
promise profile. The selected actual configuration-to-plan regression passes;
independent source review7c735118 checks exact added rules and unchanged
ancestry/client/native gates. No installed Serve/password acceptance follows.

Actual composed factory1 e43d02fb fails during SQL bootstrap before any SQL
child or Rust role; source custody and owned driver reap/group absence are
measured, while failed root/worker/SQL stages are retained. The fixture reader
return-contract error is source-reproduced and separately corrected; its
native exception subtype remains unexported. No authentication, credential
write, containment workflow, provider action or broader WSTG PASS is claimed.

Changed native2 result26d8ca5e reaches12 SQL-fixture children, including metadata
observers, all reaped, and
provisioned purpose identity/context, then refuses before Rust role/credential
transaction. The exact remaining preparation guard is unexported. Preserve
failed stages and apply two-failure source reassessment; no required workflow
or additional WSTG case is accepted from these preparation results.

### 2026-10-15 — actual factory admission reached; complete workflow still unqualified

Actual3 cf8093ae reaches18 reaped SQL-fixture children (including observers),
then fails before Rust roles; both exact principals are restored. Correcting
one invalid fixed role label separately admits actual4 dfcc025d. That case
reaches six component controls and24 reaped SQL-fixture children, then refuses
during Rust admission/issuer startup. The second role's discarded output does
not identify its exception. Dovecot and root-driver group absence are measured;
Postfix, capture, public-state preservation, runtime/scratch and two temporary
principal cleanups remain unconfirmed/retained. Audits0966cf93/32e3d3d0 preserve
these limits. No credential change, required containment workflow, installed
password journey or additional WSTG acceptance is established.

### 2026-10-15 — source-level Serve account sealed transport repair

Independent39de8770 admits eight paths with concrete paired full protected
preflight immediately before actual native Serve locking, opaque exact-config
seal and postseal exact key/socket/fresh-peer custody. No retained directory FD,
ancestor grant, purpose/deadline/peer relaxation or native flag changes. Linux
precursor controls and final changed-parent discriminator pass; the final
ignored OpenBSD entry remains uncompiled/NOT RUN. No installed HTTP/password
workflow or additional required WSTG acceptance is claimed.

Retained4 observer3 passes read-only: final source Dovecot bytes match and
original-plan bytes do not; current controlled instance/public identities are
observed without stop/deletion authority. Original cleanup remains unresolved
until separately reviewed fresh current administrative custody succeeds.

### 2026-10-15 — normal gate rejects overstrict client parent metadata

The first source batch fails five reported existing integration cases and stalls
in fixture accepts; its aggregate is interrupted only after current owned-test
identity/parent and zero descendants are confirmed. No complete-suite PASS or
commit follows. Independent2fe00a5b supersedes parent-custody clearance: directory
nlink changes during legitimate sibling creation. Bounded RED and nine focused
GREEN controls support a parent dev/inode/UID/GID/mode comparison, keeping exact
socket/key hardlink guards. Normal signed admission/native/full password WSTG
qualification remain pending; native4 issuer101 is not diagnosed by this finding.

### 2026-10-15 — actual HTTP password qualification entry (source only)

Three existing test-only paths introduce real BrowserApp/Runtime wire handling,
FileTOTP/replay/session issuance, paired account preflight and actual Enforce
Serve. Fixed nonroot1001/GID1003 bootstrap checks all saved/real/effective IDs,
empty groups, root anonymous-stream peer and CLOEXEC; legacy same-UID handling
is unchanged. Reviewc6376276, warning-free Linux compile and two new refusal
controls qualify source only. Exact native producer/custodian/HTTP-SQL-mail
consumer remains required; counts/HTML/build do not qualify password change.

Fresh cleanupfb192a4f/audit2b7e4ce9 removes the separately identified private
Postfix and two controlled principals, preserving unrelated current records and
standard metadata. Old trees/original-restoration UNKNOWN remain explicit.
Factory5 public transport FAIL05fa9a5f has no rootresult; successor7 preserves
original5s while correcting premature empty-select refusal and reporting only
closed phase/code/launch states. No root execution or historical issuer cause
is inferred. No installed password, human UAT or full S04 claim follows.

The admitted changed native6 transport now reaches actual root/driver execution.
The stored issuer reports Configuration at its fixed warm source site and
exits101; overall factory FAIL remains. Eight controls include original-service
preservation and complete owned cleanup, with24 SQL-fixture children reaped,
both purpose identities removed/public rows restored, Dovecot/Postfix/runtime/
scratch gone and cleanup reasons empty. Root/SQL/worker stage trees remain
retained on overall failure; no password transaction or full workflow passed.
The old root producer places its mutation socket under runtime0711, while the
unchanged shared socket-parent guard rejects other-execute. This is a concrete
source contract mismatch, not a uniquely measured historical exception term.
The genuine HTTP producer uses a separate root0750/GID1003 endpoint namespace
and preserves SMTP507 traversal. Its stronger integrated HTTP/SQL/mail consumer
is the next work, avoiding another rebuild solely for the superseded root-only
issuer projection. Original native4 cause remains UNKNOWN.

### 2026-10-15 — complete producer/consumer mapping precedes the password build

Combined reviewffa6db9c closes the new HTTP source contract: existing bounded
OpenBSD ps session observation, exact fixed1001 caller/drop/born custody,
non-daemon bridge quiescence before any dependency cleanup, exact inherited
controls and all17 backend obligations. The one-path epoch addon retains the
same sealed admission Arc and proves Alice stale0 Refused/current1 admitted/
Bob0 preserved within original90 after10 HTTP requests; all consumers require
its six-field report. Review88545660 and warning-free22.41s compile are source
proof only; native/installed password and S04 acceptance remain pending.

The cold root's tuple order is corrected through actual producer projection;
UTF8 transport preserves original1MiB and deadlines. Binary/upload UNSET blocks
host execution pending a matching signed build/final package review. The prior
0b270/2bca compile is honestly prior-report scope. Root had built before complete
consumer comparison; the corrected order freezes and audits the whole source
contract before the next build, reusing passed evidence without unchanged
native retries, framework expansion or operator troubleshooting.


### 2026-10-15 password HTTP qualification scope

Matching signed1893 source/native binaryd205 compiles with full1248 before-after
parity. Actual first dispatched private HTTP composition676ff7f0 fails before
HTTP/guardian/receipt/password mutation; reviewb20a5618 preserves the six component
controls and retained cleanup uncertainty. No installed password or new WSTG
workflow PASS follows. Local0664 custody refusal and exact0600 correction are
retained separately. Directory nlink investigation must preserve exact socket
identity, single-link, owner/mode, pathname and kernel-peer checks.


Maintained two-path broker repair readiness56d0356e/patcha4dbaa3b and independent
review796b1535 pass the directory5/socket6 boundary. Actual RED/GREEN3 (zero skips)
retains the first test precondition/type failures. No Rust/compiler source changes,
operator mutation, native-cause inference or activation accompanies this repair.
Fresh principal-cleanup scope4b2eebb3 confirms the exact retained-resource limits.


### 2026-10-15 — password transport and accountable execution boundaries

The new disabled admission SSH lane is purpose-exclusive and carries opaque
4096-byte authenticated request/reply frames to the authoritative epoch helper.
The original30-second relay bound, distinct key/forced command, kernel peer,
EOF/exit/reap/group absence and no-retry conditions remain mandatory. The
mutation lane retains its original60-second/continuity contract. Local changed
controls discriminate actual EOF-before-delayed-exit behavior; source review
and local transport PASS do not establish native SSH, confinement, provisioning
or installed authentication/password success.

HTTP4 resultf07c0da1 qualifies the real login/session/enabled-form prefix only.
Its expected COMPLETE33/exit0 does not establish successful credential mutation,
forwarded reply or postconditions; actual active-resource cleanup is separate.
HTTP15 source/full-package reviews02cc71c6/99b2efa7 cover original-deadline waits
and successful receipt preservation through cleanup; no historical cause is
retrospectively inferred. Existing strict native consumers stay unchanged.

Existing work-order validation now requires independent successful
producer/cleanup/consumer review and bounded, honest attempt accounting before
expensive/native dispatch. It preserves all403 original controls and110 legacy
cases and does not certify reference truth, runtime state or release acceptance.

HTTP5 resulte76d7f8a/audit6abc3e3f supersedes the zero-byte timeout as current:
five responses complete and first-frame challenge verification fails. No ACK,
accepted signed terminal, credential change, cache flush or final session/mail
postcondition is established. Actors/groups/24 SQL-fixture handles/daemons/broker
are disposed; purpose identities/private runtime/scratch remain retained with
unknown initiating cleanup guard. No native, installed or UAT PASS follows.


### 2026-10-16 — retained outcome, transport refusal and relay shutdown

Current read-only retained HTTP5 observation a0a2923e validates a completed
known_refused journal, active epoch0 and empty cache counts. This does not
authenticate the historical frame or prove a unique cause/atomic no-write. Fresh
principal-only cleanup f930481a and independent scope9139d40c remove only the two
fixture purpose names with four administrative children/four birth queries
reaped and unrelated current public rows preserved. All eight old trees remain.

Changed HTTP17/attempt6 result8612eb23 fails receive_public at the original5s
limit before root spawn or handle. No HTTP/authentication/SQL/coordinator result
is produced. Closed received-byte/EOF/decode subphase was not exported; its
cause stays UNKNOWN. Required combined reassessment28816498 covers HTTP5+6
without resetting history or granting an unchanged retry.

Maintained mutation relay shutdown now distinguishes cancellation from resource
disposition: TERM/INT sets stop, interrupts accept/frame/ACK-EOF/partial forwarding
and prevents future dispatch. Owned SSH cleanup still consumes the original
signed/resource deadline, signals only an unreaped owned leader, and retains
quarantine on uncertainty. Exact owned listener removal and previous signal
handlers are preserved. One discriminating local oldRED/newGREEN validates this
source boundary; native rcctl/paired-SSH qualification remains NOT RUN. Fixed
peer/purpose/key/socket/MAC/epoch rules and default-disabled activation are
unchanged. No release, installed password workflow or human UAT PASS follows.


### 2026-10-16 — private configuration isolation and current refusal scope

Actual obsd1 relay-stop result3f623c50 passes one positive native peer/SIGTERM
case, reaps its owned synthetic SSH child and removes exact listener/stage.
This is component scope only. HTTP7 result707b080c forwards an authenticated
known_refused terminal after actual COMPLETE33/reap/groupabsence; all five HTTP
responses finish but the pre-pending SMTP query refuses. Deep internal cause
remains UNKNOWN. Public purpose records restore and owned runtime daemons go;
root/SQLbackend/client/worker/HTTP trees remain retained. No successful change,
complete postconditions, installed password acceptance or release follows.

The maintained proxy environment binds CONFIG_FILE to its existing validated
namespace config to isolate Dovecot pre-option initialization. Existing -c,
strict stderr, exact command/account/endpoint, freshness, resource bounds and
default-disabled gates remain. The fixture-private IMAP binding and original
result-scalar observation are explicit projections, not installed defaults or
parser success. One actual-composition oldRED/newGREEN control uses bounded
Python executables with no Dovecot/auth/SQL/provider operation. Native full
workflow, source admission and independent review stay separately required.


### 2026-10-16 — per-slice design/test contract, not new execution evidence

Operator requires the entireepic to use per-slice design, planned verification,
expected/preserved outcomes and evidence-based closure before implementation.
Current S04-02 spec/ledger preserve all20mapped obligations. Source/native/
matchinginstalled/human layers stay separate. The existing validator rejects
missing/contradictory design/test/closure declarations; this structural gate
does not prove actual QA/security success. Required tests cover own-account
CSRF/session/TOTP/replay/300s/rate/policy boundaries, authoritative one-write
state, allbrowser+IMAP/SMTP/cache containment, Bobisolation, partialwrite
reconciliation, accurate changed-at and secret exclusion. Age300 expires;
newly confirmed updates require verified authoritative timestamps.

HTTP9signal11 and earlierHTTP10loginfailure remainOPEN with independent
actual9scopef83112a2/combined9+10review3644742f. Source23 fixture freshness
repair is separately reviewed, not a diagnosis or functional PASS. No new
operatorcredentials/providerSend/hostactivation occurs in this SOP admission.
Existing exact source tests are reused; fullnative/installed QA and audit are
not substituted by the contract, normal builds or past component evidence.


## 2026-10-16 — S04-02 source boundaries and actual retained uncertainty

The fixed command-versus-registration endpoint is corrected in maintained source and the private native template. Actual HTTP12 progressed to challenge/ACK and worker completion, then returned503 at cache observation; SQL write remains unproved. A reviewed read-only observation reports a complete/contained journal, epoch0contained and empty flush counts, without SQL read or mutation. Preserve this native FAIL and retained namespaces. The captured-CANCEL reader is separately corrected to use its unchanged original operation deadline, with local oldRED/new3PASS and independent source review; changed native qualification remains unrun. T01 actual owned-browser interaction coverage and T02 typed/route/real-revoked-store source controls pass with exact scopes; no installed T06–T08, recovery, provider delivery, whole-slice or release acceptance follows. V10 uses unchanged generators with12 new test assumptions and existing derived metadata reconciled; V14 adds only the exact test-only CJS classification, preserving production CSP and unknown-script refusal.


## 2026-10-16 — S04-02 password history and actual admission failure

The exact source candidate preserves verified own-UPDATE timing across incomplete containment and authentic terminal-receipt expiry, while pending/contained admission remains refused. Optional history is MAC-bound to account/epoch/request; actual Runtime and both settings views consume it. Newly confirmed success requires equal authoritative persisted readback under the same deadline. Missing, malformed or mismatched readback keeps known timing and Unconfirmed/quarantine; unbound receipts cannot supply timing. Six new source Rust cases and two changed expiry cases passed, with nine exact Python checks reused and independent source review7433bea3. No native or installed T07/release claim follows.

Actual native13 refused in unprivileged receive_public before root spawn because three nested remote source pins were stale. Preserve resultcc8e3024 and the retained carrier, correct the earlier all-pins-match assertion, and execute the real source-admission discriminator before another changed qualification. No root SQL/auth/mail or provider action was dispatched. The original T03 workflow remains open. V10 uses unchanged generators with current derived source counts/hashes; no scanner, CSP, parser, deadline or hook waiver is authorized.


## 2026-10-16 — actual native14 retained failure

The repaired nested carrier admits all current inputs. Native14 still fails the composed password workflow: challenge/ACK/worker completion/reap precede HTTP503 at the positive-cache predicate. Terminal classification, SQL write and initiating cause remain unproved. Actor/driver groups,24 command handles and Dovecot/Postfix are disposed, but broker uncertainty retains private purpose/runtime/scratch/stage state. Keep83f8da25/39dfcb0c FAIL; no old-failure diagnosis, source-T07 promotion, installed readiness or release claim follows.


## 2026-10-16 — source27 response correction and final source scope

Client first-response waiting uses the unchanged original budget; one absolute one-second partial-frame interval prevents fragment renewal. Ordinary server/send/framing/current authority/expiry/uncertainty remain. OldRED/new4PASS/independente8c2 are source evidence only, not a native14 diagnosis or installed/release qualification.

Normal commit attempt1 retained three account-test failures expecting the prior post-write `contained` terminal. Verified own-write time now accompanies explicit `changed_incomplete`; correct exact expectations while keeping account contained, consumed intent, no repeated SQL and original deadlines. Rust1762PASS/48 native ignores does not override the failed account gate. No commit, deployment or security-readiness claim precedes successful superseding normal gates.

Superseding signedf9ab641 source admission passed both normal gates:1762Rust/593account, source34 freeze8093/reviewfc756, signature/freshorigin equality and clean source-only Toronto checkout. Actual one-read retained14 reconciliatione49b/independent37dc localizes this invocation's refusal to pending confirmation before its conditional UPDATE. Underlying callback cause, matching successful full workflow, installed password capability and release readiness remain open; no production mutation or cleanup authority follows.

Actual HTTP15/c7dd4844 with independent5d6f9a29 reaches a verified synthetic write and authenticated incomplete timestamp, truthful503 and cookie clearance. The full positive workflow remains FAIL; reload/new-login/Bob acceptance and installed readiness are unproved. Normal actor/SQL/mail/runtime/purpose disposition passed, source stages retained. Post-ACK closed diagnostic metadata was discarded before cleanup; preserve it through the existing strict projection before any changed diagnostic action. No new operator test, provider send, automatic ambiguous retry or release claim follows.


2026-10-16 S04-02 source follow-up: strict account-scoped authentication/session
rollout, exact source-supported IMAP kick grammar and native broker
producer/profile composition have matching focused source evidence and
independent review. Actual18 authenticates backend Changed(epoch1/verifiedtime)
but browser503/full workflow FAIL; its epoch-only test adapters discard history.
A status-preserving fixture correction and matching native build remain required.
Production SMTP scope/IMAP final-publication/installation and owner testing are
open. No source/test/health result establishes release or parent-slice acceptance.
