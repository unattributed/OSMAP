# Sprint S04 Python review and corrections — 2026-10-23

The operator requested a full review and correction of Python used in Sprint S04
after the authorized Milestone 3 execution stopped in Python before password
submission. This record covers maintained source, its consumers, tests and
delivery integration. It does not qualify the native password journey.

The review started from signed source
`f947c3502c73a043759f46a26b27b804636e42d6`. The previous one-operation authority
was consumed by execution155. This work performed no further native fixture
provisioning, authentication, password submission, deployment, Rust rebuild,
public mail-service change or production qualification change. One bounded,
read-only observation retrieved the installed SQL `user_query` contract without
exporting its connection settings or credentials.

## Findings and corrections

| Finding | Correction and evidence boundary |
| --- | --- |
| The fixture writes a terminal `/` in Bob's `maildir`; the installed SQL projection preserves it, while the witness's `Path` spelling check rejected it. | Trim directory suffix separators only. Keep raw parent-traversal rejection, canonical spelling, nonce ownership, containment, protected ancestry and absence checks. The regression executes the real fixture producer with native effects replaced, then the observed SQL projection and actual witness/consumer. The previous committed witness fails this discriminator with `stock_bob_nonce_home`. |
| Importing guardian helpers started a separate parent-process 120-second clock before frontend setup, which could shorten the later HTTP journey. | Parent helpers use the existing actor deadline. The actual guardian subprocess still owns its 120-second limit; HTTP remains bounded at 90 seconds and the operation at its original deadline. |
| The admission actor's final authority read omitted the cleanup-reserve selector. | Pass `cleanup=True` with the original actor end time, matching the already corrected mutation actor. No deadline is replenished. |
| Cleanup could signal a process group after its direct child had already been reaped. | The build transport, frontend guardian and containment executor now distinguish live owned children from already-reaped children. A reaped identifier permits absence observation only; uncertain surviving groups remain failures. |
| Subprocess and installer wrappers obscured the actual refusal. | Preserve bounded source-owned refusal codes, sanitized unexpected categories, and separate cleanup/rollback uncertainty. No exception payload or credential output is added. |
| `EpochStore` could block opening a FIFO replacement before its regular-file check. | Add `O_NONBLOCK` to the protected open. An isolated real FIFO regression proves prompt refusal while existing regular-file tests remain in force. |
| Containment's phase clock began after process creation. | Start the same phase deadline before `Popen`; process creation consumes the original allocation. |
| The current observer rejected database version strings even though it separately checks the required schema and capabilities. | Preserve the bounded version text as observation. Retain identity, schema, engine, unique-key, trigger and reserved-state checks. |
| The observer's embedded-source capture pins did not match the actual source bytes, so direct dispatch could refuse even while focused parser tests passed. | Refresh the two actual capture pins and add a regression that binds the executable capture arguments to the embedded bytes. Independent review detected this before any host use. |
| The observer compared full directory size/timestamp metadata for public configuration ancestors. | Compare stable directory identity, ownership and permissions; keep full leaf metadata and digest continuity. Unrelated directory activity no longer fabricates a configuration change. |
| Public repository source was treated like a private 0600 packet. | Accept normal owned 0644/0664 checkout sources, reject world-writable or linked inputs, and retain bounded descriptor/read continuity and exact source hashes. Retained private receipts still require 0600. No unrelated checkout permissions were changed. |
| The result consumer treated every nonzero native result as generic transport uncertainty. | Consume a well-bound failed actor as `FAIL`, preserve its reason and observations, and assess disposition separately. Only proven pre-submission no-write plus complete cleanup evidence can be `CONFIRMED`. Submitted/incomplete mutation remains uncertain and cannot become PASS or authorize retry/deletion. |
| The request counter advanced before the durable submission checkpoint completed. | Set the request count after the checkpoint and immediately before submission; retain the earlier irreversible submission fence. |
| The normal delivery gate omitted candidate Python regressions; the old 360-second expectation survived the prior change to 690 seconds. | Add existing portable suites and standalone normal/optimized controllers to the existing gate. Fix the stale expectation. Keep private retained-artifact integration separate and execute it explicitly during this review. |
| The old stage-cleanup entrypoint still selected already-disposed startup145 paths and an obsolete source by default. | Retire direct historical dispatch and require an explicit expected source for the existing receipt-bound callable. Exact leaf/open-reference/identity checks remain unchanged. Historical copies remain immutable. |
| Browser acceptance checks used Python `assert`, including side-effecting POST calls. Optimized Python could skip both the action and its check and reach PASS. | Convert 220 checks across ten Sprint S04 workflow/shared-helper modules to explicit checks, retaining failure-only diagnostic evaluation. Execute the actual extracted POST/check at optimization levels 0 and 2: it must run once and refuse HTTP 500 in both. |
| Shared synthetic-browser startup could orphan its child after malformed or refused readiness; its origin prefix also admitted non-loopback URL spellings. | Use the born private process group, bounded failure cleanup and strict loopback URL/port validation. Exercise real disposable local Python children without Cargo or browser runs. |
| The standalone preview relied on child self-termination and an unbounded final wait; automatic temporary-directory removal could erase state with uncertain process disposition. | Bound the main and cleanup waits, verify group absence, and retain temporary evidence if disposition is uncertain. Keep standalone preview independent of Playwright imports. |
| Worker and SMTP test receive loops could spin forever on EOF; an SMTP accept could strand a non-daemon thread. | Handle partial headers, bound reply/line sizes, fail immediately on EOF and bound the fixture accept. Fix cleanup registration order so stop occurs before join. |
| One test runner called `unittest.main()` before its last class, and another whitelisted interpreter command names. | Move direct-file test discovery to EOF. Verify the already-owned child's PID/PPID/PGID/UID instead of selected Python version names. |

The observed installed query constructs both `home` and `mail` from
`'/var/vmail/' + maildir`, with the mail value prefixed by `maildir:`. The SQL
configuration SHA-256 was
`2482f8710fd8f288e65af1ffc8f7ca840c80a9d3125d3ccd245c606389dd642f`.
This establishes the current producer/consumer incompatibility. Execution155
did not retain its raw projection, so the exact unique historical string is not
claimed observed retrospectively.

## Review scope and method

The source owners reviewed the maintained candidate backend, frontend, stage,
transport, build, binding, observer and result/cleanup code, including embedded
Python. They also reviewed the account-runtime Python tree and the Sprint S04
browser workflows and shared helpers. Review covered producer/consumer contracts,
process ownership, clocks, filesystem custody, mutation fences, error propagation,
cleanup and test-result validity. Separate reviewers examined the corrections.

| Maintained review scope | Python files | Coverage |
| --- | ---: | --- |
| Entire `maint/account-runtime/` tree | 113 | All 58 implementation/support modules, all 54 baseline test modules and the new installer regression module, read in full. |
| Entire `maint/ux/s04_02_startup_candidate/` tree | 27 | All current carrier/build/binding/cleanup sources, backend/frontend sources and existing regression modules. |
| S04 browser workflows and directly used shared helpers | 12 | General preferences, appearance, sessions, general settings, reading, composition, signature, security settings, browser workflows, capture pages, preview and contrast audit. |
| Current observer and test | 2 | Wrapper, both decoded embedded observers and test/controller bodies. |
| Acceptance validator and test | 2 | Full source and test bodies, including actual pre-action routing. |
| **Total maintained Python files** | **156** | File-level line counts and SHA-256 inventory retained as `maintained-source-inventory.json`. |

The backend, journey and runtime reviewers completed the assigned full-source
reads. Independent cross-review additionally checked changed source and failure
paths. It found the stale observer capture pins and process-birth interruption
gap; both were corrected and rechecked before delivery. Root independently
reviewed the final runtime corrections. Existing historical review decisions
were not treated as approval of changed bytes.

The traceability validator and its tests were read in full. Its actual
`--pre-action` route already bypasses historical accounting/role declarations and
checks the narrow planned action. No validator redesign or new authorization
window was introduced. Historical accounting does not expire operator authority.

Retained private sprint evidence was inventoried and hashed: 32,073 Python files,
2,899 distinct hashes, 383,085,147 bytes, predominantly copied source trees and
historical execution packages. That is an automated inventory, not a claim of
32,073 independent manual reviews. Those snapshots are evidence, not the source
for a new dispatch. Their bytes, receipts and prior failed outcomes were preserved.
The maintained corrected sources and explicit current bindings govern any later
authorized use.

The candidate installer still contains dormant historical bootstrap/SSH code.
The current journey reaches only its protected read/publication functions; its
legacy routines have no import-time effects. Account-runtime Python native
mutation entrypoints remain retired. This review does not re-enable them.

Historical `source_review.json` and `s04_02_observer_review.json` records remain
hash-bound accounts of their earlier reviews. They were not relabelled as fresh
clearance for changed code. Current independent review records and the file
inventory are retained with this review's evidence.

## Native boundary and remaining limitation

The retained Rust compiler manifest has 461 entries and no `.py` inputs. Its only
account-runtime inputs are two configuration templates, which were unchanged.
The existing service and caller artifacts remain reusable against their signed
source manifest; no Rust rebuild was justified by these Python corrections.

The reused Rust HTTP entrypoint itself retains a 90-second whole-journey ceiling,
while the password operation has a 60-second bound. A nearly full fresh-TOTP
wait plus a nearly full operation and verification can exceed the outer ceiling.
Removing the unrelated Python import clock does not prove worst-case capacity
of that native deadline. This remains a concrete constraint to reconcile before
claiming native readiness; this source review does not silently extend it or
claim a successful run.

T03 remains **FAIL/open** from execution155. Its independently established
pre-submission no-write and exact-owned cleanup disposition remain historical
facts. Installed qualification, full slice completion and human UAT remain
unqualified. No new password-change attempt is scheduled by this review.

Reconciliation of the retained execution155 native evidence:

| Observation | Actual retained result |
| --- | --- |
| Native functional outcome | FAIL at `stock_bob_nonce_home`, before frontend setup and submission. |
| Password submissions / authoritative changes | 0 / 0. |
| Final authority before exact-owned disposal | Alice and Bob each one row, active, epoch 0, changed-at null; no pending or used mutation intents. |
| Sessions | Alice sessions created: 0; Bob sessions created: 0. HTTP/TOTP authority, revocations, old/new password behaviour and Bob-session preservation were not reached. |
| Cache/public boundary | Cache disabled; public configuration and Dovecot master preserved. Post-change cache witness not reached. |
| Independent disposition | Runtime paths, roles, database principals and controlled rows absent; 21 exact-owned staging files and two staging directories removed, then independently confirmed absent. |
| Timings | Dispatch 5.109 s; actor 3.291 s; service socket startup 0.597657 s; runtime cleanup 1.051379 s; staging cleanup 0.687 s. |
| Historical raw dispatcher fields | UNKNOWN/UNCERTAIN with `transport_or_cleanup`; preserved unchanged. The separate independent outcome review establishes functional FAIL and confirmed pre-submission no-write/cleanup. |

These are retained native observations from the consumed operation, not a new
execution or a fresh host-state assessment. The independent source is
`milestone3-authoritative-change-20261023/execution155/independent-outcome-review.json`
under the private S04 evidence root.

## Validation and preservation

Local doubles exercise actual Python producers and consumers; they are never
substituted for native credential, session or cache evidence.

- Portable carrier/workflow regression suite: **59 tests PASS**.
- Retained-current-source artifact integration suite: **6 tests PASS**, 1.210
  seconds in the final local run. Binary bytes were validated and copied only;
  they were not executed or rebuilt.
- Full acceptance-validator regression suite: **54 tests PASS**, 0.944 seconds.
- Interpreter selection controller: **PASS** in normal and optimized Python,
  including source-owned selection, unsafe alias/refusal and no downstream
  dispatch after refusal.
- Observer controller: **PASS** in normal and optimized Python, each with eight
  capture cases, six embedded schema/ancestor cases and two actual capture-pin
  consistency checks.
- Independent focused workflow/lifecycle review: **5 tests PASS**, 0.693
  seconds; all 220 old assertion expressions compared, with 219 exact semantic
  matches and one intentional stricter loopback-readiness check.
- Account-runtime focused results and short-reply fault injection are retained
  in `runtime-review.md`; overlapping focused counts are not added together.
- Final full `make security-check`: **PASS**, exit 0, **302.922 seconds**.
  This includes **634 account-runtime tests**, **1,880 Rust tests** with zero
  failures and **58 ignored native tests**, plus the ordinary security,
  publication, documentation, static-analysis and release-boundary checks.
  Ignored native tests remain unqualified.

The first full delivery gate passed the carrier suite and 1,880 Rust tests, then
stopped at the existing documentation-index requirement for this new report.
The report was indexed in `docs/README.md`, and the documentation guard passed.
The original failed gate log was preserved. The complete rerun passed. Normal
signed Git preservation is recorded in the execution-ledger closeout and private
delivery logs; the push runs its ordinary security hook again without bypass.

Private review material is retained under
`/home/foo/Downloads/osmap-ux-s04/python-review-20261023/`, including review reports,
the old-source discriminator, test logs, the read-only SQL contract observation
and the immutable historical inventory.
