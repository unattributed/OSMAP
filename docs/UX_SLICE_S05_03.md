# S05-03 — Existing OpenPGP runtime lifecycle and recovery

Started 2026-11-01 (America/Toronto), explicitly approved after the proposed
reuse-first engineering method and T01–T09 tests. Source baseline
`5ebe610204b602a2c715a8854164b42495d92ffc`; Contacts/Compose UAT PASS is preserved.

## Observable outcome

An authorized operation through the existing Rust client/service and GPGME
worker either returns validated correct output or refuses within its bounds
without partial sensitive output or uncontrolled owned work. After confirmed
recoverable failure, a fresh valid request succeeds. Unconfirmed cleanup refuses
further work rather than reporting success. Account isolation, existing grants,
no unattended prompts and separate mailbox/Shopkeeper custody remain intact.

## Smallest route and boundaries

Reuse `openpgp_crypto{,_protocol,_runtime,_process}.rs`, safe native primitives in
`openbsd.rs`, fixed GPGME worker/engine, the existing native runner and disposable
keys. Reconcile current S05-01/02 evidence first. Reproduce one actual uncovered
lifecycle failure, correct that boundary, retest, then qualify natively. No new
service, dependency, general harness, crypto primitive, database or UI is planned.
Preserve the 10-second crypto deadline, one worker/account and two global,
16MiB content/64KiB metadata/50-recipient bounds and all account profiles sharing
the process runner. Cancellation must not be inferred from a timeout result.

Current inspection identifies cancellation/disconnect and descendant cleanup as
questions to prove, not yet confirmed product failures. Stale-agent detection,
bounded repair and actual crypto roundtrips already exist. Use an isolated
service/key home on obsd1 for failure/recovery. Owner keys, credentials, existing
contact/key/policy records and public mail configuration remain unchanged.
No public Dovecot/Postfix/MariaDB stop/start/reload is permitted. Installation,
if code changes require it, is limited to reviewed matching OSMAP artifacts with
hashed backups, protected-state readback and guarded rollback. Never run the
owner-agent unlock launcher just to satisfy a disposable recovery test.

## T01–T09 contract

| Test | Required observation |
| --- | --- |
| T01 reuse inventory | Existing source/native evidence mapped to actual unchanged boundaries; uncovered lifecycle cases named before code. |
| T02 correctness | Real disposable-key sign/verify/encrypt/decrypt with exact bytes and tamper refusal through existing Rust service/client; reuse matching gateway evidence. |
| T03 authority | Account/peer/MAC/fingerprint/expiry/replay refusal before execution; preserve current private grants and imported-recipient opt-in. |
| T04 lifecycle | Blocked input, hang, caller cancellation/disconnect and leader/descendant termination have bounded truthful outcomes and owned cleanup. Shared account profiles retain prior semantics. |
| T05 recovery | Missing/locked/stale agent refuses private operations without prompts/content; public operations retain their capabilities; controlled repair then fresh valid service request succeeds. |
| T06 bounds | Content/output/stderr/concurrency bounds and admission release after errors; native resource controls reused or retested where changed. |
| T07 errors | Spawn failure/crash/malformed output/unknown metadata never become success or partial content; synthetic secret markers absent from public errors/logs; cleanup uncertainty explicit. |
| T08 native/installed | Current OpenBSD fixture runs actual changed production path, checks exact-owned effects/cleanup; matching changed OSMAP artifacts installed only if required, protected state and service readiness preserved. |
| T09 delivery/acceptance | Independent review and normal signed GitHub delivery; owner accepts infrastructure result separately. No invented browser ceremony or whole-epic/production acceptance. |

## Ownership, bounds and evidence

Root owns specification/integration, single compiler/native/host/Git queue and
records. Existing runtime engineer owns process-lifecycle correction; scope QA
owns Runtime/native integration tests; protocol reviewer independently checks
source, recipes and actual outcomes. File assignments precede edits. Tests use
existing libtest/runner mechanisms, not a parallel QA product.

Focused invocations are bounded by the exercised case (usually90seconds);
native compiler600seconds per build with the demonstrated compiler-only4GiB data
soft limit/jobs1/private temp/core0 profile; disposable native action300seconds
plus15seconds termination/reaping; installation360seconds with guarded rollback.
These technical bounds are not authority expiry or exact-version requirements.
Native fixtures/installed actions bind the actual signed source and outputs.
Earliest functional failure, cleanup and state certainty are recorded separately.
Two failures at one boundary require combined independent reassessment before
a changed retry. Whole-objective historic compute cost is UNKNOWN; wall time is
measured for actual invocations. Investigation accounting starts with this work
order; prior S04/S05 history is retained, not reset or repeated gratuitously.

Private evidence root: `/home/foo/Downloads/osmap-ux-s05/s05-03-20261101/`.
All tests are planned until matching execution/reuse evidence is recorded. Normal
full hooks run at delivery; focused progressive tests establish changed bounds.


## Initial causal observations

Readonly preflight confirms obsd1 identity, all eight current service roles and
CA-verified HTTPS login200. Installed Web/helper/worker/engine/environment/config
hashes are retained privately in `preflight.json`. Frozen plan integrity passes.
The current crypto primitive/protocol C/Rust files are byte-identical to the
S05-01 qualified checkpoint8577e12; this is reusable primitive evidence, not a
new lifecycle PASS. Actual S05-01 source/native review and logs remain readable.

The first focused process regression reproduces a concrete ownership failure:
`crypto_signals_only_while_the_direct_child_still_leases_its_group` runs one case,
fails with two attempted post-reap signals, and retains11.091seconds elapsed in
`process-ownership-red.json` and its log. The test callback refuses those signals
when WNOWAIT reports lost direct-child ownership, so the discriminator never
signals a historical group. The candidate correction reuses existing WNOWAIT
observation and owned-group cleanup. It does not blindly switch all profiles.

A safe peer-check extraction reuses the existing nonblocking, nonconsuming
private-control EOF check; its focused unit test passes for open peer, excess
input without consumption, half-close and full close. The crypto single-request
IPC client must retain its write side until the response; EOF after a complete
request means cancellation. This is IPC cancellation, not proof that a browser
abort propagates through the Web request. Existing account-control semantics
remain unchanged. Existing atomic termination handling can be reused for the
crypto-helper process if a disposable shutdown regression proves the need.


## Focused lifecycle corrections

The ownership regression is GREEN after retaining the leader with WNOWAIT,
signalling only while owned, reconciling real exit status and requiring whole
group absence. Shared account/profile tests pass without changing their limits.
The current crypto process group passes9tests with2explicit child fixtures.

Actual authenticated IPC disconnect then reproduced a second lifecycle failure:
the old callback never observed the closed caller and retained its worker until
approximately9.957seconds. The corrected callback uses the completed-request
peer check and the same process cleanup path; the3initial IPC tests pass in0.04s.

A separate isolated helper-termination discriminator reproduced the old helper
exiting while its worker survived. It observed that fact before waiting for the
short worker to exit naturally; actual cleanup was then confirmed, not inferred.
The corrected service stops admission, shares its existing cancellation flag,
joins at most2owned connection threads, and restores signal dispositions only
after they finish. The4-case lifecycle group passed with the worker absent at
helper exit. An additional stop-entry negative and idle20msaccept interval leave
the active2msworker polling and all original deadlines intact. Final lifecycle
source group passes5cases with1native recovery test explicitly ignored locally.

Existing protocol7, runtime authority4 and outcome2 tests pass. The peer primitive
passes1. Native helper/worker execution remains pending at this checkpoint.

The existing recovery utility had31operational Python assertions which vanished
under optimization. A disposable private-home guard regression fails against
that original source under `python -O`. The smallest correction replaces those
same31conditions with explicit checks and a compatible AssertionError subclass;
AST comparison proves every condition is unchanged. Its tests pass9cases with
2native cases explicitly ignored in both ordinary and optimized interpreters.
No owner launcher or agent was used. The native test imports the pinned repair
function only for its validated disposable home.

Strict Clippy initially refused two unbuffered `.bytes()` calls in test-only
bounded diagnostic capture. That finding and the first log are retained;
a small buffered-read correction is pending. No lint exception is introduced.


## Source freeze before native qualification

The final bounded diagnostic uses buffered reads without a lint exception.
Affected helper-stop regression1PASS, strict all-target ClippyPASS and final
format checkPASS are retained. The initial format check refused only wrapping
in the new primitive test; the formatting-only correction is recorded and no
runtime semantics changed. Actual local builds of Web, crypto helper and public
admin helper pass. Actual Cargo JSON for both libtest and the three binaries
passes through the exact native-build selector; empty/duplicate artifact
refusals are exercised before host use. Current V10 register/claims checks pass.

Native plan: extend the existing S05-01 runner conditionally for this slice,
retaining its owned fixture/agent cleanup. The300-second lifecycle mode executes
one current public-admin transaction for the shared runner, the existing actual
Rust crypto and gateway round trips, and the new same-Service agent recovery.
Each exact ignored case must actually execute1test; source/native failures and
cleanup stay separate. Fixed worker C/engine source and public-owner grants do
not change. The current compiler profile is reused with three matching Rust
binaries; no C engine replacement is planned.

The reviewed install recipe will replace only Web, public-admin helper and
crypto helper if native qualification passes. It quiesces Web, allows old bounded
workers to finish, stops only those OSMAP helper roles, atomically publishes the
matching set, then verifies loaded inodes, HTTPS and preserved state. Inventory,
workers, configuration, owner agent and public mail remain unchanged. Root-owned
hashed backups and identity-guarded whole-set rollback remain available. No old
helper worker group is signalled by a historical PID.


Independent source review `96f773c94e5109c17369b87307c8268d61c6cc8b67caa53fcae8cdadacdceee4`
and recipe review `a33e8908bdb34d3447699e0085fdb133cd7f60bbaac03efabcbf87d2c2890baf`
approve the signed checkpoint and native build/fixture. The installer review
caught partial baseline publication; it now captures a pending file and atomically
publishes the baseline only after success, with honest rollback status if absent.
Installation remains conditional on matching native results and artifact scalars.


## First native integration failure and smallest correction

The matching OpenBSD build passes (167.651seconds) and28focused native
checks pass. Public-admin, authenticated Rust crypto and production gateway
roundtrips each pass in the first disposable integration run. The following
same-Service recovery case fails on its initial sign before agent mutation
with an authenticated inner Unavailable result. Cleanup confirms owned agents
stopped; the failed fixture and original diagnostics are retained separately.

Source analysis finds that the preceding gateway test deliberately deletes
Alice's disposable secret keys and never restores them. Filesystem-only native
readback confirms Alice has 0 private-key files while Bob has 2. The smallest
correction moves recovery before the destructive gateway case, keeping gateway
last. Production Rust/C and all compiled artifact bytes remain unchanged.
A fresh disposable integration fixture will distinguish the corrected order;
the28matching focused checks do not need repetition. No installed change yet.


## Engineering and installed result — 2026-11-01

T01–T08 pass against production source69f712b4d50ac00646da4f2f1d459ce401f8e49d.
Runner-only checkpointddb44fb corrects fixture order and successful libtest
marker capture; no production input changed after the native build. Actual
native build 167.651 seconds, corrected integration 6.494 seconds, installation
6.217 seconds and installed probe 0.737 seconds are retained. Earlier compute/model
cost is UNKNOWN; these measured invocations do not imply total effort.

| Test | Result and distinguishing evidence |
| --- | --- |
| T01 reuse | Current contracts/configuration checked; unchanged S05-01 crypto primitive evidence reused. |
| T02 real crypto | Four exact native cases each run 1 test: public-admin transaction, authenticated Rust sign/verify/encrypt/decrypt, same-service recovery and production gateway protected send. |
| T03 authority | Actual native authority 4 / protocol 7 PASS; account/peer/MAC/fingerprint/replay refusals retained. No grants expanded. |
| T04 lifecycle | Actual native process 9 / runtime 5 PASS: ownership-safe group cleanup, caller disconnect, stop-entry/ordered helper shutdown and no late output. Shared account profiles preserved. |
| T05 recovery | Same Service signs, refuses stale-agent private signing as Locked, continues public encryption, then signs/verifies after bounded disposable repair. |
| T06 bounds | Existing protocol/content/output/concurrency limits retained; changed lifecycle checks pass on OpenBSD. Native fixture limits remain bounded; no new resource requirement. |
| T07 errors | Typed/no-content failures and cleanup quarantine tests pass.31 explicit recovery guards preserve their conditions under ordinary and optimized Python 9 PASS each. |
| T08 installed | Three matching Rust binaries loaded, real configured public Verify returns expected Signature refusal, HTTPS200/eight roles, preservation and exact temporary cleanup pass. |
| T09 owner | NOT RUN: infrastructure acceptance remains with the owner after signed normal delivery. No new visual page or browser ceremony. |

Installed hashes: Webe6ecd591c9108451e573d8f096b79cfa687155861fbaab36382396e6f32cce9a,
public-admin54805ad9ed119419b8a6e223afc3449520a0f91f72eea04a4009eca7bec16d31,
cryptof020b4f7d7e16fc387589993f82e7ad0efea404cf705e73e6056fb8046f6b952.
Loaded text proof retains WebPID87085/inode130023, adminPID30401/inode3758804
and cryptoPID9847/inode3758806 at installation. Later PIDs may change normally.

Installation and public-probe protected manifests all hash to
`d124a7b81d25620db522125c1ae86be03a1a52f4ed39ee87545d0c91e89193d0`.
Environment, configuration, C workers/engines and inventory remain unchanged.
No owner credential, session, key, contact or policy mutation was performed;
public mail services were neither restarted nor reconfigured. The installed
probe performs public verification only; private/recovery operations were
proved with disposable keys. Operator recovery launcher changes were source
and disposable-function tested, not installed or executed against the owner.

The failed fixture was removed only after 5 private logs were durably copied and
hash-verified, exact root identity and no socket/process were checked. Both
fixture paths, published probe and exact bootstrap candidate are absent.
Root-owned old-binary backups remain available; rollback was not required.
The initial native failure remains FAIL and is not converted to a PASS by cleanup.

Independent installed/security review
`7c3400163eb1e64a6101a873586fb57738f1043fce618fb3846941b4a61d17de`
is GO for engineering/native/installed QA. Source/recipe/runner reviews remain
separate immutable records in the private evidence root. Normal commit/push
hooks and exact GitHub equality are final delivery conditions, recorded in the
private delivery receipt after execution; no hook bypass or production approval.

This slice proves IPC cancellation, not browser-abort propagation. It does not
qualify a separate-UID crypto topology, invent private-key readiness from public
inventory, complete S05-04, or claim whole-sprint/epic/production acceptance.
The accepted Contacts/Compose experience and all frozen obligations remain intact.


## Normal delivery gate refusal and test-boundary correction

The first ordinary push stops after232.221seconds: main Rust2147PASS/77ignored,
strict Clippy/format and V10/V11/V13 pass, then the CWE guard rejects a direct
current-executable command in the new test-only file. GitHub is not updated by
that failed push. Its complete original log/result remain private and immutable.

The smallest correction reuses the existing reviewed auth crypto fixture command
factory with a fixed descendant-disposition mode. The test-only worker dispatcher
calls the same isolated assertions;3-second outer and500-millisecond inner bounds
remain unchanged. No scanner exception, command boundary or production logic is
added. Focused process9PASS/2fixturesignored, CWE and raw constructor scans pass;
generated maps are refreshed to the actual source. Current native libtest and a
targeted descendant proof will check this test-only composition; the matching
installed three production binaries need no rebuild or reinstallation.


The current signed test-only correction7e51aac builds the native libtest in
118.325seconds (actor117.804seconds). The exact duplex/descendant case actually
runs1test and passes in0.32seconds (outer0.696seconds), reporting
`DESCENDANT_ABSENCE=CONFIRMED`. This qualifies the changed test composition;
matching production69f712 source and installed artifacts are reused. T01–T08
remain PASS and infrastructure T09 remains NOT RUN. The second normal push and
fresh GitHub equality are the final delivery conditions; their actual outcome
is recorded separately after execution, without erasing the first failed gate.
