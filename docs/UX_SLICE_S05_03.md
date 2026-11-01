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
readback confirms Alice has0private-key files while Bob has2. The smallest
correction moves recovery before the destructive gateway case, keeping gateway
last. Production Rust/C and all compiled artifact bytes remain unchanged.
A fresh disposable integration fixture will distinguish the corrected order;
the28matching focused checks do not need repetition. No installed change yet.
