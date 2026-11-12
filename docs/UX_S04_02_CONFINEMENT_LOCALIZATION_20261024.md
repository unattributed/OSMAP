# S04-02-T03 Serve confinement failure localization — 2026-10-24

Milestone 3 remains NOT QUALIFIED. Execution160 failed before READY with zero
HTTP requests and zero password submissions. Issue 79 remains PASS and CLOSED.
The consumed operation authorization is not renewed. This correction extends
its existing diagnostic capture, recovery and final-consumer pipeline.

## Defect and correction

The HTTP libtest previously called the String-returning account confinement
function with a single fixed `expect` message. Issue 79 deliberately exported
only that safe message's `native_confinement` code; the private panic payload
was excluded. The resulting public diagnostic lost the internal failure boundary.
This is an observability limitation, not evidence identifying a failing syscall.

The actual confinement implementation now returns a typed failure internally,
with the original private error preserved behind the existing String-returning
public wrapper. The HTTP test emits one fixed-schema sanitized record, then
fails with the original fixed refusal marker. Successful confinement, seal
creation, purpose-key separation, peer identity and custody checks are unchanged.
The original dependency/preflight/pledge/unveil sequence stops at its first error;
no irreversible syscall is retried, including EINTR.

The final consumer retains `native_confinement` and adds these detail codes:

| Detail code suffix after `native_confinement_` | Meaning |
|---|---|
| `dependency_plan` | Dependency/confinement planning refused before syscalls |
| `purpose_separation` | Admission and mutation purposes could not be separated |
| `admission_preflight` | Admission client preflight refused |
| `mutation_preflight` | Mutation client preflight refused |
| `initial_pledge` | Initial pledge argument or syscall failed |
| `unveil_rule` | A specific ordered unveil rule argument or syscall failed |
| `unveil_lock` | Unveil lock syscall failed |
| `final_pledge` | Final pledge argument or syscall failed |
| `unsupported_platform` | Enforced confinement unavailable on this platform |

The exact schema is `osmap-serve-confinement-v1`, with `stage`, `reason`,
`syscall`, `errno` and `rule_ordinal`. Reasons are `boundary_refused`,
`invalid_argument` and `syscall_failed`. Actual native syscall failures capture
`last_os_error()` immediately. Only pledge/unveil categories and positive errno
1–4095 are exported. Unveil rules carry a one-based ordinal bound to the source
manifest and binary provenance; paths and raw error strings are excluded.
Invalid CString input is not labelled as a syscall. Missing/out-of-bound errno
remains unknown and cannot become an attributed available consumer detail.

The existing bounded stderr capture accepts one complete, closed-schema record.
Malformed, duplicate, interrupted, overflowing or conflicting records retain
explicit unavailable statuses. A later marker cannot replace an earlier different
failure. Historical records with no detail remain valid and do not invent causes.
Production operation60, HTTP journey300, guardian330, actor600 and cleanup150
limits and all qualification restrictions remain unchanged.

## Local executable evidence and review

Eight focused Rust tests passed; the explicit emitter test remains ignored in
normal suites and is invoked only by the local integration test. Tests cover
successful order, each syscall position and two unveil ordinals, EPERM, ENOENT,
EINVAL, EINTR and errno4095, original-error preservation, NUL arguments, unknown
errno, real paired-client purpose/peer/custody preflights, unsupported platform
and seal refusal. These are injected local errors, not measured OpenBSD failures.

Focused Python diagnostic/recovery tests passed32 with one explicit emitter
integration skip when no binary is supplied. Independent execution of the actual
Rust producer through guardian, frontend, atomic recovery readback and final
consumer passed14 stage/reason/ordinal variants. Positive READY/report controls,
secret-tail overflow, schema tamper, first-failure conflict, interrupted capture,
confirmed no-write and cleanup uncertainty remain executable negative controls.
Six compiler-binding/transport-cleanup tests passed. Independent source review
is CLEAR, including the correction preventing a later marker overriding an
existing different failure. Existing V10 inventories are regenerated for changed
Rust source locations/counts; security claims reference the resulting inventories.
Normal delivery gates and artifact outcome are recorded below when complete.

## Historical evidence and retained resources

Execution160's verified private manifest covers35 readable matching leaves;
manifest SHA256 is
`286d3d0e640ac417b35b141cf5a2a8c6f8f3a6df44894077dbb30197006bbffb`.
No retained evidence establishes the historical internal syscall, errno or rule.
The protected root staging directories remain retained. The private disposition
reconciles22 exact historically observed leaves, ownership/modes, diagnostic and
recovery copies, and original source/binary identities. The retained records lack
an exhaustive backend listing and an exact identity/presence observation for
the source-expected stage-birth.json. They therefore cannot establish a complete
current inventory. No disposal is authorized or performed.
The independent execution160 runtime-cleanup observation is historical evidence,
not a fresh claim that retained stages have no current open references/processes.
A future disposition requires fresh independent ownership/reference/process
observations and separately applicable approval of exact owned leaves.

The original service binary remains SHA256
`8f1ed891c8349863db59a95ba1e3d4908bc62ba7d583ea8634d3259262ab3559`,
from signed source `77f63794d3f60e4003db157eada39f4bd4222b6a`.
The execution160 HTTP libtest remains SHA256
`213f40e73fb6d6a8c9116950892faf711946d7c1b3fc0e27e80d449a0f7ed550`,
from signed source `213b2f3b9ee878fcbaf37e27acb45743a3782434`.

Only the affected libtest compile is permitted under operator item8. The existing
verified compiler freezes a fresh action/recipe identifier; execute cannot
replace it. No service rebuild, test execution, application startup, password
operation, public service operation or retained-stage deletion is part of that
compile. Its provenance is separate from both originals. The existing helper
reuse predicate correctly refuses this changed openbsd.rs/new test-module source
pair; it is not relaxed and the new artifact is not a journey-ready pair.

A separately authorized, narrowly scoped confinement-only native validation is
required to learn the installed failure boundary. It must not submit passwords
or expand into the full Milestone 3 journey. Local tests and compile-only success
cannot establish native confinement or production/UAT qualification.

Protected task evidence is retained under
`/home/foo/Downloads/osmap-ux-s04/serve-confinement-localization-20261024/`.

## Reviewed source checkpoint

Source checkpoint `4668a5122e1bf1f4870be7dde022a15065eb0265` is Shopkeeper signed
and signature-verified. Its normal commit hook passed32 acceptance-validator
tests, library check and staged whitespace checks. Independent final source
review SHA256 is
`6200d6107bffb5cb888c0d70d1e32148a046ed846adebe69d948045c88f0bc42`.
The final actual-Rust14-variant pipeline rerun passed in1.367s, binding current
local libtest SHA256
`7c909c0633429c5b42d3156d4ccc47f01658b2787355c15ad91ff3f8538b9c26`
and all three current Rust sources; binding receipt SHA256 is
`70f7d84667b0da5481ad602ba8ec140381b2e1856ae498f86e1a3f4051c43fc2`.
The retained-evidence disposition SHA256 is
`678e6d61a40949711a41edc8ba55630a1dd419cd741569ed1e361d5812878165`.
Existing V10, V11, V12 and V13 gates passed; the ordinary pre-push security gate
remains required at delivery.

## Actual compile-only artifact161

One native compile completed PASS: compiler144.520s, remote145.495s, full
dispatch146.430s. Receipt SHA256 is
`4e737681410a1e28c10b9dfee910cb48db9d18d85b77ef1572caaa059fe96779`.
The462-input signed-source manifest SHA256 is
`2b6c579e54c53b01e7cc4aaf337e7503889bd1bc581f91342f7066f23537bda0`;
source-before and source-after match. The new native libtest SHA256 is
`90ea5a20f95a7465938511d9b1e02ab8ce8a07c79c144d5a69317f21f604bedf`,
69,495,032bytes, retained privately at
`/home/foo/.osmap-s04-02-artifacts-3qg779l7/osmap-libtest` on obsd1.
The profile is test, opt-level0, debuginfo0, debug assertions and overflow checks
enabled. It was compiled, not executed. The service and plugin were not rebuilt.

The compiler receipt confirms source parity, compiler group absence and scratch
removal; local transport was reaped with its group absent. No native test,
application, confinement probe, account or public-service operation ran. These
observations concern compiler-owned scratch and do not dispose of execution160's
retained protected stages. The new artifact remains separate and unqualified for
the unchanged retained-helper journey admission predicate. No next native action
is scheduled.

Independent actual artifact outcome review is CLEAR/PASS_COMPILE_ONLY, SHA256
`bf9d430102ef0c4f9ec1dc9441c344c0560cb80a6bb7d6cacb56c07256c3e116`.
The first post-result full ledger check refused missing combined-review metadata
for historical failures158/160. Root and the independent controller explicitly
reconciled those unchanged failures and attached the completed review reference;
the refusal log is preserved. This metadata correction neither changes the
already-passed actual dispatch pre-action gate nor supplies native retry authority.

The first ordinary push hook passed the Rust suite (1,888passed, zero failed,
59explicit ignores), Clippy and the preceding checks, then refused documentation
governance because the new report index used a Markdown link without the required
literal filename in backticks. The exact filename entry was corrected; the
failed hook log is retained as normal-push.log. No branch update occurred.
A complete ordinary push-hook rerun remains required, without bypass.

## Later authorized diagnostic163 — earlier boundary failed

2026-10-24 UTC — **Confinement-only probe163 FAIL before Serve; independent no-write confirmed.** The one authorized attempt stopped at `native_admission_client` before detailed confinement, READY or G. Helper/HTTP child/guardian exited1/101/1 and were reaped. The helper trace spans mutation endpoint binding and subsequent StockRuntime construction; the unique cause and confinement syscall/errno remain unobserved. The original carrier retained resources with UNCERTAIN disposition. Subsequent independent read-only evidence confirms Alice/Bob full17 rows unchanged, both epochs0 with no pending/used intents, and public configuration/master/cache preservation. All33 runtime paths, two fixture rows, one SQL principal, two locked OS users/groups and two new protected stages remain retained. Historical execution160 stages are unchanged. No retry, Stage B or Stage C ran. Exact-signed-input artifact pairing now passes the real producer/consumer interfaces, but native runtime pairing and T03 remain NOT QUALIFIED. See [probe163 evidence](../maint/ux/s04_02_startup_candidate/confinement_probe163_evidence.json).

The original execution160 outcome remains unchanged. The current service was compiled separately from the same complete signed source inputs as the retained instrumented libtest; the previous unequal-input reuse predicate was not relaxed. No actual Serve defect was measured by diagnostic163, so no speculative confinement correction was applied. Further native testing requires fresh operator authorization and disposition of the new fixture namespace before reuse.


## Rust-only admission and helper-trace correction

The operator subsequently authorized the two Rust review findings to be fixed.
Admission construction must preserve a bounded operation, rejected invariant
and sanitized filesystem category without exporting paths, key bytes or raw
error strings. Existing shared custody checks are retained, with compatible
legacy error wrappers for existing callers. The helper must distinguish socket
binding from runtime construction and backend revalidation, and carry nested
operation/category observations to its existing startup diagnostic. Historical
trace identities and closed diagnostic vocabularies must remain compatible.

Focused Rust checks will cover successful custody, distinguishing refusals,
secret/path exclusion, legacy-error compatibility and nested failure propagation.
Tests and independent source/security review are pending at this planning entry.
This correction leaves permission/ownership predicates, five-second startup
deadline, confinement behavior and qualification flags unchanged. Python testing
code is outside this implementation scope. No host action or native readiness
claim follows from a local diagnostic test. The actual160/163 causes remain
unobserved until a separately authorized native observation supplies evidence.

Admission failures emit `OSMAP_ACCOUNT_CONSTRUCTION_V1` with schema
`osmap-account-construction-v1` and source-owned `operation`, `check` and
`category` values. The original constructor still refuses with its existing
`Unavailable` result; an output-write failure cannot replace that refusal.
This is a Rust stderr diagnostic. The unchanged Python capture/result consumers
do not promote the new schema into their public structured result, so this
source change does not establish end-to-end diagnostic delivery by those tools.

Independent Rust source/security review is CLEAR for the correction. The shared
custody refactor preserves original check order, open flags, owner/mode/size
requirements and legacy error results. Runtime construction uses the existing
`ServiceStartup` trace operation (ID6); nested revalidation enters
`BeforeRecheck` (ID9), then retains its actual `Stock*` operation. No trace IDs
or tag vocabulary were added. Specific observed categories survive propagation;
ambiguous legacy refusals remain `Unknown` instead of being guessed as invalid.
Focused tests and normal delivery gates remain pending until recorded below.

Local Rust qualification of the changed diagnostic boundary is PASS: admission
runtime33passed/3explicit native ignores, inventory runtime5passed/1explicit
native ignore, password peer13passed, trace compatibility1passed; zero failures.
The peer suite executes actual runtime construction to distinguish static-input
refusal from nested deadline/authority refusal. Existing metadata tests verify
that observed categories survive propagation. Work-order consistency and V10/V11
pass with regenerated source inventories. Two integration-time compiler errors
were corrected before these passes; they were not native failures. Normal signed
commit/push hooks and fresh remote parity remain pending at this source record.
