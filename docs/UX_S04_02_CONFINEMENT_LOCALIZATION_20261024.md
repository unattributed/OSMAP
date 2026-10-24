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
The protected root staging directories remain retained. Their recorded ownership,
diagnostic/recovery leaves and original source/binary identities are reconciled
in the private evidence disposition; no disposal is authorized or performed.
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
