# S04-02-T03 native journey timing reconciliation — 2026-10-23

This is the narrow timing correction requested after signed source
`2512a243c610e923dc4dae591f975356ca3dd5cc`. The completed Sprint S04 Python
review is not reopened. Milestones 1 and 2 remain PASS; Milestone 3 remains
NOT QUALIFIED. The previous single-operation authorization is consumed.
This work authorizes no new startup or password-change journey.

## Timing derivation

The real counter selector uses 30-second TOTP steps and the existing current+1
acceptance window. Initial Alice authentication selects the current counter;
the second Alice session can use current+1 immediately. The step-up counter may
then require a 30-second wait, and the later unused login counter may require
another 30 seconds. Thus deliberate waiting is bounded by 60 seconds with a
normally advancing wall clock; an exact step boundary attains 60 seconds in the
deterministic regression. Elapsed HTTP work reduces these waits, and a slow
password operation can eliminate the second wait. Clock anomalies still consume
the original monotonic journey deadline; they do not renew it.

The 18 requests are: login page; Bob login; two Alice logins; two Alice history
pages and password form; one password-change POST; two revoked-cookie refusals;
old-password refusal and new-password login using the same unused factor; new
Alice password form and two history pages; Bob password form and two history
pages. The journey also checks four authoritative snapshots, persisted session
revocation, unchanged Bob state, changed-at, mailbox/cache evidence, three final
native epoch probes, the Rust report and confirmed process termination.

The former 90-second ceiling can expire after a valid mutation. At Unix time
300.125, counters 10 and 11 are immediately usable; step-up counter 12 requires
29.875 seconds. A valid 59-second password operation then brings elapsed time
to 88.875 seconds before allowing the other requests and final evidence.

The corrected whole-journey operating budget is **300 seconds**:

| Work | Allowance |
|---|---:|
| Fresh-counter waiting | 60 seconds |
| One product password operation | 60 seconds |
| Other HTTP, native authentication and readback | 120 seconds |
| Authoritative and mail/cache observations | 45 seconds |
| Terminal report and process evidence | 15 seconds |

This is a finite operating allowance, not a guarantee that all component calls
can simultaneously approach their individual timeouts. Nine login-related
native calls, nine protected-GET admission calls, six changed-at reads, the
password route and three final epoch probes already have nominal maxima of
720 seconds. Those simultaneous extremes cannot fit the required 450-second
actor work period. The correction accommodates legitimate TOTP waiting and a
slow valid password operation with responsive surrounding services; expiry
continues to stop the journey and retain any uncertain mutation state.

## Corrected bounds and invariants

| Boundary | Bound and origin |
|---|---|
| Product password operation | **60 seconds, unchanged**, original deadline propagated through preparation, mutation and cleanup |
| Rust HTTP pilot | 300 seconds from the original G start; no per-request renewal |
| Python frontend | 300 seconds from READY, before G; the earlier parent deadline remains authoritative through terminal evidence |
| Guardian | 330 seconds from process import/birth: 20 setup + 300 journey + 10 owned-child cleanup; each phase is capped by that original lifetime |
| Frontend setup | 20 seconds fixed at setup entry; insufficient original WORK for 330 seconds refuses before frontend process birth |
| Enclosing actor | 600 seconds maximum, also capped by the original carrier `not_after_utc` |
| Actor work / protected cleanup | WORK = original END − 150 seconds; 150-second cleanup reserve unchanged |
| Mail witness | Original WORK, maximum 450 seconds; no separate 180-second expiry or renewed finish deadline; late journey results refused |
| HTTP/report elapsed scalars | 300,000 ms, matching the corrected journey ceiling |

The final group observation receives the original journey deadline. HTTP
responses and the final mail witness are checked after return as well as before
work. Interruption and cleanup use the original actor END. Exactly one mutation
submission is allowed; deadline failure never grants a retry or password
rollback. The frontend/password driver and backend copy remain byte-identical.

## Source, artifacts and validation

The signed compiler-source checkpoint is
`213b2f3b9ee878fcbaf37e27acb45743a3782434` (Shopkeeper signature verified).
Its only compiler-input difference is `src/http/password_tests.rs`, included
under `cfg(test)`. The source manifest contains 461 inputs and has SHA-256
`c06f963f924c94f8652834eef58d9a90c4892a870864cba8f61b88b9a5c9c2ef`.

The existing compiler carrier now supports an explicit libtest-only selection.
The one affected native build uses offline, locked `cargo test --lib --no-run`
and does not build a replacement service. Both artifact receipts are checked
separately; helper reuse refuses any differing compiler input other than the
named test file. Its original signed source remains
`77f63794d3f60e4003db157eada39f4bd4222b6a`, and its binary SHA-256 remains
`8f1ed891c8349863db59a95ba1e3d4908bc62ba7d583ea8634d3259262ab3559`.
The dispatcher explicitly accepts both receipt/manifest pairs. Their provenance
is bound into the packet, admission and recovery record; the exact-owned stage
cleanup receipt retains its existing schema and binds the admission hash.

The one native compiler action **PASS** completed with confirmed disposition:
144.479 seconds compiling, 145.429 seconds remotely and 146.407 seconds including
transport. The new artifact is 69,350,984 bytes, SHA-256
`213f40e73fb6d6a8c9116950892faf711946d7c1b3fc0e27e80d449a0f7ed550`.
Its profile is test opt-level 0 / debug-info 0, with test assertions and overflow
checks enabled. The service remains release opt-level 3 / debug-info 0. Compiler
identity and versions are retained in the native receipt. No native tests or
application executed, and `helper_built` is false.

A separate read-only host observation confirmed both artifact hashes and their
recorded ownership/inodes, absent compiler scratch and absent compiler process
group. The new binary was also fetched and independently hashed locally. Both
artifacts remain retained intentionally; no runtime resources were provisioned.
The existing local stage producer, result consumers and exact-owned cleanup ran
against these actual artifact bytes: **10 tests PASS**. This is local carrier
integration, not native password or startup qualification.

Private compiler/review/validation evidence is retained under
`/home/foo/Downloads/osmap-ux-s04/timing-reconciliation-20261023/`.
The final delivery log records normal signed commit/push hooks and remote equality.


Focused validation: **68 portable tests PASS**, **12 existing Rust preparation
original-deadline tests PASS**, and **one composed expired/overlong operation
regression PASS**. The existing interpreter-selection and observer tests pass
in normal and optimized Python modes. Independent timing review ran 37 focused
tests successfully; independent compiler and source integration reviews are CLEAR.

Coverage includes the existing real 18-request producer/consumer with
a deterministic clock, zero and maximum TOTP waits, a 59-second password response
and completion beyond 90 seconds, original journey expiry, refusal of late
terminal evidence, pre-birth budget refusal, interrupted bounded cleanup and
separate artifact provenance. Existing Rust preparation tests verify expired
and overlong operation budgets refuse without effects, and later phases cannot
replace the original operation deadline.

No native application test or host-side password operation is part of this
work. A separately authorized single Milestone 3 execution must establish the
actual native mutation, epoch, sessions, credential behavior and independent
cleanup disposition. Source tests or a compiler receipt cannot qualify T03.

Validation provenance preserves the unsuccessful preparatory checks: a local
Cargo command pointed at the wrong cache and could not resolve dependencies;
a first Rust filter selected zero tests before the exact module filter ran all
12; an intermediate source-map check found the expected stale wrapper hash
before refresh. The earlier old-artifact integration correctly refused changed
Rust inputs. None was a native compiler retry or password-operation attempt.
