# S05-04: native OpenBSD isolation qualification

Approved 2026-11-02 (Asia/Bangkok). The existing OpenPGP helpers run under verified OpenBSD service boundaries, refuse unauthorized or unsafe work, and recover through a proven isolated restore without changing accepted user behaviour.

The frozen S05-04 scope is native build, confinement, dependency qualification, helper privilege/socket/descriptor isolation, crash/core/log policy, restart and rollback. This infrastructure slice adds no visual page or capability flag merely because compilation succeeds. Reuse matching S05-01/S05-03 crypto and F3 installation evidence; recent single-principal fixtures do not qualify separate service identities.

## T01–T09

| Test | Observation |
| --- | --- |
| T01 Baseline and evidence reuse | Reconcile source, installed identities and retained evidence; name only uncovered boundaries. |
| T02 Native build and dependencies | Record current compiler, GPGME/GnuPG and linked dependencies; build and test matching changed native artifacts. |
| T03 Privilege and socket authority | Use three disposable principals and actual signed clients; prove authorized success and reachable unauthorized peer refusal. |
| T04 OpenBSD confinement | Exercise actual pledge/unveil functions with allowed public access, denied private/foreign access and engine-child restrictions. |
| T05 Descriptor isolation | Establish usable inherited descriptors before closure, then prove unneeded descriptors unavailable and real transport functional. |
| T06 Crash core and log safety | Exercise bounded failures and synthetic marker handling; verify zero core limits and no partial sensitive result or exported native diagnostics. |
| T07 Stop restart and recovery | Correct inventory process cleanup through the proven supervisor and exercise owned descendant absence, disposable stop/restart and fresh request. |
| T08 Install preservation and rollback | Qualify matching installed artifacts and protected state; exercise actual disposable binary restore and install changed OSMAP artifacts only if needed. |
| T09 Independent delivery and owner acceptance | Review source/native/installed evidence and normal signed GitHub delivery; owner accepts this infrastructure result separately. |

## Smallest engineering route

Reuse current Rust service/client protocols, hardened process supervisor, fixed GPGME workers and existing principal qualification runners. Inspection of the baseline inventory supervisor shows leader reaping before group signals and leader-only cleanup; establish the discriminator and route it through the existing proven supervisor. Preserve inventory limits and typed failures. Explicit Python checks, bounded sanitized diagnostics and exact-owned cleanup replace legacy operational assertions; no new QA framework, dependency, service or store. Public inventory/crypto/admin parents retain their actual confinement scope; worker confinement does not imply parent confinement. Shared helper identity does not imply per-account OS identity isolation.

Root owns the single native/compiler/host/Git queue and integration records. Runtime engineer owns inventory supervisor and its focused regression; scope QA owns the two existing principal runners; protocol reviewer independently checks source, dispatch and actual results.

## Boundaries and exit

Use only uniquely owned disposable principals, synthetic keys and private scratch. No owner password/TOTP/private-key operation, key/contact/policy mutation, message send, or public Dovecot/Postfix/MariaDB stop/start/reload/configuration change. OSMAP artifacts may be replaced only after matching native proof and independent review, with protected-state readback and guarded rollback. Actual rollback qualification uses an isolated service.

Record semantic APIs, native libraries and actual versions as evidence, without release-number predicates or free-memory floors. Native compilation uses the proven jobs1/debug0/private-TMP/core0/4GiB data-soft-limit profile, 600 seconds per compiler action; focused native principal actions 300 seconds plus15 seconds cleanup, installation360 seconds. These bounds do not expire operator authority. Retain earliest failure separately from cleanup and authoritative-state certainty. Two failures at the same functional boundary require combined independent reassessment before a changed retry. Existing historical cost remains UNKNOWN; actual invocations record elapsed wall time. Investigation timebox14400 seconds is accounting, not authority expiry.

Engineering exit requires matching source/native/installed observations, truthful limits, actual isolated restore, independent review and ordinary signed GitHub preservation. Owner T09 accepts only the infrastructure result; no whole-sprint, whole-epic or production-release acceptance is inferred. Private evidence is retained under `/home/foo/Downloads/osmap-ux-s05/s05-04-20261102/`. All cases remain NOT RUN until executed or explicitly reconciled to matching retained proof.

## Source correction evidence

The actual baseline ownership regression fails1case with2 post-reap group-signal attempts (10.322seconds including compilation); its callback refuses those signals. Reusing the established supervisor then passes3 inventory tests/1explicit child fixture (11.840seconds). Shared process tests pass9/2fixtures; strict Clippy and fmt pass. Independent source review approves the smallest correction. Inventory keeps10seconds/64KiBstdout/8KiBstderr and Limit/Expired error mapping. Other failures remain Unavailable. Cleanup uncertainty now quarantines all callers sharing this supervisor within that process, not other daemons. Stdin is an immediately closed pipe rather than `/dev/null`; the native inventory worker consumes no input. Native and installed qualification remain pending.
