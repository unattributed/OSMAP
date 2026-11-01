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

Record semantic APIs, native libraries and actual versions as evidence, without release-number predicates or free-memory floors. Native compilation uses the proven jobs1/debug0/private-TMP/core0/4GiB data-soft-limit profile, 600 seconds per compiler action; focused native principal actions360 seconds plus15 seconds termination (commands clamp to the240second functional deadline and cleanup ends at the fixed start+330second deadline), installation360 seconds. These bounds do not expire operator authority. Retain earliest failure separately from cleanup and authoritative-state certainty. Two failures at the same functional boundary require combined independent reassessment before a changed retry. Existing historical cost remains UNKNOWN; actual invocations record elapsed wall time. Investigation timebox14400 seconds is accounting, not authority expiry.

Engineering exit requires matching source/native/installed observations, truthful limits, actual isolated restore, independent review and ordinary signed GitHub preservation. Owner T09 accepts only the infrastructure result; no whole-sprint, whole-epic or production-release acceptance is inferred. Private evidence is retained under `/home/foo/Downloads/osmap-ux-s05/s05-04-20261102/`. All cases remain NOT RUN until executed or explicitly reconciled to matching retained proof.

## Source correction evidence

The actual baseline ownership regression fails1case with2 post-reap group-signal attempts (10.322seconds including compilation); its callback refuses those signals. Reusing the established supervisor then passes3 inventory tests/1explicit child fixture (11.840seconds). Shared process tests pass3/1explicit fixture; strict Clippy and fmt pass. Independent source review approves the smallest correction. Inventory keeps10seconds/64KiBstdout/8KiBstderr and Limit/Expired error mapping. Other failures remain Unavailable. Cleanup uncertainty now quarantines all callers sharing this supervisor within that process, not other daemons. Stdin is an immediately closed pipe rather than `/dev/null`; the native inventory worker consumes no input. Native and installed qualification remain pending.

Independent review identifies a second T07 discriminator: inventory service currently detaches connection threads, so active SIGTERM cleanup is not established by the process-runner fix. Reuse the existing actual helper/short-worker fixture to observe this boundary safely. If confirmed, stop admission and join at most2 existing requests within their original10second absolute deadline before helper exit; no new cancellation protocol or relaxed limit. Idle restart must not be represented as active-stop proof.

The active-stop discriminator confirms the second defect: helper exit is observed while the authenticated worker is still alive; its later natural absence is recorded separately. Actual RED1FAIL takes15.218seconds including compilation (3.01second test). Root and independent reviewer jointly reassess both T07 failures before the changed action. The existing termination guard/accept-loop pattern now stops admission and joins at most2 already admitted requests under their original10second budgets. Actual GREEN runtime module8PASS/1nativeignore takes14.238seconds; worker_alive_at_helper_exit=false, confirmed absence,176stdout/0stderr bytes. This drains admitted work; it does not introduce immediate inventory cancellation. The first native d6d11d8 process tests3PASS qualify only the earlier ownership correction; changed service code requires a refreshed native build and consumer proof.

## Native and installed qualification — 2026-11-02

The final runtime source is signed checkpoint `4c041501b76996e6948deeea42a24e4db2d4c231`. Its native build passes in169.444seconds (actor168.888), producing libtest `58ee84bb41c071265ea8f47870c4b33d272684881876d44ebb960dd88a164a61` and inventory helper `6853a1005412f60ae7e7290c9169ad8cd22e60ef247510d4fde74091fc283eb1`. Current native process3PASS/1child-fixture ignore and runtime8PASS/2separately gated native ignores finish in4.067seconds. The active SIGTERM case confirms worker absence before helper exit. These are11 focused Rust tests, not the full delivery suite.

The existing principal fixtures pass with three distinct disposable users each:

- Crypto/inventory:21 recorded Boolean checks,3.720seconds overall (runner3.209), including real authorized crypto/public-inventory clients, reachable unauthorized clients with the same disposable grant, key-home DAC denial, descriptor closure, worker confinement and bounds. Actual previous inventory binary → qualified candidate → previous binary transitions each have a successful authorized client and preserved configuration, grant, public and private fixture files.
- Public administration:9 recorded Boolean checks,2.920seconds overall (runner2.411), including real synthetic import/remove/CAS, secret-certificate/private-primary refusal, account isolation and durable replay refusal after actual service restart. These21/9 checks are not30 separate Rust tests.
- Both runs report service stdout/stderr0 and successful service/agent/principal cleanup. Private scratch is retained0700 until durable log/manifest readback, exact identity and open-descriptor checks, then removed. Log/manifest hashes and exact cleanup are retained privately. The root readback initially added an unnecessary no-stale-socket prerequisite and refused without changing anything. That consumer-only refusal remains recorded; closed socket files were then recorded as metadata, actual matching open descriptors were absent, and exact cleanup passed without replaying the functional workflow.

The maintained runners use explicit checks under ordinary and optimized Python, pinned root-custody inputs, bounded pipes and phase deadlines, precise source-owned failure codes/counts, and private bounded failure streams. Their actual final consumers pass11 local check groups per runner under ordinary Python0.509seconds and optimized Python0.570seconds. Those utility checks do not substitute for native functional proof.

Observed capabilities are OpenBSD, Rust/Cargo1.98.1, clang22.1.6, GPGME2.2.0 and GnuPG2.5.24, with encrypted swap enabled. Loaded worker dependencies include libgpgme25.1, libgpg-error3.32, libassuan3.0, libintl8.2, libiconv7.2 and libc103.0. These versions are observations, not admission predicates. Cargo.lock remains byte-identical, SHA256 `1ed8960aefce1d75126c703bb1d9d7a124302c7c99dedd9cb22bf9bb76bdb44c`; no dependency or capability flag was added.

Only the inventory-helper production binary is replaced on obsd1. Installation passes in4.694seconds, with loaded PID28267/inode3758861 matching the qualified hash. Fresh readback passes in0.637seconds. Existing Web/crypto/admin/worker/engine/environment/configuration artifacts remain unchanged; all eight roles are healthy and CA-verified HTTPS login returns200. Protected cutover manifests match at `3d13995c9f68cc92ee9692364ed17029416b3cf24585543dd05a7002270a4db0`. A pinned, read-only authenticated client confirms Duncan's available public inventory before and after replacement; the existing launcher redirects its two fixed success records into the configured private log, which was read back explicitly. The exact temporary probe and publication names are subsequently confirmed absent; probe cleanup takes0.312seconds. The previous qualified binary and candidate remain in the root-only rollback backup. Live rollback was not needed; actual isolated restore was exercised.

Independent installed review is `896c65f4ee3d7826380ee4981c167e71a064a3e18c4974082f744dc6494209d9`; earlier source/combined and runner reviews remain separately retained. The installed review predates final exact-probe cleanup, whose separate receipt is retained. Normal signed commit/push hooks and fresh remote equality are the final publication gate; owner readiness notification requires their actual completion.

## Qualification limits and T09

Worker pledge/unveil proof does not assert equivalent confinement of the Rust service parent. A shared helper UID is not per-account OS identity isolation. The foreign-agent case establishes endpoint custody refusal, not a fresh agent-peer-credential test. Core tests exercise the configured inherited-zero limit and actual worker entry/abort/no-file behavior; they do not claim an independent positive-to-zero reset test. Inventory shutdown drains existing bounded requests, rather than adding immediate IPC cancellation. Actual worker absence is observed independently; a zero helper exit alone does not prove all possible cleanup outcomes. Unknown cleanup remains fail-closed. No visual page or new user capability is introduced.

T01–T08 engineering/native/installed/recovery observations pass. T09 remains owner acceptance of this infrastructure result after ordinary signed GitHub publication is verified. Accepted S05-03, Contacts/Compose and bounded F3 results remain intact. Whole-epic and production-release acceptance are separate.
