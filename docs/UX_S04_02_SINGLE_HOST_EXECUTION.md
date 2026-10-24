# S04.02 single-host execution correction

## 2026-10-24 UTC — authorized Milestone 3 execution158

**Actual execution: FAIL before submission. T03: NOT QUALIFIED.** One fresh
operator-authorized execution ran on `obsd1.blackbagsecurity.com`; its authority
is consumed. No second execution, password retry or rollback occurred.

Approved signed delivery was `dc9e791f202a1398af678e83f1cebd93bb18ef67`.
The live-host hash check and the carrier independently verified the reused
service SHA-256 `8f1ed891c8349863db59a95ba1e3d4908bc62ba7d583ea8634d3259262ab3559`
and HTTP artifact SHA-256 `213f40e73fb6d6a8c9116950892faf711946d7c1b3fc0e27e80d449a0f7ed550`.
Service compiler source remains `77f63794d3f60e4003db157eada39f4bd4222b6a`;
HTTP compiler source remains `213b2f3b9ee878fcbaf37e27acb45743a3782434`.
Both original compiler receipts/manifests remain independently bound. No build
was performed, and no executable source was changed for this execution.

The fixed native service published both account sockets in 0.597726 seconds.
The root guardian created the approved native HTTP child under the expected
web identity and returned its custody frame. The subsequent READY exchange
ended with `control_eof`, before `FrontDriver` construction and before the
controller's `G` start message. Consequently the driver sent **0 of 18 HTTP
requests**, created **0 persisted browser sessions**, and issued **0 password
submissions**. There is no successful native HTTP terminal report. The retained
result does not include the guardian/native child's diagnostic, so the unique
startup cause remains **UNKNOWN**. Socket publication and child creation do not
prove trusted peer admission or an authenticated browser journey.

The actor stopped owned producers and independently reread authoritative SQL
and durable epoch state before disposing the unchanged fixtures:

| Observation | Alice | Bob |
|---|---|---|
| Full 17-column row SHA-256, initial and final | `64378ecee67368036e0054d66aea56282eb178178ba3a79958295b22f7b496bb` | `e13badede83e95655901007aef8f8cc12decef4837021b1b25fbbf775f38b71b` |
| Durable state/epoch | active / 0 | active / 0 |
| Durable changed-at | null | null |
| SQL changed-at projection | `20000101000000` | `20000101000000` |
| Pending intent / used intents | false / 0 | false / 0 |

This establishes no authoritative password update. Current-password/fresh-TOTP
authority, old-password refusal, new-password acceptance, Alice epoch0→1,
both Alice session revocations, epoch-one login/session, Bob stored-session
preservation and the completed disposable mail-path/post-change cache witness
are **NOT RUN**. Successful read-only Bob userdb projections before frontend
setup do not substitute for the missing completed witness.

The original bounds were preserved: product password operation **60 seconds**,
HTTP journey **300**, guardian **330**, actor **600** with **150** reserved for
cleanup, SSH transport **650** and enclosing dispatch **690**. The frozen actor
expiry was `2026-10-24T02:58:26Z`; dispatch ended at
`2026-10-24T02:48:30.867327Z`, approximately 595 seconds before expiry. This
execution did not encounter the former timing obstruction or start the product
password-operation clock.

| Native timing | Seconds |
|---|---:|
| Whole dispatch | 6.258 |
| Remote wrapper | 3.831 |
| Native actor | 3.592 |
| Service socket publication | 0.597726 |
| Actor runtime cleanup | 0.871284 |
| Separate independent runtime observation | 0.126817 |
| Exact inert-stage cleanup159 | 0.681 |

Cleanup was admitted only by the independently reconciled pre-submission
no-write branch. The actor removed two fixture rows, one disposable SQL
principal, two locked users, two groups, twelve backend files and five backend
directories; frontend disposal was separately confirmed. A fresh independent
host observer confirmed all **33** recorded backend/frontend paths absent,
fixture rows/principals absent and disposable role processes absent. It also
verified all 23 originally present public configuration files, both explicit
absences, the separate SQL configuration and the unchanged Dovecot master.
The public `auth_cache_size` remains zero; no cache flush was necessary or run.

After that verification, the existing exact-owned cleanup implementation was
reused with only current receipt/path/identity bindings. Cleanup159 removed
exactly **21 inert staging files and two directories**, after checking no open
leaf references. A separate fresh observation confirmed both stage paths
absent. Recovery/source/ownership/result evidence is retained privately under
`/home/foo/Downloads/osmap-ux-s04/milestone3-execution-20261023/execution158`;
the [sanitized evidence record](../maint/ux/s04_02_startup_candidate/milestone3_evidence.json)
binds the result and independent review by SHA-256. Prior execution155 evidence
remains retained in its original private directory and signed Git history.

No operator account, production host, public Dovecot/Postfix/MariaDB
configuration, public-service lifecycle or production qualification flag was
changed. Milestones 1 and 2 were not separately rerun. This failed execution
does not supersede their qualified evidence or establish installed readiness,
slice completion or human acceptance. Further native execution requires new
explicit authorization.

Current2026-10-22 MariaDB dependency correction: journey125 reached ParentPrepare but failed before HTTP. Its owned setup was safely disposed by128 after fresh127a capture. Actual read-only129/130 evidence demonstrates that the current parser rejects MariaDB's required libc++ and libc++abi shared-library names. The source correction permits plus only in library basenames within the existing protected directories; focused131 PASS retains foreign/traversal/punctuation and executable-module refusals. This fixes a demonstrated graph-admission incompatibility;125's unique historical subcause and whole ParentPrepare qualification are not inferred. Corrected signed-source native compilation and actual positive/negative/installed evidence remain required; all qualification flags remain false.

Current2026-10-22 working correction: actual116 reached the production Rust helper but stopped before HTTP. Owned disposition121 PASS restored the temporary namespace without public mail operations. The actual source calls to public doveconf effective configuration and auth_username_format were missing from the fixed metadata guard; only these two literal read-only shapes are now admitted, with a distinguishing local guard regression PASS. This source gap is established independently; its unique contribution to the historical116 failure is not claimed. Native positive/negative and ordinary installed qualification remain required. New native failure/replay/concurrency probes are cfg(test) only and have no ordinary activation flag. Continue small failure-learning loops under existing checks; do not add a parallel framework.


## Operator decision, 2026-10-21

**OSMAP production is single-host only.** Development and functional
qualification use the same local service architecture on `obsd1`.
`mail.blackbagsecurity.com` is a separate production environment and is not
a dependency for S04.02 feature development. The historical two-host SSH
relay fixture is not a required production mode or a S04.02 completion gate.
Preserve its signed evidence and implementation history without promoting it
into a product requirement.

This is an execution-topology correction. The frozen 20 obligations, four
outcomes, D04 policy, T01 through T09 requirements, independently measured
results and prior failures remain unchanged. All production qualification
flags remain CLOSED until their original functional/security evidence exists.

## Operator ruling on build memory, 2026-10-21

The operator abandoned the team-added 6 GiB free-RAM gate and the assumption
that a full optimized library-test build is a blanket completion prerequisite.
Neither is an OSMAP runtime memory requirement. No measured peak-memory study
established that floor, and the113 refusal is not evidence of inadequate host
capacity. Do not replace the withdrawn requirement with another unsupported
fixed memory floor. Scope builds and tests to the actual acceptance outcome;
retain the intended production artifact configuration where that claim depends
on it, required functional/security evidence and normal delivery hooks.

Keep original109/113 failures, source pins and private carriers unchanged as
historical evidence. The113 carrier/recipe is retired and must not be replayed.
Removing the requirement does not manufacture matching native/installed passes
or change qualification flags, execution leases or mail-service boundaries.

## Existing implementation to reuse

OSMAP already has paired Unix-domain socket clients in
`src/account_admission_runtime.rs` and `src/account_mutation_client.rs`,
constructed by `src/http_gateway_account.rs`. The Rust `account-passwd`
server binds exactly these native local sockets:

- `/var/run/osmap-account-admission/admission.sock`
- `/var/run/osmap-account-mutation/mutation.sock`

`src/config.rs` enforces these two endpoints for configured production
account-runtime clients. When account-runtime configuration is absent, it
remains absent. A configured but unqualified or unavailable pair MUST remain
unavailable; the parser does not activate password change or relax either
client's native qualification gate.

The account clients retain distinct purpose keys and a separate session-proof
key, runtime peer UID checks, current epoch, durable rate limits, per-operation
budget and uncertain-write containment. The web process receives no direct
MariaDB credential-mutation grant or arbitrary command capability. A same-host
socket does not justify removing process isolation, filesystem custody or
peer-authentication checks.

## Development and installation boundaries

- `obsd1` is the isolated source/build/test target. Use disposable Alice/Bob
  data and purpose-specific service namespaces. Inspect local Dovecot/MariaDB
  readiness only when necessary for a concrete test failure.
- Never change, stop, reload or restart public Dovecot, Postfix or MariaDB
  services, nor use real operator passwords, to qualify this slice.
- Never require SSH account-admission/mutation relays or remote Toronto
  fixtures for the normal S04.02 functional journey.
- `mail` remains the later single-host installation target after source,
  native and installed qualification and explicit operator authorization.
- The old paired-SSH fixture/results are historical only. Do not delete their
  code, evidence or original failure records as part of this correction.

## Immediate coding sequence

1. Verify the local native account service can start and bind both fixed
   sockets in a disposable development configuration, without public-service
   changes or qualification-bypass flags.
2. Complete the existing `BrowserGateway::change_own_password` path through
   local paired clients and the shared account authority. Address actual
   `primary_backend_unavailable` failures from precise traces, not guesses.
3. Reuse existing T01/T02 source PASS. Validate T03/T04/T05 against disposable
   local service and T06/T07/T08 against the matching installed local pair.
4. Run changed-boundary checks, the normal signed-source gate, independent
   review and finally T09 owner usability. Do not reinterpret a source test
   as an installed scenario PASS.

This change does not provision a database, start a service, activate the
password form, mutate credentials or authorize production deployment.
