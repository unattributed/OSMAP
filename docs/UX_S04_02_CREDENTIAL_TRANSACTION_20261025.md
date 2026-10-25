# S04-02 credential transaction and epoch/session consistency — 2026-10-25

## Outcome

**Superseding incident:** the operator's real-account public journey failed and
public readiness is withdrawn. Global native configuration had selected stale
local credentials while the normal mail authority remained Toronto. The operator
subsequently selected fully local obsd1 UX development, a separate read-only
database reference replica and isolated writable test data. See the
[current migration report](UX_S04_02_LOCAL_DEVELOPMENT_20261025.md). The controlled
transaction evidence below remains valid for its stated local scope; no real-user
or new-development-profile acceptance follows from it.

**Historical controlled-local closeout: all four outcomes, all 20 retained
obligations and T01–T08 PASS; independent audit CLEAR at that checkpoint.**
The ordinary persistent validation instance and a genuine UAT session were
available for that separate human T09 review. Human acceptance was not recorded. The following native04 result is the first
transaction checkpoint; subsequent sections retain the integration, failure and
installation evidence that completed engineering qualification.

**PASS: one complete native OSMAP credential transaction and epoch/session transition.** Native04 ran the ordinary production account-passwd service on obsd1 with a genuine guarded nonroot client. The complete client passed in 26.67 seconds. The native SQL-policy negative test passed in 0.04 seconds: Internet socket creation and file creation both remained denied with ENOSYS, both children were reaped and no forbidden file was created.

| Required observation | Actual result |
| --- | --- |
| Authorize the current credential | Real authoritative authentication and fresh TOTP algorithm verification passed |
| Generate the replacement hash and update through OSMAP | The real Rust Service/Backend performed one guarded conditional SQL transaction with verified readback |
| Prove the credential transition | The obsolete password was refused first, then the replacement password was accepted |
| Advance account authority | Durable state was active at epoch 1 with verified write time, no pending intent and no uncertainty marker |
| Revoke existing session authority | Both old stored tokens failed authority validation before record revocation; cleanup then revoked exactly two |
| Establish current authority | A new epoch-1 stored session was issued and validated |
| Preserve another account | Bob's stored bytes and authority, five prior full mailbox rows and protected state were preserved |
| Restore the fixture environment | Original OSMAP configuration/helper restored, helper exited 0, current three copied keys removed after ownership/readback checks |

The requested credential/epoch/session boundary is complete. Prior successful credential-freshness evidence was reused. This ordinary helper and real session-API proof uses test-only client constructors that bypass only the qualification flag; actual transport, keys, kernel peers, guarded lease, pending ACK, SQL, epoch and session machinery execute. TOTP uses the actual verifier with a RAM-only fixture seed. At the native04 checkpoint, installed TOTP-file custody and the HTTP/browser journey remained separate acceptance work. Subsequent sections record that qualification. Human T09 acceptance remains open.

## Failure → analysis → correction → retest

1. Native01's sole ordinary guarded operation returned authenticated KnownRefused after 9.64 seconds. Its full credential row remained unchanged. The exact initial refusal branch was unobserved. Helper exit, original OSMAP restoration and preservation passed.
2. Read-only reconciliation found epoch 0/active, null change time/intent, one consumed intent and no uncertainty marker. The hash shape, timestamp and flags were valid. The configured SQL user read the required columns under the root OS principal; that did not qualify the confined child. No credential reset or resubmission occurred.
3. Fixed transaction-phase and existing scalar process/parser diagnostics were added through the existing helper machinery. Observations reset per request, remain bounded and payload-free, and preserve unknown causes. The real helper parser and final consumer now validate them, including actual child PID and terminal signal.
4. Native02 localized refusal to abnormal SQL-child termination during snapshot reading. A read-only reproduction correlated its recorded child PID to a setsockopt pledge violation. An inet-capability candidate was tested in native03 and proved insufficient. That failed candidate and unchanged-row/epoch results remain retained.
5. The next same-artifact read-only trace established the exact operation: an AF_UNIX socket connected successfully to the fixed MariaDB Unix socket, then the client attempted an optional IP socket option. Connector/C applies this optimization without a Unix-family guard and ignores failure. The superseding correction removes the ineffective extra network capability.
6. Current and future-exec promises are now separate. Current parent and SQL pre-exec policies retain their original strict rights. The executed SQL utility receives ENOSYS for denied optional operations; it gains no denied capability. Parent future-exec ceilings support that SQL policy, while explicitly prepared non-SQL role policies remain unchanged. The native denial checks and complete ordinary transaction both passed.
7. A warm Cargo receipt was rejected before credential dispatch because its copied binaries still matched older artifacts. Scoped cleaning of only OSMAP's package, retaining dependency caches, produced fresh source-bound images and passing emitted role/config tests. Stale copies and their receipt remain preserved as an artifact-binding failure.

These observations establish the actual corrected boundary. Missing historical observations are not retrospectively assigned a unique cause, and no failed run is rewritten as PASS.

## Epoch persistence and lost terminal reply

A focused composition uses the real durable Store, FileSessionStore and SessionService. After a scripted SQL write succeeds, replacement of the pending record inode forces final epoch-publication custody to refuse. The result is ChangedIncomplete, one committed write, retained pending/uncertainty protection, old-session denial after reopening the Store, refusal of new session issuance while pending, and Bob preservation. Replay performs no second write. Its paired success control advances the epoch and admits a new session while refusing old authority.

The real guarded Unix-socket composition also loses the terminal reply deliberately. A bounded synchronization closes the client's read half after its pending ACK but before completion. The server reports Transport while one SQL effect and the active new epoch remain committed. Old stored tokens fail against actual Store authority and new-epoch issuance succeeds. Missing-ACK and trailing-byte controls remain in the existing test.

These local failure checks use scripted SQL/authentication/mail effects. The persistence failure is an actual inode-custody refusal, not native disk/fsync fault injection. They remain distinct from the native positive and installed HTTP/browser acceptance.

## Validation and provenance

- Service consistency/diagnostics: 9 PASS; process diagnostics: 9 PASS; guarded connection tests: 2 PASS.
- Final native-profile source suite: 16 PASS, including exact role/current/exec ceilings and strict SQL-config refusals.
- Native client bootstrap/RFC6238: 1 PASS; ordinary source compilation PASS.
- Existing diagnostic consumer suite: 21 PASS, including actual Rust emission through helper parsing and final consumption. Evidence suite: 10 PASS and 2 explicit emitter-dependent skips. Final child-signal compatibility controls: 3 PASS and matching independent rerun.
- Emitted OpenBSD artifact role/configuration checks: 1 PASS each. Actual native policy denial: 1 PASS containing two denied operations. Actual ordinary transaction: 1 PASS.
- Native functional artifacts use the unoptimized development profile; production performance is not qualified.
- Normal mandatory commit/push hooks, signature and fresh origin parity are recorded in the private final delivery receipt.

Source input manifest SHA256: c0b1f5a4531f8a06df9226f544e649a9a6078dd1c2bc29e9e0ef3acf15e05d91.
Ordinary helper SHA256: 0f95a68b624b4ffddb98ce4be3d82be980f394396a03e5248bfbc8ffd10438cd.
Native libtest SHA256: 7afab4f0fe1e17ddc699910c9cb8951afc0a09fcaddd24c4234d96523484f947.
Actual archive SHA256: 6079539bfd551455d2e121f50bb23277d9a3313602e35971502eea3f2f214bca.
Independent result review SHA256: a2ca67dd26ccb81a1d07a2c3e7862b5c86779f6fda72832bcdab7b516973e04a.

Independent archive validation checked 42 flat regular unique members, 41 capture hashes and 39 root-stream hashes. Private evidence/reviews are under /home/foo/Downloads/osmap-ux-s04/credential-transaction-20261025/. Raw credentials, keys and private archives are excluded from Git.

The fixture changes only controlled account state and temporary protected OSMAP account lists/helper, followed by exact restoration. Public Dovecot, Postfix and MariaDB service lifecycle/configuration remain unchanged. Resource disposition is recorded separately; retained evidence or cleanup never substitutes for functional acceptance.

## Exact fixture retirement

After native acceptance and durable archive review, the four new transaction
mailbox rows were retired in one conditional InnoDB transaction. Exact full-row
digests, row locks, zero triggers and zero foreign keys constrained the deletion;
four affected rows and zero remaining targets were acknowledged. Fresh inode,
hash and open-reference checks admitted nine remaining copied client keys and
eight fixture epoch/lock leaves. Each unlink had durable pre-action/readback
evidence and parent-directory fsync. The current native04 three key copies had
already been removed, so all twelve fixture key copies are retired.

The actual cleanup passed with seventeen confirmed leaf removals and twelve
protected files unchanged. Session/build/private diagnostic directories and all
historical resources outside the exact footprint remain retained; no recursive
removal, historical PID action or public-service operation occurred. Cleanup
archive SHA256: 98c52111d8886d90ac3c001ad215e69efb40ddebebc4654f815b4645f47e166a.
The native credential and epoch evidence describes the verified state before
this explicit retirement.

## Delivery source closure

The first signed functional checkpoint passed its normal commit hook. Its normal
push hook then refused two existing carrier-closure assertions because the source
map still contained the previous custody/parser hashes. The actual current
custody and qualification hashes and the coupled root-stage hash were refreshed,
without changing the native product or weakening source admission. The two
matching closure tests pass. The failed gate is retained; a normal signed
follow-up and ordinary push preserve both checkpoints.

The next ordinary push passed the carrier, Rust and security regressions, then
refused the documentation index because its existing inventory guard requires
the report filename in code ticks as well as its link. The index now includes
that exact filename; the guard passes. This documentation-only correction
changes no compiled input and requires no repeat credential operation.

## Ordinary installed Runtime and file-TOTP journey

The subsequent positive05 run used the normal Web Runtime, protected file-backed
TOTP, actual FileSessionStore and ordinary production helper on obsd1. Exactly one
password POST completed. All twenty HTTP observations passed, including initial
unknown history, result page and reload, result-capability isolation, refusal of
both old cookies, obsolete-password-first refusal, replacement-password login,
four Settings history views/reloads and the preserved control session.

Independent root SQL and Store witnesses established one credential transition,
active epoch 1 and authoritative write time `20261025114039` (2026-10-25 11:40:39
UTC), exactly two revoked old session records, one new epoch-1 session, unchanged
other account fields and preservation of all prior rows. The control account's
full row, epoch and session remained unchanged. Its existing TLS-verified IMAP
connection remained authenticated across the transaction and completed NOOP and
LOGOUT without message selection or delivery operations.

The normal Web artifact is
`f48d04463a868180cd49d1a3d6a085e023280343db9da6fccda773ce36a1353f`,
compiled from signed source `16d7bf4d0126e2f3186390234ffcf26ab14ad3a4`,
source manifest
`d3090ca59da501214d3c89b7de3ce0ca5bdb2b982d19217f8cfcbcef81ac20c6`.
The unchanged ordinary helper remains the native04 artifact identified above.
Both use the functional development profile; production performance remains
unqualified. Actual archive SHA256:
`9fa7fc9a0cfe95ef83efd683950f9d339ff5267cad899b83db1e85aa9e368804`.
Independent review verified 58 unique flat regular members and all 57 member
hashes; review receipt SHA256:
`663664cc23632534d0a8ea3c72d9ce3200366395d35f663f1861538ae3d3aeec`.

The browser controller did not request the post-transaction broker within its
window. Credential completion was already durable before that separate UI phase;
no repeat mutation is needed. The initial cleanup receipt remains uncertain.
Subsequent exact-identity reconciliation confirmed the five owned process IDs
absent, both fixed sockets absent, no helper references, the captured published
helper inode/digest and successful restoration of the original helper. This is
current recovery evidence and does not rewrite the initial uncertainty.

Two later read-only UI attempts used a persisted session identifier as a cookie.
This was an engineering error in the controller: SessionService stores
`SHA256("session-id:" + raw_token)`, and the raw login token is not persisted.
Actual issued-token/Store/validation composition proved the real cookie valid,
the persisted identifier equal to that domain-separated hash, no raw token in the
Store and the identifier-as-cookie refused. Correction receipt SHA256:
`f4130974e21352655d12c393674737346ff2ea3908ca6b493099f22c93225174`.
Earlier legitimate-cookie claims for those read-only attempts are withdrawn.
Their zero-POST and exact cleanup results remain valid. No session forging,
renewal, password reset or replay followed.

T04 native concurrency/replay, T05 native post-write containment and remaining
browser controls remain open. The passed installed transaction is reused; neither
its success nor the local fault tests imply complete S04-02 or human T09 acceptance.

## Native concurrency and replay

T04 completed on the fresh concurrent/control pair with the actual native service,
ordinary native clients and real stored-session machinery. The controller warmed
the genuine primary-authentication/epoch issuer before holding the existing
five-second mutation gate. During that hold, its bounded two-second admission
attempt refused session issuance and created zero issuer records. The guarded
transaction then completed, and the exact consumed signed frame received
`SIGNED_KNOWN_REFUSED` on replay.

Independent readback found active epoch 1, one used intent, no uncertainty marker,
verified time 2026-10-25 14:18:43 UTC, two revoked old session records, one live new
epoch-1 record and an unchanged control record. The other target columns and all
prior rows were preserved. This does not independently count SQL child invocations
or isolate consumed-intent refusal from stale-epoch refusal. The signed refusal
and final SQL/epoch/intent witnesses establish the bounded no-second-write claim.

Archive SHA256:
`d3ed619b60e2451ee1a4fbf596c8c898ad829d25e94f56502fe25da45de60dc3`.
Independent audit checked 46 unique regular members, all 45 member hashes and 23
additional bindings/readbacks. Review SHA256:
`c22f3e4993d858f77a74255ae095208acc1b82d0129642893d17bdc7cca36970`.
Owned cleanup, helper/configuration restoration and copied-key custody passed;
six copied keys and controlled fixture state remain deliberately retained.

## Native post-write containment and actual browser controls

T05 used the ordinary Web Runtime/file-TOTP path and a fixed test-only service
effect refusal after the real conditional SQL write and verified timestamp had
been persisted. It did not inject disk failure or execute a second target
authentication. The outcome was explicitly incomplete: epoch 0 remained
contained with one consumed intent and its bound uncertainty marker. The ordinary
native admission client refused both epoch 0 and epoch 1 for that target while
admitting the control account. Both old target records were revoked and their
HTTP cookies denied. The fourteen-request HTTP case, authoritative before/after/
final witnesses and existing TLS-authenticated IMAP control all passed. No target
password retry, rollback or post-fault primary authentication occurred.

The result page and reload retained the verified write time, 2026-10-25 14:25:10
UTC, with explicit incomplete wording and no completed-change claim. The separate
result capability did not grant account Settings authority. The control account's
row, epoch and existing session remained unchanged, as did the T04 pair's captured
epoch/lock objects and all prior rows. IMAP completed 19 NOOPs, final LOGOUT and
TLS process exit 0 without message selection or delivery.

Archive SHA256:
`c2728549f4c345b2719b1a3360854669df5b0cf497cb10cd28531029a301f07e`.
Independent audit verified 59 unique flat regular members and all 58 member
hashes; review SHA256:
`6c936f06b882307e81d1424962f8ed95444f08ad7b829d460ecd05fa24c752e8`.
Owned process cleanup, helper/configuration restoration, protected readback and
the three retained copied keys' custody passed.

Actual browser inspection used the genuine control cookie returned by normal
login and the actual target result capability. Incomplete wording, matching time
and reload passed before opening the control account's form. All three independent
visibility controls, public-dummy current-field paste, keyboard focus/activation,
Cancel, both Settings entry points, breadcrumb, Unknown history and empty final
fields passed. The first complete-network predicate was false; its cause was not
retained and remains unknown. A fresh repeated controls window observed exactly
five GETs, zero POSTs and no truncated or remaining events. The public controller
ACK arrived after its 120-second deadline: protocol failure remains recorded
separately from the observed product results and core containment PASS. It does
not justify another credential transaction.

The native test artifact is
`fab3bc8025adce166a2aa68b4ce77d2887a34f7ccfc579d25c483d3a6c387229`,
compiled from signed `0c9f699793d3911aa8472694462b14ade992cda9`, source manifest
`a4527ed43b5eb8c84f040d5127517b7fef7ab50e499f99abc60de8d1c510f1c6`.
The subsequent signed lint-only helper relocation/Boolean simplification is
independently equivalent; the artifact is not relabelled as rebuilt from that
follow-up. Normal push checks passed 1,932 Rust tests with 72 explicit native
ignores and 634 account Python tests. Existing matching deterministic freshness,
binding and durable rate controls are reused alongside the new native cases.

Persistent ordinary application access is the remaining installation step before
the [minimal owner T09 review](UX_S04_02_T09_ACCEPTANCE_20261025.md). Temporary
actor cleanup alone does not establish that access or human acceptance.

The first persistent activation stopped at the post-start helper check. It
preserved the original frontend and protected state, stopped its new services
and restored the previous helper and account configuration. Its copied private
state remains retained. Inspection of the host's actual `rc.subr` found that the
startup waiter signals direct children with ALRM; the custom helper `rc_start`
used `exec`, replacing the monitor shell with the Rust process. The correction
removes only that `exec` and retains exact root/main-process matching. The initial
helper's terminal signal was not captured and is not retrospectively asserted.
Six existing installer tests and shell syntax pass; matching changed native
activation is the next proof. Session expiry remains enforced normally; no stored
identifier is adopted as a cookie and no session timestamp is reset.

## Persistent ordinary availability and final engineering closeout

The changed activation established ordinary helper liveness. Reconciliation then
found two inactive root-owned socket leaves with no matching helper, kernel
listener or file reference. Recovery02 also exposed a native two-iteration AND/OR
loop guard that could return failure without stopping the script. A paired native
control reproduced continuation with `return 1` and immediate refusal with
`exit 1`. The changed actor uses explicit exit, current physical identity and
fresh kernel/file-reference checks before each exact unlink. No historical PID
was signalled. Both socket leaves were retired; their historical origin and the
initial helper's terminal signal remain unknown.

Recovery03 proved helper/Web process liveness but sampled the Web before a TCP
listener existed. Recovery04 added a bounded anonymous HTTP-readiness wait, with
the same unique process checked throughout. The same PID progressed from status
000 to 200, then passed loaded-executable and owned-listener checks. This changed
observation qualified the ordinary service; it did not change application
deadlines, flags or binaries. Independent actual activation receipt SHA256:
`01b7f39d9e583986a11dffd8f547a57ff00df79d4cf77edebc5c0b5d6640124f`.

The final installation uses ordinary Web `f48d0446…` at
`/usr/local/libexec/osmap/s04-02/osmap`, ordinary root helper `0f95a68b…` at
`/usr/local/libexec/osmap/account-passwd`, the corrected normal helper rc script
`097825fd…`, and separate persistent state at `/var/lib/osmap-s04-02`. The Web
listens only on 127.0.0.1:18127. The original PID 63306/port 8080, original binary
and environment, protected keys, mail configuration and T05 containment state
passed their readbacks. Normal services are intentionally running, without a
fixture/libtest service or timeout actor. They have not been enabled at boot.

The earlier control session expired normally during installation work. One fresh
disposable UAT account was created with an initial credential, followed by one
genuine normal file-TOTP login. The three-request sequence returned 200/303/200
and an enabled authenticated form. It made no password-change POST and changed
no existing credential. Root confirmed the initial row, epoch 0 and factor were
unchanged by login, with all prior rows and protected state preserved. Only the
actual returned raw cookie crossed the private RAM/FIFO broker into the browser.
Independent actual UAT receipt SHA256:
`d0bec18ef0baa171786e16112b72d820678f929adf920d353921ad2424808f03`.

The browser then passed all three independent visibility controls, public-dummy
current-field paste, keyboard focus/activation, Cancel, breadcrumb, both Settings
entry points, truthful Unknown history and empty final fields. Its fresh network
window contained five GETs, zero POSTs and no truncated/remaining events. Actual
browser record SHA256:
`0e1dfa3bb3db2beebcdfa2387e0d2f8f192d59e825e99d50c4a10776c8f4e283`.
An actual screenshot is retained privately. Service/access disposition review
SHA256:
`21437ea856d1a6ef3ab56d2718b3c5b05bd91bf9d8d04dc61505b10390d80a76`.

The final independent audit maps the exact 20 obligations, four outcomes and
T01–T08 to applicable passing source/native/installed/browser evidence. No required
engineering finding remains unresolved. Readiness receipt SHA256:
`48ccdf858073b1d3205214d9a419f49f5315d2b62870fba5d3728aea79292154`.
Failed controller attempts, their elapsed history and unknown historical causes
remain preserved. Controlled fixtures, copied purpose keys, backups and evidence
are deliberately retained for acceptance; current availability does not assert
boot persistence, production performance, public rollout or human acceptance.
The [owner T09 script](UX_S04_02_T09_ACCEPTANCE_20261025.md) requires no debugging
or additional password change. S04-02 remains unaccepted until the owner records
that usability result.

## Ordinary public frontend deployment

The operator subsequently requested the completed code at the normal
<https://obsd1.blackbagsecurity.com/login>. The already qualified Web f48 artifact
was installed at `/usr/local/bin/osmap`, preserving the original production
environment and all existing state, TOTP, mailbox and OpenPGP paths. Seven
native-local account variables were appended, with protected purpose-key copies
owned by the actual Web UID. The HTTPS proxy remains on the existing 8080 backend.

Independent preflight identified that the old helper scope contained only the
five controlled accounts. Four existing TOTP-enrolled identities matched active
mailbox rows. Both protected scopes were extended by exactly those four; their
previously absent epoch/lock records were created as active epoch zero, with
unknown changed-at. No password, SQL row or factor secret was changed. All
pre-existing epoch files and factor/configuration readbacks passed after cutover.
Existing unbound browser sessions may require a fresh normal login.

The ordinary frontend PID 91121 remained the same across HTTP 000 to 200 readiness,
then passed loaded executable inode and actual 127.0.0.1:8080 ownership checks.
The public HTTPS login returned 200 with certificate verification result zero;
the actual browser displayed the username/password/TOTP form. The ordinary
helper, QA frontend, Dovecot, Postfix and MariaDB checks passed. Only OSMAP services
were restarted. The native backup preserves the previous frontend and configuration.

The account helper was enabled at boot; startup order now places the frontend
after mail, account and OpenPGP dependencies while preserving all other relative
ordering. The first boot-order command stopped before configuration changes
because `/bin/print` does not exist; the native ksh builtin `print` corrected that
observed error, and the guarded continuation verified the unchanged configuration
before applying the order. Both attempt records remain private. No reboot was
performed or qualified.

Independent actual public-cutover receipt SHA256:
`c3f91b6e1ca501260df0435c1cc52f5494dcad1d9fea7ad83f7b04236e2ae2e9`.
This establishes normal public login-page availability and deployment provenance.
The operator's successful account authentication and T09 acceptance remain separate.
