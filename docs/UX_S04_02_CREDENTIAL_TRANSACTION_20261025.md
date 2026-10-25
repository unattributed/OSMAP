# S04-02 credential transaction and epoch/session consistency — 2026-10-25

## Outcome

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

The requested credential/epoch/session boundary is complete. Prior successful credential-freshness evidence was reused. This ordinary helper and real session-API proof uses test-only client constructors that bypass only the qualification flag; actual transport, keys, kernel peers, guarded lease, pending ACK, SQL, epoch and session machinery execute. TOTP uses the actual verifier with a RAM-only fixture seed. Installed TOTP-file custody and the HTTP/browser journey remain separate acceptance work. Full S04-02/T03 and operator UAT remain open.

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
