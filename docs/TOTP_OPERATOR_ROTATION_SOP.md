# Governed TOTP Rotation SOP

## Boundary

Slice 02 provides planned operator-assisted rotation for an existing canonical
mailbox with an existing safe active factor. It composes the accepted revocation
and no-overwrite provisioning primitives, with replacement enrollment verified
before removing the original factor. Lost-authenticator recovery remains Slice 03.

The implementation is `maint/live/osmap-rotate-totp-over-ssh.sh`.
The coordinator makes no browser, mail-runtime, service, session, or replay-store
changes. PostfixAdmin remains in service.

## Prerequisites

- Reviewed source and the companion provisioning/revocation scripts together.
- Bash, Python 3, OpenSSH, `sha256sum`, and `qrencode` on the operator workstation.
- The existing OpenBSD `doas`, Dovecot, and owner-only factor-store contract.
- A previously verified SSH host key; unknown or changed keys fail closed.
- Explicit target address and expected system FQDN after the host migration.
- An unrecorded interactive terminal for enrollment and exact authorization.
- Independently established account-owner identity and approval for planned
  rotation. This tool does not authenticate the person holding the authenticator.
- Serialized factor administration for this account, including the legacy tools.
  The composition is not a cross-process transaction or a shared administration
  lock. Concurrent root/runtime writers remain outside this contract.

## Read-only plan

```bash
bash maint/live/osmap-rotate-totp-over-ssh.sh \
  --dry-run alice@example.com \
  --host mail.blackbagsecurity.com \
  --expected-hostname mail.blackbagsecurity.com
```

Use the real canonical account only in the operator terminal; do not commit
private account identifiers. The command checks host identity, safe directory
ancestry, mailbox existence, active-factor metadata, archive-directory metadata,
and the old factor digest. It neither generates a replacement nor changes state.
Only the archive directory itself may be missing. Store ancestors must be
non-symlink directories owned by root or the runtime owner, without group/world
write permission. Environment overrides containing shell syntax are refused.

`192.168.1.44` requires `--expected-hostname obsd1.blackbagsecurity.com` and is
the former host. Testing there is not production evidence for Vultr.

## Planned rotation

Replace `--dry-run` with `--rotate`. The tool:

1. Captures the old factor digest and checks the intended host and mailbox.
2. Generates a new factor, displays enrollment only on `/dev/tty`, and checks
   a code from the replacement authenticator while the old factor remains active.
3. Requires the exact phrase `ROTATE <account> ON <expected-hostname>` after
   displaying the preservation, failure, session, and serialization boundaries.
4. Rechecks the host/mailbox and refuses any changed old-factor digest.
5. Preserves and revokes the old factor using the original digest precondition.
6. Requires positive revocation evidence before attempting replacement once.
7. Installs the replacement with atomic no-overwrite linking and verifies its
   final metadata and digest through a fresh read-only check.
8. Cleans temporary local enrollment material on exit.

Seeds, enrollment URIs, and TOTP codes are passed to subprocesses through file
descriptors or standard input, not command arguments. Do not use shell tracing,
terminal recording, or evidence capture on the enrollment terminal.

The whole sequence is not atomic: between revocation and installation there is
no active factor. An installation failure may leave that condition in place.
The preserved old factor is never automatically restored, and no mutation is
automatically retried. A stale or unrelated factor is never deliberately
overwritten by the replacement installation.

## Failure and reconciliation

Failures before mutation return nonzero and preserve the original factor.
After any mutation attempt, an unsuccessful or unverified result returns `24`
with `TOTP_ROTATION=INCOMPLETE` and `manual_review_required=true`. Interruption
may terminate before that summary; an interrupted mutation is always ambiguous.

Retain only the account/host, previous and replacement digests, UTC revocation
timestamp, and non-secret status. Inspect the canonical active path and exact
timestamped archive read-only using the revocation SOP. Classify whether the old
factor remains active, the old factor is archived with no active factor, the
replacement is active, or state conflicts. Do not rerun rotation, automatically
restore the archived factor, delete a conflicting factor, or treat a lost SSH
response as proof that no change occurred. Any further mutation requires a new
operator decision following reconciliation.

Revocation archives remain secret host state. Never export their contents into
the repository or sprint artifacts. The tool does not delete existing browser
sessions. The account's accepted TOTP counter is retained; a replacement code
may need a later time step before login succeeds. Never reset the replay store
to accelerate testing.

## Qualification

Run `python3 maint/security/test-osmap-totp-rotation.py`, both companion
`--self-test` commands, Bash syntax, ShellCheck, documentation governance, and
`make security-check`. The state-machine tests isolate host and TTY boundaries;
additional tests execute the real remote shell programs with local SSH/doas
and OpenBSD utility adapters against a synthetic store, covering preservation,
installation, no-overwrite, stale digest, file modes, and directory safety.
They do not prove native OpenBSD execution, actual QR enrollment, or production
rotation. See `TOTP_LIFECYCLE_SPRINT.md` for pending live evidence and release
limitations. Slice delivery requires a signed, verified commit and review.
