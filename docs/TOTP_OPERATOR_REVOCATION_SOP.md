# Interim TOTP Operator Revocation SOP

## Purpose

This SOP defines the bounded operator workflow for revoking one active OSMAP
TOTP factor on `mail.blackbagsecurity.com`.

The companion implementation is:

`maint/live/osmap-revoke-totp-over-ssh.sh`

This slice formalizes intentional factor revocation without turning the
provisioning tool into a general factor-lifecycle interface. It does not perform
replacement provisioning, rotation, recovery, mailbox administration, or
PostfixAdmin retirement.

## Relationship To Provisioning

Initial provisioning remains implemented by:

`maint/live/osmap-provision-totp-over-ssh.sh`

That production-qualified script deliberately refuses to overwrite an existing
factor. Revocation is therefore a separate governed operation.

The revocation tool does not modify the provisioning script or weaken its
existing-factor no-overwrite contract.

## Secret Store Boundary

The active factor path remains:

```text
/var/lib/osmap/secrets/totp/<hex-canonical-username>.totp
```

The reviewed revoked-factor directory is:

```text
/var/lib/osmap/secrets/totp-revoked
```

Active factor files must be regular non-symlink files owned by `_osmap:_osmap`
with mode `0600`.

When the revoked-factor directory already exists, it must be a regular directory,
not a symlink, owned by `_osmap:_osmap` with mode `0700`.

A missing revoked-factor directory may be created only by the governed
`--revoke` mutation after all active-factor preconditions and operator
authorization have passed. `--check` and `--dry-run` never create it.

## Supported Operations

### Self-test

```bash
maint/live/osmap-revoke-totp-over-ssh.sh --self-test
```

This is local only and must not contact production.

### Read-only factor check

```bash
maint/live/osmap-revoke-totp-over-ssh.sh \
  --check alice@example.com
```

The check verifies:

- canonical lowercase account syntax;
- mailbox presence when Dovecot can establish it;
- whether the canonical active TOTP path exists;
- regular-file and non-symlink type;
- `_osmap:_osmap` ownership;
- mode `0600`;
- active-factor SHA-256 fingerprint;
- existing revoked-directory metadata when that directory is present.

Mailbox absence is reported but does not by itself prevent revocation of a
safely identified orphaned factor. This permits cleanup of a factor that remains
after mailbox disablement or removal without inventing an alternate identity
mapping.

The check never prints the reusable TOTP secret.

### Read-only revocation plan

```bash
maint/live/osmap-revoke-totp-over-ssh.sh \
  --dry-run alice@example.com
```

If no active factor exists, the tool reports:

```text
would_revoke=false
dry_run_disposition=no_active_factor
```

and exits with status `3`.

When the active factor exists and its metadata is safe, dry-run records the
active path, reviewed revoked-path naming pattern, preservation requirement,
no-overwrite hard-link policy, digest compare-and-swap precondition, and explicit
non-claims for session revocation and replacement provisioning.

No production mutation occurs.

### Governed revocation

```bash
maint/live/osmap-revoke-totp-over-ssh.sh \
  --revoke alice@example.com
```

Revocation requires an interactive TTY and exact confirmation:

```text
REVOKE alice@example.com
```

The workflow then:

1. performs the complete read-only dry-run;
2. captures the active factor SHA-256 as a stale-state precondition;
3. requires exact operator authorization;
4. creates a UTC revocation timestamp;
5. revalidates active file type, ownership, mode, and digest remotely;
6. validates or securely creates the revoked-factor directory;
7. refuses a pre-existing destination;
8. creates a no-overwrite hard link from the active inode to the timestamped
   revoked path;
9. verifies the preserved copy digest;
10. proves the active and revoked paths reference the same inode;
11. removes the active path;
12. verifies the active path is absent;
13. verifies the preserved revoked factor remains `_osmap:_osmap`, mode `0600`,
    and byte-identical to the precondition digest;
14. reports the resulting non-secret evidence.

The timestamped revoked path format is:

```text
/var/lib/osmap/secrets/totp-revoked/<hex-account>.<UTC_TIMESTAMP>.revoked.totp
```

## Why Preserve Instead Of Delete

Revocation removes the active authentication path but preserves the previous
factor as owner-only security state.

Preservation provides:

- a bounded audit/recovery artifact;
- proof of which exact factor was revoked;
- deterministic comparison during ambiguous transport reconciliation;
- no dependency on copying or re-reading reusable secret material into evidence.

The preserved file is still secret material and must never be copied into
repository or sprint evidence archives.

## No-Overwrite And Stale-State Protection

The dry-run obtains the active factor SHA-256. The remote mutation re-reads the
active factor immediately before revocation and refuses the operation if that
digest has changed.

The archive destination is created with `ln` rather than a replacing copy or
ordinary overwrite-capable move. An existing destination therefore causes a
fail-closed error.

The active path is removed only after the archive hard link exists, has the
expected digest, and is proven to reference the same inode.

## Ambiguous Transport Failure

The tool never retries a revocation mutation automatically.

It reports:

```text
automatic_revoke_retry=false
```

Deterministic failures before active-path removal return immediately without
extra production contact.

A transport or post-removal ambiguity triggers a bounded cooldown followed by a
separate read-only reconciliation check.

Reconciliation can prove:

- active absent plus expected revoked path present and matching: revocation
  succeeded;
- active present plus expected revoked path absent: no revocation occurred;
- both paths present, conflicting paths, unsafe metadata, or both absent:
  manual review required.

Reconciliation never performs an automatic cleanup, second unlink, replacement
provision, or factor retry.

## Session Boundary

This TOTP revocation slice does **not** revoke browser sessions.

It always reports:

```text
session_revocation_performed=false
```

Existing session handling remains under OSMAP's separate session-management
boundary. Incident response may require revoking affected sessions through that
existing surface or persisted-session procedure.

A later administrative-control-plane slice may couple factor lifecycle and
session revocation only after that combined authorization and audit boundary is
reviewed.

## Rotation And Recovery Boundary

This tool does not rotate a factor and does not provision a replacement.

A planned rotation coordinator is being qualified in Slice 02; see
`TOTP_OPERATOR_ROTATION_SOP.md`. Its separately governed composition covers:

1. approved revocation;
2. explicitly authorized new-factor provisioning with enrollment verified
   before revocation;
3. any required session-handling decision.

Recovery for a lost authenticator is implemented separately in the Slice 03
candidate because it requires a stronger identity/authorization decision than
ordinary planned revocation; see `TOTP_OPERATOR_RECOVERY_SOP.md`. That tool
requires signed external identity, session-revocation, and containment
attestations. This standalone revocation tool does not supply those controls.

## Evidence Rules

Safe evidence may include:

- account identifier;
- SSH host;
- mailbox existence;
- active-factor existence;
- active owner/group/mode;
- active-factor SHA-256 fingerprint;
- revoked-directory metadata;
- timestamped revoked path;
- preserved-factor owner/group/mode;
- preserved-factor SHA-256 fingerprint;
- pass/fail workflow markers;
- reconciliation disposition.

Evidence must not include:

- reusable Base32 secret;
- `otpauth://` URI;
- TOTP code;
- password;
- session cookie;
- private mailbox contents;
- contents of active or revoked `.totp` files.

## Slice 01 Acceptance Boundary

Before integration, require:

1. Bash syntax validation;
2. ShellCheck;
3. local `--self-test`;
4. canonical-account and host negative tests;
5. documentation governance;
6. `git diff --check`;
7. full developer `make security-check`;
8. fresh production read-only `--check` and `--dry-run` contract validation;
9. a separately authorized controlled revocation test only if a disposable or
   explicitly approved factor is available;
10. sanitized evidence review;
11. signed commit and operator review before any push.

A read-only production gate does not authorize revoking the existing production
factor.
