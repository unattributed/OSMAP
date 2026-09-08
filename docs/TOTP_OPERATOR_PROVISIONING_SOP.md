# Interim TOTP Operator Provisioning SOP

## Purpose

This SOP defines the bounded interim operator workflow for provisioning an
OSMAP TOTP factor on `mail.blackbagsecurity.com`.

It closes the operator-tooling gap documented by
`TOTP_SECRET_MANAGEMENT_MODEL.md` without widening OSMAP into a general account
administration system, factor lifecycle service, or PostfixAdmin replacement.

The companion implementation is:

`maint/live/osmap-provision-totp-over-ssh.sh`

## Reconstruction Provenance

The original PR #56 operator-tool source files from August 2026 are no longer
present in the current development workspace or `~/Downloads` lineage.

Historical evidence still proves the prior accepted candidate's behavior,
security gates, live provisioning, negative paths, browser login, and exact
historical hashes. This reconstructed implementation therefore follows the
documented behavioral contract but is intentionally classified:

`BEHAVIORAL_RECONSTRUCTION_NOT_BYTE_IDENTICAL`

Do not describe the reconstructed SOP or script as the historical Aug 7 byte
stream. Fresh validation completed on 2026-09-08 before integration. The
recovered candidate matched the 2026-09-03 preservation record, and the
qualified operator script SHA-256 is
`d6ea1d3926b0a00dfc6dff42ae872c95f85cc0799a547f0d80c6a467362e6634`.
Production read-only validation confirmed the existing-factor `--check` and
fail-closed `--dry-run` no-overwrite contract without invoking provisioning or
mutating production.

Historical accepted hashes retained for provenance only:

```text
616e264fb3a1e1d6577e18d36c341dc77418c12fcc5e50071bd153ac95043d81  docs/README.md
426ad4445d39ede2f25c433ad27e0097128bdb57ee6d3455e43cd4c137488dbe  docs/TOTP_OPERATOR_PROVISIONING_SOP.md
de6c0bc9be43ce49108fce0104a5fe16da8ea42d0447a9fa5e89fd1efc9ff2f1  maint/live/osmap-provision-totp-over-ssh.sh
```

## Secret Store Contract

The tool uses the existing OSMAP file-backed TOTP model.

Default active secret directory:

```text
/var/lib/osmap/secrets/totp
```

Each factor is stored as:

```text
/var/lib/osmap/secrets/totp/<hex-canonical-username>.totp
```

The active file format is:

```text
# alice@example.com
secret=<base32-secret>
```

The active file must be:

- a regular file, not a symlink;
- owned by `_osmap:_osmap` by default;
- mode `0600`;
- outside the repository;
- installed without overwriting an existing active factor.

The provisioning tool does not modify OSMAP TOTP replay state. Replay state
remains owned by the runtime verifier under its configured cache tree.

## Supported Operations

### Self-test

```bash
maint/live/osmap-provision-totp-over-ssh.sh --self-test
```

This is local only and must not contact production.

### Read-only factor check

```bash
maint/live/osmap-provision-totp-over-ssh.sh \
  --check alice@example.com
```

The check verifies:

- the account is a canonical lowercase email address;
- the mailbox exists through Dovecot;
- whether an active TOTP file exists;
- if present, that the file is regular, non-symlink, `_osmap:_osmap`, and mode
  `0600`.

The check never reads or prints the secret value.

### Read-only provisioning plan

```bash
maint/live/osmap-provision-totp-over-ssh.sh \
  --dry-run alice@example.com
```

The dry-run first performs the remote check.

If an active factor already exists, provisioning is refused. The tool never
uses provisioning as an implicit rotation mechanism.

If no factor exists, the dry-run reports only non-secret planning metadata,
including the expected hex-encoded path, 20-byte secret size, no-overwrite
policy, enrollment-verification requirement, and rollback policy.

### Governed provisioning

```bash
maint/live/osmap-provision-totp-over-ssh.sh \
  --provision alice@example.com
```

Provisioning requires an interactive TTY and follows this exact order:

1. validate the canonical account and SSH host;
2. perform the remote read-only dry-run;
3. fail closed if the mailbox is missing, state is unsafe, or a factor exists;
4. require `qrencode` before generating enrollment material;
5. generate a fresh 20-byte random secret locally;
6. keep secret and URI material only in an owner-only temporary directory;
7. display the QR code and manual secret only on `/dev/tty`;
8. require the operator to enter a current TOTP code from the enrolled
   authenticator;
9. verify that code locally before any remote factor mutation;
10. require explicit `PROVISION <account>` operator authorization;
11. transmit the candidate secret file over the existing SSH channel without
    placing the secret in command-line arguments;
12. revalidate mailbox and active-factor absence remotely;
13. stage the file with owner `_osmap`, group `_osmap`, mode `0600`;
14. verify its SHA-256;
15. hard-link the staging inode to the final path so an existing final path
    cannot be overwritten;
16. verify final digest and metadata;
17. report successful provisioning;
18. clean all local temporary secret and URI material.

## Enrollment Material

The QR code and manual secret are sensitive one-time enrollment material.

They are displayed only through `/dev/tty`, not normal stdout or stderr, so
normal terminal evidence capture does not intentionally record them.

Do not:

- redirect the enrollment display into evidence;
- paste the secret into chat, GitHub, Issues, logs, or source control;
- save the secret or `otpauth://` URI under the repository;
- include the reusable secret in an evidence archive.

If enrollment verification fails, the tool exits before the remote install.

## Canonical Identity Rule

Only conservative lowercase email identities are accepted.

Examples:

```text
alice@example.com        accepted
Alice@example.com        rejected
alice                    rejected
alice@example            rejected
```

This prevents alternate spellings from creating multiple factor paths for the
same intended mailbox identity.

## Existing-Factor No-Overwrite Rule

An existing active factor is an absolute provisioning stop.

`--dry-run` reports:

```text
would_provision=false
dry_run_disposition=existing_secret_refused
```

`--provision` must not overwrite or replace it.

This tool does not perform ordinary TOTP rotation.

**Rotation fails closed.** An existing factor must be handled through a
separately reviewed revocation or recovery procedure before a replacement is
provisioned.

## Atomic Installation

The remote install uses a unique staging file under the active TOTP directory.

After content, owner, group, mode, and digest verification, the tool creates a
hard link from that staging inode to the final account path.

Because `ln` fails when the final path already exists, a concurrent creation
cannot be silently overwritten.

The staging link is then removed, leaving the final active inode.

## Ambiguous Remote Failure

A transport failure after remote installation begins must never trigger an
automatic provisioning retry.

The tool reports:

```text
automatic_provision_retry=false
```

After a bounded cooldown, it performs a separate reconciliation check.

If the active path is absent, no rollback is required.

If the active path exists, the tool may quarantine it only when all of the
following are proven:

- it is a regular non-symlink file;
- owner is `_osmap`;
- group is `_osmap`;
- mode is `0600`;
- its SHA-256 exactly matches the candidate file attempted by this invocation.

A byte-identical matching candidate may be moved to:

```text
/var/lib/osmap/secrets/totp-revoked
```

with an ambiguity-specific timestamped filename.

A nonmatching factor is never deleted, moved, replaced, or rewritten. That
condition fails closed with manual review required.

The quarantine directory is an ambiguity-recovery mechanism, not a general
factor-rotation interface.

## Interruption Safety

The local tool traps interruption and removes its owner-only temporary
enrollment directory.

An interruption at the QR, manual-secret, TOTP-code, or authorization stage
must occur before remote mutation and must not leave local secret or URI files.

The intended interruption status is `130`.

## PostfixAdmin Boundary

This tool does not retire, replace, modify, or administer PostfixAdmin.

Mailbox existence is checked through the existing Dovecot user/mailbox
surface. Mailbox creation and administrative account lifecycle remain outside
this interim TOTP provisioning tool.

## Rotation And Recovery Boundary

The tool intentionally does not implement general rotation.

A lost authenticator, suspected factor compromise, or planned factor rotation
requires an explicit separately governed recovery/revocation decision. Do not
force rotation by deleting an active factor and immediately rerunning
`--provision`.

The ambiguous-install quarantine behavior is not authorization for routine
factor revocation.

## SSH And Production Safety

The default SSH target is:

```text
mail.blackbagsecurity.com
```

SSH multiplexing is disabled by the tool.

For governed live campaigns:

- discover the actual route/interface/source dynamically;
- respect the host PF SSH source-rate protection;
- avoid unnecessary repeated SSH sessions;
- separate read-only validation from production mutation;
- never retry provisioning automatically after an ambiguous result.

## Evidence Rules

Safe evidence can include:

- account identifier;
- host;
- mailbox existence;
- factor existence;
- active file owner/group/mode;
- expected factor path;
- secret byte count;
- pass/fail workflow markers;
- candidate file SHA-256;
- rollback/quarantine disposition.

Evidence must not include:

- reusable Base32 secret;
- `otpauth://` URI;
- TOTP code;
- password;
- session cookie;
- private mailbox contents.

## Validation Required Before Integration

Because this file and its companion script are behavioral reconstructions, not
recovered historical bytes, integration requires fresh evidence.

Minimum sequence:

1. Bash syntax;
2. ShellCheck;
3. local `--self-test`;
4. canonical-identity negative tests;
5. exact three-file candidate scope;
6. full developer `make security-check`;
7. fresh production **read-only** `--check` and `--dry-run` contract validation;
8. controlled interruption regression if the fresh read-only gate confirms the
   host contract remains compatible;
9. evidence review;
10. signed commit only after acceptance.

No fresh production factor creation is authorized merely by reconstructing this
candidate.
