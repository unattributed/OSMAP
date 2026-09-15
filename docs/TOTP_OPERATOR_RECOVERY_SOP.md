# Governed TOTP Recovery SOP

## Scope and authority

Slice 03 provides operator-assisted recovery when an authenticator is lost but
the canonical mailbox and its active factor still exist. It reuses the Slice 02
replacement sequence after checking a short-lived, detached-signed recovery
approval. It does not recover an absent factor, authenticate the claimant,
provide recovery codes, expose a browser route, or administer mail identities.

Implementation:

- `maint/live/osmap-recover-totp-over-ssh.sh`
- `maint/live/osmap-totp-recovery-approval.py`
- the companion rotation, revocation, and provisioning scripts from the same
  reviewed source tree.

This is an interim single-operator control. The approval signer is pinned to
the existing Shopkeeper primary fingerprint
`F55E404E91A0753701F91B01A7228D3FB5084B34`; there is no caller-selected signer or
automatic key retrieval. A signature supplies attributable authorization, not
independent evidence of the claimant's identity. It does not provide separation
of duties from a privileged operator who already controls SSH and the key.

Routine autonomous commit signing does not authorize signing recovery approvals.
The recovery tool only verifies approvals; it cannot create a valid approval
by itself and never invokes a signing operation.

## Controlled validation-account rehearsal (Slice 04)

This opt-in mode is **not real-user recovery qualification**. The operator
authorized a truthful test-custody rehearsal because the reserved validation
account has no real claimant whose identity could be independently checked.
Do not invent an in-person check to make a production approval pass.

Add `--controlled-rehearsal` to the request, dry-run, and recovery commands only
for `osmap-helper-validation@blackbagsecurity.com`, host `192.168.1.44`, expected
hostname `obsd1.blackbagsecurity.com`. Other accounts, target aliases, runtime
identities, and factor-directory overrides are rejected before SSH. Production
recovery remains unchanged and rejects rehearsal approvals, even when signed.

The rehearsal approval uses `osmap-totp-controlled-rehearsal-v1`, requires
`identity_method=controlled_test_custody`, and replaces `sessions_revoked` with
the JSON boolean `no_valid_sessions`. All other fields, private-file checks,
pinned signature verification, exact factor binding, revalidation, and the
maximum 900-second lifetime remain required. `identity_case` records test
custody, not a person's identity check. A suitable non-secret case label is
`osmap-slice04-recovery-01`; the label itself is not evidence. Templates remain
intentionally invalid and are never signed automatically by the verifier.

Before approval, establish test-account custody and the authorized browser
maintenance window. Stop only `osmap_serve` on obsd1 through the reviewed host
service procedure; this interrupts **all OSMAP browser users on that host**.
Do not stop SMTP/IMAP, contact Vultr, change boot enablement, or restart the
browser service while a recovery result is ambiguous. Verify the restoration
configuration before stopping the service. Serialize service and factor
administration throughout the window, including manual and legacy tools.

`maint/live/osmap-totp-rehearsal-check.py` runs read-only on the fixed OpenBSD
host through strict SSH/doas before each approval verification. It checks the
expected session/listener/time-limit configuration, stopped service and workers,
closed loopback listener, safe file ancestry and metadata, and bounded session
records under the existing session-store lock. It refuses usable sessions for
the reserved account. It distinguishes already-revoked records from expired
unrevoked records; neither is reported as a new revocation. If usable sessions
exist, stop and use a separately reviewed revocation path. Never erase another
account's session state to satisfy this guard.

The guard does not stop services, revoke sessions, contain SMTP/IMAP, or prevent
another privileged operator from restarting a service after the check. Its
lock is released before enrollment and factor replacement; it does not make
the workflow atomic. These limitations require serialized maintenance.

The private terminal confirmation starts with `REHEARSE`, not `RECOVER`.
Results use `TOTP_RECOVERY_REHEARSAL`, never `TOTP_RECOVERY=PASS`. A successful
rehearsal exercises the shared replacement engine but does not prove a real
claimant's identity or satisfy production recovery acceptance. Keep QR/code
entry unrecorded. Reconcile the result and approved cleanup before restoring
the browser service; verify restored service health. No automatic mutation
retry, old-factor restoration, replay reset, or service restart is introduced.

## Required external controls for real-user recovery

Before an operator approves a recovery:

1. Establish the claimant's identity in person or through an established,
   independent channel. Possession of the mailbox password, access to that same
   mailbox, an email request, or a TOTP reset request alone is insufficient.
2. Revoke the account's existing sessions through a separately reviewed path.
3. Contain account access through a separately reviewed operational procedure
   so another session cannot be issued while recovery is underway. Keep access
   contained through failures, reconciliation, and final operator acceptance.
4. Record those controls in the operator's private case system. Put only opaque,
   non-secret case references in the approval, not identity documents, passwords,
   message bodies, sessions, or authenticator material.
5. Serialize all factor administration for this account, including legacy tools.

The tool verifies that the signed approval attests these controls. It does not
perform or independently prove identity checks, session revocation, containment,
or subsequent account re-enablement. If these controls cannot be established,
stop; do not substitute a planned rotation for recovery. Missing-factor and
already-partial recovery require a separate reviewed reconciliation decision.

## Request template

The operator selected obsd1 at `192.168.1.44` for this sprint. Use that explicit
target and record the evidence as obsd1 evidence. The known-host key and expected
system hostname must match. No Vultr qualification is part of this sprint.

```bash
umask 077
bash maint/live/osmap-recover-totp-over-ssh.sh \
  --request alice@example.com \
  --host 192.168.1.44 \
  --expected-hostname obsd1.blackbagsecurity.com
```

This performs a read-only factor/mailbox/host check and prints a JSON template.
It does not generate enrollment material or mutate the host. The template is
intentionally invalid: identity/case fields are incomplete and the session and
containment attestations are false. Store an operator-approved copy outside
Git with mode `0600`. Use the sprint artifact root for retained sanitized
delivery examples; private case evidence must stay outside retained artifacts.

The approval has exactly these fields:

| Field | Contract |
| --- | --- |
| `schema` | `osmap-totp-recovery-approval-v1` |
| `account`, `ssh_host`, `expected_hostname` | Exact values from the reviewed request; aliases are not interchangeable |
| `previous_factor_sha256` | Exact current active-factor digest, lowercase SHA-256 |
| `request_id` | Opaque case/request identifier, 1–64 conservative characters |
| `issued_at`, `expires_at` | Integer Unix seconds; no future issuance, current time strictly before expiry, maximum 900-second lifetime |
| `identity_method` | `in_person` or `established_out_of_band` |
| `identity_case`, `session_case`, `containment_case` | Nonempty opaque references, 1–64 characters from letters, digits, dot, underscore, hyphen; first character alphanumeric |
| `sessions_revoked`, `access_contained` | JSON booleans `true` after the external controls are established |

Additional, duplicate, missing, or malformed fields fail closed. Approval and
signature inputs must be owned by the invoking user, regular non-symlink files,
without group/other permissions, and no larger than 16 KiB each.

After the human operator checks the actual controls and explicitly authorizes
the recovery, that operator signs the exact completed JSON with the Shopkeeper
key, using a detached OpenPGP signature and the configured `gpg-agent`. Store
both files as `0600`. The verifier uses the local public-key inventory, requires
the pinned primary fingerprint, and rejects invalid, expired, revoked,
multiple, or unavailable signatures. The operator remains responsible for the
currency of the local key inventory; the tool performs no online key discovery.

## Verify and recover

```bash
bash maint/live/osmap-recover-totp-over-ssh.sh \
  --dry-run alice@example.com \
  --host 192.168.1.44 \
  --expected-hostname obsd1.blackbagsecurity.com \
  --approval /path/to/approved-recovery.json \
  --signature /path/to/approved-recovery.sig
```

A successful dry-run verifies the signature, lifetime, exact host/account/factor
binding, and attestations without enrollment or mutation. Change `--dry-run` to
`--recover` only after the separately authorized operator decision.

Recovery verifies approval before preparing enrollment. The intended new
authenticator must then pass a code check while the old factor remains active.
The operator must type exactly:

```text
RECOVER <account> ON <expected-hostname> REQUEST <request_id>
```

Immediately before revocation, the tool rechecks host/mailbox/factor state and
revalidates the same signed approval, including its expiry and content digest.
Changed, expired, or substituted approval data prevents mutation. It preserves
the old factor, revokes it, installs the verified new factor without overwrite,
and verifies the new factor's final digest and metadata. It never restores an
old factor, resets replay counters, retries a mutation, or releases containment.

The signature is not a durable one-time token. Successful replacement changes
the bound factor digest and makes that approval stale. If an operation is
interrupted or fails, keep access contained, reconcile read-only, and obtain a
new explicit operator decision before another attempt; there is no consumed-
approval database. Operator serialization remains required.

## Failure and evidence

Read-only or pre-mutation refusals are nonzero and leave the old factor intact.
Unverified mutation results return `24`, `TOTP_RECOVERY=INCOMPLETE`, and
`manual_review_required=true`. An interrupted mutation is ambiguous even if no
final summary was printed. Follow the Slice 02 reconciliation procedure using
the old/new digests and exact archive timestamp. An install failure can leave
no active factor. Do not automatically restore the lost or possibly compromised
factor and do not remove a competing factor to force recovery.

Output distinguishes signed attestations from performed operations. In
particular, `session_revocation_attested=true` does not mean this tool revoked
sessions; `session_revocation_performed=false` remains explicit.
Never retain enrollment seed/URI/code, active or archived factor bodies, or
private identity evidence. Approval outputs retain only request and content
digests, constrained request references, control-attestation flags, and status.

Qualification requires rotation regressions, recovery policy and transition
tests, real detached-signature tests with disposable synthetic keys, Bash
syntax, ShellCheck, documentation/publication checks, and `make security-check`.
`gpg` and `gpgconf` are required for the local signature tests; they do not sign
real approvals or commits. Native OpenBSD/real-authenticator recovery on the
selected obsd1 host remains a separate Slice 04 evidence requirement. Native
synthetic tests passed; see `TOTP_LIFECYCLE_OBSD1_EVIDENCE.md` for their precise
boundary and the outstanding human acceptance work. The
unavailable Vultr instance is not a dependency for this sprint.
