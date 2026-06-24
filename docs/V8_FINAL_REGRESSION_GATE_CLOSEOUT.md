# V8 Final Regression Gate Close-out

## Purpose

V8 was created because a production-visible rendering regression survived until V7 after testing discipline weakened after V2.

The V8 close-out objective is not feature growth. The objective is regression confidence.

## V8 close-out standard

V8 is complete only when:

- each V8 slice has a durable regression matrix
- each matrix has dedicated fixtures where fixtures are applicable
- each matrix has a Rust integration test or a shell gate
- each matrix has a dedicated executable gate under `maint/security/`
- `make v8-check` runs every V8 gate
- `make security-check` invokes the V8 aggregate gate
- CI runs `security-check`
- final evidence captures formatting, tests, clippy, cargo audit, V7 gates, V8 gates, and security-check

## Completed V8 slices

| Slice | Scope | Required gate |
|---|---|---|
| Slice 0 | Stabilization framework | `maint/security/osmap-v8-stabilization-gate.sh` |
| Slice 1 | Mail workflow regression matrix | `maint/security/osmap-v8-mail-workflow-gate.sh` |
| Slice 2 | Attachment safety regression matrix | `maint/security/osmap-v8-attachment-safety-gate.sh` |
| Slice 3 | Mailbox operation regression matrix | `maint/security/osmap-v8-mailbox-operation-gate.sh` |
| Slice 4 | Session integrity regression matrix | `maint/security/osmap-v8-session-integrity-gate.sh` |
| Slice 5 | Resource exhaustion and robustness matrix | `maint/security/osmap-v8-resource-robustness-gate.sh` |
| Slice 6 | Final regression gate closure | `maint/security/osmap-v8-final-regression-gate.sh` |

## Enforcement chain

The expected local and CI enforcement chain is:

```text
make security-check
  -> maint/security/osmap-security-check.sh
     -> make v8-check
        -> all V8 gates, including this final close-out gate
```

## Review and evidence status

The V8 implementation merged to `main` at
`ac2dfdd856011ec99a5238079f9eda8073577d83` on June 20, 2026.

A documentation and implementation review on June 20, 2026 confirmed:

- `make v8-check` passes all five Rust matrices and both structural gates
- the five matrices execute 25 focused integration tests
- `make security-check` invokes the V8 aggregate gate
- the GitHub Actions security workflow invokes `make security-check`
- external slice archives and their SHA256 sidecars exist under
  `$HOME/osmap-v8-evidence`
- every discovered V8 archive passes its recorded SHA256 verification

The mail workflow and attachment matrices execute their EML fixtures directly.
The mailbox, session, and resource matrices also carry reviewable text, TSV, or
ENV inventories. Except for the mailbox message-view EML and the attachment EML
used by the resource matrix, those inventory files are not parsed at test
runtime. Their corresponding vectors and assertions are encoded directly in
the Rust matrices.

This review did not claim that the V8 implementation commit was the currently
deployed production binary. At V8 closeout time, V7 remained reopened for
production availability and real-login hold proof. V9 later closed that
reopening for the tested selected-user production path.

## Non-goals

V8 does not claim feature parity with Roundcube.

V8 does not add new user-facing functionality.

V8 does not replace V4 hostile-content containment, V5 boundary hardening, V6 retirement readiness, or V7 rendering regression coverage. It preserves and extends regression confidence around them.
