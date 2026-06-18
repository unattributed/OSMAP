# OSMAP V6 Closeout Evidence

Date: 2026-06-18
Target host: `mail.blackbagsecurity.com`
Status: Incomplete; live evidence and deployment are pending

## Assessed Commit

The current pre-closeout source tip is:

```text
81f41c9 add v6 resource resilience proof
```

The final assessed commit must be the deployed V6 candidate and must be
recorded consistently by all four live reports. The Slice 09 commit is
identified by `close v6 retirement readiness evidence`; its immutable hash must
be added to the archived gate summary after the operator selects and deploys
the candidate.

## V6 Claim

OSMAP V6 proves that a selected OpenBSD-hosted user cohort can operate the
essential browser-mail workflows without Roundcube fallback, while preserving
the V4 hostile-content claim and the V5 identity, Host, Origin,
response-header, framing, and trusted HTML boundaries.

This claim is not yet satisfied because no V6 code has been deployed and the
required V6 live reports are absent.

## Exact Non-Goals

V6 does not add remote image loading, inline preview for active or
browser-executable attachments, broad JavaScript behavior, contacts, calendar,
groupware, plugins, mobile applications, OpenPGP, a ManageSieve browser UI, a
broad admin console, unbounded mailbox-wide operations, a broad async runtime
rewrite, Roundcube database import, or hidden fallback behavior.

## Slice Commits

1. `1c0a0f1` — record v6 baseline review
2. `a1db775` — define v6 controlled retirement readiness scope
3. `bb941d9` — add v6 closeout gates
4. `c7a4099` — add v6 production readiness validator
5. `d818584` — add v6 retirement rehearsal recorder
6. `d064c1b` — prove v6 operational observability
7. `f6776af` — add cross process session store locking
8. `657e12c` — preserve explicit source attachment draft references
9. `81f41c9` — add v6 resource resilience proof
10. Slice 09 — identified by commit message
   `close v6 retirement readiness evidence`

## Local Test Results

- Slice 07: `cargo test draft` passed 24 matching tests; `cargo test send`
  passed 32; `cargo test http::` passed 176; `make security-check` passed.
- Slice 08: validator syntax and regression tests passed;
  `cargo test throttle` passed 19; the targeted HTTP capacity test passed;
  `make security-check` passed.
- Final all-source verification is recorded in
  `V6_TRACES/SLICE_09_CLOSEOUT.md`.

## Required Live Evidence

| Gate | Path | Current status |
| --- | --- | --- |
| production readiness | `maint/live/latest-host-v6-production-readiness-report.txt` | missing |
| no-fallback rehearsal | `maint/live/latest-host-v6-retirement-rehearsal-report.txt` | missing |
| observability | `maint/live/latest-host-v6-observability-report.txt` | missing |
| resource resilience | `maint/live/latest-host-v6-resource-resilience-report.txt` | missing |

## Carry-Forward And Remediation Status

- V4 carry-forward: local gate available; final assessed-commit run pending.
- V5 carry-forward: local gate available; final assessed-commit run pending.
- V6 production readiness: blocked on V6 deployment and host report.
- V6 no-Roundcube-fallback rehearsal: blocked on selected-cohort walkthrough.
- V6 observability: blocked on post-deployment log and operator review.
- V6 resource resilience: validator implemented; blocked on host report.
- Session-store locking: implemented in `f6776af`.
- Explicit source-attachment draft references: implemented in `657e12c`;
  source bytes and raw MIME are not persisted.

## Evidence Archive

The archive and checksum must be produced only after the V6 gate passes:

```text
maint/live/osmap-v6-closeout-evidence.tar.gz
maint/live/osmap-v6-closeout-evidence.tar.gz.sha256
```

The archive does not currently exist because required live evidence is missing.

## Residual Risks

- OSMAP remains a narrow, self-hosted browser-mail platform, not a
  general-purpose webmail product.
- Roundcube must remain an explicit operator-controlled rollback unit until the
  selected cohort passes the no-fallback rehearsal.
- The known host is multi-purpose; deliberate pressure testing remains limited
  to isolated safe targets.
- Session locking is local-host advisory locking, not distributed locking.
- Source-message deletion, movement, mutation, or authorization changes can
  intentionally block draft resume or send.

## Rollback Note

Deployment must preserve the current binary and environment file as one
rollback unit. If any V6 validator or selected workflow fails, restore that
unit and keep Roundcube available as the explicit rollback path.

## Product Boundary

V6 does not make OSMAP a general-purpose webmail product and does not claim
Roundcube feature parity.
