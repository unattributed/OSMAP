# V10 Governance Status

## Scope

V10 is a governance, acceptance, and assurance recovery sprint. It is not a feature sprint and does not widen the OSMAP product surface.

This Slice 1 document records the authoritative V10 status baseline after the Slice 0 intake merge. It does not modify product behavior, deployment state, live-host configuration, authentication policy, mailbox handling, rendering behavior, or release posture.

## Assessed Source

- Generated at UTC: `2026-06-25T04:57:50Z`
- Local branch observed: `v10-governance-status`
- Local HEAD observed: `ec72b6f55687b716c0d21bdd4f44480b99ae5163`
- `origin/main` observed: `ec72b6f55687b716c0d21bdd4f44480b99ae5163`
- Local status clean: `true`

## Current Accepted Project State

- OSMAP remains a focused browser-mail access layer over the existing mail stack.
- The current V9 status is a selected-cohort release-candidate decision, not a broad public release claim.
- V10 Slice 0 produced the intake inventory at `docs/V10_INTAKE_AUDIT.md` and `maint/security/v10-intake-inventory.json`.
- V10 Slice 1 establishes the governance status and claims baseline so future slices have one explicit decision boundary.

## Slice 0 Intake Signals Carried Forward

| Signal | Value |
| --- | ---: |
| Markdown document inventory | `155` |
| Governance-language matches | `1494` |
| Placeholder or missing-work candidate files | `22` |
| Rust assumption inventory count | `712` |

## Acceptance Gate Status

| Gate or target | Current status | V10 disposition |
| --- | --- | --- |
| `security-check` | Existing gate | Preserved. Slice 1 must not weaken it. |
| `release-check` | Existing gate | Preserved. Slice 1 does not claim release readiness. |
| `acceptance-check` | `missing` | Define or explicitly defer in a later V10 gate slice. |
| `v10-check` | `missing` | Define or explicitly defer in a later V10 gate slice. |

## V10 Current Non-Claims

V10 does not currently claim any of the following:

- complete Roundcube replacement for all users,
- general hostile-email safety,
- malware prevention,
- attachment preview safety,
- unbounded MIME parsing safety,
- broad public release readiness,
- production deployment change,
- live-host acceptance beyond evidence already captured in prior scoped slices.

## Required Follow-On Work

Future V10 slices should handle these as bounded, separately evidenced changes:

1. Define the V10 acceptance gate and decide whether `acceptance-check` or `v10-check` should exist.
2. Triage the Slice 0 documentation and placeholder inventory into confirmed stale items, accepted historical references, and remediation work.
3. Classify Rust `.expect`, `.unwrap`, `panic!`, `todo!`, and `unimplemented!` assumptions into test-only, startup invariant, helper runtime, production request path, or remediation-required categories.
4. Refresh live-host evidence only through read-only or explicitly gated production procedures.
5. Preserve the selected-cohort V9 scope unless new evidence deliberately expands it.
