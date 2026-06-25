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
| `acceptance-check` | `present` | Added by Slice 2 as a local acceptance entry point that runs `security-check` and `v10-check`. |
| `v10-check` | `present` | Added by Slice 2 as the V10 governance and claims-boundary gate. |

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


## Slice 2 Acceptance Gate Update

V10 Slice 2 adds `make v10-check` and `make acceptance-check` as explicit local gate surfaces and exposes `security-check / v10 governance` in GitHub Actions.

This update narrows the meaning of acceptance to the current V10 governance and claims boundary. It does not claim broad public release readiness or production deployment change.

## Slice 3 Documentation Closure Status
V10 Slice 3 classifies the Slice 0 documentation placeholder and stale-status findings.

| Item | Value | Disposition |
| --- | ---: | --- |
| Placeholder or missing-work candidate files | `22` | Classified in `V10_DOCUMENTATION_STATUS_CLOSURE.md`. |
| Governance-language matches | `1494` | Classified by pattern and bounded by `V10_CLAIMS_AND_LIMITATIONS.md`. |
| Product behavior change | `0` | Slice 3 is documentation and governance only. |

Slice 3 does not claim broad release readiness, complete Roundcube replacement, general hostile-email safety, or completion of the Rust assumption triage.

## Slice 4 Rust Assumption Audit Status

V10 Slice 4 classifies the current Rust assumption inventory for fail-closed governance. The machine-readable register is `maint/security/v10-rust-assumption-audit.json`, and the repeatable scanner is `maint/security/osmap-v10-rust-assumption-audit.py`.

    | Item | Value | Disposition |
    | --- | ---: | --- |
    | Slice 0 carried-forward Rust assumption count | `712` | Preserved as the intake signal. |
    | Current normalized scanner count | `714` | Recorded in the Slice 4 audit register. |
    | Product behavior change | `0` | Slice 4 is audit and governance only. |
    | Inventory SHA256 | `eaea1f847a8b51dac00a82f25e8b117664ee22f7ed72576c10568769dc891ec4` | Enforced by `make v10-check`. |

    Slice 4 does not claim that all Rust assumptions are safe, that production request paths are panic-free, or that broad public release readiness has been reached.
