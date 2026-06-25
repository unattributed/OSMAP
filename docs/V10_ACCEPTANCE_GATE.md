# V10 Acceptance Gate and CI Visibility

## Purpose

V10 Slice 2 defines the first explicit V10 acceptance gate surface after the Slice 0 intake and Slice 1 governance baseline.

This slice creates visible local and CI entry points for the V10 governance boundary. It does not change product behavior, deployment state, live-host configuration, authentication policy, mailbox handling, rendering behavior, or release posture.

## Assessed source

- Generated at UTC: `2026-06-25T05:48:21Z`
- Local branch observed: `v10-acceptance-gate`
- Local HEAD observed: `9d34ea5a754dd475d4b54825aeadbf71e31c1d03`
- `origin/main` observed: `9d34ea5a754dd475d4b54825aeadbf71e31c1d03`

## Gate map

| Gate | Command | Purpose | Release meaning |
| --- | --- | --- | --- |
| V10 governance gate | `make v10-check` | Verifies V10 governance documents, claims boundary JSON, documentation index entries, Makefile target visibility, and CI workflow visibility. | This gate does not claim release readiness. |
| Local acceptance gate | `make acceptance-check` | Runs the existing repository security gate and then the V10 governance gate. | Establishes local acceptance for the current bounded governance state only. |
| Existing security gate | `make security-check` | Preserves existing Rust, documentation, WSTG, supply-chain, and shell-based guard coverage. | Remains the primary CI regression gate. |
| Existing release gate | `make release-check` | Preserved as a separate stricter release path. | Slice 2 does not redefine it or claim broad public release readiness. |

## CI visibility

The `security-check` workflow now exposes a separate job named `security-check / v10 governance` that runs `make v10-check` on pull requests and pushes to `main`.

This is intentionally separate from the Rust security-check job so reviewers can see whether V10 governance and claims-boundary checks passed without inspecting long Rust test logs.

## Explicit non-claims

Slice 2 does not claim any of the following:

- product behavior change,
- production deployment change,
- live-host validation refresh,
- broad public release readiness,
- complete Roundcube replacement,
- general hostile-email safety,
- unbounded MIME or mailbox parsing safety.

## Acceptance criteria for Slice 2

Slice 2 is complete only when all of the following are true:

1. `make v10-check` exists and passes.
2. `make acceptance-check` exists and passes locally when requested by the runner.
3. CI exposes `security-check / v10 governance`.
4. `maint/security/v10-claims-boundary.json` records both V10 gate targets as present.
5. `docs/README.md` indexes this document.
6. GitHub CI passes before merge.
