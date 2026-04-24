# Version 2 Pilot Status

## Purpose

This document is the single live tracker for current Version 2 pilot-closeout
status.

Use it for the current answer to:

- whether the repo-owned V2 gate is currently passing
- whether rollback evidence is current
- whether the project is ready to claim final V2 closeout
- which remaining blockers are still operational rather than implementation

Use the linked documents below for scope, operator procedure, and detailed gate
definitions. Do not treat those documents as separate live status trackers.

## Canonical Sources

- `docs/V2_DEFINITION.md` defines the Version 2 boundary
- `docs/V2_ACCEPTANCE_CRITERIA.md` defines the authoritative Version 2 gate
- `docs/PILOT_DEPLOYMENT_PLAN.md` defines pilot entry, pause, rollback, and
  exit criteria
- `docs/PILOT_WORKFLOW_INVENTORY.md` defines the current intended pilot cohort
  fit
- `docs/V2_PILOT_REHEARSAL_SOP.md` defines the standard host-side readiness
  rerun flow
- `docs/EDGE_CUTOVER_PLAN.md` and `docs/EDGE_CUTOVER_REHEARSAL_SOP.md` define
  the rollback-ready edge procedure
- `docs/INTERNET_EXPOSURE_STATUS.md` records the current interpreted exposure
  posture

`docs/V2_PILOT_EXECUTION.md` is no longer a live gate document. It is retained
only as a superseded draft pointer so the repo has one current pilot tracker.

## Current Status

- assessment date: April 24, 2026
- assessed host: `mail.blackbagsecurity.com`
- assessed host checkout: `~/OSMAP`
- overall status: `engineering-ready for controlled pilot closeout, not final-closed`
- current outcome: the repo-owned V2 readiness gate and rollback evidence flow
  both reran successfully on the validated host

Version 2 is not yet honestly final-closed. The repo now has current
engineering, deployment, exposure, and rollback proof, but it still does not
have repo-owned evidence that a real pilot cohort completed and exited the
pilot successfully.

## Evidence Snapshot

| Area | Result | Evidence | Notes |
| --- | --- | --- | --- |
| V2 readiness gate | `passed` | `maint/live/latest-host-v2-readiness-report.txt` | Full 12-step authoritative V2 wrapper passed on April 24, 2026. |
| Persistent service guard | `passed` | `maint/live/latest-host-v2-readiness-service-guard-report.txt` | `osmap_serve` and `osmap_mailbox_helper` still passed the post-proof health restore check. |
| Rollback rehearsal | `passed` | `maint/live/latest-host-edge-cutover-session.txt` | Fresh `rehearse` session created at `~/osmap-edge-cutover/proof-20260424-v2-pilot-closeout` with current apply and restore scripts. |
| Edge cutover posture | `passed` | `maint/live/latest-host-edge-cutover-report.txt` | Public HTTPS still serves the reviewed OSMAP-only root while private control-plane templates remain off the WAN listener. |
| Internet exposure gate posture | `approved_for_limited_direct_public_browser_exposure` | `maint/live/latest-host-internet-exposure-report.txt` | Current assessment still matches the approved limited direct-public browser posture. |
| Pilot scope and workflow truthfulness | `ready` | `docs/V2_DEFINITION.md`, `docs/PILOT_DEPLOYMENT_PLAN.md`, `docs/PILOT_WORKFLOW_INVENTORY.md` | The live tracker now points pilot status back to the canonical boundary and plan docs instead of a conflicting standalone execution draft. |

## This Closeout Pass

This repo pass completed the following work immediately:

- fixed formatting-only drift in `src/http/routes_mail.rs` and
  `src/http_gateway_auth.rs` after the first April 24 host rerun showed that
  `cargo fmt --check` was blocking the authoritative `security-check` phase
- reran the full repo-owned Version 2 readiness gate on
  `mail.blackbagsecurity.com`
- reran the rollback evidence flow by preparing a fresh edge-cutover rehearsal
  session with reviewed apply and restore scripts
- refreshed the archived host-side rollback, cutover, exposure, and service
  guard artifacts under `maint/live/`
- established this file as the single live pilot tracker

## Remaining Blockers To Final V2 Closeout

- no repo-owned real-user pilot execution log or explicit operator exit
  decision is archived yet
- no final Version 2 closeout record has replaced this live tracker with a
  completed pilot result

These are no longer code or host-proof gaps. They are pilot-execution and
closeout-record gaps.
