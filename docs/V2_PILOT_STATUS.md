# Version 2 Pilot Status

## Purpose

This document is the single live tracker for current Version 2 pilot-closeout
status.

Use it for the current answer to:

- whether the repo-owned V2 gate is currently passing
- whether rollback evidence is current
- whether final V2 closeout has been claimed
- which follow-up work is explicitly deferred beyond Version 2

Use the linked documents below for scope, operator procedure, and detailed gate
definitions. Do not treat those documents as separate live status trackers.

## Canonical Sources

- `docs/V2_DEFINITION.md` defines the Version 2 boundary
- `docs/V2_ACCEPTANCE_CRITERIA.md` defines the authoritative Version 2 gate
- `docs/V2_PILOT_CLOSEOUT.md` records the final pilot closeout result
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
- overall status: `final V2 pilot-complete`
- current outcome: the repo-owned V2 readiness gate, rollback evidence flow,
  limited-public browser exposure evidence, and real-user pilot execution
  record are complete for the bounded Version 2 scope

Version 2 is now pilot-complete for the current bounded browser-mail workflow
set. The completed pilot does not widen Version 2: requested additional
functionality and Thunderbird-like UX polish remain deferred to Version 3 or
later.

## Evidence Snapshot

| Area | Result | Evidence | Notes |
| --- | --- | --- | --- |
| V2 readiness gate | `passed` | `maint/live/latest-host-v2-readiness-report.txt` | Full 12-step authoritative V2 wrapper passed on April 24, 2026. |
| Persistent service guard | `passed` | `maint/live/latest-host-v2-readiness-service-guard-report.txt` | `osmap_serve` and `osmap_mailbox_helper` still passed the post-proof health restore check. |
| Rollback rehearsal | `passed` | `maint/live/latest-host-edge-cutover-session.txt` | Fresh `rehearse` session created at `~/osmap-edge-cutover/proof-20260424-v2-pilot-closeout` with current apply and restore scripts. |
| Edge cutover posture | `passed` | `maint/live/latest-host-edge-cutover-report.txt` | Public HTTPS still serves the reviewed OSMAP-only root while private control-plane templates remain off the WAN listener. |
| Internet exposure gate posture | `approved_for_limited_direct_public_browser_exposure` | `maint/live/latest-host-internet-exposure-report.txt` | Current assessment still matches the approved limited direct-public browser posture. |
| Pilot scope and workflow truthfulness | `complete` | `docs/V2_DEFINITION.md`, `docs/PILOT_DEPLOYMENT_PLAN.md`, `docs/PILOT_WORKFLOW_INVENTORY.md`, `docs/V2_PILOT_CLOSEOUT.md` | Three real trial users completed the expected bounded V2 workflows and reported that the presented functions worked as expected. |

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
- archived the final real-user pilot closeout result in
  `docs/V2_PILOT_CLOSEOUT.md`

## Final Closeout Result

The Version 2 pilot is complete for the bounded V2 scope. The final trial
cohort was:

- `duncan@blackbagsecurity.com`
- `ops@blackbagsecurity.io`
- `duncan@redactedsecurity.ca`

Each trial user completed retrieve mail, send mail, and send mail with
attachments. Each reported that the functions presented in the current code
base worked as expected.

All additional requested functionality and Thunderbird-like UX polish remain
Version 3 or later work.
