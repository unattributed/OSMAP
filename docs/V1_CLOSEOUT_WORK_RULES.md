# V1 Closeout Work Rules

## Purpose

This document is the short allowlist for active OSMAP work while Version 1
closeout remains frozen.

Use it to decide whether a proposed change is in-scope before starting work.

If a task does not clearly fit one of the allowed categories below, treat it as
Version 2 by default.

## Allowed V1-Closeout Work

- keep the frozen Version 1 status and release docs aligned with the
  authoritative gate in `ACCEPTANCE_CRITERIA.md`
- keep the repo-owned security and closeout gates healthy, including
  `make security-check`, hook wiring, closeout wrappers, and local regression
  checks
- rerun and record the affected repo-owned proof set when closeout-facing
  behavior changes
- fix repo-evidenced blockers in the shipped browser, helper, auth, session,
  send, move, search, attachment-download, or message-view surfaces
- preserve and tighten the deliberate Version 1 helper and OpenBSD confinement
  stopping point without reopening broader architecture scope
- make bounded clarity or hardening improvements inside the existing Version 1
  surface when they do not widen browser trust or product scope
- keep each completed change paired with the required docs, tests, signed
  commit, `origin/main` sync, and one explicit next-best development step

## Treat As V2 By Default

- broader folder ergonomics beyond the first useful move and archive baseline
- richer search behavior beyond ordinary daily-use needs
- richer session or device intelligence beyond first self-service visibility
- preview-heavy attachment behavior or broader rich-mail convenience features
- broader settings or preference surfaces
- deeper runtime redesign such as worker-pool or async server architecture

## Working Rule

When a task is ambiguous, require a narrow Version 1 closeout justification
before doing implementation work.
