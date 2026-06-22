# Critical Review Hardening Sprint

Date: 2026-06-22
Baseline commit: `f8eed70`
Status: In progress

## Purpose

This sprint remediates the evidence-backed findings from the June 22 critical
code and documentation review. Work is divided into narrow slices so each
security property can be reviewed, tested, and committed independently.

## Slice Plan

| Slice | Finding | CWE | Status |
| --- | --- | --- | --- |
| 1 | TOTP counter replay | CWE-294 | Implemented |
| 2 | Serial mailbox-helper availability | CWE-400 | Implemented |
| 3 | Draft transaction races and partial replacement | CWE-362, CWE-664 | Implemented |
| 4 | Multipart part-header resource bounds | CWE-400 | Pending |
| 5 | Restrictive mode at file creation | CWE-732 | Pending |
| 6 | Documentation and package metadata drift | Documentation integrity | Pending |

## Slice 1: TOTP Counter Replay

The production file-backed TOTP verifier now records the highest accepted
counter per canonical user under the writable cache tree. Counter acceptance is
serialized with a store-local advisory lock and persisted through restrictive
same-directory atomic replacement.

The operator-managed secret directory remains read-oriented. Replay state is
kept separately under `cache/totp-replay`.

The verifier rejects an accepted counter when that counter or a newer counter
was already consumed. This also prevents two cooperating processes from both
accepting the same code concurrently.

Focused validation:

- current code is accepted once
- reuse of the same code is rejected
- a newer valid counter is accepted
- concurrent consumers produce exactly one acceptance

## Slice 2: Bounded Mailbox-Helper Concurrency

The mailbox helper now admits up to four concurrent Unix-socket connections.
Each admitted connection runs in a named worker thread. Excess connections
receive an explicit capacity error without entering the Dovecot execution
path.

The active-worker counter uses an RAII slot so normal completion, early return,
and worker panic all release capacity. The helper grant replay cache is shared
behind a mutex so grant replay rejection remains process-wide while requests
execute concurrently.

Focused validation:

- slots admit work up to the configured cap
- the next slot is rejected at capacity
- dropping a slot makes capacity available again
- zero-capacity policy fails closed
- helper protocol and replay tests continue to pass

## Slice 3: Transactional Draft Persistence

All file-backed draft operations now acquire one restrictive store-local
advisory lock. Quota checks, cleanup, save, load-expiry removal, list cleanup,
and deletion therefore observe one serialized draft tree across cooperating
processes.

Saves build the complete replacement in a private staging directory. Existing
draft data is left untouched until all attachment bodies and metadata have been
written and synced. Replacement uses a backup directory and restores the prior
draft when finalization fails.

Focused validation:

- concurrent new-draft saves cannot exceed the per-user quota
- an update still replaces a complete draft
- failed replacement restores the previous readable draft
- existing owner isolation, expiry, quota, attachment, and permission tests pass
