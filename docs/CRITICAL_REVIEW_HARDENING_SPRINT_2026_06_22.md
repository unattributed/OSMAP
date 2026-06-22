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
| 2 | Serial mailbox-helper availability | CWE-400 | Pending |
| 3 | Draft transaction races and partial replacement | CWE-362, CWE-664 | Pending |
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
