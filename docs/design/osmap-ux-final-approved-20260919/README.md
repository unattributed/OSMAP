# OSMAP final approved UX reference bundle

Status: APPROVED AND LOCKED
Approval date: 2026-09-19
Repository: github.com/unattributed/OSMAP
Project control record: GitHub issue #77, `[OSMAP-UX] approved page lock manifest and pending revisions`

This archive is the final operator-approved UX reference set produced by the 2026-09-19 review cycle. The PNG bytes under `images/` are normative visual references for the named pages. Do not redraw, regenerate, substitute, simplify, or reinterpret an approved image without explicit operator approval and a new signed UX-plan revision.

## Existing implementation retained without redesign

Pages 25 and 26 intentionally have no replacement PNG in this archive:

- 25 Login: current OSMAP login page remains locked and authoritative.
- 26 TOTP Challenge: current OSMAP login/TOTP challenge remains locked and authoritative.

An implementation agent must inspect and preserve the current repository implementation for these two surfaces rather than use a generated mockup.

## Functional requirements attached to locked visuals

- Page 07 Documents is governed by the authenticated user's mailbox/storage quota. Documents must not create an independent unbounded storage pool or bypass account quota enforcement.
- Page 10 is `Settings > Security`. The earlier standalone Security page is retired as a top-level destination. `Settings > Privacy & Security` remains a distinct approved preferences/policy page.
- Page 16 allows authenticated-user mailbox subfolder create, rename, delete, and move operations, with protected/system-folder restrictions, hierarchy visibility, safe non-empty-folder handling, and account isolation.
- Page 22 provides independent accessible show/hide controls for current password, new password, and confirmation fields without changing validation or logging rules.
- Page 04 OpenPGP compose defaults are: Unsigned, Not encrypted, Encrypt-to-self Off. Recipient key status is availability state, not a user protection toggle. Security pre-flight is GREEN only when all selected protections and required send checks are satisfiable. ORANGE indicates a permitted but reduced/attention state such as unsigned, unencrypted, optional missing recipient key, encrypt-to-self off, or another non-blocking warning. A mandatory policy failure blocks Send and must never silently downgrade required protection.

## Integrity

`SHA256SUMS` contains the hashes for every retained file in this bundle except itself. The outer archive has a portable `.sha256` sidecar next to the tarball.
