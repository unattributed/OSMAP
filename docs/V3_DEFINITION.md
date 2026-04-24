# Version 3 Definition

## Purpose

This document defines the authoritative Version 3 boundary for OSMAP.

Version 3 is the daily-driver adoption release. It turns the completed Version
2 pilot evidence into a focused replacement path for users whose ordinary mail
workflows are still too dependent on Roundcube, without turning OSMAP into a
Roundcube clone.

## Authoritative Definition

OSMAP Version 3 is the first daily-driver adoption release for the validated
OpenBSD mail-host shape: it preserves the Version 2 `_osmap` web runtime,
`vmail` mailbox-helper boundary, public-edge hardening, and all Version 2
security gates, while closing the specific pilot-proven workflow gaps that
block routine browser-mail use.

## Working Definition

Version 3 is V2 plus narrowly scoped daily-use continuity, correctness, and
operator policy work:

- MIME and HTML correctness
- draft save and resume
- reply and forward attachment handling
- richer search
- bounded bulk folder actions
- session and device policy
- TLS CBC cleanup or a documented exception
- WSTG regression evidence

## Why Version 3 Exists

Version 2 proved the secure browser-mail slice under limited direct public
exposure. The pilot users completed retrieve, send, and send-with-attachments
successfully, but the closeout evidence also showed that normal daily adoption
needs a small set of continuity and ergonomics improvements.

Version 3 exists to close those proven adoption gaps. It does not exist to add
contacts, calendars, plugins, groupware, or broad administrative surfaces.

## Version 3 In Scope

| Area | Version 3 target | Acceptance source |
| --- | --- | --- |
| MIME and HTML correctness | improve message selection, encoded header handling, sanitized HTML fidelity, and deterministic fallback behavior without loading remote content | `V3_ACCEPTANCE_CRITERIA.md` |
| Draft save and resume | persist bounded compose drafts for authenticated users and resume them without weakening CSRF, session, or storage boundaries | `V3_ACCEPTANCE_CRITERIA.md` |
| Reply and forward attachments | provide explicit, bounded handling for original-message attachments during reply or forward | `V3_ACCEPTANCE_CRITERIA.md` |
| Richer search | add practical query refinement, sorting, and result clarity while preserving bounded backend-visible mailbox search | `V3_ACCEPTANCE_CRITERIA.md` |
| Bounded bulk folder actions | support selected-message actions needed for daily cleanup without adding broad mailbox-management authority | `V3_ACCEPTANCE_CRITERIA.md` |
| Session and device policy | define and enforce the chosen concurrent-session, device labeling, and revocation behavior | `V3_SECURITY_GATES.md` |
| TLS CBC cleanup | remove TLS 1.2 CBC suites or record a reviewed compatibility exception with expiry and compensating controls | `V3_SECURITY_GATES.md` |
| WSTG regression evidence | rerun and archive browser-slice WSTG evidence after each V3 feature slice | `V3_SECURITY_GATES.md` |

## Explicitly Out Of Scope

- contacts
- calendar
- groupware
- plugins
- mobile app
- broad admin console
- remote external content loading
- OpenPGP implementation, except design-only investigation
- broad runtime rewrite
- replacement of Postfix, Dovecot, nginx, PF, or the existing mail substrate
- Roundcube parity work that is not tied to the pilot-proven daily-driver gaps

## Security Invariants

- all Version 2 gates remain required
- `_osmap` must not gain mail-storage authority directly
- the `vmail` mailbox-helper boundary must remain explicit and narrow
- production `serve` mode must keep using the local mailbox-helper boundary
- browser routes must remain server-rendered and dependency-light
- state-changing routes must remain CSRF-bound and same-origin-bound
- public edge hardening must remain mandatory before direct browser exposure is
  claimed
- no V3 feature may require direct browser access to IMAP, SMTP submission,
  helper sockets, local state directories, or privileged host operations
- HTML rendering must remain sanitizer-backed, active-content-free, and
  remote-resource-free
- attachment behavior must remain bounded, explicit, and auditable
- runtime rewrite work is allowed only when a V3 acceptance gate proves the
  current shape cannot safely satisfy the requirement

## Completion Test

Version 3 is complete only when the project can honestly say all of the
following are true:

- V2 pilot-complete status remains intact
- every V3 feature has passed its acceptance gate
- the V3 security gate has current repo-owned evidence
- daily-driver users can read, search, draft, resume, reply, forward, attach,
  send, and perform bounded folder cleanup without Roundcube fallback for those
  workflows
- unsupported workflows are still clearly named instead of implied
- OSMAP remains a focused secure browser-mail access layer, not a broad
  collaboration suite
