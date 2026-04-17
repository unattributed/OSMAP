# Version 2 Definition

## Purpose

This document defines the authoritative Version 2 boundary for OSMAP.

Version 2 is not "Version 1 plus more features." It is the first release
candidate intended to make OSMAP credible for controlled real-world adoption on
the known OpenBSD mail host shape.

## Authoritative Definition

OSMAP Version 2 is the first pilot-ready, migration-capable production
candidate for the known OpenBSD mail environment: a security-first browser mail
service that preserves the existing mail stack, keeps the `_osmap` to `vmail`
least-privilege boundary intact, supports direct public browser access through
a hardened HTTPS edge once the explicit internet-exposure gate is satisfied,
and ships with the operator, migration, rollback, and validation material
needed for controlled real-world use.

## Working Definition

Version 2 is the first security-validated, operator-usable, migration-capable
OSMAP release for direct browser access on the real OpenBSD mail host shape.

## Why Version 2 Exists

Version 1 now proves the narrow browser-mail product shape:

- password-plus-TOTP browser login
- bounded sessions with revocation
- helper-backed mailbox read
- safe browser message rendering
- bounded send and one-message move
- OpenBSD confinement and least-privilege backend coupling

That is enough to freeze the first secure browser slice, but it is not yet
enough to declare OSMAP ready for limited real-world replacement of Roundcube.

Version 2 exists to close the gap between:

- a working, validated prototype
- a migration-capable, pilot-ready release candidate

## Version 2 In Scope

- one authoritative Version 2 release boundary and acceptance gate
- direct browser access over the public internet through nginx or an equivalent
  hardened HTTPS edge, but only after the internet-exposure gate is passed
- preservation of the current least-privilege runtime split:
  `_osmap` web runtime, `vmail` mailbox helper, dedicated Dovecot auth and
  userdb sockets, existing Postfix/sendmail handoff
- repeatable host proof on `mail.blackbagsecurity.com` for the core browser
  flows: login, TOTP, mailbox read, search, send, move/archive, session
  visibility, logout
- repeatable hostile-path and abuse-path proof for the same deployment shape:
  invalid login, throttled login, throttled send, throttled move, helper peer
  rejection, CSRF and same-origin rejection, bounded backend failure behavior
- migration and rollback planning sufficient to support a controlled pilot
- pilot deployment guidance that treats public browser reachability as intended,
  but still gated by explicit readiness criteria
- narrowly scoped product work only when the pilot workflow inventory proves it
  is required for migration-capable adoption

## Version 2 Out Of Scope

- calendar, contacts, groupware, mobile apps, plugin ecosystems, SaaS, and
  multi-tenant hosting
- replacement of Dovecot, Postfix, or the existing mail substrate
- broad administrative surfaces or a mixed user-admin mega-interface
- OpenPGP signing, encryption, decryption, key management, or server-side GPG
- rich-mail trust expansion such as external-resource loading, inline active
  content, preview-heavy attachment behavior, or rich-text composition
- broader settings growth beyond what is required for pilot-safe normal use
- runtime redesign for its own sake, including worker-pool or async rewrites,
  unless a current Version 2 gate exposes a concrete blocking defect
- Roundcube parity work that is not proven necessary by real workflow inventory

## Security Invariants

- the web-facing runtime must remain unprivileged and separate from
  mail-storage authority; `_osmap` must not become `vmail`
- the request path must not depend on `doas`, root privileges, or broad host
  trust shortcuts
- the mailbox-helper boundary must remain explicit and narrow
- Dovecot and Postfix remain authoritative; OSMAP stays a constrained browser
  access layer, not a second mail platform
- direct public browser access is an intended supported Version 2 target, but
  only after the repo-defined internet-exposure gate is satisfied
- public exposure must not widen backend reachability: no direct browser access
  to IMAP, SMTP submission, helper sockets, or OSMAP local state
- browser hardening must not weaken: strict session handling, CSRF, restrictive
  CSP, same-origin enforcement, safe cookies, and server-rendered minimal-client
  behavior remain mandatory
- HTML and attachment handling remain conservative unless a separately justified
  security case says otherwise
- OpenBSD confinement, explicit dependency narrowing, auditability, and
  reversible deployment remain required

## Version 2 Completion Test

Version 2 is complete only when the project can honestly say all of the
following are true:

- OSMAP is still narrow, least-privilege, and reviewable
- direct public browser access is treated as a supported deployment target,
  not as a future wish
- the public-exposure gate is defined and passed before that deployment posture
  is claimed
- the migration and rollback story is credible for a small controlled pilot
- the remaining deferred work is clearly Version 3 or later, not hidden inside
  Version 2

## Explicit Defers Beyond Version 2

- broader folder ergonomics beyond what pilot users actually require
- richer search behavior beyond ordinary browser mail use
- richer session or device intelligence beyond first useful security visibility
- preview-heavy attachment workflows
- broader settings or personalization surfaces
- helper-side opaque identity redesign beyond the current trusted-runtime split
- packaging or ports integration beyond what the current operator deployment
  guidance already proves
