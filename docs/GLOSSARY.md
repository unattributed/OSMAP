# Glossary

This glossary records recurring OSMAP terms that now appear across the Phase 0
through Version 2 closeout documentation set and the current Rust
implementation.

## Terms

### Archive Shortcut

A bounded user setting that stores one mailbox name for the current
archive-oriented move workflow. It is not a full rules engine or a general
folder-automation feature.

### Audit Event

A structured log event emitted by the OSMAP runtime for security-relevant or
operator-relevant actions such as authentication outcomes, session changes,
mailbox access, send attempts, or message moves.

### Bootstrap Mode

The `osmap bootstrap` run mode. It validates configuration and runtime
assumptions without starting the browser listener or mailbox-helper service.

### Bounded

The project's preferred design adjective for a deliberately narrow feature,
parser, policy surface, or operational behavior. A bounded slice is small
enough to review, test, and reason about without importing broad framework or
feature sprawl.

### Browser Runtime

The web-facing OSMAP `serve` process that handles HTTP requests, session
validation, browser rendering, and the current browser-side mutation routes.
In the preferred OpenBSD deployment posture it runs as `_osmap`.

### Canonical Username

The normalized user identity string OSMAP uses internally once the auth layer
has accepted the submitted mailbox identity. Throttling, session state, and
some audit fields operate on this canonicalized view.

### Closeout Gate

The authoritative Version 1 release-facing proof boundary defined in
`ACCEPTANCE_CRITERIA.md` and exercised by the repo-owned closeout validation
wrappers described in `V1_CLOSEOUT_SOP.md`. Version 2 uses the separate
readiness and pilot-closeout records in `V2_ACCEPTANCE_CRITERIA.md`,
`V2_PILOT_STATUS.md`, and `V2_PILOT_CLOSEOUT.md`.

### Development Mode

The conservative local-development environment in which OSMAP requires a
loopback listener and allows certain implementation seams that are not treated
as acceptable production posture.

### Enforce

The `OSMAP_OPENBSD_CONFINEMENT_MODE=enforce` setting. In this mode the runtime
applies the implemented OpenBSD confinement policy rather than only logging the
intended policy shape.

### Helper Boundary

The explicit local Unix-socket separation between the browser-facing OSMAP
process and the mailbox-helper process. The boundary exists to keep mailbox-read
authority out of the web-facing runtime.

### Mailbox Helper

The local-only OSMAP `mailbox-helper` process that performs helper-backed
mailbox listing, message-list retrieval, message view, search, and attachment
download operations. In the preferred OpenBSD posture it runs as `vmail`.

### Public-Safe

A documentation or repository discipline meaning the published material is
reviewable without exposing secrets, private planning notes, or sensitive
host-local details.

### Roundcube Retirement

The later-phase act of removing Roundcube from the active browser-mail role
after OSMAP migration, rollback planning, and workflow validation are complete
for the intended rollout population. The Version 2 pilot closeout does not by
itself retire Roundcube.

### Safe HTML Rendering

The current message-view behavior that allows a narrow allowlist-sanitized HTML
representation for HTML-capable messages while still preserving plain-text
fallback and avoiding external-resource loading.

### Serve Mode

The `osmap serve` run mode. It starts the browser-facing HTTP runtime and, in
production posture, now requires a configured mailbox-helper socket instead of
allowing direct mailbox-read backends.

### Session Surface

The bounded end-user browser flows around session listing, session revocation,
and logout, backed by persisted OSMAP session metadata and revocation logic.

### State Root

The top-level mutable OSMAP directory selected by `OSMAP_STATE_DIR`. Runtime,
session, settings, audit, cache, and TOTP-secret subpaths are derived beneath
this root under explicit validation rules.

### Validation Host

The real host used for repo-grounded live proof of the current deployment
shape, presently `mail.blackbagsecurity.com`.

### Validation Mailbox

The controlled mailbox used for live proof steps such as real login and send
validation. It exists so the repo can prove end-to-end behavior without
storing mailbox secrets in version control.

### VPN-First Posture

The conservative deployment assumption that browser access may initially remain
behind the current VPN and edge allowlisting model instead of treating broad
public internet exposure as the default fallback posture. Version 2 now has
approved limited direct-public browser exposure evidence, but VPN-first remains
a valid rollback or staging posture.
