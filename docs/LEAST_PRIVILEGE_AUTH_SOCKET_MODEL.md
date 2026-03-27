# Least-Privilege Dovecot Socket Model

## Purpose

This document defines the preferred host-side Dovecot socket arrangement for
OSMAP.

The goal is to let the OSMAP runtime use `doveadm auth test` plus the current
mailbox and message helper commands without teaching the application to depend
on `doas`, root privileges, or a broader mail-stack filesystem view than
necessary.

## Problem Statement

The current browser-auth path is intentionally unprivileged. On
`mail.blackbagsecurity.com`, that surfaced a real operational issue:

- the default or obvious Dovecot auth surface available to helper tools is not
  automatically reachable by the unprivileged OSMAP runtime user
- the current `/var/spool/postfix/private/auth` path is behind a directory
  boundary that an unprivileged runtime user cannot traverse
- using `doas` to bridge that gap would weaken the runtime model and make the
  trust boundary less reviewable

## Preferred Model

The preferred deployment model is:

- run OSMAP as a dedicated unprivileged service user
- expose a dedicated Dovecot auth listener for that service user
- expose a dedicated Dovecot userdb listener for that service user when mailbox
  and message helper lookups need an explicit least-privilege path
- point OSMAP at that listener with `OSMAP_DOVEADM_AUTH_SOCKET_PATH`
- point OSMAP at the userdb listener with `OSMAP_DOVEADM_USERDB_SOCKET_PATH`
- keep mailbox reads and submission on their existing authoritative surfaces

This keeps the host integration explicit and least-privilege friendly.

## Example OpenBSD-Oriented Shape

Illustrative Dovecot-side shape:

```conf
service auth {
    unix_listener /var/run/osmap/dovecot-auth {
        mode = 0660
        user = _osmap
        group = _osmap
    }
}
```

Illustrative OSMAP-side environment:

```sh
OSMAP_DOVEADM_AUTH_SOCKET_PATH=/var/run/osmap/dovecot-auth
OSMAP_DOVEADM_USERDB_SOCKET_PATH=/var/run/osmap/dovecot-userdb
```

The exact service user, group, and path can vary. The important property is
that the socket is deliberate, narrow, and reachable by the OSMAP runtime user
without privilege escalation.

## Current Validated Host Shape

On `mail.blackbagsecurity.com`, the currently validated arrangement is:

- runtime user: `_osmap`
- auth listener path: `/var/run/osmap-auth`
- userdb listener path: `/var/run/osmap-userdb`
- socket owner/group: `_osmap:_osmap`
- validation scope:
  - browser-driven invalid login under both `log-only` and `enforce`
  - browser-driven positive login plus TOTP-backed session issuance under
    `enforce`
  - mailbox-list helper reachability narrowed to Dovecot's `vmail` uid/gid
    boundary rather than to socket reachability

That validated path is not the only acceptable deployment shape, but it is now
real evidence that the least-privilege model works on the target OpenBSD host.

## Why This Is Better Than `doas`

This model is preferred because it:

- preserves an unprivileged runtime
- keeps the auth dependency visible in configuration instead of hidden in a
  privilege escalation path
- fits OpenBSD-style service separation better
- gives `pledge(2)` and `unveil(2)` planning a concrete path to model
- reduces the temptation to let the web-facing service run with broader host
  authority than it actually needs

## Confinement Implications

When the explicit Dovecot socket paths are configured, the OpenBSD confinement
plan should include:

- the explicit auth socket path with read/write access
- the explicit userdb socket path with read/write access
- read-only visibility for each socket's parent directory chain

That is still narrower and more honest than unveiling a broad mail-spool tree
or teaching the app to depend on `doas`.

## Operational Notes

Operators should:

- use a dedicated path rather than reusing a more privileged default listener
- keep directory permissions tight enough that only the intended runtime user
  and group can reach the socket
- document the socket in service-management and rollback procedures
- validate login behavior under `OSMAP_OPENBSD_CONFINEMENT_MODE=log-only` or
  `enforce`
- validate mailbox helper behavior separately from login behavior, because
  socket reachability and mailbox helper privilege requirements are not the
  same problem

## Current Status

As of March 27, 2026, OSMAP supports both explicit Dovecot socket paths in
runtime configuration and `mail.blackbagsecurity.com` now has dedicated
validated listeners at `/var/run/osmap-auth` and `/var/run/osmap-userdb` for
`_osmap`.

The current live-host outcome is intentionally mixed:

- least-privilege auth is proven for `_osmap`
- least-privilege mailbox socket reachability is also proven
- mailbox reads themselves still fail because the host Dovecot userdb resolves
  the target mailbox to `uid=2000(vmail)` and `gid=2000(vmail)`, which the
  `_osmap` process cannot assume without widening authority

This document describes the least-privilege operator path, the first live host
that proves part of it, and the remaining identity-boundary problem that still
needs a cleaner answer than `doas`.

The selected next-step answer is now documented separately in
`MAILBOX_READ_HELPER_MODEL.md`: keep auth-socket least privilege in place, but
move mailbox reads behind a local-only helper boundary instead of widening the
web-facing runtime.
