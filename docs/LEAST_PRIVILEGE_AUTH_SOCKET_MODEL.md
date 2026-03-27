# Least-Privilege Auth Socket Model

## Purpose

This document defines the preferred host-side authentication socket arrangement
for OSMAP.

The goal is to let the OSMAP runtime use `doveadm auth test` without teaching
the application to depend on `doas`, root privileges, or a broader mail-stack
filesystem view than necessary.

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
- point OSMAP at that listener with `OSMAP_DOVEADM_AUTH_SOCKET_PATH`
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
```

The exact service user, group, and path can vary. The important property is
that the socket is deliberate, narrow, and reachable by the OSMAP runtime user
without privilege escalation.

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

When `OSMAP_DOVEADM_AUTH_SOCKET_PATH` is configured, the OpenBSD confinement
plan should include:

- the explicit socket path with read/write access
- read-only visibility for the socket's parent directory chain

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

## Current Status

As of March 27, 2026, OSMAP now supports the explicit auth-socket path in
runtime configuration, but the repository does not claim that every target host
already has this dedicated Dovecot listener configured.

This document describes the intended least-privilege operator path forward.
