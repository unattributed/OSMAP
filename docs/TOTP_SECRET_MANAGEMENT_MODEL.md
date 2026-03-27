# TOTP And Secret Management Model

## Purpose

This document records the current TOTP backend and secret-management boundary
for OSMAP.

The goal is to add a real second-factor verifier without hardcoding secrets,
without committing secret material, and without pretending the secret lifecycle
is someone else's problem.

## Current TOTP Model

The current implementation uses:

- RFC 6238-style TOTP codes
- 6-digit codes by default
- 30-second time steps
- a configurable skew window, defaulting to 1 step

The verifier supports a real shared-secret backend rather than a test-only
stub.

## Current Secret Store Boundary

The current TOTP secret store is file-backed and rooted under:

- `OSMAP_TOTP_SECRET_DIR`

By default this resolves under the state root:

- `/var/lib/osmap/secrets/totp`

That keeps secret material:

- outside the repository
- outside committed config examples
- inside a bounded runtime directory that later deployment and confinement work
  can permission explicitly

## Secret File Model

The current store uses:

- one file per canonical username
- a hex-encoded filename derived from the canonical username
- a `.totp` extension
- a small text format using `secret=<base32-value>`

Example file contents:

```text
# alice@example.com
secret=JBSWY3DPEHPK3PXP
```

The file format is intentionally small so operators can inspect it easily and
future migration is straightforward.

## Why File-Backed First

The current phase does not need a database-backed secret system yet.

A file-backed model is acceptable for this slice because it:

- keeps the dependency graph small
- is easy to reason about on OpenBSD
- aligns with the current single-host, small-team operating model
- gives later `unveil(2)` and permission work a concrete filesystem target

If this becomes operationally insufficient later, it should be replaced
deliberately rather than expanded ad hoc.

## Secret Handling Rules

The current model assumes:

- TOTP secrets are provisioned by an operator-controlled process
- the committed example configuration remains non-secret
- secret files are not world-readable
- secret files are not placed under repo-managed paths
- the runtime only needs read access to the secret directory

## Current Validation State

The TOTP implementation is currently validated through:

- local unit tests using RFC-compatible reference vectors
- a real verifier implementation backed by a secret-store abstraction

Broader OpenBSD QEMU validation should remain the next preferred step before
more auth-path expansion.

## What Is Still Missing

The current TOTP slice does not yet include:

- enrollment workflows
- secret rotation workflows
- backup and recovery handling for enrolled factors
- operator tooling for secret provisioning
- persistent rate limiting around factor failures

Those belong to later WP3/WP4 work rather than this backend foundation slice.
