# Configuration And State Model

## Purpose

This document records the WP1 configuration and state boundary for the early
OSMAP proof of concept.

The main objective is to keep code, committed examples, mutable runtime state,
and future secret material clearly separated from the start.

## Configuration Source Model

The current prototype reads runtime configuration from process environment
variables.

That choice is deliberate for the early slice because it:

- avoids inventing a custom config parser too early
- keeps operator-visible settings explicit
- works cleanly with service managers and staged deployment scripts
- does not require storing secrets in the repository

## Current Configuration Fields

The early runtime recognizes:

- `OSMAP_RUN_MODE`
- `OSMAP_ENV`
- `OSMAP_LISTEN_ADDR`
- `OSMAP_DOVEADM_AUTH_SOCKET_PATH`
- `OSMAP_STATE_DIR`
- `OSMAP_RUNTIME_DIR`
- `OSMAP_SESSION_DIR`
- `OSMAP_AUDIT_DIR`
- `OSMAP_CACHE_DIR`
- `OSMAP_TOTP_SECRET_DIR`
- `OSMAP_LOG_LEVEL`
- `OSMAP_LOG_FORMAT`
- `OSMAP_SESSION_LIFETIME_SECS`
- `OSMAP_TOTP_ALLOWED_SKEW_STEPS`
- `OSMAP_OPENBSD_CONFINEMENT_MODE`

The committed example file under `config/osmap.env.example` is intentionally
non-secret.

The runtime now uses `OSMAP_RUN_MODE` to separate:

- fast bootstrap validation
- actual HTTP serving

That lets operators and tests exercise startup checks without always launching
the listener.

The runtime now also uses `OSMAP_OPENBSD_CONFINEMENT_MODE` to separate:

- no OpenBSD-specific runtime confinement
- plan-only OpenBSD confinement logging
- enforced OpenBSD confinement during serve mode

The runtime now also recognizes an optional
`OSMAP_DOVEADM_AUTH_SOCKET_PATH` setting for deployments that want OSMAP to use
an explicitly chosen Dovecot auth socket rather than the default helper
behavior.

## Environment Model

The current runtime supports three explicit environments:

- `development`
- `staging`
- `production`

Development is treated conservatively. The bootstrap currently requires the
development listener to remain loopback-bound so early local testing does not
normalize broad exposure.

## State Boundary

Mutable state is rooted at one explicit absolute directory:

- `OSMAP_STATE_DIR`

Subdirectories are then resolved beneath that root for:

- runtime files
- session state
- audit-oriented local state
- cache data
- TOTP secret files

This model keeps the future OpenBSD deployment story easier to reason about,
because state can later be owned, permissioned, unveiled, and backed up as one
coherent boundary.

## Separation Rules

The current state model is designed around these rules:

- code does not live under the mutable state root
- committed configuration examples do not contain secrets
- mutable runtime data stays inside the configured state root
- operators can override state subpaths, but they must remain under the state
  root

These rules reduce the chance of ad hoc sprawl before the service becomes more
complex.

## Validation Rules

The bootstrap currently enforces:

- run mode values must be recognized explicitly
- required fields must not be empty
- environment values must be recognized explicitly
- the optional `OSMAP_DOVEADM_AUTH_SOCKET_PATH`, when present, must be an
  absolute path
- configured state paths must be absolute
- derived mutable-state paths must stay under the state root
- development listeners must remain on loopback
- session lifetime must parse as a positive unsigned integer
- TOTP skew-step configuration must parse as a signed integer
- OpenBSD confinement mode must be one of the explicitly recognized values

These validations are intentionally strict because the project should fail
clearly when runtime assumptions drift.

## Secret Handling Posture

This slice does not yet introduce live secret values. That is also deliberate.

The current posture is:

- secret-bearing configuration stays out of the repository
- examples remain safe to publish
- future secret material should be injected through operator-managed runtime
  mechanisms, not hardcoded files under version control

## Why This Is Enough For Now

WP1 is not trying to solve the final production configuration story. It is
trying to ensure that later authentication, session, and mail-integration work
lands on a disciplined runtime boundary instead of on a pile of ad hoc settings.

That remains true now that the first browser-serving mode exists as well.

## Least-Privilege Auth Socket Configuration

The optional `OSMAP_DOVEADM_AUTH_SOCKET_PATH` exists to support a narrow host
integration pattern:

- the OSMAP runtime remains unprivileged
- the host exposes a dedicated Dovecot auth listener for that runtime user
- OSMAP points `doveadm auth test` at that explicit listener instead of
  depending on a broader or privileged socket arrangement

This is an operator-side deployment refinement, not a secret. It is safe to
include in startup reporting and confinement planning.
