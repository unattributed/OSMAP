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

- `OSMAP_ENV`
- `OSMAP_LISTEN_ADDR`
- `OSMAP_STATE_DIR`
- `OSMAP_RUNTIME_DIR`
- `OSMAP_SESSION_DIR`
- `OSMAP_AUDIT_DIR`
- `OSMAP_CACHE_DIR`
- `OSMAP_TOTP_SECRET_DIR`
- `OSMAP_LOG_LEVEL`
- `OSMAP_LOG_FORMAT`
- `OSMAP_TOTP_ALLOWED_SKEW_STEPS`

The committed example file under `config/osmap.env.example` is intentionally
non-secret.

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

- required fields must not be empty
- environment values must be recognized explicitly
- configured state paths must be absolute
- derived mutable-state paths must stay under the state root
- development listeners must remain on loopback
- TOTP skew-step configuration must parse as a signed integer

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
