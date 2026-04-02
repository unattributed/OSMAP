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
- `OSMAP_DOVEADM_USERDB_SOCKET_PATH`
- `OSMAP_MAILBOX_HELPER_SOCKET_PATH`
- `OSMAP_STATE_DIR`
- `OSMAP_RUNTIME_DIR`
- `OSMAP_SESSION_DIR`
- `OSMAP_SETTINGS_DIR`
- `OSMAP_AUDIT_DIR`
- `OSMAP_CACHE_DIR`
- `OSMAP_TOTP_SECRET_DIR`
- `OSMAP_LOG_LEVEL`
- `OSMAP_LOG_FORMAT`
- `OSMAP_SESSION_LIFETIME_SECS`
- `OSMAP_TOTP_ALLOWED_SKEW_STEPS`
- `OSMAP_LOGIN_THROTTLE_MAX_FAILURES`
- `OSMAP_LOGIN_THROTTLE_REMOTE_MAX_FAILURES`
- `OSMAP_LOGIN_THROTTLE_WINDOW_SECS`
- `OSMAP_LOGIN_THROTTLE_LOCKOUT_SECS`
- `OSMAP_SUBMISSION_THROTTLE_MAX_SUBMISSIONS`
- `OSMAP_SUBMISSION_THROTTLE_REMOTE_MAX_SUBMISSIONS`
- `OSMAP_SUBMISSION_THROTTLE_WINDOW_SECS`
- `OSMAP_SUBMISSION_THROTTLE_LOCKOUT_SECS`
- `OSMAP_OPENBSD_CONFINEMENT_MODE`

The committed example file under `config/osmap.env.example` is intentionally
non-secret.

The runtime now uses `OSMAP_RUN_MODE` to separate:

- fast bootstrap validation
- actual HTTP serving
- local mailbox-helper serving

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

The runtime now also recognizes an optional
`OSMAP_DOVEADM_USERDB_SOCKET_PATH` setting for deployments that want OSMAP to
use an explicitly chosen Dovecot userdb socket for mailbox and message helper
lookups instead of relying on a broader default surface.

The runtime now also recognizes an optional
`OSMAP_MAILBOX_HELPER_SOCKET_PATH` setting for the first local mailbox-helper
boundary. When the web runtime is configured with this socket, mailbox listing
is proxied through the helper instead of being executed directly from the
browser-facing process. When `OSMAP_RUN_MODE=mailbox-helper` is selected and the
variable is absent, the helper defaults to
`<runtime_dir>/mailbox-helper.sock`.

The runtime now also recognizes explicit login-throttle settings for the
browser authentication path:

- `OSMAP_LOGIN_THROTTLE_MAX_FAILURES`
- `OSMAP_LOGIN_THROTTLE_REMOTE_MAX_FAILURES`
- `OSMAP_LOGIN_THROTTLE_WINDOW_SECS`
- `OSMAP_LOGIN_THROTTLE_LOCKOUT_SECS`

Those settings control the current file-backed application-layer throttling
model under the existing cache boundary:

- a tighter credential-plus-remote bucket
- a higher-threshold remote-only bucket

The runtime now also recognizes explicit submission-throttle settings for the
browser send path:

- `OSMAP_SUBMISSION_THROTTLE_MAX_SUBMISSIONS`
- `OSMAP_SUBMISSION_THROTTLE_REMOTE_MAX_SUBMISSIONS`
- `OSMAP_SUBMISSION_THROTTLE_WINDOW_SECS`
- `OSMAP_SUBMISSION_THROTTLE_LOCKOUT_SECS`

Those settings control the current file-backed application-layer throttling
model for accepted outbound submissions under the existing cache boundary:

- a tighter canonical-user-plus-remote bucket
- a higher-threshold remote-only bucket

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
- user settings state
- audit-oriented local state
- cache data
- TOTP secret files
- login-throttle state under the cache tree
- submission-throttle state under the cache tree

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
- the optional `OSMAP_DOVEADM_USERDB_SOCKET_PATH`, when present, must be an
  absolute path
- the optional `OSMAP_MAILBOX_HELPER_SOCKET_PATH`, when present, must be an
  absolute path
- configured state paths must be absolute
- derived mutable-state paths must stay under the state root
- development listeners must remain on loopback
- session lifetime must parse as a positive unsigned integer
- TOTP skew-step configuration must parse as a signed integer
- login-throttle threshold, window, and lockout settings must parse as positive
  unsigned integers
- submission-throttle threshold, window, and lockout settings must parse as
  positive unsigned integers
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

## Least-Privilege Dovecot Socket Configuration

The optional Dovecot socket settings exist to support a narrow host integration
pattern:

- the OSMAP runtime remains unprivileged
- the host exposes a dedicated Dovecot auth listener for that runtime user
- the host can also expose a dedicated Dovecot userdb listener for mailbox and
  message helper lookups
- OSMAP points `doveadm auth test` and mailbox/message helper calls at those
  explicit listeners instead of depending on broader or privileged socket
  arrangements

This is an operator-side deployment refinement, not a secret. It is safe to
include in startup reporting and confinement planning.

The current validated example on `mail.blackbagsecurity.com` is:

- `OSMAP_DOVEADM_AUTH_SOCKET_PATH=/var/run/osmap-auth`
- `OSMAP_DOVEADM_USERDB_SOCKET_PATH=/var/run/osmap-userdb`

with `_osmap` using the auth listener and the `vmail` mailbox helper using the
userdb listener.

Live host validation now shows that positive browser auth works through the
dedicated `_osmap` auth listener, while helper-backed mailbox listing,
message-list retrieval, message view, and attachment download work through the
dedicated `vmail` userdb listener.

## Mailbox Helper Socket Configuration

The runtime now also has a first mailbox-helper boundary:

- the web-facing runtime can use `OSMAP_MAILBOX_HELPER_SOCKET_PATH` to proxy
  mailbox listing through a local helper
- `OSMAP_RUN_MODE=mailbox-helper` starts that helper instead of the HTTP
  listener
- the helper binds the configured Unix-domain socket, or defaults to
  `<runtime_dir>/mailbox-helper.sock` when the run mode is `mailbox-helper`

This slice currently applies to mailbox listing, message-list retrieval, and
message-view retrieval. Attachment download now reuses the helper-backed
message-view path when configured, while MIME-part decoding remains in the
browser-facing runtime for now.

## User Settings State

The runtime now also includes a first bounded user-settings surface under:

- `OSMAP_SETTINGS_DIR`

That state currently stores one persisted per-user preference:

- `html_display_preference`

The current file-backed store:

- keeps one settings file per canonical username
- derives the filename from a SHA-256 hash of the canonical username with a
  stable domain-separation prefix
- writes line-oriented content with atomic replacement semantics
- uses `0600` permissions on Unix-like systems

This keeps the first end-user settings slice inside the same explicit state
boundary as sessions, audit files, TOTP secrets, and throttle state rather
than introducing a separate browser-local or database-local preference store.
