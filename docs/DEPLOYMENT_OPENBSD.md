# Deployment OpenBSD

## Purpose

This document records the OpenBSD deployment direction for OSMAP. It is still
pre-implementation, but the hosting strategy is clear enough to define now.

## Target Environment

OSMAP is intended for deployment on OpenBSD in an environment that already uses
OpenBSD-native operational tooling and a conservative mail-stack layout.

The deployment model should assume:

- OpenBSD is the primary supported operating system
- the existing mail stack remains authoritative
- an OpenBSD-friendly edge layer such as nginx remains part of the environment
- the application may initially coexist with the current VPN-first access model

## Current Prototype Deployment Shape

The current implemented prototype is small enough to describe concretely:

- `nginx` remains the public-facing TLS edge
- OSMAP serves HTTP on a local TCP listener
- development mode requires a loopback listener
- staging or production should also prefer loopback-only exposure behind nginx
- Dovecot remains authoritative for auth and mailbox reads
- the local sendmail compatibility surface remains authoritative for outbound
  submission handoff

At the current implementation stage, a local TCP listener is the truthful
deployment target. Unix sockets remain a possible later refinement, but they
are not yet part of the running code path.

## Filesystem Layout

The deployment should use a layout that is:

- predictable
- minimally writable
- understandable to operators
- compatible with privilege separation and restricted filesystem visibility

Application runtime state, logs, secrets, and static assets should be separated
deliberately rather than mixed into a broad writable tree.

Current OSMAP state boundaries already map to:

- `run`
- `sessions`
- `audit`
- `cache`
- `secrets/totp`

This is a useful starting point for OpenBSD file ownership and confinement work.
The current confinement plan now also treats the top-level state root as a
read-only anchor and keeps only the explicit mutable child directories
writable.

## Service Accounts

The runtime should avoid unnecessary root privileges.

Expectations:

- dedicated service accounts where practical
- no root-owned long-running app processes unless strictly required
- separation of roles between edge, app, and supporting service contexts where
  the architecture allows

## Permission Model

The deployment should make it easy to answer:

- which process can read secrets
- which process can reach mail backends
- which directories are writable
- which network paths are required

This should align with OpenBSD-native least-privilege design and make
`pledge(2)` and `unveil(2)` adoption feasible where appropriate.

## Reverse Proxy Configuration

The edge layer should:

- terminate TLS cleanly
- forward only the minimum required headers and paths
- avoid exposing unused routes
- support staged deployment behind the existing VPN-first model
- proxy to the application service over loopback rather than exposing the app
  service directly

The web edge should not become a dumping ground for unrelated convenience
features.

Useful first reverse-proxy expectations now include:

- pass `Host`
- pass `X-Real-IP`
- pass `X-Forwarded-For`
- pass `X-Forwarded-Proto`
- restrict methods to `GET` and `POST` for the current slice
- keep buffering and auxiliary edge behavior conservative until needed

## Logging Integration

Deployment should provide logs that operators can actually use to investigate:

- authentication failures
- suspicious session activity
- submission abuse
- unexpected app behavior

Logs should be easy to retain, review, and correlate with surrounding host
events.

## Backup Integration

The deployment model should clearly identify:

- what must be backed up
- what must not be treated as authoritative state
- how secrets and configuration are protected
- how rollback would be performed if deployment fails

## Upgrade Strategy

A credible OpenBSD deployment strategy should support:

- predictable upgrade steps
- rollback awareness
- minimal assumptions about orchestration complexity
- packaging and service-management approaches that feel native to OpenBSD

## Hosting Strategy

The default hosting strategy should remain conservative:

- favor simple single-host or small-footprint deployments first
- preserve the existing VPN-first option until broader exposure is justified
- keep the runtime and dependency model small enough that an operator can
  understand it end to end

Preferred Phase 4 baseline:

- nginx on the host edge
- one small OSMAP application service behind nginx
- existing Dovecot and Postfix services left authoritative
- minimal app-local state stored separately from static assets and secrets

Current prototype-specific deployment guidance:

- keep OSMAP on `127.0.0.1:<port>` behind nginx
- keep OSMAP under dedicated service users that match the current runtime split
- keep the state tree owned narrowly enough that later `unveil(2)` policy can
  be practical
- keep `doveadm` and `sendmail` execution paths explicit and reviewable
- prefer a dedicated Dovecot auth listener for the OSMAP runtime user rather
  than a privileged or broad auth-socket arrangement
- use `OSMAP_DOVEADM_AUTH_SOCKET_PATH` when the host provides that dedicated
  auth listener
- use `OSMAP_DOVEADM_USERDB_SOCKET_PATH` when the host provides a dedicated
  userdb listener for mailbox and message helpers
- mailbox-helper startup now also depends on
  `OSMAP_DOVEADM_AUTH_SOCKET_PATH` so the helper can derive the one trusted
  local caller UID from the auth-socket owner before accepting mailbox
  requests
- the current validated host shape on `mail.blackbagsecurity.com` uses
  `_osmap` plus `/var/run/osmap-auth` for browser auth and `vmail` plus
  `/var/run/osmap-userdb` for mailbox-helper lookups
- use `OSMAP_OPENBSD_CONFINEMENT_MODE=log-only` or `enforce` when validating
  the OpenBSD serve runtime on hosts intended for real deployment

Current live validation on `mail.blackbagsecurity.com` now proves:

- positive browser login plus TOTP-backed session issuance under `_osmap`
- a working least-privilege auth-socket arrangement under `enforce`
- helper-backed mailbox listing, message-list retrieval, message view, and
  attachment download under `enforce` with the web runtime kept as `_osmap`
  and the mailbox helper running at the `vmail` boundary

The selected next-step deployment answer is therefore:

- keep the web-facing OSMAP runtime as `_osmap`
- introduce a dedicated local-only mailbox-read helper boundary
- let that helper hold the mailbox-read identity the host currently requires
- expose the helper over a narrowly permissioned Unix socket instead of
  widening the web-facing runtime

The first implementation slices of that answer now exist:

- `OSMAP_RUN_MODE=mailbox-helper` starts the local helper
- `OSMAP_MAILBOX_HELPER_SOCKET_PATH` selects the Unix socket path used by the
  helper and by the web runtime
- production `OSMAP_RUN_MODE=serve` now rejects configs that do not set
  `OSMAP_MAILBOX_HELPER_SOCKET_PATH`
- mailbox listing, message-list retrieval, and message-view retrieval can now
  route through that helper
- attachment download now uses a dedicated helper-side attachment operation
  when the helper socket is configured
- helper-specific confinement now exists in code and has live-host proof under
  the actual `vmail` boundary
- the repository now carries
  `maint/live/osmap-live-validate-helper-peer-auth.ksh` to prove the helper
  accepts trusted `_osmap` callers and rejects unrelated local callers even
  when the isolated helper socket permissions are widened during validation
- the helper-side confinement view on the validated host now narrows
  `doveadm` support paths to explicit `doveconf`, loader, Dovecot config, and
  Dovecot config-socket paths plus exact resolved shared-library files where
  the host exposes them
- the browser-facing `_osmap` runtime now narrows its auth-backed `doveadm`
  and local sendmail/Postfix dependency view too, down to explicit mailwrapper,
  sendmail, `postdrop`, Postfix config, and exact resolved shared-library
  paths where the validated host exposes them
- the repository now carries `maint/live/osmap-live-validate-login-send.ksh`
  to prove real password-plus-TOTP login plus one real browser send through
  that split-runtime enforced deployment posture
- the repository now also carries
  `maint/live/osmap-live-validate-v1-closeout.ksh` so operators can run the
  current repo-owned Version 1 proof set through one wrapper while still
  supplying mailbox secrets only through environment variables at runtime, and
  can optionally emit a small step-summary report for review records
- the repository now also carries
  `maint/live/osmap-run-v1-closeout-over-ssh.sh` so a workstation that can
  actually reach `mail.blackbagsecurity.com` can trigger that same host-side
  closeout wrapper and pull the resulting report back locally

For the short operator SOP that ties the standard `~/OSMAP` rerun path, the
repo-owned helper for the temporary validation-password override, and the
expected closeout report shape together in one place, see
`docs/V1_CLOSEOUT_SOP.md`.

The repository now also carries first operator scaffolding for that split under
`maint/openbsd/`:

- `osmap-serve.env.example` for the `_osmap` browser-facing runtime
- `osmap-mailbox-helper.env.example` for the `vmail` mailbox-helper runtime
- `libexec/` launcher examples that source those env files and execute one
  explicit OSMAP CLI run mode
- `rc.d/` example scripts for `osmap_serve` and `osmap_mailbox_helper`
- `README.md` with socket-permission and startup-order guidance for the current
  helper boundary

That does not claim that packaging or `rc.d` integration is final. It does make
the current `_osmap` plus `vmail` deployment shape concrete enough to review,
stage, and hand to operators without inventing the service split from scratch.

This is more likely to produce a system that OpenBSD operators, and eventually
potential downstream packagers, would consider credible.
