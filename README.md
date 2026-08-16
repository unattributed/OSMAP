# OSMAP

**OpenBSD Secure Mail Access Platform** is a small, security-focused webmail
application for hardened OpenBSD mail hosts.

OSMAP gives users browser access to an existing mail system without replacing
nginx, Dovecot, Postfix, Rspamd, PF, TLS, or native mail clients. It is written
in Rust, renders its interface on the server, uses no runtime JavaScript, and
keeps privileged mailbox access behind a local helper boundary.

The project deliberately favors a narrow attack surface, least privilege,
bounded resource use, safe message rendering, and reversible operations over
feature breadth or complete Roundcube parity.

## What OSMAP provides

- password-and-TOTP login, bounded sessions, logout, and session revocation;
- mailbox and message browsing, bounded search, reply, forward, drafts,
  attachments, local submission, and basic folder operations;
- plain-text fallback and allowlist-sanitized HTML with remote content blocked;
- CSRF, same-origin, Host, request parsing, throttling, and worker-budget
  controls;
- a server-rendered, responsive, keyboard-accessible interface with no
  frontend framework or external asset dependency;
- a split OpenBSD runtime: an unprivileged web process and a narrowly scoped
  mailbox helper connected by a permissioned Unix socket; and
- repository-owned security, regression, deployment, rollback, and evidence
  gates.

OSMAP is a webmail access layer, not a mail server. It does not replace the
existing transport, mailbox, filtering, or TLS services.

## Architecture

```text
Browser
   |
   v
nginx TLS edge
   |
   v
OSMAP web service (loopback, unprivileged)
   |                    |
   | Unix socket        | local submission
   v                    v
mailbox helper       Postfix / sendmail
   |
   v
Dovecot and existing mail storage
```

The public network boundary ends at nginx. Production `serve` mode is
loopback-only, and mailbox authority stays outside the browser-facing process.
See the [architecture](docs/ARCHITECTURE.md) and
[security model](docs/SECURITY_MODEL.md) for the complete trust boundaries.

## Project status

OSMAP is actively developed and security-sensitive. The crate is currently
version `0.1.0`. The repository contains production-validated and deployed
slices, but those results are bounded to the documented OpenBSD host,
configuration, test corpus, and selected user cohort. Treat OSMAP as
operator-integrated software, not a turnkey general-availability release.

| Milestone | Brief status |
|---|---|
| V13 | Reviewed production deployment, credentialed WSTG assurance, and adversarial validation closeout |
| V14 | Authenticated WebUI modernization, accessibility, and OpenPGP state UX; no JavaScript or runtime cryptography added |
| V15 | Deployed HTTP edge/origin parser assurance; the fixed 37-case offline and live corpus passed with no policy or request-cardinality failures |

The [current project status](docs/CURRENT_PROJECT_STATUS.md) and latest
[V15 assurance record](docs/V15_HTTP_DIFFERENTIAL_ASSURANCE.md) contain the
precise evidence and claim boundaries. Historical version documents remain
useful as provenance, not as competing statements of current status.

Important limits:

- the current release evidence is still bounded;
- complete Roundcube replacement, general hostile-email safety, universal
  production readiness, and full ASVS verification are not claimed;
- OpenPGP policy, diagnostics, helper scaffolding, and UI states exist, but
  runtime decrypt, verify, sign, encrypt, PGP/MIME, and key-management
  operations are not implemented; and
- calendars, groupware, plugins, SaaS hosting, multi-tenancy, and attachment
  preview are outside the current scope.

Read [known limitations](docs/KNOWN_LIMITATIONS.md) before evaluating or
deploying the project.

## Get started

The reviewed toolchain is pinned in `rust-toolchain.toml`. With Rust and the
native build prerequisites installed:

```sh
git clone https://github.com/unattributed/OSMAP.git
cd OSMAP

cargo build
cargo test
make security-check
```

To validate the default development configuration without starting a service:

```sh
OSMAP_STATE_DIR=/tmp/osmap cargo run -- bootstrap
```

To preview the local browser surface:

```sh
OSMAP_STATE_DIR=/tmp/osmap cargo run -- serve
```

This listens on `127.0.0.1:8080` by default. The login page is available
locally, but real authentication and mailbox workflows require the Dovecot,
helper, state, and submission integration described in the deployment docs.
Do not expose the development listener directly to a network.

On Debian-family development systems, the repository can install and verify
its reviewed workstation prerequisites:

```sh
bash maint/development/bootstrap-debian.sh
make verify-debian
```

The bootstrap uses `sudo` for APT operations. Review the
[Debian development bootstrap](docs/DEBIAN_DEVELOPMENT_BOOTSTRAP.md) before
running it.

## Run modes and configuration

OSMAP is configured through environment variables; the complete documented
baseline is in [`config/osmap.env.example`](config/osmap.env.example).

| Command | Purpose |
|---|---|
| `osmap bootstrap` | Validate configuration, report non-secret runtime settings, and exit |
| `osmap serve` | Run the loopback HTTP and browser service |
| `osmap mailbox-helper` | Run the local privileged mailbox helper |

Production uses separate environment files and service accounts for `serve`
and `mailbox-helper`. Start the helper first, keep the HTTP service on loopback,
and place nginx at the TLS edge.

## Deploy on OpenBSD

OSMAP is not a single-command deployment. It integrates with security-sensitive
host services and must be installed with explicit users, paths, socket
permissions, Dovecot listeners, nginx policy, logging, validation, and rollback.

Start with:

- [OpenBSD deployment guide](docs/DEPLOYMENT_OPENBSD.md)
- [OpenBSD service examples](maint/openbsd/README.md)
- [Hardening guide](docs/HARDENING_GUIDE.md)
- [Build and release process](docs/BUILD_AND_RELEASE_PROCESS.md)
- [Internet exposure checklist](docs/INTERNET_EXPOSURE_CHECKLIST.md)

## Development and validation

Use `make security-check` as the normal developer and CI gate. A broader local
run is available through `make acceptance-check` and `make v14-check`.

The strict release gate is evidence-dependent:

```sh
OSMAP_SECURITY_PROFILE=release make release-check
```

It intentionally fails closed when required live-host, authenticated WSTG,
TLS, supply-chain, resource-control, or sanitized evidence is missing or stale.
A local source check is not a release claim.

See [CONTRIBUTING.md](CONTRIBUTING.md), the
[test strategy](docs/TEST_STRATEGY.md), and the
[documentation index](docs/README.md) to contribute.

## Security, support, and license

Report suspected vulnerabilities privately through
[SECURITY.md](SECURITY.md), not a public issue. General support guidance is in
[SUPPORT.md](SUPPORT.md), and community expectations are in
[CODE_OF_CONDUCT.md](CODE_OF_CONDUCT.md).

OSMAP is distributed under the [ISC License](LICENSE), without warranty.
Operators remain responsible for deployment, configuration, monitoring,
backup, recovery, legal compliance, and risk acceptance.
