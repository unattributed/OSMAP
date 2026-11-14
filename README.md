# OSMAP

**OpenBSD Secure Mail Access Platform** is a security-focused webmail application
for administrators who run their own OpenBSD mail infrastructure. It provides
browser access to existing mailboxes through a Rust application, a server-rendered
interface, and narrowly scoped local helpers.

OSMAP integrates with Dovecot, Postfix, nginx, and the host's existing account and
mail storage configuration. Those services remain authoritative for mail delivery,
authentication, and storage. The design prioritizes least privilege, bounded work,
safe message rendering, and recoverable operations.

[Getting started](#getting-started) · [Installation](#openbsd-installation) ·
[Operations](#operations-and-monitoring) · [Development](#development) ·
[Decision history](docs/DECISION_LOG.md)

## Capabilities

The current source includes:

- **Mail:** mailbox browsing, account-wide search, conversation views, reply and
  forward, attachments, drafts and autosave, Sent copies, scheduled sending, and
  an Outbox with recovery controls for unsent messages.
- **Organization:** folders, Archive, Bin/Trash and Junk, message moves, labels,
  snooze, account storage reporting, and notifications.
- **Account and interface:** password-plus-TOTP login, session management,
  account preferences, light/dark/system appearance, responsive layouts,
  keyboard controls, and icon or text-label presentation.
- **OpenPGP:** public-key inventory and import, account/recipient bindings,
  contacts, signing and encryption, protected reading and downloads, and
  session-bound personal-key controls through native GPGME/GnuPG helpers.
- **Security boundaries:** CSRF and origin checks, strict HTTP/Host handling,
  authentication and submission throttles, worker budgets, sanitized message
  HTML, blocked remote content, and OpenBSD confinement.

## Project status

OSMAP is under active development; the crate version is `0.1.0`. It is
operator-integrated software, not a turnkey general-availability release.
The UX work was
promoted to `main` on 2026-11-12. Installed and owner-accepted journeys exist on
the documented OpenBSD hosts, but independent-host installation, broader account
enrollment, and whole-application security/release qualification remain open.
The 2026-11-13 Toronto recovery-contact acceptance covers one selected account;
it does not enable every account-management operation for all users.

Feature availability depends on the installed helpers, account enrollment, keys,
and configuration. Consult [current project status](docs/CURRENT_PROJECT_STATUS.md)
and the linked slice records for exact acceptance scope. The
[known limitations](docs/KNOWN_LIMITATIONS.md) and
[security model](docs/SECURITY_MODEL.md) describe the wider constraints. Historical
V1–V15 records describe their assessed versions; later UX records cover the
subsequent runtime OpenPGP and mail workflows.

The release history includes these bounded assurance milestones:

| Milestone | Assessed scope | Record |
| --- | --- | --- |
| V13 | Reviewed production deployment, credentialed WSTG assurance, and adversarial validation closeout | [V13 assurance](docs/V13_WSTG_ASSURANCE_INTEGRITY_AND_ADVERSARIAL_VALIDATION.md) |
| V14 | Authenticated WebUI modernization, accessibility, and OpenPGP state UX | [V14 UX](docs/V14_STREAMLINE_WEBUI_OPENPGP_UX.md) |
| V15 | Deployed HTTP edge/origin parser assurance | [V15 HTTP assurance](docs/V15_HTTP_DIFFERENTIAL_ASSURANCE.md) |

Across these records, the current release evidence is still bounded;
complete Roundcube replacement, general hostile-email safety, universal
production readiness, and full ASVS verification are not claimed. The later
runtime decrypt, verify, sign, encrypt, PGP/MIME, and key-management
capabilities retain their individual configuration and acceptance boundaries.

## Architecture

```text
Browser ── HTTPS ── nginx ── loopback HTTP ── OSMAP Web (_osmap)
                                               │
                                  authenticated local Unix sockets
                                               │
                     ┌─────────────────────────┼────────────────────────┐
                     ▼                         ▼                        ▼
              Mailbox helper            Account services         OpenPGP helpers
                 (vmail)                  (configured)             (_osmapgpg)
                     │                         │                        │
              Dovecot / mail store      Account/epoch state       GPGME / GnuPG

OSMAP Web ── local sendmail → Postfix → delivery
```

The Web service binds to loopback in production. The mailbox helper authenticates
the local peer and authenticated request grants; the Web identity does not need direct mailbox
ownership. Account and OpenPGP services have separate grants and configuration.
A deployment may use the documented restricted backend bridge when mail storage
is on another host. See [architecture](docs/ARCHITECTURE.md),
[mailbox helper](docs/MAILBOX_READ_HELPER_MODEL.md), and
[backend integration](maint/mail-backend/) for the boundaries and topology.

## Getting started

Use the toolchain in [`rust-toolchain.toml`](rust-toolchain.toml). The Rust language
minimum is declared separately in [`Cargo.toml`](Cargo.toml). OpenBSD is the
runtime target; Debian-family Linux is also used for development.

```sh
git clone https://github.com/unattributed/OSMAP.git
cd OSMAP
cargo build --locked --bin osmap
```

On a Debian-family workstation, the repository supplies a package/toolchain
bootstrap and read-only verifier:

```sh
bash maint/development/bootstrap-debian.sh
make verify-debian
```

Review the [workstation guide](docs/DEBIAN_DEVELOPMENT_BOOTSTRAP.md) first; the
bootstrap uses `sudo` for package installation.

For an isolated local configuration check and login-page preview:

```sh
umask 077
export OSMAP_ENV=development
export OSMAP_STATE_DIR="$(mktemp -d /tmp/osmap-preview.XXXXXXXX)"
export OSMAP_LISTEN_ADDR=127.0.0.1:8080
export OSMAP_ALLOWED_HOSTS=localhost:8080,127.0.0.1:8080
cargo run --locked --bin osmap -- bootstrap
cargo run --locked --bin osmap -- serve
```

Open `http://127.0.0.1:8080/login`; stop the process with Ctrl-C. This preview
provides no test mailbox or default login. Authentication and mail operations
require the Dovecot, TOTP, helper, and submission integration below.

## OpenBSD installation

Installation currently requires administrator integration. There is no qualified
general-purpose installer. The procedures below describe the existing host
layout; adapt paths, identities, hostname, and backend topology before use on
another host.

### Prerequisites and configuration

Provide a working Dovecot/Postfix mail system, nginx with a valid TLS certificate,
the reviewed Rust toolchain, `ksh`, `doas`, and dedicated service identities.
The baseline uses `_osmap` for Web, `vmail` for the mailbox helper, and `osmaprt`
for socket traversal. Discover the actual Web UID with `id -u _osmap`; replace
example numeric UIDs with the observed value.

Prepare separate Web and helper environment files from
[`maint/openbsd/`](maint/openbsd/README.md). The
[configuration example](config/osmap.env.example) documents the baseline;
[`src/config.rs`](src/config.rs) defines validation and optional service settings.

| Setting or resource | Required integration |
| --- | --- |
| `OSMAP_ENV`, `OSMAP_LISTEN_ADDR` | `production`, with a loopback listener such as `127.0.0.1:8080` |
| `OSMAP_ALLOWED_HOSTS` | The browser-facing hostname, matching nginx and origin policy |
| Dovecot listeners | Dedicated auth and userdb sockets; set `OSMAP_DOVEADM_AUTH_SOCKET_PATH` and helper `OSMAP_DOVEADM_USERDB_SOCKET_PATH` |
| Trusted Web peer | Helper `OSMAP_TRUSTED_WEB_RUNTIME_UID` matches `_osmap` and the auth-socket owner |
| Helper socket | Both services use the same `OSMAP_MAILBOX_HELPER_SOCKET_PATH`; restrict traversal and socket access to their runtime identities |
| Helper grants | At least 32 random bytes, identical in separate service-readable `0600` files; configure each service's own `OSMAP_MAILBOX_HELPER_GRANT_KEY_PATH` |
| State and secrets | Separate Web/helper roots, private TOTP/key directories, and Web sessions `0700` for guarded account/key actions |
| Confinement | `OSMAP_OPENBSD_CONFINEMENT_MODE=enforce` for the qualified OpenBSD runtime |

The generic Web example points at the helper's grant path: change it to a
Web-owned copy, such as `/var/lib/osmap/secrets/mailbox-helper-grant.key`.
Keep the helper's copy under `/var/lib/osmap-helper/secrets/`. Grant files
must not be group-readable.

### Install and start the services

Use these procedures in order from a reviewed checkout on the target. Each
rehearsal prepares staged files, apply/restore scripts, and a session report.
The scripts carry host-specific settings; review the staged environment before
applying them.

| Step | Rehearsal command | Installation and rollback instructions |
| --- | --- | --- |
| 1. Build and stage `/usr/local/bin/osmap` | `ksh maint/live/osmap-live-rehearse-binary-deployment.ksh` | [Binary deployment](docs/MAIL_HOST_BINARY_DEPLOYMENT_SOP.md) |
| 2. Establish the socket group | `ksh maint/live/osmap-live-rehearse-runtime-group-provisioning.ksh` | [Runtime group](docs/MAIL_HOST_RUNTIME_GROUP_PROVISIONING_SOP.md) |
| 3. Stage env, launchers, rc scripts and logs | `ksh maint/live/osmap-live-rehearse-service-artifacts.ksh` | [Service artifacts](docs/MAIL_HOST_SERVICE_ARTIFACTS_SOP.md) |
| 4. Prepare state and start helper, then Web | `ksh maint/live/osmap-live-rehearse-service-activation.ksh` | [Service activation](docs/MAIL_HOST_SERVICE_ACTIVATION_SOP.md) |

For each step, review and adapt the staged files and generated scripts, then
execute that session's generated apply script. For example:

```sh
# Replace <session> with the directory printed by the rehearsal.
sh "$HOME/osmap-service-artifacts/<session>/scripts/apply-service-artifacts.sh"
```

Reinvoking the rehearsal wrapper with `--mode apply` regenerates staged files
from repository defaults; it does not preserve adaptations made only to staging.
These older wrappers install the baseline pair. They do not provision TOTP,
grant keys, account services, or OpenPGP. The activation wrapper also sets the
Web session directory to `0750`; reconcile it to the required `0700` before
testing guarded workflows. Preserve existing environment settings and secrets
during upgrades rather than replacing them with examples.

Once the configured pair is installed, the service commands are:

```sh
doas rcctl configtest osmap_mailbox_helper
doas rcctl configtest osmap_serve
doas rcctl start osmap_mailbox_helper
doas rcctl check osmap_mailbox_helper
doas rcctl start osmap_serve
doas rcctl check osmap_serve
ksh maint/live/osmap-live-validate-service-enablement.ksh
```

Configure nginx to proxy the HTTPS hostname to the loopback listener with matching
Host/origin policy. Read the [deployment guide](docs/DEPLOYMENT_OPENBSD.md) and
[internet exposure checklist](docs/INTERNET_EXPOSURE_CHECKLIST.md).
The [existing edge artifacts](maint/openbsd/mail.blackbagsecurity.com/README.md)
contain deployment-specific addresses and private control routes; adapt them
explicitly for a new host.

Enroll controlled accounts through the [TOTP provisioning procedure](docs/TOTP_OPERATOR_PROVISIONING_SOP.md).
Account operations require the separately configured [account runtime](maint/account-runtime/).
OpenPGP requires the [native preparation and key-custody procedure](maint/openpgp-runtime/deployment.md)
and later [personal-key workflow](docs/UX_SLICE_S07_04.md).
The [Toronto recovery-contact procedure](maint/openbsd/README.md#bounded-toronto-recovery-contact-activation)
covers a selected-account repair.

Before enabling OSMAP at boot with `rcctl enable`, verify the complete dependency
startup order and reboot behavior on that host. Account admission must be ready
before Web starts; an rc process check alone does not prove readiness.

## Operations and monitoring

Check both services and the actual browser entry path:

```sh
doas rcctl check osmap_mailbox_helper osmap_serve
OSMAP_LOGIN_HOST=mail.example.org \
  ksh maint/openbsd/libexec/osmap-login-availability.ksh --check-only
```

Replace `mail.example.org` with the configured hostname. The entry check expects
`GET /` to redirect to `/login` with `303`, and `GET /login` to return `200`.
Also check the public HTTPS URL to cover nginx and TLS. After deployment, verify
a controlled password-plus-TOTP login, mailbox read, and send/receipt journey.
An available login page does not prove backend authentication or mail delivery.

| Evidence | Default location or command |
| --- | --- |
| Web startup and application events | `/var/log/osmap/serve.log` |
| Mailbox-helper events | `/var/log/osmap/mailbox-helper.log` |
| Public edge access/errors | `/var/log/nginx/osmap.public.access.log`, `/var/log/nginx/osmap.public.error.log` |
| Runtime/socket/env checks | `ksh maint/live/osmap-live-validate-service-enablement.ksh` |
| Browser availability recovery | Installed `osmap-login-availability.ksh --recover`, under the documented bounded cron wrapper |

Review authentication failures, session activity, submission errors, backend
refusals, timeouts, and crash loops. Separate public OSMAP logs from private
administration logs, rotate them, and exclude credentials, message contents,
search terms, and one-use proofs from shared evidence. Metrics and alerting
expectations are in [observability and monitoring](docs/OBSERVABILITY_AND_MONITORING.md).

Back up configuration, TOTP and purpose keys, account epochs, settings, drafts,
and OpenPGP custody under appropriate access controls, alongside the mail
system's authoritative backups. Retain a matching binary/configuration rollback
set and state needed to recover pending operations. After an authorized Dovecot
configuration change, refresh the dependent account service before Web and
recheck signed admission and fresh login, as described in the
[service guidance](maint/openbsd/README.md#account-authority-after-dovecot-configuration-changes).
Use the [incident response plan](docs/INCIDENT_RESPONSE_PLAN.md) for failures.

## Development

| Path | Responsibility |
| --- | --- |
| `src/http*`, `src/http/`, `src/*_ui.rs` | HTTP parser, routes, Runtime composition, and server-rendered interface |
| `src/auth*`, `src/session*`, `src/account_*` | Authentication, sessions, account admission and guarded operations |
| `src/mailbox*`, `src/mime.rs`, `src/rendering*` | Mail backends/helper protocol, MIME processing and safe rendering |
| `src/send*`, `src/draft*`, `src/scheduled*` | Submission, persistence, scheduling and recovery |
| `src/openpgp*`, `src/protected*`, `src/bin/` | OpenPGP clients, policies, protected workflows and service binaries |
| `maint/openbsd/`, `maint/account-runtime/`, `maint/openpgp-runtime/` | OpenBSD service artifacts and native integrations |
| `maint/security/`, `maint/ux/`, `.github/workflows/` | Regression, security, acceptance and CI tooling |
| `docs/` | Architecture, decisions, operator procedures and scoped delivery evidence |

Use focused tests for changed behavior. The normal developer gate is:

```sh
make security-check
```

It covers Rust checks/tests, available Clippy/rustfmt, and repository security
guards. `make install-hooks` installs the shared commit/push hooks. Documentation
changes need content, link, and diff review; live and native qualification remain
separate. The evidence-dependent release gate is
`OSMAP_SECURITY_PROFILE=release make release-check`; missing live or authenticated
evidence prevents a release claim.

Read [CONTRIBUTING.md](CONTRIBUTING.md), [test strategy](docs/TEST_STRATEGY.md),
and [build/release process](docs/BUILD_AND_RELEASE_PROCESS.md) before submitting
changes. The [decision log](docs/DECISION_LOG.md) explains the design chronology;
the [documentation index](docs/README.md) links the detailed records.

## Security, support, and license

Report suspected vulnerabilities privately through [SECURITY.md](SECURITY.md).
Use [SUPPORT.md](SUPPORT.md) for support and
[CODE_OF_CONDUCT.md](CODE_OF_CONDUCT.md) for collaboration expectations.
OSMAP is licensed under the [ISC License](LICENSE).
