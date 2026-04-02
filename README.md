# OSMAP — OpenBSD Secure Mail Access Platform

OSMAP is a security-focused web mail access platform designed for OpenBSD systems.  
It replaces traditional webmail interfaces such as Roundcube with a restricted, maintainable, and internet-exposure-ready alternative.

The project prioritizes security, operational simplicity, and long-term maintainability over feature breadth.

---

## Project Goals

OSMAP aims to provide a safe browser-based interface to an existing mail system without altering the core mail transport infrastructure.

Key objectives:

- Replace Roundcube in hardened environments
- Operate safely when exposed to the public internet
- Minimize attack surface
- Enforce strong authentication
- Preserve compatibility with IMAP/SMTP backends
- Remain maintainable by a small operator team
- Use a clearly defined software supply chain
- Support reproducible builds and deployments

---

## Non-Goals (Version 1)

OSMAP intentionally avoids feature creep.

Out of scope for the initial release:

- Calendar and groupware features
- Mobile applications
- Plugin ecosystems
- Multi-tenant hosting
- SaaS deployment model
- Replacement of Postfix, Dovecot, or other core mail services
- ProtonMail-style zero-access encryption
- Enterprise identity federation

---

## Intended Environment

OSMAP is designed specifically for a self-hosted OpenBSD mail stack.

Typical deployment includes:

- OpenBSD operating system
- Postfix (SMTP and submission services)
- Dovecot (IMAP)
- Rspamd spam filtering
- MariaDB or compatible database
- nginx reverse proxy
- TLS-only access

Native mail clients such as Thunderbird remain supported and unchanged.

---

## Security Philosophy

Security is the primary design driver.

Principles include:

- Minimal exposed functionality
- Least privilege operation
- Explicit trust boundaries
- Defense in depth
- Observability and auditability
- Reversible deployments
- Supply chain awareness
- Maintainability over novelty

The project aligns with recognized guidance such as:

- OWASP Top 10
- CWE Top 25
- MITRE ATT&CK (defensive perspective)
- Applicable NIST cybersecurity guidance

---

## Why Replace Roundcube?

Traditional webmail platforms often prioritize features and extensibility over security minimalism.

OSMAP focuses on:

- Reduced complexity
- Tighter integration with hardened systems
- Clear operational model
- Explicit security assumptions
- Long-term sustainability

---

## Development Approach

The project follows a structured, phased methodology:

1. Charter and planning baseline
2. Current system analysis
3. Product definition
4. Security and trust model
5. Architecture design
6. Secure SDLC and release governance
7. Implementation planning and proof-of-concept definition
8. Controlled implementation, validation, and hardening
9. Deployment, migration, and legacy retirement

Each phase produces formal outputs to support traceability and auditability.

---

## Status

- OSMAP is now a working prototype with real Rust implementation, not only a
  design repo.
- Planning, architecture, security, SDLC, and implementation-control documents
  are populated through the current Phase 6 baseline.
- The runtime includes typed configuration, explicit state layout, structured
  logging, bounded auth, TOTP, session issuance and revocation, CSRF handling,
  mailbox browsing, message listing and viewing, mailbox-scoped search,
  MIME-aware inspection, attachment upload and forced-download paths,
  compose/send, reply/forward draft generation, and a first one-message move
  path between existing mailboxes.
- The browser layer now includes a first self-service session-management page
  backed by the persisted session metadata and revocation primitives already in
  the runtime.
- The largest Rust implementation hotspots are being reduced through
  behavior-preserving internal splits across the HTTP, mailbox, and mailbox
  helper layers so the browser boundary and helper boundary stay easier to
  audit as the prototype matures.
- That session-management slice is now also proven on
  `mail.blackbagsecurity.com` under `enforce` with the web runtime kept as
  `_osmap` and the helper kept at the `vmail` boundary, using a synthetic
  session store to validate `/sessions` and `POST /sessions/revoke`.
- The browser layer is server-rendered and dependency-light, with bounded HTTP
  parsing and explicit separation from the underlying mail stack.
- OpenBSD-specific work is already in the prototype: dedicated `_osmap`
  runtime assumptions, explicit Dovecot socket configuration, and
  operator-controlled `pledge(2)` / `unveil(2)` enforcement modes.
- Positive browser authentication plus TOTP-backed session issuance are proven
  on `mail.blackbagsecurity.com` under `_osmap`.
- The mailbox-helper runtime now exists in-repo: a local Unix-socket helper
  plus helper-backed mailbox listing, message-list retrieval, and message-view
  retrieval, and the attachment route now reuses that helper-backed message
  fetch when configured.
- The helper-backed read path is now also proven on `mail.blackbagsecurity.com`
  under `OSMAP_OPENBSD_CONFINEMENT_MODE=enforce`: mailbox listing,
  message-list retrieval, message view, and attachment download all succeeded
  against an attachment-bearing validation mailbox with the web runtime kept as
  `_osmap` and the mailbox helper running at the `vmail` boundary.
- A full read-oriented browser trace is now also proven on
  `mail.blackbagsecurity.com` under `enforce`: real password-plus-TOTP login,
  issued browser session cookie, helper-backed mailbox listing, helper-backed
  message view, and attachment download all succeeded in one continuous flow.
- OSMAP is still prototype-grade, not production-ready, and does not yet have a
  public deployment.
- The remaining clear Version 1 product gaps are safe HTML mail rendering and a
  bounded settings surface. Broader folder-organization ergonomics still
  remain, but the first backend-authoritative move workflow is now present.
- The backend now includes a first bounded application-layer login-throttling
  slice for the browser auth path. Broader auth-abuse resistance and
  request-abuse controls still remain active hardening work, and the service
  still depends on adjacent controls such as nginx, PF, and operator
  monitoring.
- The largest Rust hotspots are also being reduced with behavior-preserving
  internal refactors. The browser layer has been split across dedicated
  `http_runtime`, `http_gateway`, and `http_browser` modules, and the mailbox
  layer now has dedicated parser, backend, service, and model modules to make
  security review and future maintenance easier.
- Current priority work is continued HTTP hardening, tighter OpenBSD helper and
  filesystem narrowing, broader end-to-end live validation beyond the now
  proven authenticated read path, and continued behavior-preserving reduction
  of oversized implementation hotspots where that improves auditability.
- GitHub-side security validation now has two explicit lanes:
  GitHub default CodeQL setup remains the authoritative CodeQL scanner for this
  repository, while the repo-owned `security-check` workflow is the
  authoritative CI gate for Rust checks, tests, clippy, formatting, and the
  current CWE-oriented shell guards.

---

## Target Users

OSMAP is intended for:

- Security-conscious self-hosters
- Organizations operating their own mail infrastructure
- Operators of hardened OpenBSD systems
- Environments where public webmail exposure is necessary but risk must be tightly controlled

---

## Contributing

Contribution guidance now lives in [`CONTRIBUTING.md`](CONTRIBUTING.md).
The main project documentation set lives under [`docs/`](docs/README.md); the
repository root is intentionally kept for the main project README, build files,
license, and GitHub-detected community files.

The short version:

- keep changes small and reviewable
- preserve OSMAP's bounded scope and OpenBSD-first posture
- update tests and docs with meaningful implementation changes
- run `make security-check` before commit when working on the Rust backend
- install the repo-owned hook path with `make install-hooks` if you want that
  gate to run automatically on each commit
- expect GitHub Actions to enforce the same repo-owned `make security-check`
  gate on pushes and pull requests to `main`
- expect extra scrutiny for auth, session, HTTP, MIME, attachment, helper, and
  confinement work

Security-sensitive reports should follow [`SECURITY.md`](SECURITY.md), not
public issues.

---

## Security Notice

This software is intended for use in security-sensitive environments.  
Improper deployment or modification may expose sensitive data or services.

Always evaluate changes in a controlled environment before production use.

Private vulnerability reporting guidance is in [`SECURITY.md`](SECURITY.md).

---

## License

OSMAP is licensed under the ISC license. See [`LICENSE`](LICENSE).

---

## Disclaimer

OSMAP is provided without warranty.  
Operators are responsible for secure configuration, deployment, and ongoing maintenance.

## Community Files

The repository now includes the expected public collaboration files for a
healthy GitHub project:

- [`CODE_OF_CONDUCT.md`](CODE_OF_CONDUCT.md)
- [`CONTRIBUTING.md`](CONTRIBUTING.md)
- [`SECURITY.md`](SECURITY.md)
- [`SUPPORT.md`](SUPPORT.md)
- [`.github/ISSUE_TEMPLATE/`](.github/ISSUE_TEMPLATE)
- [`.github/pull_request_template.md`](.github/pull_request_template.md)
