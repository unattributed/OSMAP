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
  mailbox browsing, message listing and viewing, MIME-aware inspection,
  attachment upload and forced-download paths, compose/send, and reply/forward
  draft generation.
- The browser layer is server-rendered and dependency-light, with bounded HTTP
  parsing and explicit separation from the underlying mail stack.
- OpenBSD-specific work is already in the prototype: dedicated `_osmap`
  runtime assumptions, explicit Dovecot socket configuration, and
  operator-controlled `pledge(2)` / `unveil(2)` enforcement modes.
- Positive browser authentication plus TOTP-backed session issuance are proven
  on `mail.blackbagsecurity.com` under `_osmap`.
- The mailbox-read identity boundary is not fully solved on the live host yet:
  the current Dovecot virtual-user model still resolves mailbox access to
  `vmail`, so broader least-privilege live mailbox reads are not yet proven.
- The mailbox-helper runtime now exists in-repo: a local Unix-socket helper
  plus helper-backed mailbox listing, message-list retrieval, and message-view
  retrieval, and the attachment route now reuses that helper-backed message
  fetch when configured.
- OSMAP is still prototype-grade, not production-ready, and does not yet have a
  public deployment.
- Current priority work is live-host validation of the helper under the actual
  `vmail` boundary, continued HTTP hardening, and tightening the OpenBSD
  deployment and confinement model around the helper split.

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

The short version:

- keep changes small and reviewable
- preserve OSMAP's bounded scope and OpenBSD-first posture
- update tests and docs with meaningful implementation changes
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
