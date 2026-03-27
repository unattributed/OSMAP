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

Planning, architecture, security, and implementation-governance baselines are
documented through the Phase 6 proof-of-concept planning layer.

WP0 is now complete: the repository has a dependency-minimal Rust toolchain
baseline, a source tree, conservative build and test entrypoints, and a small
bootstrap executable.

WP1 and WP2 are now complete: the runtime has a typed configuration model, an
explicit mutable-state layout, and a small structured logging/error baseline.

The project is not yet production-ready and does not yet have a running public
deployment, but it now has a real bounded browser prototype rather than only a
design baseline. WP3 now includes bounded credential handling, a real
Dovecot-oriented primary-auth path, a real TOTP backend with a bounded
secret-store model, a second-factor verification stage, and audit-quality auth
events. The runtime now also includes a first session-management baseline with
bounded token issuance, validation, revocation, and per-user session listing.
The first mailbox read primitive is now present too: mailbox listing behind the
validated-session gate using the existing Dovecot surface. The second WP5 slice
is now present as well: per-mailbox message-list retrieval using a bounded
Dovecot-backed message-summary path. The first WP6 slice is now in place too:
bounded per-message retrieval using the same validated-session and Dovecot-backed
read path. The next rendering step is now in place as well: a plain-text-first
browser-safe rendering layer on top of the fetched message payload. The next
follow-on WP6 step is now in place too: a dependency-light MIME-aware and
attachment-aware analysis layer that preserves the current plain-text safety
posture while surfacing attachment metadata honestly.
The next implementation step is now in place too: a dependency-light
HTTP/browser slice with bounded request parsing, login/logout routes,
session-gated mailbox pages, and message-view rendering over the existing
runtime. The binary now supports `OSMAP_RUN_MODE=bootstrap` for fast startup
validation and `OSMAP_RUN_MODE=serve` for the current listener path. The next
implementation step is now in place too: a first compose/send browser slice
with bounded outbound input validation, a local `sendmail` compatibility
handoff, and submission audit events. The browser runtime now also has a first
CSRF strategy for current state-changing form routes, plus explicit nginx-facing
deployment guidance and an early OpenBSD confinement map. The next send-path
step is now in place too: server-side reply and forward draft generation with
attachment-aware notices built from the current message-view path. The runtime
now also has an operator-controlled OpenBSD confinement mode with real
`pledge(2)` and `unveil(2)` enforcement on OpenBSD. The next send-path step is
now in place too: bounded new attachment upload and multipart submission
behavior. The OpenBSD confinement view has also had its first real narrowing
pass away from a blanket `/var` unveil, and live-host validation exposed and
closed a real `fattr` promise gap in the session-refresh path. The next mailbox
read step is now in place too: bounded attachment download using the existing
session, message-view, and MIME part-path model, with forced-download browser
headers and conservative transfer-decoding support.

The next implementation steps are to keep tightening the helper-compatible
OpenBSD view, investigate the remaining live `doveadm` helper caveats under
`enforce`, and continue reducing correctness and denial-of-service risk in the
custom HTTP/browser runtime.

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
