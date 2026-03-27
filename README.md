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
prototype. WP3 now includes bounded credential handling, a real
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

The next implementation step is to carry this runtime into actual HTTP/browser
request handling without weakening the security boundaries that are now in
place.

---

## Target Users

OSMAP is intended for:

- Security-conscious self-hosters
- Organizations operating their own mail infrastructure
- Operators of hardened OpenBSD systems
- Environments where public webmail exposure is necessary but risk must be tightly controlled

---

## Contributing

Contribution guidelines will be defined as the architecture stabilizes.

Security-relevant changes require careful review.

---

## Security Notice

This software is intended for use in security-sensitive environments.  
Improper deployment or modification may expose sensitive data or services.

Always evaluate changes in a controlled environment before production use.

---

## License

To be determined.

---

## Disclaimer

OSMAP is provided without warranty.  
Operators are responsible for secure configuration, deployment, and ongoing maintenance.
