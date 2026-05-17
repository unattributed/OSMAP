# OSMAP: OpenBSD Secure Mail Access Platform

OSMAP is a security-focused webmail access platform for hardened OpenBSD mail systems.

It is intended to replace broad, plugin-heavy webmail interfaces such as Roundcube with a smaller, more restricted, and more maintainable browser access layer. The project prioritizes security, operational simplicity, auditability, and long-term maintainability over feature breadth.

OSMAP does not replace the mail stack. Postfix, Dovecot, Rspamd, nginx, TLS, PF, and the surrounding OpenBSD host controls remain authoritative.

The project-wide TLS floor is defined in [`docs/TLS_STANDARD.md`](docs/TLS_STANDARD.md):
TLS 1.2 minimum, TLS 1.3 preferred, certificate and hostname verification on,
and no legacy weak protocol or cipher fallback.

---

## Project Goals

OSMAP aims to provide safe browser-based access to an existing mail system without weakening the underlying mail transport or delivery architecture.

Primary goals:

- Replace Roundcube in hardened self-hosted environments
- Operate safely behind a hardened public HTTPS edge
- Minimize exposed browser functionality
- Preserve compatibility with existing IMAP and SMTP infrastructure
- Enforce strong authentication
- Maintain clear trust boundaries between the browser runtime and mailbox access
- Run with least privilege on OpenBSD
- Keep deployments reversible and auditable
- Maintain a clearly defined software supply chain
- Support reproducible builds, validation, and deployment checks
- Remain maintainable by a small operator team

---

## Non-Goals

OSMAP intentionally avoids broad webmail feature creep.

Out of scope unless a later version explicitly redefines the project boundary:

- Calendar and groupware features
- Mobile applications
- Plugin ecosystems
- SaaS deployment model
- Multi-tenant hosting
- Replacement of Postfix, Dovecot, Rspamd, nginx, PF, or other core host services
- ProtonMail-style zero-access encryption
- Enterprise identity federation
- Broad JavaScript-heavy application behavior
- Attachment preview behavior that widens browser trust
- Unbounded mailbox-wide operations

---

## Intended Environment

OSMAP is designed for a self-hosted OpenBSD mail stack.

A typical deployment includes:

- OpenBSD
- Postfix for SMTP and submission
- Dovecot for mailbox access
- Rspamd for spam filtering
- nginx as the public HTTPS edge
- TLS-only browser access
- PF and host-level network controls
- A dedicated `_osmap` web runtime user
- A mailbox helper boundary running with only the mailbox authority it needs

Native mail clients such as Thunderbird remain supported and unchanged.

---

## Security Philosophy

Security is the primary design driver.

Core principles:

- Minimal exposed functionality
- Least privilege operation
- Explicit trust boundaries
- Defense in depth
- Strong authentication
- Session revocation and expiry
- Bounded parsing and request handling
- Safe rendering by default
- Supply-chain awareness
- Observable and auditable runtime behavior
- Reversible deployments
- Maintainability over novelty

The project aligns its planning and validation with recognized security guidance, including:

- OWASP Top 10
- OWASP ASVS
- OWASP WSTG
- CWE Top 25
- MITRE ATT&CK from a defensive perspective
- Applicable NIST cybersecurity guidance

---

## Why Replace Roundcube?

Traditional webmail platforms often prioritize features, extensibility, and compatibility over security minimalism.

OSMAP exists for environments where public webmail access is necessary, but the exposed browser surface must remain narrow and reviewable.

OSMAP focuses on:

- Reduced complexity
- Fewer exposed features
- Server-rendered browser flows
- Clear operational assumptions
- Stronger alignment with OpenBSD host controls
- Explicit validation before direct internet exposure
- Long-term sustainability for small operator teams

---

## Development Approach

The project follows a phased methodology:

1. Charter and planning baseline
2. Current system analysis
3. Product definition
4. Security and trust model
5. Architecture design
6. Secure SDLC and release governance
7. Implementation planning and proof-of-concept definition
8. Controlled implementation, validation, and hardening
9. Pilot deployment, migration planning, and legacy retirement criteria
10. Daily-driver hardening and broader adoption readiness

Each phase produces documentation, implementation changes, validation scripts, or acceptance evidence that can be reviewed later.

---

## Current Status

OSMAP is now a working Rust prototype with live-host validation evidence. It is no longer only a planning repository.

The current implementation includes:

- Typed runtime configuration
- Structured logging
- Bounded HTTP parsing
- Server-rendered browser flows
- Password plus TOTP authentication
- Session issuance, listing, revocation, idle expiry, and absolute lifetime expiry
- CSRF protection for state-changing browser routes
- Mailbox listing
- Message listing and viewing
- Server-rendered mailbox sorting by UID, subject, sender, received time, flags, and size
- Bounded one-mailbox and all-mailbox search
- MIME-aware message inspection
- Safe HTML rendering through a narrow sanitizer
- Plain-text fallback preference
- Attachment upload limits
- Forced-download attachment behavior
- Compose and send
- Reply and forward draft generation
- One-message move support between existing mailboxes
- Selected-message move and archive controls with capped selections
- Login, send, and message-move throttling
- Bounded concurrent connection handling
- Runtime observability for capacity, timeouts, accept failures, and response-write failures

OpenBSD-specific work is already present:

- Dedicated `_osmap` runtime assumptions
- Dedicated mailbox helper boundary
- Helper-backed mailbox listing
- Helper-backed message listing
- Helper-backed message view
- Helper-backed attachment download
- Explicit Dovecot socket configuration
- Operator-controlled `pledge(2)` and `unveil(2)` enforcement modes
- Production `serve` mode refusal when the required local mailbox helper boundary is not configured

The project has also reduced some large implementation hotspots through internal module splits across the HTTP, mailbox, and mailbox-helper layers. This improves reviewability as the browser and helper boundaries become more security-sensitive.

OSMAP remains prototype-grade. The current code has passed meaningful controlled validation on the known OpenBSD target environment, but it is not yet ready for broad public adoption.

---

## Validation Status

The known live validation target is:

- `mail.blackbagsecurity.com`

The standard host-side validation checkout is:

- `~/OSMAP`

Important validation entry points include:

- [`maint/live/osmap-host-validate.ksh`](maint/live/osmap-host-validate.ksh)
- [`maint/live/osmap-live-validate-v1-closeout.ksh`](maint/live/osmap-live-validate-v1-closeout.ksh)
- [`maint/live/osmap-run-v1-closeout-over-ssh.sh`](maint/live/osmap-run-v1-closeout-over-ssh.sh)

Validation performed so far includes:

- Positive browser login with password plus TOTP
- Session issuance and stale-session rejection after logout
- Session listing and revocation flows
- Helper-backed mailbox listing
- Helper-backed message listing
- Helper-backed message view
- Helper-backed attachment download
- Sanitized HTML rendering
- Plain-text fallback preference persistence
- Settings-backed archive shortcut behavior
- One-message move from `INBOX` to `Junk`
- Bounded all-mailboxes search
- Bounded send flow
- Send-throttle proof
- Message-move throttle proof
- Capacity-reached and over-capacity listener behavior
- Response-write failure and recovery observability

The repository-owned security validation currently has two lanes:

- GitHub default CodeQL setup for CodeQL scanning
- Repo-owned `security-check` workflow for Rust checks, tests, clippy, formatting, and current shell-based security guards

The TLS validation gate is:

- [`maint/security/osmap-tls-policy-guard.sh`](maint/security/osmap-tls-policy-guard.sh) for static repository policy drift
- [`maint/security/osmap-live-tls-standard-validate.py`](maint/security/osmap-live-tls-standard-validate.py) for live edge evidence, defaulting to `https://mail.blackbagsecurity.com`

Further supply-chain assurance work is planned for Version 3.

---

## Version 1 Closeout Priorities

The Version 1 closeout contract is frozen in:

- [`docs/ACCEPTANCE_CRITERIA.md`](docs/ACCEPTANCE_CRITERIA.md)

The remaining Version 1 closeout rule is intentionally narrow:

1. Keep `README.md`, closeout-facing docs, and validation references aligned with the accepted gate.
2. Use `ksh ./maint/live/osmap-live-validate-v1-closeout.ksh` on `mail.blackbagsecurity.com`, or `./maint/live/osmap-run-v1-closeout-over-ssh.sh` from a reachable workstation, whenever closeout-facing behavior changes.
3. Only take additional Version 1 implementation or hardening work when a failing proof or repo inconsistency reveals a specific blocker.

Day-to-day scoping guidance lives in:

- [`docs/V1_CLOSEOUT_WORK_RULES.md`](docs/V1_CLOSEOUT_WORK_RULES.md)

---

## V2 Direction

Version 2 is the first pilot-complete, migration-capable production candidate for the known OpenBSD mail environment.

It preserves OSMAP's narrow security shape while making the project credible for controlled real-world use and limited direct browser access through a hardened public HTTPS edge after the explicit internet-exposure gate is satisfied.

The authoritative Version 2 definition and release gate live in:

- [`docs/V2_DEFINITION.md`](docs/V2_DEFINITION.md)
- [`docs/V2_ACCEPTANCE_CRITERIA.md`](docs/V2_ACCEPTANCE_CRITERIA.md)
- [`docs/V2_PILOT_CLOSEOUT.md`](docs/V2_PILOT_CLOSEOUT.md)
- [`docs/V2_PILOT_STATUS.md`](docs/V2_PILOT_STATUS.md)
- [`docs/PILOT_WORKFLOW_INVENTORY.md`](docs/PILOT_WORKFLOW_INVENTORY.md)

The short form is:

- Keep the `_osmap` plus `vmail` least-privilege split
- Preserve Dovecot and Postfix as the authoritative backends
- Support direct public browser access only after the repo-defined exposure gate is passed
- Focus Version 2 on migration readiness, operator readiness, pilot closeout, and hostile-path proof
- Avoid broad feature expansion until the daily-driver security foundation is stronger

Unless a narrower migration-capable need is proven, the following remain beyond Version 2:

- Broader folder ergonomics beyond the first practical move and archive baseline
- Richer search behavior beyond ordinary daily-use needs
- Richer session or device intelligence beyond first useful security visibility
- More attachment convenience behavior that would widen browser trust
- Broader settings behavior beyond the first bounded user preference
- Mailbox-helper identity derivation beyond the current trusted-service boundary
- Deeper runtime redesign such as worker-pool or async server architecture

---

## V3 Direction

Version 3 is the focused daily-driver hardening cycle for the known OpenBSD mail environment.

It preserves all Version 2 security gates while moving OSMAP from controlled pilot usefulness toward safer routine use by selected real users. Version 3 is not a broad feature-expansion release. Its purpose is to close the most important assurance, correctness, resource-control, and workflow gaps exposed by Version 2 before OSMAP grows a larger browser surface.

The authoritative Version 3 definition and release gate live in:

- [`docs/V3_DEFINITION.md`](docs/V3_DEFINITION.md)
- [`docs/V3_ACCEPTANCE_CRITERIA.md`](docs/V3_ACCEPTANCE_CRITERIA.md)
- [`docs/V3_ROADMAP.md`](docs/V3_ROADMAP.md)
- [`docs/V3_SECURITY_GATES.md`](docs/V3_SECURITY_GATES.md)

The short form is:

- Preserve the `_osmap` plus `vmail` least-privilege split
- Preserve Dovecot and Postfix as the authoritative backends
- Keep direct public browser access gated by repo-owned security checks and live-host validation
- Split developer partial checks from release-mode validation
- Make release-mode validation fail on skipped required checks or missing evidence
- Make Rust supply-chain assurance a first-class release gate
- Require credential and TOTP-backed evidence for WSTG and other security tests that need authenticated coverage
- Add strict timeout and resource-control evidence around expensive browser, helper, mailbox, MIME, attachment, send, search, and move paths
- Strengthen MIME and HTML correctness through fixture-driven tests before adding richer mail behavior
- Prove session revocation, expiry, and concurrent-session behavior with regression tests
- Improve daily-driver usability only where the security model remains narrow, bounded, and testable

Version 3 priority work is:

1. Release-mode validation that cannot pass on skipped required security checks
2. Supply-chain assurance for Rust dependencies, CI, local checks, and release evidence
3. Explicit resource limits and timeout behavior for expensive browser, helper, mailbox, MIME, attachment, send, search, and move operations
4. WSTG and security-test release evidence, including credential and TOTP-backed authenticated coverage where required
5. Fixture-driven MIME, attachment, charset, transfer-encoding, encoded-header, and sanitized-HTML validation
6. Session-store concurrency, revocation, expiry, and device-policy correctness
7. Daily-driver improvements such as draft continuity, reply and forward correctness, safer attachment handling, richer bounded search, and bounded bulk folder actions

The highest-risk Version 3 technical concerns are:

- Developer checks can currently appear useful even when required release evidence is missing or skipped
- Credential-gated WSTG tests can skip in ordinary runner mode, which is acceptable for developer partial testing but not for release evidence when authenticated coverage is required
- Dependency and supply-chain assurance must be strong enough to block release candidates, not just advise developers
- External command and helper paths need hard timeout behavior and consistent error mapping
- Resource-exhaustion controls need to cover more expensive mailbox and rendering paths
- MIME and HTML behavior needs a larger hostile fixture corpus
- Session-store race and revocation behavior needs stronger concurrency coverage
- TLS CBC disposition needs either closure or a documented exception
- Live-host evidence must be sanitized and reviewable without committing secrets

The implemented validation entry points are:

- `make security-check` for developer and CI-oriented partial validation
- `make release-check` for strict V3 release validation with `OSMAP_SECURITY_PROFILE=release`

`make release-check` requires the pinned Rust toolchain and supply-chain tools,
dependency inventory generation, V2 carry-forward evidence, host-readiness
evidence, a release-mode WSTG summary with authenticated credential and TOTP
coverage, current V3 pilot rehearsal evidence, and a sanitized release evidence
archive. It is expected to fail on a normal workstation until those
operator-provided evidence files and credentials are available.

Unless a narrower daily-driver need is proven and covered by tests, the following remain beyond Version 3:

- Plugin support
- Calendar or groupware features
- Mobile applications
- Multi-tenant hosting
- Enterprise identity federation
- ProtonMail-style zero-access encryption
- Broad JavaScript-heavy webmail behavior
- Remote external content loading
- Unbounded mailbox-wide operations
- Attachment preview behavior that widens browser trust
- Runtime redesign that is not directly justified by measured security or reliability needs

## Target Users

OSMAP is intended for:

- Security-conscious self-hosters
- Organizations operating their own mail infrastructure
- Operators of hardened OpenBSD systems
- Environments where public webmail exposure is necessary but risk must be tightly controlled
- Small teams that value a narrow, auditable webmail surface over broad feature convenience

---

## Contributing

Contribution guidance lives in:

- [`CONTRIBUTING.md`](CONTRIBUTING.md)

The main documentation set lives under:

- [`docs/`](docs/README.md)

The repository root is intentionally kept for the main project README, build files, license, and GitHub-detected community files.

The short version:

- Keep changes small and reviewable
- Preserve OSMAP's bounded scope and OpenBSD-first posture
- Update tests and docs with meaningful implementation changes
- Run `make security-check` before committing Rust backend changes
- Install the repo-owned hook path with `make install-hooks` if automatic local checks are desired
- Expect GitHub Actions to enforce the repo-owned `make security-check` gate on pushes and pull requests to `main`
- Expect extra scrutiny for auth, session, HTTP, MIME, attachment, helper, command execution, and confinement work
- Do not weaken security controls to make tests pass
- Do not add secrets, host-private credentials, or sensitive runtime material to the repository

Security-sensitive reports should follow:

- [`SECURITY.md`](SECURITY.md)

Do not report sensitive issues through public GitHub issues.

---

## Security Notice

OSMAP is intended for security-sensitive environments.

Improper deployment, configuration, or modification may expose sensitive mail, credentials, sessions, or host services.

Operators should always:

- Review configuration before deployment
- Validate changes in a controlled environment first
- Keep host-level controls such as PF, nginx, TLS, Dovecot, Postfix, and monitoring aligned with the documented deployment model
- Treat browser-exposed functionality as security-sensitive
- Run the repo-owned validation checks before production use
- Preserve rollback paths

Private vulnerability reporting guidance is in:

- [`SECURITY.md`](SECURITY.md)

---

## License

OSMAP is licensed under the ISC license.

See:

- [`LICENSE`](LICENSE)

---

## Disclaimer

OSMAP is provided without warranty.

Operators are responsible for secure configuration, deployment, monitoring, validation, and ongoing maintenance.

---

## Community Files

The repository includes the expected public collaboration files for a healthy GitHub project:

- [`CODE_OF_CONDUCT.md`](CODE_OF_CONDUCT.md)
- [`CONTRIBUTING.md`](CONTRIBUTING.md)
- [`SECURITY.md`](SECURITY.md)
- [`SUPPORT.md`](SUPPORT.md)
- [`.github/ISSUE_TEMPLATE/`](.github/ISSUE_TEMPLATE)
- [`.github/pull_request_template.md`](.github/pull_request_template.md)
