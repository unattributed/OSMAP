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
  mailbox browsing, message listing and viewing, bounded one-mailbox and
  all-mailbox search,
  MIME-aware inspection, attachment upload and forced-download paths,
  compose/send, reply/forward draft generation, and a first one-message move
  path between existing mailboxes.
- The browser layer now includes a first self-service session-management page
  backed by the persisted session metadata and revocation primitives already in
  the runtime.
- The browser layer now also includes a first bounded settings page and a safe
  HTML rendering path: HTML-capable messages can be rendered through a narrow
  allowlist sanitizer, users can choose between sanitized HTML and plain-text
  fallback, and the same settings surface now also carries a bounded archive
  mailbox shortcut preference.
- Production `serve` mode now also refuses to run without the local mailbox
  helper boundary, so the Version 1 browser runtime no longer treats direct
  mailbox backends as an acceptable deployment shape there.
- The largest Rust implementation hotspots are being reduced through
  behavior-preserving internal splits across the HTTP, mailbox, and mailbox
  helper layers so the browser boundary and helper boundary stay easier to
  audit as the prototype matures.
- That session-management slice is now also proven on
  `mail.blackbagsecurity.com` under `enforce` with the web runtime kept as
  `_osmap` and the helper kept at the `vmail` boundary, using a synthetic
  session store to validate `/sessions`, `POST /sessions/revoke`, and
  `POST /logout`, including stale-session rejection after logout.
- The browser layer is server-rendered and dependency-light, with bounded HTTP
  parsing and explicit separation from the underlying mail stack.
- OpenBSD-specific work is already in the prototype: dedicated `_osmap`
  runtime assumptions, explicit Dovecot socket configuration, and
  operator-controlled `pledge(2)` / `unveil(2)` enforcement modes.
- The binary now also accepts an optional explicit run-mode argument
  (`bootstrap`, `serve`, or `mailbox-helper`), which keeps OpenBSD
  service-management examples small and gives the split runtime distinct
  process-table shapes.
- Positive browser authentication plus TOTP-backed session issuance are proven
  on `mail.blackbagsecurity.com` under `_osmap`.
- The mailbox-helper runtime now exists in-repo: a local Unix-socket helper
  plus helper-backed mailbox listing, message-list retrieval, and message-view
  retrieval, and attachment download now also runs through a dedicated
  helper-backed operation when configured.
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
- The previous top-level Version 1 product gaps around safe HTML rendering and
  a bounded settings surface are now closed in first-release form. Broader
  folder-organization ergonomics still remain later refinements, but the first
  backend-authoritative move workflow is now present.
- The safe-HTML rendering and settings slice is now also live-proven on
  `mail.blackbagsecurity.com` under `enforce` with a controlled HTML-bearing
  mailbox message and a synthetic validated session: sanitized HTML renders by
  default, the settings page persists `prefer_plain_text`, and the same
  message then falls back to plain-text rendering.
- The settings-backed archive shortcut is now also live-proven on
  `mail.blackbagsecurity.com` under `enforce`: `POST /settings` persists
  `archive_mailbox_name=Junk`, the mailbox and message pages both render
  archive shortcut forms with that configured destination, and a controlled
  message is then archived from `INBOX` to `Junk` through the existing
  `POST /message/move` route.
- Mailbox-list pages now also expose bounded selected-message archive controls
  when an archive mailbox is configured. The selected archive route reuses the
  same message-move backend once per selected UID instead of adding broader
  mailbox-write authority.
- The bounded all-mailboxes search flow is now also live-proven on
  `mail.blackbagsecurity.com` under `enforce`: the mailboxes page renders the
  global search form, the mailbox page renders the all-mailboxes toggle, and a
  controlled `/search?q=...` request returned matching messages from both
  `INBOX` and `Junk` in one browser result set.
- The backend now applies two bounded file-backed login-throttle buckets on the
  browser auth path: a tighter credential-plus-remote bucket and a higher
  threshold remote-only bucket.
- The backend now also applies two bounded file-backed submission-throttle
  buckets on the browser send path: a tighter canonical-user-plus-remote
  bucket and a higher threshold remote-only bucket.
- The backend now also applies two bounded file-backed message-move throttle
  buckets on the browser folder-organization path: a tighter
  canonical-user-plus-remote bucket and a higher threshold remote-only bucket.
- That bounded send-throttle behavior is now also live-proven on
  `mail.blackbagsecurity.com` under `enforce`: an isolated host validation run
  using a synthetic validated session confirmed one accepted `POST /send`
  followed by `429 Too Many Requests` with `Retry-After` on the second matching
  submission.
- The bounded message-move throttle is now also live-proven on
  `mail.blackbagsecurity.com` under `enforce`: a controlled message injected
  into `INBOX` was moved once through `POST /message/move`, then the second
  matching move attempt returned `429 Too Many Requests` with `Retry-After`.
- Broader auth-abuse resistance and request-abuse controls still remain active
  hardening work, and the service still depends on adjacent controls such as
  nginx, PF, and operator monitoring.
- The current HTTP runtime now uses bounded concurrent connection handling
  instead of a strictly sequential listener, with an explicit in-flight cap
  and `503 Service Unavailable` when that cap is reached.
- The first live mutation-path proof now also exists on
  `mail.blackbagsecurity.com` under `enforce`: a controlled one-message move
  from `INBOX` to `Junk` and a bounded send flow both succeeded through the
  real browser routes with the `_osmap` plus `vmail` runtime split.
- The authenticated read and first mutation paths are therefore both proven on
  the target host, but broader mutation coverage and operational-hardening
  work still remain.
- The largest Rust hotspots are also being reduced with behavior-preserving
  internal refactors. The browser layer has been split across dedicated
  `http_runtime`, `http_gateway`, and `http_browser` modules, and the mailbox
  layer now has dedicated parser, backend, service, and model modules to make
  security review and future maintenance easier.
- A fresh repo-grounded reassessment now shows no equally strong candidate for
  another narrow per-route throttle right now: selected-message archive reuses
  the message-move throttle once per selected UID, while the remaining
  authenticated POST routes are settings update, session revoke, and logout,
  and they are lower-volume, CSRF-bound, and lower abuse value than login,
  send, or message move.
- Current priority work is therefore centered on keeping the frozen Version 1
  contract around the already-implemented helper/OpenBSD boundary aligned with
  the successful April 14, 2026 current-pushed-snapshot live-host closeout
  rerun, using the
  repo-owned closeout wrappers for targeted reruns when closeout-facing
  behavior changes, and only taking narrower runtime or confinement changes
  when repo evidence exposes a real blocker.
- The HTTP runtime now also distinguishes connection-lifecycle failures more
  honestly: read timeouts return `408 Request Timeout`, while empty or
  truncated connections are logged and closed without treating them as generic
  `400 Bad Request` traffic.
- The bounded listener now also applies backoff after repeated accept
  failures and emits central request-completion events with status and
  duration so slow requests are easier to spot during hardening.
- The bounded runtime now also emits connection high-watermark and
  capacity-reached events, and its response-write failure events carry richer
  request and response context for operator triage.
- The listener now also escalates sustained `accept(2)` failure streaks to an
  error-level event and emits a recovery event when successful accepts resume.
- The runtime now also escalates sustained response-write failure streaks and
  emits a recovery event when response writes resume after repeated failures.
- A live host observability proof now also exists for the bounded runtime on
  `mail.blackbagsecurity.com`: with the connection cap forced to `1`, one held
  connection triggered capacity-reached and over-capacity rejection events,
  then timed out cleanly and allowed normal health requests to resume.
- A second live host observability proof now also exists on
  `mail.blackbagsecurity.com` under `enforce`: repeated reset-backed
  `GET /login` requests drove sustained response-write failures reported as
  `Broken pipe (os error 32)`, and a subsequent normal `GET /healthz`
  triggered `http_response_write_recovered` after returning `200 OK`.
- The standard host-side validation checkout on `mail.blackbagsecurity.com` is
  now `~/OSMAP`, with [osmap-host-validate.ksh](maint/live/osmap-host-validate.ksh)
  used there to run repo-owned validation under home-local `TMPDIR`,
  `CARGO_HOME`, and `CARGO_TARGET_DIR` instead of depending on `/tmp`.
- The authoritative Version 1 host closeout gate is now
  `ksh ./maint/live/osmap-live-validate-v1-closeout.ksh` in that same
  `~/OSMAP` checkout, and a reachable workstation can trigger that exact
  host-side wrapper through
  [osmap-run-v1-closeout-over-ssh.sh](maint/live/osmap-run-v1-closeout-over-ssh.sh)
  and pull back the small review report.
- A supplemental real-user browser walkthrough now also exists on April 12,
  2026 against a temporary review instance launched from the current
  `~/OSMAP` checkout on `mail.blackbagsecurity.com`: the real mailbox user
  `duncan@blackbagsecurity.com` signed in with mailbox password plus OSMAP
  TOTP, viewed mailboxes, reviewed `/sessions`, opened a real message,
  rendered sanitized HTML, and sent a browser-composed message that was
  confirmed delivered in Proton Mail. Proton Pass and Proton Authenticator
  were used as operator tools during that walkthrough; OSMAP itself does not
  depend on either product.
- GitHub-side security validation now has two explicit lanes:
  GitHub default CodeQL setup remains the authoritative CodeQL scanner for this
  repository, while the repo-owned `security-check` workflow is the
  authoritative CI gate for Rust checks, tests, clippy, formatting, and the
  current CWE-oriented shell guards.

## V1 Closeout Priorities

The Version 1 closeout contract is now frozen in
`docs/ACCEPTANCE_CRITERIA.md`, and the remaining repo-grounded closeout work
is:

1. Keep `README.md`, the closeout-facing docs, and the repo-owned validation
   references aligned with that gate, with the successful April 14, 2026
   current-pushed-snapshot host rerun archived in
   `maint/live/latest-host-v1-closeout-report.txt`, and with the supplemental
   April 12, 2026 real-user browser walkthrough.
2. Use `ksh ./maint/live/osmap-live-validate-v1-closeout.ksh` on
   `mail.blackbagsecurity.com`, or
   `./maint/live/osmap-run-v1-closeout-over-ssh.sh` from a reachable
   workstation, whenever closeout-facing behavior changes.
3. Only take additional implementation or hardening work when a failing proof
   or a repo inconsistency reveals a narrower blocker.

For the short allowlist that turns that rule into day-to-day scoping guidance,
see `docs/V1_CLOSEOUT_WORK_RULES.md`.

## V2 Direction

Version 2 is now defined as the first pilot-ready, migration-capable production
candidate for the known OpenBSD mail environment. It is intended to preserve
OSMAP's narrow security-first shape while making the project credible for
controlled real-world use and direct browser access through a hardened public
HTTPS edge once the explicit internet-exposure gate is satisfied.

The authoritative Version 2 definition and release gate now live in:

- `docs/V2_DEFINITION.md`
- `docs/V2_ACCEPTANCE_CRITERIA.md`
- `docs/PILOT_WORKFLOW_INVENTORY.md`

The short form is:

- keep the `_osmap` plus `vmail` least-privilege split
- preserve Dovecot and Postfix as the authoritative backends
- support direct public browser access only after the repo-defined exposure gate
  is passed
- focus Version 2 on migration readiness, operator readiness, pilot readiness,
  and hostile-path proof rather than on broad feature expansion

Unless a narrower migration-capable need is proven, the following remain beyond
Version 2:

- broader folder ergonomics beyond the first practical move/archive baseline
- richer search behavior beyond ordinary daily-use needs
- richer session or device intelligence beyond first useful security visibility
- more attachment convenience behavior that would widen browser trust
- broader settings surface beyond the first bounded user preference
- mailbox-helper identity derivation beyond the current trusted-service
  boundary, including opaque helper-side identity handles
- deeper runtime redesign such as worker-pool or async server architecture

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
  gate to run automatically on each commit and again before each push
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
