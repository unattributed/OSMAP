# Decision Log

## 2026-03-27

### Keep planning artifacts public and non-sensitive

The repository will keep a public documentation map under `docs/`, including
placeholder documents for planned work. Those placeholders should contain
minimal public-safe text rather than private planning detail or empty file
stubs.

### Complete Phase 0 with public-safe formal outputs

The project now treats Phase 0 as complete enough to proceed because the
charter, constraints, assumptions, roadmap, and early acceptance criteria are
documented in reviewable form.

### Ground Phase 1 in live-system evidence

Phase 1 documentation will be based on read-only inspection of the existing mail
host rather than inferred architecture alone. This keeps the replacement effort
anchored to operational reality.

### Preserve the current VPN-first access model as the starting point

The current environment intentionally keeps webmail, IMAP, and authenticated
submission behind WireGuard and nginx allowlisting. OSMAP should treat that as
the baseline security posture and only relax it by explicit later-phase design
decision.

### Define Version 1 as a narrow mail-only replacement

Phase 2 defines Version 1 as a browser-based mail product with strong
authentication, core mailbox workflows, attachments, search, session management,
and audit visibility. Groupware, plugin ecosystems, mobile apps, and broad
administrative surfaces remain out of scope.

### Preserve native-client coexistence

The product definition explicitly keeps Thunderbird and other native clients as
supported access paths. OSMAP is not intended to replace them or centralize all
mail access in the browser.

### Keep the decision log current during phase execution

`docs/DECISION_LOG.md` should be updated as meaningful phase decisions are made.
It is a live project control document, not an after-action summary written only
at the end of a phase.

### Define Phase 3 around adversary-aware design

Phase 3 treats credential attacks, account takeover, submission abuse, message
content abuse, and local pivot risks as first-class design constraints. The goal
is to prevent avoidable classes of security failure before architecture and code
work begin.

### Make identity and session handling a first-class subsystem

Version 1 browser authentication is not treated as a cosmetic login screen. MFA,
session lifecycle, revocation, and session visibility are now explicit security
requirements that later phases must preserve.

### Treat public exposure as an approval gate, not a default assumption

The project keeps the VPN-first model as a valid deployment posture until
monitoring, abuse controls, and incident readiness justify broader exposure.

### Prefer designs that can leverage OpenBSD-native confinement

Later architecture work should favor designs that can practically use
OpenBSD-specific hardening primitives such as `pledge(2)` and `unveil(2)`,
especially in security-sensitive backend or session-handling components.

### Aim for OpenBSD-native credibility, not just OpenBSD compatibility

The project should be developed as software that could plausibly be respected by
OpenBSD-oriented maintainers: small dependency surface, conservative hosting
strategy, privilege-aware design, reproducible build discipline, and no
Linux-first operational assumptions.

### Select a small edge-plus-app architecture for Version 1

Phase 4 selects a simple architecture: nginx at the edge, one small OSMAP
application service behind it, and the existing mail stack left authoritative
for IMAP and submission behavior.

### Keep the browser product as a controlled consumer of the mail stack

The architecture intentionally avoids direct browser-to-mail protocols and
avoids turning OSMAP into a replacement mail transport platform. It is a narrow
policy and access layer on top of the existing substrate.

### Do not let toolchain preference override OpenBSD portability goals

Rust remains attractive for security-sensitive backend code, but it is not being
treated as an unquestionable requirement if it would materially undermine broad
OpenBSD usability or future packaging credibility.

### Treat implementation governance as part of the architecture

Phase 5 defines review, dependency, testing, SBOM, signing, and release rules
before implementation so the project does not drift into insecure build and
deployment habits.

### Require small, explainable release mechanics

The build and release model should remain simple enough for operators and
OpenBSD-minded maintainers to understand, verify, and roll back.

### Keep phase artifacts useful as the project advances

Phase documentation should be maintained as working project controls. Earlier
phase documents should be corrected and expanded when later work exposes gaps,
rather than being left as stale milestones.

### Start implementation with a narrow proof-of-concept slice

Phase 6 will begin with a constrained prototype that proves login, mailbox
read, send, and session handling rather than attempting a broad feature-complete
replacement immediately.

### Prefer low-complexity browser behavior for the first implementation

The first implementation path should favor server-rendered or otherwise minimal
client behavior over a heavy frontend architecture. This keeps the browser
surface smaller and the OpenBSD maintenance story more credible.

### Keep OpenBSD confinement work close to implementation

`pledge(2)`, `unveil(2)`, runtime-user separation, and listener scoping should
be evaluated early in the implementation sequence rather than postponed until a
large prototype already exists.

### Start the proof of concept with a dependency-minimal Rust skeleton

WP0 chooses Rust for the initial backend baseline because memory safety is
valuable for a security-sensitive service, but the repository starts with a
standard-library-only bootstrap so the dependency graph stays intentionally
small while the actual runtime shape is still being proven.

### Defer framework selection until the required flows force it

The repository skeleton does not yet adopt a web framework, async runtime, or
ORM. Those choices should be justified by the login, mailbox, and send-path
requirements rather than assumed up front.

### Keep mutable prototype data under one explicit state root

WP1 defines one state root with bounded subdirectories for runtime, session,
audit, and cache data so later OpenBSD deployment and confinement work has a
clear filesystem boundary to operate on.

### Start with a small structured logger instead of a large logging stack

WP2 introduces stable structured text events and explicit bootstrap error types
without adding a heavyweight logging framework before the runtime behavior is
mature enough to justify it.

### Treat primary credential success as MFA-required, not login-complete

The first WP3 auth slice does not mark the user fully authenticated after a
successful primary credential check. It returns an explicit MFA-required
decision so the codebase does not accidentally normalize password-only browser
auth.

### Bound auth inputs before backend integration

Username, password, request-id, remote-address, and user-agent inputs are now
bounded and validated before backend verification so the auth surface starts
from explicit limits rather than unbounded request data.

### Use `doveadm auth test` as the first real primary-auth integration path

WP3 connects primary credential verification to the Dovecot surface that exists
today on the OpenBSD mail host. The implementation feeds the password through
standard input so it is not exposed on the command line.

### Keep second-factor verification separate from session issuance

The current auth flow now has an explicit second-factor stage. Successful factor
verification yields an authenticated-pending-session result rather than silently
creating a session as part of the verifier itself.

### Validate auth changes in QEMU before wider host use

The existing OpenBSD QEMU lab path should be the first isolated integration
target for auth-path validation before broader testing on
`mail.blackbagsecurity.com`.

### Use a narrow live-host auth rejection test as an early safety check

Once Rust was available on `mail.blackbagsecurity.com`, the project added an
ignored test that safely validates the real `doveadm auth test` path with
invalid credentials. This gives us a small real-host proof point without
pretending broader auth behavior is already production-validated.

### Add a real TOTP backend before session issuance

WP3 now includes a real RFC 6238-style TOTP verifier and a file-backed secret
store boundary under the configured state root. That lets the project prove
factor verification before it takes on the higher-risk session layer.

### Store TOTP secrets under the explicit state boundary

The current secret-management model keeps TOTP secrets in a dedicated directory
under the state root so permissions, backups, and later `unveil(2)` policy can
reason about one bounded secret path.

### Keep project-local QEMU validation infrastructure in this repository

OSMAP now carries its own thin `maint/qemu/` wrapper layer around the upstream
OpenBSD lab model so isolated validation is reusable from this repository
instead of remaining tribal knowledge outside it.

### Store only a derived session identifier on disk

The browser-facing session token should remain an opaque bearer value, while
the file-backed session store keeps only a hash-derived session identifier.
This reduces casual local token exposure without introducing a large session
framework at this stage.

### Make logout and operator revocation explicit runtime behaviors

The session layer now supports both token-driven logout revocation and
session-id-driven operator revocation. Revocation is treated as a first-class
state transition with audit events rather than as a UI afterthought.

### Require bounded session lifetime from configuration

Session lifetime is now an explicit positive runtime setting rather than an
implicit default hidden in code. The bootstrap rejects zero-valued lifetimes so
the runtime does not accidentally normalize non-expiring sessions during early
development.

### Keep session visibility in the core runtime model

Per-user session listing, issuance timestamps, expiry, revocation state,
remote-address summaries, and user-agent summaries are now part of the runtime
session record. The project will build later UI and operator views on top of
that explicit substrate instead of inventing visibility after the browser layer
is already complex.

### Use the validated-session boundary as the mailbox gate

The first WP5 mailbox slice does not re-implement session logic. Mailbox
listing consumes a previously validated session so the mailbox layer stays a
consumer of the identity/session boundary rather than becoming its own access
control system.

### Use `doveadm mailbox list` for the first mailbox-read primitive

The first mailbox-listing backend uses `doveadm mailbox list` because it keeps
the prototype close to the Dovecot authority that already exists on the target
OpenBSD host while avoiding a heavier IMAP dependency before message retrieval
actually forces it.

### Log mailbox counts, not mailbox-name dumps, on the success path

The mailbox-listing success event records mailbox count plus identity and
request context, but not the full mailbox-name list. That keeps audit output
useful without turning mailbox activity logs into a content-heavy mirror of
user state.

### Use `doveadm -f flow fetch` for the first message-summary path

The second WP5 slice uses `doveadm -f flow fetch` with a small field set
(`uid`, `flags`, `date.received`, `size.virtual`, and `mailbox`) so the runtime
can retrieve bounded message summaries without committing to a larger IMAP
dependency before message-view work forces that choice.

### Keep message-list summaries intentionally content-light

The first message-list model records identifiers, flags, date, size, and
mailbox membership, but not message subjects, snippets, or bodies. This keeps
the runtime honest about what has actually been implemented and avoids turning
the audit/event path into a message-content mirror.

### Keep `nginx` as the planned edge layer for the browser service

The current architecture continues to assume `nginx` at the edge with OSMAP
behind it on a local listener or socket. This preserves the existing OpenBSD
deployment posture and keeps public-facing HTTP/TLS concerns out of the
application runtime.

### Use mailbox plus UID as the first bounded message-view request key

The first WP6 slice identifies a message by validated mailbox name plus IMAP
UID. That is enough to retrieve one bounded message payload without inventing a
larger browser-facing query model too early.

### Keep the first fetched message payload honest and non-rendering-oriented

The first message-view slice fetches metadata, full header text, and body text,
but it does not claim to have solved MIME parsing, HTML transformation, or
attachment policy. Rendering remains a separate follow-on step rather than an
implicit side effect of retrieval.

### Keep the first browser rendering mode plain-text-first

The first rendering layer turns fetched body text into escaped browser-safe text
inside a preformatted block. This keeps hostile HTML from becoming active
markup while the project is still proving the message-read path.

### Limit the first rendered header summary to a small safe subset

The current renderer only extracts `Subject` and `From`, with conservative
header unfolding and bounded values. Full header presentation and MIME-aware
interpretation remain later work rather than hidden complexity in the first
rendering step.

### Keep MIME parsing as a small inspection layer instead of a rendering engine

The next WP6 step adds MIME-aware classification, but it keeps that logic in a
separate bounded analysis layer. The renderer consumes MIME decisions rather
than parsing arbitrary structures ad hoc during browser transformation.

### Prefer plain-text part selection over HTML interpretation

When a message is multipart and includes both plain text and HTML, the current
prototype should select the plain-text part and keep HTML content withheld.
This preserves readability for common mail while keeping hostile markup out of
the browser path.

### Surface attachment metadata before attachment download behavior exists

The current runtime now exposes part path, file name, content type,
disposition, and a size hint for attachment-like parts. That gives later UI and
download work an honest substrate without pretending attachment retrieval is
already implemented.

### Keep bootstrap validation and HTTP serving as separate run modes

The binary now supports both `bootstrap` and `serve` modes. This keeps startup
verification and fast test runs simple while allowing the first real HTTP slice
to exist without making every invocation start a listener.

### Keep the first browser slice framework-free and server-rendered

The first HTTP/browser implementation uses a small handwritten request parser,
router, and HTML rendering path instead of adopting a full web framework. That
keeps the request boundary explicit while the product is still proving its
shape.

### Keep the first browser login flow single-step while preserving MFA layers

The first browser login page accepts username, password, and TOTP in one form.
This simplifies the HTML flow, but the runtime still executes separate primary
credential, second-factor, and session-issuance stages underneath that form.

### Start browser session cookies with strict transport and cache posture

The current browser slice uses `HttpOnly` and `SameSite=Strict` cookies, sets
`Secure` outside development, suppresses cache storage on sensitive responses,
and emits a restrictive content-security policy. This is the current minimum
browser posture, not the endpoint of hardening work.

### Use the local `sendmail` compatibility surface for the first outbound slice

The first browser send path should hand a bounded plain-text message to the
host's existing submission surface through `/usr/sbin/sendmail` rather than
inventing a new SMTP client inside OSMAP.

### Keep the first compose slice plain-text-only and attachment-free

The initial outbound form should prove recipient validation, message handoff,
and audit behavior first. Attachments, reply/forward helpers, and richer
composition behavior remain later work.

### Bind CSRF control to persisted session state

The current browser runtime now stores a CSRF token with each session record
and requires that token on the current state-changing form routes. This keeps
browser write protection tied to the same explicit session lifecycle already
used for auth and revocation.

### Keep the first OSMAP HTTP deployment loopback-only behind nginx

The current browser runtime should continue to assume `nginx` at the edge and
OSMAP on a local-only TCP listener. This preserves the narrow deployment model
and keeps public HTTP/TLS behavior out of the application process.

### Treat `pledge(2)` and `unveil(2)` as implementation work driven by the real access graph

The prototype is now concrete enough to map likely confinement boundaries:
bounded state directories, one local listener, `doveadm`, and `sendmail`.
Runtime enforcement should be added from that real surface, not from generic
theory.

### Build reply and forward as server-side draft generation first

The next send-path step should reuse the existing message-view and plain-text
rendering layers to generate reply and forward drafts on the server side. This
keeps the browser simple and avoids trusting live HTML message content during
outbound composition.

### Make attachment handling explicit before real upload exists

The current reply and forward flow should be attachment-aware even before file
upload or reattachment exists. Drafts now carry attachment notices and forward
metadata so the product does not silently drop attachment context while
pretending the action is complete.

### Introduce an operator-controlled OpenBSD confinement mode

The runtime now exposes `disabled`, `log-only`, and `enforce` confinement
modes. This lets operators validate the promise and unveil plan before they
commit to enforcement on a live OpenBSD host.

### Enforce a first helper-compatible `pledge(2)` and `unveil(2)` boundary now

The current serve runtime now applies a real OpenBSD confinement boundary when
enforcement is enabled. The unveiled filesystem view is still broader than the
final target because `doveadm` and `sendmail` remain external helper
dependencies, but the process is no longer relying on confinement as a future
idea only.

### Record live browser-auth caveats exactly as observed

The current browser-driven invalid-login path on `mail.blackbagsecurity.com`
produced the same `doveadm` backend error with confinement disabled and
enabled. That behavior should be tracked as a host/browser integration caveat,
not misclassified as a confinement regression.

### Remove non-required SHA-1 from session and CSRF derivation

The browser session layer should keep HMAC-SHA1 only where standards require it
for TOTP compatibility. Persisted session identifiers and per-session CSRF
tokens now use domain-separated SHA-256 derivation from the opaque bearer
token, which improves the non-TOTP cryptographic baseline without widening the
runtime design.

### Add bounded new attachment upload before original-message reattachment

The send path now accepts bounded new file uploads and submits them through the
existing local `sendmail` surface as MIME attachments. That closes a real user
workflow gap without pretending reply and forward can already reconstruct the
source message's attachment set.

### Keep multipart parsing separate from the router

The browser runtime now uses a dedicated form-parsing module for URL-encoded
and multipart compose inputs. This keeps `src/http.rs` from absorbing even more
protocol and boundary-handling detail while the custom HTTP surface is still
under active hardening.

### Narrow OpenBSD helper paths based on live host evidence

The enforced `unveil(2)` view no longer exposes all of `/var` and `/etc`.
Instead it now uses helper-specific paths such as `/etc/dovecot`,
`/etc/mailer.conf`, `/var/spool/postfix`, and `/var/dovecot`, which is a more
honest and reviewable boundary for the current host-integrated prototype.

### Add `fattr` to the steady-state OpenBSD promise set

Live enforced-host testing showed that session refresh updates file permissions
on temp session records during save. The confinement policy now includes
`fattr` explicitly so the reviewed promise set matches the real file-state
behavior instead of relying on an accidentally incomplete abstraction.

### Reuse the existing message-view and MIME part-path model for downloads

Attachment download now rides on top of the current mailbox-plus-UID message
view and MIME part-path model. OSMAP is not adding a second attachment storage
or retrieval namespace just to make browser downloads convenient.

### Force attachment downloads instead of adding preview behavior

The first attachment route uses forced-download headers, conservative filename
sanitization, and `nosniff`. The project should not widen browser trust by
normalizing inline preview behavior before the simpler download path is proven.

### Treat enforced synthetic-session attachment results as real evidence

Live OpenBSD validation now proves that a synthetic file-backed session can be
validated and refreshed on disk under `enforce`, and that the attachment route
itself is reachable under that boundary. The remaining `doveadm` stats-writer
problem observed on `mail.blackbagsecurity.com` should be tracked as a helper
integration caveat, not hand-waved away.

### Suppress ancillary `doveadm` stats-writer dependencies in helper calls

The current helper invocations now pass `-o stats_writer_socket_path=` for the
auth and mailbox read paths. This keeps OSMAP closer to the credential and
mailbox behavior it actually needs and removes avoidable stats-writer socket
noise from live helper failures on the target host.

### Add per-connection HTTP read and write timeouts before widening the listener

The HTTP runtime is still sequential, so one slow client can matter
operationally. The listener now configures conservative read and write
timeouts on each connection to reduce the chance of an indefinitely stalled
client pinning the process while broader HTTP hardening continues.

### Treat the remaining live browser-auth caveat as a host auth-socket issue

Current live-host diagnosis shows that the unresolved browser-auth caveat on
`mail.blackbagsecurity.com` is now the Dovecot auth-socket accessibility
boundary for the runtime user, not the old stats-writer behavior and not the
OpenBSD confinement mode itself. OSMAP should not solve that by growing
privileges; it should be addressed as deliberate host-side operator work.

### Treat `clippy` and `rustfmt` as part of the OpenBSD validation baseline

The project's `Makefile` already exposes `make lint` and `make fmt-check`, so
the OpenBSD host and project-local QEMU workflows should install
`rust-clippy` and `rust-rustfmt` rather than normalizing silent tool absence.
That keeps the validation story consistent for sysadmins and collaborating
developers working on the real target platform.

### Add explicit repository-level community standards files

The public repository now carries explicit collaboration files for conduct,
contributions, security reporting, support guidance, issue intake, pull request
review, and licensing. Those files should reflect OSMAP's real project posture:
bounded scope, security-first review, OpenBSD-friendly maintenance, and private
handling of sensitive reports rather than generic open-source boilerplate.

### Use an ISC license as the default public license posture

OSMAP's public repository now uses the ISC license. That is a deliberate fit
for the project's OpenBSD-oriented goals: simple text, permissive reuse, and a
low-friction licensing posture for conservative downstream operators and
packagers.

### Expose the auth socket path as explicit operator configuration

OSMAP now supports an optional `OSMAP_DOVEADM_AUTH_SOCKET_PATH` setting instead
of forcing the browser-auth path to depend on hidden host defaults. This keeps
the least-privilege Dovecot auth listener arrangement explicit in deployment,
startup reporting, and confinement planning.

### Reject ambiguous HTTP request shapes earlier in the parser

The HTTP runtime now fails closed on duplicate headers, oversized request
targets, fragment-bearing targets, and HTTP/1.1 requests that omit `Host`.
These checks reduce ambiguity in the custom parser before any additional
browser-facing surface is added.

### Configure a dedicated Dovecot auth listener for the OSMAP runtime user

`mail.blackbagsecurity.com` now exposes a dedicated `/var/run/osmap-auth`
listener owned by `_osmap` for OSMAP's browser-auth path. That keeps the host
integration explicit and least-privilege friendly instead of teaching the app
to depend on `doas` or on the Postfix-facing auth socket.

### Normalize peer socket addresses to bare IP strings before auth-helper use

Live host validation exposed that `doveadm auth test` rejects `rip=` values
that include a port. OSMAP now normalizes peer addresses to bare IP strings at
the HTTP edge, which keeps auth-helper metadata valid and makes request audit
logs more consistent.

### Add an explicit Dovecot userdb socket path for mailbox helpers

OSMAP now supports `OSMAP_DOVEADM_USERDB_SOCKET_PATH` so mailbox, message-list,
and message-view helpers can target a dedicated least-privilege Dovecot userdb
listener instead of inheriting a broader default path.

### Treat positive live auth and mailbox reads as separate proof points

Live validation on `mail.blackbagsecurity.com` now proves positive browser
login, TOTP completion, and session issuance under `_osmap` with enforced
confinement. It does not yet prove mailbox reads under `_osmap`.

### Record the remaining live mailbox blocker as a Dovecot identity boundary

The current post-auth live-host blocker is no longer auth-socket reachability.
It is Dovecot's virtual-mail identity model: mailbox helpers resolve to
`uid=2000(vmail)` and `gid=2000(vmail)`, which an unprivileged `_osmap`
process cannot assume without widening authority.

### Keep the web-facing runtime unprivileged and move mailbox reads behind a helper boundary

The selected next-step answer to the Dovecot mailbox identity boundary is not
to run the web-facing OSMAP service as `vmail` and not to introduce `doas` into
the request path. The web-facing runtime should remain unprivileged while
mailbox reads move behind a dedicated local helper boundary.

### Treat direct `doveadm` mailbox execution from the web process as a prototype bridge

The current direct `doveadm` mailbox-read path remains useful for a bounded
prototype because it already has validation, bounded parsing, and audit seams.
It should no longer be treated as the likely final least-privilege shape on the
current host.

### Start the mailbox helper migration with mailbox listing only

The first in-repo mailbox-helper slice now exists, but it is intentionally
narrow: local Unix-domain socket transport plus mailbox listing only. The
project will migrate the broader read path one operation family at a time
instead of rewriting mailbox access in one large jump.

### Extend the mailbox helper migration to message-list retrieval

The next helper-backed read operation is now in place too: message-list
retrieval can use the local mailbox helper when configured. Message view and
attachment retrieval remain on the direct prototype path for now.

### Extend the mailbox helper migration to message-view retrieval

The next helper-backed read operation is now in place as well: bounded
single-message retrieval can use the local mailbox helper when configured. This
finishes the core mailbox read-path migration through message view without yet
claiming helper-backed attachment bytes or live-host proof under the `vmail`
boundary.

### Keep attachment downloads on the helper-backed read path when configured

The attachment route now reuses the helper-backed message-view fetch path when
`OSMAP_MAILBOX_HELPER_SOCKET_PATH` is configured. This avoids leaving one
browser read path on direct `doveadm` execution after the rest of the mailbox
read surface has moved behind the helper boundary.

### Give the mailbox helper its own OpenBSD confinement shape

The `mailbox-helper` run mode now has a distinct OpenBSD confinement plan with
`unix` socket promises and without the sendmail and TCP listener allowances the
browser-facing `serve` runtime still needs. That keeps the helper boundary
explicit in both process layout and confinement policy.

### Keep helper-owned socket creation create-capable under `unveil(2)`

Live host validation showed that the helper could reach enforced confinement but
still fail before serving requests because its own socket path had been
unveiled as read/write rather than read/write/create. The helper runtime now
keeps `rwc` on its explicit socket path while the web-facing runtime keeps the
narrower connect-only view.

### Keep helper-backed serve mode on `inet` plus `unix`, not `unix` alone

When the browser-facing runtime uses the local mailbox helper, it still has to
bind and serve loopback HTTP. The serve-mode promise set therefore now keeps
both `inet` and `unix` instead of incorrectly switching to the helper-only
`unix` profile.

### Treat live `doveadm -f flow fetch` output as the parser truth

Live host validation showed two real parser mismatches: unquoted
`date.received` values in message-list output and multiline `hdr=` / `body=`
output in single-message fetches. The bounded Dovecot flow parser now handles
those live formats explicitly instead of only the idealized quoted forms used
earlier in tests.

### Prove the helper-backed read path under `enforce` on the target host

Live validation on `mail.blackbagsecurity.com` now proves a narrower and more
useful claim than earlier slices did:

- `_osmap` can authenticate through `/var/run/osmap-auth`
- the mailbox helper can resolve mailbox reads through `/var/run/osmap-userdb`
  while running at the `vmail` boundary
- mailbox listing, message-list retrieval, message view, and attachment
  download all succeed under `OSMAP_OPENBSD_CONFINEMENT_MODE=enforce`

This does not yet replace broader end-to-end browser coverage, but it does
prove that the selected `_osmap` plus local helper plus `vmail` split works on
the current host without teaching OSMAP to depend on `doas`.

### Treat real login plus helper-backed reads as the new live-proof baseline

The current host proof no longer stops at synthetic session setup. On
`mail.blackbagsecurity.com`, OSMAP now has a continuous enforced-confinement
browser trace that starts with real password-plus-TOTP login and carries the
issued session cookie through helper-backed mailbox listing, message view, and
attachment download.

That makes the authenticated read path a proven live behavior rather than only
an inferred combination of smaller proofs.

### Drop `/var/dovecot` and `/var/log/dovecot.log` from the confinement plan

The earlier confinement plan kept those Dovecot paths because the helper
dependency picture was still fuzzy. Follow-on live validation now shows the
current auth socket, userdb socket, mailbox helper, and attachment-read flows
work without direct unveil access to either path.

The active OpenBSD confinement plan therefore removes both paths instead of
keeping them as speculative helper allowances.

### Reject unsupported HTTP request framing instead of guessing

The custom HTTP runtime now makes its request-framing boundary more explicit:

- `Transfer-Encoding` is rejected because OSMAP does not implement chunked or
  alternate body framing
- GET requests with bodies are rejected instead of being accepted as undefined
  edge cases
- POST requests must carry an explicit `Content-Length`

That keeps the sequential custom parser smaller and less ambiguous rather than
trying to be liberal in ways that widen smuggling and malformed-request risk.

### Accept only one valid session cookie and one canonical route form

The browser runtime now treats the session cookie and request path more
strictly:

- the session cookie parser now accepts only one valid OSMAP session token
- malformed or duplicate session-cookie candidates are ignored instead of being
  guessed at
- non-canonical path forms such as repeated slashes, trailing-slash aliases,
  `.` segments, and `..` segments are rejected before routing

That reduces ambiguity at the request boundary without changing any legitimate
browser path OSMAP currently emits.

### Reject ambiguous form fields and unsupported login/logout body types

The browser runtime now treats form parsing more strictly as well:

- duplicate query or form field names are rejected instead of silently
  overwriting earlier values
- empty field names are rejected instead of being treated as unnamed input
- `POST /login` and `POST /logout` accept only URL-encoded form bodies instead
  of guessing at other content types

That keeps the browser boundary smaller and more reviewable by refusing body
shapes the current routes do not need.

### Bound high-risk header values and keep browser responses same-origin

The browser runtime now treats a few request and response headers more
conservatively:

- `Host`, `Cookie`, and `Content-Type` now have explicit smaller bounds instead
  of inheriting only the total header-budget limit
- empty or obviously malformed `Host` values are rejected before routing
- the current HTML, redirect, and attachment responses now carry
  `Cross-Origin-Resource-Policy: same-origin`

That reduces request-boundary trust in attacker-controlled headers and keeps
browser-visible responses more consistent without changing the current route
surface.

### Reconcile Version 1 targets against the actual repository state

The repository now implements far more than an early design skeleton, but it
still does not satisfy every Version 1 product requirement. The current docs
should say that plainly.

At that point in the implementation, the active product gaps were recorded as:

- message search
- folder operations such as move or archive
- browser-visible session or device management
- safe HTML email rendering beyond the current plain-text-first posture
- a bounded first-release settings surface

That keeps execution priorities honest and avoids letting implementation depth
in some areas imply that Version 1 is feature-complete when it is not.

### Add a first browser-visible session-management page before broader feature work

The session core already tracked issuance, expiry, last-seen, revocation,
remote address, and user-agent metadata. The next useful slice was therefore
not a bigger mail feature, but a thin browser view over those existing
primitives.

The browser layer now includes:

- a `/sessions` view backed by the existing per-user session listing primitive
- CSRF-bound self-service revocation by persisted session identifier
- explicit ownership checks so a user can revoke only their own session
  records

That closes one real Version 1 gap with minimal new trust surface and without
inventing a heavier device-management subsystem.

### Prove the session-management browser slice on the live OpenBSD host

The first `/sessions` and `POST /sessions/revoke` slice is now validated on
`mail.blackbagsecurity.com` under the real `_osmap` plus `vmail` split with
`OSMAP_OPENBSD_CONFINEMENT_MODE=enforce`.

That proof used a synthetic persisted session store rather than live mailbox
credentials, because the goal of this slice was to validate the new
session-management routes themselves:

- `GET /sessions` returned `200`
- revoking a non-current session returned `303` to `/sessions?revoked=1`
- revoking the current session returned `303` to `/login` and cleared the
  browser cookie
- both targeted session records were updated with `revoked_at`

This keeps the live proof narrow and high-confidence while still exercising the
real deployment split and confinement mode.

### Add a first mailbox-scoped backend-authoritative search slice

The next Version 1 gap to close should widen end-user capability, not just
browser hardening. Search is useful, but the first slice should stay narrow and
reuse the existing authority boundaries.

The browser layer now includes:

- a `GET /search` route that requires an authenticated session and a mailbox
  scope plus one free-text query
- backend-authoritative search execution through Dovecot rather than
  browser-side filtering
- helper-backed search proxying when the mailbox helper socket is configured,
  preserving the lower-authority web runtime shape
- bounded search result rendering that surfaces enough metadata to navigate to
  the matching message without inventing a broader query DSL

This closes the explicit browser-search gap while keeping the first search
model mailbox-scoped and intentionally simple.

### Treat mailbox-scoped search as implemented, not as a remaining Version 1 gap

The repository now proves that mailbox-scoped search exists in the browser
runtime, the helper path, and the tests. Product and status documents should no
longer list search as wholly unimplemented.

The honest current state is narrower:

- mailbox-scoped backend-authoritative search is implemented
- cross-mailbox or richer query ergonomics remain future refinement

That keeps the repo aligned with what the code actually delivers instead of
letting stale status language misdirect the next work.

### Add a first helper-compatible one-message move slice

The next meaningful ordinary-use gap after search and session self-management
was folder organization. The smallest coherent slice was one-message move
between existing mailboxes, not bulk actions or an archive abstraction.

The browser and mailbox layers now include:

- a validated one-message move request
- backend-authoritative `doveadm move` execution
- helper-backed move proxying when the mailbox helper socket is configured
- a CSRF-protected `POST /message/move` route
- a server-rendered move form on the message-view page
- bounded audit events for move success and failure

This closes the first folder-organization gap while preserving the helper
boundary instead of teaching the web-facing runtime to own mailbox-write
authority directly.

### Add a repo-owned CWE Top 25 security-check workflow for the Rust backend

The Rust backend now has enough real implementation depth that informal
"remember to review it carefully" guidance is no longer a sufficient security
gate.

The repository now includes:

- a shared `make security-check` entrypoint
- a repo-owned pre-commit hook path under `.githooks/`
- a current `CWE_TOP25_REVIEW_BASELINE.md` document tied to the actual code and
  current MITRE Top 25 list

The current gate is intentionally narrow and concrete. It runs the standard
Rust validation entrypoints and also fails if:

- new `unsafe` code appears outside the reviewed OpenBSD FFI boundary
- shell-based command execution appears in the Rust backend
- new direct `Command::new` call sites appear outside the reviewed auth
  command-execution boundary

This does not claim that OSMAP is free of all dangerous weakness classes. It
does establish a repeatable, repo-owned security review baseline so future Rust
changes are vetted more systematically before commit.

### Keep GitHub default CodeQL setup authoritative until the repository
explicitly transitions to advanced setup

The repository previously carried an always-on advanced CodeQL workflow. That
configuration conflicted with GitHub default CodeQL setup and caused SARIF
processing failures instead of useful alerts.

OSMAP now treats GitHub default CodeQL setup as the authoritative CodeQL
scanner while that repository setting remains enabled. The repo-owned
authoritative CI workflow is now the GitHub Actions `security-check` job, which
mirrors `make security-check`.

The repository still keeps a manual `codeql-advanced` workflow template, but it
is an explicit future-transition path, not the active CodeQL authority. It
should only be used after maintainers intentionally disable default CodeQL
setup in repository settings.

The workflow files should prefer Node 24-capable action versions directly over
the temporary `FORCE_JAVASCRIPT_ACTIONS_TO_NODE24=true` compatibility switch.
That keeps the repository on the cleaner long-term pattern instead of carrying
an unnecessary migration flag once the referenced actions have current Node 24
support.

### Treat runner-side clippy and rustfmt as part of the authoritative Rust
security gate

The first `security-check` GitHub Actions run failed even though the local
pre-commit path had passed, because the runner had `clippy` and `rustfmt`
installed and surfaced real lint debt that the stripped-down local cargo
environment did not exercise.

That failure was resolved by fixing the Rust code to satisfy the stricter gate,
not by weakening the workflow. OSMAP should continue to treat runner-side
`cargo clippy --all-targets -- -D warnings` and `cargo fmt --check` as part of
the authoritative backend quality bar.

### Investigate GitHub Actions failures from live workflow state before
changing workflow files

The recent GitHub Actions failure around commit `6b3778b` looked at first like
a workflow-definition problem, but direct review of the live workflow runs
showed the actual failing job was the repo-owned `security-check` gate rather
than CodeQL.

That distinction mattered. The correct fix was:

- inspect the live workflow set and run outcomes on GitHub first
- reproduce the stricter runner-side Rust toolchain locally
- fix the Rust lint and formatting debt the runner exposed
- only keep workflow edits that improve the long-term repository posture

OSMAP should continue to treat GitHub-hosted workflow state as the source of
truth for CI failure diagnosis, then reconcile local reproduction against that
evidence before changing YAML.

### Keep public status documents synchronized with the current browser,
helper, and CI reality

By late Phase 6, the project had accumulated enough real implementation depth
that several public-facing documents were at risk of lagging behind the code.
In particular, the docs index, HTTP/browser baseline, and work decomposition
needed to reflect:

- browser-visible session management
- mailbox-scoped search and one-message move in the browser layer
- helper-backed attachment-read behavior
- live enforced-host proof for the authenticated read path
- the repo-owned GitHub `security-check` lane as part of the operational
  documentation set

Status-facing documents should continue to be corrected as soon as the repo
proves a new reality, rather than being left at an earlier phase milestone.

### Let security, Rust, and OpenBSD best practice win over convenience

OSMAP should not treat "it works" as a sufficient design standard when a
clearer or safer option is established practice in the security, Rust, or
OpenBSD communities.

When those communities offer relevant best practice, the project should bias
toward:

- explicit trust boundaries over convenience shortcuts
- reviewable memory-safe and parser-safe design over cleverness
- OpenBSD-native operational discipline over cross-platform convenience hacks

That principle does not eliminate engineering judgment, but it does set the
default direction: convenience should justify itself against stronger practice,
not the other way around.

### Anchor best-practice language to current upstream guidance

The project's "best practices win" rule should point to concrete, current
sources rather than remain generic. For current design and SDLC judgment,
OSMAP now explicitly treats OpenBSD `pledge(2)` and `unveil(2)`, Rust API
Guidelines and RustSec guidance, OWASP ASVS, and current GitHub code-scanning
documentation as the primary external reference set.

### Treat `docs/` as the source of truth for project documentation

OSMAP should keep project, architecture, security, operational, and
implementation documents under `docs/` by default. The main exceptions are the
repository `README.md`, licensing or build metadata, and the small set of
root-level or `.github/` files that GitHub detects specially for community and
workflow behavior.

## 2026-04-02

### Add a first bounded application-layer login-throttling slice

The browser auth path now applies a small file-backed login throttle before the
auth backend is reached. The first slice is intentionally narrow:

- keyed by presented username plus remote address
- bounded by explicit threshold, window, and lockout settings
- stored under the existing cache boundary
- integrated into the current server-rendered browser login flow

This does not claim that auth abuse resistance is fully solved. It does mean
OSMAP no longer depends entirely on external rate limiting for the first layer
of browser-login brute-force friction.

### Start a behavior-preserving `http.rs` decomposition pass

`src/http.rs` had grown large enough that reviewability risk was becoming a
practical concern in the browser boundary. The first decomposition pass is
intentionally conservative:

- move shared response, escaping, and event-building helpers into
  `src/http_support.rs`
- move server-rendered browser HTML helpers into `src/http_ui.rs`
- leave routing, parsing, and test behavior in `src/http.rs` unchanged

This is a maintainability and auditability refactor, not a feature change. The
goal is to reduce concentration of unrelated concerns in the browser-facing
runtime before later slices touch routing or parser structure more deeply.

### Continue `http.rs` decomposition by separating parser and request-shape code

After extracting response and UI helpers, the next highest-risk concentration in
`src/http.rs` was the parser and request-shape logic: header parsing, body
bounds, target normalization, cookie extraction, and compose-source decoding.

That code now lives in `src/http_parse.rs`, while `src/http.rs` re-exports the
public parse entrypoints and keeps routing behavior unchanged. This keeps the
observable request surface stable while making the custom HTTP boundary easier
to review in smaller, purpose-specific units.

### Split auth and session route handlers out of `http.rs`

The next concentrated concern inside `src/http.rs` was auth and session route
handling: login, logout, root redirect, session listing, session revocation,
and the validated-session / CSRF helpers those routes depend on.

Those handlers now live in `src/http/routes_auth.rs` as an internal child
module. That keeps the routing table in `src/http.rs` stable while reducing the
amount of authentication and session logic mixed into mail and compose route
code.

### Split mailbox and content routes out of `http.rs`

After separating auth and session flows, the next largest browser concern in
`src/http.rs` was the mailbox and content route set:

- mailbox home and mailbox message listing
- mailbox-scoped search
- message view
- attachment download
- first message move workflow

Those handlers now live in `src/http/routes_mail.rs` as an internal child
module. This keeps the dispatch table and transport loop stable while reducing
the amount of mailbox-specific browser logic mixed into compose/send and server
infrastructure code.

### Treat GitHub runner-side rustfmt as authoritative for style drift

The recent `http.rs` decomposition commits passed the local repo gate here, but
the GitHub `security-check / rust` workflow still failed on `main`. The root
cause was not a workflow bug and not a Rust logic regression. It was style
drift:

- local `make security-check` skipped `cargo fmt --check` because `rustfmt` was
  not installed in this environment
- the GitHub runner and the OpenBSD validation host did have `rustfmt`
- the extracted route and parser files were therefore functionally correct but
  not yet rustfmt-normalized

For this project, runner-side `cargo fmt --check` should be treated as an
authoritative CI signal. When the local environment lacks `rustfmt`, OSMAP
should prefer formatting from a toolchain-complete validation host before
assuming the workflow itself is broken.

### Split compose and send routes out of `http.rs`

The last large browser route family still sitting directly in `src/http.rs`
was the compose and submission flow:

- compose form rendering
- reply/forward draft preparation
- compose form parsing and submission
- submission error handling

Those handlers now live in `src/http/routes_compose.rs` as an internal child
module. This keeps the route table and server loop in `src/http.rs` stable
while reducing how much browser-side mutation logic remains mixed into parsing,
transport, and unrelated route concerns.

### Split mailbox-helper protocol out of `mailbox_helper.rs`

After the `http.rs` route extractions, the next clean maintainability target was
`src/mailbox_helper.rs`, which still combined:

- helper request and response types
- line-oriented protocol encoding and parsing
- protocol-specific field validation and base64 helpers
- Unix socket client and server transport wiring

The protocol types and parsing helpers now live in
`src/mailbox_helper_protocol.rs` as an internal child module of
`src/mailbox_helper.rs`. This keeps the helper transport boundary stable while
making the protocol itself easier to audit separately from the socket and
backend wiring.
