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

### Split mailbox parser helpers out of `mailbox.rs`

After reducing `http.rs` and then `mailbox_helper.rs`, the next largest
maintainability hotspot was `src/mailbox.rs`, which still mixed:

- mailbox service and backend trait definitions
- `doveadm` backend wiring
- the bounded flow-output parser cluster for mailbox, message-list,
  message-view, and message-search results

The Dovecot flow parser family now lives in `src/mailbox_parse.rs` as an
internal child module of `src/mailbox.rs`. This keeps the service and backend
interfaces stable while making the flow parser boundary easier to review
separately from mailbox business logic.

### Split mailbox service layer out of `mailbox.rs`

After moving the Dovecot parser cluster into `src/mailbox_parse.rs`,
`src/mailbox.rs` still combined:

- mailbox outcome and trait definitions
- validated-session service logic and audit-event construction
- `doveadm` backend implementations

The validated-session service layer and its bounded audit-event helpers now
live in `src/mailbox_service.rs` as an internal child module of
`src/mailbox.rs`, with the service types re-exported so the public mailbox API
stays stable. This keeps service logic easier to review separately from command
construction and backend execution details.

### Treat repeated GitHub security-check failures as runner-side rustfmt drift

The current April 2 refactor commits continued to show red commit badges on
GitHub even after the code and tests stayed behaviorally sound. Direct
inspection of the live checks confirmed:

- `security-check / rust` was the failing check
- both CodeQL `Analyze` jobs were green for those same commits
- the failing step was still `run repo security gate`
- the concrete failure was repeated `cargo fmt --check` drift on extracted Rust
  modules, while `cargo clippy --all-targets -- -D warnings` remained clean

For this project, repeated GitHub Actions failures of that shape should be
treated as a formatting synchronization issue, not as evidence that CodeQL or
the workflow design itself is broken. When the local workstation lacks
`rustfmt`, OSMAP should normalize Rust formatting from a toolchain-complete
validation host before pushing structural refactors.

### Prefer Linux-runner formatting reproduction for persistent `fmt` drift

The remaining red `security-check / rust` status after the first April 2
format-normalization commit was not a new logic defect. Reproducing the gate
with an isolated Linux `rustup` toolchain showed the concrete mismatch:

- one extra blank line in `src/http.rs`
- `cargo fmt --check` on Linux was still red
- `cargo clippy --all-targets -- -D warnings` was already green

For this project, when OpenBSD-side formatting looks clean but GitHub's Linux
runner still fails `cargo fmt --check`, the authoritative reproduction should
be a Linux toolchain that matches the runner's Rust formatting path. That
keeps CI fixes narrow and prevents unnecessary workflow churn.

### Split `doveadm` backends out of `mailbox.rs`

After moving parser helpers into `src/mailbox_parse.rs` and validated-session
services into `src/mailbox_service.rs`, `src/mailbox.rs` still carried all of
the concrete `doveadm` backend implementations for:

- mailbox listing
- message listing
- message view
- message search
- one-message move

Those backend implementations now live in `src/mailbox_backend.rs`, with the
existing `Doveadm*Backend` types re-exported from `src/mailbox.rs` so the
public mailbox API stays stable. This keeps command construction and backend
execution details easier to review separately from mailbox domain types and
service outcomes.

### Split helper server dispatch from `mailbox_helper.rs` transport plumbing

After moving the helper protocol into `src/mailbox_helper_protocol.rs`,
`src/mailbox_helper.rs` still combined:

- Unix socket listener and bounded read/write transport helpers
- client backend implementations for helper consumers
- server-side request dispatch into mailbox backends
- helper-specific operation logging

The server-side request dispatch and helper-response logging now live in
`src/mailbox_helper_dispatch.rs`, while `src/mailbox_helper.rs` keeps the
socket transport and helper client plumbing. This reduces reviewer load at the
least-privilege mailbox helper boundary without changing helper protocol or
runtime behavior.

### Split HTTP transport and top-level dispatch out of `http.rs`

After moving parser helpers, UI helpers, and route families out of
`src/http.rs`, the module still combined:

- the top-level `BrowserApp` request dispatch match
- the sequential listener startup path
- per-connection request/response transport handling
- the synthetic HTTP request-id counter

Those pieces now live in `src/http_runtime.rs`, with `run_http_server` still
re-exported from `src/http.rs` so the external interface stays stable. This
keeps the browser-boundary runtime flow easier to review separately from the
HTTP types, browser gateway contracts, and runtime gateway wiring.

### Split HTTP runtime gateway wiring out of `http.rs`

After moving parser helpers, route families, and the transport/runtime loop out
of `src/http.rs`, the module still combined:

- runtime gateway construction from validated configuration
- browser-gateway adapter wiring across auth, session, mailbox, send, and
  attachment services
- helper-aware backend selection for read and move operations
- the concrete runtime backend enums that bridge direct and helper-backed
  mailbox flows

Those pieces now live in `src/http_gateway.rs`, with
`RuntimeBrowserGateway` still re-exported from `src/http.rs` so the public
browser-layer interface stays stable. This keeps `http.rs` closer to its
intended role as the home for HTTP types and browser contracts rather than the
full runtime assembly point.

### Split browser contracts out of `http.rs`

After moving parser helpers, route families, the transport/runtime loop, and
the runtime gateway assembly out of `src/http.rs`, the module still carried a
large cluster of browser-facing contract definitions:

- the `BrowserGateway` trait
- browser-visible outcome and decision types for login, session, mailbox,
  message, attachment, move, and send flows
- browser-safe session metadata shared between runtime adapters and routes

Those browser-layer contracts now live in `src/http_browser.rs`, with the
existing public types re-exported from `src/http.rs` so route modules and tests
continue to use the same interface. This keeps `http.rs` more focused on core
HTTP types and the browser application shell while making the browser contract
surface easier to audit independently.

### Split mailbox domain models out of `mailbox.rs`

After moving parser helpers, backend implementations, and service wiring out of
`src/mailbox.rs`, the module still carried a large cluster of mailbox-specific
domain contracts:

- mailbox and message policy bounds
- validated mailbox request types for list, search, view, and move operations
- mailbox and message summary/view structs
- mailbox public-failure and audit-failure enums
- mailbox outcomes and backend traits

Those pieces now live in `src/mailbox_model.rs`, with the existing public
types re-exported from `src/mailbox.rs` so the mailbox API remains stable for
backends, services, helper code, routes, and tests. This keeps `mailbox.rs`
closer to the narrower role it has after the earlier parser and service splits,
and makes the mailbox domain surface easier to audit independently from parser
and backend execution code.

### Split helper client backends out of `mailbox_helper.rs`

After moving the helper protocol into `src/mailbox_helper_protocol.rs` and the
server-side dispatch into `src/mailbox_helper_dispatch.rs`,
`src/mailbox_helper.rs` still combined:

- helper Unix-socket listener and bounded transport helpers
- client backend adapters used by the web-facing runtime
- helper test harness code

The repeated client-side Unix-socket request/response adapters now live in
`src/mailbox_helper_client.rs`, with the existing
`MailboxHelper*Backend` types re-exported from `src/mailbox_helper.rs` so the
public helper-backed mailbox API stays stable. This keeps the least-privilege
helper transport boundary easier to review by separating client proxy behavior
from listener lifecycle and server plumbing.

### Split helper-aware mailbox backend selection out of `http_gateway.rs`

After moving browser contracts, route families, and transport logic out of the
HTTP boundary, `src/http_gateway.rs` still combined:

- high-level browser flow orchestration
- runtime gateway construction from validated configuration
- helper-versus-direct mailbox backend selection for list, search, view, and
  move operations
- the concrete runtime backend enums that bridge those mailbox flows

That mailbox backend selection layer now lives in
`src/http_mailbox_backends.rs` as an internal child module of
`src/http_gateway.rs`. This keeps `http_gateway.rs` more focused on browser
workflow assembly while making the helper-aware mailbox backend boundary easier
to audit separately from login, session, rendering, and submission flow logic.

### Split auth and session gateway flows out of `http_gateway.rs`

After moving helper-aware mailbox backend selection into
`src/http_mailbox_backends.rs`, `src/http_gateway.rs` still combined:

- browser login flow orchestration
- session validation, logout, session listing, and session revocation
- auth/session service construction and browser-safe session projection helpers
- mailbox, rendering, attachment, and submission flow wiring

The auth and session browser-flow cluster now lives in
`src/http_gateway_auth.rs` as an internal child module of
`src/http_gateway.rs`. This keeps `http_gateway.rs` more focused on mailbox,
rendering, attachment, and submission orchestration while making the browser
auth/session boundary easier to review separately from the rest of the runtime
gateway assembly.

### Split mailbox, rendering, attachment, and submission flows out of `http_gateway.rs`

After moving auth/session flow logic into `src/http_gateway_auth.rs`,
`src/http_gateway.rs` still combined:

- mailbox list and mailbox message-list browser flows
- mailbox search and message-view browser flows
- attachment-download orchestration
- submission and one-message move browser flows
- the remaining submission and attachment service builders

That browser workflow cluster now lives in `src/http_gateway_mail.rs` as an
internal child module of `src/http_gateway.rs`. This keeps the gateway root
much closer to a thin runtime-configuration and delegation shell, while making
the mailbox and submission browser-flow boundary easier to review separately
from auth/session and helper-aware backend selection.

### Reassess remaining real Version 1 and security gaps after the gateway refactors

After the latest browser-boundary and mailbox-boundary maintainability work,
the repository no longer needs to treat internal decomposition as the default
next priority. A fresh repo-grounded review now confirms:

- message search is implemented
- browser-visible session self-management is implemented
- the first one-message move workflow is implemented
- the live authenticated read path is proven on `mail.blackbagsecurity.com`

The remaining highest-confidence Version 1 product gaps are now:

- safe HTML mail rendering beyond the current plain-text-first withholding
  policy
- a bounded first-release end-user settings surface

The remaining highest-confidence active security and hardening gaps are now:

- broader auth-abuse and request-abuse resistance beyond the first browser
  login-throttling slice
- the correctness and availability constraints of the current sequential HTTP
  runtime
- broader live-host proof for mutation workflows such as send and move

Until a new hotspot materially harms auditability again, those product and
security gaps should outrank additional internal refactor work.

### Use an allowlist sanitizer for safe HTML rendering instead of a hand-rolled HTML filter

The first-release HTML rendering slice should not invent its own HTML parser or
sanitizer rules. OSMAP now uses a dedicated sanitizer crate with an explicit
allowlist policy and a narrow browser contract:

- only a small set of presentational tags is allowed
- only a narrow set of attributes is allowed
- only `http`, `https`, and `mailto` link schemes are allowed
- relative URLs are denied
- scriptable or external-fetch oriented tags such as `script`, `style`,
  `iframe`, `object`, `embed`, and `svg` are removed

This keeps the hostile-content boundary explicit and reviewable while avoiding
the long-term risk of a hand-rolled sanitizer.

### Keep plain-text fallback even when sanitized HTML is available

The safe-HTML rendering slice does not replace the existing plain-text-first
posture. Instead, OSMAP now supports two explicit rendering modes:

- `plain_text_preformatted`
- `sanitized_html`

When plain text exists, compose, reply, and forward generation still stay on
plain text. Even when HTML is rendered for browser reading, the browser and
outbound composition boundary does not start trusting HTML as the canonical
message body.

### Use the first bounded settings surface only for HTML display preference

The first bounded settings slice should expose one meaningful user-facing
control without becoming a broad preference platform. OSMAP now exposes a
session-gated, CSRF-bound settings page that currently stores one preference:

- whether HTML-capable messages prefer sanitized HTML rendering
- or prefer plain-text fallback when plain text is available

This closes the first-release settings gap in a way that fits the existing
threat model instead of opening a broad browser-local preference surface.

### Store end-user settings under the explicit state boundary

End-user settings should live under the same explicit state model as sessions,
TOTP secrets, audit files, and cache data. OSMAP now stores user settings
under `OSMAP_SETTINGS_DIR` with:

- one file per canonical username
- a SHA-256-derived filename with stable domain separation
- atomic replacement semantics
- `0600` permissions on Unix-like systems

That keeps the first settings slice compatible with the existing OpenBSD state
ownership and confinement model.

### Validate the HTML rendering and settings slice through the repo-owned gate locally and on `mail.blackbagsecurity.com`

The safe-HTML and settings slice was validated through the repo-owned
`make security-check` gate in two environments:

- a strict local Rust toolchain environment with `cargo test`, `clippy`, and
  `fmt --check`
- `mail.blackbagsecurity.com` under the host-local OpenBSD Rust toolchain

That validation covered the new sanitizer-backed rendering path, the bounded
settings surface, the settings-backed browser gateway integration, and the
updated route surface under the same gate the repository expects for normal
development.

### Tighten the repo-owned `unsafe` scan to match Rust syntax instead of prose

The repo-owned `security-check` script originally matched any line containing
`unsafe` followed by whitespace. The new HTML rendering notice text included
the phrase "unsafe URLs", which triggered a false positive even though no new
Rust `unsafe` block existed outside `src/openbsd.rs`.

The guard now looks for Rust syntax forms instead:

- `unsafe {`
- `unsafe fn`
- `unsafe impl`
- `unsafe trait`

This keeps the gate aligned with the project's real safety goal: catch
unreviewed Rust `unsafe`, not user-facing prose.

### Prove the safe-HTML rendering and settings slice on the live OpenBSD host

The safe-HTML rendering and settings slice is no longer only validated through
unit tests and the repo-owned gate. It is now also live-proven on
`mail.blackbagsecurity.com` under `OSMAP_OPENBSD_CONFINEMENT_MODE=enforce`
using:

- a controlled HTML-only mailbox message in the disposable validation mailbox
- a synthetic validated browser session under the `_osmap` plus `vmail` split
- a browser-side settings update from `prefer_sanitized_html` to
  `prefer_plain_text`

That proof matters because it verifies the hostile-content boundary and the
new settings persistence path on the actual OpenBSD host shape rather than
only in test fixtures.

### Expand browser-login throttling to include a remote-only bucket

The original browser-login throttle keyed only on presented username plus
remote address. That was a useful first slice, but it still left easy room for
username rotation from one source address.

OSMAP now applies two bounded file-backed buckets on the browser login path:

- a tighter credential-plus-remote bucket
- a higher-threshold remote-only bucket

This keeps the implementation small and reviewable while making repeated
credential rotation from one source materially more expensive. It does not
replace adjacent controls such as nginx, PF, or monitoring, but it is a better
default abuse-resistance posture than a single credential-keyed bucket alone.

### Treat the first live browser mutation proof as complete on the target host

The target-host proof gap is now narrower than "send and move are unproven."
On `mail.blackbagsecurity.com` under
`OSMAP_OPENBSD_CONFINEMENT_MODE=enforce`, OSMAP now has live proof for:

- a controlled one-message move from `INBOX` to `Junk`
- a bounded send flow through `POST /send`

That proof used:

- the disposable validation mailbox
- a synthetic validated browser session
- the real `_osmap` plus `vmail` runtime split
- helper-backed mailbox authority under the same confinement posture used for
  earlier read-path validation

This matters because it moves the project from "implemented but not host-proven"
to "first bounded mutation routes proven on the real OpenBSD target host"
without widening the browser trust model or touching ordinary user mail.

### Declare the minimum Rust toolchain and make the local gate honest about it

The repository now declares `rust-version = "1.86"` in `Cargo.toml` because
the current dependency set already requires that level in practice.

The repo-owned `security-check` script now reads that declared minimum and, if
the local environment is older, skips the cargo-based phases with an explicit
note instead of failing for the wrong reason or pretending the full Rust gate
ran locally.

That keeps the developer workflow honest:

- the full Rust gate still runs in CI and on compatible hosts such as
  `mail.blackbagsecurity.com`
- local shell-based safety guards still run everywhere
- contributors are not encouraged to treat an outdated local toolchain as a
  meaningful validation environment

### Add a bounded submission throttle before widening broader request-abuse work

The next request-abuse slice should not start with a generic global limiter.
The highest-value unclosed gap after login throttling was submission abuse on
`POST /send`, because that path can be exercised repeatedly by a compromised
browser session and maps directly to an existing threat called out in the
security model.

OSMAP now applies a bounded file-backed submission throttle on the browser send
path with:

- a tighter canonical-user-plus-remote bucket
- a higher-threshold remote-only bucket

The send route now returns `429 Too Many Requests` with `Retry-After` when that
throttle is active. This keeps the control narrow, auditable, and aligned with
the existing state boundary instead of introducing a general-purpose rate-limit
framework too early.

### Prove send throttling through the live browser route with a reusable host harness

The bounded send-throttle slice is now not only unit-tested. The repository now
also carries a reusable live-host validation script at:

- `maint/live/osmap-live-validate-send-throttle.ksh`

On `mail.blackbagsecurity.com` under
`OSMAP_OPENBSD_CONFINEMENT_MODE=enforce`, that harness proves:

- one accepted `POST /send` through the real browser route
- `303 See Other` to `/compose?sent=1` on the first submission
- `429 Too Many Requests` with `Retry-After` on the second matching
  submission
- emitted `submission_throttle_engaged` and `submission_throttled` runtime log
  events

This keeps the submission-abuse control grounded in repeatable OpenBSD host
evidence rather than only in unit tests or ad hoc operator memory.

### Add a bounded message-move throttle before widening generic mutation controls

The next request-abuse slice after login and send should still stay narrow.
OSMAP already has one real authenticated mailbox mutation route:

- `POST /message/move`

That route now applies a bounded file-backed application-layer message-move
throttle with:

- a tighter canonical-user-plus-remote bucket
- a higher-threshold remote-only bucket

When the throttle is active, the browser route returns `429 Too Many Requests`
with `Retry-After`, and the runtime emits bounded mailbox audit events for both
throttle engagement and rejected move attempts.

This keeps abuse resistance focused on the highest-risk authenticated mutation
path that currently exists, rather than introducing a generic global limiter
before the rest of the mutation surface is even present.

### Prove message-move throttling through the live browser route with a reusable host harness

The bounded message-move throttle slice is now also grounded in repeatable
OpenBSD host evidence, not only in unit coverage. The repository now carries a
reusable live-host validation script at:

- `maint/live/osmap-live-validate-move-throttle.ksh`

On `mail.blackbagsecurity.com` under
`OSMAP_OPENBSD_CONFINEMENT_MODE=enforce`, that harness proves:

- one accepted `POST /message/move` through the real browser route
- `303 See Other` to `/mailbox?name=INBOX&moved_to=Junk` on the first move
- `429 Too Many Requests` with `Retry-After` on the second matching move
- emitted `message_move_throttle_engaged` and `message_move_throttled` runtime
  log events

The proof uses:

- a disposable validation mailbox
- a synthetic validated browser session
- the real `_osmap` plus `vmail` runtime split
- the helper-backed mailbox authority boundary under enforced OpenBSD
  confinement

This keeps the folder-organization abuse-resistance claim tied to repeatable
target-host evidence rather than only to library tests or ad hoc operator
validation.

### Pause narrow per-route throttling after login, send, and message move

A fresh repo-grounded reassessment of the current browser surface shows that
OSMAP now has three high-value route-specific abuse controls in place:

- login throttling on `POST /login`
- submission throttling on `POST /send`
- message-move throttling on `POST /message/move`

The remaining authenticated POST routes are currently:

- `POST /settings`
- `POST /sessions/revoke`
- `POST /logout`

Those routes are CSRF-bound, low-volume, and lower abuse value than login,
send, or mailbox mutation. There is therefore not yet a comparably strong case
for another narrow per-route throttle slice.

The better next priorities after this reassessment are:

- sequential HTTP/runtime hardening
- broader live-host proof beyond the first bounded mutation workflows
- remaining Version 1 workflow gaps such as richer search behavior and broader
  folder ergonomics

### Distinguish empty, truncated, and timed-out HTTP connections from real malformed requests

The sequential HTTP runtime previously normalized too many connection-lifecycle
failures into the same generic `400 Bad Request` path. That was too coarse for
a small custom listener because it blurred together three materially different
cases:

- an empty connection that closes before any bytes arrive
- a truncated request that ends before headers or body are complete
- a read timeout where the client stalls before finishing the request

The runtime now treats those separately:

- empty connections are logged and closed without emitting an HTTP response
- truncated requests are logged as incomplete and closed without emitting an
  HTTP response
- read timeouts now return `408 Request Timeout`

Actual malformed requests still use the `400 Bad Request` path.

This is a narrow correctness and resilience improvement for the current
sequential listener. It does not change the listener model, but it does make
transport failure handling more explicit and easier to reason about during
review and later hardening.

### Add accept-failure backoff and central request-completion logging to the sequential HTTP runtime

The next sequential-runtime resilience slice should stay narrow and focus on
operational behavior, not architecture changes.

The runtime now adds two small controls:

- bounded backoff after consecutive `accept(2)` failures so the listener does
  not spin hot on a broken accept loop
- one central completion event for parsed requests carrying method, path,
  status, response size, and duration, with slow requests promoted to a warn
  event

This keeps the current listener model intact while improving two real weak
spots in a custom sequential server:

- repeated accept failures are less likely to produce a tight log-and-spin
  loop
- operators no longer need to reconstruct request timing only from scattered
  route-local audit events

This is still not a concurrency change or a complete denial-of-service
solution. It is a bounded resilience and observability improvement that fits
the current prototype stage.

### Replace the strictly sequential HTTP listener with a bounded-concurrency model

The next narrow runtime step after connection-lifecycle cleanup and
observability should address the biggest remaining structural limitation
directly: one-connection-at-a-time serving.

OSMAP now handles accepted HTTP connections concurrently up to an explicit
operator-configured cap:

- `OSMAP_HTTP_MAX_CONCURRENT_CONNECTIONS`

The runtime uses a small thread-per-connection model with:

- one in-flight counter
- bounded admission
- `503 Service Unavailable` plus `Retry-After` when the runtime is already at
  capacity

This was selected over a broader async or worker-pool rewrite because it:

- removes the strictly sequential bottleneck
- stays dependency-light and reviewable
- fits the current standard-library-first runtime shape
- keeps the operator boundary explicit through one visible capacity setting

This is still not a complete denial-of-service solution or a claim of
high-throughput production readiness. It is a bounded concurrency upgrade that
materially improves the browser runtime posture without derailing the current
architecture.

### Add connection-cap observability and richer write-failure accounting

After the bounded concurrency upgrade, the next narrow runtime-hardening step
should improve operator visibility rather than widen protocol behavior again.

OSMAP now:

- emits an info event when it reaches a new in-flight connection high-water mark
- emits a warn event when it reaches its configured in-flight capacity
- includes active-connection context on over-capacity rejection logs
- includes richer request/response context on response-write failure logs when
  the request had already been parsed

This was chosen over broader queueing or worker-pool work because it gives
operators more actionable signals about runtime pressure and partial failure
without changing the current trust boundary or transport model.

### Escalate sustained accept-loop failures and emit recovery when the listener resumes

After adding bounded concurrency and pressure observability, the next narrow
HTTP-runtime step should make sustained listener failure less ambiguous.

OSMAP now:

- keeps ordinary single accept failures at `warn`
- promotes sustained accept-failure streaks to an explicit error-level event
- emits an info-level recovery event when successful accepts resume after such
  a streak

This was chosen over broader transport redesign because it improves operator
visibility into listener health without widening the protocol surface or
changing the current bounded-concurrency runtime model.

### Escalate sustained response-write failures and emit recovery when writes resume

After clarifying accept-loop health, the next narrow runtime-hardening step
should do the same for response-output failures.

OSMAP now:

- keeps ordinary response-write failures at `warn`
- promotes sustained response-write failure streaks to explicit error-level
  events
- emits an info-level recovery event when response writes resume after a
  sustained streak
- applies the same streak accounting to normal route responses and
  over-capacity `503` responses

This was chosen over broader transport or buffering changes because it makes
partial-output failure easier to observe and triage without changing the
current bounded-concurrency request model.

### Add a live host observability harness for bounded runtime signals

After tightening the runtime's connection-pressure and failure accounting, the
next useful step is a real host proof that those signals appear under the
actual `_osmap` deployment shape rather than only in unit tests.

The repo now includes a live validation harness that proves, on
`mail.blackbagsecurity.com` under `enforce`, that an isolated one-slot runtime
can emit:

- `http_connection_capacity_reached`
- `http_connection_rejected_over_capacity`
- `http_request_timed_out`
- `http_request_completed`

This was chosen as the next live-proof step because it exercises the new
runtime observability path without requiring a broader transport-failure lab or
an unstable synthetic denial-of-service test.

### Standardize host-side validation on `~/OSMAP` on `mail.blackbagsecurity.com`

The persistent `~/OSMAP` clone on `mail.blackbagsecurity.com` is now the
standard host-side validation checkout for OSMAP. The repo should prefer that
path over copying throwaway trees into home directories or `/tmp` for routine
validation.

Because `/tmp` on the host may be too small or busy for repeat Rust builds, the
repo now carries a small wrapper at:

- `maint/live/osmap-host-validate.ksh`

That wrapper runs `make security-check` or another passed command with
`TMPDIR`, `CARGO_HOME`, and `CARGO_TARGET_DIR` rooted under the operator's home
directory. This keeps repeat validation predictable, reduces ad hoc temp-tree
sprawl on the host, and leaves the local workstation checkout as the
authoritative development tree.

### Turn the repo-grounded reassessment into an explicit V1 closeout and V2 defer map

The project is now far enough along that the main risk is no longer missing
basic product shape. The bigger risk is drifting into convenient extra work
before the first release boundary is finished and frozen.

At that point, the official Version 1 closeout order was:

1. narrow HTTP/runtime hardening
2. minimum folder-organization ergonomics for ordinary use
3. search usability only to the point of replacing normal current workflows
4. broader live-host proof on `mail.blackbagsecurity.com`
5. helper and OpenBSD confinement tightening to a clear V1 stopping point
6. Version 1 boundary freeze and documentation alignment

The project should now treat the following as Version 2 work unless a narrower
first-release requirement is proven:

- broader ergonomics beyond the first practical folder/search baseline
- richer session or device intelligence
- broader attachment convenience behavior
- broader settings surface
- deeper runtime redesign beyond the current bounded-concurrency model

This decision keeps the project focused on a defensible first release instead
of continuing feature or architectural drift once the core browser and mail
flows already exist.

## 2026-04-09

### Treat HTTP worker-thread spawn failure as a bounded-concurrency availability fault

The bounded-concurrency listener now treats per-connection worker-thread spawn
failure as an explicit runtime fault instead of assuming thread creation always
succeeds.

When a connection slot has already been reserved but the worker thread cannot
be started, OSMAP now:

- releases the reserved in-flight connection slot immediately
- emits an explicit `http_connection_worker_spawn_failed` error event
- records the before-and-after active-connection counts on that event

This was chosen as the next narrow runtime-hardening step because a spawn
failure after slot acquisition could otherwise leave the listener artificially
at capacity and turn a transient host fault into a sticky availability problem.

### Make HTTP completion logging reflect successful response delivery

The bounded-concurrency runtime previously emitted `http_request_completed`
as soon as a parsed response had been prepared, before the response bytes were
actually written to the client socket.

OSMAP now:

- emits request-completion and slow-request events only after `write_all`
  succeeds
- keeps response-write failures as the authoritative signal when delivery does
  not complete
- makes connection-slot release saturating so an accidental extra release
  cannot wrap the active-connection counter to a huge value

This was chosen as the next narrow runtime-hardening step because completion
logs should reflect successful delivery rather than merely prepared routing
outcome, and the connection-cap counter should fail safely even if later
runtime changes ever introduce an extra release path.

### Emit explicit bounded-runtime visibility when an HTTP worker thread panics

The bounded-concurrency listener previously handled worker-thread spawn failure
explicitly, but once a worker had started it still relied on the default panic
path, which could release the connection slot without leaving a clear runtime
signal about why that connection died.

OSMAP now:

- wraps each connection worker body in a bounded panic catch
- emits `http_connection_worker_panicked` with the remote address, worker
  thread name, and post-release active-connection count
- keeps the connection-slot release path explicit even when a worker aborts
  unexpectedly

This was chosen as the next narrow runtime-hardening step because it improves
operator visibility into one concrete bounded-concurrency failure mode without
changing the transport model, adding a worker pool, or widening browser scope.

### Prove sustained HTTP response-write failure and recovery on the live OpenBSD host

After proving connection-pressure and timeout signals on the live host, the
next bounded runtime proof stayed narrow and exercised one more real failure
mode that operators may need to diagnose in production-like conditions:
repeated client disconnects during response delivery.

The repo now carries and has exercised the reusable live-host validation script
at:

- `maint/live/osmap-live-validate-http-write-observability.ksh`

On `mail.blackbagsecurity.com` under
`OSMAP_OPENBSD_CONFINEMENT_MODE=enforce`, that proof showed:

- repeated reset-backed `GET /login` requests drove
  `http_response_write_failed_sustained`
- the live host reported those write failures as `Broken pipe (os error 32)`
- a subsequent normal `GET /healthz` still returned `200 OK`
- the runtime emitted `http_response_write_recovered` once delivery succeeded
  again

This was chosen as the next bounded live-proof step because it exercised a
real output-failure and recovery path under the actual `_osmap` runtime shape
without widening browser scope or requiring a broader transport-fault lab.

### Reassess the top remaining Version 1 closeout risk after the live HTTP proof

After the bounded listener gained explicit worker-spawn and worker-panic
visibility, delivery-aligned completion logging, sustained write-failure
escalation and recovery, and two live-host observability proofs under
`enforce`, the next repo-grounded reassessment no longer treated HTTP/runtime
as the single most obvious remaining closeout risk.

The current browser folder-organization workflow is still much narrower than
the runtime posture:

- one-message move exists only from the message-view page
- archive still depends on manually typing the archive mailbox name
- mailbox-list pages still do not offer practical organization actions

That means the folder workflow is still only technically present rather than
practical enough for ordinary daily use, which now outweighs another
incremental listener tweak as the next best Version 1 closeout focus.

The official next implementation focus therefore shifts to:

- minimum folder-organization ergonomics for ordinary daily use

HTTP/runtime work remains incomplete and still depends on adjacent controls,
but it is no longer the first active delivery risk relative to the user-facing
workflow gap above.

### Add a settings-backed archive shortcut without broadening mailbox authority

The first practical folder-organization improvement should reduce repetitive
manual mailbox typing for the common archive workflow without turning OSMAP
into a broad mailbox-management project.

OSMAP now:

- stores one optional archive mailbox name in the existing bounded settings
  surface
- validates that archive mailbox name with the same bounded mailbox-name rules
  already used by the move path
- renders one-click archive forms on the message-view page and mailbox-list
  rows when that setting is configured
- keeps archive behavior on the same CSRF-bound `POST /message/move` route and
  backend-authoritative `doveadm move` path rather than introducing a second
  mutation mechanism

This was chosen as the next folder-organization step because it makes daily
organization materially easier while preserving the existing helper boundary,
move throttle, and single-message authority model.

### Prove the settings-backed archive shortcut on the live OpenBSD host

After adding the settings-backed archive shortcut locally, the next step stayed
narrow: prove that the real browser settings route, the real server-rendered
archive shortcut forms, and the existing helper-backed move path all work
together on `mail.blackbagsecurity.com` under `enforce`.

The repo now carries and has exercised the reusable live-host validation script
at:

- `maint/live/osmap-live-validate-archive-shortcut.ksh`

On `mail.blackbagsecurity.com` under
`OSMAP_OPENBSD_CONFINEMENT_MODE=enforce`, that proof showed:

- `POST /settings` persisted `archive_mailbox_name=Junk` through the real
  browser route
- the retained settings file under the isolated host proof root also recorded
  `html_display_preference=prefer_sanitized_html` and
  `archive_mailbox_name=Junk`
- the mailbox page and message-view page both rendered archive shortcut forms
  carrying `destination_mailbox=Junk`
- a controlled message was archived from `INBOX` to `Junk` through the
  existing `POST /message/move` route
- the live runtime emitted `user_settings_updated`, repeated
  `user_settings_loaded` with `archive_mailbox_name="Junk"`, and
  `message_moved` for that archive action

This was chosen as the next proof step because it validates the first
post-runtime-hardening folder-ergonomics improvement against the actual
`_osmap` plus `vmail` host boundary before broader mailbox UX work continues.

### Reassess whether folder organization still blocks the next Version 1 item

After the one-message move path gained list-page archive actions, a
settings-backed archive mailbox destination, and live-host proof on
`mail.blackbagsecurity.com`, the next repo-grounded reassessment no longer
treated folder organization as the first remaining Version 1 blocker.

The current folder workflow now appears practical enough for ordinary daily
use because it offers:

- one-message move into an arbitrary existing mailbox
- one-click archive from mailbox-list and message-view pages once the archive
  mailbox is configured
- live-host proof that the settings route, archive shortcut rendering, and
  helper-backed archive action succeed together under `enforce`

The remaining missing items in this area:

- bulk move from mailbox-list pages
- archive mailbox discovery beyond the explicit user setting
- richer drag-and-drop or mailbox-management actions

now fit better as later workflow refinements than as the first closeout risk.

The official next implementation focus therefore shifts to:

- improve search only enough to replace ordinary Roundcube-era retrieval
  workflows

### Widen the bounded search slice to cover all visible mailboxes

The smallest search improvement that materially changes ordinary retrieval
behavior is not advanced syntax or richer sorting. It is letting the browser
search across all visible mailboxes without forcing the user to guess which
folder currently holds the message.

OSMAP now keeps the existing backend-authoritative search path, but broadens
the browser scope in a deliberately narrow way:

- `/search` still requires a bounded free-text query and still relies on the
  existing Dovecot-backed search path for every mailbox search
- mailbox-list pages now offer a search form that can stay in the current
  mailbox or switch to all visible mailboxes
- the mailboxes landing page now also exposes a simple search-all-mailboxes
  form for the common retrieval case
- search results now show the mailbox for each match so cross-mailbox results
  remain navigable without adding richer search-product features

This was chosen instead of a broader search feature project because it closes
the most obvious Roundcube-era retrieval gap while preserving the helper
boundary, bounded output limits, and backend authority model already in place.

### Prove the bounded all-mailboxes search flow on the live OpenBSD host

After widening the search slice to cover all visible mailboxes, the next
evidence step stayed narrow: prove that the real browser search surface works
under `enforce` on `mail.blackbagsecurity.com` before treating search as
operationally credible.

The repo now carries and has exercised the reusable live-host validation script
at:

- `maint/live/osmap-live-validate-all-mailbox-search.ksh`

That proof was run through the repo-owned host wrapper from a disposable clone,
with retained host artifacts under:

- `/home/osmap-live-all-mailbox-search-proof`

The retained proof root now includes:

- `mailboxes-response.txt`
- `mailbox-response.txt`
- `search-response.txt`
- `state/runtime/serve.log`

On `mail.blackbagsecurity.com` under
`OSMAP_OPENBSD_CONFINEMENT_MODE=enforce`, that proof showed:

- `/mailboxes` rendered the global `Search all mailboxes` form for the
  synthetic validated session
- `/mailbox?name=INBOX` rendered the new `scope=all` toggle on the mailbox
  search form
- one bounded `/search?q=...` request returned `HTTP/1.1 200 OK` with
  `Scope: All mailboxes`
- the retained search response rendered two controlled hits in one result set:
  one in `Junk` and one in `INBOX`
- the retained runtime log emitted `mailbox_listed` plus two
  `message_searched` events for the same query token, one with
  `mailbox_name="Junk"` and one with `mailbox_name="INBOX"`

This was chosen as the next proof step because it validates the new
all-mailboxes retrieval behavior at the real `_osmap` plus `vmail` boundary
without widening the search scope into a richer feature project first.

### Reassess whether search still blocks the next Version 1 item

After widening search to cover all visible mailboxes and proving that behavior
on `mail.blackbagsecurity.com` under `enforce`, the next repo-grounded
reassessment no longer treats search as the first remaining Version 1 blocker.

The current search workflow now appears sufficient for ordinary daily use
because it offers:

- backend-authoritative free-text search without inventing a second search
  engine inside OSMAP
- one-mailbox search when the user already knows the folder context
- all-mailboxes search when the user only remembers message content and needs
  ordinary Roundcube-style retrieval across visible folders
- result rows that surface the mailbox for each hit so cross-folder results
  remain navigable
- live-host proof that the real browser surface renders the all-mailboxes form,
  the mailbox-page scope toggle, and a bounded multi-mailbox result set under
  the real `_osmap` plus `vmail` boundary

The remaining missing items in this area:

- richer query operators or field-specific search
- explicit sorting controls on result pages
- broader refinement behavior such as saved searches or faceting

now fit better as later search-product refinements than as the first closeout
risk for Version 1.

The official next implementation focus therefore shifts to:

- broaden live-host proof on `mail.blackbagsecurity.com` for the already-
  implemented browser surface

### Prove the broader session-management browser surface on the live OpenBSD host

After closing the first search reassessment, the strongest remaining live-host
gap was the current session/logout browser surface. Earlier host proof had
already covered the first `/sessions` and revoke path, but the current
closeout target needed a reusable harness that exercised the broader
already-implemented session-management surface under `enforce`.

The repo now carries and has exercised the reusable live-host validation script
at:

- `maint/live/osmap-live-validate-session-surface.ksh`

That proof was run through the repo-owned host wrapper from a disposable clone,
with retained host artifacts under:

- `/home/osmap-live-session-surface-proof`

The retained proof root now includes:

- `sessions-response.txt`
- `sessions-revoked-response.txt`
- `revoke-response.txt`
- `logout-response.txt`
- `stale-sessions-response.txt`
- `state/runtime/serve.log`
- `state/sessions/*.session`

On `mail.blackbagsecurity.com` under
`OSMAP_OPENBSD_CONFINEMENT_MODE=enforce`, that proof showed:

- `GET /sessions` returned `HTTP/1.1 200 OK`
- the retained sessions page rendered both the current session and a second
  synthetic active session with remote address `203.0.113.9`
- `POST /sessions/revoke` returned `HTTP/1.1 303 See Other` with
  `Location: /sessions?revoked=1`
- the retained `/sessions?revoked=1` response carried the success banner after
  the non-current revoke
- the retained non-current session record now has a non-empty `revoked_at`
- `POST /logout` returned `HTTP/1.1 303 See Other` with `Location: /login`
  and a `Set-Cookie` clearing the browser session
- the retained current session record now also has a non-empty `revoked_at`
- a subsequent stale-cookie `GET /sessions` redirected back to `/login`
- the retained runtime log emitted `session_listed` and two
  `session_revoked` events, one for the other session and one for the current
  session

This was chosen instead of another new browser feature because it closes the
last obvious gap in broader live-browser proof for the already-implemented
surface without widening OSMAP's Version 1 contract.

### Reassess the broader live-host proof item after the session/logout proof

After proving the current session-management browser surface under `enforce`,
the broader live-host proof item no longer appears to be the first remaining
Version 1 blocker.

The currently implemented browser surface now has live-host proof on
`mail.blackbagsecurity.com` for:

- positive browser login plus TOTP-backed session issuance
- mailbox listing, message listing, message view, and forced-download
  attachment retrieval at the real `_osmap` plus `vmail` boundary
- safe HTML rendering and the bounded settings surface
- bounded send and one-message move flows
- bounded all-mailboxes search
- the first self-service session-management surface, including revoke and
  logout behavior

The official next implementation focus therefore shifts to:

- tighten the helper and OpenBSD confinement boundary to a clear Version 1
  stopping point

### Freeze the mailbox helper boundary into production `serve` configuration

Once broader live-browser proof was in place, the next helper/OpenBSD boundary
question was no longer "should the helper exist?" but "is that boundary an
actual Version 1 rule or just a documented preference?"

The narrowest useful answer is now implemented:

- production `OSMAP_RUN_MODE=serve` rejects configs that do not set
  `OSMAP_MAILBOX_HELPER_SOCKET_PATH`
- the startup report now emits `mailbox_boundary_mode` with either
  `local_helper_socket` or `direct_doveadm`

This was chosen instead of a broader helper rewrite because it turns the
already-selected mailbox helper boundary into an operator-visible deployment
rule without removing the direct backend seam needed for development, tests,
and narrow staging work.

The effect is deliberate:

- development and staging can still use the direct mailbox backend seam when
  needed for bounded local work
- production `serve` can no longer drift into direct mailbox authority from
  the browser-facing runtime silently
- the Version 1 stopping point becomes clearer in configuration, startup
  logging, and deployment guidance before further helper or confinement
  narrowing happens

## 2026-04-10

### Carry the helper boundary into an operator-visible OpenBSD split-runtime layout

Freezing the mailbox helper into production `serve` configuration was not
enough on its own. The project also needed an operator-facing deployment shape
that matches that boundary instead of leaving it as a purely internal runtime
rule.

OSMAP now treats the current OpenBSD deployment model as a split runtime:

- one browser-facing `serve` process
- one local `mailbox-helper` process
- separate example environment files and launch wrappers for each runtime

This was chosen instead of keeping one monolithic service wrapper because the
selected least-privilege design is now real project policy, not just an
implementation detail hidden inside one binary.

### Carry repo-owned OpenBSD `rc.d` scaffolding for the split runtime

Once the split runtime became the intended operator model, the repository
needed first-class OpenBSD supervision examples that reflect it. OSMAP now
carries repo-owned example `rc.d` scripts and launcher scaffolding for:

- `osmap_serve`
- `osmap_mailbox_helper`

This does not claim that packaging or final base-system integration is
complete. It does mean the project now treats OpenBSD service supervision for
the split runtime as something operators should be able to review, test, and
adapt directly from the repository rather than reconstruct from prose alone.

### Use a dedicated helper-side attachment-download operation instead of reusing helper-backed message view

The earlier helper-backed attachment path reused helper-side message view and
then resolved attachment bytes in the web-facing runtime. That was a useful
bridge, but it was no longer the right stopping point once the helper boundary
itself became a production rule.

OSMAP now treats attachment-byte retrieval as its own helper operation:

- the web-facing runtime asks the local helper for one bounded attachment
- the helper resolves the attachment part from the fetched message
- the helper protocol returns the bounded attachment payload directly
- helper failures preserve stable browser-facing meanings such as
  `invalid_request`, `not_found`, and temporary failure

This was chosen instead of continuing to tunnel attachment download through the
helper-backed message-view bridge because the dedicated operation keeps mailbox
authority narrower and makes the helper boundary more honest about what the
browser process is and is not allowed to do.

### Keep status and deployment docs synchronized with the helper boundary that actually ships

Once the helper-side attachment-download operation and OpenBSD split-runtime
scaffolding landed, several status-facing docs still described the older
bridge behavior. That was no longer acceptable because the current helper
boundary is now part of the real deployment posture, not just an internal
refactor detail.

The active docs now need to say the current state plainly:

- attachment download uses a dedicated helper-side operation
- the helper boundary now also carries search and the first one-message move
  workflow
- production `serve` treats the mailbox helper as a required deployment rule
  rather than an optional preference

This was chosen instead of leaving older wording in place because stale helper
docs would mislead operator review, deployment staging, and the next round of
implementation planning.

### Narrow the OpenBSD filesystem view by making the top-level state root read-only

The confinement plan still unveiled the whole configured OSMAP state root as
write-capable even though the runtime already had explicit writable subtrees
for:

- runtime files
- sessions
- settings
- audit
- cache
- TOTP secrets

That was broader than necessary for the current Version 1 runtime shape.

OSMAP now keeps the top-level state root itself read-only in both `serve` and
`mailbox-helper` modes while leaving only the explicit mutable subdirectories
writable.

This was chosen instead of leaving the broader root-level write view in place
because it gives the helper/OpenBSD boundary a cleaner and more reviewable
Version 1 stopping point without changing the existing state layout or
operator-facing deployment model.

Local validation and disposable-host validation on `mail.blackbagsecurity.com`
both passed after this change, including the repo-owned `make security-check`
gate and a real helper-backed enforced all-mailboxes browser search workflow.

### Narrow the helper-side OpenBSD dependency view to explicit `doveadm` and Dovecot paths

The helper-side confinement plan still carried blanket `/usr/libexec`,
`/usr/local/lib`, and `/etc/dovecot` visibility even though host tracing on
`mail.blackbagsecurity.com` showed a smaller stable dependency set for the
current helper-backed search and move workflows.

OSMAP now narrows the `mailbox-helper` view by:

- keeping `/usr/local/bin/doveadm` explicit
- adding `/usr/local/bin/doveconf` explicitly because the traced `doveadm`
  execution invokes it on the validated host
- narrowing the loader path to `/usr/libexec/ld.so`
- preferring exact resolved shared-library files from `/usr/lib` and
  `/usr/local/lib` when the current host exposes the expected versioned names
- narrowing Dovecot config visibility to `dovecot.conf`, `conf.d`, and
  `local.conf`
- adding the explicit Dovecot config-socket path at `/var/dovecot/config`
- keeping a conservative broader-library fallback only when a host does not
  expose the expected exact versioned library filenames

This was chosen instead of hard-coding one OpenBSD package ABI snapshot or
keeping the broader helper library/config roots because the new plan is both
more reviewable on the validated host and less brittle across later host
library upgrades.

Validation after this narrowing passed locally and on the target OpenBSD host:

- local `cargo test openbsd`
- local `make security-check`
- disposable-host `./maint/live/osmap-host-validate.ksh make security-check`
- disposable-host `ksh ./maint/live/osmap-live-validate-all-mailbox-search.ksh`
  as the read proof
- disposable-host `ksh ./maint/live/osmap-live-validate-move-throttle.ksh`
  as the mutation proof

### Narrow the serve-side OpenBSD dependency view to explicit auth and sendmail paths

After narrowing the helper-side dependency view, the browser-facing `serve`
runtime still carried broader allowances than the validated host actually used:

- blanket `/usr/libexec`
- blanket `/usr/local/lib`
- blanket `/etc/dovecot`
- `/etc/mail`
- `/var/spool/smtpd`

Host tracing on `mail.blackbagsecurity.com` showed a more precise current
dependency picture:

- auth-backed `doveadm` on `_osmap` uses the same explicit loader, Dovecot
  config, config-socket, and resolved shared-library shape already proven for
  the helper
- `/usr/sbin/sendmail` is a mailwrapper that reads `/etc/mailer.conf`, then
  execs `/usr/local/sbin/sendmail`
- the local sendmail/Postfix path currently relies on exact loader and library
  files, `/etc/postfix/main.cf`, `/etc/pwd.db`, `/etc/group`, `/etc/localtime`,
  `/usr/share/zoneinfo/posixrules`, `/dev/urandom`, `/var/spool/postfix`, and
  `/usr/local/sbin/postdrop`

OSMAP now narrows the `serve`-mode filesystem view accordingly instead of
keeping the broader directory-wide auth/sendmail allowances.

This was chosen instead of leaving the broader serve view in place because the
current host evidence is now good enough to make the browser-facing runtime
reviewable on the same terms as the helper, without pretending the runtime is
already independent of Dovecot or Postfix.

The repository now also carries `maint/live/osmap-live-validate-login-send.ksh`
as a repo-owned positive-login proof harness. That script:

- provisions an isolated TOTP secret for the validation mailbox inside the
  temporary OSMAP state tree
- performs a real password-plus-TOTP login under enforced confinement
- carries the issued session cookie into the compose flow
- submits one real browser message and confirms delivery into the validation
  mailbox

Validation after this narrowing passed locally and on the target OpenBSD host:

- local `cargo test openbsd`
- local `cargo test login_sets_session_cookie_and_redirects`
- local `cargo test compose_page_renders_csrf_bound_form`
- local `cargo test sendmail_backend_uses_local_submission_surface`
- local `make security-check`
- disposable-host `./maint/live/osmap-host-validate.ksh make security-check`
- disposable-host `ksh ./maint/live/osmap-live-validate-login-send.ksh`
  as the real positive-login-plus-send proof

### Treat V1 closeout drift as the next repo-level risk, not more helper/OpenBSD redesign

After the serve-side auth/sendmail narrowing landed, the repo-owned
`maint/live/osmap-live-validate-login-send.ksh` harness existed, and
production `serve` already rejected configs without
`OSMAP_MAILBOX_HELPER_SOCKET_PATH`, continuing to frame helper/OpenBSD
tightening as the next default item would have been stale.

The current closeout rule is now:

- use `docs/ACCEPTANCE_CRITERIA.md` as the authoritative Version 1 gate
- keep `README.md`, `KNOWN_LIMITATIONS.md`, `IMPLEMENTATION_PLAN.md`,
  `OPENBSD_RUNTIME_CONFINEMENT_BASELINE.md`, and the current status entries in
  `DECISION_LOG.md` aligned with that gate
- treat the current conservative library fallbacks and repo-owned split-
  runtime scaffolding as the deliberate Version 1 stopping point unless a
  failing proof exposes a narrower blocker
- take further implementation work only when repo truth, not stale planning
  text, shows an unclosed blocker

This was chosen instead of continuing with more speculative confinement
tightening because the repository already has the narrower serve-side
dependency view, a real password-plus-TOTP login-plus-send proof, and a frozen
production helper boundary. The larger remaining risk is closeout drift:
stale status text, ambiguous release criteria, and future work getting pulled
back into solved design debates.

### Add one repo-owned wrapper for the authoritative V1 closeout proof set

Once `docs/ACCEPTANCE_CRITERIA.md` became the authoritative Version 1 gate, the
proof set itself still existed only as a list of separate commands. That was
accurate, but it left repeat operator validation more manual than it needed to
be.

OSMAP now carries `maint/live/osmap-live-validate-v1-closeout.ksh` as a thin
wrapper around the current closeout proof set:

- `./maint/live/osmap-host-validate.ksh make security-check`
- `ksh ./maint/live/osmap-live-validate-login-send.ksh`
- `ksh ./maint/live/osmap-live-validate-all-mailbox-search.ksh`
- `ksh ./maint/live/osmap-live-validate-archive-shortcut.ksh`
- `ksh ./maint/live/osmap-live-validate-session-surface.ksh`
- `ksh ./maint/live/osmap-live-validate-send-throttle.ksh`
- `ksh ./maint/live/osmap-live-validate-move-throttle.ksh`

That wrapper also keeps the secret boundary honest: the real login-plus-send
step still requires an operator-supplied `OSMAP_VALIDATION_PASSWORD`, and the
repository still does not carry mailbox credentials.

This was chosen instead of inventing a broader validation framework because the
current closeout need is only to make the authoritative Version 1 proof set
easier to run, rerun, and review without changing what the gate actually is.

### Let the V1 closeout wrapper emit a small reviewable run summary

Once the closeout proof wrapper existed, the next friction point was not what
to run but how to leave a small, operator-readable record of what actually ran.

`maint/live/osmap-live-validate-v1-closeout.ksh` now also supports:

- `--list` to print the current authoritative step set
- `--report <path>` to write a small pass-summary file for the steps executed

This was chosen instead of adding a larger reporting system because the V1
closeout need is only a minimal review artifact that records the exact proof
subset that passed, without changing the proof scripts themselves or inventing
a new persistence layer.

### Add a repo-owned SSH wrapper for the host-side V1 closeout gate

The authoritative Version 1 proof set now has a host-side wrapper and a small
report format, but one more practical friction point remained: the validating
workstation may not be the same machine as `mail.blackbagsecurity.com`.

OSMAP now carries `maint/live/osmap-run-v1-closeout-over-ssh.sh` so a machine
that can reach the private host can:

- SSH into the standard `~/OSMAP` checkout
- run `maint/live/osmap-live-validate-v1-closeout.ksh` there with the selected
  steps
- forward `OSMAP_VALIDATION_PASSWORD` only for the remote invocation when the
  real login-plus-send step is included
- fetch the resulting closeout summary report back to the local machine

This was chosen instead of broadening the live-proof scripts themselves because
the actual blocker was operator reachability to the private host, not the proof
logic. The smallest useful answer is a thin orchestration wrapper that keeps
the authoritative gate unchanged while making the real host run easier from a
reachable workstation.

### Freeze the V1 release decision after a full host rerun

On April 11, 2026, the full authoritative wrapper
`ksh ./maint/live/osmap-live-validate-v1-closeout.ksh` was rerun on
`mail.blackbagsecurity.com` and passed end to end:

- `security-check=passed`
- `login-send=passed`
- `all-mailbox-search=passed`
- `archive-shortcut=passed`
- `session-surface=passed`
- `send-throttle=passed`
- `move-throttle=passed`

Because the repository still does not carry mailbox credentials, the real
`login-send` proof was executed in one controlled shell session by installing a
random temporary validation password, running the wrapper, and restoring the
original mailbox password hash before exit.

This freezes the Version 1 release decision against
`docs/ACCEPTANCE_CRITERIA.md`: the next repo-level work is closeout discipline
and release handling, not more browser features, OpenBSD redesign, or broader
helper expansion. Future implementation work should be reopened only by a new
failing proof or a concrete repo inconsistency.

### Align the frozen V1 release story with the actual closeout path

After the April 11, 2026 full host rerun, the acceptance gate already treated
Version 1 closeout as frozen, but some release-facing docs still described that
freeze as future work. The off-host SSH wrapper also still had a concrete
operator-path bug: its handling of remote `~/...` paths broke the documented
host project-root and report-path flow before the closeout wrapper could
complete.

OSMAP now makes the smallest correction that matches repo truth:

- `README.md`, `KNOWN_LIMITATIONS.md`, `IMPLEMENTATION_PLAN.md`,
  `OPENBSD_RUNTIME_CONFINEMENT_BASELINE.md`, and
  `ACCEPTANCE_CRITERIA.md` now all treat the Version 1 gate as already frozen
  and the remaining work as documentation parity plus targeted proof reruns
- `maint/live/osmap-run-v1-closeout-over-ssh.sh` now normalizes remote
  `~/...` paths correctly and runs its remote commands through explicit
  `sh -lc` execution so the project-root and report-path handling stay stable
  across SSH
- the authoritative host-side closeout path remains
  `ksh ./maint/live/osmap-live-validate-v1-closeout.ksh`, with the SSH wrapper
  kept as the thin off-host trigger rather than as a second gate

This was chosen instead of introducing a new closeout-status document or a
broader orchestration layer because the repository already had the correct gate,
proof set, and wrapper shape. The real defects were stale wording and a narrow
SSH-wrapper bug, so the smallest correct change was to align the existing docs
and make the existing operator path actually honor the documented remote path.

Validation for this change was:

- `sh -n ./maint/live/osmap-run-v1-closeout-over-ssh.sh`
- `ssh mail.blackbagsecurity.com 'cd ~/osmap-v1-closeout-clean-20260411-002325 && ksh ./maint/live/osmap-live-validate-v1-closeout.ksh --list'`
- `./maint/live/osmap-run-v1-closeout-over-ssh.sh --remote-project-root ~/osmap-v1-closeout-clean-20260411-002325 --local-report ./maint/live/latest-host-security-check-report.txt security-check`

That validation proved three things:

- the authoritative closeout step list still matches the acceptance gate
- the off-host SSH wrapper can now reach a host-side closeout checkout, run the
  `security-check` step, write a report, and fetch that report back locally
- Version 1 scope and release posture remain unchanged: the current remaining
  repo work is closeout discipline, not scope widening
