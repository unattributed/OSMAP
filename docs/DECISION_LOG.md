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
