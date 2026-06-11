# Version 3 Roadmap

## Purpose

This roadmap sequences Version 3 work so OSMAP becomes a focused daily-driver hardening release without weakening the Version 2 trust boundary or drifting into broad webmail parity.

## Roadmap Rules

- keep application changes behind the gates in `V3_ACCEPTANCE_CRITERIA.md`
- preserve the `_osmap` plus `vmail` runtime boundary before adding workflow convenience
- treat release-mode validation as the first Version 3 deliverable, not a closeout afterthought
- land one feature slice at a time with tests, WSTG disposition, and security evidence
- update `PILOT_WORKFLOW_INVENTORY.md` when a workflow changes disposition
- keep WSTG regression proof current as browser routes are added
- require credential and TOTP-backed evidence for authenticated WSTG or other security tests that need authenticated coverage
- reject feature requests that belong to contacts, calendar, groupware, plugins, mobile app, broad admin, external content loading, OpenPGP implementation, broad JavaScript behavior, or unbounded mailbox management

## Work Sequence

| Order | Slice | Deliverable | Exit gate |
| --- | --- | --- | --- |
| 0 | V3 release-gate foundation | split developer partial validation from release-mode validation; define evidence archive expectations; require release-mode failure on skipped required phases | release-mode gate fails on skipped Cargo, skipped required supply-chain tooling, missing host-readiness evidence, missing V2 carry-forward evidence, or skipped authenticated WSTG/security tests that require credential and TOTP coverage |
| 1 | Supply-chain assurance | make RustSec advisory review, cargo-deny source and license enforcement, duplicate dependency rejection, dependency exception handling, and SBOM or dependency inventory evidence part of the release gate | supply-chain gate produces timestamped evidence and cannot pass when required tools are missing |
| 2 | Resource and timeout hardening | identify expensive HTTP, auth, helper, mailbox, search, MIME, attachment, send, move, and bulk paths; add or verify bounded inputs, outputs, timeouts, deterministic failures, and the worker-budget design in `REQUEST_WORKER_BUDGET_MODEL.md` | tests and docs prove expensive paths are bounded and fail closed or fail clearly |
| 3 | WSTG release-mode coverage | update WSTG pack and documentation so authenticated security checks cannot be counted complete when credential and TOTP-dependent tests are skipped | WSTG evidence shows unauthenticated coverage, authenticated coverage where applicable, and sanitized prompt-auth or dedicated validation-account proof |
| 4 | MIME and HTML correctness | tighten representative message correctness before expanding compose continuity | MIME/HTML feature gate passes with regression tests and no remote content loading |
| 5 | Session and device policy | choose concurrent-session behavior, device labels, revocation semantics, and isolated-cookie race retest | session/device security gate passes |
| 6 | Draft save and resume design | define draft storage, ownership, limits, routes, cleanup, and failure behavior before code in `V3_DRAFT_SAVE_RESUME_DESIGN.md` | design reviewed against session, CSRF, state-path, resource, and confinement constraints |
| 7 | Draft save and resume implementation | authenticated draft create, list, update, resume, send, and delete | draft feature gate passes |
| 8 | Reply and forward attachment handling | explicit original-attachment selection and bounded reattachment through `docs/V3_REPLY_FORWARD_ATTACHMENT_HANDLING_DESIGN.md` | reply/forward attachment gate passes |
| 9 | Richer bounded search | practical refinements, sorting, result caps, deterministic invalid-query handling, and timeout behavior where applicable | richer bounded search gate passes |
| 10 | Bounded bulk folder actions | selected-message cleanup beyond archive only, with per-message revalidation | bulk folder-action gate passes |
| 11 | TLS standard and CBC cleanup | enforce `docs/TLS_STANDARD.md` across code, tooling, CI, release evidence, and the public edge; remove TLS 1.2 CBC suites or document a reviewed exception | TLS standard gate passes, including static guard evidence and live proof that weak protocols fail while TLS 1.2 and TLS 1.3 pass with acceptable ciphers |
| 12 | V3 pilot rehearsal | run daily-driver workflow rehearsal with selected users and archive sanitized evidence | V3 closeout evidence is ready |

Slice 12 is represented in release mode by
`OSMAP_RELEASE_V3_PILOT_REHEARSAL_EVIDENCE`, defaulting to
`maint/live/latest-host-v3-pilot-rehearsal-report.txt` plus
`docs/PILOT_WORKFLOW_INVENTORY.md`. A V3 release candidate must fail until that
sanitized selected-cohort rehearsal evidence exists for the assessed commit.

## Current Status

As of the V4 assessed code commit `09a95b7`, the release gate, supply-chain
gate, resource and timeout evidence path, WSTG release-mode coverage,
MIME/HTML live proof path, draft save/resume slice, reply/forward attachment
selection slice, bounded search refinements, TLS standard evidence, and pilot
rehearsal capture helper are present in the repository.

The richer bounded search slice has two implemented sub-slices:

- mailbox and search-result table sorting for UID, subject, from, received,
  flags, and size
- whitelisted search field refinement with `field=all|subject|from`

Those sub-slices passed local Rust validation and the developer
`make security-check` gate. The V3 release evidence was refreshed during V4
closeout for assessed ref `09a95b7f4e9744a20bcd85430e4f0428cafeebe7`; the
tracked evidence is:

- `maint/live/osmap-v3-release-evidence-summary.md`
- `maint/live/osmap-v3-release-evidence-summary.json`
- `maint/live/osmap-v3-release-evidence.tar.gz`

That refreshed release evidence is carried forward by
`docs/V4_CLOSEOUT_EVIDENCE.md` and the `v4.0.0` release handoff.

## Post-V3 Rule

The release-gate foundation implementation is `make release-check`. It keeps
`make security-check` as developer partial validation and adds a strict release
profile that fails on skipped required phases, missing pinned tools, missing
dependency inventory, missing V2 or host evidence, missing release-mode WSTG
evidence, missing V3 MIME/HTML live proof, missing pilot rehearsal evidence, or
missing sanitized evidence summary/archive generation.

Future changes that touch V3-governed browser, authentication, session, helper,
mailbox, send, search, MIME, attachment, TLS, WSTG, or release-evidence
surfaces must preserve this fail-closed release behavior before the change can
inherit a later release claim.

## Functional Implementation Track

After the release-gate foundation is in place, continue the functional Version 3 work with MIME and HTML correctness.

MIME and HTML correctness remains the first functional slice because drafts, replies, forwards, search, attachment handling, and user trust all depend on reliable message summaries, body selection, attachment metadata, and safe rendering.

The MIME and HTML implementation plan should inspect and extend:

- `src/mime.rs`
- `src/rendering_html.rs`
- message summary and message-view rendering routes
- current MIME, HTML, attachment, charset, transfer-encoding, and encoded-header tests
- `maint/live/osmap-live-validate-encoded-header-summary.ksh`
- WSTG scripts that cover HTML, injection, attachment, and search behavior

Do not add remote image loading, rich-text compose, JavaScript rendering, attachment preview, or a new mail-client engine as part of this slice.

The current fixture corpus covers hostile input plus several common real-world
mail shapes: newsletter-style related messages, calendar invites,
delivery-status notifications, unsupported charsets, nested multipart, encoded
headers, and suspicious attachment metadata. The next MIME slice should broaden
that corpus with more mail-generator samples, language and charset variety, and
larger but still bounded body and attachment metadata cases.

## Draft Save And Resume Track

The draft save and resume design gate is now
`docs/V3_DRAFT_SAVE_RESUME_DESIGN.md`.

That document intentionally stops short of runtime persistence. It defines the
storage root, owner scoping, route shape, CSRF and same-origin requirements,
compose-policy limits, attachment persistence boundary, cleanup behavior,
failure behavior, WSTG/ASVS disposition, and evidence hygiene that the
implementation slice must satisfy.

The first storage primitive now exists in `src/draft.rs`, and authenticated
browser routes now cover draft list, resume, save, delete, and send-success
cleanup. The WSTG testing pack now has release-required ASVS-mapped draft route
coverage in `OSMAP-WSTG-BUSL-002`. Host-safe authenticated evidence from
`mail.blackbagsecurity.com` passed on 2026-05-07 in
`maint/wstg-testing-pack/output/osmap-wstg-20260507-173210/`, so draft save and
resume may be treated as `supported_with_limits` for Version 3 pilot planning.
The limits still exclude browser-local drafts, attachment preview, inline image
rendering, remote content loading, and automatic original-message attachment
reattach.

## Reply And Forward Attachment Track

The reply and forward attachment handling design gate is now
`docs/V3_REPLY_FORWARD_ATTACHMENT_HANDLING_DESIGN.md`.

The implementation keeps selection explicit, fetches selected original
attachments through the existing bounded helper-backed message and attachment
path, includes selected originals in the aggregate compose attachment limits,
and fails visibly rather than silently dropping a confirmed selection.
It does not add inline preview, inline image rendering, remote content loading,
automatic reattach, or broad MIME-client behavior.

## Richer Bounded Search Track

The richer bounded search slice remains intentionally narrow. OSMAP now
supports server-rendered sorting controls for mailbox and search result tables
and whitelisted search field refinement for all message text, subject, and
from. The field refinement is carried through the helper protocol as a signed
whitelisted value and maps to fixed Dovecot search keys rather than
user-controlled backend syntax.

The remaining search decision is product scope, not another parser shortcut:
Version 3 can either stop at the current bounded controls or explicitly design
a future advanced-search surface. Broad query languages, saved searches,
facets, JavaScript-heavy search UI, and arbitrary backend search syntax remain
out of scope unless a later roadmap revision names them.

## Security Foundation Track

The security foundation track continues throughout Version 3 and blocks release if incomplete:

- release-mode validation semantics
- supply-chain evidence
- SBOM or dependency inventory evidence
- host-readiness evidence
- authenticated WSTG evidence where credentials and TOTP are required
- external command and helper timeout evidence
- resource-exhaustion regression tests
- worker-budget design and implementation evidence for slow synchronous request
  occupancy
- session/device policy evidence
- TLS standard and TLS CBC disposition evidence

Feature work may proceed only when it does not obscure or defer these gates.
During feature-slice development, local unit/route coverage plus
`make security-check` is the normal developer gate. Host deployment and
interactive credential-backed WSTG release capture are required for the final
V3 release candidate, and earlier whenever a slice materially changes auth,
session, CSRF, helper-boundary, or public-edge behavior.

## Design-Only Investigation Track

OpenPGP may receive design-only investigation during Version 3, limited to:

- threat model
- user workflow inventory
- key custody options
- reasons to defer implementation

No OpenPGP signing, encryption, decryption, key management, browser cryptography, or server-side GPG implementation is in Version 3 scope.

## Defers Beyond Version 3

- contacts
- calendar
- groupware
- plugin ecosystem
- mobile app
- broad admin console
- remote external content loading
- broad runtime rewrite not justified by measured security or reliability evidence
- rich-text compose
- attachment preview behavior that widens browser trust
- full Roundcube parity
- unbounded mailbox-wide operations
