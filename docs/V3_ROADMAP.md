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
| 8 | Reply and forward attachment handling | explicit original-attachment selection and bounded reattachment | reply/forward attachment gate passes |
| 9 | Richer bounded search | practical refinements, sorting, result caps, deterministic invalid-query handling, and timeout behavior where applicable | richer bounded search gate passes |
| 10 | Bounded bulk folder actions | selected-message cleanup beyond archive only, with per-message revalidation | bulk folder-action gate passes |
| 11 | TLS CBC cleanup | remove TLS 1.2 CBC suites or document a reviewed exception | TLS gate passes |
| 12 | V3 pilot rehearsal | run daily-driver workflow rehearsal with selected users and archive sanitized evidence | V3 closeout evidence is ready |

## First Next Step

Start by making the V3 release gate honest before adding more daily-driver surface.

The first release-gate foundation implementation is now `make release-check`.
It keeps `make security-check` as developer partial validation and adds a
strict release profile that fails on skipped required phases, missing pinned
tools, missing dependency inventory, missing V2 or host evidence, missing
release-mode WSTG evidence, or missing sanitized evidence summary/archive
generation.

The first implementation plan should inspect and extend:

- `Makefile`
- `maint/security/osmap-security-check.sh`
- `maint/security/osmap-supply-chain-check.sh`
- `maint/security/test-osmap-wstg-testing-pack.sh`
- `maint/wstg-testing-pack/README.md`
- `maint/wstg-testing-pack/run.sh`
- `maint/wstg-testing-pack/run-wstg-pack.py`
- `maint/wstg-testing-pack/wstg-asvs-mapping.json`
- the current evidence references in `docs/V2_PILOT_STATUS.md`, `docs/V2_PILOT_CLOSEOUT.md`, `docs/INTERNET_EXPOSURE_STATUS.md`, and the V3 docs

The expected outcome is not a large feature. The expected outcome is a clean release-mode path that proves when full security validation actually happened and fails when required evidence is missing.

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

The next implementation step should add the smallest server-side draft store
that follows that design. The first storage primitive now exists in
`src/draft.rs`; the next step is authenticated browser route wiring, route
tests, and WSTG updates before any workflow disposition changes from
`roundcube_fallback`.

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
- TLS CBC disposition evidence

Feature work may proceed only when it does not obscure or defer these gates.

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
