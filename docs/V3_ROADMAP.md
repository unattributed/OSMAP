# Version 3 Roadmap

## Purpose

This roadmap sequences Version 3 work so OSMAP becomes a focused daily-driver
adoption release without weakening the Version 2 trust boundary or drifting
into broad webmail parity.

## Roadmap Rules

- keep application changes behind the gates in `V3_ACCEPTANCE_CRITERIA.md`
- preserve the `_osmap` plus `vmail` runtime boundary before adding workflow
  convenience
- land one feature slice at a time with tests and security evidence
- update `PILOT_WORKFLOW_INVENTORY.md` when a workflow changes disposition
- keep WSTG regression proof current as browser routes are added
- reject feature requests that belong to contacts, calendar, groupware,
  plugins, mobile app, broad admin, external content loading, or OpenPGP
  implementation

## Work Sequence

| Order | Slice | Deliverable | Exit gate |
| --- | --- | --- | --- |
| 1 | MIME and HTML correctness | tighten representative message correctness before expanding compose continuity | MIME/HTML feature gate passes with regression tests and no remote content loading |
| 2 | Draft save and resume design | define draft storage, ownership, limits, routes, and failure behavior before code | design reviewed against session, CSRF, state-path, and confinement constraints |
| 3 | Draft save and resume implementation | authenticated draft create, list, update, resume, send, and delete | draft feature gate passes |
| 4 | Reply and forward attachment handling | explicit original-attachment selection and bounded reattachment | reply/forward attachment gate passes |
| 5 | Richer search | practical refinements, sorting, result caps, and deterministic invalid-query handling | richer search gate passes |
| 6 | Bounded bulk folder actions | selected-message cleanup beyond archive only, with per-message revalidation | bulk folder-action gate passes |
| 7 | Session and device policy | concurrent-session decision, device labels, policy enforcement, race retest | session/device security gate passes |
| 8 | TLS CBC cleanup | remove TLS 1.2 CBC suites or document a reviewed exception | TLS gate passes |
| 9 | WSTG regression closeout | rerun applicable WSTG pack and archive evidence | WSTG gate passes |
| 10 | V3 pilot rehearsal | run daily-driver workflow rehearsal with selected users | V3 closeout evidence is ready |

## First Next Step

Start Version 3 with the MIME and HTML correctness slice. It is the lowest-risk
foundation for later daily-driver work because drafts, replies, forwards, and
search all depend on reliable message summaries, body selection, attachment
metadata, and safe rendering.

The first implementation plan should inspect and extend:

- `src/mime.rs`
- `src/rendering_html.rs`
- message summary and message-view rendering routes
- current MIME, HTML, attachment, and encoded-header tests
- `maint/live/osmap-live-validate-encoded-header-summary.ksh`
- WSTG scripts that cover HTML, injection, attachment, and search behavior

Do not add remote image loading, rich-text compose, JavaScript rendering, or a
new mail-client engine as part of this slice.

## Design-Only Investigation Track

OpenPGP may receive design-only investigation during Version 3, limited to:

- threat model
- user workflow inventory
- key custody options
- reasons to defer implementation

No OpenPGP signing, encryption, decryption, key management, or server-side GPG
implementation is in Version 3 scope.

## Defers Beyond Version 3

- contacts
- calendar
- groupware
- plugin ecosystem
- mobile app
- broad admin console
- remote external content loading
- broad runtime rewrite
- full Roundcube parity
