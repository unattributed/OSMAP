# Version 3 Acceptance Criteria

## Purpose

This document defines the testable Version 3 release gate for OSMAP.

Version 3 is acceptable only when every in-scope daily-driver feature has a
specific implementation gate, all Version 2 gates still pass, and the public
browser posture remains least-privilege and regression-tested.

## Required Baseline

Before any Version 3 feature is treated as complete:

- `make security-check` passes in a compatible local or host toolchain
- the Version 2 readiness wrapper still passes on the validated host posture
- public-edge exposure remains gated by the existing internet-exposure,
  edge-cutover, rollback, observability, and service-health evidence
- the implementation still requires the mailbox helper in production `serve`
  mode
- no new browser route bypasses session validation, CSRF for state changes, or
  same-origin enforcement
- docs for the feature name the unsupported cases and fallback behavior

## Feature Gates

| Feature | Acceptance gate |
| --- | --- |
| MIME and HTML correctness | MIME parsing remains bounded by part count, nesting, header, filename, and body limits; encoded subject/from/date summaries render correctly for representative messages; multipart alternative selection is deterministic; malformed MIME falls back to safe text or clear withheld-state UI; sanitized HTML keeps the allowlist posture, strips active content, denies relative URLs, and never loads remote resources; regression tests cover plain text, HTML-only, multipart alternative, attachment-bearing, malformed boundary, encoded header, inline `cid:` metadata, and oversized inputs. |
| Draft save and resume | Authenticated users can save, list, resume, update, send, and delete bounded drafts; drafts are scoped to the canonical user; draft state is stored under reviewed OSMAP state paths with restrictive permissions; draft POST routes are CSRF-bound and same-origin-bound; sending a draft submits once and either deletes or marks the draft according to documented behavior; expired or revoked sessions cannot access drafts; tests cover ownership isolation, invalid draft IDs, oversized drafts, attachment limits, and backend failures. |
| Reply and forward attachment handling | Reply and forward compose flows show original attachments explicitly; users can choose which original attachments to include where the policy allows it; included attachments are fetched through the existing helper-backed, bounded attachment path and revalidated at send time; aggregate attachment count and size limits include both uploaded and original-message attachments; failures do not silently drop selected attachments after user confirmation; tests cover reply default behavior, forward default behavior, selected original attachments, stale source messages, oversized aggregate attachments, and helper failures. |
| Richer search | Users can search one mailbox or all visible mailboxes with documented query fields, date or sender refinements if implemented, result sorting, empty-state behavior, and bounded result limits; unsupported query syntax returns deterministic 400-class responses; all-mailbox search stays limited to browser-visible mailboxes; search does not expose backend-only mailbox names; tests cover valid refinements, invalid refinements, sorting, result caps, unknown mailbox rejection, and backend-unavailable behavior. |
| Bounded bulk folder actions | Users can select a bounded number of visible messages and perform approved actions such as archive, move to a visible mailbox, mark read/unread if implemented, or delete only if separately approved by the roadmap; every action revalidates each mailbox/UID tuple at action time; partial success is reported explicitly; existing move throttles or equivalent abuse controls apply; tests cover valid selection, empty selection, over-limit selection, invalid destination, stale UID, mixed partial results, CSRF rejection, and same-origin rejection. |
| Session and device policy | The chosen policy for concurrent sessions, device labels, remembered device metadata, and revocation is documented and enforced; session list displays enough metadata for users to identify sessions without exposing secrets; policy violations are deterministic and logged; tests cover session cap behavior, device label normalization, revocation of one session, revocation of other sessions, revoke-all, expired sessions, idle sessions, and isolated-cookie race retesting. |
| TLS CBC cleanup or exception | TLS 1.2 CBC suites are removed from the reviewed public-edge configuration, or `V3_SECURITY_GATES.md` records a dated compatibility exception with evidence, owner, expiry, and compensating controls; evidence includes an external TLS scan or equivalent command output archived under `maint/live/`. |
| WSTG regression evidence | The WSTG testing pack is current for the V3 browser surface; all applicable scripts pass or have documented non-applicability; new V3 routes are covered by route, auth, CSRF, same-origin, injection, upload, business-logic, session, and transport checks as applicable. |

## Daily-Driver Gate

Version 3 is daily-driver ready only when a representative user can complete
the following without Roundcube fallback for these workflows:

- login with password plus TOTP
- read plain-text, sanitized-HTML, and attachment-bearing messages
- search enough ordinary mail to find recent and older messages
- compose, save draft, resume draft, attach, and send
- reply and forward with clear attachment handling
- perform bounded folder cleanup on selected messages
- review and revoke browser sessions according to the chosen device policy
- log out and have stale sessions rejected

## Not A Roundcube Clone Gate

Version 3 is not acceptable if it adds broad parity work that is not needed for
the daily-driver adoption boundary. The following remain excluded unless a
future version explicitly redefines OSMAP:

- contacts and address-book management
- calendar and groupware
- plugin ecosystem
- broad admin console
- remote external content loading
- mobile app
- OpenPGP implementation
- generic mailbox-management suite

## Evidence Required At Closeout

The Version 3 closeout record must link:

- the commit or tag being assessed
- local `make security-check` result, or the reason the local cargo phases were
  skipped and the host/CI result that covered them
- current V2 readiness evidence
- V3 feature-gate evidence for every in-scope feature
- WSTG regression evidence
- TLS CBC removal or exception evidence
- a pilot or rehearsal workflow inventory showing that daily-driver gaps are
  closed for the selected cohort
