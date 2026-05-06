# Version 3 Acceptance Criteria

## Purpose

This document defines the testable Version 3 release gate for OSMAP.

Version 3 is acceptable only when every in-scope daily-driver feature has a specific implementation gate, every required security gate has evidence, all Version 2 gates still pass, and the public browser posture remains least-privilege and regression-tested.

## Required Baseline

Before any Version 3 feature is treated as complete:

- the project distinguishes developer partial checks from release-mode validation
- release-mode validation fails when required validation is skipped or incomplete
- `make security-check` remains available for developer partial checks
- `make release-check` passes in a compatible local or host toolchain without skipping required release phases
- Cargo build, tests, clippy, formatting checks, dependency inventory generation, and Rust supply-chain checks have successful release evidence for the assessed commit
- the Version 2 readiness wrapper still passes on the validated host posture
- public-edge exposure remains gated by the existing internet-exposure, edge-cutover, rollback, observability, and service-health evidence
- production `serve` mode still requires the mailbox helper
- no new browser route bypasses session validation, CSRF for state changes, same-origin enforcement, resource limits, or audited error behavior
- WSTG coverage is updated for changed browser routes, or a documented non-applicability record explains why no new check is needed
- authenticated WSTG and other credential-dependent security tests include credential and TOTP-backed evidence where those tests require it
- docs for the feature name unsupported cases, failure behavior, limits, and fallback behavior

## Release-Mode Rule

Developer validation may report skipped phases clearly.

Release-mode validation must fail when a required phase is skipped. This includes skipped Cargo validation, skipped supply-chain validation, missing host-readiness evidence, missing V2 carry-forward evidence, missing TLS edge evidence, missing resource-timeout evidence, missing V3 feature-gate evidence, and skipped authenticated WSTG or other security tests when the test requires credential and TOTP coverage.

The MIME and HTML correctness gate must include a current redacted live proof
report from `maint/live/osmap-live-validate-v3-mime-html-proof.ksh`. Release
mode must fail when `maint/live/latest-host-v3-mime-html-proof-report.txt` is
missing, belongs to a different assessed commit, lacks the required runtime,
message-view, forced-download, and audit non-leakage pass markers, or contains
session cookies, CSRF tokens, passwords, TOTP material, raw session identifiers,
synthetic full body markers, or full attachment body markers.

For WSTG and other security tests that require authenticated coverage, evidence must show that the real browser credential and TOTP path was exercised. The evidence may use a dedicated validation account with stored test secrets in a local uncommitted `.env`, or a human-prompted flow such as `--prompt-auth --auth-email`. The evidence must not commit plaintext passwords, reusable TOTP seeds, active session cookies, private message bodies, or private attachment content.

The release evidence summary is written to
`maint/live/osmap-v3-release-evidence-summary.json` and
`maint/live/osmap-v3-release-evidence-summary.md`. It must include the checked
TLS edge evidence path, TLS CBC cleanup status, checked resource-timeout
evidence path, and resource-timeout status. Release mode must record an empty
`skipped_checks` array before it can pass.

## Feature Admission Rule

A Version 3 feature may enter implementation only when the following are named in the design or ticket:

- the pilot-proven workflow gap it closes
- the user-visible workflow it enables
- the browser routes and state-changing actions it touches
- the helper operations it uses or adds
- request, response, mailbox, MIME, attachment, and storage limits
- timeout behavior for external command, helper, or backend boundaries
- CSRF, same-origin, session, and authorization requirements
- WSTG disposition
- unit, route, integration, host, and manual-security evidence expected at closeout
- unsupported cases and fallback behavior

## Feature Gates

| Feature | Acceptance gate |
| --- | --- |
| MIME and HTML correctness | MIME parsing remains bounded by part count, nesting, header, filename, charset, transfer encoding, and body limits. Encoded subject, from, date, body, and attachment metadata render correctly for representative messages. Multipart alternative selection is deterministic. Malformed MIME falls back to safe text or clear withheld-state UI. Sanitized HTML keeps the allowlist posture, strips active content, denies relative URLs unless explicitly reviewed, and never loads remote resources. Regression tests cover plain text, HTML-only, multipart alternative, attachment-bearing, malformed boundary, encoded header, transfer-encoded body, inline `cid:` metadata, suspicious filenames, unsupported charset, and oversized inputs. |
| Draft save and resume | Authenticated users can save, list, resume, update, send, and delete bounded drafts. Drafts are scoped to the canonical user. Draft state is stored under reviewed OSMAP state paths with restrictive permissions. Draft POST routes are CSRF-bound and same-origin-bound. Sending a draft submits once and either deletes or marks the draft according to documented behavior. Expired or revoked sessions cannot access drafts. Tests cover ownership isolation, invalid draft IDs, oversized drafts, attachment limits, stale sessions, storage failures, and backend failures. |
| Reply and forward attachment handling | Reply and forward compose flows show original attachments explicitly. Users can choose which original attachments to include where policy allows it. Included attachments are fetched through the existing helper-backed, bounded attachment path and revalidated at send time. Aggregate attachment count and size limits include both uploaded and original-message attachments. Failures do not silently drop selected attachments after user confirmation. Tests cover reply default behavior, forward default behavior, selected original attachments, stale source messages, oversized aggregate attachments, and helper failures. |
| Richer bounded search | Users can search one mailbox or all visible mailboxes with documented query fields, refinements if implemented, result sorting, empty-state behavior, and bounded result limits. Unsupported query syntax returns deterministic 400-class responses. All-mailbox search stays limited to browser-visible mailboxes. Search does not expose backend-only mailbox names. Expensive searches have bounded execution and result behavior. Tests cover valid refinements, invalid refinements, sorting, result caps, unknown mailbox rejection, backend-unavailable behavior, and timeout behavior where applicable. |
| Bounded bulk folder actions | Users can select a bounded number of visible messages and perform approved actions such as archive, move to a visible mailbox, mark read or unread if implemented, or delete only if separately approved by the roadmap. Every action revalidates each mailbox and UID tuple at action time. Partial success is reported explicitly. Existing move throttles or equivalent abuse controls apply. Tests cover valid selection, empty selection, over-limit selection, invalid destination, stale UID, mixed partial results, CSRF rejection, same-origin rejection, and backend failure. |
| Session and device policy | Concurrent browser sessions are allowed by policy, with bounded lifetime, idle timeout, visible metadata, and user-driven revocation. Session list displays normalized device labels, remote address, user-agent metadata, timestamps, and revocation state without exposing secrets or adding remembered-device cookies. Tests cover concurrent session behavior, device label normalization, revocation of one session, revocation of other sessions, revoke-all, expired sessions, idle sessions, and isolated-cookie race retesting. |
| TLS CBC cleanup or exception | TLS 1.2 CBC suites are removed from the reviewed public-edge configuration, or `V3_SECURITY_GATES.md` records a dated compatibility exception with evidence, owner, expiry, exact suites retained, and compensating controls. Evidence includes an external TLS scan or equivalent command output archived under a reviewed evidence path. Current cleanup evidence is `maint/live/osmap-v3-tls-cbc-cleanup-evidence-2026-05-02.txt`. |
| WSTG regression evidence | The WSTG testing pack is current for the V3 browser surface. All applicable scripts pass or have documented non-applicability. Authenticated WSTG tests that require credential and TOTP coverage must not be counted complete if skipped. New V3 routes are covered by route, auth, CSRF, same-origin, injection, upload, business-logic, session, and transport checks as applicable. |

## Daily-Driver Gate

Version 3 is daily-driver ready only when a representative user can complete the following without Roundcube fallback for these workflows:

- login with password plus TOTP
- read plain-text, sanitized-HTML, and attachment-bearing messages
- search enough ordinary mail to find recent and older messages
- compose, save draft, resume draft, attach, and send
- reply and forward with clear attachment handling
- perform bounded folder cleanup on selected messages
- review and revoke browser sessions according to the chosen device policy
- log out and have stale sessions rejected

This gate must be supported by sanitized evidence. Evidence may prove workflow completion without storing private mailbox content.

## Not A Roundcube Clone Gate

Version 3 is not acceptable if it adds broad parity work that is not needed for the daily-driver adoption boundary. The following remain excluded unless a future version explicitly redefines OSMAP:

- contacts and address-book management
- calendar and groupware
- plugin ecosystem
- broad admin console
- remote external content loading
- mobile app
- OpenPGP implementation
- generic mailbox-management suite
- broad JavaScript-heavy client behavior
- unbounded mailbox-wide operations

## Evidence Required At Closeout

The Version 3 closeout record must link:

- the commit or tag being assessed
- release-mode validation result for that commit or tag
- Cargo build and test evidence from a compatible toolchain
- supply-chain evidence, including advisory, source, license, and duplicate dependency checks
- current V2 readiness evidence
- host-readiness and public-edge evidence for the intended deployment host
- V3 feature-gate evidence for every in-scope feature
- current redacted V3 live MIME and HTML proof evidence
- resource-timeout evidence for helper-backed mailbox, search, message-view,
  compose source loading, attachment download, all-mailbox search fanout, and
  message-move paths
- WSTG regression evidence
- authenticated WSTG or other credential-dependent security evidence proving credential and TOTP paths were exercised where required
- TLS CBC removal or exception evidence
- a pilot or rehearsal workflow inventory showing that daily-driver gaps are closed for the selected cohort
- a sanitized evidence archive that excludes plaintext passwords, reusable TOTP seeds, active session cookies, private message bodies, private attachment content, and host secrets
