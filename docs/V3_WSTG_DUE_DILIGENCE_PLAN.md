# Version 3 WSTG Due Diligence Plan

## Purpose

This document defines the Version 3 OWASP Web Security Testing Guide due-diligence workstream for OSMAP.

The goal is not to claim broad compliance from a small browser regression pack. The goal is to make the coverage model honest, repeatable, version-pinned, and strong enough that the known WSTG gaps are addressed before Version 3 closeout.

OSMAP is a focused OpenBSD-first webmail access layer. The authoritative mail substrate remains Postfix, Dovecot, Rspamd, nginx, TLS, PF, and the OpenBSD host. WSTG evidence in this repository validates the OSMAP browser surface and the directly relevant public-edge posture. Mail-stack internals remain covered by mail-stack and live-host validation tooling unless this document names a browser-facing OSMAP boundary.

## Source Standard

The WSTG source used for V3 coverage analysis must be recorded for every release candidate.

Required metadata:

- WSTG source name
- WSTG source URL
- WSTG version or branch
- capture date
- upstream commit hash when using the OWASP `master` branch
- local matrix file used for the run
- OSMAP git commit or tag being assessed
- target host and base URL
- authenticated mode, unauthenticated mode, or both
- evidence archive path

The current repository already has a WSTG v4.2 matrix at:

- `maint/wstg-testing-pack/wstg-scenario-matrix.v42.csv`
- `maint/wstg-testing-pack/wstg-scenario-matrix.v42.json`

Version 3 must add or maintain a latest-track matrix when the OWASP current development tree is used. That matrix should be named:

- `maint/wstg-testing-pack/wstg-scenario-matrix.latest.json`

The latest-track matrix must include the upstream commit hash, because OWASP latest content can move.

## Coverage Dispositions

Every WSTG item in the active matrix must have exactly one clear disposition:

| Disposition | Meaning |
| --- | --- |
| `automated` | A deterministic OSMAP test exists and produces redacted evidence. |
| `manual` | The item needs human interaction or operator review and has a required evidence shape. |
| `not_applicable` | The item does not apply to OSMAP, with a written reason and supporting evidence. |
| `covered_by_other_evidence` | Another named OSMAP or mail-stack artifact covers the boundary. |
| `deferred` | The item is applicable but intentionally deferred with a dated decision-log entry, owner, reason, and expiry or trigger. |
| `blocked` | The item cannot be completed because a required fixture, account, host state, or implementation boundary is missing. |

`skip` is a runner outcome, not a release disposition. A skipped required WSTG item cannot satisfy Version 3 release mode.

## Current Baseline

The current WSTG pack is useful targeted regression coverage, but it is not full WSTG coverage.

| Baseline item | Current state |
| --- | --- |
| Existing OSMAP WSTG runner tests | 30 mapped tests |
| Existing explicit gaps | 3 gaps |
| Existing WSTG scenario matrix | WSTG v4.2 |
| WSTG v4.2 scenario rows | 97 |
| WSTG v4.2 rows mapped by current pack | 36 |
| WSTG v4.2 rows not mapped by current pack | 61 |
| WSTG v4.2 rows with explicit Slice 1 disposition | 97 |
| WSTG v4.2 automated dispositions | 36 |
| WSTG v4.2 blocked dispositions pending due diligence | 61 |
| Current OWASP latest coverage | Must be pinned and tracked before V3 closeout |

The Version 3 workstream therefore treats the current pack as a starting point. It must be extended into a slice-based due-diligence program.

## V3 WSTG Slices

### Slice 1, Coverage inventory and source pinning

Priority: critical.

Required before V3 close: yes.

Required outcomes:

- Record WSTG v4.2 and current latest source metadata.
- Keep the existing v4.2 matrix.
- Add a latest-track matrix when using OWASP latest.
- Add matrix-level status fields for automated, manual, not applicable, deferred, blocked, and covered by other evidence.
- Make each runner report include WSTG source metadata, OSMAP commit, target host, authenticated mode, result, and evidence path.
- Ensure `.env` remains ignored and `.env.example` documents every non-secret variable.

Acceptance evidence:

- `docs/V3_WSTG_DUE_DILIGENCE_PLAN.md`
- `docs/V3_WSTG_COVERAGE_GATE.md`
- `maint/wstg-testing-pack/COVERAGE.md`
- `maint/wstg-testing-pack/wstg-scenario-matrix.v42.json`
- `maint/wstg-testing-pack/wstg-scenario-matrix.latest.json`, when latest is used
- WSTG output summary showing source metadata

### Slice 2, Authorization and account isolation

Priority: critical.

Required before V3 close: yes.

Required outcomes:

- Prove one authenticated mailbox user cannot access another user's mailbox, message, attachment, draft, sent item, or bulk action target.
- Test mailbox name tampering.
- Test UID or message identifier tampering.
- Test attachment access tampering.
- Test draft access tampering.
- Test sent mail access tampering.
- Test route authorization bypass.
- Test privilege escalation attempts.
- Produce negative evidence showing denied cross-user access.

Acceptance evidence:

- Two controlled validation accounts or an equivalent isolated fixture model.
- Redacted requests and responses for cross-user denial cases.
- No private message body or attachment content in committed evidence.

Slice 2 implementation evidence starts with:

- `docs/V3_AUTHORIZATION_ACCOUNT_ISOLATION.md`
- `OSMAP-WSTG-ATHZ-001`
- authenticated, TOTP-backed, host-assisted primary-vs-secondary negative
  evidence for mailbox, message, attachment, sent-mail, search, stale-session,
  and route-bypass probes

### Slice 3, Session lifecycle and cookie security

Priority: critical.

Required before V3 close: yes.

Required outcomes:

- Fresh session issuance after login.
- Logout invalidates the session.
- Old session cookie cannot be reused after logout.
- Session fixation is rejected.
- Idle timeout behavior is tested or explicitly documented.
- Absolute timeout behavior is tested or explicitly documented.
- Concurrent session behavior is tested and documented.
- Cookie flags are validated: `Secure`, `HttpOnly`, and `SameSite`.
- CSRF protections remain valid on state-changing routes.
- TOTP authenticated flow produces evidence without exposing reusable secrets.

Acceptance evidence:

- Authenticated WSTG release run with credential and TOTP proof.
- Session invalidation evidence.
- Concurrent-session or device-policy evidence.

Slice 3 implementation evidence starts with:

- `docs/V3_SESSION_LIFECYCLE_EVIDENCE.md`
- `OSMAP-WSTG-SESS-006`
- authenticated old-cookie-after-logout and stale-cookie rejection evidence
- static timeout, exposed-token, concurrent-session, puzzling, and revocation
  race evidence

### Slice 4, IMAP, SMTP, and webmail-specific input validation

Priority: critical.

Required before V3 close: yes.

Required outcomes:

- Safe synthetic IMAP command-injection style payloads in mailbox names.
- Safe synthetic IMAP command-injection style payloads in search terms.
- Message UID tampering checks.
- SMTP header injection checks for recipient, subject, and display-name fields.
- Newline injection checks in send fields.
- Attachment filename injection checks.
- Dangerous content type handling checks.
- Dangerous message body handling checks.
- Stored HTML email sanitization regression checks.
- Reflected HTML or script payload checks in UI fields.
- CSV injection checks where exports exist, or not-applicable proof where exports do not exist.

Acceptance evidence:

- Controlled fixtures only.
- Non-destructive validation accounts only.
- No destructive or uncontrolled fuzzing.

Slice 4 implementation evidence starts with:

- `docs/V3_WEBMAIL_INPUT_VALIDATION_EVIDENCE.md`
- `OSMAP-WSTG-INPV-004`
- authenticated rejected probes for SMTP header/newline, display-name-shaped
  recipient, mailbox, UID, search, attachment filename, and dangerous
  content-type inputs
- static proof for body handling, attachment content-type normalization, stored
  HTML sanitization, and CSV export non-applicability

### Slice 5, Weak cryptography and transport security

Priority: critical.

Required before V3 close: yes.

Required outcomes:

- TLS 1.0 rejected.
- TLS 1.1 rejected.
- TLS 1.2 accepted only with strong forward-secret AEAD cipher suites if TLS 1.2 is enabled.
- TLS 1.3 preferred where supported.
- Anonymous, null, MD5, RC4, 3DES, DES, export, and CBC legacy suites rejected.
- HSTS present and correct.
- Sensitive authenticated routes are HTTPS-only.
- Session cookies are not sent over plaintext.
- OCSP stapling status recorded if available, but not a hard fail unless the project documents it as required.

Acceptance evidence:

- Static TLS policy guard output.
- Live TLS standard validation output.
- Weak-protocol and weak-cipher rejection evidence.

### Slice 6, API-style route and state-transition testing

Priority: high.

Required before V3 close: yes, unless not applicable with evidence.

Required outcomes:

- Inventory all API-like or form-backed endpoints.
- Test broken object-level authorization.
- Test broken function-level authorization.
- Test excessive data exposure.
- Test JSON endpoints if any exist.
- Mark GraphQL not applicable with evidence if GraphQL does not exist.
- Test method tampering on sensitive routes.
- Test content-type tampering on sensitive routes.
- Test replay of state-changing requests.
- Test duplicate submit behavior.

Acceptance evidence:

- Endpoint inventory.
- Redacted state-transition evidence.
- Not-applicable proof for GraphQL if unused.

### Slice 7, Business logic and workflow abuse

Priority: high.

Required before V3 close: yes.

Required outcomes:

- Send workflow cannot be skipped or forged.
- Draft workflow cannot be abused to send without authorization.
- Attachment workflow validates size, type, and ownership.
- Move, delete, and bulk actions require valid session and CSRF state.
- Search does not expose unauthorized data.
- Rate-limit or misuse protections are tested or documented.
- Payment functionality marked not applicable with evidence.

Acceptance evidence:

- Controlled validation-account workflow run.
- Redacted business-logic report.
- No private mailbox content committed.

### Slice 8, Client-side, browser storage, and UI security

Priority: high.

Required before V3 close: yes, unless not applicable with evidence.

Required outcomes:

- DOM XSS disposition.
- HTML injection disposition.
- JavaScript execution disposition.
- CSS injection disposition.
- Client-side redirect disposition.
- Clickjacking disposition.
- CORS disposition.
- Browser storage disposition.
- Reverse tabnabbing disposition.
- WebSocket not-applicable proof if unused.
- Web messaging not-applicable proof if unused.
- Flash not-applicable proof if unused.
- Client-side template injection not-applicable proof if unused.

Acceptance evidence:

- Browser header evidence.
- Route evidence.
- Source review evidence where client-side behavior is intentionally absent.

### Slice 9, Error handling and information disclosure

Priority: high.

Required before V3 close: yes.

Required outcomes:

- No stack traces to unauthenticated users.
- No stack traces to authenticated users.
- No raw Rust panic output.
- No raw backend command output.
- No secrets, session IDs, TOTP secrets, IMAP credentials, SMTP credentials, or filesystem paths in UI errors.
- Invalid mailbox, invalid UID, invalid attachment, invalid route, and invalid method errors are safe.

Acceptance evidence:

- Error-route evidence.
- Redaction evidence.
- Static review of logging and error paths.

### Slice 10, Release gate integration

Priority: critical.

Required before V3 close: yes.

Required outcomes:

- Release mode fails when WSTG source metadata is missing.
- Release mode fails when the active WSTG matrix is missing.
- Release mode fails when critical slices are incomplete.
- Release mode fails when required authenticated WSTG tests are skipped.
- Release mode fails when TOTP human-interaction or dedicated-account evidence is missing for applicable authenticated checks.
- Release mode fails when not-applicable items lack written reasons.
- Release mode fails when reports claim success without evidence paths.
- Release mode fails when high-priority deferrals lack decision-log approval.

Acceptance evidence:

- `make release-check` evidence.
- WSTG release summary.
- Sanitized release evidence archive.

## Safe Testing Rules

All V3 WSTG tests must remain defensive, scoped, and controlled.

Allowed:

- safe synthetic payloads
- controlled validation accounts
- controlled mailbox fixtures
- bounded request counts
- host-assisted read-only checks
- explicitly approved host-assisted live validators that clean up after themselves

Not allowed:

- uncontrolled fuzzing
- destructive testing against real user mail
- credential stuffing
- denial-of-service testing
- broad internet scanning
- payloads intended for third-party misuse
- committed secrets or private mailbox contents

## Closeout Rule

Version 3 cannot close until every critical WSTG slice is coded, tested, and evidenced, or marked not applicable with a reviewed reason and supporting evidence.

High-priority WSTG gaps cannot be silently ignored. A high-priority deferral requires a decision-log entry, owner, reason, evidence, and expiry or explicit follow-up trigger.
