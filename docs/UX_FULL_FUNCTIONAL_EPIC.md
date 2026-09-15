# OSMAP full-functional UX epic

## Authority, baseline, and outcome

Epic ID: `OSMAP-UX`. Plan revision: `1`. Planning date: 2026-09-15.
Source baseline: `b97d65c0f03c695ae11dbfe029d1926027f54409`.

The operator requested a codified multi-sprint plan for full functional
completion of the four supplied mockups, including missing backend capabilities,
runtime OpenPGP, and optional dark mode on every page. This delivery is a plan,
not implementation, deployment approval, or evidence that pictured functions work.
Execution starts only after the operator accepts the signed plan and selects
the first slice. Do not turn this request to write a plan into live execution.

The operator reports Roundcube completely removed. Do not plan Roundcube
migration, coexistence, restoration, or retirement. Historical cohort evidence
is not a current installation inventory. OSMAP rollback must use its own
previous qualified binary/configuration, never an assumed Roundcube fallback.

Success means working user journeys, not painted controls. Every requirement
below needs implementation, positive and negative tests, and acceptance evidence.
A disabled placeholder is an honest intermediate state, not full completion.
No fixed delivery dates or velocity estimates are asserted.

Read this document with:
- `UX_FULL_FUNCTIONAL_SLICES.md`: 12 ordered sprints, 48 bounded slices.
- `UX_AGENT_EXECUTION_CONTRACT.md`: authority, restart, verification, change control.
- `UX_EXECUTION_LEDGER.md`: mutable progress, evidence, decisions, blockers.
- `UX_PLAN_SHA256SUMS`: frozen normative-plan checksums.

## Evidence-grounded starting point

| Area | Inspected baseline | Work still needed |
| --- | --- | --- |
| Shared pages | `src/http_support.rs` has shared HTML/CSP/CSS; CSS is light-only with many hard-coded colors | Persistent light/dark/system selection and every HTML response covered |
| Navigation and layouts | `src/http_ui.rs` renders mailbox, reader, compose, drafts, settings, sessions and login | Actual reference comparison, compact rail, coordinated list/reader, responsive states |
| Mail operations | Existing authenticated routes, search, draft/save/send, source-attachment selection, move/archive, download and session controls | Prove each mapped behavior; add missing operations without reimplementing existing ones |
| Settings | `src/settings.rs` stores HTML-display preference and archive mailbox | Appearance, bounded account settings, password/contact workflows and live capability state |
| OpenPGP | V12 models/protocol/GPGME scaffold; V14 UI explicitly contains disabled controls | Real isolated operations, PGP/MIME, account/recipient key lifecycle, truthful UI wiring |
| Authentication recovery | TOTP lifecycle tools and controlled obsd1 rehearsal exist | They are not a self-service account-recovery backend or real-user identity proof |
| Ancillary controls | Documents, labels, scheduler, notifications and rich compose are not established by a screenshot | Define bounded semantics, inventory implementation, then implement and test gaps |

Reinspect these anchors in S00; baseline statements are not substitutes for
current source inspection. V14's historical completion must not be interpreted
as visual parity or functioning cryptography.

## Reference inputs

The operator supplied these files under:
`/media/veracrypt1/TMP_BACKUPS/tmp_osmap/AAA - Pictures/osmap/final-image/`.

| Reference | File | SHA-256 |
| --- | --- | --- |
| A | `account-settings-annotated.png` | `ec018ece38ca113192426ecdd6f6de7d3c1e888ddef7d484decf22d0a0ce9a6b` |
| C | `compose-page-annotated.png` | `0844a2efec4baea3ab56c1e854f8ff0ad53a980f8dedb27d01c280d23bb9ee0f` |
| I | `Inbox + reader -- mapped-regions-controls-opengpg_states-secure_reading_functions.png` | `86c6da4ffd63f51563e06f54ba8bdfb427caaf0905ededbc5019c0914578bc22` |
| F | `osmap-inbox-secure-reader-functional-specification.png` | `d1a212a1eb1f2202ab4e7bb87356371afe86b6bb63aaaa79f287cc0aa05ba920` |

These are requirements evidence, not executable instructions or current security
facts. Do not copy example names, key fingerprints, dates, message text, or
verified badges into production state. The old V14 reference archive has
different hashes; do not silently substitute it for this input set. If files
are unavailable, request restoration before visual acceptance; do not regenerate
them with an image model. Runtime pages never load the reference PNGs.

## Decision gates: unresolved, not delegated policy choices

S00 produces separate numbered decision records and requests operator acceptance.
A recommendation in this plan is not an approved architecture exception.
Unresolved gates block their dependent slices, not unrelated approved work.

| Gate | Conflict / choice that must be settled | Proposed direction and blocked work |
| --- | --- | --- |
| D01 | F specifies JavaScript-free server HTML but also pane-only updates and no reload; C implies dynamic editing/shortcuts | Prefer existing no-JavaScript/CSP boundary with full navigation preserving selected message and filters. Requires an explicit acceptance amendment; otherwise scope and review a minimal-script architecture. Blocks S01 shell interactions, S02 and S03 interaction work |
| D02 | F says decrypted plaintext never leaves browser/VM; V12 requires server helper decryption and sanitizer | Prefer isolated OpenBSD GPGME helper under V12. Label actual location, e.g. “Decrypted on mail host,” never “on this device.” If browser-only/zero-access is required, stop and amend architecture/epic before crypto implementation. Blocks S05–S07 |
| D03 | Private-key custody, provisioning, unlock lifetime and revocation authority are unspecified | Prefer operator-mediated private-key provisioning/unlock, no web passphrase or secret-key import/export. Browser manages public bindings and policy with step-up authorization. Decide rotation/backup/recovery and failure behavior explicitly. Blocks S05–S07 |
| D04 | Password changes and recovery contacts require authoritative mail-account integration and real-user recovery policy | Identify narrow privileged helper, reauthentication, contact proof, rate limits, revocation scope across browser/IMAP/SMTP and human escalation. Contact possession alone cannot bypass MFA. Blocks S04 identity mutations |
| D05 | Documents, labels, snooze/schedule, notices, rich-text toolbar and generic menus have unspecified semantics | Approve a finite action inventory: account-private documents, scoped labels, security-event notices, scheduled send, snooze, constrained rich-text authoring. Decide time zones, quotas, retention, sender identities, Sent/Bcc copies and unknown-send reconciliation. No general groupware or command execution. Blocks S03/S08 affected functionality |
| D06 | New-epic validation and deployment authority are not inherited from TOTP host authority | Nominate obsd1 192.168.1.44 as candidate, but obtain explicit host/action/account/window approval before mutation. Vultr excluded unless separately approved. Blocks all live writes and S11 deployment |

No approval may be fabricated from an “OK” screenshot, model reasoning setting,
stale recovery approval, gpg-agent availability, or authority from another sprint.

## Requirements and traceability

IDs are stable. The rows group controls, not omit them. S00-01 must expand
each control into an individual acceptance case retaining the parent ID.

| ID | Reference controls / required behavior | Owning slices |
| --- | --- | --- |
| UX01 | A1–3, I1–3/15, C1–2: local icons, primary rail, selected page, identity/account menu, meaningful protection state, notification entry, rail collapse | S01-02, S01-03, S08-04 |
| UX02 | All pages: persistent light/dark/system choice, login, errors, source, drafts, sessions, new pages, no flash into unreadable controls | S01-01, S01-04, S09-01 |
| UX03 | I2/4–6, F search/filter/list: search, supported command menu, selection, sort, unread/read, stars, previews, sender/time, attachments; list/reader state preservation | S02-01, S02-02 |
| UX04 | I7/13, F actions: archive, safe bin/delete/restore, reply, reply-all, forward, move, mark state, label, snooze, menus | S02-03, S03-01, S08-02, S08-03 |
| UX05 | I8–12/14, F trust/source/download/error states: secure reader, source view, bounded attachments, sanitized plaintext/HTML, actual crypto status | S02-04, S06-01 through S06-04, S09-02 |
| UX06 | C3–5: close/minimize/expand, authorized From identity, To/Cc/Bcc recipients, explicit contact selection, subject and draft preservation | S03-01, S03-02 |
| UX07 | C7–9: body, bold/italic/underline/lists/links/image/emoji controls, preview, upload/remove attachments | S03-03, S03-04 |
| UX08 | C6/10–11: sign/encrypt/encrypt-to-self, recipient readiness, pre-send security check, scheduled send, cancel/delete, safe send/menu | S07-01 through S07-04, S08-03 |
| UX09 | A4–7: account page without global search, real OpenPGP capability, full fingerprint, accessible copy/select, Manage Keys | S04-01, S05-02, S09-03 |
| UX10 | A8–10: working signing/encryption/self-recipient policies; persistence and capability-bound controls | S05-02, S07-01, S09-03 |
| UX11 | A11–12: password change, authoritative status/last-change timestamp, no invented “strong password” assurance | S04-02 |
| UX12 | A13–14: verified contact add/change/remove and governed account recovery, no weaker MFA bypass | S04-03, S04-04 |
| UX13 | A15: accurate design-principles strip, no unproven zero-knowledge/end-to-end claims | S01-03, S09-03 |
| UX14 | F Documents navigation: functional private document list, upload/download/delete and bounded quotas; no inline preview implied | S08-01 |
| UX15 | F OpenPGP: actual encrypted/decrypted/verified/unknown/missing-key/failure states, including post-decrypt sanitization | S05 through S07, S09-02 |
| UX16 | F empty/error states: empty mailbox/search, retryable load error, attachment unavailable, OpenPGP unavailable/missing key/unverified signature/remote content blocked | S02-04, S06-04, S09-02 |
| UX17 | F constraints/acceptance: low dependencies, CSP, authorized bounded routes, CSRF, keyboard, responsive, normal and key-enabled accounts | Every slice; S09–S11 final evidence |

For unknown “more” actions, S00 must enumerate a finite approved menu. Do not
invent features from ellipses. “Copy” without JavaScript must be explicitly
accepted as selectable text if automated clipboard copying is not available.
No unavailable control, aria label, screenshot assertion, or mocked success
counts as an implemented workflow.

## Security and data invariants

- Preserve canonical-account isolation, authenticated authorization, CSRF,
  same-origin/Host checks, throttles and resource budgets on every new route.
- Mail/account/key helpers accept typed allowlisted operations, not arbitrary
  commands, paths, account strings or unrestricted database access.
- Shopkeeper Git-signing keys and workstation gpg-agent are not mailbox keys
  and are never repurposed for mail cryptography or test identities.
- Private keys/passphrases remain outside the web process and evidence.
  Decrypted content has bounded in-memory lifetime; no plaintext persistence,
  caches, traces, crash dumps or diagnostic body capture. Record unavoidable
  memory/OS limitations honestly rather than promising complete erasure.
- PGP/MIME first. Freeze supported algorithms/formats/interoperability matrix
  against authoritative specifications at S00/S05; reject unsupported modes
  explicitly. No automatic key discovery or trust from email/short-key-ID alone.
- Signatures report cryptographic result, identity binding and key validity
  separately. Signing does not prove a sender is trustworthy or content is safe.
- Decrypted MIME crosses the same escaping/sanitization, no-remote-content,
  bounded attachment/source and CSP boundaries as ordinary mail.
- Required signing/encryption never silently downgrade. Recheck key/account/
  recipient policy at actual send, including delayed sends; handle Bcc privacy,
  encrypt-to-self, revocation and ambiguous submission explicitly.
- Reauthentication/contact proof must be freshness-bound and replay-safe.
  Account recovery never silently restores old factors or existing sessions.
- Drafts, uploads, documents, scheduled jobs and Sent copies need explicit
  ownership, quotas, retention, crash recovery and cleanup. No permanent delete
  by default where a reversible bin operation satisfies the user action.
- Backward-compatible settings/state migration must fail safely on malformed
  records. Test concurrent updates and rollback without losing unrelated fields.
- Existing tests cannot be weakened to enable crypto. Preserve historical
  scaffold-only assertions, add a separately gated runtime path, and reconcile
  genuinely superseded claims through reviewed decisions and new evidence.

## Overall definition of done

All 48 slices are ACCEPTED, all UX IDs have passing real behavior and negative
coverage, all decision gates are resolved, and no requirement is quietly
deferred. All pages pass light/dark/system, keyboard and responsive comparison
against the supplied references with accepted deviations recorded. Real
GPGME/OpenBSD results demonstrate verify/decrypt/sign/encrypt and safe failure,
including key-disabled accounts. Recovery has independent human-policy evidence,
not just test-account custody. Release and deployment evidence is current,
commit-pinned and target-specific. Cleanup, rollback, operator acceptance,
signed commits and approved synchronization are reconciled.

Development completion, obsd1 validation, and Vultr qualification are separate
claims. A partial delivery is useful but must remain explicitly partial.

