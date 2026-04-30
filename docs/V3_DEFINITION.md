# Version 3 Definition

## Purpose

This document defines the authoritative Version 3 boundary for OSMAP.

Version 3 is a focused daily-driver hardening cycle for the validated OpenBSD mail-host shape. It turns the completed Version 2 pilot into safer routine browser-mail use without turning OSMAP into a Roundcube clone, a groupware suite, or a broad mailbox-management product.

## Authoritative Definition

OSMAP Version 3 is V2 plus controlled daily-use continuity, correctness, and release assurance.

Version 3 preserves the Version 2 `_osmap` web runtime, the `vmail` mailbox-helper boundary, public-edge hardening, the production helper requirement, and all Version 2 security gates. It closes only the pilot-proven workflow gaps that block routine browser-mail use for selected users.

Version 3 is not acceptable if feature work outruns security evidence. Daily-driver features may be built only behind explicit resource limits, tests, WSTG coverage, supply-chain review, and release-mode validation.

## Version 3 Operating Principle

The Version 3 cycle is foundation-first.

The first obligation is to make the release gate honest and non-ambiguous. Developer validation may remain partial, but release validation must fail on skipped required checks, missing supply-chain tools, missing authenticated WSTG coverage where credentials and TOTP are required, missing host-readiness evidence, or missing sanitized evidence artifacts.

Feature delivery comes after that standard is enforceable.

## Working Definition

Version 3 is V2 plus narrowly scoped work in these areas:

- release-mode validation that cannot pass on skipped required security checks
- Rust supply-chain assurance as a first-class release gate
- explicit resource and timeout controls for expensive browser, helper, mailbox, MIME, send, and move paths
- WSTG and other security-test evidence that exercises credential and TOTP-dependent paths when those paths are in scope
- MIME and HTML correctness
- draft save and resume
- reply and forward attachment handling
- richer bounded search
- bounded bulk folder actions
- session and device policy
- TLS CBC cleanup or a dated compatibility exception

## Why Version 3 Exists

Version 2 proved the secure browser-mail slice under limited direct public exposure. The pilot users completed retrieve, send, and send-with-attachments successfully. The closeout evidence also showed that normal daily adoption needs a small set of continuity, correctness, and ergonomics improvements.

Version 3 exists to close those proven adoption gaps while increasing assurance. It does not exist to add contacts, calendars, plugins, groupware, mobile applications, broad administrative surfaces, remote external content loading, or a general Roundcube replacement feature set.

## Version 3 In Scope

| Area | Version 3 target | Acceptance source |
| --- | --- | --- |
| Release-mode validation | separate developer partial checks from release gates; release gates fail on skipped required checks, missing evidence, missing supply-chain tooling, or missing credential and TOTP-backed security coverage when required | `V3_SECURITY_GATES.md` |
| Supply-chain assurance | make dependency inventory, advisory review, source control, license control, duplicate-dependency review, and exception handling mandatory for release candidates | `V3_SECURITY_GATES.md` |
| Resource and timeout control | prove expensive HTTP, auth, helper, mailbox, search, MIME, attachment, send, move, and bulk paths have bounded inputs, bounded outputs, deterministic failure behavior, and timeouts where external command or helper boundaries exist | `V3_SECURITY_GATES.md` |
| WSTG and security-test evidence | keep the WSTG pack current for the V3 browser surface; authenticated WSTG and other credential-dependent security tests must prove that real credential and TOTP paths were exercised without committing secrets | `V3_SECURITY_GATES.md` |
| MIME and HTML correctness | improve message selection, transfer decoding, encoded header handling, attachment metadata, sanitized HTML fidelity, and deterministic fallback behavior without loading remote content | `V3_ACCEPTANCE_CRITERIA.md` |
| Draft save and resume | persist bounded compose drafts for authenticated users and resume them without weakening CSRF, session, storage, or ownership boundaries | `V3_ACCEPTANCE_CRITERIA.md` |
| Reply and forward attachments | provide explicit, bounded handling for original-message attachments during reply or forward | `V3_ACCEPTANCE_CRITERIA.md` |
| Richer bounded search | add practical query refinement, sorting, and result clarity while preserving backend-visible mailbox limits and result caps | `V3_ACCEPTANCE_CRITERIA.md` |
| Bounded bulk folder actions | support selected-message actions needed for daily cleanup without adding broad mailbox-management authority | `V3_ACCEPTANCE_CRITERIA.md` |
| Session and device policy | define and enforce concurrent-session, device labeling, revocation, expiry, and race-retest behavior | `V3_SECURITY_GATES.md` |
| TLS CBC cleanup | remove TLS 1.2 CBC suites or record a dated compatibility exception with owner, expiry, evidence, and compensating controls | `V3_SECURITY_GATES.md` |

## Explicitly Out Of Scope

- contacts
- calendar
- groupware
- plugins
- mobile applications
- broad admin console
- SaaS or multi-tenant hosting model
- enterprise identity federation
- remote external content loading
- attachment preview behavior that widens browser trust
- JavaScript-heavy webmail behavior
- OpenPGP implementation, except design-only investigation
- broad runtime rewrite not justified by a measured security or reliability blocker
- replacement of Postfix, Dovecot, nginx, PF, Rspamd, or the existing mail substrate
- Roundcube parity work that is not tied to pilot-proven daily-driver gaps
- unbounded mailbox-wide operations

## Security Invariants

- all Version 2 gates remain required
- `_osmap` must not gain mail-storage authority directly
- the `vmail` mailbox-helper boundary must remain explicit, local, narrow, and reviewable
- production `serve` mode must keep using the local mailbox-helper boundary
- browser routes must remain server-rendered and dependency-light
- state-changing routes must remain CSRF-bound and same-origin-bound
- public edge hardening must remain mandatory before direct browser exposure is claimed
- no V3 feature may require direct browser access to IMAP, SMTP submission, helper sockets, local state directories, or privileged host operations
- HTML rendering must remain sanitizer-backed, active-content-free, and remote-resource-free
- attachment behavior must remain bounded, explicit, forced-download by default, and auditable
- every new browser route must have resource limits, auth/session expectations, CSRF and same-origin expectations, WSTG disposition, and tests before it can be accepted
- runtime rewrite work is allowed only when an acceptance gate proves the current shape cannot safely satisfy the requirement

## Completion Test

Version 3 is complete only when all of the following are true:

- V2 pilot-complete status remains intact
- release-mode validation exists and cannot pass on skipped required checks
- every V3 security gate has current repo-owned or explicitly archived sanitized evidence
- every in-scope V3 feature has passed its acceptance gate
- WSTG and other credential-dependent security tests prove that credential and TOTP paths were exercised where applicable
- daily-driver users can read, search, draft, resume, reply, forward, attach, send, and perform bounded folder cleanup without Roundcube fallback for those workflows
- unsupported workflows are still clearly named instead of implied
- OSMAP remains a focused secure browser-mail access layer, not a broad collaboration suite
