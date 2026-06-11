# Version 4 Definition

## Purpose

This document defines the authoritative Version 4 boundary for OSMAP.

Version 4 is a hostile-content safety release. It takes the Version 3
daily-driver browser-mail surface and tightens the parts most exposed to
attacker-controlled message content: MIME body selection, sanitized HTML
rendering, external-link treatment, attachment download behavior, and evidence
redaction.

## Authoritative Definition

OSMAP Version 4 is V3 plus hostile-content containment for the browser
application boundary.

Version 4 is not a rich webmail rendering release. It does not exist to make
email content globally safe, to add remote content loading, or to preview active
attachments. Email remains attacker controlled. Version 4 exists to prove that
viewing untrusted messages in OSMAP does not give that attacker active browser
execution, automatic remote fetches, invisible unsafe navigation, or unsafe
attachment serving by default.

## Operating Principle

The Version 4 cycle is evidence-first.

Every V4 change must preserve the server-rendered, no-Javascript,
no-remote-load browser boundary. A payload class is not considered handled until
there is fixture, route, or live-host evidence showing the expected safe
behavior and the evidence itself is redacted enough to commit or archive
safely.

## Working Definition

Version 4 is V3 plus narrowly scoped work in these areas:

- hostile HTML sanitizer hardening
- visible disclosure for preserved external links
- attachment download hardening for browser-executable media types
- MIME failure behavior for malformed, ambiguous, unsupported, or oversized
  inputs
- fixture and live evidence for modern hostile webmail payload classes
- redacted release evidence that maps each payload class to expected OSMAP
  behavior

## In Scope

| Area | Version 4 target | Acceptance source |
| --- | --- | --- |
| Sanitized message rendering | strip active content, remote fetch surfaces, scriptable containers, form controls, unsafe URL schemes, relative URLs, comments, metadata refresh, CSS, SVG, MathML, frames, objects, embeds, templates, and event handlers | `V4_ACCEPTANCE_CRITERIA.md` |
| Link risk visibility | preserve only reviewed schemes and visually disclose preserved destinations in rendered message bodies | `V4_ACCEPTANCE_CRITERIA.md` |
| Attachment containment | force download and downgrade browser-executable attachment media types to `application/octet-stream` with `nosniff` | `V4_ACCEPTANCE_CRITERIA.md` |
| MIME fail-closed behavior | withhold or clearly mark unsupported, malformed, ambiguous, or oversized message bodies instead of rendering unsafe content | `V4_ACCEPTANCE_CRITERIA.md` |
| Live hostile-content proof | prove hostile HTML rendering, attachment download hardening, and report redaction through the repo-owned live validator or an approved route-level successor | `V4_SECURITY_GATES.md` |
| Residual-risk documentation | name remaining user-driven risk for external links and files opened outside OSMAP | `V4_HOSTILE_CONTENT_TEST_MATRIX.md` |

## Explicitly Out Of Scope

- rich HTML mail rendering
- Javascript-based message display
- inline image rendering
- automatic remote-content loading
- attachment preview
- malware scanning
- URL reputation scoring
- content rewriting that claims to make files safe outside OSMAP
- contacts, calendar, groupware, plugins, mobile applications, or broad
  Roundcube parity work
- replacing Postfix, Dovecot, nginx, PF, Rspamd, or the existing mail substrate

## Security Invariants

- all Version 3 gates remain required
- OSMAP remains a focused secure browser-mail access layer
- browser routes remain server-rendered and dependency-light
- no V4 feature may require client-side Javascript
- remote message resources must not load automatically
- HTML message bodies must remain sanitizer-backed
- state-changing routes remain CSRF-bound and same-origin-bound
- attachment downloads remain bounded, explicit, auditable, and forced-download
  by default
- message bodies, attachment bodies, session cookies, CSRF tokens, credentials,
  TOTP material, provider secrets, and host secrets must not enter release
  evidence

## Completion Test

Version 4 is complete only when all of the following are true:

- V3 closeout and carry-forward gates remain intact for the assessed commit or
  tag
- every V4 acceptance criterion has fixture, route, live-host, or documented
  non-applicability evidence
- the V4 hostile-content safety gate passes in the local security check
- the live hostile-content validator or approved successor produces a current
  sanitized report for the assessed commit or tag
- release evidence proves hostile HTML rendering, executable attachment
  containment, and evidence redaction
- residual risk for preserved external links and files opened outside OSMAP is
  documented plainly
- unsupported rich-mail behaviors remain named rather than implied

