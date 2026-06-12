# Version 4 Acceptance Criteria

## Purpose

This document defines the testable Version 4 release gate for OSMAP.

Version 4 is acceptable only when hostile message content remains contained
inside the browser boundary, executable attachments are not served as active
browser content, evidence is redacted, and all Version 3 carry-forward gates
still pass.

## Required Baseline

Before any Version 4 slice is treated as complete:

- all Version 3 release and security gates remain required
- `make security-check` or the equivalent developer gate passes for the
  assessed commit
- the Rust build, test, clippy, formatting, and supply-chain phases pass on a
  compatible toolchain
- no new browser route bypasses session validation, CSRF for state changes,
  same-origin enforcement, resource limits, or audited error behavior
- the browser content-security posture remains no-script and no-remote-load
- WSTG and security-test dispositions are updated when the browser surface
  changes, or a documented non-applicability record explains why no new check
  is needed
- docs name unsupported rich-mail behavior, failure behavior, limits, residual
  risk, and fallback behavior

## Release-Mode Rule

Developer validation may be used for local iteration.

Release validation must fail when required V4 evidence is missing, skipped,
stale, or tied to a different assessed commit or tag. This includes local
fixture coverage, route or live-host hostile-content evidence, executable
attachment download evidence, and evidence-redaction checks.

The hostile corpus gate is mandatory release evidence. It must execute
`maint/security/osmap-v4-hostile-assurance-gate.sh`, produce
`maint/live/osmap-v4-hostile-assurance-report.json`, archive
`maint/live/osmap-v4-hostile-assurance-evidence.tar.gz`, and fail if fixture
metadata or category coverage is incomplete.

The current live evidence lane is
`maint/live/osmap-live-validate-v4-hostile-content.ksh`, which writes
`maint/live/latest-host-v4-hostile-content-report.txt`. An approved successor
may replace it only if it proves the same hostile HTML rendering, attachment
download hardening, and redaction requirements.

## Feature Gates

| Feature | Acceptance gate |
| --- | --- |
| Hostile HTML sanitizer hardening | Sanitized HTML rendering strips scriptable tags, event handlers, form controls, CSS, SVG, MathML, frames, objects, embeds, templates, comments, metadata refresh, unsafe URL schemes, relative URLs, protocol-relative URLs, `cid:` references, and automatic remote fetch surfaces. Tests cover raw, encoded, mixed-case, and entity-obfuscated payloads where practical. |
| Link destination disclosure | Allowed message-body links preserve only reviewed schemes and expose their destinations visibly in rendered message bodies. Tests prove the disclosure CSS remains present and preserved links carry reviewed relationship attributes. |
| Remote-content suppression | Remote images, tracking pixels, inline `cid:` images, media tags, source tags, and other fetch-capable markup do not survive rendered message bodies. Inline image parts may be surfaced as attachment metadata only. |
| MIME fail-closed behavior | Unsupported charsets, malformed boundaries, ambiguous multipart structures, excessive body size, excessive part counts, strange headers, and unsupported transfer shapes render an explicit withheld placeholder or fail closed without panics or private-data leakage. |
| Browser-executable attachment containment | HTML, SVG, XML, script, and other browser-executable attachment media types are forced to download, receive `Content-Disposition: attachment`, include `X-Content-Type-Options: nosniff`, and are downgraded to `application/octet-stream` when served. |
| Suspicious attachment metadata | Suspicious filenames, path-shaped filenames, RFC 2231 continuations, nested message files, calendar invites, PDFs, archives, and delivery-status parts are surfaced through bounded metadata and download behavior without path trust. |
| Evidence redaction | Reports and release evidence exclude message bodies, attachment bodies, session tokens, CSRF tokens, credentials, TOTP material, provider secrets, and host secrets. Evidence may include synthetic labels, pass markers, commit or tag identity, command identity, and sanitized result paths. |
| Residual-risk clarity | Documentation states that OSMAP contains browser rendering and download serving risk, but cannot prove a file is safe after the user opens it outside OSMAP. |
| Security claim matrix | `docs/V4_SECURITY_CLAIM_MATRIX.md` maps each hostile-content claim to implementation, automated test, validation evidence, residual risk, documented limitation, and non-goal. |

## Evidence Required At Closeout

The Version 4 closeout record must link:

- the commit or tag being assessed
- local security-check evidence for that commit or tag
- Cargo build, test, clippy, formatting, and supply-chain evidence from a
  compatible toolchain
- current Version 3 carry-forward evidence or an explicit statement that the
  V4 assessment is not a release closeout
- V4 sanitizer fixture evidence
- V4 executable attachment download evidence
- V4 hostile-content live report or approved route-level successor evidence
- evidence-redaction review for the V4 report
- updated V4 hostile-content test matrix
- residual-risk statement for external links and files opened outside OSMAP
- a sanitized evidence archive that excludes plaintext passwords, reusable TOTP
  seeds, active session cookies, private message bodies, private attachment
  content, provider secrets, and host secrets
- V4 hostile corpus report and archive generated by
  `maint/security/osmap-v4-hostile-assurance-gate.sh`
