# Version 4 Security Gates

## Purpose

This document defines the security evidence required before OSMAP Version 4 can
be described as hostile-content safe for the browser-mail boundary.

Version 4 hardens the message content path, so its gate must prove that
attacker-controlled mail cannot gain active browser execution, automatic remote
resource loading, unsafe attachment serving, or unsafe evidence leakage by
default.

## Required Carry-Forward Gates

All Version 3 gates remain mandatory for a Version 4 release claim:

- developer or release security-check evidence for the assessed commit
- Cargo build, test, clippy, formatting, and supply-chain evidence
- WSTG and route-security evidence for changed browser surfaces
- Version 2 and Version 3 host-readiness evidence when the claim includes
  deployment readiness
- TLS, public-edge, helper-boundary, session, CSRF, same-origin, resource, and
  evidence-hygiene gates that are still applicable to the assessed surface

Version 4 cannot pass by replacing, weakening, or silently skipping any of these gates.

## Version 4 Gate Additions

| Gate | Required evidence |
| --- | --- |
| Hostile HTML rendering | Unit, route, or live evidence proves active tags, event handlers, forms, CSS, SVG, MathML, frames, objects, embeds, templates, comments, metadata refresh, unsafe schemes, relative URLs, protocol-relative URLs, and remote fetch surfaces do not survive browser rendering. |
| External-link visibility | Evidence proves preserved message-body links disclose their destinations visibly and keep reviewed relationship attributes such as `noopener`, `noreferrer`, and `nofollow`. |
| Executable attachment containment | Evidence proves browser-executable attachment types are forced to download, carry `nosniff`, and are downgraded to `application/octet-stream` when served. |
| MIME ambiguity handling | Evidence proves malformed, unsupported, ambiguous, or oversized MIME bodies fail closed or render a clear withheld placeholder. |
| Evidence redaction | The V4 evidence path proves that message bodies, attachment bodies, active session material, CSRF tokens, passwords, TOTP material, provider secrets, and host secrets are not written to committed or archived reports. |
| Residual-risk disclosure | Documentation states that OSMAP contains browser-rendering and serving risk but does not claim to make externally opened files safe. |
| Hostile corpus release gate | The version-controlled corpus under `tests/testdata/hostile-mail-corpus/` executes through `maint/security/osmap-v4-hostile-assurance-gate.sh`; release validation fails if execution is skipped, fixture metadata is incomplete, report generation is absent, or evidence archiving is absent. |
| Security claim matrix | `docs/V4_SECURITY_CLAIM_MATRIX.md` maps hostile-content claims to implementation, automated tests, validation evidence, residual risk, documented limitations, and non-goals. |

## Current Evidence Lane

The current live-host evidence lane is
`maint/live/osmap-live-validate-v4-hostile-content.ksh`.

That validator must:

- start or target a reviewed OSMAP runtime with the browser boundary intact
- inject controlled hostile HTML and executable attachment messages
- validate the `/message` route for sanitized rendering
- validate the `/attachment` route for executable attachment containment
- prove preserved external links disclose their destinations
- prove forbidden payload markers are absent from rendered message bodies
- prove report output excludes secrets and private body markers
- write the sanitized report
  `maint/live/latest-host-v4-hostile-content-report.txt`

The local wrapper regression test is
`maint/security/test-osmap-live-validate-v4-hostile-content.sh`. It proves the
validator remains syntactically valid and still checks the expected payload
classes, attachment hardening, and report-redaction markers.

It is not a substitute for the live-host proof at release closeout.

The local and release corpus evidence lane is
`maint/security/osmap-v4-hostile-assurance-gate.sh`. It validates
`tests/testdata/hostile-mail-corpus/MANIFEST.json`, verifies required fixture
metadata, executes `tests/v4_hostile_assurance.rs`, writes the machine-readable
report `maint/live/osmap-v4-hostile-assurance-report.json`, and archives the
corpus/report bundle as
`maint/live/osmap-v4-hostile-assurance-evidence.tar.gz`.

The local MIME ambiguity evidence is `docs/V4_MIME_AMBIGUITY_EVIDENCE.md`.
It names product-code tests in `src/mime.rs` that prove malformed, nested,
suspicious, unsupported, and oversized MIME inputs fail closed or surface only
bounded metadata before browser rendering.

## Evidence Hygiene Rule

Version 4 evidence must be timestamped, tied to the assessed commit or tag, and
reviewable by a later operator.

Evidence must not include:

- plaintext passwords
- reusable TOTP seeds
- current TOTP codes
- active session cookies
- CSRF tokens
- private message bodies
- private attachment contents
- provider tokens
- host secrets
- unredacted personal mailbox data

Synthetic hostile-content markers may be used only when the report proves that
private body and attachment markers are absent from committed evidence.

## Failure Rule

If a V4 change passes ordinary functional tests but fails one of the security gates above, the change remains incomplete.

The remedy is a scoped fix, a documented out-of-scope deferral, or removal from
the Version 4 boundary.
