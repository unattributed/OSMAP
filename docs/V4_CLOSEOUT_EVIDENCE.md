# Version 4 Closeout Evidence

## Purpose

This document records the current Version 4 hostile-content live proof and ties
it to the V4 closeout evidence set.

It does not claim broad rich-mail safety, malware prevention, attachment
preview safety, or Roundcube parity. It records that the V4 hostile-content
browser-boundary proof and carry-forward evidence passed for the assessed code
commit named below.

## Assessed Snapshot

| Field | Value |
| --- | --- |
| Assessed code commit | `09a95b7` |
| Assessed host | `mail.blackbagsecurity.com` |
| Host checkout | `~/OSMAP` |
| Validator | `maint/live/osmap-live-validate-v4-hostile-content.ksh` |
| Sanitized report | `maint/live/latest-host-v4-hostile-content-report.txt` |
| Result marker | `result=v4_hostile_content_live_proof_passed` |

The host checkout was fast-forwarded to `09a95b7` before the validator ran.

## Command

The live proof was run on the reviewed OpenBSD host from the standard checkout:

```sh
cd ~/OSMAP
ksh ./maint/live/osmap-live-validate-v4-hostile-content.ksh
```

## Evidence Summary

The sanitized live report proves:

- the validation mailbox existed for the dedicated validation account
- the current OSMAP tree built successfully on the host
- the enforced mailbox-helper runtime started successfully as `vmail`
- the enforced browser runtime started successfully as `_osmap`
- hostile HTML message viewing returned `HTTP/1.1 200 OK`
- sanitized HTML mode was used for the hostile HTML message
- visible safe text and an allowed safe link survived rendering
- preserved link destinations were visibly disclosed by the browser CSS
- unsafe schemes and navigation targets were absent from the rendered body:
  `javascript:`, mixed-case `JaVaScRiPt:`, `blob:`, `vbscript:`, `file:`,
  `data:`, `cid:`, relative URLs, and protocol-relative URLs
- remote fetch, credential-harvest, and scriptable container surfaces were
  absent from the rendered body, including forms, inputs, iframes, SVG, MathML,
  object, embed, template, video, audio, source, image, autofocus, and event
  handler payloads
- HTML, SVG, and JavaScript attachments were visible as attachment metadata
- HTML, SVG, and JavaScript attachment downloads returned `HTTP/1.1 200 OK`
- those browser-executable attachment downloads were forced downloads,
  downgraded to `application/octet-stream`, emitted `X-Content-Type-Options:
  nosniff`, and preserved `Cross-Origin-Resource-Policy: same-origin`
- message cleanup was attempted after the proof
- audit logs did not contain the hostile HTML body marker or executable
  attachment body markers
- the committed report excludes password, TOTP material, session cookie, CSRF
  token, private message body, attachment body, provider secret, and host secret
  material

## Evidence Hygiene

The committed report is intentionally sanitized. It contains synthetic marker
statuses, route status lines, mailbox/UID references for disposable validation
messages, host identity, assessed commit, and pass/fail result markers.

The report does not contain plaintext passwords, reusable TOTP seeds, active
session cookies, CSRF tokens, private message bodies, private attachment
contents, provider tokens, or host secrets.

## V3 Carry-Forward Evidence

The V3 carry-forward bundle was refreshed on `mail.blackbagsecurity.com` for
assessed ref `09a95b7f4e9744a20bcd85430e4f0428cafeebe7`.

Tracked evidence:

- `maint/live/osmap-v4-frozen-v3-release-evidence-summary.json`
- `maint/live/osmap-v3-release-evidence-summary.md`
- `maint/live/osmap-v3-release-evidence.tar.gz`

`maint/live/osmap-v4-frozen-v3-release-evidence-summary.json` is the immutable
V3 carry-forward summary used by V4 closeout and tuple validation. The current
`maint/live/osmap-v3-release-evidence-summary.json` path remains a generated
release-check output for later assurance runs and is not used as the frozen
V4.0.0 carry-forward input.

The refreshed V3 release evidence summary records:

- generated UTC: `2026-06-11T12:09:28Z`
- host target: `mail.blackbagsecurity.com`
- command: `make release-check`
- Cargo build, test, clippy, and fmt-check: `passed`
- supply-chain gate: `passed`
- dependency inventory: `passed`
- WSTG summary and authenticated WSTG: `passed`
- TLS CBC cleanup and TLS standard validation: `passed`
- resource and timeout hardening: `passed`
- helper-boundary evidence: `passed`
- V3 live MIME and HTML proof: `passed`
- V3 pilot rehearsal: `passed`
- sanitized evidence archive: `passed`
- skipped checks: none

The host release-check was invoked with explicit toolchain pins matching the
reviewed host toolchain (`rustc` and `cargo` 1.94.1, clippy 0.1.94, rustfmt
1.8.0) and with `~/.cargo/bin` in `PATH` so the installed `cargo-audit` and
`cargo-deny` subcommands were visible.

## Current V4.6 Assurance Addendum

The historical `v4.0.0` closeout tuple remains frozen at assessed code commit
`09a95b7`, release tag `v4.0.0`, and evidence bundle commit `59da020`.

Current V4 assurance has since been strengthened without adding end-user
functionality or expanding the hostile-content claim. The current assurance
lane records:

- current repository commit after V4.6 gate and evidence refresh:
  `090e9a2403992747882e49c3d9756b30baecc247`
- V4 security claim-matrix gate commit:
  `d1fd3ebd31034aeb315c71d1a2f65fdb751ce122`
- current hostile-assurance report assessed ref:
  `d1fd3ebd31034aeb315c71d1a2f65fdb751ce122`
- current hostile-assurance report:
  `maint/live/osmap-v4-hostile-assurance-report.json`
- current hostile-assurance archive:
  `maint/live/osmap-v4-hostile-assurance-evidence.tar.gz`
- enforced claim matrix:
  `docs/V4_SECURITY_CLAIM_MATRIX.md`
- claim-matrix release gate:
  `maint/security/osmap-v4-security-claim-matrix-gate.sh`

The claim-matrix gate is now part of both developer and release validation. It
fails when:

- any required hostile-content claim row is missing
- implementation, automated-test, validation-evidence, residual-risk,
  limitation, or non-goal cells are empty or placeholder text
- a repo path cited by the matrix does not exist
- the V4 hostile-assurance report is missing, failed, or lacks cited component
  observations
- zero-network assertions regress
- route-backed observations or bounded resource observations are absent
- the hostile-assurance archive omits the report, corpus manifest, or
  representative hostile fixtures

The current hostile-assurance report records:

- generated UTC: `2026-06-13T10:35:28Z`
- status: `passed`
- release gate: `maint/security/osmap-v4-hostile-assurance-gate.sh`
- hostile corpus metadata: `12 fixtures cover 11 required categories`
- browser-rendered negative assertions: route-backed message responses had
  inert body DOM and zero observed auto-fetch surfaces
- MIME parser robustness: malformed boundary, invalid transfer, deep nesting,
  header count, part count, and boundary length checks are bounded
- attachment deception handling: active attachment media are downgraded, forced
  download headers are present, and body size is bounded
- browser isolation verification: CSP/frame headers, forced-download headers,
  source invariants, and route-backed browser observations are verified
- network assertions: zero remote fetches, beacons, WebSockets, and service
  worker registrations
- evidence metadata: git commit, host OS, hostname, make, Rust, Cargo,
  rustfmt, clippy, cargo-audit, and cargo-deny versions

The closeout distinction is intentional: the frozen `v4.0.0` tuple remains the
historical release evidence, while the current V4 assurance report/archive and
claim-matrix gate prove that the same hostile-content containment claim remains
continuously validated for the current assessed tree.

## Residual-Risk Statement

OSMAP V4 contains hostile message content inside the browser boundary; it does
not make attacker-controlled email globally safe.

Residual risks remain:

- preserved external links can still lead to phishing, malware, credential
  capture, or misleading destinations outside OSMAP
- OSMAP visibly discloses preserved link destinations, but it does not provide
  URL reputation, detonation, or destination safety scoring
- downloaded attachments are forced downloads, receive reviewed browser-safety
  headers, and browser-executable media types are downgraded to
  `application/octet-stream`, but files may still be malicious after a user
  opens them in external applications
- OSMAP does not claim malware scanning, document sanitization, archive
  inspection, attachment preview safety, or safety for files after they leave
  the OSMAP browser boundary
- unsupported rich-mail behavior may be withheld or reduced to bounded
  metadata instead of rendered with Roundcube-like fidelity

## Closeout Status

The V4 hostile-content closeout evidence bundle is assembled for assessed code
commit `09a95b7` as the historical `v4.0.0` release tuple.

The V4 MIME ambiguity and metadata breadth slice is locally covered by
`docs/V4_MIME_AMBIGUITY_EVIDENCE.md` and the named product-code regression
tests in `src/mime.rs`.

The historical `v4.0.0` bundle includes:

- local `make security-check` evidence for the code tree committed as
  `09a95b7`
- refreshed V3 release carry-forward evidence for
  `09a95b7f4e9744a20bcd85430e4f0428cafeebe7`
- refreshed live V4 hostile-content proof for `09a95b7`
- V4 MIME ambiguity and metadata breadth evidence
- this residual-risk statement for external links and files opened outside
  OSMAP

The current V4 assurance lane additionally includes:

- release tuple validation by `maint/security/osmap-v4-release-tuple-gate.sh`
- security claim matrix validation by
  `maint/security/osmap-v4-security-claim-matrix-gate.sh`
- refreshed metadata-bearing hostile-assurance report/archive for
  `d1fd3ebd31034aeb315c71d1a2f65fdb751ce122`
- local and mail-host claim-matrix gate passes at
  `090e9a2403992747882e49c3d9756b30baecc247`

Any product, test, security-gate, or release-evidence change after the current
assessed assurance commits requires a new evidence pass before it can inherit
the current V4 hostile-content containment claim.
