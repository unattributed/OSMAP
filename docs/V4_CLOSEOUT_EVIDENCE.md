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

- `maint/live/osmap-v3-release-evidence-summary.md`
- `maint/live/osmap-v3-release-evidence-summary.json`
- `maint/live/osmap-v3-release-evidence.tar.gz`

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
commit `09a95b7`.

The V4 MIME ambiguity and metadata breadth slice is locally covered by
`docs/V4_MIME_AMBIGUITY_EVIDENCE.md` and the named product-code regression
tests in `src/mime.rs`.

The bundle includes:

- local `make security-check` evidence for the code tree committed as
  `09a95b7`
- refreshed V3 release carry-forward evidence for
  `09a95b7f4e9744a20bcd85430e4f0428cafeebe7`
- refreshed live V4 hostile-content proof for `09a95b7`
- V4 MIME ambiguity and metadata breadth evidence
- this residual-risk statement for external links and files opened outside
  OSMAP

Any code change after `09a95b7` requires a new assessed commit or tag and a new
closeout evidence pass before it can inherit this V4 closeout claim.
