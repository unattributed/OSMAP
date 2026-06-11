# Version 4 Closeout Evidence

## Purpose

This document records the current Version 4 hostile-content live proof and ties
it to the V4 closeout evidence set.

It does not claim broad rich-mail safety, malware prevention, attachment
preview safety, or Roundcube parity. It records that the V4 hostile-content
browser-boundary proof passed for the assessed code commit named below.

## Assessed Snapshot

| Field | Value |
| --- | --- |
| Assessed code commit | `a3f6e98` |
| Assessed host | `mail.blackbagsecurity.com` |
| Host checkout | `~/OSMAP` |
| Validator | `maint/live/osmap-live-validate-v4-hostile-content.ksh` |
| Sanitized report | `maint/live/latest-host-v4-hostile-content-report.txt` |
| Result marker | `result=v4_hostile_content_live_proof_passed` |

The host checkout was fast-forwarded to `a3f6e98` before the validator ran.

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

## Closeout Status

The V4 live hostile-content proof slice is complete for assessed commit
`a3f6e98`.

The V4 MIME ambiguity and metadata breadth slice is locally covered by
`docs/V4_MIME_AMBIGUITY_EVIDENCE.md` and the named product-code regression
tests in `src/mime.rs`.

Full V4 closeout still requires the final closeout bundle to include:

- the local security gate for the final assessed release commit or tag
- the V3 carry-forward evidence required by `V4_SECURITY_GATES.md`
- this V4 hostile-content live proof or a newer proof for the final assessed
  commit or tag
- a final residual-risk statement for external links and files opened outside
  OSMAP
