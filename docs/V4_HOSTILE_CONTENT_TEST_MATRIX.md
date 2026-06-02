# Version 4 Hostile Content Test Matrix

## Purpose

This matrix tracks the payload classes V4 uses to prove that OSMAP is safe for
viewing hostile message content inside the browser boundary.

## Matrix

| Payload class | Expected OSMAP behavior | Current evidence |
| --- | --- | --- |
| raw script and event handlers | strip before browser rendering | sanitizer fixtures and live MIME/HTML proof |
| unsafe link schemes | remove `javascript:`, `data:`, `cid:`, relative, and protocol-relative navigation targets | sanitizer fixtures and live MIME/HTML proof |
| allowed external links | preserve only allowed schemes and expose the destination visually in rendered message bodies | V4 CSS destination disclosure and live hostile-content proof |
| forms and credential-harvest inputs | strip form controls and submitted payload markers | sanitizer fixtures and live MIME/HTML proof |
| CSS import, inline styles, and metadata refresh | strip style-bearing surfaces and head metadata | sanitizer fixtures and live MIME/HTML proof |
| SVG, MathML, frames, objects, embeds, and templates | remove tag contents from rendered output | sanitizer fixtures and live MIME/HTML proof |
| tracking pixels and inline `cid:` images | do not render inline; surface attachment metadata only | MIME/HTML fixture and live proof |
| malformed or unsupported MIME | render an explicit withheld placeholder or fail closed | MIME fixture coverage |
| browser-executable attachments | force download and downgrade risky response types to `application/octet-stream` | V4 attachment tests and live hostile-content proof |
| evidence redaction | exclude message bodies, attachment bodies, session tokens, CSRF tokens, credentials, and TOTP material | live proof scripts and release evidence rules |

## Residual Risk

OSMAP cannot prove that a file is safe after a user opens it outside the
application. V4 therefore treats attachment safety as containment and clear
handling, not malware prevention.

## Live Evidence Lane

`maint/live/osmap-live-validate-v4-hostile-content.ksh` is the host-assisted
evidence lane for this matrix. It injects controlled hostile HTML and
browser-executable attachment messages, validates the running `/message` and
`/attachment` routes, and writes the sanitized report
`maint/live/latest-host-v4-hostile-content-report.txt`.
