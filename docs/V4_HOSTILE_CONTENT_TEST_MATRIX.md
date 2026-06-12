# Version 4 Hostile Content Test Matrix

## Purpose

This matrix tracks the payload classes V4 uses to prove that OSMAP is safe for
viewing hostile message content inside the browser boundary.

## Matrix

| Payload class | Expected OSMAP behavior | Current evidence |
| --- | --- | --- |
| raw script and event handlers | strip before browser rendering | hostile corpus fixture `html/hostile_html_active_content.eml`, sanitizer fixtures, and live MIME/HTML proof |
| unsafe link schemes | remove `javascript:`, `data:`, `cid:`, relative, protocol-relative, blob, and file navigation targets | hostile corpus fixture `html/suspicious_link_matrix.eml`, sanitizer fixtures, and live MIME/HTML proof |
| allowed external links | preserve only allowed schemes and expose the destination visually in rendered message bodies | V4 CSS destination disclosure, hostile corpus execution, and live hostile-content proof |
| forms and credential-harvest inputs | strip form controls and submitted payload markers | hostile corpus execution, sanitizer fixtures, and live MIME/HTML proof |
| CSS import, inline styles, preload, and metadata refresh | strip style-bearing surfaces and head metadata | hostile corpus fixture `html/css_tracking_cid_abuse.eml`, sanitizer fixtures, and live MIME/HTML proof |
| SVG, MathML, frames, objects, embeds, audio, video, and templates | remove tag contents from rendered output | hostile corpus execution, sanitizer fixtures, and live MIME/HTML proof |
| tracking pixels and inline `cid:` images | do not render inline; surface attachment metadata only | hostile corpus fixture `html/css_tracking_cid_abuse.eml`, MIME/HTML fixture, and live proof |
| malformed or unsupported MIME | render an explicit withheld placeholder or fail closed | hostile corpus MIME fixtures, MIME robustness assertions, and product-code MIME tests |
| header, part, and nesting abuse | enforce bounded header count, part count, boundary length, and nesting depth | hostile corpus fixtures under `mime/` and `tests/v4_hostile_assurance.rs` |
| browser-executable attachments | force download and downgrade risky response types to `application/octet-stream` | hostile corpus attachment fixtures, V4 attachment tests, and live hostile-content proof |
| attachment filename deception | normalize deceptive, path-like, double-extension, and unicode-deception filenames into bounded metadata/download names | hostile corpus fixtures under `attachments/` and `unicode/` |
| browser isolation assumptions | keep CSP, frame ancestry, no opener widening, no service worker/WebSocket/BroadcastChannel/WebRTC surfaces, `nosniff`, CORP, and no-referrer intact | `tests/v4_hostile_assurance.rs` and release gate source invariant checks |
| evidence redaction and archiving | exclude message bodies, attachment bodies, session tokens, CSRF tokens, credentials, and TOTP material while archiving machine-readable evidence | `maint/security/osmap-v4-hostile-assurance-gate.sh` and release evidence rules |

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

The repository-owned corpus gate is
`maint/security/osmap-v4-hostile-assurance-gate.sh`. It executes
`tests/v4_hostile_assurance.rs` against
`tests/testdata/hostile-mail-corpus/`, validates fixture metadata coverage,
scans route-backed message-view responses for inert body DOM and zero
auto-fetch/API surfaces, verifies forced-download attachment responses, writes
`maint/live/osmap-v4-hostile-assurance-report.json`, and archives
`maint/live/osmap-v4-hostile-assurance-evidence.tar.gz`.
