# Version 4 Hostile Content Safety Goals

## Purpose

Version 4 focuses OSMAP on modern hostile-content safety inside the browser
application boundary.

The goal is not to make email content globally safe. Email remains attacker
controlled. The goal is to make OSMAP safe for viewing untrusted messages by
default, keep active content out of the browser, keep remote content from
loading automatically, and make the remaining user-driven risk visible.

## Scope

V4 is in scope for:

- sanitizer hardening for hostile HTML and MIME inputs
- browser-safe message rendering controls
- visible treatment of sanitized external links
- attachment download hardening for browser-executable content types
- expanded fixture and live evidence for modern webmail attack methods
- release evidence that maps payload classes to expected OSMAP behavior

V4 is not in scope for:

- rich HTML mail rendering
- JavaScript-based message display
- inline image rendering
- remote-content loading
- attachment preview
- malware scanning
- broad MIME-client parity

## Security Goals

OSMAP V4 should prove these controls:

- untrusted plain text is escaped before browser presentation
- untrusted HTML is parsed through the narrow sanitizer before presentation
- scriptable tags, event handlers, forms, CSS, SVG, MathML, frames, templates,
  comments, metadata refresh, unsafe URL schemes, relative URLs, and remote
  fetch surfaces do not survive message rendering
- allowed message-body links expose their destination to the user
- browser-executable attachment media types are downgraded on download rather
  than served as active browser content
- unsupported, malformed, ambiguous, or oversized MIME bodies fail closed or
  render an explicit withheld placeholder
- message bodies and attachment bodies do not enter audit logs or release
  evidence

## Modern Payload Classes

V4 validation should cover at least:

- raw and encoded script payloads
- mixed-case and entity-obfuscated URL schemes
- `javascript:`, `data:`, `blob:`, `cid:`, relative, and protocol-relative
  URLs
- form, input, autofocus, and event-handler credential-harvest payloads
- CSS import, style attribute, background URL, and metadata refresh payloads
- SVG, MathML, iframe, object, embed, and template payloads
- tracking pixels, remote images, and inline `cid:` references
- malformed multipart boundaries, nested multipart structures, duplicate or
  strange headers, transfer-encoding tricks, and unsupported charsets
- suspicious filenames, RFC 2231 filename continuations, HTML/SVG/XML/script
  attachments, calendar invites, PDFs, archives, and nested message files

## Exit Gate

V4 is complete only when:

- code changes preserve the no-JavaScript, no-remote-load browser boundary
- fixture tests cover the payload classes above where practical
- host-assisted or route-level evidence proves hostile HTML rendering,
  attachment download hardening, and evidence redaction
- residual risks are documented plainly, especially external links and files
  opened outside OSMAP

The current host-assisted live evidence lane is
`maint/live/osmap-live-validate-v4-hostile-content.ksh`, which writes the
sanitized report `maint/live/latest-host-v4-hostile-content-report.txt`.
