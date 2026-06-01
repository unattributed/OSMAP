# V3 Webmail Input Validation Evidence

## Scope

`OSMAP-WSTG-INPV-004` records the Slice 4 evidence lane for webmail-specific
input validation, starting with `WSTG-v42-INPV-10` IMAP/SMTP injection.

The lane focuses on OSMAP browser boundaries that can influence Dovecot IMAP
commands, local sendmail submission, MIME headers, attachment metadata, and
stored browser rendering.

## Dynamic Evidence

The WSTG runner uses a real authenticated password-plus-TOTP session. Rejected
probes must fail before local submission; the attachment content-type probe is
the one accepted positive control and must reach delivery with a malformed
media type normalized by the compose boundary:

- subject newline injection is rejected before local submission
- recipient newline injection is rejected before local submission
- display-name-shaped recipient input is rejected because the current send
  slice accepts only simple addr-spec recipients
- mailbox-name command-shaped tampering is rejected or safely denied
- UID tampering with an invalid UID is rejected
- search-term command-shaped tampering is rejected or safely denied
- path-like attachment filename input is rejected before submission
- malformed attachment content-type input is exercised with an otherwise valid
  recipient so the accepted request proves the content-type path independently
  of recipient/header validation

Evidence bodies are omitted or redacted.

## Static Evidence

Static evidence ties the dynamic probes to code-level controls:

- recipients reject control and whitespace characters
- subjects reject control characters and line breaks
- uploaded attachment filenames reject control characters and path separators
- unsupported attachment content types normalize to `application/octet-stream`
- body text may contain ordinary line breaks, but remains sendmail stdin data
  and is not promoted to command arguments
- mailbox and search command-shaped values stay single Dovecot arguments
- stored HTML rendering strips scriptable attributes, forms, and remote fetch
  surfaces

The existing `OSMAP-WSTG-INPV-003` command-injection lane remains the broader
safe command-boundary due-diligence check. `OSMAP-WSTG-INPV-004` is the
webmail-specific SMTP/IMAP and MIME-input lane.

## Explicit Non-Scope

OSMAP does not expose CSV export functionality in the current browser surface.
CSV injection remains not applicable unless an export route is added.
