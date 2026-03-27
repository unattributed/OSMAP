# Attachment Download Slice Baseline

## Purpose

This document records the first implemented attachment-download slice for
OSMAP.

The goal of this slice is to close the obvious mailbox workflow gap without
turning the browser into a preview-heavy mail client or adding a second mail
retrieval model beside the one that already exists.

## Status

As of March 27, 2026, the runtime now includes a bounded attachment-download
route at `GET /attachment`.

The current slice provides:

- session-gated attachment download
- mailbox-plus-UID-plus-part-path authorization reuse
- MIME-part resolution through the existing bounded message-view payload
- helper-backed source-message retrieval when
  `OSMAP_MAILBOX_HELPER_SOCKET_PATH` is configured
- forced-download HTTP responses rather than inline preview behavior
- conservative `Content-Disposition` filename sanitization
- conservative `Content-Type` normalization with `nosniff`
- support for common `Content-Transfer-Encoding` values:
  `base64`, `quoted-printable`, `7bit`, `8bit`, and `binary`
- structured mailbox audit events for download success and failure

This is the first honest attachment-download path, not the final attachment
handling story.

## Current Request Model

The current route accepts only:

- `mailbox`
- `uid`
- `part`

The `part` selector must be a conservative dotted numeric child-part path such
as `1.2`.

This keeps the route aligned with the already surfaced attachment metadata and
avoids inventing a second attachment identifier scheme inside the browser layer.

## Current Browser Posture

The browser-facing download behavior is intentionally narrow:

- downloads require an already validated session
- the route is read-only and therefore does not widen CSRF scope
- surfaced attachments are offered as explicit links, not auto-previewed
- the HTTP response forces `Content-Disposition: attachment`
- `X-Content-Type-Options: nosniff` remains enabled
- the route does not attempt image preview, HTML preview, or MIME convenience
  behavior

This preserves the existing low-trust browser model.

## Current MIME And Decoding Model

The download path reuses the current MIME analysis boundary rather than
bypassing it.

Today that means:

- only parts already surfaced as attachments are downloadable
- multipart traversal stays within the existing bounded MIME analyzer
- decoded attachment bytes are capped conservatively
- unsupported or malformed transfer encodings fail closed
- non-surfaced parts are treated as not found rather than exposed implicitly

The route can therefore serve common encoded attachments without claiming full
MIME-client completeness.

## Validation Status

This slice is currently validated through:

- local Rust unit coverage for MIME part lookup, transfer decoding, filename
  sanitization, and HTTP forced-download behavior
- local `make check`, `make test`, `make lint`, and `make fmt-check`
  entrypoints, with honest environment notes where tooling is absent
- OpenBSD host `cargo test` on `mail.blackbagsecurity.com`
- OpenBSD host ignored live `doveadm` tests on `mail.blackbagsecurity.com`
- OpenBSD host enforced-serve validation with a synthetic file-backed session
  under `/tmp`, including `GET /healthz` and a session-gated attachment-route
  request

The enforced-host synthetic-session validation confirmed:

- the server started under `OSMAP_OPENBSD_CONFINEMENT_MODE=enforce`
- the synthetic session was accepted
- the session record's `last_seen_at` was updated on disk under enforced mode
- the attachment route returned the expected bounded failure response for a
  synthetic missing-user session

The local runtime now also keeps the attachment route on the helper-backed
read path when a mailbox helper socket is configured. This avoids teaching the
web-facing runtime to fall back to direct mailbox reads for attachment
downloads after mailbox listing, message listing, and message view have already
moved behind the helper boundary.

## Live-Host Proof Update

Follow-on validation on `mail.blackbagsecurity.com` now proves the attachment
path more completely than the first synthetic-session check did.

The current validated host shape now uses:

- `_osmap` plus `/var/run/osmap-auth` for browser auth
- `vmail` plus `/var/run/osmap-userdb` for mailbox-helper userdb lookups
- a helper-backed message-view fetch path under
  `OSMAP_OPENBSD_CONFINEMENT_MODE=enforce`

Using that shape, OSMAP now successfully:

- listed mailboxes under a synthetic bounded session
- listed messages in `INBOX`
- rendered a message view for the attachment-bearing validation message
- downloaded the attachment bytes successfully under enforced confinement

## What This Slice Proves

This slice now proves that:

- OSMAP can close the attachment-download workflow gap without widening browser
  trust to preview behavior
- the existing mailbox, message-view, and MIME layers are coherent enough to
  support one explicit download route
- attachment download can remain bounded and auditable
- the helper-backed read path is coherent enough to carry attachment downloads
  under the target `vmail` boundary on the current host
- the project can add real value without abandoning its low-dependency and
  reviewability posture

## What Is Still Missing

This slice does not yet include:

- original filename fidelity for RFC 2231 or encoded-word edge cases
- attachment preview behavior
- original-message attachment reattachment in reply or forward flows
- attachment download rate controls beyond adjacent nginx and network controls
- a dedicated helper-side attachment-byte operation separate from the current
  helper-backed message-view fetch

Those remain later hardening and live-integration work.
