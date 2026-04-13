# Rendering Policy Baseline

## Purpose

This document records the bounded browser-rendering policy for fetched
messages.

The goal of this slice is to transform a fetched message payload into something
safe for browser presentation without turning OSMAP into a rich HTML mail
client or a browser-trusting rendering engine.

## Status

As of April 2, 2026, the runtime now includes a conservative rendering layer on
top of the completed message-view fetch baseline.

The current slice provides:

- a plain-text-first rendering policy with bounded safe-HTML support
- header extraction for a small summary surface
- bounded RFC 2047 encoded-word decoding for the narrow `Subject` and `From`
  summary values
- a bounded inline-image policy notice when HTML-capable messages surface
  inline image attachment metadata
- bounded `Content-ID` metadata surfacing for surfaced attachment parts so the
  browser can distinguish likely `cid:`-backed inline assets from generic
  inline-disposition images
- browser-safe HTML escaping for plain-text rendering
- a narrow allowlist sanitizer for HTML-capable messages
- two explicit rendering modes: preformatted plain text and sanitized HTML
- structured audit events for rendering operations

The follow-on MIME-aware and attachment-aware policy layer now exists too and
is documented separately in `MIME_AND_ATTACHMENT_POLICY_BASELINE.md`. The
first bounded end-user rendering preference is documented separately in
`SETTINGS_SURFACE_BASELINE.md`.

This slice is now also live-proven on `mail.blackbagsecurity.com` under
`OSMAP_OPENBSD_CONFINEMENT_MODE=enforce` using a controlled HTML-only message
delivered to the disposable validation mailbox and a synthetic validated
browser session.

The current inline-image metadata follow-on is now also live-proven there
through `maint/live/osmap-live-validate-inline-image-metadata.ksh`, which
injects one controlled multipart/related HTML message with a `cid:`-referenced
inline image part and confirms the browser message view surfaces the bounded
inline-image notice plus the attachment `Content-ID` metadata.

This is intentionally smaller than a full message renderer.

## Current Rendering Modes

The current rendering modes are:

- `plain_text_preformatted`
- `sanitized_html`

That means:

- plain-text bodies are HTML-escaped and wrapped in a `<pre>` block
- sanitized HTML bodies are wrapped in a small container and rendered through a
  restrictive allowlist policy
- the message view now shows the active rendering mode to the user
- HTML-capable messages with surfaced inline image metadata now render an
  explicit browser notice instead of attempting inline image display
- surfaced attachment metadata now includes bounded `Content-ID` values when
  they are present and valid
- the inline-image notice is now more precise when HTML-capable messages
  surface true `cid:`-style inline-image metadata
- compose/reply/forward body generation still uses plain-text content, even
  when sanitized HTML is rendered for browser reading

This is intentionally conservative. The first goal is safe readable output, not
feature parity with legacy webmail.

## Header Handling

The current renderer extracts only a narrow summary:

- `Subject`
- `From`

The renderer unfolds continuation lines conservatively and applies explicit
length bounds before those values can move toward a browser-facing layer. It
now also performs bounded RFC 2047 encoded-word decoding for those summary
fields when the message uses common `utf-8`, `us-ascii`, or `iso-8859-1`
encoded words.

It does not yet attempt:

- full header presentation
- address parsing
- MIME header interpretation beyond the narrow follow-on classification layer
- full RFC 2047 coverage across all possible header charsets and edge cases

Those are later refinements, not assumptions.

## Security Posture

The rendering slice follows these rules:

- consume only already-fetched message data
- escape HTML-significant characters before plain-text browser presentation
- sanitize HTML through a dedicated allowlist policy instead of preserving
  arbitrary markup
- deny relative URLs and limit link schemes to `http`, `https`, and `mailto`
- strip comments and remove scriptable or external-fetch oriented tags such as
  `script`, `style`, `iframe`, `object`, `embed`, and `svg`
- keep rendering output bounded
- log rendering activity by identifiers and context, not message content

This keeps the first rendering step aligned with the project’s conservative
mail-content threat model.

## What This Slice Proves

This slice now proves that:

- the project can turn a fetched message into browser-safe output without
  trusting live message HTML
- header summary extraction can stay bounded and reviewable
- rendering can be modeled as a separate layer after message retrieval
- the system can offer a first-release safe-HTML path without becoming a rich
  HTML mail client
- the current sanitized-HTML path and plain-text fallback both work against a
  real OpenBSD host mailbox under the `_osmap` plus `vmail` runtime split

## What Is Still Missing

This slice still does not yet include:

- attachment preview behavior
- inline image rendering
- richer browser presentation beyond the current server-rendered route set
- permissive HTML layout support, broad inline styling, or any external
  resource loading

The first bounded attachment-download route now exists separately from the
renderer, which preserves the current conservative browser posture.
