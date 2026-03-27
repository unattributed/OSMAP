# Rendering Policy Baseline

## Purpose

This document records the next WP6 step after bounded message retrieval:
plain-text-first browser rendering.

The goal of this slice is to transform a fetched message payload into something
safe for browser presentation without claiming support for rich HTML mail or
full client behavior.

## Status

As of March 27, 2026, the runtime now includes a conservative rendering layer on
top of the completed message-view fetch baseline.

The current slice provides:

- a plain-text-first rendering policy
- header extraction for a small summary surface
- browser-safe HTML escaping for fetched body text
- a preformatted body presentation mode
- structured audit events for rendering operations

The follow-on MIME-aware and attachment-aware policy layer now exists too and
is documented separately in `MIME_AND_ATTACHMENT_POLICY_BASELINE.md`.

This is intentionally smaller than a full message renderer.

## Current Rendering Mode

The current rendering mode is:

- `plain_text_preformatted`

That means:

- fetched body text is HTML-escaped
- the escaped text is wrapped in a `<pre>` block
- line breaks are preserved by the browser naturally
- no HTML mail is interpreted as active markup

This is intentionally conservative. The first goal is safe readable output, not
feature parity with legacy webmail.

## Header Handling

The current renderer extracts only a narrow summary:

- `Subject`
- `From`

The renderer unfolds continuation lines conservatively and applies explicit
length bounds before those values can move toward a browser-facing layer.

It does not yet attempt:

- full header presentation
- address parsing
- encoded-word decoding
- encoded-word decoding
- MIME header interpretation beyond the narrow follow-on classification layer

Those are later refinements, not assumptions.

## Security Posture

The rendering slice follows these rules:

- consume only already-fetched message data
- escape HTML-significant characters before browser presentation
- avoid any attempt to execute or preserve active HTML mail
- keep rendering output bounded
- log rendering activity by identifiers and context, not message content

This keeps the first rendering step aligned with the project’s conservative
mail-content threat model.

## What This Slice Proves

This slice now proves that:

- the project can turn a fetched message into browser-safe plain-text output
- header summary extraction can stay bounded and reviewable
- rendering can be modeled as a separate layer after message retrieval
- the system can move forward without pretending safe HTML rendering is already
  solved

## What Is Still Missing

This slice still does not yet include:

- HTML mail sanitization policy
- attachment retrieval or download behavior
- inline image policy
- encoded header decoding
- browser templates or request handlers

Those remain later work after the plain-text safety posture is established.
