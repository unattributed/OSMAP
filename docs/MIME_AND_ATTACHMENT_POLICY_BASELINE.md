# MIME And Attachment Policy Baseline

## Purpose

This document records the next WP6 follow-on step after plain-text-first
rendering: MIME-aware message classification and attachment-aware metadata
surfacing.

The goal of this slice is to tell the truth about common mail structures
without turning the prototype into a rich HTML client prematurely.

## Status

As of March 27, 2026, the runtime now includes a dependency-light MIME analysis
layer and attachment metadata surface on top of the completed message-view and
plain-text rendering baselines.

The current slice provides:

- top-level MIME classification for fetched messages
- bounded parsing of `Content-Type` and `Content-Disposition`
- bounded first-layer and nested multipart inspection
- plain-text part selection for common multipart layouts
- explicit HTML-withheld and structure-withheld placeholder behavior
- attachment metadata surfacing without attachment retrieval
- rendering audit fields that now describe MIME type, body source, and
  attachment count

This is intentionally smaller than a full MIME engine.

## Current Behavior

The runtime now distinguishes between:

- single-part `text/plain` messages
- single-part `text/html` messages
- multipart messages that contain a safe plain-text part
- multipart messages that contain only HTML or non-renderable parts
- attachment-oriented or binary-only content

The current renderer still exposes only browser-safe preformatted text.

That means:

- selected plain-text bodies are escaped and wrapped in `<pre>`
- HTML-only content is withheld behind an explicit placeholder
- multipart messages without a safe plain-text preview are withheld behind an
  explicit placeholder
- attachment-bearing messages now expose attachment metadata without exposing
  attachment content

## Attachment Metadata Surface

The current attachment metadata model includes:

- part path
- filename when present
- content type
- disposition
- size hint in bytes

This is enough to support:

- honest operator and developer reasoning about message structure
- later attachment download design
- later UI work that shows attachments without guessing

It is not yet a download or preview contract.

## Security Posture

This slice follows these rules:

- MIME inspection is separate from browser rendering
- only selected plain text is rendered for the browser
- HTML presence is recorded, not interpreted
- multipart traversal is bounded by depth, part count, and boundary length
- attachment metadata is surfaced without exposing attachment bodies
- malformed or incomplete structures fall back to explicit withheld states

This keeps the project aligned with the existing hostile-content threat model
while still making progress on real-world message structure.

## Common Layouts Covered

The current logic is intentionally aimed at common mail shapes first:

- single-part plain-text mail
- single-part HTML mail
- `multipart/alternative` with text/plain plus text/html
- `multipart/mixed` carrying a readable body plus attachments
- nested multipart layouts where a top-level mixed message contains an
  alternative body and a separate attachment

That coverage is practical enough to move the prototype forward while staying
reviewable.

## What This Slice Proves

This slice now proves that:

- OSMAP can classify common MIME message shapes without a large dependency
- the browser-facing layer can preserve a plain-text-first posture even when
  the message is HTML or multipart
- attachment metadata can be surfaced honestly before attachment download
  behavior exists
- the project can support common multipart mail without quietly becoming a rich
  HTML mail renderer

## What Is Still Missing

This slice does not yet include:

- HTML sanitization and safe HTML rendering
- encoded-word and RFC 2231 parameter decoding
- attachment retrieval handlers or download authorization behavior
- inline image rendering
- nested message/rfc822 presentation
- browser templates or HTTP request handlers

Those remain later WP6 and post-WP6 work.
