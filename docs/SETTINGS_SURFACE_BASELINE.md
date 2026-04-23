# Settings Surface Baseline

## Purpose

This document records the first bounded end-user settings surface for OSMAP.

The goal of this slice is not to create a broad preferences platform. The goal
is to expose a small set of meaningful user-facing controls that fit the
current security model and browser workflow boundary.

## Status

As of April 9, 2026, the runtime now includes a file-backed settings surface
behind the validated-session boundary.

The current slice provides:

- a server-rendered `GET /settings` page
- a CSRF-bound `POST /settings` update path
- two persisted per-user settings:
  `html_display_preference` and `archive_mailbox_name`
- explicit defaults when no settings file exists
- archive mailbox validation against the authenticated user's current mailbox
  list before a configured shortcut is persisted
- structured audit events for settings load and update operations

This is intentionally small and reviewable.

The current settings slice is now also live-proven on
`mail.blackbagsecurity.com` under `OSMAP_OPENBSD_CONFINEMENT_MODE=enforce`
through the browser route itself: the default HTML preference is rendered,
`POST /settings` persists both `prefer_sanitized_html` and
`archive_mailbox_name=Junk`, the subsequent settings page reload reflects that
stored state, and the configured archive shortcut appears on both mailbox and
message pages before a real archive action succeeds.

## Current Settings

The first settings surface currently controls two behaviors:

- whether HTML-capable messages prefer sanitized HTML rendering
- or prefer plain-text fallback when a plain-text body is available
- which existing mailbox should be used for the one-click archive shortcut
  when that shortcut is enabled

The stored values now include:

- `prefer_sanitized_html`
- `prefer_plain_text`
- one optional `archive_mailbox_name`

The default is `prefer_sanitized_html`.

## Storage Model

User settings are stored under the explicit state boundary in
`OSMAP_SETTINGS_DIR`.

The current file-backed store:

- keeps one settings file per canonical username
- derives the filename from a SHA-256 hash of the canonical username with a
  stable domain-separation prefix
- writes through a unique same-directory temp file before atomic rename so
  concurrent saves do not share one intermediate pathname
- uses `0600` permissions on Unix-like systems
- keeps the serialized format small and line-oriented

This stays aligned with the rest of OSMAP's explicit state model instead of
introducing an ad hoc database or browser-local preference contract.

## Security Posture

This slice follows these rules:

- settings are session-gated
- updates require the current per-session CSRF token
- archive shortcut destinations must be syntactically valid mailbox names and
  must exist in the authenticated user's mailbox listing at save time
- settings load failure does not widen browser trust silently
- stale archive destinations that no longer resolve are hidden from message and
  mailbox shortcut forms instead of being reused as hidden move targets
- message rendering falls back safely when settings cannot be loaded
- settings remain strictly user-facing rather than administrative

The current implementation uses the settings surface to control rendering
behavior plus one bounded folder shortcut, which makes the feature user-visible
without creating a broad new browser trust boundary.

## What This Slice Proves

This slice now proves that:

- OSMAP can provide a bounded end-user settings page without becoming a large
  preferences UI
- per-user rendering preference and archive shortcut destination can be
  persisted safely under the existing state boundary
- syntactically valid but non-existent archive destinations are rejected with a
  clear 400-class validation response and are not saved
- a meaningful user-facing control can be added without widening the mail or
  submission trust boundaries
- the stored settings can drive real browser-visible rendering and
  folder-organization behavior on the OpenBSD host rather than only
  unit-test fixtures

## What Is Still Missing

This slice does not yet include:

- multiple unrelated user preferences
- device labeling or richer session preference controls
- mailbox layout customization beyond the current archive shortcut
- identity or recovery preferences
- a broad per-user profile model

Those remain out of scope for the current first-release settings posture.
