# Settings Surface Baseline

## Purpose

This document records the first bounded end-user settings surface for OSMAP.

The goal of this slice is not to create a broad preferences platform. The goal
is to expose one meaningful user-facing control that fits the current security
model and the newly implemented HTML-rendering behavior.

## Status

As of April 2, 2026, the runtime now includes a file-backed settings surface
behind the validated-session boundary.

The current slice provides:

- a server-rendered `GET /settings` page
- a CSRF-bound `POST /settings` update path
- one persisted per-user setting:
  `html_display_preference`
- explicit defaults when no settings file exists
- structured audit events for settings load and update operations

This is intentionally small and reviewable.

The current settings slice is now also live-proven on
`mail.blackbagsecurity.com` under `OSMAP_OPENBSD_CONFINEMENT_MODE=enforce`
through the browser route itself: the default HTML preference is rendered,
`POST /settings` persists `prefer_plain_text`, and the subsequent message view
reflects that stored preference.

## Current Setting

The first settings surface controls one behavior:

- whether HTML-capable messages prefer sanitized HTML rendering
- or prefer plain-text fallback when a plain-text body is available

The stored values are:

- `prefer_sanitized_html`
- `prefer_plain_text`

The default is `prefer_sanitized_html`.

## Storage Model

User settings are stored under the explicit state boundary in
`OSMAP_SETTINGS_DIR`.

The current file-backed store:

- keeps one settings file per canonical username
- derives the filename from a SHA-256 hash of the canonical username with a
  stable domain-separation prefix
- uses `0600` permissions on Unix-like systems
- keeps the serialized format small and line-oriented

This stays aligned with the rest of OSMAP's explicit state model instead of
introducing an ad hoc database or browser-local preference contract.

## Security Posture

This slice follows these rules:

- settings are session-gated
- updates require the current per-session CSRF token
- settings load failure does not widen browser trust silently
- message rendering falls back safely when settings cannot be loaded
- settings remain strictly user-facing rather than administrative

The current implementation uses the settings surface to control rendering
behavior, which makes the feature user-visible without creating a broad new
browser trust boundary.

## What This Slice Proves

This slice now proves that:

- OSMAP can provide a bounded end-user settings page without becoming a large
  preferences UI
- per-user rendering preference can be persisted safely under the existing
  state boundary
- a meaningful user-facing control can be added without widening the mail or
  submission trust boundaries
- the stored preference can drive a real browser-visible rendering change on
  the OpenBSD host rather than only a unit-test fixture

## What Is Still Missing

This slice does not yet include:

- multiple unrelated user preferences
- device labeling or richer session preference controls
- mailbox layout customization
- identity or recovery preferences
- a broad per-user profile model

Those remain out of scope for the current first-release settings posture.
