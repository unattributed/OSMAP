# Logging And Error Model

## Purpose

This document records the WP2 logging and error-handling baseline for the early
OSMAP prototype.

The goal is to establish useful operator diagnostics without adding a large
logging framework or leaking sensitive details.

## Logging Objectives

The current logging model is designed to:

- provide stable startup diagnostics
- keep event shape explicit and reviewable
- support later expansion into auth, session, and audit events
- remain dependency-light

## Current Event Shape

The bootstrap logger emits structured text lines containing:

- timestamp
- level
- category
- action
- message
- bounded key/value fields

This is intentionally simple. It is readable in a terminal and still structured
enough for later processing.

## Current Categories

The early logger currently distinguishes:

- `bootstrap`
- `config`
- `state`
- `auth`
- `session`
- `mailbox`

This now covers the runtime foundation plus the first authentication and session
layers. Later phases can add request, mailbox, and submission categories as
real behavior appears.

## Error-Handling Posture

The current bootstrap error model is intentionally handwritten and small.

It currently distinguishes:

- invalid configuration
- unsupported configuration values
- invalid state path boundaries

The purpose is to fail clearly and early when runtime assumptions are unsafe or
ambiguous.

## Non-Leaky Operator Errors

The current startup path follows these rules:

- operator-facing failures identify the configuration field that failed
- errors describe the violated rule
- errors do not print secret values because no secret-bearing settings are part
  of this slice
- startup exits cleanly on invalid bootstrap state rather than attempting hidden
  fallback behavior

## Logging Level Model

The current runtime supports:

- `debug`
- `info`
- `warn`
- `error`

The logger applies simple minimum-level filtering so the event model remains
predictable before later subsystems start producing higher-volume output.

## Why No Logging Framework Yet

WP2 deliberately avoids adding a full logging stack at this stage because the
project still needs to prove:

- what the runtime actually does
- what events really matter
- which dependencies are justified

The early structured logger is enough to define the event shape without letting
tooling complexity outrun the implementation.

## Next Expansion Points

This model should evolve later to include:

- richer request-to-action correlation across mail operations
- mail-operation audit events
- deployment-specific output routing on OpenBSD

Those should be added when real behavior exists, not preemptively.
