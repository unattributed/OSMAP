# V6 Observability Evidence Model

## Purpose

V6 requires proof that an operator can review authentication, session,
submission, helper, capacity, and browser-boundary behavior without exposing
credentials or private mail content.

## Required Event Evidence

The serve log must contain normalized evidence for:

- login denial
- successful second-factor completion
- session issuance with a redacted `session_ref`
- session revocation
- a send attempt represented by success or bounded failure metadata
- invalid Host or same-origin rejection, unless carried forward from the V6
  production readiness report

The helper log must contain health or bounded failure evidence. Capacity or
route-budget behavior must be observed, or the operator must explicitly record
that triggering it was not live-safe and rely on local regression evidence.

## Redaction Boundary

The validator rejects raw password, TOTP, CSRF, OSMAP cookie, cookie-header,
session identifier, message-body, attachment-body, and private-key markers.
The report records event-category dispositions and file metadata, not raw log
lines.

## Operator Review

Automation proves the minimum event and redaction shape. A human operator must
also confirm the evidence was reviewable and sufficient for incident response.
The report is not passing without that explicit confirmation.
