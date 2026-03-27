# Architecture Overview

## Status

This document is an initial public architecture baseline. It describes the
direction of the system and the constraints that future implementation work
should respect.

## Intended Deployment Context

OSMAP is designed for a self-hosted OpenBSD environment where mail transport and
storage already exist. The application should sit in front of established mail
services rather than replace them.

## High-Level Shape

The platform is expected to consist of:

- A tightly scoped web interface for authenticated users
- A backend service with explicit, minimal responsibilities
- Integration points for existing IMAP and submission services
- A reverse proxy or equivalent edge layer handling TLS termination and request
  filtering
- Logging and operational visibility appropriate for an internet-exposed system

## Architectural Constraints

- OpenBSD is the target operating environment
- Security is prioritized over feature breadth
- Components should run with least privilege
- Trust boundaries must be explicit and reviewable
- Operational simplicity is preferred over architectural novelty
- New dependencies require justification

## Out Of Scope For This Document

This initial version does not yet lock in implementation language, datastore
details, deployment topology, or protocol translation strategy. Those decisions
should be recorded once they are validated.

## Next Questions

- What minimal webmail feature set is required for version 1
- Where authentication state should live and how it should be constrained
- Which backend interactions are required versus intentionally omitted
- What observability is necessary for safe internet exposure
