# Project Charter

## Purpose

OSMAP exists to provide a security-focused web mail access layer for an
self-hosted OpenBSD mail stack.

The initial project goal is to replace feature-heavy webmail interfaces with a
smaller, more maintainable system that is suitable for controlled internet
exposure.

## Problem Statement

Traditional webmail platforms often trade security minimalism for feature depth
and extensibility. That trade-off is undesirable for environments that value
restricted functionality, predictable operations, and small-team maintenance.

## Goals

- Provide browser-based mail access for an existing OpenBSD mail deployment
- Preserve compatibility with established IMAP and SMTP backends
- Minimize attack surface and operational complexity
- Support reproducible builds and controlled deployment practices
- Produce documentation that can guide implementation and review

## Non-Goals

- Groupware, calendaring, or plugin ecosystems in the initial release
- Replacing Postfix, Dovecot, nginx, or the broader mail transport stack
- Multi-tenant SaaS operation
- Broad enterprise feature parity with legacy webmail platforms

## Scope For The Current Phase

The repository is currently focused on design and planning artifacts rather than
production code. This phase is intended to establish shared assumptions,
security objectives, and architectural direction before implementation begins.

## Success Criteria

- Core project intent is documented and reviewable
- Security priorities are stated before implementation work starts
- Initial architecture constraints are captured in writing
- Major decisions can be recorded and revisited as the project evolves

## Deliverables

- A project charter
- A living architecture overview
- A living security model
- A decision log for material design choices
