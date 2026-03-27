# Security Model

## Security Posture

OSMAP is intended for environments where exposing webmail access is necessary
but must be tightly controlled. Security requirements therefore shape the
project before feature design.

## Primary Objectives

- Reduce externally reachable attack surface
- Limit privilege and blast radius of every component
- Protect mail content, credentials, and session state
- Make trust boundaries explicit
- Support monitoring, review, and safe rollback

## Core Assumptions

- The system may be reachable from the public internet
- It will coexist with an existing OpenBSD mail stack
- Native mail clients continue to operate independently of the web interface
- Operators prefer maintainability and reviewability over broad functionality

## Trust Boundaries

The following boundaries should be treated as first-class design concerns:

- User browser to public edge
- Public edge to application service
- Application service to mail backends
- Application service to any persistence or session store
- Operator access paths into deployment and maintenance workflows

## Security Principles

- Least privilege by default
- Defense in depth at network, process, and application layers
- Minimal exposed functionality
- Explicit authentication and authorization controls
- Dependency and supply chain scrutiny
- Observable behavior for incident response and audit

## Deferred Details

This document is intentionally high level for the planning phase. Concrete
controls, threat scenarios, and mitigations should be added as the architecture
and implementation choices harden.
