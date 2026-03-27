# Project Charter

## Executive Summary

OSMAP is a greenfield replacement for Roundcube in a self-hosted OpenBSD mail
environment. The project is not a mail-server replacement and not a general
groupware platform. Its purpose is to produce a smaller, more defensible, more
maintainable web mail access layer that can eventually be exposed with greater
confidence than the current legacy webmail path.

## Why The Project Exists

Email remains the recovery channel and control plane for many other systems.
That makes browser-based mail access a disproportionately valuable target.
Legacy webmail products often carry broad functionality, large browser-facing
attack surfaces, plugin ecosystems, and long-lived compatibility baggage.

The project exists because the current operator environment is already strongly
hardened at the infrastructure layer, but the browser-facing mail path still
deserves a smaller and more security-driven design.

## Problem Statement

The current environment uses Roundcube successfully, but Roundcube is still a
general-purpose webmail application that introduces:

- a larger public- or semi-public-facing application surface than desired
- ongoing patching and dependency burden
- session and browser-side risk that is higher than protocol-native clients
- application-specific secrets and database state that must be maintained
- migration friction if stronger identity and session controls are introduced

## Project Purpose

Design and implement a restricted, secure, stable mail access platform that:

- runs on OpenBSD
- preserves compatibility with the existing mail transport infrastructure
- replaces the Roundcube web interface
- is realistic to operate long-term with a small team
- fits within a disciplined secure software development lifecycle

## Version 1 Goals

- Replace Roundcube with a purpose-built secure mail web interface
- Preserve IMAP and SMTP compatibility with the existing stack
- Keep native mail clients such as Thunderbird fully supported
- Make trust boundaries explicit
- Favor least privilege, reduced complexity, and high reviewability
- Produce enough documentation to support safe implementation and migration

## Version 1 Non-Goals

- Replacing Postfix, Dovecot, nginx, Rspamd, MariaDB, or the base OpenBSD host
- Replacing SOGo in version 1
- Building groupware, calendaring, contact sync, or plugin ecosystems into the
  OSMAP replacement
- Delivering a multi-tenant hosted service
- Reproducing every convenience feature present in legacy webmail suites
- Delivering a zero-access encrypted service model similar to ProtonMail

## Target Environment

The current deployment baseline is a single OpenBSD 7.7 host that already runs
the mail stack and supporting operational services. OSMAP is expected to sit on
top of that existing environment rather than replace its foundations.

Current observed stack elements include:

- OpenBSD 7.7 on `mail.blackbagsecurity.com`
- Postfix for inbound SMTP and authenticated submission
- Dovecot for IMAP, LMTP, and authentication-related roles
- nginx and PHP-FPM for the current web applications
- MariaDB for application state
- Roundcube as the current browser mail UI
- SOGo and PostfixAdmin as adjacent control-plane applications
- PF, WireGuard, sshguard, Suricata, Rspamd, Redis, and ClamAV as supporting
  security and operational components

## Constraints

- Security takes priority over feature breadth
- The solution must be maintainable by a small operator team
- Migration must not break core mail delivery or native-client access
- The system should be realistic to validate, operate, and recover
- Public documentation must not expose private secrets or sensitive local-only
  operational data

## Engineering Principles

- Minimal attack surface
- Least privilege
- Explicit trust boundaries
- Defense in depth
- Observability and auditability
- Reversible changes
- Small, understandable components
- Documentation that reflects reality

## Governance Baseline

The project aligns with the following guidance families:

- OWASP Top 10 for common web application risks
- CWE Top 25 for high-value software weakness classes
- MITRE ATT&CK for adversary behavior awareness and defensive planning
- Applicable NIST guidance for risk management, zero trust, and lifecycle
  governance

## Phase 0 Outcome

Phase 0 establishes that the project is valid, constrained, and worth
continuing. The project should move forward only if:

- the purpose and scope remain stable
- the existing system is understood well enough to avoid careless regression
- the replacement effort remains smaller and safer than carrying Roundcube
  indefinitely

## Success Conditions

The project is successful when:

- users can complete required mail workflows without Roundcube
- native-client access remains intact
- the web access layer is materially smaller and easier to reason about than
  the system it replaces
- the deployment can be operated safely by a small team
- Roundcube can be retired without service loss
