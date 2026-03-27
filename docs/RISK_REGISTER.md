# Risk Register

## Purpose

This is the initial public-safe risk register for the OSMAP program.

## Scale

- Likelihood: Low, Medium, High
- Impact: Medium, High, Critical

## Current Risks

| ID | Risk | Likelihood | Impact | Phase Relevance | Initial Response |
| --- | --- | --- | --- | --- | --- |
| R-001 | Replacement scope grows from secure webmail into a second full mail platform | Medium | High | 0-5 | Hold firm on version 1 scope and non-goals |
| R-002 | Current Roundcube workflows are incompletely understood, causing migration regressions | High | High | 1-4 | Inventory actual user workflows before design lock |
| R-003 | Identity and session hardening for the web UI conflicts with native-client compatibility | High | Critical | 1-4 | Treat auth as a stack-wide design problem, not a single-UI patch |
| R-004 | The new system introduces more complexity than the platform it replaces | Medium | High | 2-6 | Favor narrow interfaces and small components |
| R-005 | Public exposure occurs before logging, abuse controls, and recovery paths are mature | Medium | Critical | 3-8 | Keep initial deployment behind current exposure boundaries if needed |
| R-006 | Secrets, private notes, or local-only operational details leak into the public repo | Medium | High | 0-8 | Maintain strict separation between `docs/` and ignored private paths |
| R-007 | Coexistence with SOGo, PostfixAdmin, and existing control-plane tools creates hidden coupling | Medium | High | 1-5 | Document shared host, routing, and operational dependencies |
| R-008 | Application database and preference migration is harder than expected | Medium | High | 1-7 | Treat data/state migration as a first-class workstream |
| R-009 | Browser-facing threat exposure remains too high even after replacement | Medium | Critical | 3-8 | Validate whether VPN-only or staged exposure is the safer steady state |
| R-010 | Small-team operational capacity is exceeded by the chosen design | High | High | 0-8 | Prefer maintainability and auditability over novelty |

## Current Assessment

The dominant early risks are not coding risks. They are scope, dependency,
auth, and migration risks. That is why Phase 0 and Phase 1 documentation work
comes before implementation.
