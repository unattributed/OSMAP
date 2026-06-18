# V6 Definition: Controlled Roundcube Retirement Readiness

## Purpose

OSMAP V6 is a controlled Roundcube retirement readiness milestone for a
selected OpenBSD-hosted user cohort. It proves that the cohort can perform its
essential browser-mail workflows without normal Roundcube fallback while the
existing mail substrate and native clients remain unchanged.

V6 is not a feature-parity release. It is an evidence, operations, migration,
and narrow blocker-remediation milestone.

## V6 Claim

OSMAP V6 proves that a selected OpenBSD-hosted user cohort can operate the
essential browser-mail workflows without Roundcube fallback, while preserving
the V4 hostile-content claim and the V5 identity, Host, Origin,
response-header, framing, and trusted HTML boundaries.

The claim requires live, sanitized evidence from the known OpenBSD target or
an explicitly documented equivalent target. Local tests alone cannot close
V6.

## Carried-Forward Boundaries

V6 carries forward:

- the V4 hostile-content assurance that active content, automatic remote
  loading, unsafe message HTML, and browser-executable attachment rendering
  remain contained by the narrow browser boundary
- the V5 canonical identity, configured Host, same-origin, response-header,
  strict request-framing, plain-text response, and typed trusted HTML
  boundaries
- the `_osmap` browser runtime and `vmail` mailbox-helper split
- helper-backed production mailbox access with no acceptable direct `doveadm`
  production fallback
- CSRF enforcement, `OSMAP_ALLOWED_HOSTS`, forced-download attachment handling,
  bounded request parsing, and dependency-light server-rendered operation

V6 does not widen the browser trust boundary.

## In Scope

V6 closes only narrow blockers needed for selected-cohort operation without
Roundcube fallback:

- authoritative scope, acceptance, and release gates
- production-readiness evidence
- a no-Roundcube-fallback workflow rehearsal
- operational observability and incident evidence
- bounded resource-resilience proof
- cross-process safety for the file-backed session store, or a validated and
  release-gated single-process invariant
- persistence of explicit source-attachment selections across draft resume,
  when required by the selected cohort
- sanitized closeout evidence, archive, checksums, and operator handoff

## Non-Goals

V6 does not add:

- remote image loading
- inline preview for active or browser-executable attachments
- broad JavaScript behavior
- contacts, calendar, groupware, plugins, or mobile app behavior
- OpenPGP
- a ManageSieve browser UI
- a broad admin console
- unbounded mailbox-wide operations
- a broad async runtime rewrite
- Roundcube database import
- hidden fallback behavior that weakens security
- general-purpose webmail or broad Roundcube feature parity

## Completion Rule

V6 is complete only when every criterion in `V6_ACCEPTANCE_CRITERIA.md` and
every closeout condition in `V6_SECURITY_GATES.md` passes for the same assessed
state. Missing tools, missing live context, failed workflows, unsafe evidence,
or Roundcube fallback keep V6 incomplete.
