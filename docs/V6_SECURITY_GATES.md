# V6 Security Gates

## Purpose

These gates make controlled Roundcube retirement an evidence-backed claim.
V6 cannot pass by replacing, weakening, or silently skipping V4, V5, or current
repository security checks.

## Carry-Forward Gates

- `maint/security/osmap-v4-hostile-assurance-gate.sh` must pass for the assessed
  source and preserve the V4 no-active-content and no-remote-load boundary.
- The V5 boundary gate must confirm the evidence documents, configured Host and
  invalid-Host production proof, typed HTML boundary, and current source tests.
- `make security-check` remains mandatory.
- Production retains `_osmap` and `vmail` separation, helper-backed mailbox
  access, `OSMAP_ALLOWED_HOSTS`, same-origin checks, CSRF, strict framing,
  validated response headers, typed HTML responses, and forced downloads.

## V6 Closeout Inputs

The V6 closeout gate must fail unless all of these public-safe inputs exist and
are marked passed:

- V6 definition, acceptance criteria, roadmap, security gates, and slice traces
- V4 hostile-content assurance
- V5 boundary carry-forward
- production readiness report
- no-Roundcube-fallback rehearsal report
- observability report
- resource resilience report
- cross-process session-store locking or a validated release-gated
  single-process invariant
- V6 closeout evidence
- sanitized evidence archive and checksum

## Live Evidence Rules

- Live evidence must come from the known OpenBSD target or an explicitly
  equivalent target.
- Developer, dry-run, and allow-missing-context modes may aid development but
  cannot emit passing closeout reports.
- Authenticated workflows must use human-prompted or environment-provided
  secrets that are not written to evidence.
- Reports must not contain passwords, TOTP material, raw cookies, CSRF values,
  private keys, private mailbox bodies, raw attachment content, or private
  host-only material.
- Missing checks fail closed.

## Migration Gate

The selected cohort must complete every required workflow without Roundcube
fallback. `roundcube_fallback_used=yes`, any required failed workflow, or an
unclassified required workflow fails V6.

Roundcube remains an operator-controlled rollback unit during the cutover
window. The V6 claim concerns normal operation without fallback, not deletion
of rollback capability before evidence exists.

## Boundary-Remediation Gates

- Session operations that read-modify-write file-backed state must have
  cross-process coordination, or production must prove and enforce a
  single-mutator invariant.
- Draft resume may persist only explicit source mailbox, UID, and selected part
  references. Send must refetch and revalidate them.
- Resource testing must prove deterministic bounded failure, redaction, and
  recovery without unsafe production pressure.

## Failure Rule

If a V6 change passes ordinary functional tests but fails one of these gates,
the change and V6 milestone remain incomplete.
