# V10 Claims and Limitations

## Purpose

This document records what OSMAP may and may not claim at the start of V10 after the Slice 0 intake baseline.

It is intended to prevent release-language drift, documentation drift, and accidental expansion of the V9 selected-cohort claim.

## Allowed Claims

| Claim | Current basis | Boundary |
| --- | --- | --- |
| OSMAP is a security-first browser-mail access layer | Project charter, program baseline, prior release docs | It is not a mail-server, groupware, or plugin platform replacement. |
| V4 hostile-content containment has a historical evidence basis | V4 closeout, hostile corpus, and live-host evidence references | This does not become a general hostile-email, malware, or attachment-preview safety claim. |
| V7 rendering regression reopening is closed for the tested path | V7 closeout and later V9 reconciliation | This does not remove the need to rerun gates after deployment, rendering, or edge changes. |
| V9 selected-cohort release-candidate decision is accepted | V9 closeout and Slice 0 intake baseline | This is not a broad public release or universal Roundcube retirement claim. |
| V10 Slice 0 created an intake inventory | `docs/V10_INTAKE_AUDIT.md`, `maint/security/v10-intake-inventory.json` | Inventory findings are triage signals, not confirmed defects by themselves. |
| V10 Slice 1 records an authoritative governance status baseline | This document and `docs/V10_GOVERNANCE_STATUS.md` | This slice does not modify product behavior or production state. |

## Explicit Non-Claims

OSMAP V10 does not currently claim:

- full Roundcube feature parity,
- complete Roundcube replacement for every mailbox or user group,
- general hostile-email safety,
- malware prevention,
- attachment preview safety,
- URL reputation, phishing detection, or safe-click rewriting,
- unbounded MIME or mailbox parsing safety,
- complete denial-of-service resistance,
- complete TOTP enrollment, recovery, or lifecycle management,
- broad public release readiness,
- live deployment change as part of Slice 1.

## Claims Expansion Rule

A claim may only expand when all of the following are true:

1. The new claim is written in a versioned document.
2. Its evidence source is named by commit, archive, live run, or gate output.
3. Its non-goals and residual risks are stated next to the claim.
4. The relevant regression or release gate passes.
5. The documentation index and governance records are updated in the same slice.

## Current Risk Emphasis

The dominant V10 risks are evidence drift, stale status language, overbroad release claims, regression of existing daily-driver behavior, and unclassified fail-closed assumptions in production-adjacent Rust paths.

## Slice 1 Disposition

Slice 1 is complete only when these files exist, validate, and are indexed:

- `docs/V10_GOVERNANCE_STATUS.md`
- `docs/V10_CLAIMS_AND_LIMITATIONS.md`
- `maint/security/v10-claims-boundary.json`
- `docs/README.md` entries for both V10 documents


## Slice 2 Gate Claim

V10 may now claim that it has explicit local gate entry points for the current governance boundary:

- `make v10-check`
- `make acceptance-check`

This claim is limited to governance, claims-boundary, documentation-index, Makefile, and CI visibility validation. It does not expand the project into release readiness, production deployment, general hostile-email safety, or Roundcube feature parity.

## Slice 3 Documentation Closure Boundary
Slice 3 adds one bounded claim: the Slice 0 documentation placeholder and stale-status inventory has been classified for governance purposes.

This does not claim that every historical document has been rewritten, every future-work item has been implemented, all Rust assumptions are safe, production deployment has changed, or broad public release readiness has been reached.

The authoritative closure record is `docs/V10_DOCUMENTATION_STATUS_CLOSURE.md`, with machine-readable evidence in `maint/security/v10-documentation-status-closure.json`.
