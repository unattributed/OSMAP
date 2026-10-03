# OSMAP WSTG v4.2 Scenario Matrix

This document summarizes `maint/wstg-testing-pack/wstg-scenario-matrix.v42.json`.

The matrix is a due-diligence control, not a test result. A scenario is not complete until it has either executed evidence or a documented not-applicable proof.

## Current coverage summary

| Category | WSTG v4.2 scenario entries | Mapped by current OSMAP pack | Needs applicability or evidence decision |
| --- | ---: | ---: | ---: |
| INFO | 10 | 10 | 0 |
| CONF | 11 | 11 | 0 |
| IDNT | 5 | 5 | 0 |
| ATHN | 10 | 10 | 0 |
| ATHZ | 4 | 4 | 0 |
| SESS | 9 | 9 | 0 |
| INPV | 19 | 19 | 0 |
| ERRH | 2 | 2 | 0 |
| CRYP | 4 | 4 | 0 |
| BUSL | 9 | 9 | 0 |
| CLNT | 13 | 13 | 0 |
| APIT | 1 | 1 | 0 |

## Interpretation

- `mapped_in_current_pack` means the current OSMAP mapping references the WSTG ID.
- `not_mapped_in_current_pack` means the current OSMAP mapping does not reference the WSTG ID.
- `not_applicable_candidate_but_requires_repo_or_live_proof` means the scenario may not apply to OSMAP, but release due diligence still needs evidence.
- `candidate_gap_for_v3_wstg_due_diligence_backlog` means the scenario should become a manual or automated due-diligence item.

## Supplemental mapping note

The current OSMAP mapping includes these WSTG identifiers that were not present in the retrieved OWASP v4.2 stable table of contents used for this matrix:

- `WSTG-v42-CONF-12`

For those identifiers, keep the OSMAP test if it is valuable, but add a source note that explains whether it comes from latest WSTG content, an OWASP mirror, or an OSMAP-specific supplemental control.

## UX S02-01 search-helper development delta

The authenticated all-folder search operation is a new helper protocol boundary.
Its bounded component evidence supplements the existing mappings; it does not
mark a full WSTG scenario or credential-backed release run complete.

| Existing mapping | Concrete component check |
| --- | --- |
| WSTG-v42-ATHZ-02 / ATHZ-04 | Canonical account and ordered scope grants; foreign/mismatched identities refused; owned native paired accounts and exact mailbox GUID scope |
| WSTG-v42-INPV-12 | Typed search field and literal argument vector; no client-selected program or shell command; pattern-shaped names resolved to exact GUIDs |
| WSTG-v42-BUSL-03 / BUSL-05 | Operation/account/count/order/query/field-bound HMAC, in-process replay refusal, byte/row/result bounds, absolute transport deadline and worker release |
| WSTG-v42-ERRH-01 | Whole-result refusal for malformed/out-of-scope/late replies; finite gateway error codes exclude private queries and native diagnostics |

Executed attempts, source pins and matching deployment outcomes belong in
`docs/UX_EXECUTION_LEDGER.md` and the S02 sprint root. Helper replay remains
in-memory; restart/clock-rollback protection, human password/TOTP, SMTP delivery,
OpenPGP and broad hostile-email or strict-release assurance are not established
by these Search tests.

## Git commit comment

```text
add wstg due diligence matrix
```
