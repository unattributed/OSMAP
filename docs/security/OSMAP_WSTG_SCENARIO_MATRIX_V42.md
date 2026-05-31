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

## Git commit comment

```text
add wstg due diligence matrix
```
