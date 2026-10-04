# V10 targeted fail-closed remediation

## Purpose

This document records V10 Slice 5, targeted fail-closed remediation.

Slice 4 intentionally failed closed by classifying many Rust assumptions as high relevance. That was appropriate for the audit phase, but it was too broad to safely guide code changes. Slice 5 remediates that first problem by separating Rust assumptions inside source test modules from production-adjacent runtime assumptions, then gating the refined register.

## Selected remediation target

The selected remediation target is `src_test_module_assumption_reclassification`.

This target was selected because the Slice 4 audit included source-file assumptions that are inside Rust test modules. Treating those as production-adjacent would dilute the runtime remediation queue and create false confidence about the real production-path backlog.

## Current UX classification snapshot — 2026-10-04

Current evidence comes from `maint/security/v10-rust-assumption-audit.json` and `maint/security/v10-fail-closed-remediation.json`, generated respectively at UTC `2026-10-04T10:56:18Z` and `2026-10-04T10:56:18Z`. The earlier June `722` totals below remain historical; they are not the current scanner counts.

| Signal | Current value |
| --- | ---: |
| Baseline scanner count | `5879` |
| Refined scanner count | `5879` |
| Source test-module assumptions | `5793` |
| High relevance before refinement | `2039` |
| High relevance after refinement | `0` |
| Test/fixture assumptions before refinement | `3827` |
| Test/fixture assumptions after refinement | `5874` |
| Classification complete | `true` |

| Inventory / retained register | SHA-256 |
| --- | --- |
| Baseline normalized inventory | `1e4697be6ae6de542ddc38bf20da1eb5cb1d0d3d493319873bd2d0a195ba2d9d` |
| Refined normalized inventory | `1939eaeb2ab6c0be587b3687ffe4fbd2a635094348f57018bd874a0283bcd171` |
| Baseline register file | `974a344a3dd399510eb659e34d7f4e494f78c9212132b960ce79190086144603` |
| Refined register file | `dcd92cca1222e909ddd3644c8c4a845266767a4dd71ad6a50fae03e11952e63a` |


### Current refined classification

| Signal | Count |
| --- | ---: |
| control_flow_invariant | `3` |
| startup_or_global_invariant | `2` |
| test_or_fixture_assumption | `5874` |

### Current refined relevance

| Signal | Count |
| --- | ---: |
| low | `5874` |
| medium | `5` |

Current refined high-relevance top files: **none**. The current classification still records five medium-relevance assumptions. Reclassifying test-module assumptions is audit precision, not proof that production code is panic-free, a runtime behavior change, release readiness, or UX slice completion. The original assessed-source provenance is preserved in `docs/V10_RUST_ASSUMPTION_FAIL_CLOSED_AUDIT.md`; this snapshot records exact current generated evidence without inventing a newly assessed Git commit.

## Historical June 2026 evidence summary

- Baseline Slice 4 scanner count: 722
- Refined Slice 5 scanner count: 722
- Source test-module assumptions classified as test or fixture assumptions: 645
- High-relevance assumptions before refinement: 644
- High-relevance assumptions after refinement: 0
- Test or fixture assumptions before refinement: 76
- Test or fixture assumptions after refinement: 721

## Historical June refined high-relevance top files

- none

## What changed

- Added `maint/security/osmap-v10-fail-closed-remediation.py`.
- Added `maint/security/v10-fail-closed-remediation.json`.
- Added this document.
- Updated the V10 claims boundary and governance gate.
- Added `make v10-fail-closed-remediation-check`.

## This slice does not claim

- This slice does not claim production Rust paths are panic-free.
- This slice does not claim all high-relevance assumptions have been remediated.
- This slice does not claim runtime product behavior changed.
- This slice does not claim broad public release readiness.

## Required follow-up

The next runtime remediation slice should select one concrete user-reachable high-relevance path from the refined list, convert it into an explicit error or fail-closed response, and add regression coverage.
