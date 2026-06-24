# V9 Release Candidate Closeout

Status: PASS
Generated from: `osmap-v9-slice-7-release-candidate-gate-20260624-143641Z`
Generated at UTC: `2026-06-24T16:00:48Z`

## Decision

OSMAP V9 is accepted as a selected-cohort release candidate.

This is a bounded release-candidate decision. It does not claim complete Roundcube feature parity, general hostile email safety, unbounded mailbox parsing safety, or release readiness outside the documented selected-cohort scope.

Final reason from the Slice 7 gate:

```text
current main is a V9 release candidate with production runtime code identity proven, docs-only source drift from the live binary, clean checks, healthy services, hostile-content carry-forward, hold-period proof, V7 closeout, V6 selected-cohort closeout, limitations, and rollback references
```

## Authoritative commit and runtime identity

- Current main release-candidate commit: `a8915c0993b96a9d53de083dc84cb7520aef0097`
- Production runtime source commit: `49c9f230d7865f01deadbc6a5a0f6e876c63e89b`
- Production binary SHA256: `411c976cccb0687f1a6e840470584fd8921eb5469e68905e457cf3edfe0cdea3`

The live production runtime code remains the PR #19 deployed binary. Current main differs from production source by documentation-only files.

## Production to main drift

Changed files between production runtime source and current main:

- `README.md`
- `docs/BUILD_AND_RELEASE_PROCESS.md`
- `docs/DECISION_LOG.md`
- `docs/KNOWN_LIMITATIONS.md`
- `docs/README.md`
- `docs/V7_PRODUCTION_AVAILABILITY_CLOSEOUT.md`
- `docs/V9_PRODUCTION_CONVERGENCE.md`

Non-documentation changed files:

- none

## Required checks

- `bounded_crash_scan_zero`: `true`
- `codeql_or_analysis_present`: `true`
- `github_checks_no_bad`: `true`
- `github_checks_no_pending`: `true`
- `limitations_documented`: `true`
- `main_sha_present`: `true`
- `production_binary_hash_expected`: `true`
- `production_osmap_services_ok`: `true`
- `production_source_head_expected`: `true`
- `production_supporting_services_ok`: `true`
- `production_to_main_diff_docs_only`: `true`
- `rollback_instructions_documented`: `true`
- `security_gate_present`: `true`
- `slice3_forward_send_marker_present`: `true`
- `slice3_hold_period_pass`: `true`
- `slice4_hostile_carry_forward_pass`: `true`
- `slice5_v7_doc_merge_post_main_pass`: `true`
- `slice5_v7_production_closeout_pass`: `true`
- `slice6_v6_selected_cohort_pass`: `true`

## GitHub checks

Successful checks:

- `Analyze (python)`
- `Analyze (actions)`
- `Analyze (rust)`
- `security-check / rust`

Skipped checks:

- `security-check / live tls`

Pending checks:

- none

Bad checks:

- none

## Production services

- `dovecot`: `true`
- `nginx`: `true`
- `osmap_mailbox_helper`: `true`
- `osmap_serve`: `true`
- `postfix`: `true`
- `redis`: `true`
- `rspamd`: `true`

## Prior V9 evidence chain

### slice1_intake

- present: `true`
- sha verified: `true`
- decision: `None`
- verdict: `None`
- reason: `None`
- archive sha256: `5de376e832ae79f8c29afd1e3b0243f8ac09a04d4bb0c71a7a771fd65403e331`

### slice2_doc_merge_post_main

- present: `true`
- sha verified: `true`
- decision: `PASS`
- verdict: `None`
- reason: `PR #20 merged, main contains validated V9 documentation, and post-merge GitHub checks completed without failures`
- archive sha256: `14ce91a8e116c7450479df9225b9498519e1106b78c7080fbea6da9f6cfe68c4`

### slice3_hold

- present: `true`
- sha verified: `true`
- decision: `PASS`
- verdict: `ANALYST_REVIEW_REQUIRED`
- reason: `required captures completed`
- archive sha256: `18c3710a109d8d5152e11d2cebafacae4c8047be9587a5d5ef691d462bba6b0d`

### slice4_v4_carry_forward

- present: `true`
- sha verified: `true`
- decision: `PASS`
- verdict: `None`
- reason: `V4 hostile-content assurance, claim matrix, release tuple reconciliation, and evidence validation passed against current main`
- archive sha256: `0a67c1e254a7277003253d26fc5b3d5700072fe53c453a6dc890374ae53c2ac1`

### slice5_v7_doc_merge_post_main

- present: `true`
- sha verified: `true`
- decision: `PASS`
- verdict: `None`
- reason: `PR #21 merged, main contains validated V7 closeout documentation, and post-merge GitHub checks completed without failures`
- archive sha256: `675067ca2a2de801ed1fa06de8b3f1bdb3cafde27aae0abee74f78090316fbdc`

### slice5_v7_production_closeout

- present: `true`
- sha verified: `true`
- decision: `PASS`
- verdict: `V7_PRODUCTION_AVAILABILITY_CAN_BE_CLOSED`
- reason: `V7 production availability evidence is satisfied by Slice 3 hold proof, V7 rendering regression gate, V7 boundary gate, and current production snapshot`
- archive sha256: `2a2514ca62028bb1d444802b2f614014e7dae92e52864517caebdfadd39b7076`

### slice6_v6_selected_cohort

- present: `true`
- sha verified: `true`
- decision: `PASS`
- verdict: `V5`
- reason: `V6 selected-cohort / no-Roundcube closeout criteria are satisfied by documentation and evidence`
- archive sha256: `844625e0d942b1366bcab3f1d5bcc9df4b1903754551af73cb8a1506d02ba959`

## Warnings carried forward

- `current main differs from production source by documentation-only files`
- `Slice 3 production_hold_verdict remains ANALYST_REVIEW_REQUIRED, but later V7 and V6 closeout evidence accepted the hold proof`
- `skipped check-runs: security-check / live tls`

## Not claimed

- `general hostile email safety`
- `complete Roundcube feature parity`
- `unbounded mailbox parsing safety`
- `release readiness beyond the documented selected-cohort scope`

## Operator interpretation

This closeout supports selected-cohort operation without Roundcube fallback under the documented limitations and stop criteria. It does not expand the security claim beyond the tested evidence.

Rollback and fallback instructions remain governed by the existing deployment, service, and Roundcube retirement documentation:

- `docs/MAIL_HOST_BINARY_DEPLOYMENT_SOP.md`
- `docs/V6_ROUNDCUBE_RETIREMENT_REHEARSAL.md`
- `docs/V6_RELEASE_OPERATOR_HANDOFF.md`
- `docs/V7_PRODUCTION_AVAILABILITY_CLOSEOUT.md`
- `docs/V9_PRODUCTION_CONVERGENCE.md`

## Closeout result

V9 release-candidate gate: PASS.
