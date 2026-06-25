# V10 Documentation Placeholder and Stale-Status Closure

## Purpose
V10 Slice 3 closes the documentation ambiguity identified by the Slice 0 intake. It classifies literal placeholder wording, stale-status language, missing-work headings, future-work wording, and historical version references without erasing useful provenance.

This slice is documentation and governance only. It does not change product behavior, deployment state, live-host configuration, authentication policy, mailbox handling, rendering behavior, or release posture.

## Assessed source
- Generated at UTC: `2026-06-25T08:27:19Z`
- Local branch observed: `v10-doc-status-closure`
- Local HEAD observed: `318d6983719fceb15a49f35451cdba144d30d08e`
- `origin/main` observed: `318d6983719fceb15a49f35451cdba144d30d08e`
- Local status clean: `true`

## Slice 0 signals closed by classification

| Signal | Slice 0 value | Slice 3 disposition |
| --- | ---: | --- |
| Markdown document inventory | `155` | Preserved as the documentation baseline. |
| Governance-language matches | `1494` | Classified by pattern and bounded by the claims register. |
| Placeholder or missing-work candidate files | `22` | Classified by path and context in this closure. |
| Rust assumption inventory count | `712` | Not changed here. Deferred to the Rust assumption slice. |

## Placeholder inventory classification

| Disposition | Count | Meaning |
| --- | ---: | --- |
| `accepted_historical_security_evidence_language` | `9` | Historical evidence of fail-closed rendering or MIME behavior. |
| `classified_historical_or_contextual_language` | `4` | Retained historical or contextual wording bounded by V10 claims. |
| `accepted_gate_or_regression_sentinel` | `2` | Guard or regression-test wording that protects prior behavior. |
| `accepted_platform_template_example` | `2` | GitHub issue template example fields, not unresolved implementation work. |
| `accepted_product_safe_placeholder_language` | `2` | Source or product wording for intentionally withheld safe output. |
| `classified_governance_meta_language` | `2` | Governance discussion of documentation placeholders, now bounded by this closure. |
| `accepted_configuration_example_language` | `1` | Non-secret placeholder configuration example language. |

### Placeholder candidate paths

| Path | Disposition | Rationale |
| --- | --- | --- |
| `.github/ISSUE_TEMPLATE/bug_report.yml` | `accepted_platform_template_example` | GitHub issue templates use placeholder fields as example user-interface text. This is not an unresolved project implementation placeholder. |
| `.github/ISSUE_TEMPLATE/feature_request.yml` | `accepted_platform_template_example` | GitHub issue templates use placeholder fields as example user-interface text. This is not an unresolved project implementation placeholder. |
| `docs/DECISION_LOG.md` | `classified_governance_meta_language` | The match discusses documentation governance or historical placeholder policy. Slice 3 replaces ambiguity with this explicit closure record. |
| `docs/MIME_AND_ATTACHMENT_POLICY_BASELINE.md` | `accepted_historical_security_evidence_language` | The match documents historical fail-closed rendering or MIME behavior where safe placeholder output is the intended security behavior. |
| `docs/OSMAP_HELPER_SECURITY_REVIEW_2026_05_13.md` | `classified_historical_or_contextual_language` | The match is retained as historical or contextual wording and is bounded by the V10 claims and limitations register. |
| `docs/README.md` | `classified_governance_meta_language` | The match discusses documentation governance or historical placeholder policy. Slice 3 replaces ambiguity with this explicit closure record. |
| `docs/ROUNDCUBE_DEPENDENCY_ANALYSIS.md` | `accepted_configuration_example_language` | The match refers to non-secret placeholder configuration examples or override descriptions, not embedded credentials. |
| `docs/V4_ACCEPTANCE_CRITERIA.md` | `accepted_historical_security_evidence_language` | The match documents historical fail-closed rendering or MIME behavior where safe placeholder output is the intended security behavior. |
| `docs/V4_AUDIT_REMEDIATION_REPORT.md` | `classified_historical_or_contextual_language` | The match is retained as historical or contextual wording and is bounded by the V10 claims and limitations register. |
| `docs/V4_CLOSEOUT_EVIDENCE.md` | `classified_historical_or_contextual_language` | The match is retained as historical or contextual wording and is bounded by the V10 claims and limitations register. |
| `docs/V4_HOSTILE_CONTENT_SAFETY_GOALS.md` | `accepted_historical_security_evidence_language` | The match documents historical fail-closed rendering or MIME behavior where safe placeholder output is the intended security behavior. |
| `docs/V4_HOSTILE_CONTENT_TEST_MATRIX.md` | `accepted_historical_security_evidence_language` | The match documents historical fail-closed rendering or MIME behavior where safe placeholder output is the intended security behavior. |
| `docs/V4_ROADMAP.md` | `accepted_historical_security_evidence_language` | The match documents historical fail-closed rendering or MIME behavior where safe placeholder output is the intended security behavior. |
| `docs/V4_SECURITY_CLAIM_MATRIX.md` | `classified_historical_or_contextual_language` | The match is retained as historical or contextual wording and is bounded by the V10 claims and limitations register. |
| `docs/V4_SECURITY_GATES.md` | `accepted_historical_security_evidence_language` | The match documents historical fail-closed rendering or MIME behavior where safe placeholder output is the intended security behavior. |
| `docs/V7_BOUNDARY_HARDENING_DUE_DILIGENCE.md` | `accepted_historical_security_evidence_language` | The match documents historical fail-closed rendering or MIME behavior where safe placeholder output is the intended security behavior. |
| `docs/V7_RENDERING_REGRESSION_CLOSEOUT.md` | `accepted_historical_security_evidence_language` | The match documents historical fail-closed rendering or MIME behavior where safe placeholder output is the intended security behavior. |
| `docs/V8_MAIL_WORKFLOW_MATRIX.md` | `accepted_historical_security_evidence_language` | The match documents historical fail-closed rendering or MIME behavior where safe placeholder output is the intended security behavior. |
| `maint/security/osmap-v4-security-claim-matrix-gate.sh` | `accepted_gate_or_regression_sentinel` | The match is inside a gate, regression test, or required-text check that protects prior security behavior. |
| `maint/security/osmap-v7-rendering-regression-gate.sh` | `accepted_gate_or_regression_sentinel` | The match is inside a gate, regression test, or required-text check that protects prior security behavior. |
| `src/http_ui.rs` | `accepted_product_safe_placeholder_language` | The literal word placeholder is used in source comments or safe browser output paths to describe intentionally withheld or bounded rendering, not missing implementation text. |
| `src/rendering.rs` | `accepted_product_safe_placeholder_language` | The literal word placeholder is used in source comments or safe browser output paths to describe intentionally withheld or bounded rendering, not missing implementation text. |

## Stale-status and version-reference classification

| Pattern group | Count | Slice 3 disposition |
| --- | ---: | --- |
| `stale` | `71` | Allowed as risk, future-work, or stale-summary warning language only when bounded by V10 claims. |
| `future` | `89` | Allowed as risk, future-work, or stale-summary warning language only when bounded by V10 claims. |
| `remaining` | `128` | Allowed as risk, future-work, or stale-summary warning language only when bounded by V10 claims. |
| `What Is Still Missing` | `14` | Allowed only when the surrounding document states current scope, historical status, or explicit non-claim boundaries. |
| `Current Status` | `12` | Allowed only when the surrounding document states current scope, historical status, or explicit non-claim boundaries. |
| `Residual Risk` | `19` | Allowed only when the surrounding document states current scope, historical status, or explicit non-claim boundaries. |
| `This does not claim` | `10` | Allowed only when the surrounding document states current scope, historical status, or explicit non-claim boundaries. |
| `TODO` | `1` | Must remain rare. Slice 3 records this as a triage signal, not an allowed release claim. |
| `V1` through `V9` references | `1135` | Historical provenance. These references are not stale by themselves. |

## Highest-density scan paths

| Path | Match count | Disposition |
| --- | ---: | --- |
| `docs/DECISION_LOG.md` | `378` | Review-density signal retained for future targeted documentation work. |
| `docs/OWASP_ASVS_BASELINE.md` | `55` | Review-density signal retained for future targeted documentation work. |
| `README.md` | `54` | Review-density signal retained for future targeted documentation work. |
| `docs/V8_STABILIZATION_PROGRAM.md` | `40` | Review-density signal retained for future targeted documentation work. |
| `docs/V9_PRODUCTION_CONVERGENCE.md` | `39` | Review-density signal retained for future targeted documentation work. |
| `docs/KNOWN_LIMITATIONS.md` | `37` | Review-density signal retained for future targeted documentation work. |
| `docs/V4_AUDIT_REMEDIATION_REPORT.md` | `32` | Review-density signal retained for future targeted documentation work. |
| `docs/V6_CLOSEOUT_EVIDENCE.md` | `31` | Review-density signal retained for future targeted documentation work. |
| `docs/V7_BOUNDARY_HARDENING_DUE_DILIGENCE.md` | `29` | Review-density signal retained for future targeted documentation work. |
| `docs/V8_FINAL_REGRESSION_GATE_CLOSEOUT.md` | `28` | Review-density signal retained for future targeted documentation work. |
| `docs/V4_CLOSEOUT_EVIDENCE.md` | `25` | Review-density signal retained for future targeted documentation work. |
| `docs/BUILD_AND_RELEASE_PROCESS.md` | `24` | Review-density signal retained for future targeted documentation work. |
| `docs/V6_TRACES/SLICE_09_CLOSEOUT.md` | `24` | Review-density signal retained for future targeted documentation work. |
| `docs/V7_PRODUCTION_AVAILABILITY_CLOSEOUT.md` | `24` | Review-density signal retained for future targeted documentation work. |
| `docs/README.md` | `22` | Review-density signal retained for future targeted documentation work. |

## Closure decision

Slice 3 closes the documentation placeholder and stale-status issue as follows:

1. Literal placeholder wording is classified by context and no longer treated as an unreviewed open-ended release defect by default.
2. Historical version references are accepted as provenance unless a document uses them to expand current claims.
3. Future-work, remaining-work, residual-risk, and non-claim language remains permitted only when it is bounded by the V10 claims register.
4. Any future claim expansion must update `docs/V10_CLAIMS_AND_LIMITATIONS.md`, `maint/security/v10-claims-boundary.json`, and pass `make v10-check`.
5. Rust fail-closed assumption classification remains out of scope for Slice 3 and is preserved as a future V10 slice.

## Explicit non-claims

This closure does not claim:

- that every historical document has been rewritten,
- that every future-work item has been implemented,
- that all Rust assumptions are safe,
- that production deployment has changed,
- that OSMAP is a broad public release,
- that OSMAP has complete Roundcube feature parity.

## Slice 3 acceptance criteria

Slice 3 is complete only when all of the following are true:

1. `docs/V10_DOCUMENTATION_STATUS_CLOSURE.md` exists and is indexed.
2. `maint/security/v10-documentation-status-closure.json` validates as JSON.
3. `maint/security/v10-claims-boundary.json` records `V10 Slice 3` and the closure signals.
4. `make v10-check` passes locally and in CI.
5. GitHub CI passes before merge.
