# OSMAP WSTG Due-Diligence Review, Amended Against Current Repo

Date: 2026-05-19

Reviewed source: uploaded `OSMAP-main.zip`, extracted locally and inspected as the current committed repository snapshot.

## Executive conclusion

The current OSMAP WSTG pack is significantly stronger than the earlier runner-only snapshot. The earlier high-risk static-marker findings have been partly remediated in the current repo. The runner now includes live host-assisted evidence for MIME/HTML rendering, attachment behavior, and bulk folder actions, expanded reflected-input probes, body truncation tracking, remote Git ref matching instead of `git reset --hard`, and release-mode fail-closed behavior.

However, it is still not a complete OWASP WSTG due-diligence suite. The current pack has 27 OSMAP-specific tests mapped to 29 unique WSTG identifiers. The official WSTG v4.2 web-application testing table of contents used for this review lists 97 scenario entries in sections 4.1 through 4.12, excluding the 4.10.0 business-logic introduction. The current pack maps 28 of those scenario entries, leaving 69 scenario entries requiring an explicit applicability decision, evidence test, manual procedure, or not-applicable proof.

The correct public and release wording should be:

> OSMAP provides WSTG-v4.2-mapped release regression evidence for its browser-facing webmail surface. A full independent WSTG due-diligence assessment remains in progress and requires a scenario-by-scenario applicability matrix.

## What improved in the current committed repo

### 1. Static HTML, attachment, and bulk-action checks have been moved toward live evidence

Current runner observations:

- `run-wstg-pack.py` maps `OSMAP-WSTG-CLNT-002` to `test_html_rendering_live`.
- `run-wstg-pack.py` maps `OSMAP-WSTG-BUSL-001` to `test_attachment_live`.
- `run-wstg-pack.py` maps `OSMAP-WSTG-BUSL-004` to `test_bulk_folder_actions_live`.
- `mime_html_live_evidence()` checks the remote repo ref against `OSMAP_WSTG_EXPECTED_REF` or the local Git HEAD before running host evidence.
- `test-osmap-wstg-testing-pack.sh` validates that those tests are not mapped as static-only WSTG evidence.

This directly addresses the previous finding that release-required WSTG tests were passing on static marker grep alone.

### 2. The dangerous host-assisted reset was removed

The current runner no longer uses `git checkout main` or `git reset --hard origin/main` in the host-assisted paths I inspected. It now checks `git rev-parse HEAD` on the remote repo and fails on mismatch. The repo test also explicitly fails if `git reset --hard origin/main` appears in the runner.

### 3. HTTP body truncation is now recorded and used in absence assertions

`HttpEvidence` now has a `truncated` field, response reads check for an extra byte after `DEFAULT_BODY_LIMIT`, and evidence headers include `X-OSMAP-WSTG-Body-Truncated`. Path traversal and reflected-input checks fail when evidence is truncated before absence checks can be trusted.

### 4. Reflected input testing is better but still not broad enough

The current payload list includes raw script, image/event-handler, autofocus/onfocus, and `javascript:` payload classes. This is a meaningful improvement, but it still does not constitute full reflected, stored, DOM, HTML injection, HTTP parameter pollution, SQL/IMAP/command/SSRF, and request-smuggling coverage across all application entry points.

### 5. Release-mode behavior is stronger

The repo validation script confirms 27 mapped WSTG tests across all OWASP Top 10 2025 categories. It also validates syntax, manifest completeness, authenticated draft/source-attachment mapping, live-evidence markers, safe skips, and release-mode failure when authenticated coverage is skipped.

## Current repo-specific concerns

### High: The pack is still OSMAP-specific mapped evidence, not complete WSTG due diligence

The mapping covers 29 unique WSTG identifiers. The WSTG v4.2 web-application testing table used for this amended review contains 97 scenario entries. The current pack does not yet have an explicit applicability decision for every unmapped scenario.

Examples of scenario families that still need explicit treatment:

- INFO-01, INFO-04, INFO-06 through INFO-10 reconnaissance, entry-point mapping, and architecture mapping.
- CONF-03, CONF-04, CONF-08 through CONF-11 file extension, backup file, cross-domain policy, file permission, subdomain takeover, and cloud storage checks.
- IDNT-01 through IDNT-05 identity lifecycle coverage beyond login enumeration.
- ATHN-02, ATHN-04, ATHN-05, ATHN-07 through ATHN-09 authentication scenarios that may be not applicable but still need proof.
- ATHZ-02 and ATHZ-03 authorization bypass and privilege escalation.
- SESS-01, SESS-04, SESS-07 through SESS-09 session schema, exposed variables, timeout, puzzling, and hijacking.
- INPV-03 through INPV-19 broad input validation classes, especially HTTP parameter pollution, IMAP/SMTP injection, host-header injection, request splitting/smuggling, SSRF, and command/code injection.
- CRYP-01 through CRYP-04. Some TLS evidence exists, but the current mapping uses CONF and does not fully map cryptography WSTG scenarios.
- CLNT-01 through CLNT-13 beyond the currently mapped CORS, clickjacking, and HTML rendering pieces.
- APIT-01 GraphQL, probably not applicable, but it needs explicit proof.

### Medium: `COVERAGE.md` is still declared-mapping coverage, not runtime evidence coverage

The runtime `report.md` now has a proven OWASP Top 10 table. That is good. The generated `COVERAGE.md` still reports release-required tests from mapping metadata. Keep it, but label it clearly as a mapping crosswalk, not as an evidence report.

### Medium: README limitations are stale

The README still states that static rendering and attachment checks verify source and documentation alignment and do not inject live mailbox content unless tests are added later. That is now stale because the current runner has host-assisted MIME/HTML evidence and attachment evidence. Update the README so operators do not underestimate or misdescribe the current test behavior.

### Medium: The latest committed release evidence appears stale relative to the current mapping

`maint/live/osmap-wstg-release-summary.json` in the uploaded repo shows a generated time of 2026-05-15 and reports 26 passing tests. The current mapping has 27 tests, including `OSMAP-WSTG-BUSL-004`. Treat that JSON as historical evidence, not current release evidence, until a new full release run is committed.

### Medium: The release gate still does not require a WSTG scenario matrix

Release mode fails on mapped test failures and skipped coverage, which is correct. It does not yet fail because an official WSTG v4.2 scenario lacks an applicability decision. That is the next major due-diligence gate.

## Recommended amended next step

Add the included files:

- `docs/security/OSMAP_WSTG_DUE_DILIGENCE_REVIEW_2026_05_19.md`
- `docs/security/OSMAP_WSTG_SCENARIO_MATRIX_V42.md`
- `maint/wstg-testing-pack/wstg-scenario-matrix.v42.json`
- `maint/wstg-testing-pack/wstg-scenario-matrix.v42.csv`
- `prompts/codex-osmap-wstg-due-diligence-refactor.md`

Then have Codex implement the next real release-gate change:

1. Load `wstg-scenario-matrix.v42.json` in the WSTG pack validation script.
2. Fail CI when any official WSTG scenario has `requires_applicability_decision_and_evidence`.
3. Allow `not_applicable` only when backed by a repo path, route inventory, configuration proof, or live evidence reference.
4. Split `COVERAGE.md` into `MAPPING_COVERAGE.md` and evidence-driven runtime reports.
5. Regenerate live release evidence after the gate exists.

## Git commit comment

```text
add wstg due diligence matrix
```
