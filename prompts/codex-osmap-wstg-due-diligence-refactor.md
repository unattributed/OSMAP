# Codex Prompt, OSMAP WSTG Due-Diligence Refactor

You are operating as a full-access AI agent inside VSCodium on the local OSMAP repository.

Repository path:

```text
/home/foo/Workspace/OSMAP
```

Goal:

Make the OSMAP WSTG pack honest and defensible for due diligence. Do not claim complete OWASP WSTG testing unless every WSTG v4.2 scenario has an executed evidence reference or a documented not-applicable proof.

Inputs added by this bundle:

```text
docs/security/OSMAP_WSTG_DUE_DILIGENCE_REVIEW_2026_05_19.md
docs/security/OSMAP_WSTG_SCENARIO_MATRIX_V42.md
maint/wstg-testing-pack/wstg-scenario-matrix.v42.json
maint/wstg-testing-pack/wstg-scenario-matrix.v42.csv
```

Required work:

1. Read the current WSTG pack implementation:
   - `maint/wstg-testing-pack/run-wstg-pack.py`
   - `maint/wstg-testing-pack/wstg-asvs-mapping.json`
   - `maint/wstg-testing-pack/README.md`
   - `maint/security/test-osmap-wstg-testing-pack.sh`
   - `maint/live/osmap-wstg-release-summary.json`

2. Update documentation first:
   - Correct stale README wording that still says static rendering and attachment checks do not inject live mailbox content.
   - Clearly distinguish mapping coverage from runtime evidence coverage.
   - Label `maint/live/osmap-wstg-release-summary.json` as historical if it predates the current mapping.

3. Add validation of `maint/wstg-testing-pack/wstg-scenario-matrix.v42.json`:
   - Every scenario must have one of these final statuses:
     - `automated_dynamic`
     - `manual_required`
     - `not_applicable_with_proof`
     - `deferred_gap`
   - Release mode must fail if any scenario remains `requires_applicability_decision_and_evidence`.
   - Release mode must fail if any `not_applicable_with_proof` item lacks a repo file, live route inventory, configuration proof, or explicit evidence reference.

4. Do not remove the current OSMAP-specific tests. Keep them as release regression evidence.

5. Add or update tests under `maint/security/test-osmap-wstg-testing-pack.sh` so CI proves:
   - The matrix is valid JSON.
   - All official scenario IDs are unique.
   - All mapped WSTG IDs in `wstg-asvs-mapping.json` either exist in the scenario matrix or are explicitly documented as supplemental.
   - The matrix contains no unresolved scenario in release mode.
   - `COVERAGE.md` is not presented as runtime proof.

6. Run these local validations:

```bash
cd /home/foo/Workspace/OSMAP
python3 -m py_compile maint/wstg-testing-pack/run-wstg-pack.py
sh maint/security/test-osmap-wstg-testing-pack.sh
cargo test --locked
```

7. Do not run destructive tests. Do not mutate the remote checkout. If host-assisted evidence is needed, require `OSMAP_WSTG_EXPECTED_REF` and fail closed on mismatch.

8. Commit changes with this commit message:

```text
add wstg due diligence matrix gate
```

9. After committing, report:
   - files changed
   - test results
   - remaining WSTG scenario counts by status
   - next safest engineering slice
