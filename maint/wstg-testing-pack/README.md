# OSMAP WSTG Testing Pack

This pack performs safe, repeatable OWASP WSTG validation for the OSMAP browser interface at `https://mail.blackbagsecurity.com`, with ASVS 5.0.0 and the project Top 10 crosswalk used for control mapping.

It validates OSMAP only. It does not claim to validate the whole mail stack, all private control-plane applications, or complete ASVS compliance.

## Standards

The current implemented matrix is anchored to:

- OWASP Web Security Testing Guide v4.2
- OWASP Application Security Verification Standard 5.0.0
- OWASP Top 10 2025 project crosswalk

The Version 3 due-diligence track also requires a pinned latest-track WSTG inventory when the OWASP current development tree is used. Latest-track evidence must record the OWASP upstream commit hash, because OWASP latest content can change.

Identifier rules:

- WSTG v4.2 identifiers use `WSTG-v42-CAT-NN`.
- ASVS identifiers use `v5.0.0-C.S.R`.
- Project Top 10 identifiers use `A01:2025` through `A10:2025`.
- Latest-track WSTG identifiers must include source metadata that ties them to a captured upstream commit.

Canonical files:

- `wstg-asvs-mapping.json`, implemented test mapping
- `wstg-scenario-matrix.v42.csv`, v4.2 due-diligence matrix
- `wstg-scenario-matrix.v42.json`, v4.2 due-diligence matrix
- `wstg-scenario-matrix.latest.json`, latest-track matrix when generated
- `COVERAGE.md`, rendered coverage and gap table

Every release-required WSTG test must keep WSTG, ASVS, and Top 10 mappings where applicable. If a check cannot map cleanly to the active WSTG matrix, document it as a gap, not as compliance coverage.

## Version 3 Due-Diligence Rule

For Version 3, this pack is a living regression suite and a coverage-control system.

Every active WSTG item must have one disposition:

- `automated`
- `manual`
- `not_applicable`
- `covered_by_other_evidence`
- `deferred`
- `blocked`

A runner `skip` is not a release disposition. Release mode must fail when a required authenticated, TOTP-backed, host-assisted, or critical WSTG item is skipped.

The governing documents are:

- `docs/V3_WSTG_DUE_DILIGENCE_PLAN.md`
- `docs/V3_WSTG_COVERAGE_GATE.md`
- `docs/V3_SECURITY_GATES.md`

## Setup

```bash
cd /home/foo/Workspace/OSMAP/maint/wstg-testing-pack
cp .env.example .env
```

The default `.env.example` is safe and contains no secrets. Authenticated tests skip unless all of these are true:

- `OSMAP_ALLOW_AUTHENTICATED_TESTS=true`
- `OSMAP_TEST_EMAIL` is set
- `OSMAP_TEST_PASSWORD` is set
- `OSMAP_TOTP_SECRET` is set

Secrets are redacted from reports and evidence. Do not commit `.env`.

## Safe Limits

The runner is scoped to `OSMAP_BASE_URL` and uses bounded requests. It does not perform destructive testing, denial-of-service testing, credential stuffing, uncontrolled fuzzing, or broad internet scanning.

The brute-force throttle probe defaults to three invalid attempts with a delay between requests. Increase `OSMAP_THROTTLE_PROBE_ATTEMPTS` only for a controlled validation window.

Most host-assisted tests use `ssh $OSMAP_SSH_HOST` and read-only commands. Host-assisted checks are disabled unless `--include-host` or `OSMAP_ALLOW_HOST_ASSISTED_TESTS=true` is used. SSH-assisted host checks use `OSMAP_SSH_TIMEOUT_SECONDS`, defaulting to 300 seconds, so slower release hosts can finish bounded live validators without relaxing the browser request timeout.

Any test that sends mail, moves mail, deletes mail, mutates drafts, changes settings, or injects controlled messages must use dedicated validation accounts and controlled fixtures only.

## Running

Unauthenticated dynamic and static checks:

```bash
./run.sh --unauthenticated
```

Unauthenticated plus host-assisted checks:

```bash
./run.sh --unauthenticated --include-host
```

Authenticated checks, only when `.env` contains a dedicated validation account:

```bash
./run.sh --authenticated
```

Authenticated checks for a real account without storing the password or TOTP secret:

```bash
./run.sh --prompt-auth --auth-email pilot-primary@example.invalid
```

Release mode:

```bash
./run.sh --release --prompt-auth --auth-email pilot-primary@example.invalid
```

Release mode enables authenticated and host-assisted coverage, rejects selected test subsets, and exits nonzero when release-required tests are skipped, missing, warning, failing, or incomplete.

Run one mapped test:

```bash
./run.sh --test-id OSMAP-WSTG-CONF-002
```

## Outputs

Each run writes a timestamped directory under `OSMAP_OUTPUT_DIR` or `maint/wstg-testing-pack/output/`:

- `summary.json`, machine-readable results
- `report.md`, human-readable report
- `evidence/`, redacted request, response, static, and host evidence
- `logs/`, runner logs where applicable

Version 3 summaries must include or be extended to include:

- WSTG source version or branch
- WSTG source URL
- WSTG source commit when using latest
- active matrix file
- OSMAP git commit or tag
- test timestamp
- target hostname and base URL
- authenticated or unauthenticated mode
- test account labels without secrets
- result
- evidence path
- WSTG mapping
- ASVS mapping where applicable
- not-applicable reason where relevant
- manual evidence requirement where automation is not safe or not possible

## Statuses

- `pass`, expected secure behavior was observed
- `fail`, confirmed behavior violates the mapped expectation
- `warning`, evidence was useful but inconclusive under safe limits
- `skip`, test was intentionally not run, usually due to missing credentials
- `not_applicable`, the mapped area does not apply to current OSMAP scope

## Adding A Test

1. Add or update the item in the active WSTG matrix.
2. Add a new object to `wstg-asvs-mapping.json` when the test is implemented.
3. Use versioned WSTG and ASVS identifiers.
4. Map the check to one or more Top 10 categories where applicable.
5. Implement a deterministic runner method in `run-wstg-pack.py` or a documented helper.
6. Produce redacted evidence under the run directory.
7. Prefer `not_applicable`, `manual`, `blocked`, or `warning` over unsafe probing.
8. Run `python3 -m py_compile run-wstg-pack.py` and the relevant runner test.
9. Update `COVERAGE.md` and any affected V3 release-gate documentation.

## V3 Priority Backlog

The following WSTG areas must be completed in managed slices before Version 3 closeout:

1. Coverage inventory and source pinning
2. Authorization and account isolation
3. Session lifecycle and cookie security
4. IMAP, SMTP, and webmail-specific input validation
5. Weak cryptography and transport security
6. API-style route and state-transition testing
7. Business logic and workflow abuse
8. Client-side, browser storage, and UI security
9. Error handling and information disclosure
10. Release gate integration

## Limitations And False Positives

- Authenticated tests require a dedicated validation account and current TOTP secret, or `--prompt-auth` with a real account. Without one of those, they skip by design in developer mode.
- Skipped credential-gated checks are release failures when the check is required for Version 3.
- The throttle check is intentionally bounded and may return `warning` if the configured safe attempt count does not reach the production threshold.
- Static rendering and attachment checks verify source and documentation alignment. They do not inject live mailbox content unless authenticated, fixture-driven tests are explicitly enabled.
- TLS policy findings may reflect edge compatibility choices documented in the OSMAP Version 3 backlog.
- Not-applicable decisions must be rechecked when new routes, storage behavior, JavaScript, APIs, or browser workflows are added.

## Operator Note

This pack verifies the OSMAP web interface and its immediate nginx and host deployment posture. Mail transport controls such as Postfix, Dovecot, Rspamd, Suricata, SBOM cron, and broad PF operations remain covered by existing mail-stack and live-host validation tooling outside this pack unless a WSTG item maps directly to the OSMAP browser boundary.
