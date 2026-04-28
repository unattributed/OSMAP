# OSMAP WSTG Testing Pack

This pack performs safe, repeatable OWASP WSTG validation for the OSMAP browser
interface at `https://mail.blackbagsecurity.com`.

It validates OSMAP only. It does not claim to validate the whole mail stack,
all private control-plane applications, or complete ASVS compliance.

## Standards

- OWASP Web Security Testing Guide v4.2
- OWASP Application Security Verification Standard 5.0.0
- WSTG identifiers use `WSTG-v42-CAT-NN`
- ASVS identifiers use `v5.0.0-C.S.R`

The canonical mapping is `wstg-asvs-mapping.json`. The rendered coverage table
is `COVERAGE.md`.

## Setup

```bash
cd /home/foo/Workspace/OSMAP/maint/wstg-testing-pack
cp .env.example .env
```

The default `.env.example` is safe and contains no secrets. Authenticated tests
skip unless all of these are true:

- `OSMAP_ALLOW_AUTHENTICATED_TESTS=true`
- `OSMAP_TEST_EMAIL` is set
- `OSMAP_TEST_PASSWORD` is set
- `OSMAP_TOTP_SECRET` is set

Secrets are redacted from reports and evidence. Do not commit `.env`.

## Safe Limits

The runner is scoped to `OSMAP_BASE_URL` and uses bounded requests. It does not
perform destructive testing, denial of service testing, credential stuffing,
uncontrolled fuzzing, or broad internet scanning.

The brute-force throttle probe defaults to three invalid attempts with a delay
between requests. Increase `OSMAP_THROTTLE_PROBE_ATTEMPTS` only for a controlled
validation window.

Host-assisted tests use `ssh $OSMAP_SSH_HOST` and read-only commands. They are
disabled unless `--include-host` or `OSMAP_ALLOW_HOST_ASSISTED_TESTS=true` is
used.

## Running

Unauthenticated dynamic and static checks:

```bash
./run.sh --unauthenticated
```

Unauthenticated plus read-only host-assisted checks:

```bash
./run.sh --unauthenticated --include-host
```

Authenticated checks, only when `.env` contains a dedicated validation account:

```bash
./run.sh --authenticated
```

Authenticated checks for a real account without storing the password or TOTP
secret:

```bash
./run.sh --prompt-auth --auth-email duncan@blackbagsecurity.com
```

This prompts locally for the account password and for a fresh TOTP code whenever
the runner must create a new login session. The code has a short lifetime, so
wait for each prompt before generating or reading the current code. The password
and TOTP codes are redacted from evidence and are not written to `.env`,
reports, or shell history.

Run one mapped test:

```bash
./run.sh --test-id OSMAP-WSTG-CONF-002
```

## Outputs

Each run writes a timestamped directory under `OSMAP_OUTPUT_DIR` or
`maint/wstg-testing-pack/output/`:

- `summary.json`: machine-readable results
- `report.md`: human-readable report
- `evidence/`: redacted request, response, static, and host evidence
- `logs/`: reserved for runner logs

The runner exits nonzero only when a test has confirmed `fail`. Skipped
credential-gated tests do not fail the run.

## Statuses

- `pass`: expected secure behavior was observed
- `fail`: confirmed behavior violates the mapped expectation
- `warning`: evidence was useful but inconclusive under safe limits
- `skip`: test was intentionally not run, usually due to missing credentials
- `not_applicable`: the mapped area does not apply to current OSMAP scope

## Adding a Test

1. Add a new object to `wstg-asvs-mapping.json`.
2. Use WSTG v4.2 and ASVS 5.0.0 versioned identifiers.
3. Implement a deterministic runner method in `run-wstg-pack.py`.
4. Produce redacted evidence under the run directory.
5. Prefer skip or warning over unsafe probing.
6. Run `python3 -m py_compile run-wstg-pack.py` and the relevant runner test.

If a check cannot map cleanly to WSTG v4.2 or ASVS 5.0.0, document it as a gap
instead of presenting it as compliance coverage.

## Limitations And False Positives

- Authenticated tests require a dedicated validation account and current TOTP
  secret, or `--prompt-auth` with a real account. Without one of those, they
  skip by design.
- The throttle check is intentionally bounded and may return `warning` if the
  configured safe attempt count does not reach the production threshold.
- Static rendering and attachment checks verify source and documentation
  alignment. They do not inject live mailbox content unless authenticated,
  fixture-driven tests are explicitly added later.
- TLS policy findings may reflect edge compatibility choices documented in the
  OSMAP Version 3 backlog.

## Operator Note

This pack verifies the OSMAP web interface and its immediate nginx/host
deployment posture. Mail transport controls such as Postfix, Dovecot, Rspamd,
Suricata, SBOM cron, and broad PF operations remain covered by the existing
mail-stack and live-host validation tooling outside this pack.
