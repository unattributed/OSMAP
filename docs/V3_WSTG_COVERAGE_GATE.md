# Version 3 WSTG Coverage Gate

## Purpose

This document defines the release gate for Version 3 WSTG due diligence.

The gate exists to prevent OSMAP Version 3 from closing with undocumented WSTG gaps, skipped authenticated coverage, missing TOTP evidence, or reports that claim success without reviewable artifacts.

## Gate Position

This gate is part of the Version 3 release evidence set. It complements:

- `docs/V3_DEFINITION.md`
- `docs/V3_ACCEPTANCE_CRITERIA.md`
- `docs/V3_SECURITY_GATES.md`
- `docs/V3_WSTG_DUE_DILIGENCE_PLAN.md`
- `maint/wstg-testing-pack/README.md`
- `maint/wstg-testing-pack/COVERAGE.md`

## Required Inputs

A V3 release candidate must provide:

| Input | Required content |
| --- | --- |
| WSTG source metadata | Version or branch, upstream URL, capture date, and commit hash when using OWASP latest. |
| Active WSTG matrix | Machine-readable matrix with one disposition per WSTG item. |
| OSMAP commit | Git commit or tag being assessed. |
| Target | Hostname and base URL used for live evidence. |
| Auth mode | Unauthenticated, authenticated, prompt-auth, dedicated account, or host-assisted. |
| Evidence directory | Timestamped output directory with summary, report, evidence, and logs where applicable. |
| Secret hygiene proof | Confirmation that passwords, TOTP seeds, TOTP codes, session cookies, private keys, tokens, and private message contents were not committed. |

## Release-Failing Conditions

Release mode must fail when any of the following are true:

- WSTG source metadata is missing.
- The active WSTG matrix is missing.
- The active WSTG matrix lacks a disposition for any item.
- Any critical WSTG slice is incomplete.
- Any required authenticated WSTG test is skipped.
- Any required TOTP evidence is missing.
- Any not-applicable item lacks a written reason.
- Any covered-by-other-evidence item lacks a named artifact.
- Any deferred high-priority or critical item lacks a decision-log entry.
- Any report claims pass without an evidence artifact path.
- Any test leaks plaintext passwords, reusable TOTP seeds, active session cookies, private mailbox contents, provider tokens, private keys, or host secrets.
- Any live test was run against an unapproved target.
- Any destructive test touched real user mail outside a controlled validation window.

## Slice Gate Table

| Slice | Area | Priority | Release rule |
| --- | --- | --- | --- |
| 1 | Coverage inventory and source pinning | Critical | Must pass. |
| 2 | Authorization and account isolation | Critical | Must pass. |
| 3 | Session lifecycle and cookie security | Critical | Must pass. |
| 4 | IMAP, SMTP, and webmail-specific input validation | Critical | Must pass. |
| 5 | Weak cryptography and transport security | Critical | Must pass. |
| 6 | API-style route and state-transition testing | High | Must pass or be not applicable with evidence. |
| 7 | Business logic and workflow abuse | High | Must pass. |
| 8 | Client-side, browser storage, and UI security | High | Must pass or be not applicable with evidence. |
| 9 | Error handling and information disclosure | High | Must pass. |
| 10 | Release gate integration | Critical | Must pass. |

## Evidence Schema

Each automated or manual evidence item must identify:

- WSTG item ID
- OSMAP test ID
- OSMAP git commit or tag
- target base URL
- timestamp
- runner mode
- authentication mode
- whether TOTP was required
- whether TOTP was exercised
- result: pass, fail, warning, skip, or not applicable
- evidence artifact path
- redaction status
- limitation or not-applicable reason, when relevant

## Authenticated Evidence Rule

Authenticated security tests are incomplete unless the evidence proves that the real credential and TOTP-dependent path was exercised.

Approved methods:

- dedicated validation account using local uncommitted `.env` secrets
- human-prompted run using `--prompt-auth --auth-email`

The evidence must prove:

- login form access
- credential submission
- TOTP challenge and response path where required
- session issuance
- protected route access
- logout or revocation path where applicable
- session invalidation where applicable

The evidence must not include reusable secrets.

## Not-Applicable Rule

A not-applicable WSTG item is acceptable only when the report states:

- why the WSTG item does not apply to OSMAP
- which source, route inventory, configuration, or runtime evidence supports that conclusion
- whether the item must be reconsidered if a future feature adds the missing surface

Examples:

- GraphQL may be not applicable only if source and route inventory show no GraphQL endpoint.
- WebSocket may be not applicable only if source and edge configuration show no WebSocket route.
- Payment functionality may be not applicable because OSMAP has no payment workflow.

## Deferral Rule

A deferral is not a pass.

A high-priority or critical WSTG item may be deferred only with:

- decision-log entry
- owner
- reason
- risk statement
- expiry date or trigger
- compensating control if applicable
- command or evidence that will close the deferral

Critical deferrals block Version 3 close unless the Version 3 definition is changed.

## Developer Mode Versus Release Mode

Developer mode may skip credential-gated tests when credentials or TOTP are not available, but it must report the skip clearly.

Release mode must fail on skipped required checks.

Expected developer command:

```bash
cd /home/foo/Workspace/OSMAP/maint/wstg-testing-pack
./run.sh --unauthenticated
```

Expected authenticated release command shape:

```bash
cd /home/foo/Workspace/OSMAP/maint/wstg-testing-pack
./run.sh --release --prompt-auth --auth-email pilot-primary@example.invalid
```

Expected project release gate:

```bash
cd /home/foo/Workspace/OSMAP
make release-check
```

## Secret Hygiene Rule

Evidence must be sanitized before it is committed.

Do not commit:

- `.env`
- passwords
- reusable TOTP seeds
- current TOTP codes
- active session cookies
- private keys
- provider tokens
- host secrets
- private message bodies
- private attachment contents
- unredacted personal mailbox data

## Closeout Statement

V3 WSTG due diligence is complete only when the active matrix shows no unresolved critical items, no undocumented high-priority gaps, no skipped required authenticated tests, and no missing evidence artifacts.
