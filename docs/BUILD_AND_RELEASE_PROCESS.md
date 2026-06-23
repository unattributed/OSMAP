# Build And Release Process

## Purpose

This document defines the expected build and release discipline for OSMAP. It is
written early so implementation does not drift into ad hoc release habits.

## Build Steps

The build process should:

- start from versioned source
- resolve only approved dependencies
- produce deterministic or at least repeatable artifacts where practical
- fail clearly when required tooling, tests, or generated assets are missing

The build should avoid hidden network-time side effects wherever possible.

## Artifact Generation

Release artifacts should eventually include:

- application binaries or packages as appropriate to the chosen implementation
- static frontend assets if the architecture requires them
- configuration templates or examples needed for deployment
- an SBOM or equivalent manifest
- release notes or operator-facing change information

## Signing Requirements

Release artifacts should be signed before being treated as trusted for
deployment.

Expectations:

- use a repeatable signing process
- make signature verification feasible for operators
- do not treat unsigned production artifacts as acceptable by default

## Versioning Scheme

The project should use a versioning approach that:

- is understandable to operators
- supports rollback and comparison
- distinguishes pre-release work from stable release candidates

The exact scheme can be finalized later, but it should remain conservative and
predictable.

## Deployment Flow

The release flow should eventually look like:

1. Source and dependency review
2. Developer validation with `make security-check`, including the supply-chain
   subgate from `make supply-chain-check`
3. Matching CI confirmation from the repo-owned `security-check` workflow
4. Strict release validation with `make release-check` on a host or operator
   workstation that has the pinned Rust toolchain, pinned supply-chain tools,
   release WSTG human-prompt credential and TOTP evidence, V2 carry-forward evidence,
   host-readiness evidence, TLS edge evidence, TLS standard evidence,
   resource-timeout evidence, current redacted V3 live MIME and HTML proof
   evidence, current redacted V3 pilot rehearsal evidence, and a sanitized
   evidence archive
5. Build
6. Static analysis and required tests
7. Dependency inventory or SBOM generation
8. Artifact signing
9. Staged deployment validation
10. Controlled production rollout

The current strict command is:

```bash
make release-check
```

The historical `release-check` remains responsible for the frozen V4 release
tuple and its V3 carry-forward inputs. V6 adds a separate, stricter closeout
command:

```bash
make v6-check
```

`v6-check` first validates the V5 boundary-hardening carry-forward and then
requires the complete V6 definition, traces, sanitized production-readiness,
no-Roundcube-fallback rehearsal, observability, resource-resilience, and
closeout evidence. It is expected to fail until live evidence and closeout are
complete. Developer `security-check` runs regression tests for the V5 and V6
gate logic without treating fixture reports as release evidence.

After `osmap-v6-retirement-readiness-gate.sh` passes, create the sanitized V6
archive and checksum with:

```bash
sh maint/security/osmap-v6-evidence-archive.sh
```

The archiver reruns the V6 gate, includes only the documented public-safe
closeout inputs and sanitized reports, rejects likely secret or content
markers, and writes `maint/live/osmap-v6-closeout-evidence.tar.gz` plus its
`.sha256` file.

It writes:

- `maint/live/osmap-v3-dependency-inventory.txt`
- `maint/live/osmap-v3-release-evidence-summary.json`
- `maint/live/osmap-v3-release-evidence-summary.md`
- `maint/live/osmap-v3-release-evidence.tar.gz`

It also requires the TLS CBC cleanup evidence identified by
`OSMAP_RELEASE_TLS_EDGE_EVIDENCE`, which defaults to
`maint/live/osmap-v3-tls-cbc-cleanup-evidence-2026-05-02.txt`.
It requires project-wide TLS standard evidence identified by
`OSMAP_RELEASE_TLS_STANDARD_EVIDENCE`, which defaults to
`maint/live/latest-host-tls-standard-report.json`. That report is produced by
`python3 maint/security/osmap-live-tls-standard-validate.py --report maint/live/latest-host-tls-standard-report.json`
and must prove the standard in `TLS_STANDARD.md`: weak protocol versions fail,
TLS 1.2 and TLS 1.3 negotiate correctly, TLS 1.2 uses only a strong
forward-secret AEAD cipher, forced weak TLS 1.2 cipher probes are rejected,
and certificate plus hostname validation remain enabled.
Resource and timeout evidence is identified by
`OSMAP_RELEASE_RESOURCE_TIMEOUT_EVIDENCE`, which defaults to
`maint/live/osmap-v3-resource-timeout-evidence-2026-05-02.txt` and
`maint/live/latest-host-v3-resource-controls-report.txt`.
Helper-boundary evidence is identified by
`OSMAP_RELEASE_HELPER_BOUNDARY_EVIDENCE`, which defaults to
`maint/live/latest-host-helper-boundary-report.txt` plus the repo-owned
`maint/live/osmap-live-validate-helper-peer-auth.ksh` validator. This evidence
must prove more than service liveness: unauthorized peer rejection, helper
socket ownership and mode, malformed request rejection, missing or invalid
grant rejection, and the active confinement posture.
The V3 MIME and HTML live proof report is identified by
`OSMAP_RELEASE_V3_MIME_HTML_PROOF_REPORT`, which defaults to
`maint/live/latest-host-v3-mime-html-proof-report.txt`. Release validation also
checks that `maint/live/osmap-live-validate-v3-mime-html-proof.ksh` exists, is
executable, passes `sh -n`, and remains documented.
The V3 pilot rehearsal evidence is identified by
`OSMAP_RELEASE_V3_PILOT_REHEARSAL_EVIDENCE`, which defaults to
`maint/live/latest-host-v3-pilot-rehearsal-report.txt` and
`docs/PILOT_WORKFLOW_INVENTORY.md`. The report must be sanitized and must prove
the assessed commit closed the selected cohort's daily-driver workflows without
Roundcube fallback for those workflows.
After the actual selected-cohort rehearsal is complete, operators can write the
sanitized report with `maint/live/osmap-live-record-v3-pilot-rehearsal.ksh`.
The helper requires explicit `passed` confirmations for each required workflow
and refuses to write the report when any confirmation is missing.

The normal GitHub `security-check` workflow remains a developer and CI signal.
It must not be described as full V3 release validation unless the run also has
the required host, human-prompt credential, TOTP, WSTG, pilot rehearsal, and
sanitized evidence inputs.

## V9 Production Convergence

V9 is a production convergence and operational closure milestone. It is not a
new-feature sprint and is not a release tag by itself.

The V9 Slice 1 intake run on 2026-06-22 captured the following convergence
state:

- local `main`: `49c9f230d7865f01deadbc6a5a0f6e876c63e89b`
- remote `origin/main`: `49c9f230d7865f01deadbc6a5a0f6e876c63e89b`
- production checkout `/home/foo/OSMAP`: `49c9f230d7865f01deadbc6a5a0f6e876c63e89b`
- live binary `/usr/local/bin/osmap`: `411c976cccb0687f1a6e840470584fd8921eb5469e68905e457cf3edfe0cdea3`
- PR #19 deployment evidence archive: `osmap-forward-body-binary-deploy-20260622-133538Z.tar.gz`
- PR #19 deployment evidence SHA256: `21a2d3b97808fe6bc971974ef46a42d27216f31f04cefe7cf4894c1f667a7800`
- V9 Slice 1 intake evidence archive: `osmap-v9-slice-1-intake-20260622-142413Z.tar.gz`
- V9 Slice 1 intake evidence SHA256: `5de376e832ae79f8c29afd1e3b0243f8ac09a04d4bb0c71a7a771fd65403e331`

This proves source and production identity convergence for the assessed
snapshot. It does not prove release-candidate readiness.

A V9 release-candidate decision still requires at least:

- bounded production hold-period proof against the deployed binary;
- V4 hostile-content carry-forward refresh on current `main`;
- explicit V7 production availability closeout using real-login evidence;
- explicit V6 selected-cohort/no-Roundcube closeout decision;
- a final release gate that records unresolved limitations and rollback.

Source sync must not be described as deployment. A production deployment claim
requires source identity, rebuilt binary identity, installed live binary hash,
service restart or continuity evidence, service health, functional operation,
selected logs, rollback reference, archive, and checksum.

## Rollback Strategy

Every release process should assume rollback may be necessary.

Rollback expectations:

- previous known-good artifacts remain identifiable
- deployment steps are reversible where practical
- release notes describe any data or configuration considerations
- operators are not forced to improvise rollback during an incident

## OpenBSD-Friendly Release Posture

If the project aims for OpenBSD credibility, the build and release process
should remain:

- simple enough to understand
- hostile to unnecessary dependency growth
- compatible with packaging and redistribution expectations
- free of Linux-first release assumptions
