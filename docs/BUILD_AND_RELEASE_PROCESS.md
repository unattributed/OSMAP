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
   release WSTG credential and TOTP evidence, V2 carry-forward evidence,
   host-readiness evidence, TLS edge evidence, TLS standard evidence,
   resource-timeout evidence, current redacted V3 live MIME and HTML proof
   evidence, and a sanitized evidence archive
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
forward-secret AEAD cipher, no weak legacy cipher is accepted, and certificate
plus hostname validation remain enabled.
Resource and timeout evidence is identified by
`OSMAP_RELEASE_RESOURCE_TIMEOUT_EVIDENCE`, which defaults to
`maint/live/osmap-v3-resource-timeout-evidence-2026-05-02.txt` and
`maint/live/latest-host-v3-resource-controls-report.txt`.
The V3 MIME and HTML live proof report is identified by
`OSMAP_RELEASE_V3_MIME_HTML_PROOF_REPORT`, which defaults to
`maint/live/latest-host-v3-mime-html-proof-report.txt`. Release validation also
checks that `maint/live/osmap-live-validate-v3-mime-html-proof.ksh` exists, is
executable, passes `sh -n`, and remains documented.

The normal GitHub `security-check` workflow remains a developer and CI signal.
It must not be described as full V3 release validation unless the run also has
the required host, credential, TOTP, WSTG, and sanitized evidence inputs.

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
