# Supply Chain Policy

## Purpose

This document defines the supply-chain posture for OSMAP so the project remains
auditable, maintainable, and credible in security-sensitive and OpenBSD-oriented
environments.

## Approved Dependency Sources

Dependencies should come from:

- official upstream release sources
- actively maintained ecosystems with clear provenance
- components that can be reviewed, packaged, and updated predictably

Dependencies should not be added casually from:

- abandoned projects
- opaque one-maintainer ecosystems with weak release hygiene
- convenience packages with poor provenance or unclear maintenance

## Dependency Selection Rules

New dependencies should be justified when they:

- touch authentication, session handling, parsing, or crypto
- substantially increase the build toolchain
- introduce large transitive dependency trees
- complicate OpenBSD packaging or long-term maintenance

Preference should be given to:

- smaller libraries over sprawling frameworks when viable
- stable interfaces over fashionable churn
- components that do not force Linux- or cloud-specific assumptions

## Verification Requirements

The project should maintain enough process to verify:

- where dependencies came from
- which version is in use
- why a dependency was accepted
- whether it introduces licensing, maintenance, or security concerns

Dependencies should not be treated as "free" just because they build.

## Current Enforcement Gate

The repository now includes a first-class Rust dependency gate:

- `deny.toml` defines the approved registry, git-source, duplicate-version, and
  license policy.
- `maint/security/osmap-supply-chain-check.sh` refreshes the RustSec advisory
  database with `git` where available, then runs `cargo audit --no-fetch` for
  vulnerable and yanked advisory checks.
- The same script runs `cargo deny` for duplicate dependency, source, and
  license policy checks, plus a `cargo tree -d --locked` duplicate-version
  backstop.
- `make supply-chain-check` runs only the dependency gate.
- `make security-check` runs the dependency gate after the normal Rust build,
  test, lint, and formatting phases.
- `make release-check` requires the pinned supply-chain tools, reruns the
  supply-chain gate, and generates deterministic dependency inventory evidence
  with `cargo tree --locked --all-features --color never`.
- The repo-owned GitHub Actions `security-check` workflow bootstraps the
  pinned `cargo-audit` and `cargo-deny` versions before running the shared
  security gate.

The current pinned tool versions are recorded in
`maint/security/osmap-supply-chain-check.sh`. Maintainers should update those
pins deliberately when the repo's Rust floor changes or when the advisory
ecosystem requires a newer parser.

The script refreshes the advisory database with `git` before calling
`cargo-audit` because that path is simpler to inspect and proved more portable
on the OpenBSD target host than relying on cargo-audit's internal fetch path.

The gate fails on:

- RustSec vulnerable or yanked dependencies
- unexpected duplicate dependency versions
- wildcard dependency requirements
- dependencies from unapproved registries or git sources
- dependency licenses outside the reviewed allowlist

No project exception is currently recorded for a vulnerable advisory,
unapproved source, duplicate dependency version, or unapproved license.

## Risk-Based Dependency Admission

OSMAP does not use an arbitrary dependency-count or SBOM-size ceiling. A small
count can still hide a high-risk parser, cryptographic, native, or heavily
transitive dependency, while a larger count can be justified when the total
trusted-computing-base effect is understood and bounded.

Every direct Cargo dependency, including development, build, and target-specific
dependencies, must have a matching entry in
`maint/security/v15-dependency-admission.json`. The admission record is
machine-checked against `Cargo.toml` and `Cargo.lock` and must include:

- purpose and trust-boundary justification
- maintainer and source provenance
- licence compatibility
- maintenance status
- OpenBSD compatibility
- unsafe-code assessment
- transitive dependency inventory
- vulnerability review
- selected-feature minimisation
- default-feature review
- replacement and removal analysis
- SBOM effect
- locally maintained code removed
- total trusted-computing-base effect

The record binds the exact manifest and lockfile digests. A dependency addition,
removal, version change, source change, scope change, optionality change, or
feature change therefore fails closed until the admission record is reviewed
and refreshed.

Existing dependencies are recorded as an accepted baseline without claiming an
independent source audit that has not been performed. New or changed
dependencies require a new risk decision rather than inheriting the baseline
decision.

The executable controls are:

- `maint/security/osmap-v15-dependency-admission-gate.py`
- `maint/security/test-osmap-v15-dependency-admission-gate.py`
- the `risk-based direct dependency admission` phase of
  `maint/security/osmap-supply-chain-check.sh`

## Update Policy

Dependency updates should be:

- deliberate
- reviewable
- tested for compatibility impact
- prioritized when they address meaningful security or maintenance risk

## SBOM Expectations

Releases should eventually produce a software bill of materials that identifies:

- direct dependencies
- important transitive dependencies
- version information
- build-relevant toolchain components

Every release candidate must have a corresponding SBOM or equivalent manifest.
The current accepted release evidence is the deterministic dependency inventory
written by `make release-check` to
`maint/live/osmap-v3-dependency-inventory.txt`. A future SBOM tool may replace
or augment this inventory only when the tool version is pinned and documented.

## License Considerations

The project should prefer dependencies with licensing that is:

- compatible with redistribution
- understandable to operators and downstream packagers
- unlikely to create adoption friction in conservative environments

## Risk Evaluation Process

Each new dependency should be evaluated against:

- security relevance
- maintenance quality
- transitive dependency growth
- licensing implications
- OpenBSD packaging implications
- whether the dependency adds complexity disproportionate to its value

## Ports-Friendly Packaging Posture

If future OpenBSD ports-tree adoption is a goal, the project should avoid common
reasons maintainers reject software:

- excessive dependency sprawl
- giant vendored trees with weak provenance
- fragile builds that require constant internet access
- Linux-specific packaging assumptions
- runtime dependency on heavyweight services that add little clear value

If frontend tooling is necessary, it should be kept as small and deterministic
as possible.
