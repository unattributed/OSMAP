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

Every release candidate should have a corresponding SBOM or equivalent manifest.

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
