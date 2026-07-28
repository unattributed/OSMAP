# Toolchain And Repository Baseline

## Purpose

This document records the WP0 implementation decision for the Phase 6 proof of
concept.

The goal of WP0 is not to freeze every future technical choice forever. The
goal is to choose a credible starting point that fits the project's documented
security posture, OpenBSD goals, and small-team maintenance model.

## Selected Toolchain

OSMAP's implementation uses:

- Rust as the backend implementation language
- Cargo as the build and test entrypoint
- a repository-local `Makefile` for obvious operator and developer commands
- a dependency-minimal runtime with a reviewed Cargo dependency set

This choice remains intentional and is re-evaluated through the triggers below.

## Why Rust

Rust is being chosen for the WP0 baseline because it offers:

- memory safety for security-sensitive service code
- explicit error handling and type boundaries
- a strong fit for small, reviewable backend components
- a realistic path toward later OpenBSD confinement work if the runtime remains
  simple

This does not mean "Rust at any cost." The project already records that
OpenBSD portability and maintainer credibility outrank blind attachment to a
toolchain.

## Why Not A Large Framework Yet

The repository does not currently adopt a web framework, template system, ORM,
or async runtime as part of WP0.

That is deliberate.

At this stage, the project needs:

- a compilable repository
- a testable configuration path
- a clear place to add later slices
- no uncontrolled dependency growth

Framework selection should happen only when the login, mailbox, and send-path
requirements force a concrete need.

## Current Dependency Posture

The current direct runtime dependency set is:

- `ammonia` for allowlist HTML sanitization
- `getrandom` for security-sensitive random values
- `hmac`, `sha1`, and `sha2` for TOTP, request grants, identifiers, and
  integrity-oriented derivations
- `libc` for the reviewed OpenBSD and Unix syscall boundary

The repository remains framework-free and does not use an ORM, browser
JavaScript framework, or async runtime. `Cargo.lock`, `cargo audit`, and
`cargo deny` keep the transitive set reviewable.

## Repository Layout

The repository baseline now includes:

- `Cargo.toml` for package metadata
- `src/main.rs` for the executable entrypoint
- `src/lib.rs` for shared library modules
- `src/config.rs` for conservative environment-based configuration loading
- `src/error.rs` for small handwritten bootstrap errors
- `src/bootstrap.rs` for startup validation and operator-readable bootstrap
  reporting
- `config/osmap.env.example` for non-secret configuration examples
- `Makefile` for build, test, lint, and run entrypoints

## Operational Defaults

The bootstrap defaults are intentionally conservative:

- loopback listener by default
- explicit state directory
- explicit log level
- no secret values committed to the repo

These defaults are suitable for local development and controlled staging, not
for public exposure.

## Tooling Notes

The reviewed development and release toolchain is:

- Rust and Cargo `1.94.1`
- rustfmt `1.8.0`
- Clippy `0.1.94`
- cargo-audit `0.22.1`
- cargo-deny `0.18.3`

`rust-toolchain.toml` pins the reviewed collaborator toolchain and components.
The Debian-family installation and verification procedure is maintained in
[`DEBIAN_DEVELOPMENT_BOOTSTRAP.md`](DEBIAN_DEVELOPMENT_BOOTSTRAP.md) and the
repo-owned scripts under `maint/development/`.

`Cargo.toml` declares Rust `1.86` as the minimum supported language floor. The
developer gate runs build checks, tests, strict Clippy, formatting, supply-chain
validation, security invariants, and the V8 regression matrices. Release mode
adds pinned toolchain and live-evidence requirements.

## Re-Evaluation Triggers

The toolchain decision should be revisited if any of the following occur:

- OpenBSD packaging or portability costs become disproportionate
- confinement work reveals runtime incompatibilities that materially harm the
  design
- the dependency graph grows faster than the security value it provides
- the implementation can no longer be maintained confidently by a small team

## WP0 Outcome

WP0 is satisfied when the project has:

- a recorded toolchain decision
- a clear source layout
- conservative local build and test entrypoints
- a baseline executable that can be compiled and exercised

That baseline now exists in the repository.
