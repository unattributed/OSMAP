# Toolchain And Repository Baseline

## Purpose

This document records the WP0 implementation decision for the Phase 6 proof of
concept.

The goal of WP0 is not to freeze every future technical choice forever. The
goal is to choose a credible starting point that fits the project's documented
security posture, OpenBSD goals, and small-team maintenance model.

## Selected Toolchain

OSMAP's initial proof-of-concept implementation will use:

- Rust as the backend implementation language
- Cargo as the build and test entrypoint
- a repository-local `Makefile` for obvious operator and developer commands
- a dependency-minimal bootstrap with no third-party runtime crates yet

This choice is provisional but intentional.

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

The WP0 repository skeleton uses:

- the Rust standard library only

This keeps the initial trust surface very small while Phase 6 begins.

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

The current sandbox environment provides:

- `cargo build`
- `cargo check`
- `cargo test`

The current sandbox environment does not provide:

- `cargo fmt`
- `cargo clippy`

The `Makefile` reflects this honestly by running `cargo check` unconditionally
and treating formatting and Clippy as conditional tooling until those
components are installed in the developer environment or CI image.

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
