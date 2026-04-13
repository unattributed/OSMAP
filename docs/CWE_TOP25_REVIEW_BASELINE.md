# CWE Top 25 Review Baseline

## Purpose

This document records the current repository-grounded OSMAP review posture
against the current MITRE CWE Top 25 list.

It is not a claim that OSMAP is free of all weakness classes forever. It is a
repeatable review baseline that:

- identifies which Top 25 categories are materially relevant to the current
  Rust backend
- records the controls already present in the repository
- records the residual risks that still need active hardening
- defines the shared `security-check` workflow that future commits should pass

This document is the weakness-class half of the current Version 1 security
review pair. `OWASP_ASVS_BASELINE.md` is the control-and-verification half for
the shipped browser and helper surfaces.

## Review Basis

This baseline is grounded in:

- the current Rust implementation under `src/`
- the current test suite and Makefile entrypoints
- the current OpenBSD runtime and helper architecture
- the current MITRE 2025 CWE Top 25 list

The 2025 list includes weakness classes such as XSS, SQL injection, CSRF,
authorization failures, path traversal, command injection, unsafe file upload,
deserialization of untrusted data, exposure of sensitive information, and
resource-exhaustion weaknesses.

## How This Fits With The ASVS Baseline

This baseline answers "which high-value weakness classes remain relevant to the
current repo, and what concrete controls are already visible against them?"

`OWASP_ASVS_BASELINE.md` answers the adjacent question "which implemented
Version 1 controls and verification areas map cleanly to the current browser,
auth, session, mail, and helper surfaces?"

Taken together, the two documents are meant to be read as one small
security-review pair:

- `CWE_TOP25_REVIEW_BASELINE.md` keeps the repo honest about weakness classes
  and residual risk
- `OWASP_ASVS_BASELINE.md` keeps the repo honest about the implemented control
  posture and verification story

## Current Repository Assessment

### Strengths already visible in the code

- XSS-oriented browser output risk is materially reduced by server-side HTML
  escaping, a default-deny Content Security Policy, and a plain-text-first
  rendering model.
- CSRF protection is present on current state-changing browser routes, using
  per-session CSRF tokens and constant-time comparison.
- Path traversal risk is materially reduced by bounded mailbox-name,
  attachment-part, and state-root validation rather than browser-controlled
  filesystem path resolution.
- Command injection risk is materially reduced because the Rust backend does
  not invoke a shell; direct process execution is concentrated in reviewed,
  fixed-program command surfaces.
- Memory-safety exposure is materially reduced by Rust, with current `unsafe`
  use confined to the reviewed OpenBSD FFI boundary in `src/openbsd.rs`.
- Deserialization-of-untrusted-data risk is currently low because the repo does
  not use generic object deserialization frameworks for the browser or helper
  protocol.

### Residual risks still requiring active work

- `CWE-770` remains relevant because the HTTP runtime now uses bounded
  thread-per-connection handling with an explicit in-flight cap, but that is
  still only one layer of broader request-resource control rather than a full
  denial-of-service solution.
- `CWE-862`, `CWE-863`, `CWE-284`, and `CWE-639` remain relevant because the
  browser and helper surfaces are authorization-sensitive and need continuous
  regression review as features expand.
- `CWE-434` remains relevant because bounded upload support now exists and must
  keep its current filename, content-type, size, and browser-handling
  restrictions.
- `CWE-200` remains relevant because OSMAP handles message data, attachment
  metadata, session state, and operator logs.

## Current Rust-Specific Findings

As of April 2, 2026, the current repository review found:

- no shell-based command execution in the Rust backend
- no direct `Command::new` use outside the reviewed auth command-execution
  boundary in `src/auth.rs`
- no `unsafe` use outside the reviewed OpenBSD FFI boundary in
  `src/openbsd.rs`
- no generic serde-style deserialization layer in the Rust backend

The most important remaining security gap confirmed by the repository is still
broader auth abuse resistance and resource-throttling strategy beyond the
current dual-bucket browser-login throttle, not a newly discovered injection
or memory-safety defect.

## Security Check Workflow

The repository now includes a shared `make security-check` entrypoint plus
repo-owned `pre-commit` and `pre-push` hook paths.

The repository also carries a GitHub Actions `security-check` workflow that
mirrors the same gate on pushes and pull requests. GitHub default CodeQL setup
remains the authoritative CodeQL scanner for this repository while default
setup is enabled.

That workflow currently does all of the following:

- `cargo check`
- `cargo test`
- `cargo clippy --all-targets -- -D warnings` when `cargo-clippy` is installed
- `cargo fmt --check` when `rustfmt` is installed
- fail if new `unsafe` appears outside `src/openbsd.rs`
- fail if shell-based command execution appears in `src/`
- fail if new direct `Command::new` call sites appear outside `src/auth.rs`

Install the shared hook path with:

```sh
make install-hooks
```

That sets `core.hooksPath` to `.githooks` for the local checkout so the
repo-owned security gate runs automatically before commit and before push.

## GitHub Code Scanning Posture

OSMAP now separates two concerns clearly:

- repo-owned Rust quality and security gating runs through `make security-check`
  locally, through the repo-owned pre-commit and pre-push hooks, and through
  the GitHub Actions `security-check` workflow
- CodeQL alert generation remains the responsibility of GitHub default CodeQL
  setup while that repository setting is enabled

The repository also carries a manual `codeql-advanced` workflow template for a
future deliberate move to advanced CodeQL configuration. It must not be treated
as the active CodeQL path until GitHub default setup is intentionally disabled
in repository settings.

## What This Does Not Claim

This baseline does not claim:

- that OSMAP is production-ready
- that the current checks replace human review
- that the current checks prove absence of all CWE Top 25 classes
- that auth abuse resistance and resource-exhaustion risk are fully solved

It does claim that OSMAP now has a concrete, repeatable Rust-backend security
review gate that is aligned with the project’s actual risk profile instead of a
generic checklist. For the adjacent control-oriented browser and helper review
posture, read this together with `OWASP_ASVS_BASELINE.md`.
