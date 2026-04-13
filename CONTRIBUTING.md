# Contributing to OSMAP

## Before You Start

OSMAP is not a general-purpose webmail feature factory. It is a bounded,
security-focused mail access project with an OpenBSD-first operational model.
Contributions are welcome, but they need to fit the project rather than pull it
toward generic web application sprawl.

Before proposing a change, read:

- [`README.md`](README.md)
- [`docs/ARCHITECTURE.md`](docs/ARCHITECTURE.md)
- [`docs/SECURITY_MODEL.md`](docs/SECURITY_MODEL.md)
- [`docs/SECURE_SDLC.md`](docs/SECURE_SDLC.md)
- [`docs/DECISION_LOG.md`](docs/DECISION_LOG.md)

## What Good Contributions Look Like

The most useful contributions usually do one or more of these:

- reduce security risk
- improve correctness under malformed or hostile input
- tighten trust boundaries
- simplify code or operational behavior
- improve OpenBSD portability or confinement posture
- add focused tests for real project risk
- correct stale or misleading documentation

## Changes That Need Extra Care

The following areas are security-sensitive and require unusually careful work:

- authentication and MFA
- session handling and CSRF
- HTTP parsing and routing
- message parsing, MIME handling, and attachment behavior
- helper execution boundaries
- OpenBSD `pledge(2)` and `unveil(2)` behavior
- dependency additions

If your change touches any of those, keep it small and explain the security
impact clearly.

## Scope and Design Expectations

Contributors should preserve these project rules:

- keep the dependency footprint small
- keep behavior bounded and reviewable
- prefer server-rendered, low-complexity browser behavior
- do not rebuild authoritative mail services already provided by the host stack
- do not add feature surface casually
- do not weaken OpenBSD-first deployment assumptions for convenience

If a proposed change has a non-obvious design or operational cost, open an
issue first before investing heavily in implementation.

## Development Workflow

1. Start from the current repository state, not from stale summaries.
2. Keep each change narrowly scoped.
3. Add or update tests when behavior changes.
4. Update all associated and applicable documentation in the same change stream
   when implementation, project status, operational guidance, or known
   limitations change.
5. Keep commit messages contextual and useful to sysadmins and collaborating
   developers.
6. Sign commits so the mainline history remains attributable and reviewable.
7. When working directly on `main`, validate locally, commit, and sync the
   resulting snapshot to `origin/main` instead of leaving completed work only in
   a local checkout.
8. Close out each completed change with the next best development step so the
   repository preserves momentum instead of ending at a bare status report.

## Validation

Use the repo entrypoints where available:

- `make check`
- `make test`
- `make lint`
- `make fmt-check`
- `make security-check`

If you cannot run one of them in your environment, say so clearly in the pull
request. Do not claim a check passed if it was not run.

GitHub Actions mirrors the Rust backend gate with the repo-owned
`security-check` workflow. That workflow is the authoritative CI job for the
Rust backend. GitHub default CodeQL setup remains the repository's
authoritative CodeQL scanner unless maintainers deliberately disable default
setup and switch to advanced CodeQL configuration.

The repository now declares its minimum supported Rust toolchain in
[`Cargo.toml`](Cargo.toml). If your local `rustc` is older than that minimum,
the repo-owned `security-check` script will skip the cargo-based phases
locally and still run the shell guards. In that case, use CI or a compatible
host such as `mail.blackbagsecurity.com` for the full Rust gate instead of
claiming a local pass you did not actually have.

To enable the repo-owned pre-commit hook path for this checkout, run:

- `make install-hooks`

For OpenBSD-facing work, maintainers may also validate changes on:

- a project-local QEMU lab under `maint/qemu/`
- `mail.blackbagsecurity.com`

## Documentation Expectations

Documentation is part of the work, not a cleanup step.

When your change affects behavior, update the relevant public documents. In
particular:

- keep status statements honest
- revise stale "not yet implemented" language when code now exists
- update all other associated docs that describe the same shipped boundary or
  operator workflow, not only the first document you touched
- update [`docs/DECISION_LOG.md`](docs/DECISION_LOG.md) for meaningful
  security, architecture, or governance decisions

## Security Reporting

Do not file public issues for suspected vulnerabilities, secrets exposure, or
other sensitive security problems.

Use [`SECURITY.md`](SECURITY.md) instead.

## Pull Request Checklist

Before opening a pull request, make sure:

- the change is within project scope
- the diff is small enough to review carefully
- tests or validation evidence are included
- docs are updated if needed
- no secrets or private operational data were added
- new dependencies, if any, are justified explicitly

## License

By contributing to OSMAP, you agree that your contributions are made under the
repository license.
