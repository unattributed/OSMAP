# Debian-Family Development Environment Bootstrap

## Purpose

This document defines the reviewed workstation bootstrap for collaborating on
OSMAP from a Debian-family Linux distribution.

The procedure targets Debian 13 and compatible Debian-family
distributions. Current acceptance evidence verifies the complete procedure on:

- Parrot Security 7.3 (`echo`), the Debian-based security distribution from
  Parrot Security

A plain Debian collaborator must run the repository verifier and applicable
local gates before claiming that workstation as accepted. The documentation
does not treat shared package management as proof of an unevidenced host.

The workstation is a development and local-CI environment. It is not intended
to duplicate the OpenBSD production host or every command in the OpenBSD base
system.

## Platform Responsibilities

The development workstation provides:

- source control and signed-commit preparation
- the reviewed Rust toolchain
- local builds, tests, formatting, and strict Clippy
- Cargo dependency auditing and policy validation
- Python for repository-owned assurance helpers
- GPGME development headers for OpenPGP-related compilation and checks
- ShellCheck and GNU userland tools used by local validation
- SSH access for separately authorised OpenBSD validation

The OpenBSD host provides authoritative validation for:

- OpenBSD `/bin/ksh` scripts
- `doas`, `signify`, `sha256`, `rcctl`, `pkg_add`, and other native tooling
- `pledge(2)` and `unveil(2)` behaviour
- OpenBSD service integration
- host mail-stack integration
- sanitised live release evidence

Functional capability is the objective. Linux and OpenBSD package names and
commands are naturally different and must not be forced into literal parity.

## Security and Dependency Constraints

The bootstrap preserves OSMAP's existing security posture:

- use signed APT repositories rather than unverified package downloads
- do not pipe network downloads directly into a shell
- do not add Node.js, npm, frontend frameworks, external CDNs, or runtime
  JavaScript
- keep Cargo assurance tools pinned
- do not run `apt autoremove` as part of project bootstrap
- do not copy secrets, private keys, production configuration, or mail data
  into the repository
- keep OpenBSD-specific validation authoritative on OpenBSD

## Reviewed Tool Versions

The reviewed development and release toolchain is:

| Tool | Required version |
|---|---:|
| Rust | 1.94.1 |
| Cargo | 1.94.1 |
| Clippy | 0.1.94 |
| rustfmt | 1.8.0 |
| cargo-audit | 0.22.1 |
| cargo-deny | 0.18.3 |

`Cargo.toml` retains Rust `1.86` as the minimum supported language floor.
`rust-toolchain.toml` pins the reviewed collaborator and release toolchain.
These are different controls and should not be conflated.

## Fresh Checkout

Clone the repository using the collaborator's configured Git transport:

```sh
mkdir -p "$HOME/Workspace"
cd "$HOME/Workspace"

git clone git@github.com:unattributed/OSMAP.git
cd OSMAP
```

HTTPS is also supported when that is the collaborator's intended Git
authentication method.

## Automated Bootstrap

Run the bootstrap as a normal user. It uses `sudo` only for APT package
operations and executes all Rust, Cargo, virtual-environment, and Git
configuration as the collaborator account.

```sh
cd "$HOME/Workspace/OSMAP"

bash maint/development/bootstrap-debian.sh
```

Do not source the script and do not run it as root.

The script:

1. verifies the operating-system family;
2. installs the reviewed native build and assurance prerequisites;
3. installs the signed distribution `rustup` package when needed;
4. permits replacement only of conflicting distribution Rust packages;
5. installs Rust 1.94.1 with Clippy and rustfmt;
6. installs pinned `cargo-audit` and `cargo-deny`;
7. creates `.venv`;
8. enables `.githooks`;
9. runs the read-only environment verifier.

The bootstrap may replace Debian-distributed `rustc`, `cargo`, and associated
standard-library packages with the distribution's `rustup` package. It fails
closed if APT proposes unrelated removals.

## Manual Verification

The environment verifier performs no package installation:

```sh
cd "$HOME/Workspace/OSMAP"

bash maint/development/verify-debian.sh
```

The same verifier is available through Make:

```sh
make verify-debian
```

A PASS confirms the reviewed tool versions, GPGME development metadata,
repository Python virtual environment, executable Git hooks, and locked Cargo
metadata.

## Local Validation

Start with the developer gate:

```sh
make security-check
```

For a broader local acceptance run:

```sh
make supply-chain-check
make acceptance-check
make v14-check
```

The strict release gate also requires current live and sanitised evidence and
must not be claimed from local source checks alone:

```sh
OSMAP_SECURITY_PROFILE=release make release-check
```

## Git Hooks and Signed Commits

The bootstrap enables the repository-owned hooks:

```sh
make install-hooks
```

Collaborators must configure their own signing identity and verify it before
creating project commits:

```sh
git config --get user.name
git config --get user.email
git config --get user.signingkey
git config --get commit.gpgsign
```

Do not commit private keys or export them into the repository.

## OpenBSD Validation

OpenBSD validation is separate from workstation bootstrap. An authorised
maintainer may use the project QEMU lab or an explicitly approved OpenBSD host.

The Debian-family bootstrap does not install or emulate the complete OpenBSD
base system. In particular, a Linux workstation is not deficient merely
because it uses:

- `sudo` instead of `doas`
- `sha256sum` instead of `sha256`
- GNU or Linux build tools instead of OpenBSD base utilities

OpenBSD-specific scripts must still be checked with native OpenBSD `/bin/ksh`
before release acceptance.

## Updating the Baseline

Changes to the required package set or pinned versions must update together:

- this document
- `rust-toolchain.toml`
- `docs/TOOLCHAIN_AND_REPOSITORY_BASELINE.md`
- `maint/development/bootstrap-debian.sh`
- `maint/development/verify-debian.sh`
- applicable security and release gates

Dependency additions require explicit security and maintenance justification.
