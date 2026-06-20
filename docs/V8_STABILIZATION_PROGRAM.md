# V8 Stabilization Program

## Purpose

V8 exists because OSMAP has reached the point where regression risk is more important than feature expansion.

The V7 rendering regression close-out showed that an existing daily-driver behavior can fail in production when testing discipline weakens. The immediate rendering defect has been fixed and protected by fixtures, Rust tests, security gates, and CI enforcement. V8 turns that incident lesson into a broader stabilization program.

OSMAP remains an OpenBSD-native secure webmail project intended to replace Roundcube with a smaller trust boundary, a lower attack surface, stronger operational control, and evidence-backed security claims.

## Lessons learned from V7

The V7 close-out established several project lessons.

First, working behavior is not durable unless it is protected by repeatable tests. Message rendering appeared to be a solved daily-driver path, but a production-visible multipart rendering regression survived until V7 because test discipline had weakened after V2.

Second, security claims need executable evidence. Documentation and review are useful, but they are not sufficient when a behavior can regress silently.

Third, gates must exercise real behavior. Structural checks help preserve coverage names and documentation references, but the important gates must run Rust tests or operational validation that can fail when behavior regresses.

Fourth, feature work must not outrun the evidence model. OSMAP should not pursue Roundcube feature parity when doing so expands attack surface or weakens confidence in the existing security and daily-driver surface.

## Regression philosophy

V8 treats regression prevention as a first-class release goal.

A V8 test is valuable when it protects one of the following:

- a security boundary
- hostile-content containment
- authentication and session integrity
- safe mail rendering
- attachment safety
- mailbox daily-driver behavior
- operational robustness
- OpenBSD deployment suitability

A V8 test is not valuable merely because it increases coverage numbers. The program favors focused fixtures, targeted Rust tests, and explicit gates tied to real failure modes.

Regression coverage should be added in the smallest useful form. The goal is not broad feature expansion. The goal is to make already-supported behavior difficult to break unnoticed.

## Evidence-first methodology

Every V8 slice must produce evidence outside the repository.

Required evidence includes:

- operating environment
- operating system details
- Rust version
- Cargo version
- git state
- changed files
- git diff
- test output
- gate output
- final validation output
- commit hash
- evidence archive
- SHA256 digest

A slice is not complete until its evidence archive exists and the required validation commands have passed.

Assertions without evidence are not accepted for V8 close-out decisions.

## Stabilization scope

V8 stabilization covers five regression matrices plus final CI enforcement.

The planned matrices are:

1. mail workflow regression
2. attachment safety
3. mailbox operations
4. session integrity
5. resource exhaustion and robustness

The final release gate must aggregate these checks through `make v8-check`.

## Non-goals

V8 does not aim to add general end-user features.

V8 does not pursue Roundcube feature parity.

V8 does not broaden the trust boundary.

V8 does not accept test-only changes that weaken production security behavior.

V8 does not replace V5, V6, or V7 gates. It carries them forward and adds stabilization coverage on top.

V8 does not treat grep-only validation as sufficient for matrix close-out. Slice 0 may use a foundation gate while the matrix gates are not yet implemented, but later V8 matrix gates must execute real tests.

## Release criteria

V8 is complete only when the following are true:

- mail workflow regression coverage is implemented
- attachment safety coverage is implemented
- mailbox operations coverage is implemented
- session integrity coverage is implemented
- resource exhaustion and robustness coverage is implemented
- `make v8-check` executes every V8 matrix gate
- CI executes V8 coverage
- V7 protections remain enforced
- V8 protections are mandatory for release
- evidence archives and SHA256 digests exist for every slice

The required validation commands for every completed slice are:

```sh
cargo fmt --check
cargo test
cargo clippy --all-targets --all-features -- -D warnings
cargo audit
make v7-check
make v8-check
make security-check
```

Missing tools are failures, not skips.

## Evidence requirements

Each slice must write evidence outside the repository.

Recommended evidence root:

```sh
$HOME/osmap-v8-evidence
```

Each run should create a timestamped directory and a corresponding archive:

```sh
$HOME/osmap-v8-evidence/<slice-name>-<timestamp>/
$HOME/osmap-v8-evidence/<slice-name>-<timestamp>.tar.gz
$HOME/osmap-v8-evidence/<slice-name>-<timestamp>.tar.gz.sha256
```

The evidence archive must include the validation transcript and the final commit hash for the slice.

## CI expectations

The current CI enforcement path is the `security-check` workflow. That workflow checks out the repository, installs the Rust toolchain, and runs `make security-check`.

During Slice 0, `make v8-check` is introduced as a foundation target. It validates that the V8 stabilization framework exists and that the repository has an explicit V8 gate entrypoint.

During Slices 1 through 5, the V8 matrix gates should be added as executable shell gates under `maint/security/` and wired into `make v8-check`.

During Slice 6, CI should be updated so V8 gates are mandatory. The expected enforcement path is either:

- call `make v8-check` from `make security-check`, or
- add an explicit CI step in `.github/workflows/security-check.yml` that runs `make v8-check`

The Slice 6 implementation must ensure that CI fails on V8 regressions and that V7 protections remain enforced.
