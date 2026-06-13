# V4 Audit Remediation Report

## Audit Date

2026-06-13 UTC

## Repository State

| Item | Value |
| --- | --- |
| Repository | `/home/foo/Workspace/OSMAP` |
| Branch | `main` |
| Commit before remediation | `24a44f26299f1df17da4999268a561adca4dd4b7` |
| Commit after remediation | this commit (`git rev-parse HEAD` after checkout) |
| Release tag under review | `v4.0.0` |
| Frozen evidence bundle commit | `59da020` |
| Frozen V4 assessed code commit | `09a95b7` |
| Refreshed hostile-assurance report commit | `4074d3599641f25143ed75699ca92f0dfc02003a` |

## Findings Investigated

| Finding | Result | Evidence |
| --- | --- | --- |
| V4 evidence references may be inconsistent | Confirmed, with explanation | The closeout and handoff documents identify the frozen `v4.0.0` tuple as tag `v4.0.0`, evidence bundle `59da020`, and assessed code `09a95b7`. The hostile-assurance JSON had referenced a later assessed commit. This is valid only when treated as current-code assurance evidence, not as the frozen release tuple. |
| Release guards may not validate the full tuple | Confirmed | Existing closeout and hostile-content gates did not reconcile closeout docs, handoff docs, live V4 proof, V3 carry-forward JSON, V4 hostile-assurance JSON, and the assurance archive as one audited chain. |
| Evidence chain may not be reproducible from a clean checkout | Confirmed and remediated | Developer reproducibility is strong: `make security-check`, cargo tests, clippy, fmt, and V4 assurance tests passed. The workstation and `mail.blackbagsecurity.com` both carry the reviewed Rust/Cargo `1.94.1` toolchain. The release gate had stale `1.86.0`/`0.1.86` pins and now requires the confirmed `1.94.1`/`0.1.94` toolchain. The required historical live evidence files and frozen V3 carry-forward summary are now committed or explicitly tracked so strict release reproduction no longer depends on unstated local files. |
| Hostile-content containment proof may lack browser-mail boundary coverage | Refuted for the inspected scope | `tests/v4_hostile_assurance.rs` already includes route-backed DOM negative assertions, zero auto-fetch surface observations, MIME fail-closed cases, forced-download attachment assertions, and browser-isolation source/header checks. No new hostile-content product test was justified by this audit. |
| Toolchain and evidence metadata may be incomplete | Confirmed | The V4 hostile-assurance report lacked structured toolchain and host metadata. The gate now injects `evidence_metadata` with git commit, tags, host OS, hostname, and tool availability/version records. |

## Remediation Performed

- Added `maint/security/osmap-evidence-metadata.sh` to capture evidence metadata without requiring optional tools to exist.
- Updated `maint/security/osmap-v4-hostile-assurance-gate.sh` to inject and validate `evidence_metadata` before archiving the V4 report.
- Added `maint/security/osmap-v4-release-tuple-gate.sh` to validate the frozen `v4.0.0` release tuple and the current hostile-assurance report/archive chain.
- Added `maint/live/osmap-v4-frozen-v3-release-evidence-summary.json` so V4 tuple validation has an immutable V3 carry-forward input separate from current release-check output.
- Added the required sanitized historical `latest-host-*` live evidence files to source control by narrowing `.gitignore` exceptions.
- Updated release-check Rust toolchain pins to the confirmed development and mail-host toolchain: `rustc`/`cargo` `1.94.1`, clippy `0.1.94`, rustfmt `1.8.0`, cargo-audit `0.22.1`, and cargo-deny `0.18.3`.
- Wired the tuple gate into `maint/security/osmap-release-check.sh`.
- Added `maint/security/test-osmap-v4-release-tuple-gate.sh` and wired it into `maint/security/osmap-security-check.sh`.
- Updated hook-install regression coverage for the new security scripts.
- Refreshed `maint/live/osmap-v4-hostile-assurance-report.json` and `maint/live/osmap-v4-hostile-assurance-evidence.tar.gz` with metadata-bearing current assurance evidence.
- Updated V4 security documentation to describe frozen release tuple evidence separately from current-code hostile-assurance evidence.

## Toolchain Validation Status

Toolchain validation is complete for V4 remediation scope.

| Environment | rustc | cargo | clippy | rustfmt | cargo-audit | cargo-deny | Result |
| --- | --- | --- | --- | --- | --- | --- | --- |
| Development workstation | `1.94.1` | `1.94.1` | `0.1.94` | `1.8.0` | `0.22.1` | `0.18.3` | Matches release-check pins |
| `mail.blackbagsecurity.com` | `1.94.1` | `1.94.1` | `0.1.94` | `1.8.0` | `0.22.1` | `0.18.3` | Matches release-check pins |

After the pin and evidence-chain updates, `sh maint/security/osmap-release-check.sh`
no longer fails during pinned toolchain validation or historical evidence
lookup. The V4 tuple gate now validates the frozen carry-forward evidence from
`maint/live/osmap-v4-frozen-v3-release-evidence-summary.json` while allowing
the current release-check summary to be regenerated for the assessed checkout.

## Files Changed

- `Makefile`
- `.gitignore`
- `docs/V4_AUDIT_REMEDIATION_REPORT.md`
- `docs/V4_SECURITY_CLAIM_MATRIX.md`
- `docs/V4_SECURITY_GATES.md`
- `docs/V4_CLOSEOUT_EVIDENCE.md`
- `docs/V4_RELEASE_OPERATOR_HANDOFF.md`
- `maint/live/latest-host-edge-cutover-report.txt`
- `maint/live/latest-host-helper-boundary-report.txt`
- `maint/live/latest-host-internet-exposure-report.txt`
- `maint/live/latest-host-service-enablement-report.txt`
- `maint/live/latest-host-v2-readiness-report.txt`
- `maint/live/latest-host-v2-readiness-service-guard-report.txt`
- `maint/live/latest-host-v3-mime-html-proof-report.txt`
- `maint/live/latest-host-v3-pilot-rehearsal-report.txt`
- `maint/live/latest-host-v3-resource-controls-report.txt`
- `maint/live/osmap-v4-hostile-assurance-evidence.tar.gz`
- `maint/live/osmap-v4-hostile-assurance-report.json`
- `maint/live/osmap-v4-frozen-v3-release-evidence-summary.json`
- `maint/security/osmap-evidence-metadata.sh`
- `maint/security/osmap-publication-guard.sh`
- `maint/security/osmap-release-check.sh`
- `maint/security/osmap-security-check.sh`
- `maint/security/osmap-v4-hostile-assurance-gate.sh`
- `maint/security/osmap-v4-release-tuple-gate.sh`
- `maint/security/test-osmap-install-hooks.sh`
- `maint/security/test-osmap-v4-release-tuple-gate.sh`

## Tests Run

| Command | Result | Notes |
| --- | --- | --- |
| `sh maint/security/osmap-v4-hostile-assurance-gate.sh` | Passed | Refreshed report/archive and injected evidence metadata. |
| `sh maint/security/test-osmap-v4-release-tuple-gate.sh` | Passed | Positive tuple validation and negative mismatch cases passed. |
| `sh maint/security/test-osmap-v3-release-check.sh` | Passed | Release-check fail-closed harness passed after hook-test update. |
| `OSMAP_RELEASE_EVIDENCE_DIR=/tmp/osmap-release-check.lF2pmP make release-check` | Failed before remediation | The initial failure proved the stale pin: release-check required Rust/Cargo `1.86.0` while both validated systems had `1.94.1`; the isolated evidence directory also lacked historical live evidence files. |
| `sh maint/security/osmap-release-check.sh` | Passed after remediation | Strict release validation passed with pinned toolchain validation, cargo build/test/clippy/fmt, V4 hostile assurance, V4 tuple validation, supply-chain validation, dependency inventory, docs, TLS, and archived evidence generation. |
| `make release-check` | Passed after remediation | The documented operator target passed end to end using the committed historical evidence set and frozen V3 carry-forward summary. |
| `make security-check` | Passed | Full developer gate passed, including V4 tuple regression and nested release-check fail-closed tests. |
| `cargo fmt --check` | Passed | No formatting changes required. |
| `cargo clippy --all-targets --all-features -- -D warnings` | Passed | No warnings. |
| `cargo test --all-targets --all-features` | Passed | 443 library tests passed, 4 live-host-dependent tests ignored, 1 binary test passed, 1 V4 integration test passed. |
| `cargo test --test v4_hostile_assurance -- --nocapture` | Passed | V4 assurance integration test passed. |

## Live Host Validation

Read-only validation was performed against `mail.blackbagsecurity.com`.

| Check | Result |
| --- | --- |
| Local `date -u` | `Sat Jun 13 04:31:27 UTC 2026` |
| Local `uname -a` | `Linux parrot 7.0.9+parrot7-amd64 #1 SMP PREEMPT_DYNAMIC Parrot 7.0.9-1parrot1 (2026-05-28) x86_64 GNU/Linux` |
| Remote host | `mail.blackbagsecurity.com` |
| Remote `date -u` | `Sat Jun 13 04:31:27 UTC 2026` |
| Remote `uname -a` | `OpenBSD mail.blackbagsecurity.com 7.9 GENERIC.MP#449 amd64` |
| Remote checkout | `/home/foo/OSMAP`, clean `main`, fast-forwarded to this remediation commit |
| Remote release-check reproduction | `make release-check` passed at `4074d3599641f25143ed75699ca92f0dfc02003a` |
| Remote Rust toolchain | `rustc`/`cargo` `1.94.1`, clippy `0.1.94`, rustfmt `1.8.0`, cargo-audit `0.22.1`, cargo-deny `0.18.3` |
| Local Rust toolchain | `rustc`/`cargo` `1.94.1`, clippy `0.1.94`, rustfmt `1.8.0`, cargo-audit `0.22.1`, cargo-deny `0.18.3` |
| Remote V4 live proof | `result=v4_hostile_content_live_proof_passed` |
| `curl -k -I https://mail.blackbagsecurity.com/` | HTTP 400 with expected hardening headers; OSMAP rejects `HEAD` on `/` |
| `GET https://mail.blackbagsecurity.com/` | HTTP 303 redirect to `/login` |

The live host repository was fast-forwarded after the local remediation was
committed and pushed. Services were not restarted, runtime configuration was not
changed, and no private mail content or credentials were captured. The host
checkout now carries the corrected release-check toolchain pins and the
metadata-bearing V4 hostile-assurance report/archive from this remediation.

## Residual Risks

- Older live proof reports remain point-in-time evidence. Release-check allows
  those reports to carry forward only when the proof commit is an ancestor of
  the assessed commit and no product, test, or security-gate paths changed
  after the proof.
- V4 contains hostile email content within the browser-mail boundary; it does
  not make malicious links safe, scan downloads for malware, provide URL
  reputation, safely preview arbitrary active documents, or claim Roundcube
  feature parity.

## Final V4 Status Recommendation

V4 release-ready: evidence tuple reconciled and gates pass.
