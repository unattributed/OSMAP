# CWE Top 25 And WSTG Review - 2026-06-13

## Scope

This review examined the OSMAP repository and the authorized live target
`https://mail.blackbagsecurity.com` for evidence of MITRE CWE Top 25 weakness
classes and OWASP WSTG coverage regressions.

The review is a bounded technical assessment, not a proof that vulnerabilities
cannot exist. The finding language is intentionally narrow: no confirmed CWE
Top 25 embedded weakness was found in the reviewed code paths and the current
unauthenticated plus host-assisted WSTG lane passes after the remediation below.

## Review Basis

- Repository commit before remediation:
  `e7390e645fecc36e8fc877b9b9e2992ef3ec6bb8`
- Review date UTC: `2026-06-13`
- Local Rust toolchain observed:
  `rustc 1.94.1`, `cargo 1.94.1`, `clippy 0.1.94`, `rustfmt 1.8.0`
- CWE benchmark: MITRE 2025 CWE Top 25 Most Dangerous Software Weaknesses.
- WSTG benchmark: repository WSTG testing pack mapped to OWASP WSTG v4.2,
  ASVS 5.0.0, and the project OWASP Top 10 2025 crosswalk.

## Confirmed Finding

`OSMAP-WSTG-CONF-010` contained a stale file-permission marker for the live
serve environment file:

- stale expected marker: `/etc/osmap/osmap-serve.env` group id `1001`
- live and documented posture: `/etc/osmap/osmap-serve.env` group id `1002`
  for `osmaprt`

The live posture was restrictive (`0640`) and aligned with the documented
runtime group model. The issue was in the WSTG runner expectation, not in the
host permission posture.

## Remediation

Updated `maint/wstg-testing-pack/run-wstg-pack.py` so
`OSMAP-WSTG-CONF-010` expects the documented `osmaprt` group id for the serve
environment file.

Added a reusable CWE Top 25 weak-pattern guard:

- `maint/security/osmap-cwe-top25-guard.py`
- `maint/security/osmap-cwe-top25-guard.sh`
- `maint/security/test-osmap-cwe-top25-guard.sh`

The guard is wired into `make security-check`, so local runs, repo hooks, and
GitHub Actions reject newly introduced high-risk patterns such as unreviewed
`unsafe`, shell command execution, unreviewed `Command::new`, SQL database
drivers, outbound HTTP client dependencies, browser code-execution sinks, and
generic binary/object deserialization surfaces.

## CWE Top 25 Review Summary

No confirmed CWE Top 25 embedded weakness was found in the reviewed code paths.

Material observations:

- `CWE-79`: hostile HTML, scriptable browser APIs, unsafe URL schemes, remote
  resources, and browser-rendered negative assertions are covered by V4 hostile
  assurance tests and WSTG client/input-validation lanes.
- `CWE-89`: no SQL database driver or query construction surface was found in
  the Rust application. SQL appears only in live validation tooling and WSTG
  applicability evidence.
- `CWE-352`: state-changing browser routes are covered by same-origin, CSRF,
  and session tests.
- `CWE-862`, `CWE-863`, `CWE-284`, `CWE-306`, `CWE-639`: authentication,
  session, and authorization remain security-sensitive and are covered by Rust
  route tests and WSTG authenticated lanes. Fresh live authenticated WSTG was
  not rerun in this pass because no local WSTG credential file was present.
- `CWE-787`, `CWE-416`, `CWE-125`, `CWE-120`, `CWE-121`, `CWE-122`,
  `CWE-476`: memory-safety exposure is materially reduced by Rust. Source
  scans found `unsafe` confined to the reviewed OpenBSD FFI boundary.
- `CWE-22`: path traversal is covered by state-root, mailbox, draft,
  attachment, and HTTP parser validation plus WSTG path traversal probes.
- `CWE-78`, `CWE-77`: source scans found no shell invocation surface in `src/`.
  Direct process spawning remains concentrated in the reviewed auth boundary,
  with shell-shaped input covered as inert argv/stdin data in tests.
- `CWE-94`: no application code-generation or runtime-eval surface was found.
- `CWE-434`: attachment and upload-like surfaces remain forced through bounded,
  inert metadata/download handling rather than unsafe preview.
- `CWE-502`: no generic untrusted object-deserialization layer was found in the
  Rust browser or helper paths.
- `CWE-20`: HTTP, form, MIME, header, mailbox, draft, and attachment inputs
  have bounded parsing and negative tests.
- `CWE-200`: logs, session metadata, and validation artifacts remain sensitive;
  existing redaction and logging gates passed.
- `CWE-918`: no outbound HTTP fetch path was found in the Rust app for hostile
  message content or user-controlled URLs.
- `CWE-770`: resource bounds and throttles are present and tested, but denial
  of service remains a residual operational risk requiring continuous review.

## WSTG Results

Fresh current-pass WSTG validation:

- Command:
  `maint/wstg-testing-pack/run.sh --unauthenticated --include-host --output-dir /tmp/osmap-wstg-review-fixed`
- Target: `https://mail.blackbagsecurity.com`
- Generated at: `2026-06-13T14:43:16.245326+00:00`
- Result: `34 pass`, `0 fail`, `0 warning`, `12 skip`
- Skipped tests: authenticated/TOTP-backed WSTG lanes that require validation
  credentials.

Historical release WSTG evidence retained in the repository:

- File: `maint/live/osmap-wstg-release-summary.json`
- Generated at: `2026-06-01T14:22:17.184963+00:00`
- Result: `46 pass`, `0 fail`, `0 warning`, `0 skip`
- Mode: release mode with prompt-auth for the validation account.

## Commands Run

```sh
make security-check
sh maint/security/test-osmap-wstg-testing-pack.sh
maint/wstg-testing-pack/run.sh --unauthenticated --include-host --test-id OSMAP-WSTG-CONF-010 --output-dir /tmp/osmap-wstg-conf010
maint/wstg-testing-pack/run.sh --unauthenticated --include-host --output-dir /tmp/osmap-wstg-review-fixed
rg -n "unsafe[[:space:]]*(fn|impl|trait|\\{)|Command::new|std::process::Command|/bin/sh|sh -c|cmd /c|powershell|serde_json::from_str|bincode|deserialize|from_raw|transmute|MaybeUninit|set_len|libc::|extern \"C\"" src
rg -n "rusqlite|postgres|mysql|sqlx|diesel|SELECT |INSERT |UPDATE |DELETE |sqlite|SQL" Cargo.toml Cargo.lock src tests maint --glob '!target/**'
rg -n "eval\\(|Function\\(|innerHTML|outerHTML|document\\.write|srcdoc|javascript:|data:|blob:|file:|cid:|WebSocket|serviceWorker|BroadcastChannel|RTCPeerConnection|fetch\\(" src tests maint/wstg-testing-pack --glob '!target/**'
```

## Result

Current status recommendation:

`V4 conditionally release-ready: current unauthenticated and host-assisted WSTG
validation passes, security-check passes, and no confirmed CWE Top 25 embedded
weakness was found; fresh current-commit release-mode WSTG still requires
authenticated validation credentials or prompt-auth execution.`

## Residual Risks

- Fresh release-mode WSTG with authenticated/TOTP-backed lanes was not rerun in
  this pass because no local `.env` validation credential file was present.
- Historical release-mode WSTG evidence exists and passed, but it predates this
  remediation commit.
- CWE Top 25 review remains a regression-oriented review, not a guarantee of
  absence of all vulnerabilities.
