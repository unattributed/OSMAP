# OSMAP V7 Boundary Hardening Due Diligence

Date: 2026-06-18
Sprint: V7 boundary hardening due diligence
Status: Implementation complete; one follow-up remains

## Objective

Revalidate and narrowly remediate five post-V6 browser and file-state boundary
findings without widening the browser trust boundary, adding feature work, or
introducing new dependencies.

## Assessed Baseline

The V7 branch was created from the current `main` branch at:

```text
a6186406e35b1143580b533ff7817b4ed371efe9 record v6 production readiness
```

The checkout was clean before branch creation. Baseline `cargo fmt --check`,
`cargo test`, strict all-target clippy, and `cargo audit` all passed.

The final assessed code and gate commit before this documentation closeout is:

```text
9a9b942 cover v7 gate hook installation
```

External evidence for this run is rooted at:

```text
/home/foo/osmap-v7-boundary-hardening-evidence/20260618-114455Z
```

## Finding Revalidation

| Finding | V7 baseline status | Current-code evidence | Planned disposition |
| --- | --- | --- | --- |
| Headerless HTTP request buffering | Valid | `read_http_request` permits `max_header_bytes + max_upload_body_bytes` before finding the header terminator. | Bound pre-terminator reads to `max_header_bytes` while preserving parsed multipart body allowance. |
| Weak or empty TOTP secret | Valid | `parse_secret_file` accepts the output of `decode_base32` without a decoded-length minimum; empty and separator-only values decode to zero bytes. | Require at least 20 decoded bytes and add fail-closed regression coverage. |
| File-backed state creation and locking | Partially valid | V6 added a restrictive store-local session advisory lock and lock failures fail closed. Session and throttle temporary files still use `File::create` before chmod; throttle uses a predictable per-key temp name and has no cross-process store lock. | Preserve V6 session locking; create temporary files atomically with restrictive mode and collision resistance; assess a small throttle lock. |
| Forwarded client IP trust | Valid, deployment-sensitive | The runtime is documented and configured as loopback-only behind nginx. Nginx overwrites `X-Real-IP` but appends `X-Forwarded-For`; OSMAP accepts the last `X-Forwarded-For` hop from any loopback peer when `X-Real-IP` is absent. Effective addresses feed audit context and login, submission, and message-move throttle keys. | Retain loopback-trusted `X-Real-IP`, remove default `X-Forwarded-For` trust, and document listener isolation. |
| Compose form content type inconsistency | Valid | The shared helper accepts parameters and case-insensitive media types, but `parse_compose_form` accepts only an exact lower-case URL-encoded content type. | Reuse the shared helper and preserve multipart behavior. |

The detailed source search is recorded in
`slice0-current-code-audit.txt` under the external evidence root.

## Final Finding Status

| Finding | Final status | V7 result |
| --- | --- | --- |
| Headerless HTTP request buffering | Closed | Unterminated streaming reads fail once buffered bytes exceed `max_header_bytes`; valid parsed multipart requests retain their upload allowance. |
| Weak or empty TOTP secret | Closed | Decoded secret material shorter than 20 bytes fails closed; empty, separator-only, short, malformed, and valid RFC 6238 cases have regression coverage. |
| File-backed state creation and locking | Partially closed; follow-up required | Session and throttle temporary creation is restrictive, exclusive, collision-safe, and atomically renamed. V6 session locking remains intact. Throttle read-modify-write transactions remain unlocked across processes. |
| Forwarded client IP trust | Closed with deployment requirement | Only loopback-supplied `X-Real-IP` is trusted. `X-Forwarded-For` is ignored. The backend must remain isolated behind the reviewed loopback nginx listener. |
| Compose form content type inconsistency | Closed | Compose uses the shared URL-encoded media-type helper and accepts charset parameters and case variation while rejecting unsupported types. |

## Slice Status

| Slice | Status | Result |
| --- | --- | --- |
| 0. Current-code audit confirmation | Complete | All five findings revalidated; session locking narrowed to a partially remediated finding. |
| 1. Headerless request bound | Complete | Unterminated reads are bounded by the header limit; parsed multipart requests retain their upload allowance. |
| 2. TOTP secret minimum | Complete | Empty, separator-only, malformed, and decoded secrets shorter than 20 bytes fail closed. |
| 3. File-backed state writes | Complete | Session and throttle temporary files use restrictive atomic creation; throttle temp names include pid plus a process-local counter. |
| 4. Forwarded client IP trust | Complete | Only a valid `X-Real-IP` from a loopback peer can replace the socket peer address; `X-Forwarded-For` is ignored. |
| 5. Compose content type | Complete | Compose accepts parameterized and mixed-case URL-encoded media types through the shared helper; unsupported types still fail closed. |
| 6. Final gate and live due diligence | Complete | Final Rust checks, project gate, isolated local live checks, and bounded public health checks completed. |

## Slice Changes

### Slice 1: Headerless request bound

`read_http_request` now searches each received chunk for a header terminator
before applying the header-only limit. If no terminator exists and the buffered
bytes exceed `max_header_bytes`, the request fails with the existing
`http headers exceeded maximum length` reason. Once valid headers are parsed,
the existing content-type-specific body allowance remains in effect.

### Slice 2: TOTP secret minimum

`MIN_TOTP_SECRET_BYTES` is 20 bytes. Secret-file parsing rejects decoded
material below that floor without including secret material in the operator
error. The existing 20-byte RFC 6238 reference secret remains valid.

### Slice 3: File-backed state writes

Session and throttle temporary files now use `OpenOptions` with
`create_new(true)` and Unix mode `0600`, eliminating the create-then-chmod
window and preventing an existing temp path from being truncated. Session
temporary names retain the existing session id, pid, and atomic counter.
Throttle temporary names now include the key id, pid, and an atomic counter.
Both stores preserve same-directory atomic rename.

The V6 store-local session advisory lock and fail-closed lock behavior are
unchanged. A throttle advisory lock was not added because the current store
trait exposes separate `load`, `save`, and `remove` operations while service
updates span complete read-modify-write transactions and, often, two related
buckets. Locking only `save` would not close lost-update races. Correct
cross-process serialization requires a separate, reviewable transaction
change rather than a misleading narrow lock.

### Slice 4: Forwarded client IP trust

The effective remote address now trusts only a syntactically valid
`X-Real-IP` when the immediate peer is loopback. `X-Forwarded-For` is ignored,
including when supplied by a loopback peer. Requests from non-loopback peers
cannot replace the socket peer address with either header.

The reviewed production template overwrites `X-Real-IP` with nginx
`$remote_addr`; it may continue to append `X-Forwarded-For` for edge logging
because OSMAP no longer consumes that chain. Production `serve` remains
configured on `127.0.0.1:8080`. This trust rule is safe only while listener
isolation keeps untrusted local users and processes from connecting directly
to the OSMAP HTTP socket.

### Slice 5: Compose form content type

`parse_compose_form` now uses `is_urlencoded_form_content_type` instead of an
exact lower-case string match. URL-encoded compose submissions therefore
accept media-type parameters and ASCII case variation consistently with other
form routes. Unsupported media types and existing multipart validation remain
unchanged.

### Slice 6: Gate and due diligence

A lightweight `maint/security/osmap-v7-boundary-hardening-gate.sh` now checks
the durable source and regression-test invariants for all five findings. It is
available through `make v7-check`, runs from `make security-check`, and is
covered by the hook-install regression fixture.

## Tests And Evidence

Baseline results:

- `cargo fmt --check`: passed
- `cargo test`: passed, including 483 library tests with 4 documented live-host
  tests ignored
- `cargo clippy --all-targets --all-features -- -D warnings`: passed
- `cargo audit`: passed

Final results:

- `cargo fmt --check`: passed
- `cargo test`: passed, including 494 library tests with 4 documented live-host
  tests ignored, the binary test, hostile-assurance integration test, and doc
  test
- `cargo clippy --all-targets --all-features -- -D warnings`: passed
- `cargo audit`: passed
- `make security-check`: passed
- V5 boundary gate: passed
- V7 boundary hardening gate: passed
- V6 retirement-readiness gate: not passed because the pre-existing
  `latest-host-v6-retirement-rehearsal-report.txt` input and other required V6
  live closeout reports are absent; this is not a V7 code regression

Evidence files:

- `baseline.txt`
- `tool_versions.txt`
- `baseline-check-status.txt`
- `baseline-cargo-fmt-check.txt`
- `baseline-cargo-test.txt`
- `baseline-cargo-clippy.txt`
- `baseline-cargo-audit.txt`
- `slice0-current-code-audit.txt`
- `slice1-http-parse-tests.txt`
- `slice1-cargo-fmt-check.txt`
- `slice1-diff.txt`
- `slice2-totp-tests.txt`
- `slice2-cargo-fmt-check.txt`
- `slice2-diff.txt`
- `slice3-session-tests.txt`
- `slice3-throttle-tests.txt`
- `slice3-cargo-fmt-check.txt`
- `slice3-diff.txt`
- `slice4-http-parse-tests.txt`
- `slice4-cargo-fmt-check.txt`
- `slice4-diff.txt`
- `slice5-http-form-tests.txt`
- `slice5-cargo-fmt-check.txt`
- `slice5-diff.txt`
- `slice6-v7-gate.txt`
- `slice6-v7-gate-diff.txt`
- `final-check-status.txt`
- `final-cargo-fmt-check.txt`
- `final-cargo-test.txt`
- `final-cargo-clippy.txt`
- `final-cargo-audit.txt`
- `final-make-security-check.txt`
- `final-v5-boundary-gate.txt`
- `final-v6-retirement-readiness-gate.txt`
- `final-v7-boundary-hardening-gate.txt`
- `local-live-listeners-before.txt`
- `local-live-listeners-after.txt`
- `local-live-listeners-stopped.txt`
- `local-live-http-checks.txt`
- `deployed-live-public-http-checks.txt`

## Live Test Results

An isolated development instance was started with:

```text
env OSMAP_ENV=development OSMAP_LISTEN_ADDR=127.0.0.1:18080 OSMAP_STATE_DIR=/tmp/osmap-v7-live-20260618-114455Z cargo run -- serve
```

Local bounded results:

- the listener appeared only on `127.0.0.1:18080`
- `GET /` returned `303` with `Location: /login`
- `GET /login` returned `200` and the sanitized `OSMAP Login` title
- the login response body contained no cookie, CSRF, or password assignment
  marker
- a 16,385-byte headerless request returned `400 Bad Request`
- a terminated oversized header request returned `400 Bad Request`
- the compose charset and forwarded-header policy harnesses passed
- the isolated listener was stopped and removed after testing

Bounded deployed public checks against `mail.blackbagsecurity.com`:

- browser-path `GET /` returned `303` with `Location: /login`
- `GET /login` returned `200` and the sanitized `OSMAP Login` title
- the login response body contained no cookie, CSRF, or password assignment
  marker
- `HEAD /` returned the known non-browser `400` response

No credentials, cookies, TOTP codes, CSRF tokens, mailbox contents, or
attachment contents were captured. The deployed checks prove current public
service health only. V7 was not deployed to the production host during this
sprint, so V7 behavior is proven by the isolated local live run and tests.

## Evidence Archive

The final sanitized archive and checksum are produced outside the repository:

```text
/home/foo/osmap-v7-boundary-hardening-evidence/osmap-v7-boundary-hardening-evidence-20260618-114455Z.tar.gz
/home/foo/osmap-v7-boundary-hardening-evidence/osmap-v7-boundary-hardening-evidence-20260618-114455Z.tar.gz.sha256
```

## Residual Risks

- Advisory file locking remains local-host coordination between cooperating
  processes, not distributed locking.
- Throttle records now have safe temporary-file creation and replacement, but
  concurrent processes can still lose increments across an unlocked
  read-modify-write transaction. Closing that race requires a follow-up
  transaction-level store API and lock.
- The production browser runtime must remain reachable only through the trusted
  loopback nginx proxy for `X-Real-IP` to be authoritative.
- Deliberate load, fuzzing, and hostile high-volume tests remain outside this
  sprint and are inappropriate for the known multi-purpose production host.
- Production still runs its pre-V7 deployed binary until an operator performs
  a separate reviewed deployment and post-deployment validation.

## Final Status

V7 implementation, local live due diligence, public service health checks, and
repository gates are complete. Four findings are closed. File-backed state
creation is closed, but the broader throttle cross-process read-modify-write
race is only partially closed and requires a focused transaction-level locking
follow-up. No new dependency was added and the browser trust boundary was not
widened.
