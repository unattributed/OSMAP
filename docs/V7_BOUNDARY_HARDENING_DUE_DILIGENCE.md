# OSMAP V7 Boundary Hardening Due Diligence

Date: 2026-06-18
Sprint: V7 boundary hardening due diligence
Status: In progress

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

## Slice Status

| Slice | Status | Result |
| --- | --- | --- |
| 0. Current-code audit confirmation | Complete | All five findings revalidated; session locking narrowed to a partially remediated finding. |
| 1. Headerless request bound | Complete | Unterminated reads are bounded by the header limit; parsed multipart requests retain their upload allowance. |
| 2. TOTP secret minimum | Complete | Empty, separator-only, malformed, and decoded secrets shorter than 20 bytes fail closed. |
| 3. File-backed state writes | Complete | Session and throttle temporary files use restrictive atomic creation; throttle temp names include pid plus a process-local counter. |
| 4. Forwarded client IP trust | Pending | Not started. |
| 5. Compose content type | Pending | Not started. |
| 6. Final gate and live due diligence | Pending | Not started. |

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

## Tests And Evidence

Baseline results:

- `cargo fmt --check`: passed
- `cargo test`: passed, including 483 library tests with 4 documented live-host
  tests ignored
- `cargo clippy --all-targets --all-features -- -D warnings`: passed
- `cargo audit`: passed

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

## Live Test Results

Pending Slice 6.

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

## Final Status

V7 remains open while implementation, final gates, live due diligence, and
evidence archival are incomplete.
