# OSMAP V7 Boundary Hardening Due Diligence

Date: 2026-06-18
Sprint: V7 boundary hardening due diligence
Status: Implemented and production verified

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

The production-deployed binary was rebuilt natively from:

```text
c937c5c790f2d5e80e90e3f0adb4a8e872b1a4d5 allow advisory state locks under openbsd pledge
```

The installed production binary SHA-256 is:

```text
88075f6a57382b3ff75c5f81967c441378e79dc9472596653831747657b467e2
```

The installed nginx edge artifacts are from V7 branch commit `e1c8d08`. The
serve launcher with sanitized child-exit reporting is from commit `b0116b0`.

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
| File-backed state creation and locking | Closed by post-V7 follow-up | Session and throttle temporary creation is restrictive, exclusive, collision-safe, and atomically renamed. Session and throttle read-modify-write transactions use store-local advisory locks across cooperating processes. |
| Forwarded client IP trust | Closed with deployment requirement | Only loopback-supplied `X-Real-IP` is trusted. `X-Forwarded-For` is ignored. The backend must remain isolated behind the reviewed loopback nginx listener. |
| Compose form content type inconsistency | Closed | Compose uses the shared URL-encoded media-type helper and accepts charset parameters and case variation while rejecting unsupported types. |

These dispositions were reevaluated against production-deployed binary source
commit `c937c5c790f2d5e80e90e3f0adb4a8e872b1a4d5` after the deployment incident.
The final source search, V7 invariant gate, installed binary identity, native
service state, loopback listener, and public browser path were recaptured in
the production evidence root. The rc.d supervision correction does not alter
the disposition of the five original findings; it closes the operational
defect exposed while deploying them.

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
- OpenBSD-native `cargo fmt --check`: passed
- OpenBSD-native `cargo test`: passed, including 494 library tests with 4
  documented live-host tests ignored
- OpenBSD-native strict all-target clippy: passed
- OpenBSD-native V7 boundary hardening gate: passed
- OpenBSD-native `cargo audit`: inconclusive because the installed audit
  process segfaulted after updating its advisory database; the same dependency
  graph passed `cargo audit` on the development host
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
- `production-auth-fix-verification.txt`
- `production-edge-cutover-report.txt`
- `production-internet-exposure-report.txt`
- `production-post-hold-state.txt`
- `production-post-hold-http.txt`

Production deployment evidence is rooted at:

```text
/home/foo/osmap-v7-boundary-hardening-evidence/production-20260618-120051Z
/home/foo/osmap-v7-boundary-hardening-evidence/production-fix-20260618-185057Z
```

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

Bounded deployed public checks against `mail.blackbagsecurity.com` after
installing V7:

- browser-path `GET /` returned `303` with `Location: /login`
- `GET /login` returned `200` and the sanitized `OSMAP Login` title
- the login response body contained no cookie, CSRF, or password assignment
  marker
- `HEAD /` returned the known non-browser `400` response
- a headerless over-limit request returned `400 Bad Request`
- an oversized terminated header returned `400 Bad Request`
- a loopback request carrying only `X-Forwarded-For` retained
  `remote_addr=127.0.0.1` in the sanitized audit record
- `osmap_serve` and `osmap_mailbox_helper` remained supervised and healthy
- the production backend remained bound only to `127.0.0.1:8080`
- the native OpenBSD V7 gate passed at branch commit `b0116b0`
- the edge cutover validator passed
- the internet exposure assessment approved the limited direct public browser
  exposure
- a post-remediation hold check at `2026-06-18T18:56:16Z` found nginx,
  `osmap_serve`, and `osmap_mailbox_helper` healthy with no upstream error
  newer than the pre-fix `2026-06-19 01:36:19` login failure

### Production Login Failure, Root Cause, and Remediation

Successful password-plus-TOTP login repeatedly caused nginx `502 Bad Gateway`
responses because the OSMAP process terminated before returning the login
response. The behavior reproduced with both the initial V7 candidate and the
paired pre-V7 rollback binary, proving that it was not introduced by the five
V7 finding remediations.

A sanitized supervisor was installed to preserve the child exit reason.
The controlled operator login at `2026-06-18T18:36:19Z` proved that OSMAP was
terminated by signal 6 with exit status 134. The last successful application
step before termination was accepted second-factor verification.

The confirmed cause was an incomplete OpenBSD `pledge(2)` profile. V6 added
store-local `flock(2)` session locking, but the serve promise set omitted the
required `flock` promise. A valid TOTP advanced into session issuance,
`flock(2)` violated the enforced promise set, and OpenBSD terminated the
process. Invalid authentication did not reach that code path and therefore
returned normally.

Commit `c937c5c` adds only the required `flock` promise to the serve profiles
and adds regression assertions for serve mode with and without the mailbox
helper. Native OpenBSD `cargo test openbsd` and `cargo test session` passed
before deployment.

The corrected release binary was installed with SHA-256:

```text
88075f6a57382b3ff75c5f81967c441378e79dc9472596653831747657b467e2
```

The paired rollback unit is:

```text
/usr/local/bin/osmap.pre-v7-pledge-fix-20260618T184118Z
/etc/osmap/osmap-serve.env.pre-v7-pledge-fix-20260618T184118Z
```

At `2026-06-18T18:43:20Z`, a fresh Firefox login using the operator's valid
password and TOTP completed successfully. Sanitized server evidence recorded
`second_factor_accepted`, `session_issued`, `GET /mailboxes` status 200, and
`GET /mailbox` status 200. OSMAP remained healthy and nginx recorded no new
upstream errors. No credentials, cookies, TOTP values, CSRF tokens, session
tokens, mailbox contents, or attachment contents were captured.

An attempted rc.d process-match refinement was rejected during live
validation because it did not match OpenBSD rc.subr behavior. The host was
immediately restored to the known-good child process match, service control
was normalized with a clean stop and start, and the branch contains an
explicit revert. Managed child exit status 143 is classified as an expected
service stop by the launcher.

### Public Edge Log and Resource Hardening

The reviewed public nginx edge now:

- logs method, normalized `$uri`, status, byte count, host, upstream status,
  and bounded timing data;
- omits query strings, referrers, cookies, user agents, and client-supplied
  forwarding chains from new public access records;
- maintains public access and error logs as `root:wheel` mode `0640`;
- applies a conservative per-source login request limit, general request
  limit, and connection limit with HTTP 429 on limit rejection;
- retains application-level authentication throttling as the authoritative
  login decision control.

The deployment passed `nginx -t`, reload, effective-configuration inspection,
newsyslog dry-run, public `GET /` redirect, and public `GET /login` page checks.
A request containing a unique query marker produced a new access record with
only `uri="/"`, confirming that the query string was not retained.

No credentials, cookies, TOTP codes, CSRF tokens, mailbox contents, or
attachment contents were captured.

## Evidence Archive

The final sanitized archive and checksum are produced outside the repository:

```text
/home/foo/osmap-v7-boundary-hardening-evidence/osmap-v7-boundary-hardening-evidence-20260618-114455Z.tar.gz
/home/foo/osmap-v7-boundary-hardening-evidence/osmap-v7-boundary-hardening-evidence-20260618-114455Z.tar.gz.sha256
/home/foo/osmap-v7-boundary-hardening-evidence/osmap-v7-production-deployment-evidence-20260618-120051Z.tar.gz
/home/foo/osmap-v7-boundary-hardening-evidence/osmap-v7-production-deployment-evidence-20260618-120051Z.tar.gz.sha256
```

## Residual Risks

- Advisory file locking remains local-host coordination between cooperating
  processes, not distributed locking.
- Throttle transaction locking coordinates cooperating processes on one host
  and one state directory. It is not distributed locking across hosts.
- The production browser runtime must remain reachable only through the trusted
  loopback nginx proxy for `X-Real-IP` to be authoritative.
- Deliberate load, fuzzing, and hostile high-volume tests remain outside this
  sprint and are inappropriate for the known multi-purpose production host.
- The OpenBSD host's `cargo audit` process segfaulted, so its native audit run
  is not positive evidence. The development-host audit passed, and all other
  native host checks passed.

## Final Status

V7 is implemented and production verified. The five original findings have
the dispositions recorded above. The browser-availability invariant passed
with a real password-plus-TOTP login, successful session issuance, mailbox
rendering, post-login process survival, no new nginx upstream error, and the
installed one-minute recovery guard.

The production login outage was fully reevaluated and closed by adding the
`flock` pledge promise required by V6 session locking. Public edge logging and
resource controls were also deployed and verified. V7 does not require another
code follow-up for production login availability.

The post-V7 throttle transaction-locking follow-up closes the final explicit V7
state-store race. Its implementation and evidence are recorded in
`POST_V7_THROTTLE_TRANSACTION_LOCKING.md`.
