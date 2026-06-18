# V5 Boundary Hardening Evidence

## Sprint Metadata

- sprint name: OSMAP V5 identity, origin, and response boundary hardening
- branch name: `feature/v5-boundary-hardening`
- starting commit: `6d7739c4dd59b717e33cf0f83e60c54cab1f421d`
- initial implementation/test range ending commit:
  `490518237ef6c0249feaa30f4c6cb23a4d34492e`
- final pre-deployment boundary-hardening commit:
  `927516f77dd7a92e199ced8f5f90fe894e584a48`
- evidence closeout commit: `d03acd1`
- production deployment record commit: `4961d09`
- summary verdict: V5 remediation and production deployment are complete; five
  findings were confirmed and remediated, one was confirmed and accepted as
  existing strict request-framing behavior, and one was not confirmed and
  deferred as future typed-template hardening.

## Finding Status

| Finding | Status | Evidence | Remediation | Tests |
|---|---|---|---|---|
| canonical username validation | confirmed and remediated | Source review confirmed that backend `canonical_username` values and submitted-username fallback values were plain `String`s reused by auth, session issuance/load, TOTP secret path derivation, audit fields, and sendmail envelope/`From` construction. | Added `CanonicalUsername` and `MailboxIdentity` validation boundaries. Auth backend canonical output, second-factor identity input, session issue/load, TOTP secret loading, and sendmail submission now fail closed on control characters, whitespace boundary issues, display-name syntax, comma-separated addresses, header-like syntax, and malformed outbound addr-spec values. | `cargo test identity`; `cargo test auth::tests::`; `cargo test send::tests::sendmail_backend`; `cargo test session::tests::parses_serialized_session_records`; `cargo test totp::tests::file_secret_store_uses_hex_encoded_usernames` |
| centralized HTTP response header validation | confirmed and remediated | Source review confirmed `HttpResponse::with_header` accepted raw header names and values and `to_http_bytes` serialized them directly. Future call sites could therefore introduce response splitting if attacker-controlled CRLF reached the helper. | Added central response-header validation for non-empty RFC-token-like names, name length, value length, and value control characters. Invalid names or values now fail closed to a static `500 Internal Server Error` response without serializing the unsafe header. | `cargo test response_header_helper` |
| configured host and origin enforcement | confirmed and remediated | Source review confirmed same-origin validation used the incoming request `Host` as the expected origin. A reverse proxy that routed arbitrary Host values to OSMAP could therefore make attacker-controlled `Origin`/`Referer` values appear same-origin. | Added `OSMAP_ALLOWED_HOSTS`, carried it into `HttpPolicy`, reject missing or unexpected `Host` values with `421`, and compare `Origin`/`Referer` authorities against the configured allow-list. Updated OpenBSD deployment examples so nginx Host rejection and app-level Host/Origin/Referer enforcement stay aligned. | `cargo test config::tests::`; `cargo test configured_host`; `cargo test unconfigured_host`; `cargo test without_host`; `cargo test attacker_host` |
| session record identity field validation | confirmed and remediated | Source review confirmed session load validated `session_id` and `csrf_token`, and V5 slice 1 revalidated `canonical_username`, but line parsing still used `str::lines()` plus trimming and did not enforce explicit loaded `remote_addr` or `user_agent` bounds. | Session record parsing now rejects control characters before splitting fields, reuses V5 canonical username validation, and enforces required/length/control-character checks for `remote_addr` and `user_agent`. Corrupted or legacy unsafe records fail closed and require re-login. | `cargo test session::tests::rejects_tampered_session_record`; `cargo test session::tests::parses_serialized_session_records` |
| consistent security headers for health and text responses | confirmed and remediated | Source review confirmed `/healthz` built a direct `HttpResponse::text` with only `Content-Type` and `Cache-Control`, bypassing the common security header helpers. | Added `plain_text_response` for non-cacheable text/plain responses with `Cache-Control: no-store`, `X-Content-Type-Options: nosniff`, `Cross-Origin-Resource-Policy: same-origin`, and `Referrer-Policy: no-referrer`; `/healthz` now uses it. CSP is intentionally omitted for text/plain because `nosniff` prevents HTML interpretation and HTML responses carry CSP. | `cargo test healthz_response_includes_plain_text_security_headers` |
| strict HTTP framing rejection | confirmed and accepted with rationale | Source review confirmed the parser already rejects unsupported `Transfer-Encoding`, requires explicit `Content-Length` on POST, rejects GET bodies, rejects duplicate headers, and rejects body bytes whose length differs from the declared `Content-Length`. This safely rejects pipelining and extra bytes rather than attempting to multiplex requests on one connection. | No behavioral code change was needed. Added regression tests and documented this as intentional request-smuggling hardening. Responses continue to emit `Connection: close`. | `cargo test rejects_extra_bytes_after_declared_body_length`; `cargo test rejects_pipelined_second_request_bytes`; `cargo test rejects_duplicate_content_length_body_framing`; `cargo test rejects_unsupported_transfer_encoding_headers` |
| template and trusted HTML boundary review | not confirmed; deferred with rationale | Source review found `html_response` still accepts trusted body HTML, but current page call sites escape user-controlled values through `escape_html`; message body HTML inserted by `render_message_page` comes from escaped plain text or `rendering_html::sanitize_html_body`. Focused tests confirm hostile HTML and plain text are contained. | No code change in V5. A future `TrustedHtml`/`EscapedHtml` wrapper could make this harder to misuse, but implementing it across all page templates would be a broad UI refactor and no current exploit path was confirmed. | `cargo test message_view_renders_safe_body_and_attachments`; `cargo test escapes_plain_text_body_for_browser_display`; `cargo test fixture_hostile_html_strips_active_and_remote_content`; `cargo test renders_message_view_with_plain_text_policy` |

## Files Changed

- `src/identity.rs`
- `src/lib.rs`
- `src/auth.rs`
- `src/send.rs`
- `src/session.rs`
- `src/totp.rs`
- `src/http.rs`
- `src/http_runtime.rs`
- `src/http/routes_auth.rs`
- `src/http_support.rs`
- `src/config.rs`
- `src/bootstrap.rs`
- `src/mailbox_helper.rs`
- `src/openbsd.rs`
- `config/osmap.env.example`
- `maint/openbsd/osmap-serve.env.example`
- `maint/openbsd/mail.blackbagsecurity.com/etc/osmap/osmap-serve.env`
- `docs/DEPLOYMENT_OPENBSD.md`
- `docs/V5_BOUNDARY_HARDENING_EVIDENCE.md`
- `docs/DECISION_LOG.md`

## Tests Added

- `identity::tests::canonical_username_rejects_hostile_identity_values`
- `identity::tests::canonical_username_accepts_simple_mailbox_identity`
- `identity::tests::mailbox_identity_requires_conservative_addr_spec`
- `auth::tests::authentication_rejects_hostile_backend_canonical_username`
- Updated auth and sendmail regression tests so unsafe canonical/sender identity values are rejected while command/body data remains non-shell-expanded.
- `http::tests::response_header_helper_rejects_invalid_header_names`
- `http::tests::response_header_helper_rejects_crlf_header_value_splitting`
- `http::tests::response_header_helper_accepts_expected_safe_headers`
- `config::tests::rejects_unsafe_allowed_hosts`
- `http::tests::rejects_requests_with_unconfigured_host`
- `http::tests::rejects_routed_requests_without_host`
- `http::tests::accepts_requests_with_configured_host`
- `http::tests::state_changing_routes_require_origin_matching_configured_host`
- `http::tests::rejects_origin_matching_attacker_host_but_not_configured_host`
- `http::tests::rejects_referer_matching_attacker_host_but_not_configured_host`
- `http::tests::accepts_referer_matching_configured_host`
- `session::tests::rejects_tampered_session_record_canonical_username`
- `session::tests::rejects_tampered_session_record_control_characters`
- `session::tests::rejects_tampered_session_record_user_agent_length`
- `http::tests::healthz_response_includes_plain_text_security_headers`
- `http::tests::rejects_extra_bytes_after_declared_body_length`
- `http::tests::rejects_pipelined_second_request_bytes`
- `http::tests::rejects_duplicate_content_length_body_framing`

## Commands Run

| Command | Result |
|---|---|
| `git switch main && git pull --ff-only origin main && git switch -c feature/v5-boundary-hardening` | passed; branch created from current `origin/main` |
| `cargo fmt --check` | passed at baseline |
| `cargo test` | passed at baseline: 443 lib tests passed, 4 ignored; 1 main test passed; 1 integration test passed |
| `cargo clippy --all-targets --all-features -- -D warnings` | passed at baseline |
| `cargo audit` | passed at baseline |
| `cargo deny check` | unavailable/evaluation blocked; installed tool failed loading the fetched advisory database because it does not support a CVSS 4.0 advisory |
| `rg -n "with_header\|Content-Disposition\|Location\|Set-Cookie\|canonical_username\|sendmail\|From:\|csrf\|Origin\|Referer\|Host" src tests docs` | completed; broad review inventory was noisy and is being followed up per finding |
| `cargo test identity` | passed |
| `cargo test auth::tests::` | passed: 22 passed, 1 ignored |
| `cargo test send::tests::sendmail_backend` | passed: 4 passed |
| `cargo test session::tests::parses_serialized_session_records` | passed |
| `cargo test totp::tests::file_secret_store_uses_hex_encoded_usernames` | passed |
| `cargo test response_header_helper` | passed |
| `cargo test config::tests::` | passed |
| `cargo test configured_host` | passed |
| `cargo test unconfigured_host` | passed |
| `cargo test without_host` | passed |
| `cargo test attacker_host` | passed |
| `cargo test session::tests::rejects_tampered_session_record` | passed |
| `cargo test session::tests::parses_serialized_session_records` | passed |
| `cargo test healthz_response_includes_plain_text_security_headers` | passed |
| `cargo test rejects_extra_bytes_after_declared_body_length` | passed |
| `cargo test rejects_pipelined_second_request_bytes` | passed |
| `cargo test rejects_duplicate_content_length_body_framing` | passed |
| `cargo test rejects_unsupported_transfer_encoding_headers` | passed |
| `cargo test message_view_renders_safe_body_and_attachments` | passed |
| `cargo test escapes_plain_text_body_for_browser_display` | passed |
| `cargo test fixture_hostile_html_strips_active_and_remote_content` | passed |
| `cargo test renders_message_view_with_plain_text_policy` | passed |
| `cargo fmt --check` | passed after V5 remediation |
| `cargo test` | passed after V5 remediation: 466 lib tests passed, 4 ignored; 1 main test passed; 1 integration test passed |
| `cargo test --quiet` on the June 18, 2026 repository tip | passed: 470 lib tests passed, 4 ignored; 1 main test passed; 1 integration test passed |
| `cargo clippy --all-targets --all-features -- -D warnings` | passed after V5 remediation |
| `cargo audit` | passed after V5 remediation |
| `cargo deny check` | still unavailable in the default user cargo home; the installed parser fails before repo evaluation on fetched advisory `RUSTSEC-2026-0146` because it does not support CVSS 4.0 |
| `make security-check` | passed after V5 remediation; this includes `cargo check`, `cargo test`, the V4 hostile-content assurance gate, clippy, fmt, the repo supply-chain gate with isolated `CARGO_HOME`, publication hygiene, documentation governance, TLS policy, CWE Top 25, command-boundary, OpenBSD artifact, live-wrapper regression, WSTG-pack, and release-check guards |
| `rg -n "with_header\|Content-Disposition\|Location\|Set-Cookie\|canonical_username\|sendmail\|From:\|csrf\|Origin\|Referer\|Host" src tests docs` | completed after V5 remediation; broad inventory remains intentionally noisy and was used to verify changed boundaries and call sites |

## Live-Safe Validation

V5 was deployed and validated on `mail.blackbagsecurity.com` on June 14, 2026.
The assessed production deployment used commit
`927516f77dd7a92e199ced8f5f90fe894e584a48`.

The live checks recorded in `V5_PRODUCTION_DEPLOYMENT_COMPLETE.md` proved:

- both `osmap_serve` and `osmap_mailbox_helper` were healthy after deployment
- `GET https://mail.blackbagsecurity.com/healthz` returned `200`
- the health response included `Cross-Origin-Resource-Policy: same-origin`,
  `Referrer-Policy: no-referrer`, and `X-Content-Type-Options: nosniff`
- a request routed to the same public address with `Host: attacker.invalid` was
  rejected with `421`
- local application-level checks accepted
  `Host: mail.blackbagsecurity.com` and rejected `Host: attacker.invalid`
- the production `OSMAP_ALLOWED_HOSTS` value was
  `mail.blackbagsecurity.com`

## Known Limitations

- Standalone `cargo deny check` could not evaluate the repo from the default user cargo home because the local `cargo-deny` advisory parser rejected a fetched CVSS 4.0 advisory. The repo-owned `make security-check` supply-chain phase passed using its isolated cargo home and advisory database.
- Finding 7 typed HTML wrappers remain deferred. Current exploitability was not confirmed; existing rendering paths escape or sanitize user-controlled values, and a wrapper conversion would be broader than the targeted V5 remediation slices.

## Remaining Deferred Work

- Finding 7 typed HTML wrappers are deferred. Current exploitability was not confirmed; existing rendering paths escape or sanitize user-controlled values, and a wrapper conversion would be broader than the targeted V5 remediation slices.

## Follow-Up Review Slice

A post-evidence review identified three small boundary hardening refinements before V5 closure:

- response serialization now validates headers even when future code constructs `HttpResponse` directly instead of using `with_header`
- the default local allowed-host configuration includes the actual browser Host values for the default loopback listener, including `localhost:8080` and `127.0.0.1:8080`
- same-origin validation now rejects non-loopback `http://` Origin and Referer authorities while preserving loopback HTTP development support

These changes keep the V5 theme focused on identity, origin, and response-boundary hardening.

## Closeout Status

V5 is a deployed boundary-hardening milestone, not a separately tagged release.
The formal release evidence described in the main README remains anchored to
`v4.0.0`. V5 adds production-proven identity, Host/origin, response-header,
plain-text response, and strict request-framing defenses without broadening the
product scope or hostile-content claims.
