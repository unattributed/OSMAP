# V5 Boundary Hardening Evidence

## Sprint Metadata

- sprint name: OSMAP V5 identity, origin, and response boundary hardening
- branch name: `feature/v5-boundary-hardening`
- starting commit: `6d7739c4dd59b717e33cf0f83e60c54cab1f421d`
- ending commit: pending
- summary verdict: in progress

## Finding Status

| Finding | Status | Evidence | Remediation | Tests |
|---|---|---|---|---|
| canonical username validation | confirmed and remediated | Source review confirmed that backend `canonical_username` values and submitted-username fallback values were plain `String`s reused by auth, session issuance/load, TOTP secret path derivation, audit fields, and sendmail envelope/`From` construction. | Added `CanonicalUsername` and `MailboxIdentity` validation boundaries. Auth backend canonical output, second-factor identity input, session issue/load, TOTP secret loading, and sendmail submission now fail closed on control characters, whitespace boundary issues, display-name syntax, comma-separated addresses, header-like syntax, and malformed outbound addr-spec values. | `cargo test identity`; `cargo test auth::tests::`; `cargo test send::tests::sendmail_backend`; `cargo test session::tests::parses_serialized_session_records`; `cargo test totp::tests::file_secret_store_uses_hex_encoded_usernames` |
| centralized HTTP response header validation | confirmed and remediated | Source review confirmed `HttpResponse::with_header` accepted raw header names and values and `to_http_bytes` serialized them directly. Future call sites could therefore introduce response splitting if attacker-controlled CRLF reached the helper. | Added central response-header validation for non-empty RFC-token-like names, name length, value length, and value control characters. Invalid names or values now fail closed to a static `500 Internal Server Error` response without serializing the unsafe header. | `cargo test response_header_helper` |
| configured host and origin enforcement | confirmed and remediated | Source review confirmed same-origin validation used the incoming request `Host` as the expected origin. A reverse proxy that routed arbitrary Host values to OSMAP could therefore make attacker-controlled `Origin`/`Referer` values appear same-origin. | Added `OSMAP_ALLOWED_HOSTS`, carried it into `HttpPolicy`, reject missing or unexpected `Host` values with `421`, and compare `Origin`/`Referer` authorities against the configured allow-list. Updated OpenBSD deployment examples so nginx Host rejection and app-level Host/Origin/Referer enforcement stay aligned. | `cargo test config::tests::`; `cargo test configured_host`; `cargo test unconfigured_host`; `cargo test without_host`; `cargo test attacker_host` |
| session record identity field validation | pending | pending | pending | pending |
| consistent security headers for health and text responses | pending | pending | pending | pending |
| strict HTTP framing rejection | pending | pending | pending | pending |
| template and trusted HTML boundary review | pending | pending | pending | pending |

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

## Live-Safe Validation

No live checks have been run for V5 so far.

## Known Limitations

- V5 is still in progress; findings 2 through 7 have not yet been closed.
- `cargo deny check` could not evaluate the repo because the local `cargo-deny` advisory parser rejected a fetched CVSS 4.0 advisory.

## Remaining Deferred Work

- None yet. Finding 7 may be deferred if source review confirms the current rendering boundary is not exploitable and a typed HTML wrapper would be broader than the V5 remediation slice.
