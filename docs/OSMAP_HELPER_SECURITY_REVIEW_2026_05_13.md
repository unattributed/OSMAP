# OSMAP Helper Security Review - 2026-05-13

This matrix records the May 13, 2026 critical inspection of `osmap_serve` and
`osmap_mailbox_helper`. Health checks are treated only as liveness evidence;
security-boundary conclusions require code, tests, or host-validation evidence.

| Finding | Status | Evidence | Fix Applied Or Reason Not Fixed | Tests Added | Residual Risk |
| --- | --- | --- | --- | --- | --- |
| Helper boundary authorization | Confirmed | `src/mailbox_helper.rs` authorized the Unix peer UID, while `src/mailbox_helper_protocol.rs` accepted caller-supplied `canonical_username`; Dovecot `doveadm -u` calls are intentionally authoritative for the supplied user and do not bind to the browser session. | Added short-lived HMAC helper request grants bound to operation, canonical username, mailbox fields, UID/part where applicable, issue/expiry, and nonce. Helper verifies the grant before dispatch and rejects replayed signatures in-process. Added `OSMAP_MAILBOX_HELPER_GRANT_KEY_PATH`; the key file must be regular, at least 32 bytes, and owner-only. | Helper tests reject missing grant, altered username, expired grant, replay, and read grant reused for mutation. | Replay cache is per helper process; a helper restart forgets old nonces, so short expiry remains part of the defense. |
| Helper protocol encoding and parser hardening | Confirmed | The old helper request and response protocol used raw string fields such as `canonical_username`, `mailbox_name`, `query`, `message_subject`, and `reason`. | Request and response string fields now use `_b64` fields. Unknown, duplicate, missing, legacy raw, and control-character fields are rejected. | Parser tests cover duplicate fields, legacy raw fields, unknown fields, control characters, and encoded request/response round trips. | The protocol remains intentionally line-oriented; future fields must preserve the encoded-field convention. |
| Health checks are insufficient as release evidence | Confirmed | Existing docs and scripts include `rcctl`/`healthz` checks, but liveness alone does not prove helper authorization or malformed protocol rejection. | Release check now requires helper-boundary evidence in addition to host readiness and liveness evidence. The live helper peer-auth validator was updated for grant-backed requests. | `test-osmap-v3-release-check.sh` now creates helper-boundary fixture evidence for release mode. | Fresh live host evidence still must be captured before a real release. |
| Browser-facing runtime authority | Partially confirmed | `src/openbsd.rs` still gives serve mode `proc exec` because auth and send paths still execute `doveadm` and `sendmail`; with a helper socket configured, serve mode skips the Dovecot userdb socket and mailbox helper binds mailbox authority. | Did not remove `proc exec`; doing so would break current auth and send behavior. Added grant-key unveil rules and retained the existing TODO direction: remove `proc exec` only after auth/submission helper separation. | Existing OpenBSD plan tests verify helper-socket mode skips userdb and includes explicit helper paths. | Serve still has process execution authority for auth/submission, not mailbox read/move authority. |
| Supply-chain assurance cannot be skipped silently | Partially confirmed | Release mode already fails missing pinned `cargo-audit` and `cargo-deny` and fails on skipped checks. Developer mode may skip cargo phases when the local toolchain is unavailable. | No code change in this pass beyond documenting that developer skip is not release evidence. | Existing release-check tests cover missing clippy/rustfmt/audit/deny and skipped release checks. | Future work should archive separate deny/audit/metadata/direct/transitive outputs in addition to the existing dependency inventory. |
| Ammonia sanitizer regression protection | Partially confirmed | `src/rendering_html.rs` uses Ammonia with a narrow tag/attribute allowlist and denies relative URLs; tests already cover script, style, event handlers, svg, iframe, object, embed, template, javascript, data, cid, relative, and protocol-relative URLs. | Added this invariant to the review record; the policy remains intentionally minimal and was not weakened. | Existing sanitizer tests cover unsafe tags, attributes, schemes, comments, and fetch surfaces. | Add explicit `math` regression coverage if the sanitizer allowlist changes. |
| Mailbox mutation authority | Confirmed | `MessageMove` is a state-changing helper operation and previously used the same peer-UID trust model as reads. | Grant verification binds the exact operation and move fields. Helper audit already emits `mailbox_helper_message_moved` with username, source, destination, and UID, without message contents. | Added read-grant-for-mutation rejection test. | Only one-message move exists today; future mutation operations must use separate operation-bound grants and audit events. |
| Maintainability cleanup without hiding boundaries | Confirmed | Helper client code repeats connect/write/shutdown/read/parse flows; security logic was embedded per operation. | Kept changes minimal for this pass; request signing is centralized through `encode_authorized_request`, while operation-specific response checks remain explicit. | Existing helper client round-trip and timeout tests still pass. | A fuller typed request/response transport helper would reduce duplication further, but should preserve explicit per-operation validation. |

## Operator Impact

Deployments that configure `OSMAP_MAILBOX_HELPER_SOCKET_PATH` must also set
`OSMAP_MAILBOX_HELPER_GRANT_KEY_PATH` in both `serve` and `mailbox-helper`
environments. Install the same random key for the web runtime and helper, with
owner-only permissions such as `0600`. Do not log or commit this key.

## Migration Steps

1. Generate at least 32 bytes of random key material on the OpenBSD host.
2. Install it at an operator-managed path, for example
   `/var/lib/osmap-helper/secrets/mailbox-helper-grant.key`.
3. Restrict the file to the service identities that need to read it.
4. Set `OSMAP_MAILBOX_HELPER_GRANT_KEY_PATH` in both service env files.
5. Restart `osmap_mailbox_helper`, then `osmap_serve`.
6. Re-run helper-boundary validation and archive
   `maint/live/latest-host-helper-boundary-report.txt` for release evidence.
