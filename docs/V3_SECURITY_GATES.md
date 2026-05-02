# Version 3 Security Gates

## Purpose

This document defines the security evidence required before OSMAP Version 3 can be described as daily-driver ready.

Version 3 adds user-facing workflow continuity, so its security gate must prove that convenience did not erode the Version 2 least-privilege runtime, public-edge posture, browser hardening, supply-chain posture, or evidence quality.

## Required Carry-Forward Gates

All Version 2 gates remain mandatory:

- `make security-check` or the release-mode successor for the assessed commit
- Version 2 readiness wrapper
- persistent service guard
- internet-exposure assessment
- edge-cutover and rollback evidence
- auth observability evidence
- public-send audit-correlation evidence
- helper peer-auth rejection evidence
- request guardrail evidence
- backend-unavailable behavior evidence
- CSRF and same-origin rejection evidence

Version 3 cannot pass by replacing, weakening, or silently skipping any of these gates.

## Developer Partial Mode And Release Mode

OSMAP may keep a developer partial mode for local iteration. Developer partial mode may skip phases when tools, credentials, host access, or a compatible Rust toolchain are unavailable, but it must report those skips clearly.

Release mode is different. Release mode must fail when a required validation phase is skipped, incomplete, or missing evidence.

The implemented entry points are:

- `make security-check`: developer profile, equivalent to `OSMAP_SECURITY_PROFILE=developer`
- `make release-check`: strict release profile, equivalent to `OSMAP_SECURITY_PROFILE=release`

The release profile currently requires pinned versions of `rustc`, `cargo`,
`cargo clippy`, `cargo fmt`, `cargo-audit`, and `cargo-deny`; runs Cargo build,
test, clippy, formatting, and supply-chain phases; generates
`cargo tree --locked --all-features` dependency inventory evidence; validates
release-mode WSTG evidence; checks V2 carry-forward and host-readiness evidence;
requires archived TLS edge evidence proving the TLS CBC disposition;
and writes `maint/live/osmap-v3-release-evidence-summary.json`,
`maint/live/osmap-v3-release-evidence-summary.md`, and
`maint/live/osmap-v3-release-evidence.tar.gz`.

Release mode must fail on:

- skipped Cargo build, test, formatting, or lint phases required by the release profile
- missing or skipped supply-chain tooling required by the release profile
- missing dependency inventory or SBOM evidence required by the release profile
- missing host-readiness evidence for the intended deployment host
- missing V2 carry-forward evidence
- missing TLS CBC cleanup or exception evidence for the intended public edge
- missing V3 feature-gate evidence
- skipped authenticated WSTG tests when the mapped test requires credential and TOTP coverage
- skipped security tests outside WSTG when those tests require credential and TOTP coverage
- missing sanitized evidence archive for the assessed commit or tag

## Credential And TOTP Security-Test Rule

This rule applies only to WSTG and other security tests that require authenticated coverage.

Authenticated security tests must not be treated as complete unless credential and TOTP-dependent paths are actually exercised through the real browser login flow. This can be proven through one of two approved methods:

- a dedicated validation account with local uncommitted `.env` secrets
- a human-prompted run that collects the account password and current TOTP code at runtime, such as `--prompt-auth --auth-email`

The evidence must prove that authenticated checks exercised the real credential, TOTP, session issuance, protected route access, logout, and session invalidation paths where applicable.

The evidence must not commit or archive plaintext passwords, reusable TOTP seeds, active session cookies, private message bodies, private attachment content, provider credentials, host secrets, or unredacted personal mailbox data.

## Version 3 Gate Additions

| Gate | Required evidence |
| --- | --- |
| Release-mode validation | Evidence that a release-mode path exists and fails closed when required checks are skipped. The path must distinguish release failures from developer partial skips. |
| Supply-chain assurance | `make supply-chain-check`, `make security-check`, or `make release-check` evidence showing RustSec advisory checks, duplicate dependency rejection, approved-source enforcement, license allowlist enforcement, dependency inventory generation, and exception handling. Any exception must be dated, owned, justified, and scoped to a specific crate, version, advisory, source, or license. |
| Resource and timeout control | Tests and docs proving bounded behavior for expensive HTTP parsing, authentication, helper calls, mailbox access, search, MIME parsing, attachment upload and download, send, move, and future bulk paths. External command and helper boundaries must have timeout behavior or a documented reason why the path is not external or blocking. |
| MIME and HTML regression | Unit or route tests plus live or fixture evidence for encoded headers, transfer-encoded text bodies, multipart alternatives, nested multipart, sanitized hostile HTML, malformed MIME, inline `cid:` metadata, attachment metadata, suspicious filenames, remote-content neutralization, unsupported charsets, and oversized input rejection. |
| Draft storage boundary | Tests and docs proving draft ownership isolation, restrictive state paths, bounded draft and attachment sizes, CSRF and same-origin enforcement, expired-session rejection, cleanup behavior, and deterministic storage failure handling. |
| Reply/forward attachment safety | Tests proving selected original attachments are helper-fetched, revalidated at send time, included in aggregate limits, and not silently dropped after confirmation. |
| Richer bounded search guardrails | Tests proving query validation, mailbox visibility limits, backend and rendered result caps, sorting determinism, invalid-query 400-class behavior, backend-unavailable behavior, and timeout behavior where applicable. |
| Bounded bulk action safety | Tests proving selection caps, per-message revalidation, partial-result reporting, move/delete/archive policy limits, throttling or equivalent abuse controls, CSRF rejection, same-origin rejection, and backend failure behavior. |
| Session/device policy | Tests and docs proving the chosen concurrent-session policy, device labels, revocation semantics, idle and absolute timeout behavior, and isolated-cookie retest of the revoke-race scenario. |
| TLS CBC disposition | Archived evidence that TLS 1.2 CBC suites are removed, or a documented exception with owner, date, reason, expiry, exact suites retained, compatibility evidence, and compensating controls. |
| WSTG regression | Current WSTG testing-pack run covering the V3 browser surface, with pass, fail, warning, skip, and non-applicable disposition archived under `maint/live/` or a successor evidence path. Release mode must fail when authenticated WSTG tests that require credential and TOTP coverage are skipped. |

## TLS CBC Rule

The preferred Version 3 outcome is removal of TLS 1.2 CBC suites from the reviewed public-edge configuration.

As of 2026-05-02, the reviewed nginx public-edge artifact in
`openbsd-mailstack` commit `c285d98` limits web TLS to `TLSv1.2` and
`TLSv1.3`, with an explicit AEAD-only TLS 1.2 cipher list. Live evidence for
`mail.blackbagsecurity.com:443` is archived at
`maint/live/osmap-v3-tls-cbc-cleanup-evidence-2026-05-02.txt`.

An exception is allowed only when all of the following are documented:

- affected client population
- exact suites retained
- reason removal is not yet acceptable
- compensating controls
- named owner
- expiry date
- retest command and archived output

An exception without expiry does not satisfy the Version 3 gate.

## Session And Device Policy Rule

Version 3 must choose one policy and implement it consistently:

- allow concurrent sessions with clear device labels and user-driven revocation, or
- cap sessions per user or per device class with deterministic eviction or denial behavior

The chosen policy must be visible in documentation, user-facing session pages, logs, and tests. The April 2026 revoke-race observation must be retested with isolated cookie jars before it is classified as fixed, not reproducible, or a confirmed server-side defect.

## WSTG Regression Rule

The WSTG testing pack must be treated as a living regression suite for the browser slice. When Version 3 adds or changes routes, update the pack or record why an existing script already covers the route.

At Version 3 closeout, archive evidence for:

- baseline routes
- authentication and throttling
- credential and TOTP-backed authenticated checks where required
- logout and CSRF
- search and reflected-input handling
- settings and mass-assignment checks
- upload and attachment paths
- business-logic checks for draft, send, move, bulk action, session revocation, and workflow circumvention
- HTML, CSS, DOM, template, and client-side injection applicability
- CORS, clickjacking, XSSI, reverse-tabnabbing, and API reconnaissance checks
- TLS transport checks, including CBC disposition

Credential-gated WSTG checks may still be skipped in developer partial mode, but a skipped credential-gated security check cannot satisfy Version 3 release mode when that check is applicable.

## Evidence Hygiene Rule

Evidence must be timestamped, tied to the assessed commit or tag, and reviewable by a later operator.

Evidence must not include:

- plaintext passwords
- reusable TOTP seeds
- current TOTP codes except redacted proof that prompting occurred
- active session cookies
- private message bodies
- private attachment contents
- private keys
- provider tokens
- host secrets
- unredacted personal mailbox data

When a live-host proof cannot be committed safely, the repo must contain a sanitized evidence summary that identifies the command, date, host, commit or tag, operator role, pass or fail result, skipped checks if any, and location of the protected raw evidence.

## Failure Rule

If a Version 3 feature passes ordinary functional tests but fails one of the security gates above, the feature remains incomplete. The remedy is a scoped fix, a documented out-of-scope deferral, or removal from the Version 3 boundary.
