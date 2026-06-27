# V12 OpenPGP Helper Protocol Scaffold

## Purpose

V12 Slice 4 defines the `osmap-openpgp-helper` protocol boundary before any OpenPGP cryptographic operation is implemented. The goal is to make the request and response contract reviewable, testable, and fail-closed before later slices introduce GPGME-backed work.

Slice 4 is a protocol scaffold only. It does not decrypt mail, verify signatures, sign mail, encrypt mail, parse PGP/MIME payloads, prompt for passphrases, access secret keys, expose browser UI controls, or call GPGME.

## Boundary model

The browser-facing OSMAP process must not directly handle private key material or invoke OpenPGP tooling. Later implementation slices must route OpenPGP requests through a narrow helper boundary that consumes previously validated account bindings.

The helper protocol requires:

- a bounded request identifier
- an authenticated account identity
- an operation name from a small allow-list
- explicit full OpenPGP fingerprint authorization when an operation is account-key scoped
- message digests or opaque references instead of logging or transporting plaintext in evidence
- bounded response metadata
- redacted failure reasons suitable for audit evidence

## Slice 4 allowed operations

Only non-cryptographic scaffold operations are allowed in Slice 4:

- `capability_status`
- `policy_check`
- `diagnostic_ping`

Any operation that would decrypt, verify, sign, encrypt, export, import, or otherwise transform OpenPGP message material is out of scope for Slice 4 and must fail closed.

## Request safety rules

A valid Slice 4 helper protocol definition proves these rules:

- request handlers consume validated full fingerprints, not email-only matches
- short key IDs are not accepted as authorization boundaries
- user ID text is not accepted as an authorization boundary
- unknown operation names fail closed
- missing account identity fails closed
- plaintext, passphrases, private key material, and raw message bodies are not protocol fields
- audit evidence records only bounded metadata and boolean invariants

## Response safety rules

A valid response envelope must preserve the same boundary:

- no decrypted message body in response metadata
- no signed content in response metadata
- no private key material in response metadata
- no passphrase value in response metadata
- no browser-trusted HTML result from cryptographic status alone
- failure responses are redacted and bounded

## Evidence requirements

A valid Slice 4 evidence run includes:

- helper protocol validator self-test
- example protocol validation report
- no-crypto-operations report check
- V12 claims, diagnostics, account binding, and helper protocol gates
- `make v12-check`
- `cargo fmt --check`
- `cargo test --locked --all-features`
- `cargo clippy --locked --all-targets --all-features -- -D warnings`
- `cargo audit`
- `make security-check`
- carried-forward `make release-check` status

The known V3 stale live evidence release blocker remains carried forward until final release evidence is refreshed.
