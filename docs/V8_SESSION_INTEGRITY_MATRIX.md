# V8 Session Integrity Regression Matrix

## Purpose

V8 Slice 4 creates durable regression coverage for browser session integrity.

This is not a feature expansion. The goal is to prevent already-supported login and session lifecycle behavior from regressing after the V7 testing discipline incident.

## Scope

The Slice 4 matrix covers:

- session token validation
- token debug redaction
- session issuance
- CSRF token derivation and separation from session identifiers
- session validation
- last-seen refresh
- expired session fail-closed behavior
- idle timeout fail-closed behavior
- logout-style revocation by browser token
- revoke-all-except-current behavior
- revoke-all behavior
- session listing expiration behavior
- file-backed persistence without raw bearer token storage
- audit-event session redaction

## Fixture inventory

Fixtures live under:

```text
tests/fixtures/session_integrity/
```

| Fixture | Required outcome |
|---|---|
| `lifecycle.env` | Session issue and validate lifecycle baseline |
| `timeout_cases.tsv` | Active, expired, and idle-timeout behavior |
| `revocation_cases.tsv` | Logout, revoke-current, revoke-except-current, and revoke-all behavior |

## Test implementation

The Rust integration test is:

```text
tests/v8_session_integrity_matrix.rs
```

It validates:

- fixture inventory
- invalid token rejection
- `SessionToken` debug redaction
- opaque token, persisted session ID, and CSRF token separation
- issue and validate success paths
- last-seen refresh persistence
- expired and idle sessions fail closed and persist revocation
- logout-style session revocation
- revoke-all-except-current behavior
- revoke-all behavior
- user-scoped session listing and timeout handling
- file-backed persistence without raw bearer token storage
- audit-event session redaction

## Gate

The executable gate is:

```text
maint/security/osmap-v8-session-integrity-gate.sh
```

It performs fixture and documentation presence checks, then executes the Rust test:

```sh
cargo test --test v8_session_integrity_matrix
```

The aggregate V8 gate must run this Slice 4 gate through:

```sh
make v8-check
```

A dedicated convenience target is also provided:

```sh
make v8-session-integrity-check
```

## Non-goals

Slice 4 does not implement mailbox operation coverage. That is already covered by V8 Slice 3.

Slice 4 does not implement resource exhaustion and robustness coverage. That belongs to V8 Slice 5.

Slice 4 does not make final CI enforcement changes. That belongs to V8 Slice 6.
