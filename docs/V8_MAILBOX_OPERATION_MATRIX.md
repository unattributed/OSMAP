# V8 Mailbox Operation Regression Matrix

## Purpose

V8 Slice 3 creates durable regression coverage for mailbox operations that already exist in OSMAP.

This is not a feature expansion. The goal is to prevent daily-driver mailbox behavior from regressing after the V7 testing discipline incident.

## Scope

The Slice 3 matrix covers:

- mailbox listing
- message listing
- message-list sorting
- mailbox-scoped search
- search result sorting
- single-message retrieval
- one-message move and archive-style operation semantics
- request validation for mailbox names, queries, sort controls, UIDs, and move targets
- backend failure handling
- audit-event session redaction

## Fixture inventory

Fixtures live under:

```text
tests/fixtures/mailbox_operations/
```

| Fixture | Required outcome |
|---|---|
| `mailboxes.txt` | Stable mailbox listing inventory, including nested mailbox names |
| `messages.tsv` | Message listing and sorting by UID, subject, sender, received time, flags, and size |
| `search_results.tsv` | Search result sorting and mailbox retention |
| `message_view.eml` | Single-message retrieval metadata and body fixture |
| `move_operations.tsv` | Valid move, same-mailbox rejection, and zero-UID rejection cases |

## Test implementation

The Rust integration test is:

```text
tests/v8_mailbox_operation_matrix.rs
```

It validates:

- fixture inventory
- mailbox name validation
- message-list request validation
- search query and search-field validation
- sort column and sort direction parsing
- message-list sorting
- search-result sorting
- mailbox listing success path
- message listing success path
- search success path
- message view success path
- message move success path
- parser and backend failure behavior
- message-not-found public reason behavior
- audit-event session redaction

## Gate

The executable gate is:

```text
maint/security/osmap-v8-mailbox-operation-gate.sh
```

It performs fixture and documentation presence checks, then executes the Rust test:

```sh
cargo test --test v8_mailbox_operation_matrix
```

The aggregate V8 gate must run this Slice 3 gate through:

```sh
make v8-check
```

A dedicated convenience target is also provided:

```sh
make v8-mailbox-operation-check
```

## Non-goals

Slice 3 does not implement attachment download safety coverage. That is already covered by V8 Slice 2.

Slice 3 does not implement session integrity coverage. That belongs to V8 Slice 4.

Slice 3 does not implement resource exhaustion and robustness coverage. That belongs to V8 Slice 5.

Slice 3 does not make final CI enforcement changes. That belongs to V8 Slice 6.
