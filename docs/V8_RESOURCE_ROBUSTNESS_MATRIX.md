# V8 Resource Exhaustion and Robustness Regression Matrix

## Purpose

V8 Slice 5 creates durable regression coverage for bounded behavior and fail-closed handling around resource pressure.

This is not a feature expansion. The goal is to prevent already-supported daily-driver and security behavior from regressing after the V7 testing discipline incident.

## Scope

The Slice 5 matrix covers:

- overlength session token rejection
- configured mailbox name bound rejection
- invalid message UID rejection
- invalid same-mailbox move rejection
- attachment download output bound enforcement
- fail-closed public reason for oversized attachment output
- audit-event session redaction on bounded rejection
- deterministic sorting over larger synthetic message lists
- deterministic sorting over larger synthetic search result lists

## Fixture inventory

Fixtures live under:

```text
tests/fixtures/resource_robustness/
```

| Fixture | Required outcome |
|---|---|
| `limits.env` | Bounded limit cases used by the Rust matrix |
| `sort_matrix.tsv` | Deterministic sorting expectations for larger synthetic message sets |
| `rejection_matrix.tsv` | Fail-closed request and output rejection expectations |

These ENV and TSV files are reviewable inventories. The Rust matrix encodes
the corresponding bounds and expected outcomes directly, generates the larger
synthetic message sets in memory, and executes the attachment EML fixture used
by the output-bound case. The tabular files are not runtime data inputs.

## Test implementation

The Rust integration test is:

```text
tests/v8_resource_robustness_matrix.rs
```

It validates:

- fixture inventory
- invalid request rejection before backend work
- oversized attachment output rejection
- public failure reason stability
- audit redaction on resource-bound rejection
- deterministic sort behavior over 256 synthetic message summaries
- deterministic sort behavior over 256 synthetic search results

## Gate

The executable gate is:

```text
maint/security/osmap-v8-resource-robustness-gate.sh
```

It performs fixture and documentation presence checks, then executes the Rust test:

```sh
cargo test --test v8_resource_robustness_matrix
```

The aggregate V8 gate must run this Slice 5 gate through:

```sh
make v8-check
```

A dedicated convenience target is also provided:

```sh
make v8-resource-robustness-check
```

## Non-goals

Slice 5 does not add new runtime limits.

Slice 5 does not change production request handling.

Slice 5 does not make final CI enforcement changes. V8 Slice 6 completed
aggregate CI enforcement.
