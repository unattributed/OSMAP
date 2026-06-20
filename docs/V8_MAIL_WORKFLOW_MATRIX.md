# V8 Mail Workflow Regression Matrix

## Purpose

V8 Slice 1 creates durable regression coverage for real-world mail workflows that OSMAP already needs to handle safely.

This is not a feature expansion. The goal is to prevent already-supported mail reading behavior from regressing after the V7 rendering incident.

## Scope

The Slice 1 matrix covers these message shapes:

- `text/plain`
- `text/html`
- `multipart/alternative`
- `multipart/mixed`
- nested multipart
- attachment-heavy mail
- malformed MIME

The matrix verifies both internal rendering state and browser-facing labels.

## Regression outcomes

Each workflow must preserve the following outcomes:

- body selection
- body source labels
- rendering mode labels
- remote-content status
- sanitized HTML notices
- safe fallback behavior

## Fixture inventory

Fixtures live under:

```text
tests/fixtures/mail_workflows/
```

| Fixture | Message type | Required outcome |
|---|---|---|
| `text_plain.eml` | `text/plain` | Select plain body, render escaped text, label as `singlepart_plain_text` and `plain_text_preformatted` |
| `text_html.eml` | `text/html` | Render sanitized HTML, remove active and remote-fetch surfaces, show remote-content and sanitized-HTML status |
| `multipart_alternative.eml` | `multipart/alternative` | Render sanitized HTML by default, preserve plain-text preference behavior |
| `multipart_mixed.eml` | `multipart/mixed` | Select plain body and surface attachment metadata |
| `nested_multipart.eml` | nested multipart | Select nested HTML safely and surface inline Content-ID image metadata without inline rendering |
| `attachment_heavy.eml` | attachment-heavy mail | Preserve body selection while surfacing multiple attachment metadata rows |
| `malformed_mime.eml` | malformed MIME | Fail closed with a safe placeholder and without raw HTML rendering |

## Test implementation

The Rust integration test is:

```text
tests/v8_mail_workflow_matrix.rs
```

It validates:

- fixture inventory
- MIME body source classification
- rendering mode classification
- HTML-present status
- attachment metadata count
- message-view page Body Source label
- message-view page Rendering Mode label
- message-view page HTML Present label
- remote-content page status
- sanitized HTML notice
- absence of raw active HTML markers
- malformed MIME safe fallback behavior

## Gate

The executable gate is:

```text
maint/security/osmap-v8-mail-workflow-gate.sh
```

It performs fixture and documentation presence checks, then executes the real Rust test:

```sh
cargo test --test v8_mail_workflow_matrix
```

The aggregate V8 gate must run this Slice 1 gate through:

```sh
make v8-check
```

## Non-goals

Slice 1 does not implement attachment filename safety coverage. V8 Slice 2
provides that matrix.

Slice 1 does not implement mailbox state behavior coverage. V8 Slice 3
provides that matrix.

Slice 1 does not implement session integrity coverage. V8 Slice 4 provides
that matrix.

Slice 1 does not implement resource exhaustion coverage. V8 Slice 5 provides
that matrix.

Slice 1 does not make CI enforcement final. V8 Slice 6 completed aggregate CI
enforcement.
