# V8 Attachment Safety Regression Matrix

## Purpose

V8 Slice 2 creates durable regression coverage for attachment download safety.

This is not a feature expansion. The goal is to prevent already-supported attachment behavior from regressing after the V7 testing discipline incident.

## Scope

The Slice 2 matrix covers:

- safe media type preservation
- browser-executable media type fallback to `application/octet-stream`
- filename sanitization
- generated fallback filenames for untrusted path-shaped metadata
- base64 decoding
- quoted-printable decoding
- unsupported transfer encoding fail-closed behavior
- decoded attachment byte limits
- invalid and unsurfaced part path rejection
- forced-download HTTP headers
- attachment audit redaction

## Fixture inventory

Fixtures live under:

```text
tests/fixtures/attachments/
```

| Fixture | Required outcome |
|---|---|
| `safe_pdf_base64.eml` | Decode base64 PDF bytes, preserve `report.pdf`, preserve `application/pdf`, force download headers |
| `quoted_printable_text.eml` | Decode quoted-printable bytes, preserve `notes.txt`, preserve `text/plain`, force download headers |
| `suspicious_html_attachment.eml` | Sanitize hostile filename metadata and force `text/html` to `application/octet-stream` |
| `svg_active_attachment.eml` | Force `image/svg+xml` to `application/octet-stream` |
| `generated_filename_fallback.eml` | Replace path-shaped filename metadata with generated fallback filename |
| `unsupported_encoding.eml` | Deny unsupported transfer encoding with stable public and audit reasons |

## Test implementation

The Rust integration test is:

```text
tests/v8_attachment_safety_matrix.rs
```

It validates:

- fixture inventory
- filename safety
- content type normalization
- decoded attachment bytes
- mailbox and UID preservation
- surfaced part path preservation
- forced-download response headers
- invalid part path rejection
- unsurfaced part path rejection
- unsupported encoding fail-closed behavior
- decoded size fail-closed behavior
- audit field redaction

## Gate

The executable gate is:

```text
maint/security/osmap-v8-attachment-safety-gate.sh
```

It performs fixture and documentation presence checks, then executes the Rust test:

```sh
cargo test --test v8_attachment_safety_matrix
```

The aggregate V8 gate must run this Slice 2 gate through:

```sh
make v8-check
```

A dedicated convenience target is also provided:

```sh
make v8-attachment-safety-check
```

## Non-goals

Slice 2 does not implement mailbox listing, search, sort, move, or archive coverage. That belongs to V8 Slice 3.

Slice 2 does not implement session integrity coverage. That belongs to V8 Slice 4.

Slice 2 does not implement resource exhaustion and robustness coverage. That belongs to V8 Slice 5.

Slice 2 does not make final CI enforcement changes. That belongs to V8 Slice 6.
