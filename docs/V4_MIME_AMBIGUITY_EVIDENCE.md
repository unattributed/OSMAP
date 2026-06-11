# Version 4 MIME Ambiguity Evidence

## Purpose

This document records the Version 4 slice 4 evidence for MIME ambiguity and
metadata breadth.

Evidence class: MIME ambiguity and metadata breadth.

The slice does not claim full rich-mail compatibility. It proves that selected
malformed, nested, suspicious, unsupported, and oversized MIME inputs either
fail closed or surface only bounded metadata before browser rendering.

## Product-Code Evidence

The primary evidence is in `src/mime.rs` product-code regression tests:

- `v4_mime_missing_multipart_boundary_withholds_structure`
- `v4_mime_nested_depth_limit_withholds_deeper_structure`
- `v4_mime_unsupported_transfer_encoding_withholds_text_body`
- `v4_mime_suspicious_filename_is_bounded_metadata_only`
- `v4_mime_malformed_rfc2231_filename_still_surfaces_attachment`
- `v4_mime_oversized_boundary_fails_closed`

These tests cover the V4 roadmap slice 4 classes:

| Class | Evidence behavior |
| --- | --- |
| Malformed multipart | A multipart body without a declared boundary is classified as `MultipartStructureWithheld` with no selected body or attachments. |
| Nested multipart ambiguity | A structure beyond the configured depth limit is classified as `MultipartStructureWithheld` instead of traversing further. |
| Unsupported transfer shape | Unknown text transfer encoding is withheld as `BinaryWithheld` without rendering through an unreviewed decoder. |
| Suspicious metadata | Path-shaped filenames remain bounded attachment metadata and do not replace the safe preview body. |
| Malformed RFC 2231 metadata | A malformed extended filename is not trusted, but an attachment disposition still surfaces the part as metadata. |
| Oversized MIME control data | A boundary above the configured bound fails closed with a deterministic MIME analysis error. |

## Existing Carry-Forward Fixtures

The V4 tests build on the existing MIME fixture corpus in `tests/fixtures/mime/`,
including malformed boundaries, nested multipart attachment lookup, RFC 2231
suspicious filenames, unsupported HTML charsets, delivery-status reports,
calendar invites, and related multipart mail with inline `cid:` metadata.

## Gate Status

The V4 local safety guard requires this document and the named product-code
tests. The full `make security-check` path runs the Rust test suite before the
shell guards.

This evidence is carried by the V4 assessed code commit `09a95b7` and by the
`v4.0.0` evidence bundle at `59da020`. Any later code change that alters MIME
analysis, rendering, attachment metadata, or closeout evidence must refresh
this proof before inheriting the V4 hostile-content safety claim.
