# V8 Mail Workflow Fixtures

These fixtures support V8 Slice 1. They are intentionally small, synthetic, and focused on regression prevention.

| Fixture | Message type | Regression objective |
|---|---|---|
| `text_plain.eml` | `text/plain` | Plain body selection, escaped browser rendering, plain-text labels |
| `text_html.eml` | `text/html` | Sanitized HTML rendering, remote-content status, active-content stripping |
| `multipart_alternative.eml` | `multipart/alternative` | Prefer-sanitized-HTML default and prefer-plain-text fallback |
| `multipart_mixed.eml` | `multipart/mixed` | Plain body selection with attachment metadata surfaced |
| `nested_multipart.eml` | nested multipart | Nested body selection and inline Content-ID metadata without inline rendering |
| `attachment_heavy.eml` | attachment-heavy mail | Body selection preserved while multiple attachment metadata rows surface |
| `malformed_mime.eml` | malformed MIME | Safe fallback without raw HTML rendering or panic |
