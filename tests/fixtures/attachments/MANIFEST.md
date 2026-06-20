# V8 Attachment Safety Fixtures

These fixtures support V8 Slice 2. They are synthetic and intentionally small.

| Fixture | Regression objective |
|---|---|
| `safe_pdf_base64.eml` | Decode base64 attachment, preserve safe filename, preserve safe media type, force download headers |
| `quoted_printable_text.eml` | Decode quoted-printable attachment bytes without widening response headers |
| `suspicious_html_attachment.eml` | Preserve payload as download-only data while forcing browser-executable HTML to `application/octet-stream` |
| `svg_active_attachment.eml` | Force browser-executable SVG to `application/octet-stream` and keep forced-download headers |
| `generated_filename_fallback.eml` | Reject path-trusted filename metadata and generate a safe fallback filename |
| `unsupported_encoding.eml` | Fail closed for unsupported transfer encoding with public and audit reasons |
