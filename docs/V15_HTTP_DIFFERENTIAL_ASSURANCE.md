# V15 HTTP Edge/Origin Differential Assurance

## Purpose

OSMAP accepts browser traffic through nginx and then parses the forwarded
HTTP/1.1 request itself. The security boundary is therefore the combined
interpretation of the edge and origin, not either parser in isolation.

The V15 differential harness preserves the exact request bytes and records:

- source-parser acceptance or rejection through a Rust parser oracle
- raw edge response status, headers, connection closure, and response count
- raw direct-origin response over the OpenBSD loopback listener
- nginx and OSMAP log lines containing the per-case run token
- the required strict origin policy and edge policy for every corpus case

## Repository Components

- `examples/osmap-http-parser-oracle.rs`
- `maint/security/osmap-v15-http-differential.py`
- `maint/security/test-osmap-v15-http-differential.py`
- `maint/security/v15-http-differential-corpus.json`

These components add no runtime dependency and do not alter the server-rendered,
JavaScript-free browser surface.

## Two-Stage Use

### Offline inventory

The offline mode runs all 37 byte cases through the source parser oracle. It
records required-policy findings without failing the harness process when
`--enforcement inventory` is selected.

This mode is used when admitting or reviewing the harness itself. A finding
is evidence that parser remediation is required, not evidence that the
harness malfunctioned.

### Live required-policy campaign

The live mode sends the same rendered bytes to:

1. `mail.blackbagsecurity.com:443` using validated TLS and SNI
2. the active OSMAP loopback listener at `127.0.0.1:8080` through the
   authorised SSH connection to `mail`
3. the local source parser oracle

The live campaign also captures matching nginx and OSMAP log evidence using
a unique non-secret query token. It does not use credentials, session
cookies, CSRF tokens, or state-changing payloads.

Live execution must use `--enforcement required-policy`. Any required-policy
disagreement returns non-zero and blocks acceptance until reviewed.

## Corpus Classes

The corpus covers:

- canonical controls
- request-line whitespace
- CRLF, bare-LF, and mixed line termination
- obsolete folding and invalid field names
- Host authority requirements
- duplicate, conflicting, comma-list, and malformed Content-Length
- Transfer-Encoding and CL/TE combinations
- truncated, excess, and pipelined bytes
- GET/POST body rules
- request-target normalization
- request-line, field, and header-block limits

Cases explicitly marked `MEASURE` are retained as evidence until the edge
and origin policy is reviewed. They are not silently converted to PASS.

## Evidence Handling

Reports contain base64-encoded raw request bytes and bounded response bodies.
They contain no credentials or session material. The live bundle must keep
the host log capture and JSON result together with the SHA-256 evidence
manifest.

## Acceptance Boundary

The harness implementation can be accepted when its self-tests, offline
inventory, and normal OSMAP gates pass. Parser conformance is accepted only
after a separate live campaign runs the complete corpus with required-policy
enforcement.
