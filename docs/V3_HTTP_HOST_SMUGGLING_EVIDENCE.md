# V3 HTTP Host And Smuggling Evidence

## Scope

`OSMAP-WSTG-INPV-006` records the Slice 4 evidence lane for host-header,
incoming-request, and HTTP splitting/smuggling validation. It maps:

- `WSTG-v42-INPV-15` HTTP splitting and smuggling
- `WSTG-v42-INPV-16` HTTP incoming requests
- `WSTG-v42-INPV-17` host-header injection

The lane focuses on malformed request shapes that normal HTTP client libraries
hide, so the runner uses raw TLS requests against the public edge.

## Dynamic Evidence

The WSTG runner uses unauthenticated rejected or non-state-changing probes only:

- CL.TE request smuggling shape is rejected
- duplicate `Content-Length` headers are rejected
- encoded CRLF in the request target does not reach a successful browser route
  or create an injected response header
- missing `Host` is rejected
- obsolete folded headers are rejected
- non-normalized request targets are rejected
- duplicate `Host` headers are rejected
- malformed `Host` values with path characters are rejected
- an arbitrary untrusted `Host` value is not reflected into the response body,
  `Location`, or cookie metadata

No probe includes credentials, a real session cookie, or a valid CSRF token.

## Static Evidence

Static evidence ties the raw probes to code-level controls:

- the HTTP parser rejects duplicate headers
- HTTP/1.1 requests must include `Host`
- `Host` must not be empty, oversized, or contain path/user-info characters
- `Transfer-Encoding` is unsupported at the OSMAP parser boundary
- `Content-Length` must parse and match the body size
- request targets must be normalized and must not include fragments
- browser redirects use relative paths rather than Host-derived absolute URLs

This lane complements `OSMAP-WSTG-INPV-005`, which covers higher-level method,
content-type, and duplicate-parameter tampering.
