# V3 HTTP Input Tampering Evidence

## Scope

`OSMAP-WSTG-INPV-005` records the Slice 4 evidence lane for HTTP method,
content-type, and duplicate-parameter tampering. It maps `WSTG-v42-INPV-03`
HTTP verb tampering and `WSTG-v42-INPV-04` HTTP parameter pollution.

The lane focuses on request-shape controls that sit before authenticated
mailbox, compose, session, settings, and message-move behavior.

## Dynamic Evidence

The WSTG runner uses unauthenticated rejected probes only:

- unsupported methods on browser routes are rejected before normal routing
- GET requests carrying a request body are rejected at the parser boundary
- POST requests to GET-only browser routes do not create alternate actions
- JSON content-type submissions to form routes are rejected
- duplicate query parameters are rejected
- duplicate URL-encoded form fields are rejected

No probe includes valid credentials, a valid CSRF token, or a real session
cookie, and no probe should perform a state-changing action.

## Static Evidence

Static evidence ties the probes to code-level controls:

- the HTTP parser admits only `GET` and `POST`
- the parser rejects GET bodies and requires POST `Content-Length`
- form-backed routes gate accepted content types explicitly
- URL query parsing rejects duplicate field names
- URL-encoded and multipart form parsing reject duplicate field names
- the browser route table keeps GET and POST handlers explicit

This lane complements `OSMAP-WSTG-CONF-004`, which records the narrower
configuration evidence that `OPTIONS` and `TRACE` are not accepted as
application methods.
