# HTTP Hardening Baseline

## Purpose

This document records the current hardening posture for the first OSMAP
HTTP/browser runtime.

The goal is to keep the browser boundary explicit, minimal, and compatible with
the OpenBSD deployment strategy already selected for the project.

## Status

As of April 2, 2026, the runtime now has a real browser surface plus the first
round of HTTP-specific hardening controls:

- loopback-only listener defaults in development
- strict response headers on HTML and redirect responses
- `HttpOnly` and `SameSite=Strict` session cookies
- `Secure` cookies outside development
- session-bound CSRF tokens on current state-changing form routes
- a file-backed dual-bucket application-layer login-throttling check before
  the current auth backend is reached
- server-rendered HTML with conservative message rendering and no client-side
  scripting dependency
- an operator-controlled OpenBSD confinement mode for serve runtime

This is a useful baseline, not the final hardening endpoint.

## Current Browser Protections

The current browser runtime enforces:

- bounded request header and body sizes
- bounded high-risk request-header values such as `Host`, `Cookie`, and
  `Content-Type`
- bounded request-target length
- bounded request-header count
- bounded query-field counts
- bounded form field counts
- rejection of duplicate or empty query/form field names instead of silently
  overwriting earlier values
- per-connection read and write timeouts on the sequential listener
- binary-safe multipart request parsing for the current upload path
- cache suppression for sensitive pages and redirects
- a restrictive content-security policy
- `Cross-Origin-Resource-Policy: same-origin` on the current browser and
  attachment responses
- `Referrer-Policy: no-referrer`
- `X-Content-Type-Options: nosniff`
- `X-Frame-Options: DENY`
- explicit logout revocation instead of cookie deletion alone
- strict session-cookie parsing for the bearer token the runtime actually uses
- rejection of duplicate request headers instead of silently accepting the last
  one
- rejection of malformed HTTP/1.1 requests without `Host`
- rejection of empty or obviously malformed `Host` header values
- rejection of unsupported `Transfer-Encoding` request framing
- rejection of GET request bodies instead of trying to interpret them
- rejection of POST requests that omit `Content-Length`
- rejection of unsupported login/logout form content types instead of guessing
  at non-URL-encoded bodies
- rejection of non-canonical request-path forms such as repeated slashes,
  trailing-slash aliases, and dot segments
- rejection of fragment-bearing or otherwise ambiguous request targets
- normalization of peer socket addresses to bare IP strings before they reach
  auth-helper metadata or structured request audit context
- explicit distinction between parse failures, read timeouts, truncated
  requests, and empty connections in the listener lifecycle
- `408 Request Timeout` on read timeouts instead of collapsing that case into a
  generic `400 Bad Request`
- silent connection close for empty or truncated requests instead of replying to
  incomplete traffic as though it were a well-formed HTTP exchange
- bounded backoff after repeated listener accept failures instead of spinning
  hot on a broken accept loop
- thresholded escalation for sustained listener accept failures plus a recovery
  event when accepts resume
- explicit in-flight connection caps with `503 Service Unavailable` plus
  `Retry-After` when the runtime is already at capacity
- connection high-watermark and capacity-reached observability events so
  in-flight pressure is visible without an external profiler
- central request-completion logging with status, response size, and duration
  so slow requests can be observed without inferring lifecycle from route-local
  audit events alone
- richer response-write failure logging with request method/path and attempted
  response size when the request had already been parsed
- thresholded escalation for sustained response-write failures plus a recovery
  event when response writes resume

The current HTML rendering path stays deliberately small and uses either
escaped plain text or a narrow allowlist sanitizer. It still blocks external
fetches, scriptable markup, relative URLs, and richer client-side HTML
behavior.

Because the current server now uses bounded concurrent connection handling,
those read/write timeouts remain an important correctness control as well as a
convenience feature. They do not solve request-resource exhaustion on their
own, but they do reduce the risk that one slow or stalled client will hold a
worker slot open indefinitely.

The runtime now also treats incomplete connection lifecycles more explicitly.
An empty connection is logged and closed without an HTTP response, a truncated
request is logged as incomplete and closed without an HTTP response, and a read
timeout now returns `408 Request Timeout`. That keeps the server from
normalizing transport-level failure cases into the same path used for a real
malformed request.

The listener now also backs off after repeated accept failures, escalates
sustained accept-failure streaks, rejects accepted connections when it is
already at its configured in-flight cap, and emits one central completion
event for parsed requests. It also now reports new connection high-water marks
and explicit capacity-reached transitions, and it carries more context on
response-write failures, including sustained-failure escalation and recovery.
That gives OSMAP a bounded concurrency model with better operator visibility
without pretending it now has a full production queueing or worker-management
layer.

That observability posture is now also live-proven on
`mail.blackbagsecurity.com` under `enforce` with the runtime cap forced to one
in-flight connection: the host proof exercised capacity-reached,
over-capacity rejection, request-timeout, and request-completion events in one
isolated run.

That bounded observability posture is now also further live-proven through
`maint/live/osmap-live-validate-http-write-observability.ksh` on
`mail.blackbagsecurity.com` under `enforce`: repeated reset-backed
`GET /login` requests drove sustained response-write failure events, the host
reported those failures as `Broken pipe (os error 32)`, and a subsequent
normal `GET /healthz` emitted `http_response_write_recovered` after returning
`200 OK`.

## Current CSRF Strategy

The current CSRF model uses one token derived for each persisted session record.

That token is:

- stored alongside the bounded session record
- rendered into state-changing forms
- required for `POST /send`
- required for `POST /logout`
- compared with a constant-time byte comparison helper
- derived with a separate SHA-256-based label from the bearer token so it does
  not reuse the persisted session identifier value

This model keeps CSRF tied to the existing session lifecycle instead of adding
an unrelated browser-state store.

## Current Reply And Forward Posture

The current browser layer now allows reply and forward draft generation, but it
keeps those flows inside the same narrow safety posture:

- drafts are generated server-side
- they use the plain-text compose projection, not live HTML message content
- attachment context is surfaced as metadata and warnings, not as silent file
  reattachment
- bounded new file uploads are accepted only through the compose form and are
  handed to the existing submission surface as MIME attachments
- original-message attachments are still not silently reattached during reply
  or forward generation

## nginx-Facing Deployment Shape

The current deployment model continues to assume:

- `nginx` terminates TLS
- OSMAP listens only on a local loopback address
- the public edge never reaches OSMAP directly from the network
- the browser app remains behind one narrow reverse-proxy entrypoint

The current prototype only supports a TCP listener, so the practical first
deployment shape is loopback TCP rather than a Unix socket.

Example staging shape:

```nginx
server {
    listen 443 ssl http2;
    server_name mail.example.invalid;

    ssl_certificate /etc/ssl/mail.fullchain.pem;
    ssl_certificate_key /etc/ssl/private/mail.key;

    location / {
        limit_except GET POST { deny all; }

        proxy_pass http://127.0.0.1:8080;
        proxy_http_version 1.1;
        proxy_set_header Host $host;
        proxy_set_header X-Real-IP $remote_addr;
        proxy_set_header X-Forwarded-For $proxy_add_x_forwarded_for;
        proxy_set_header X-Forwarded-Proto https;
        proxy_buffering off;
    }
}
```

Operators can tighten this further, but this shape matches the current runtime
truthfully: small app, local listener, narrow method surface, and edge-owned
TLS.

## Current OpenBSD Confinement State

The current runtime now has a real OpenBSD confinement control:

- `disabled`
- `log-only`
- `enforce`

Today the process needs to:

- read configuration from environment variables
- bind a local TCP listener
- read and write bounded state under the configured OSMAP state tree
- execute `/usr/local/bin/doveadm` for auth and mailbox reads
- execute `/usr/sbin/sendmail` for outbound submission
- preserve restrictive permissions on session-state files as they are updated

The enforced OpenBSD mode now applies:

- a concrete `pledge(2)` promise set for serve mode
- a concrete `unveil(2)` ruleset derived from config and helper paths
- a locked unveil table before steady-state serving begins

The current ruleset is still broader than the final target because the helper
process model forces compatibility with existing libraries and mail-stack
runtime paths. The important change is that confinement is no longer only a
plan: it now exists as a tested runtime behavior on OpenBSD, and the first
narrowing pass has already replaced a blanket `/var` unveil with helper-specific
paths.

Live host validation now also proves that the current browser login route can
deny invalid credentials cleanly through a dedicated least-privilege Dovecot
auth socket under both `log-only` and `enforce`.

Live host validation now also proves that the current safe-HTML rendering and
settings routes work under `enforce` against a controlled HTML-only mailbox
message when the web runtime is kept as `_osmap` and the helper is kept at the
`vmail` boundary.

## What This Baseline Does Not Yet Claim

This baseline does not mean:

- public-internet exposure is now the default
- nginx configuration is finalized for production
- the current listener is high-throughput
- the current timeout values and connection cap eliminate denial-of-service
  risk from a small thread-per-connection runtime
- attachment downloads are fully live-host-proven or fully helper-hardened
- CSRF coverage exists beyond the currently implemented form routes
- the current unveil view is narrow enough for final adoption
- every live browser workflow is fully proven on the target host

Those remain active hardening and integration work, not solved problems.
