# HTTP Hardening Baseline

## Purpose

This document records the current hardening posture for the first OSMAP
HTTP/browser runtime.

The goal is to keep the browser boundary explicit, minimal, and compatible with
the OpenBSD deployment strategy already selected for the project.

## Status

As of March 27, 2026, the runtime now has a real browser surface plus the first
round of HTTP-specific hardening controls:

- loopback-only listener defaults in development
- strict response headers on HTML and redirect responses
- `HttpOnly` and `SameSite=Strict` session cookies
- `Secure` cookies outside development
- session-bound CSRF tokens on current state-changing form routes
- server-rendered HTML with escaped message rendering and no client-side
  scripting dependency

This is a useful baseline, not the final hardening endpoint.

## Current Browser Protections

The current browser runtime enforces:

- bounded request header and body sizes
- bounded form field counts
- cache suppression for sensitive pages and redirects
- a restrictive content-security policy
- `Referrer-Policy: no-referrer`
- `X-Content-Type-Options: nosniff`
- `X-Frame-Options: DENY`
- explicit logout revocation instead of cookie deletion alone

The current HTML rendering path stays deliberately small and keeps message
content escaped or plain-text-first unless a later slice proves a broader
policy safely.

## Current CSRF Strategy

The current CSRF model uses one token derived for each persisted session record.

That token is:

- stored alongside the bounded session record
- rendered into state-changing forms
- required for `POST /send`
- required for `POST /logout`
- compared with a constant-time byte comparison helper

This model keeps CSRF tied to the existing session lifecycle instead of adding
an unrelated browser-state store.

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

## Early OpenBSD Confinement Feasibility

The current runtime shape is now concrete enough to map its likely confinement
needs.

Today the process needs to:

- read configuration from environment variables
- bind a local TCP listener
- read and write bounded state under the configured OSMAP state tree
- execute `/usr/local/bin/doveadm` for auth and mailbox reads
- execute `/usr/sbin/sendmail` for outbound submission

That means any future confinement work must account for both filesystem access
and controlled process execution. A realistic early evaluation target is:

- `unveil(2)` for the configured state tree plus the required executable paths
- `pledge(2)` with a promise set that preserves local TCP serving, bounded file
  I/O, and child-process execution

The exact promise set is not being claimed as finished here, because the
runtime still needs more live validation first. The important point is that the
required access graph is now small enough to reason about concretely.

## What This Baseline Does Not Yet Claim

This baseline does not mean:

- public-internet exposure is now the default
- nginx configuration is finalized for production
- the current listener is concurrent or high-throughput
- `pledge(2)` or `unveil(2)` are already enforced in code
- attachment downloads or uploads are hardened
- CSRF coverage exists beyond the currently implemented form routes

Those remain active hardening and integration work, not solved problems.
