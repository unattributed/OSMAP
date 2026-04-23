# Edge Cutover Plan

## Purpose

This document is the repo-owned operator plan for moving the canonical HTTPS
browser entry path on `mail.blackbagsecurity.com` from Roundcube to OSMAP
without widening OSMAP authority.

It defines:

- the exact nginx route replacement at the canonical mail host root
- the required listener and PF changes for direct public HTTPS browser access
- the rollback path to re-restrict or restore Roundcube without changing the
  `_osmap` plus `vmail` runtime split

It is intentionally specific to the current validated host shape.

The reviewed host-side artifact files for that cutover now live under:

- `maint/openbsd/mail.blackbagsecurity.com/nginx/sites-enabled/main-ssl.conf`
- `maint/openbsd/mail.blackbagsecurity.com/nginx/templates/osmap-root.tmpl`
- `maint/openbsd/mail.blackbagsecurity.com/pf.anchors/macros.pf`
- `maint/openbsd/mail.blackbagsecurity.com/pf.anchors/selfhost.pf`

For the host-side rehearsal and generated apply or restore scripts that use
those files from the standard `~/OSMAP` checkout, see
`EDGE_CUTOVER_REHEARSAL_SOP.md`.

## Current Host Baseline

As of April 17, 2026, the validated host still uses this edge shape:

- `/etc/nginx/sites-enabled/main-ssl.conf` includes
  `/etc/nginx/templates/roundcube.tmpl`
- the canonical HTTPS vhost listens on `127.0.0.1:443` and `10.44.0.1:443`
- nginx control-plane allow entries remain `10.44.0.0/24` and `127.0.0.1`
- `/etc/pf.anchors/selfhost.pf` blocks WAN ingress to TCP `443`
- OSMAP still runs behind nginx on `127.0.0.1:8080`

That is a valid staged posture, but it is not the intended direct-public OSMAP
posture for Version 2.

## Target Public HTTPS Posture

The intended cutover shape is deliberately narrow:

- nginx remains the only public TLS edge
- OSMAP `serve` remains loopback-only on `127.0.0.1:8080`
- OSMAP continues to run as `_osmap`
- mailbox access continues to cross the existing helper socket boundary to
  `vmail`
- direct public exposure is added only for HTTPS on the canonical OSMAP browser
  path
- WAN exposure for IMAP, submission, ManageSieve, helper sockets, and the
  loopback OSMAP listener does not expand as part of this change
- control-plane routes such as `/postfixadmin/`, `/pf/`, `/dr/`, and similar
  paths remain on the loopback and WireGuard HTTPS listeners only

## Exact nginx Route Replacement

### 1. Split The Public OSMAP Listener From Private HTTPS Listeners

In `/etc/nginx/sites-enabled/main-ssl.conf`, do not place the public WAN
listener in the same server block as private/control templates.

The public server block for `192.168.1.44:443` must include only the shared TLS
template and the OSMAP root template:

```nginx
server {
    listen 192.168.1.44:443 ssl;
    http2 on;

    server_name mail.blackbagsecurity.com;

    root /htdocs;
    index index.php index.html;

    include /etc/nginx/templates/ssl.tmpl;
    include /etc/nginx/templates/osmap-root.tmpl;
}
```

The private/control server block must keep the loopback and WireGuard listeners
separate from the WAN listener:

```nginx
server {
    listen 127.0.0.1:443 ssl;
    listen 10.44.0.1:443 ssl;
    http2 on;

    server_name mail.blackbagsecurity.com 10.44.0.1 127.0.0.1;

    include /etc/nginx/templates/ssl.tmpl;
    include /etc/nginx/templates/misc.tmpl;
    include /etc/nginx/templates/osmap-root.tmpl;
    include /etc/nginx/templates/sogo.tmpl;
    include /etc/nginx/templates/postfixadmin.tmpl;
    include /etc/nginx/templates/php-catchall.tmpl;
    include /etc/nginx/templates/stub_status.tmpl;
    include /etc/nginx/templates/pf_dashboard.locations.tmpl;
    include /etc/nginx/templates/ops_monitor.locations.tmpl;
    include /etc/nginx/templates/obsd1_dr_portal.locations.tmpl;
    include /etc/nginx/templates/rspamd.tmpl;
    include /etc/nginx/templates/brevo_webhook.locations.tmpl;
}
```

### 2. Add The OSMAP Root Template

Create `/etc/nginx/templates/osmap-root.tmpl` with this route shape:

```nginx
# OSMAP on mail.blackbagsecurity.com
# Canonical browser path:
#   https://mail.blackbagsecurity.com/

# Preserve legacy entry aliases but converge on the canonical root.
location = /mail { return 301 /; }
location = /webmail { return 301 /; }
location = /osmap { return 301 /; }
location ^~ /mail/ { return 301 /; }
location ^~ /webmail/ { return 301 /; }
location ^~ /osmap/ { return 301 /; }

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
```

This keeps the public browser path narrow and consistent with the current
OpenBSD deployment model documented in `DEPLOYMENT_OPENBSD.md` and
`HTTP_HARDENING_BASELINE.md`.

### 3. Keep Control-Plane Restrictions Separate

The cutover does not make every existing HTTPS route public.

- do not add `control-plane-allow.tmpl` to the OSMAP root location
- do keep the current allowlist posture for control-plane and operator routes
  on the private listener
- do not include private/control templates in the public WAN server block
- do not remove allow checks from unrelated nginx templates as part of this
  cutover

The goal is to expose the OSMAP browser surface, not the host control plane.

### 4. Public HTTPS Listener Shape

Keep the current local and WireGuard listeners in the private/control server
block, and keep the host egress listener in the public OSMAP-only server block:

```nginx
listen 127.0.0.1:443 ssl;
listen 10.44.0.1:443 ssl;
listen 192.168.1.44:443 ssl;
```

`server_name mail.blackbagsecurity.com` remains the canonical public browser
hostname. `10.44.0.1` and `127.0.0.1` stay on the private/control server block.
If upstream NAT or port forwarding is required, forward only TCP `443` to
`192.168.1.44:443`. Do not forward `8080`, helper sockets, IMAP, submission,
or ManageSieve as part of this change.

## Exact PF Changes For Public HTTPS

The current PF policy intentionally blocks WAN ingress to `443`. The cutover
must make one explicit exception for browser HTTPS while leaving other end-user
mail ports closed on the WAN.

### 1. Remove `443` From The WAN Blocked Set

In `/etc/pf.anchors/macros.pf`, change:

```pf
wan_blocked_tcp_svcs   = "{ 110, 143, 443, 465, 587, 993, 995, 2000, 4190, 8080, 9999 }"
```

to:

```pf
wan_blocked_tcp_svcs   = "{ 110, 143, 465, 587, 993, 995, 2000, 4190, 8080, 9999 }"
```

### 2. Add An Explicit Public HTTPS Rule

In `/etc/pf.anchors/selfhost.pf`, add this rule before the WAN blocked-port
rule:

```pf
# Public HTTPS for OSMAP at the canonical mail host root
pass in quick on $ext_if inet proto tcp from any to ($ext_if) port = 443 \
    flags S/SA synproxy state (if-bound)
```

Keep the existing WAN blocked-port rule for the remaining end-user ports.

This is intentionally narrower than opening all historical mail-client ports on
the WAN. Version 2 needs direct public browser access, not public IMAP or
submission expansion.

## Cutover Procedure

1. Confirm the candidate repo snapshot is synced to `origin/main`.
2. Re-run the current Version 2 readiness report from `~/OSMAP`.
3. Back up the active edge files on the host:
   - `/etc/nginx/sites-enabled/main-ssl.conf`
   - `/etc/nginx/templates/roundcube.tmpl`
   - `/etc/pf.anchors/macros.pf`
   - `/etc/pf.anchors/selfhost.pf`
4. Install the reviewed repo-owned cutover artifacts from
   `maint/openbsd/mail.blackbagsecurity.com/`:
   - `nginx/sites-enabled/main-ssl.conf`
   - `nginx/templates/osmap-root.tmpl`
   - `pf.anchors/macros.pf`
   - `pf.anchors/selfhost.pf`
8. Validate nginx and PF before reload:
   - `doas nginx -t`
   - `doas pfctl -nf /etc/pf.conf`
9. Reload the edge services:
   - `doas rcctl reload nginx`
   - `doas pfctl -f /etc/pf.conf`
10. Re-run:
   - `ksh ./maint/live/osmap-live-validate-edge-cutover.ksh`
   - `ksh ./maint/live/osmap-live-assess-internet-exposure.ksh`
   - the current Version 2 readiness wrapper
11. Update `INTERNET_EXPOSURE_STATUS.md` with the post-cutover result.

## Rollback And Re-Restriction

If the public OSMAP edge must be removed quickly:

1. Restore the backed-up pre-cutover edge files:
   - `/etc/nginx/sites-enabled/main-ssl.conf`
   - `/etc/pf.anchors/macros.pf`
   - `/etc/pf.anchors/selfhost.pf`
2. Remove `/etc/nginx/templates/osmap-root.tmpl` if it was only added for the
   cutover and is no longer needed.
5. Validate and reload nginx and PF:
   - `doas nginx -t`
   - `doas rcctl reload nginx`
   - `doas pfctl -nf /etc/pf.conf`
   - `doas pfctl -f /etc/pf.conf`
6. Re-run the repo-owned exposure assessment and record the host as
   re-restricted or not approved for direct public browser exposure.

Rollback must not:

- move OSMAP off `127.0.0.1:8080`
- run the browser runtime as `vmail`
- widen helper or Dovecot socket reachability
- rely on request-path privilege escalation

## Validation After Cutover

A candidate cutover is not complete until all of the following are true:

- nginx serves OSMAP at `https://mail.blackbagsecurity.com/`
- the OSMAP backend remains reachable only through nginx and loopback
- `maint/live/osmap-live-validate-edge-cutover.ksh` passes on the changed host
- the current Version 2 readiness report still passes
- the repo-owned exposure assessment reflects the new listener and PF posture
- operator rollback remains available without privilege widening

This plan is the exact operator artifact that should be followed before
`INTERNET_EXPOSURE_STATUS.md` can move to an approved direct-public result.
