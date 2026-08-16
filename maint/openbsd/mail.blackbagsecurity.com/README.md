# mail.blackbagsecurity.com Edge Artifacts

This directory carries the reviewed edge-cutover artifacts for the validated
`mail.blackbagsecurity.com` host shape.

These files are intentionally host-specific. They are not generic nginx or PF
examples. They are the repo-owned replacements and additions referenced by
`docs/EDGE_CUTOVER_PLAN.md` for the real Version 2 browser-edge move on the
validated host.

The current artifact set is:

- `etc/osmap/osmap-serve.env`
- `etc/osmap/osmap-mailbox-helper.env`
- `nginx/sites-enabled/main-ssl.conf`
- `nginx/conf-enabled/10-osmap-public-edge.conf`
- `nginx/templates/osmap-root.tmpl`
- `nginx/templates/osmap-public-root.tmpl`
- `newsyslog/osmap-public.conf`
- `pf.anchors/macros.pf`
- `pf.anchors/selfhost.pf`

The nginx HTTPS artifact intentionally separates the public WAN listener from
the private/control listeners:

- `192.168.1.44:443` is OSMAP-only and includes only shared TLS policy plus
  `osmap-public-root.tmpl`
- `127.0.0.1:443` and `10.44.0.1:443` retain adjacent private/control
  templates such as SOGo, PostfixAdmin, PF dashboards, Rspamd, and operator
  portals
- both HTTPS server blocks reject unexpected `Host` headers with HTTP `421` so
  the listener default cannot serve OSMAP or private routes for arbitrary names
- the public access log records normalized paths without query strings,
  referrers, cookies, or client-supplied forwarding chains
- public OSMAP logs are retained as `root:wheel` mode `0640`
- a conditional differential log records method, complete test target,
  authority, and upstream outcome only for bounded `OSMAPS04-*` corpus tokens
- OSMAP locations close the client connection after one response so queued
  pipelined bytes cannot create a second origin request
- public requests have conservative per-source request and connection limits;
  application throttling remains authoritative for authentication decisions

Do not merge those listeners back into one server block. PF can only open TCP
`443`; nginx is the path-level boundary that keeps public HTTPS limited to
OSMAP.

The service env files are the reviewed `mail.blackbagsecurity.com` inputs for
the split `_osmap` plus `vmail` runtime install. They are paired with the
generic launchers and `rc.d` scripts under `maint/openbsd/` and the host-side
wrappers `maint/live/osmap-live-rehearse-service-artifacts.ksh` and
`maint/live/osmap-live-rehearse-service-activation.ksh`.

## TLS note

The current live certificate at
`/etc/ssl/mail.blackbagsecurity.com.fullchain.pem` is a Let's Encrypt E7 leaf
that does not advertise an OCSP responder URL in its Authority Information
Access extension.

That means OCSP stapling is not currently implementable for this exact host
certificate chain with either direct nginx stapling or an OpenBSD
`ocspcheck`-generated staple file. The repo-owned validator
`maint/live/osmap-live-validate-nginx-ocsp-stapling.ksh` is the authoritative
check for this prerequisite and should be run before attempting any stapling
configuration change on this host.

Use these artifacts when the host is ready for:

- reviewed OSMAP binary deployment into `/usr/local/bin/osmap`
- reviewed OSMAP service-artifact installation into `/etc/osmap/`,
  `/usr/local/libexec/osmap/`, and `/etc/rc.d/`
- reviewed OSMAP service-activation into the persistent `_osmap` plus `vmail`
  runtime
- reviewed OSMAP service installation under the split runtime users
- reviewed OSMAP browser-edge cutover

They are meant to replace hand-edited ad hoc changes during those moves.
