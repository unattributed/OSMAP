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
- `nginx/templates/osmap-root.tmpl`
- `pf.anchors/macros.pf`
- `pf.anchors/selfhost.pf`

The service env files are the reviewed `mail.blackbagsecurity.com` inputs for
the split `_osmap` plus `vmail` runtime install. They are paired with the
generic launchers and `rc.d` scripts under `maint/openbsd/` and the host-side
wrappers `maint/live/osmap-live-rehearse-service-artifacts.ksh` and
`maint/live/osmap-live-rehearse-service-enablement.ksh`.

Use these artifacts when the host is ready for:

- reviewed OSMAP binary deployment into `/usr/local/bin/osmap`
- reviewed OSMAP service-artifact installation into `/etc/osmap/`,
  `/usr/local/libexec/osmap/`, and `/etc/rc.d/`
- reviewed OSMAP service installation under the split runtime users
- reviewed OSMAP browser-edge cutover

They are meant to replace hand-edited ad hoc changes during those moves.
