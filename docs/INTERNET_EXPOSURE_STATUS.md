# Internet Exposure Status

## Current Assessment

- assessment date: April 18, 2026
- assessed host: `mail.blackbagsecurity.com`
- assessed host checkout: `~/OSMAP`
- assessed host snapshot for the current repo-owned exposure report: `03d9e75`
- current repo-owned host artifacts:
  - `maint/live/latest-host-edge-cutover-session.txt`
  - `maint/live/latest-host-edge-cutover-report.txt`
  - `maint/live/latest-host-internet-exposure-report.txt`
  - `maint/live/latest-host-v2-readiness-report.txt`
- current result: `not approved for direct public browser exposure`

## Why The Result Is Not Approved Yet

The current host no longer matches the earlier staged Roundcube-at-root posture.
The reviewed OSMAP edge cutover is now applied and validator-proven. The
remaining reason the repo-owned exposure assessment still returns
`not approved` is narrower:

- the repo-owned exposure assessment still records
  `nginx_control_plane_allowlist_is_limited_to_wireguard_and_loopback`
- that allowlist is intentionally still narrow for control-plane and operator
  routes
- the public OSMAP root does not depend on that control-plane allowlist, so
  the remaining work is an explicit approval decision and any follow-on
  refinement of the exposure assessor, not a broken browser-edge deployment

That means the host has reached the reviewed cutover posture, but the repo does
not yet auto-promote it to an approved direct-public result.

## What Is Already True

The current state is not a blank slate:

- HTTP on port `80` redirects to HTTPS except for ACME challenge handling
- the active nginx TLS template enforces `TLSv1.2` and `TLSv1.3`, disables
  session tickets, and sets HSTS
- the repo-owned Version 2 readiness gate passed on `mail.blackbagsecurity.com`
  and the current report is archived at
  `maint/live/latest-host-v2-readiness-report.txt`
- the reviewed canonical HTTPS edge cutover is now applied on the validated
  host and the current edge report is archived at
  `maint/live/latest-host-edge-cutover-report.txt`
- the canonical HTTPS vhost now serves OSMAP at `/` through
  `/etc/nginx/templates/osmap-root.tmpl`, not Roundcube
- HTTPS now listens on `127.0.0.1:443`, `10.44.0.1:443`, and
  `192.168.1.44:443`
- PF now permits public ingress to TCP `443` while keeping the other end-user
  mail-client ports blocked on WAN
- the repo-owned internet-exposure assessment wrapper now exists and can
  produce a current host report without depending on operator memory alone
- the current repo-owned exposure report now records the actual post-cutover
  `mail` host posture for snapshot `03d9e75`
- incident handling, pilot, rollback, and hostile-path guidance now exist in
  repo-owned docs
- OSMAP host-side least-privilege assumptions are already present on the
  validated host, including `_osmap`, `vmail`, and the dedicated Dovecot auth
  and userdb listeners
- the repo now also has a reviewed host-side service-enablement path for the
  split `_osmap` plus `vmail` runtime install before edge cutover
- the repo now also has a reviewed host-side binary-deployment path that can
  build, stage, install, and restore `/usr/local/bin/osmap` before the service
  install is attempted
- that reviewed binary-deployment path has now been applied on the validated
  host, and the current service report confirms `service_binary_state=installed`
  for snapshot `70fa951`
- the repo now also has a reviewed host-side runtime-group provisioning path
  that can create `osmaprt`, add `_osmap` to it, and restore the prior
  supplementary-group state without widening `_osmap` into `vmail`
- that reviewed runtime-group provisioning path has now been applied on the
  validated host, and the current service report confirms both
  `shared_group_line=osmaprt:...` and `_osmap` membership in `osmaprt` for
  snapshot `0b73b8a`
- the repo now also has a reviewed host-side service-artifact path that can
  install the reviewed env files, launchers, and `rc.d` scripts without
  mixing in service startup
- that reviewed service-artifact path has now been applied on the validated
  host, and the current service report confirms the reviewed `/etc/osmap`,
  `/usr/local/libexec/osmap`, and `/etc/rc.d` files are installed for
  snapshot `5a6bfde`
- the repo now also has a reviewed host-side service-activation path that can
  create the reviewed state/runtime directories, start both OSMAP services,
  and immediately rerun the service validator
- that reviewed service-activation path has now been applied on the validated
  host, and the current service report confirms a healthy persistent loopback
  OSMAP runtime for snapshot `6c92c4d`
- the repo now also has a host-side validator for that persistent service
  install, with the current host report archived at
  `maint/live/latest-host-service-enablement-report.txt`
- the current archived service-artifact apply session is
  `maint/live/latest-host-service-artifact-session.txt`
- the current archived service-activation apply session is
  `maint/live/latest-host-service-activation-session.txt`

## What Must Happen Before Approval

Before this status can move to an approved direct-public result, the repo and
the validated host still need both of the following:

- an explicit operator approval decision that the current reviewed edge,
  rollback path, and post-cutover readiness evidence are sufficient for the
  intended direct-public use
- a decision on whether the remaining exposure-assessment blocker should stay
  as an approval hold or be narrowed so it only evaluates control-plane routes
  rather than the public OSMAP root

## Security Meaning

The current result should be read as:

- OSMAP Version 2 browser behavior is materially proven on the real host
- the persistent `_osmap` plus `vmail` loopback runtime is now present and
  validator-proven on the real host
- the reviewed browser edge is now deployed on the validated host
- the current remaining exposure hold is about explicit approval and precise
  exposure-gate interpretation, not about a failed edge cutover or broken V2
  runtime

That is a tighter and more advanced state than the earlier staged posture, but
it is still not the same thing as a completed approval decision.
