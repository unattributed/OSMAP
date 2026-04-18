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
  - `maint/live/latest-external-browser-path-verification.txt`
  - `maint/live/latest-host-auth-observability-report.txt`
- current result: `approved for limited direct public browser exposure`

## Why The Result Is Approved

The current host no longer matches the earlier staged Roundcube-at-root posture.
The reviewed OSMAP edge cutover is now applied and validator-proven, and the
repo-owned internet-exposure assessment now evaluates the public OSMAP root
separately from intentionally narrower control-plane routes.

- the current repo-owned exposure report records
  `nginx_control_plane_allowlist_is_limited_to_wireguard_and_loopback`
- that allowlist is intentionally still narrow for control-plane and operator
  routes
- the public OSMAP root does not depend on that control-plane allowlist
- the repo now records that narrower control-plane posture as an advisory
  finding rather than a blocker for the public OSMAP browser surface

That means the validated host has reached the reviewed cutover posture and is
approved for limited direct public browser exposure under the current recorded
conditions.

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
  `mail` host posture for snapshot `d1c1a2f`
- the repo now also has an outside-in browser-path verification artifact from a
  system outside the WireGuard-only management plane, archived at
  `maint/live/latest-external-browser-path-verification.txt`
- that outside-in proof confirms the public HTTPS root redirects to the OSMAP
  login page with a valid certificate and the expected username, password, and
  `totp_code` form fields
- the repo now also has a host-side auth-observability validator that confirms
  login failures are captured into the reviewed serve audit log instead of
  disappearing into `/dev/null`
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

## Approval Conditions

This limited direct-public approval holds only while all of the following stay
true:

- the canonical HTTPS root continues to serve OSMAP through the reviewed edge
  shape in `maint/live/latest-host-edge-cutover-report.txt`
- the full Version 2 readiness gate continues to pass, as recorded in
  `maint/live/latest-host-v2-readiness-report.txt`
- WAN `443` remains intentionally enabled while the other end-user mail-client
  ports remain blocked on WAN
- control-plane and operator-only routes remain separately restricted
- the rollback path in `EDGE_CUTOVER_PLAN.md` remains ready to restore the
  narrower posture quickly

## Security Meaning

The current result should be read as:

- OSMAP Version 2 browser behavior is materially proven on the real host
- the persistent `_osmap` plus `vmail` loopback runtime is now present and
  validator-proven on the real host
- the reviewed browser edge is now deployed on the validated host
- the current narrower control-plane allowlist is intentional and remains an
  advisory condition, not a blocker for the public OSMAP browser root

That is the recorded limited-approval state for the current validated host.
