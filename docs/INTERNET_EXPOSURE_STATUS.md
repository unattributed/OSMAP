# Internet Exposure Status

## Current Assessment

- assessment date: April 17, 2026
- assessed host: `mail.blackbagsecurity.com`
- assessed host checkout: `~/OSMAP`
- assessed host snapshot for the current repo-owned exposure report: `74d9222`
- repo commit that archives that readiness report: `bbf795c`
- current repo-owned exposure report artifact:
  `maint/live/latest-host-internet-exposure-report.txt`
- current result: `not approved for direct public browser exposure`

## Why The Result Is Not Approved Yet

The current host still uses a deliberately narrow staged browser-access model:

- nginx HTTPS for `mail.blackbagsecurity.com` listens on `127.0.0.1:443` and
  `10.44.0.1:443`, not on the public WAN address
- PF in the active `selfhost` anchor allows public ingress for SSH, WireGuard,
  and SMTP on port `25`, while explicitly blocking public ingress for end-user
  ports such as `443`, `465`, `587`, `993`, and `4190`
- nginx still serves Roundcube at the canonical HTTPS root through
  `/etc/nginx/templates/roundcube.tmpl`
- the nginx control-plane allowlist currently permits only `10.44.0.0/24` and
  `127.0.0.1`
- no reviewed nginx route currently places OSMAP at the canonical hardened
  HTTPS edge for direct public browser use

Those facts mean the host is still in a controlled staged posture, not in the
intended Version 2 direct-public browser posture.

## What Is Already True

The current state is not a blank slate:

- HTTP on port `80` redirects to HTTPS except for ACME challenge handling
- the active nginx TLS template enforces `TLSv1.2` and `TLSv1.3`, disables
  session tickets, and sets HSTS
- the repo-owned Version 2 readiness gate passed on `mail.blackbagsecurity.com`
  and the current report is archived at
  `maint/live/latest-host-v2-readiness-report.txt`
- the repo-owned internet-exposure assessment wrapper now exists and can
  produce a current host report without depending on operator memory alone
- the current repo-owned exposure report now records the actual `mail` host
  posture for snapshot `74d9222`
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
- the repo now also has a host-side validator for that persistent service
  install, with the current host report archived at
  `maint/live/latest-host-service-enablement-report.txt`
- the current archived service-artifact apply session is
  `maint/live/latest-host-service-artifact-session.txt`

## What Must Happen Before Reassessment

Before this status can move to an approval result, the repo and the validated
host still need all of the following:

- the remaining service-activation path must be applied and validated so the
  reviewed runtime users, env files, launchers, and `rc.d` scripts become a
  healthy persistent loopback OSMAP runtime
- the repo-owned service-enablement validator must pass on the candidate host,
  not just confirm that reviewed service artifacts are installed
- the helper socket and loopback `127.0.0.1:8080` listener must exist before
  the browser edge is switched away from Roundcube
- the cutover steps in `EDGE_CUTOVER_PLAN.md` must be applied and validated so
  the canonical HTTPS route serves OSMAP, not Roundcube
- the PF and listener changes in `EDGE_CUTOVER_PLAN.md` must be applied so the
  chosen public HTTPS edge shape is intentional rather than accidental
- the rollback or temporary re-restriction path in `EDGE_CUTOVER_PLAN.md` must
  remain available
- an updated exposure reassessment run against the changed host shape using
  `INTERNET_EXPOSURE_SOP.md` and
  `maint/live/osmap-live-assess-internet-exposure.ksh`

## Security Meaning

The current result should be read as:

- OSMAP Version 2 browser behavior is now materially proven on the real host
- the current host is still correctly staged behind a narrow network posture
- the project must not describe the current snapshot as publicly exposed OSMAP
  until the real edge deployment and rollback story are separately reviewed

That is an honest staged state, not a contradiction.
