# Internet Exposure SOP

## Purpose

This document records the standard operator procedure for evaluating whether
the current OSMAP snapshot is ready to be described as suitable for direct
public browser access.

It exists to keep one short, repo-owned answer for:

- how to assess the current host posture on `mail.blackbagsecurity.com`
- how to tie the public-exposure decision to the current pushed repo snapshot
- how to record either a staged deferral or a limited approval honestly

`INTERNET_EXPOSURE_CHECKLIST.md` remains the control checklist. This document
does not replace that checklist. It defines the routine operator workflow for
reviewing it against the real host.

The authoritative host-side assessment entrypoint is now:

- `ksh ./maint/live/osmap-live-assess-internet-exposure.ksh`

## Standard Inputs

Use these inputs together:

- `docs/INTERNET_EXPOSURE_CHECKLIST.md`
- `docs/EDGE_CUTOVER_PLAN.md`
- `docs/INTERNET_EXPOSURE_STATUS.md`
- `docs/V2_ACCEPTANCE_CRITERIA.md`
- `docs/INCIDENT_RESPONSE_PLAN.md`
- `docs/PILOT_DEPLOYMENT_PLAN.md`
- `maint/live/latest-host-v2-readiness-report.txt`

The standard validated host is:

- `mail.blackbagsecurity.com`

The routine operator access path is:

- `ssh mail`

The standard host checkout is:

- `~/OSMAP`

## Standard Review Flow

1. Sync the local repo and the host checkout to the reviewed `origin/main`
   snapshot before collecting new evidence.
2. Confirm the current host-side OSMAP gate with the repo-owned Version 2
   rehearsal path and keep the current report archived under
   `maint/live/latest-host-v2-readiness-report.txt`.
3. Run the repo-owned host-side exposure assessment wrapper and capture its
   report.
4. Inspect the live host exposure shape further if needed, at minimum:
   - active HTTPS and HTTP listeners
   - active nginx vhost and route ownership at the canonical mail host
   - PF ingress policy for public WAN, WireGuard, and loopback
   - TLS termination behavior and redirect posture
   - rollback posture if the browser surface must be narrowed again quickly
5. Compare those observed host facts against every section in
   `INTERNET_EXPOSURE_CHECKLIST.md`.
6. Update `INTERNET_EXPOSURE_STATUS.md` so it records:
   - the exact assessment date
   - the assessed host
   - the assessed repo snapshot
   - whether direct public browser exposure is approved or not approved
   - the factual blockers or conditions attached to that result
7. If the result remains `not approved`, keep the current staged posture and
   record the narrowest concrete next requirements.
8. If the result becomes `approved`, record the exact public edge shape, the
   rollback path, and the operator conditions under which that approval holds.

## Standard Commands

These commands are the standard evidence-gathering baseline on `mail`:

```sh
ssh mail
cd ~/OSMAP
git rev-parse --short HEAD
ksh ./maint/live/osmap-live-assess-internet-exposure.ksh \
  --report "$HOME/osmap-internet-exposure-report.txt"
```

The wrapper report is the standard starting point, not the whole decision by
itself. The operator review must still connect the listener facts, nginx route
ownership, PF ingress policy, rollback posture, and the current V2 readiness
report into one exposure decision.

## Standard Outcomes

Use one of these explicit outcomes:

- `not approved for direct public browser exposure`
- `approved for limited direct public browser exposure`

Avoid softer phrases such as "probably ready" or "should be fine." The point of
this SOP is to force a concrete operator decision tied to the real host and the
current repo state.

## Current Reality

As of April 17, 2026, the current `mail.blackbagsecurity.com` posture is still
a staged narrow-exposure deployment, not a direct-public OSMAP deployment.

That is a valid current state. It should be recorded truthfully, not treated as
a failure. Version 2 intends to support direct public browser access, but only
after the explicit exposure gate is actually passed.
