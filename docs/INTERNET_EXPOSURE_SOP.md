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
- `ksh ./maint/live/osmap-live-validate-edge-cutover.ksh` after the edge move

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

The standard off-host outside-in evidence artifact is:

- `maint/live/latest-external-browser-path-verification.txt`

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
5. If the host claims to have applied the OSMAP edge move, run the repo-owned
   edge-cutover verifier too and keep its report with the exposure review.
6. From a system outside the WireGuard-only management plane, perform one real
   HTTPS browser-path verification against `https://mail.blackbagsecurity.com/`
   and archive the resulting redirect, login-page, TLS, and routing evidence
   under `maint/live/latest-external-browser-path-verification.txt`.
7. Compare those observed host facts against every section in
   `INTERNET_EXPOSURE_CHECKLIST.md`.
8. Update `INTERNET_EXPOSURE_STATUS.md` so it records:
   - the exact assessment date
   - the assessed host
   - the assessed repo snapshot
   - whether direct public browser exposure is approved or not approved
   - the factual blockers or conditions attached to that result
   - any advisory findings that apply only to separately restricted
     control-plane or operator routes
9. If the result remains `not approved`, keep the current staged posture and
   record the narrowest concrete next requirements.
10. If the result becomes `approved`, record the exact public edge shape, the
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

The standard outside-in confirmation uses a non-management path:

```sh
dig +short mail.blackbagsecurity.com
ip route get "$(dig +short mail.blackbagsecurity.com | tail -n 1)"
curl -sS -A 'Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/135.0 Safari/537.36' \
  -L -D /tmp/osmap-public.headers -o /tmp/osmap-public.body \
  --write-out 'remote_ip=%{remote_ip}\nhttp_code=%{http_code}\nnum_redirects=%{num_redirects}\nurl_effective=%{url_effective}\nssl_verify_result=%{ssl_verify_result}\n' \
  https://mail.blackbagsecurity.com/
```

Archive the resulting route, redirect chain, login-page markers, and TLS
identity under `maint/live/latest-external-browser-path-verification.txt`.

## Standard Outcomes

Use one of these explicit outcomes:

- `not approved for direct public browser exposure`
- `approved for limited direct public browser exposure`

Avoid softer phrases such as "probably ready" or "should be fine." The point of
this SOP is to force a concrete operator decision tied to the real host and the
current repo state.

Use `approved for limited direct public browser exposure` when:

- the canonical HTTPS root serves OSMAP through the reviewed edge shape
- the public WAN HTTPS server block includes only shared TLS policy and
  `osmap-root.tmpl`
- WAN `443` is intentionally enabled
- the full Version 2 readiness gate still passes
- rollback remains available
- any remaining narrower restrictions apply only to control-plane or
  operator-only routes on loopback or WireGuard rather than the public OSMAP
  browser root

## Current Reality

As of April 18, 2026, the validated `mail.blackbagsecurity.com` host has the
reviewed OSMAP browser edge applied and still passes the full guarded Version 2
readiness gate. The remaining exposure review work is now about explicit
approval and precise recording of any control-plane-only restrictions, not
about a missing or broken public OSMAP root deployment.
