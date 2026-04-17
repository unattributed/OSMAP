# Network And Exposure Analysis

## Purpose

This document records the current network exposure model that OSMAP inherits.

## Current Exposure Summary

The host is not currently exposing the full webmail surface to the public
internet. Instead, the observed policy is:

- WAN exposure for SSH
- WAN exposure for WireGuard
- WAN exposure for SMTP on port 25
- explicit WAN blocking for end-user web and mail access ports
- VPN-only access for webmail, IMAP, authenticated submission, and related user
  services

## Evidence From PF Policy

The active PF configuration explicitly documents that:

- WAN should allow only rate-limited SSH, WireGuard, and SMTP ingress
- ports such as 80, 443, 465, 587, 993, 995, 110, 143, 4190, and 8080 are
  intended to be WireGuard-only
- VPN clients are NATed out to the public internet but restricted from reaching
  certain internal address ranges

The `selfhost` anchor reinforces that policy by:

- allowing SSH from the public internet with rate limiting
- allowing WireGuard from the public internet
- blocking end-user mail and web ports on the WAN
- allowing those same ports from the WireGuard subnet

## Evidence From Live Listeners

Observed bindings support the PF policy:

- `:443` is bound to localhost and the WireGuard address, not to a public WAN
  address
- `:993`, `:465`, and `:587` are likewise bound to localhost and the WireGuard
  address
- port `25` remains openly bound for SMTP ingress

## nginx Control-Plane Policy

The nginx control-plane allowlist permits:

- `10.44.0.0/24`
- `127.0.0.1`

That means the web applications themselves are not only protected by PF. nginx
also applies an application-layer allowlist for control-plane access.

## Security Meaning

The current environment derives a substantial portion of its security from
network segmentation and VPN access. That matters for OSMAP because it means the
project is starting from a relatively conservative exposure model.

## Implications For The Replacement

- OSMAP should not assume the current staged host posture is already the final
  Version 2 browser-access posture
- Any move from the current narrow staged posture to direct public browser
  access should be treated as a separate, explicit security decision
- Identity, session, logging, and abuse controls will need to carry more weight
  if the network boundary becomes less trusted
- The safest migration path may still involve first replacing Roundcube while
  keeping the current narrow staged posture intact, but that should be treated
  as a rollout phase rather than the intended permanent Version 2 destination

## Open Questions

- Which parts of the current control plane should remain VPN-only indefinitely
- Which exact nginx, PF, and rollback changes are required before OSMAP can
  replace Roundcube at the direct public HTTPS edge
- What protections must exist before relaxing the current network boundary
