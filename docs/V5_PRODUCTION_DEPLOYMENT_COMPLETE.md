# OSMAP V5 Production Deployment Complete

Date: 2026-06-14  
Target: mail.blackbagsecurity.com  
Status: Complete

## Deployment summary

OSMAP V5 boundary hardening has been deployed to production on `mail.blackbagsecurity.com`.

V5 focused on strengthening identity, origin, host, response-header, and browser-mail boundary enforcement without expanding OSMAP toward Roundcube feature parity.

## Deployed commit

```text
927516f77dd7a92e199ced8f5f90fe894e584a48
```

## Live production binary

```text
SHA256 (/usr/local/bin/osmap) = 3b72992bb468ee08f5db120a4c1c64e6a681cbbae4b7c3dfee10a96edf032f61
```

## Production host policy

```text
OSMAP_ALLOWED_HOSTS=mail.blackbagsecurity.com
```

The host policy intentionally uses the DNS name, not a WAN IP address. This supports DDNS and WireGuard split DNS because OSMAP validates the HTTP `Host` value rather than pinning to a static IP.

## Service state after deployment

```text
osmap_serve(ok)
osmap_mailbox_helper(ok)
```

## Validation evidence

The following checks passed after deployment:

```text
public valid host:
https://mail.blackbagsecurity.com/healthz
HTTP/2 200

public invalid host:
https://attacker.invalid/healthz resolved to the same address
HTTP/2 421
```

The valid public response included V5 response-hardening headers:

```text
cross-origin-resource-policy: same-origin
referrer-policy: no-referrer
x-content-type-options: nosniff
```

Local application-level host-boundary validation also passed before public verification:

```text
valid Host: mail.blackbagsecurity.com -> 200
invalid Host: attacker.invalid -> 421
```

## Rollback artifacts retained

```text
backup binary:
/usr/local/bin/osmap.pre-v5-retry-20260614T132818Z

backup env:
/etc/osmap/osmap-serve.env.pre-v5-retry-20260614T132818Z
```

## Operational note

The initial V5 cutover attempt exposed an important deployment lesson: the service environment file must preserve the correct ownership and mode.

The required production permission model is:

```text
/etc/osmap/osmap-serve.env
root:osmaprt
0640
readable by _osmap
```

Future deployment automation must treat the binary and service environment file as one rollback unit.

## Decision

V5 boundary hardening is deployed and operational in production.

V5 production deployment is complete.
