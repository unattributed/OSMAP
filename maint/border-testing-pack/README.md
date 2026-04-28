# OSMAP Border Testing Pack

This pack performs safe, evidence-producing border checks for the public OSMAP
interface and the adjacent OpenBSD mailstack posture on `mail.blackbagsecurity.com`.

It complements the WSTG pack. The WSTG pack validates OWASP WSTG and ASVS
controls for the OSMAP application. This pack adds MITRE ATT&CK and OWASP Top
10 oriented perimeter assurance.

## Scope

- Public target: `https://mail.blackbagsecurity.com`
- SSH-assisted host target: `mail.blackbagsecurity.com`
- Local backend reference repo: `/home/foo/Workspace/openbsd-mailstack`
- Primary MITRE technique: `T1071.001` Application Layer Protocol: Web Protocols
- Additional ATT&CK coverage includes public application exposure, external
  remote services, service discovery, ingress tool transfer, and exfiltration
  over web-like channels where safe to validate.
- OWASP Top 10 coverage is mapped in `mitre-owasp-border-mapping.json`.

## Safety Limits

The suite is intentionally bounded. It does not:

- run destructive tests
- perform denial-of-service testing
- run broad internet scans
- attempt credential stuffing or password attacks
- execute malware or emulate a live C2 implant
- send production email
- log into adjacent control-plane tools

It uses deterministic HTTP requests, bounded TCP connect checks, read-only SSH
commands, local repo review, and one benign purple-team logging marker.

## Setup

```bash
cd /home/foo/Workspace/OSMAP/maint/border-testing-pack
cp .env.example .env
```

The default SSH host is `mail.blackbagsecurity.com`. The short `mail` alias is
not assumed because it may not exist from mobile-tethered or collaborator
networks.

## Running

Public-only checks:

```bash
./run.sh
```

Full border checks with read-only host evidence:

```bash
./run.sh --include-host
```

Run one mapped check:

```bash
./run.sh --include-host --test-id OSMAP-BORDER-LOG-001
```

## Purple-Team Logging Check

`OSMAP-BORDER-LOG-001` creates a unique benign marker in an HTTP request from
the operator's current network path, then uses SSH to look for the marker in
backend logs on `mail.blackbagsecurity.com`.

The required success artifact is the nginx access log entry. Suricata and pf
context is collected where available, but TLS inspection is not assumed.

## Outputs

Each run creates a timestamped output directory containing:

- `summary.json`
- `report.md`
- redacted request and response evidence
- host-side command evidence when `--include-host` is used

The runner exits nonzero on confirmed failures. Warnings mean the test completed
but found an inconclusive or partially degraded assurance signal.

## Adding A Test

1. Add an entry to `mitre-owasp-border-mapping.json`.
2. Add a matching method in `run-border-pack.py`.
3. Keep probes scoped to `mail.blackbagsecurity.com`.
4. Produce evidence under the run directory.
5. Avoid secrets, credentials, destructive behavior, and unbounded request loops.
