# OSMAP TLS Standard

## Purpose

OSMAP is an OpenBSD-first secure webmail access platform. OpenBSD, nginx,
Postfix, Dovecot, Rspamd, PF, and the host remain authoritative for public
service exposure. OSMAP must not weaken host TLS policy.

This document defines the project-wide TLS floor for OSMAP code, validation
tooling, release evidence, and CI gates.

## Standard

OSMAP TLS Standard:

- TLS 1.2 is the minimum allowed protocol version.
- TLS 1.3 is preferred where supported.
- TLS 1.0 and TLS 1.1 are prohibited.
- SSLv2 and SSLv3 are prohibited.
- TLS 1.2 must use only strong forward-secret AEAD suites.
- Anonymous, null, export, MD5, RC4, 3DES, DES, and CBC-mode legacy suites are prohibited.
- Certificate validation and hostname verification must remain enabled in client-side validation tooling.
- The test harness must fail closed when weak TLS is detected.
- Public service validation must prove that TLS 1.0 and TLS 1.1 fail, while TLS 1.2 and TLS 1.3 succeed with acceptable cipher suites.

TLS 1.2 ciphers must provide forward secrecy and AEAD. Acceptable families are
the ECDHE or DHE suites using GCM, CCM, or ChaCha20-Poly1305. Legacy RSA key
exchange, CBC-mode TLS 1.2 suites, anonymous suites, null suites, export
suites, MD5 suites, RC4, DES, and triple-DES are not acceptable.

TLS 1.3 should remain enabled wherever the edge supports it. The standard does
not force TLS 1.3 only because OSMAP supports controlled clients that may still
require TLS 1.2, but TLS 1.2 is the floor, not a compatibility downgrade path.

## Client Validation Tooling

Python validation clients must use the platform default trust store, preserve
certificate and hostname verification, and set the minimum protocol version to
TLS 1.2 immediately after constructing the default TLS context.

Validation tooling must not use unverified TLS contexts, disable hostname
verification, disable certificate verification, or use protocol-specific legacy
constructors.

## Rust Boundary

The current OSMAP Rust application does not terminate public TLS. Public HTTPS
remains an nginx and host-edge responsibility. If Rust code later adds an
outbound or inbound TLS client/server dependency, that code must enforce this
standard explicitly and must be covered by `maint/security/osmap-tls-policy-guard.sh`.

The TLS policy guard scans repository code, including Rust sources, for
prohibited legacy protocol and cipher drift. New Rust TLS code must not add
weaker defaults or bypass this gate.

## Live Evidence

The live validator is:

```bash
python3 maint/security/osmap-live-tls-standard-validate.py --report maint/live/latest-host-tls-standard-report.json
```

The default target is `https://mail.blackbagsecurity.com`. Operators may pass a
different HTTPS URL or host as the first argument for staged or alternate
deployments.

Release evidence must prove:

- TLS 1.0 fails.
- TLS 1.1 fails.
- TLS 1.2 succeeds with a strong forward-secret AEAD cipher only.
- TLS 1.3 succeeds where supported.
- No weak legacy TLS ciphers are accepted.
- Python validation clients set minimum TLS 1.2 and keep certificate and hostname verification enabled.

Release mode must fail when this evidence is missing, stale, or fails the
standard.
