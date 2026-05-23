# Version 3 Crypto And Transport Evidence

## Scope

This document records Slice 5 due-diligence evidence for weak cryptography and
transport security.

Mapped WSTG rows:

- `OSMAP-WSTG-CRYP-001`
- `WSTG-v42-CRYP-01` weak transport layer security
- `WSTG-v42-CRYP-03` sensitive information sent via unencrypted channels
- `OSMAP-WSTG-CRYP-002`
- `WSTG-v42-CRYP-02` padding oracle
- `WSTG-v42-CRYP-04` weak encryption

## Transport Boundary

`OSMAP-WSTG-CRYP-001` verifies the browser-facing transport boundary. Public
TLS terminates at nginx, not inside the Rust application, and OSMAP must not
weaken that host edge.

Required evidence:

- `docs/TLS_STANDARD.md` defines TLS 1.2 as the minimum allowed protocol
  version and TLS 1.3 as preferred where supported.
- The TLS standard prohibits anonymous, null, export, MD5, RC4, 3DES, DES,
  and CBC-mode legacy suites.
- `maint/security/osmap-tls-policy-guard.sh` statically rejects weak TLS drift.
- `maint/security/osmap-live-tls-standard-validate.py` proves TLS 1.0 and TLS
  1.1 rejection, TLS 1.2 with strong forward-secret AEAD only, TLS 1.3 where
  supported, certificate validation, hostname validation, and weak TLS 1.2
  cipher rejection.
- Browser `/login` evidence must be fetched over HTTPS.
- Cleartext HTTP must redirect to HTTPS or be unreachable.
- The public HTTPS response must include `Strict-Transport-Security`.
- Production session cookies are built with `Secure`, `HttpOnly`,
  `SameSite=Strict`, and `Path=/`.
- The reviewed nginx OSMAP root template forwards `X-Forwarded-Proto https`.

These checks cover sensitive credentials and session tokens at the OSMAP
browser surface without requiring live user credentials.

## Primitive Applicability

`OSMAP-WSTG-CRYP-002` records not-applicable decisions for cryptographic
primitive rows that require an application encryption/decryption surface.

Padding oracle is not applicable to the current OSMAP browser surface. OSMAP
has no application encryption/decryption primitive, no CBC decryptor, no
attacker-controlled ciphertext decrypt route, and no padding oracle surface.

Weak encryption is not applicable to the current OSMAP browser surface. OSMAP
has no custom reversible encryption and no browser-exposed encryption mode,
key wrapping, or decrypt endpoint. Current cryptographic use is limited to
TOTP HMAC-SHA1 verification, session-token randomness, and non-reversible
token references/hashes. Public transport cryptography is delegated to the
nginx TLS edge and validated by `OSMAP-WSTG-CRYP-001`.

Future trigger: if OSMAP adds an application encryption/decryption primitive,
encrypted object format, browser-exposed decrypt route, or Rust TLS endpoint,
the affected CRYP row must move from not-applicable proof to dynamic negative
testing.
