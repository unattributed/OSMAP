# V12 OpenPGP GPGME Availability Proof

V12 Slice 6 proves that the development environment exposes GPGME metadata before any OpenPGP cryptographic helper implementation starts.

This slice is a dependency remediation and evidence slice only. It does not decrypt, verify signatures, sign, encrypt, parse PGP/MIME, prompt for passphrases, list secret keys, access private key material, or expose browser OpenPGP controls.

## Required result

A successful Slice 6 evidence run must show that GPGME metadata is available through `pkg-config gpgme` and that a compile/link probe against `<gpgme.h>` succeeds.

The preferred Debian or Parrot package set is:

```text
pkg-config
libgpgme-dev
```

The preferred OpenBSD package set is:

```text
pkgconf
gpgme
```

Package installation is operator-controlled. The runner attempts remediation only when `OSMAP_INSTALL_GPGME_DEPS=1` is set.

## Boundary preserved

A successful Slice 6 report proves these constraints:

- GPGME is the preferred future OpenPGP runtime binding.
- GPGME metadata is available before runtime helper implementation begins.
- Direct `gpg` runtime cryptographic fallback remains forbidden.
- Runtime OpenPGP cryptographic operations remain disabled.
- The browser-facing request handler still does not touch keys, passphrases, decrypted plaintext, raw message bodies, or trusted HTML derived from decrypted content.

The known V3 stale live evidence release blocker remains carried forward until final release evidence is refreshed.
