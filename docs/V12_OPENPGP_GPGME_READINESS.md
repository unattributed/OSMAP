# V12 OpenPGP GPGME Readiness Gate

V12 Slice 5 validates whether the host and build environment are ready for a future GPGME-backed OpenPGP helper implementation.

This slice is a readiness and policy gate only. It does not implement decryption, signature verification, signing, encryption, PGP/MIME parsing, passphrase handling, browser UI integration, helper cryptographic operations, or private key access.

## Boundary goals

The readiness gate exists to prevent accidental drift from the approved design:

- GPGME remains the preferred runtime integration path for future OpenPGP helper work.
- Direct browser-facing calls to `gpg` are not an approved runtime design.
- Command-line `gpg` may be inspected only for version metadata in this slice.
- GPGME metadata may be inspected through `gpgme-config` or `pkg-config gpgme`.
- Missing GPGME does not enable fallback cryptography.
- Missing GPGME blocks later cryptographic helper slices until dependency readiness is proven.
- Runtime cryptographic operations remain disabled in Slice 5 even when GPGME is detected.

## Accepted Slice 5 outcomes

The gate can pass in either of these states:

1. `ready_for_gpgme_design_only`: GPGME metadata is detected. Future implementation work may proceed to a compile/link scaffold slice, but cryptographic operations remain disabled.
2. `blocked_missing_gpgme`: GPGME metadata is not detected. The project remains safe because cryptographic operations remain disabled and no fallback to direct `gpg` runtime operation is allowed.

This distinction is intentional. The slice should create truthful evidence rather than pretending GPGME is present.

## Explicitly forbidden in Slice 5

Slice 5 must not:

- list secret keys,
- decrypt a message,
- verify a message signature,
- sign a message,
- encrypt a message,
- parse PGP/MIME content,
- prompt for or store passphrases,
- collect private key material,
- emit decrypted plaintext,
- create browser-visible OpenPGP controls,
- route browser requests to key material,
- introduce direct `gpg` runtime fallback for cryptographic operations.

## Required evidence

The Slice 5 evidence archive must include:

- host and tool versions,
- repository branch and HEAD,
- GPGME readiness report JSON,
- GPGME readiness gate output,
- V12 aggregate gate output,
- cargo fmt, cargo test, clippy, cargo audit, and security-check results,
- optional carried-forward release-check output.

The known stale V3 live evidence release blocker remains outside Slice 5 readiness scope.
