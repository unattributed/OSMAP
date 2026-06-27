# V12 OpenPGP GPGME Helper Compile Scaffold

## Purpose

Slice 7 adds a compile and link only scaffold for the future `osmap-openpgp-helper` boundary.

This slice proves that a narrow helper-shaped source file can be compiled and linked against GPGME after Slice 6 proved dependency availability. It does not implement OpenPGP message processing.

## Boundary

The Slice 7 scaffold is intentionally non-cryptographic.

It must not:

- decrypt messages
- verify signatures
- sign messages
- encrypt messages
- parse PGP/MIME
- list secret keys
- access private key material
- prompt for passphrases
- store passphrases
- expose browser UI controls
- call direct `gpg` runtime crypto as a fallback

The scaffold may include GPGME headers and link against GPGME so later slices can add helper implementation behind a narrow protocol boundary.

## Evidence required

A valid Slice 7 evidence run includes:

- Slice 6 dependency availability carried forward
- `pkg-config gpgme` metadata available
- a successful compile and link probe for the helper scaffold source
- scanner proof that forbidden OpenPGP operations are absent from the scaffold
- `make v12-check`
- `make v12-check` with GPGME required
- `cargo fmt --check`
- `cargo test --all-features`
- `cargo clippy --all-targets`
- `cargo audit`
- `make security-check`
- optional carried-forward `make release-check` output

The known stale V3 live evidence release blocker remains outside Slice 7 scope.

<!-- OSMAP:V12-SLICE8-HELPER-INVOCATION:START -->

## Slice 8 helper invocation scaffold

Slice 7 proved the GPGME-linked helper compile scaffold. Slice 8 adds protocol-only helper invocation evidence. The invoked helper remains non-cryptographic and must not be treated as implemented OpenPGP mail handling.

<!-- OSMAP:V12-SLICE8-HELPER-INVOCATION:END -->
