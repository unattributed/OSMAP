# V12 OpenPGP Key Inventory And Diagnostics

## Status

This is a diagnostics only slice. It does not implement OpenPGP decryption, signature verification, signing, encryption, key discovery for delivery, account binding, or UI controls.

## Purpose

Slice 2 establishes a safe local diagnostic surface for OpenPGP prerequisites before any cryptographic message operation is connected to OSMAP.

The diagnostic goal is to answer these questions without crossing the private-key boundary:

- Is `gpg` available for local OpenPGP public key inspection?
- Is the preferred GPGME toolchain visible through `gpgme-config` or `pkg-config gpgme`?
- Which public primary key fingerprints are present in the local keyring?
- Which public-key capabilities and subkey counts are visible?
- Are user ID values, passphrases, secret-key records, decrypted plaintext, and signed content absent from evidence output?

## Hard safety rules

The diagnostic helper:

- must not list secret keys
- must not export any key material
- must not collect user ID values
- must not decrypt, sign, or encrypt mail
- must not prompt for or store passphrases
- must not read message bodies
- must not run from a browser request handler
- must only write sanitized local evidence chosen by the operator

The output may include public key fingerprints, public-key algorithm metadata, public-key capabilities, public key creation and expiration timestamps, user ID counts, and subkey counts. It must not include the literal user ID strings from the keyring.

## Implementation boundary

The diagnostics helper is `maint/security/osmap-v12-openpgp-diagnostics.py`. It runs as an operator tool and not as part of request handling. The V12 gate verifies the helper remains diagnostics-only.

This slice prepares later account fingerprint binding. It does not make email address matching authoritative. Slice 3 must bind account capability to explicit configured fingerprints and must fail closed for ambiguous or missing configured fingerprints.

## Evidence expectation

A valid Slice 2 evidence run includes:

- tool versions
- git branch and commit
- applied diff
- diagnostics self-test result
- sanitized live diagnostics output
- `make v12-check`
- `make security-check`
- Rust format, test, clippy, and audit results
- carried-forward `make release-check` status

The known V3 stale live evidence release blocker remains carried forward until final release evidence is refreshed.

<!-- OSMAP:V12-SLICE3-ACCOUNT-BINDING:START -->

## Slice 3 dependency on diagnostics

Slice 3 adds account binding validation that can optionally compare configured full fingerprints against the Slice 2 diagnostics inventory. When such an inventory is supplied, configured fingerprints absent from the inventory fail closed.

<!-- OSMAP:V12-SLICE3-ACCOUNT-BINDING:END -->
