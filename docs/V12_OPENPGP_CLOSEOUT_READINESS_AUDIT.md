# V12 OpenPGP closeout readiness audit

V12 Slice 14 is a closeout readiness audit for the non-cryptographic OpenPGP foundation completed through Slice 13.

This slice does not add OpenPGP runtime functionality. It verifies that the V12 documentation, Makefile gates, security-check integration, helper boundary scaffolds, policy models, and known limitations remain aligned before any future cryptographic implementation slice.

## Readiness assertions

- All V12 OpenPGP gates are present in `make v12-check`.
- All V12 OpenPGP gates are present in `make security-check`.
- V12 claims remain bounded to policy, diagnostics, helper protocol scaffolding, compile/link proof, typed helper-client planning, and non-cryptographic policy models.
- Browser handlers do not touch OpenPGP key material.
- Helper process spawning is not enabled by V12.
- PGP/MIME parsing is not enabled by V12.
- Decrypt, verify, sign, and encrypt paths are not enabled by V12.
- Passphrase handling is not implemented by V12.
- Private-key access is not implemented by V12.
- Browser UI controls are not implemented by V12.
- Decrypted-content rendering is not implemented by V12.
- The Rust helper client and protocol-only helper share exact schemas, request
  fields, limits, operations, and full-fingerprint validation.
- Executable Rust tests prove that malformed, ambiguous, mismatched, or
  runtime-crypto helper responses fail closed.
- The stale V3 live evidence `make release-check` blocker remains carried forward and outside the V12 OpenPGP foundation acceptance boundary.

## Closeout boundary

V12 is a foundation sprint. It prepares the trust boundary, policy gates, helper protocol discipline, and evidence model required before real OpenPGP cryptographic implementation. Any future cryptographic implementation must be a separate sprint or explicitly scoped slice with fresh evidence.

## Closeout remediation

The final code and security audit found that the initial Rust boundary checked
helper output with string markers, used a request field that did not match the
protocol-only helper, accepted a caller-selected helper path, and had no
executable Rust behavior tests. Those defects could have allowed malformed or
mismatched helper data to satisfy a future integration check.

The remediated foundation now:

- serializes and deserializes versioned JSON with strict typed structures;
- rejects duplicate fields, unknown fields, wrong schemas, wrong operations,
  helper rejection, runtime-crypto claims, unexpected stderr, and oversized
  output;
- uses one fixed helper install path and exact protocol argument;
- requires a full 40-byte or 64-byte hexadecimal fingerprint for policy
  checks;
- aligns the Rust request field, helper request field, schemas, and byte
  limits; and
- runs executable Rust tests plus the protocol-only helper adversarial matrix.

## Future work not completed by V12

Future slices may implement PGP/MIME parsing, helper process execution, GPGME cryptographic operations, inbound decryption and verification, outbound encryption and signing, encrypt-to-self, account UI controls, and secure decrypted-content rendering. None of those are enabled by this slice.
