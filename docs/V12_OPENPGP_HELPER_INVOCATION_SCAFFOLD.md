# V12 OpenPGP Helper Invocation Scaffold

## Purpose

Slice 8 proves the narrow invocation shape for the future `osmap-openpgp-helper` boundary.

This slice is protocol-only. It validates JSON request and response handling, bounded helper input and output, exact argument discipline, no shell invocation, timeout handling, and fail-closed behavior for unknown operations.

## Non-goals

Slice 8 does not implement OpenPGP mail cryptography.

It does not decrypt, verify signatures, sign, encrypt, parse PGP/MIME, prompt for passphrases, list secret keys, access private keys, render decrypted content, add browser UI controls, or allow direct `gpg` cryptographic fallback.

## Helper invocation boundary

The protocol-only helper is invoked with one exact argument:

```text
osmap-openpgp-helper-protocol-only.py --protocol-only
```

The caller sends one bounded JSON object on stdin and expects one bounded JSON object on stdout. Stderr must remain non-sensitive and diagnostic only.

The allowed protocol-only operations are:

- `diagnostic_ping`
- `capability_status`
- `policy_check`

Unknown operations must fail closed.

## Safety invariants

Slice 8 requires these properties:

- helper invocation uses an exact argv list
- helper invocation does not use a shell
- request input is bounded
- response output is bounded
- timeout handling is enforced
- unknown operation fails closed
- malformed JSON fails closed
- unsupported arguments fail closed
- runtime cryptography remains disabled
- direct `gpg` cryptographic fallback remains forbidden
- browser request handlers still do not touch keys, passphrases, decrypted plaintext, raw message bodies, or trusted HTML derived from decrypted content

## Evidence expectations

The Slice 8 evidence archive must include:

- environment and tool versions
- git status before and after apply
- full source diff
- helper invocation report JSON
- helper invocation gate output
- helper invocation regression test output
- all prior V12 gates
- `make v12-check`
- `OSMAP_V12_REQUIRE_GPGME_AVAILABLE=1 make v12-check`
- cargo format, test, clippy, and audit output
- `make security-check`
- `OSMAP_V12_REQUIRE_GPGME_AVAILABLE=1 make security-check`
- optional carried-forward release-check output

The known stale V3 live evidence release blocker remains outside Slice 8 scope.
