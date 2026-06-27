# V12 OpenPGP capability policy model

V12 Slice 11 defines the non-cryptographic OpenPGP capability policy model.

The model exists to prevent premature UI or cryptographic integration from appearing before account bindings, recipient policy, and hostile-content handling are explicit.

## Capability states

- `unavailable_no_account_key`: the account has no explicit configured OpenPGP fingerprint. OpenPGP controls must not be exposed.
- `available_configured_fingerprint`: the account has exactly one explicit configured primary fingerprint and account policy permits OpenPGP capability.
- `fail_closed_ambiguous_account_binding`: multiple or duplicate configured fingerprints create an ambiguous capability state and must fail closed.
- `fail_closed_recipient_key_missing`: outbound encryption is required by policy, but no usable recipient key policy is present.
- `signed_not_safe`: a verified signature can identify a signing result, but it does not make message content safe.
- `decrypted_still_hostile`: decrypted content remains hostile until it passes through the existing secure rendering path.

## Non-goals in this slice

Slice 11 does not implement helper spawning, PGP/MIME parsing, decryption, signature verification, signing, encryption, passphrase handling, private-key access, browser UI controls, decrypted-content rendering, key discovery, WKD, keyserver lookup, or automatic UID trust.
