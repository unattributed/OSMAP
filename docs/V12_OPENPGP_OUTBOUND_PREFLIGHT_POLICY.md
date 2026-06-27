# V12 OpenPGP outbound preflight policy model

V12 Slice 12 defines a non-cryptographic outbound OpenPGP preflight policy model.

The model exists to make send-time policy decisions explicit before any encryption, signing, or PGP/MIME construction code exists.

## Policy decisions

- `allow_required_all_recipient_keys_present`: encryption is required and all recipient key policies resolve to exactly one explicit configured fingerprint.
- `fail_closed_missing_recipient_key_policy`: encryption is required and at least one recipient has no configured recipient key policy.
- `fail_closed_ambiguous_recipient_key_policy`: encryption is required and at least one recipient has multiple configured fingerprints.
- `fail_closed_encrypt_to_self_sender_key_missing`: encrypt-to-self is required but the sender account cannot be resolved to an explicit configured fingerprint.
- `fail_closed_signing_requested_sender_signing_missing`: signing is requested but sender signing capability is not available.
- `allow_unencrypted_send_by_account_policy`: encryption is not required and the account explicitly permits unencrypted send.
- `fail_closed_unencrypted_send_disallowed`: encryption is not required but the account policy does not permit unencrypted send.

## Security rules

Recipient keys are policy objects. Recipient email text, UID text, keyserver discovery, and WKD discovery are not trusted by this model.

A successful preflight decision only means a future send operation may proceed to a later OpenPGP implementation stage. It does not perform encryption, signing, helper spawning, PGP/MIME construction, or sent-message storage.

## Non-goals in this slice

Slice 12 does not implement helper spawning, PGP/MIME construction, encryption, signing, decryption, verification, passphrase handling, private-key access, browser UI controls, key discovery, WKD, keyserver lookup, or sent encrypted mail generation.
