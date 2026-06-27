# V12 OpenPGP inbound security-state model

V12 Slice 13 defines a non-cryptographic inbound OpenPGP security-state model.

The model exists to make inbound message state transitions explicit before any PGP/MIME parsing, helper invocation, decryption, verification, or rendering code exists.

## Security-state rules

- `encrypted_not_decrypted`: an encrypted message state does not imply decrypted content exists.
- `signed_not_trusted`: a signed message state does not imply signer trust or content safety.
- `verified_not_safe`: a verified signature does not make message content safe.
- `decrypted_not_renderable`: decrypted content is still hostile and is not renderable by default.
- `renderable_requires_secure_path`: renderable content requires the existing OSMAP secure rendering path.
- `failed_or_ambiguous_fails_closed`: failed or ambiguous inbound security state fails closed.
- `unsigned_unencrypted_normal_path`: unsigned and unencrypted mail remains on the existing normal rendering path and does not gain OpenPGP claims.

## Boundary requirements

Inbound OpenPGP labels are state labels only. They must not cause browser handlers to touch keys, private key material, decrypted plaintext, passphrases, helper execution, or OpenPGP runtime operations.

Verified does not mean safe. Decrypted does not mean safe. Decrypted does not mean renderable. Any future decrypted content must enter the existing secure rendering path as hostile content.

## Non-goals in this slice

Slice 13 does not implement helper spawning, PGP/MIME parsing, decryption, verification, signing, encryption, passphrase handling, private-key access, browser UI controls, key discovery, WKD, keyserver lookup, decrypted-content rendering, or message body persistence.
