# V12 OpenPGP Account Fingerprint Binding

V12 Slice 3 defines the account capability binding model for OpenPGP. It does not decrypt, verify signatures, sign, encrypt, prompt for passphrases, list secret keys, or expose OpenPGP controls in the browser.

## Purpose

The purpose of this slice is to prevent email-address-only key matching from becoming an authorization boundary. OpenPGP capability is available only when an account is explicitly configured with one or more full OpenPGP fingerprints.

## Binding rule

Each OpenPGP-enabled account must have:

- a canonical OSMAP account identity,
- a full primary OpenPGP fingerprint,
- an explicit list of allowed fingerprints,
- no email-address-only key lookup policy,
- no short key ID authorization,
- no implicit trust in user ID text.

A configured primary fingerprint must also be present in the account's allowed fingerprint list.

## Fail-closed behavior

The binding validator fails closed when:

- the account entry is missing,
- the account entry is duplicated,
- the account identity contains control characters or unsupported shape,
- a fingerprint is missing,
- a fingerprint is not a full hexadecimal OpenPGP fingerprint,
- a short key ID is used instead of a full fingerprint,
- the primary fingerprint is not in the allowed fingerprint list,
- email-only matching fields are present,
- user ID matching fields are present,
- key discovery or automatic recipient lookup fields are present,
- an optional diagnostics inventory is supplied and a configured fingerprint is absent from that inventory.

## What this slice does not implement

Slice 3 does not implement account UI, decryption, verification, signing, encryption, PGP/MIME parsing, passphrase handling, GPGME integration, helper sockets, or browser controls. It creates a local validation boundary that later helper and UI slices must preserve.

## Security invariant

Decrypted content is still untrusted content. Verified signed content is still untrusted content. A fingerprint binding only authorizes which local OpenPGP key material may be considered for a given OSMAP account in later slices.

## Evidence expectations

Evidence for this slice must include:

- successful validation of the example account binding file,
- regression tests proving duplicate accounts fail closed,
- regression tests proving short key IDs fail closed,
- regression tests proving email-only and user-ID matching fields fail closed,
- regression tests proving missing inventory fingerprints fail closed when an inventory is supplied,
- confirmation that no cryptographic operation is attempted.
