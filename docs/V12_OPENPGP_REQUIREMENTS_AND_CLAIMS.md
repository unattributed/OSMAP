# OSMAP V12 OpenPGP Requirement And Claims Boundary

## Status

OSMAP V12 moves OpenPGP from prior out-of-scope status into a bounded implementation track. Earlier version documents may continue to describe OpenPGP as out of scope for those releases. This document is the current V12 authority for OpenPGP requirement scope, claims, and non-claims until replaced by later V12 evidence.

## Product Language

OSMAP remains Protected by Default. Remote content blocking, link protection, sanitized HTML, attachment isolation, and explicit source viewing remain the normal behavior for message viewing. OpenPGP status indicators must not imply that decrypted or signed content is safe.

The UI must keep source viewing behind an explicit View Source button or icon control. Decryption, signature verification, signing, and encryption must not weaken the existing rendering boundary.

## Primary Requirement

Accounts with explicitly configured and usable OpenPGP keys must be able to decrypt received mail, verify signatures, sign outbound mail, and encrypt outbound mail. Accounts without configured OpenPGP keys must continue to behave normally and must not display OpenPGP controls that imply unavailable capability.

## Bounded Implementation Requirements

1. Use PGP/MIME first for inbound and outbound OpenPGP mail.
2. Prefer GPGME as the runtime integration path for OpenPGP operations.
3. Integrate OpenPGP through a narrow helper boundary, named `osmap-openpgp-helper` unless a later slice records a better equivalent.
4. Keep normal web request handlers away from private key material, passphrases, and direct cryptographic process control.
5. Bind account OpenPGP capability to explicit configured fingerprints, not email addresses alone.
6. Fail closed when more than one key matches and no explicit fingerprint is configured.
7. Treat decrypted content as untrusted message content.
8. Treat verified signatures as authenticity metadata, not content safety metadata.
9. Send decrypted content through the same secure rendering path used for ordinary mail.
10. Do not store OpenPGP passphrases in OSMAP state, logs, drafts, settings, or evidence.
11. Do not log decrypted plaintext, passphrases, private key material, or full sensitive message bodies.
12. Show OpenPGP capability only for accounts with configured and usable keys.
13. Preserve normal mailbox, rendering, compose, and send behavior for accounts without keys.
14. Fail closed when outbound account policy requires encryption and any required recipient key is missing.
15. Support encrypt-to-self for encrypted sent mail when account policy enables it.
16. Keep every OpenPGP slice paired with tests, documentation, security gates, and evidence artifacts.

## Account Binding Model

The minimum account binding unit is the OSMAP account identity plus explicit fingerprint configuration. Email address matching may be used only as a discovery or diagnostic hint. It must not be sufficient authority to decrypt, sign, or enable account OpenPGP controls.

A configured account may eventually contain these fields or their equivalent:

```text
openpgp.enabled = true
openpgp.signing_fingerprint = <full fingerprint>
openpgp.decryption_fingerprints = <full fingerprint list>
openpgp.default_sign_policy = disabled | optional | default | required
openpgp.default_encrypt_policy = disabled | optional | default | required
openpgp.encrypt_to_self = true | false
```

This document does not require this exact storage format. Later slices must preserve the explicit fingerprint and fail-closed behavior regardless of representation.

## Helper Boundary Requirements

The OpenPGP helper must be a narrow boundary that accepts bounded requests and returns structured results. It must not expose a browser-facing decrypt endpoint. It must not accept raw account names as a substitute for configured fingerprint authorization.

Minimum helper result metadata should include operation, success or failure state, recipient fingerprints, signer fingerprints where available, signature verification status, key availability status, and safe public failure reasons. Plaintext may be returned only to the OSMAP server process path that immediately feeds the existing rendering pipeline. Plaintext must not be persisted.

## Rendering Requirement

Decrypted content must be rendered as hostile message content. Sanitized HTML, plain text escaping, remote content blocking, link protection, Content Security Policy behavior, and attachment isolation remain mandatory. A verified signature must not bypass sanitizer, MIME limits, attachment policy, or source-view controls.

## Claims Allowed After Slice 1

After this documentation slice, OSMAP may claim only that V12 has a documented OpenPGP requirement and claims boundary. It must not claim implemented OpenPGP decryption, verification, signing, encryption, key discovery, account binding, or UI integration until later slices provide code and evidence.

## Non-Claims

OSMAP V12 does not claim Proton-style zero-access storage, browser-side cryptography, automatic trust in signed content, automatic key discovery as authorization, malware detection, attachment safety based on cryptographic status, private key backup, passphrase management, web-of-trust policy enforcement, WKD trust automation, or universal OpenPGP compatibility.

## Slice Ownership

Slice 1 is documentation and governance only. Slice 2 may introduce non-sensitive key inventory diagnostics. Slice 3 may introduce account fingerprint binding. Decrypt, verify, sign, encrypt, and UI work must remain out of claim scope until their dedicated slices pass evidence review.

<!-- OSMAP:V12-SLICE2-DIAGNOSTICS:START -->

## Slice 2 key inventory and diagnostics status

Slice 2 adds diagnostics only. It provides a local operator diagnostic helper for OpenPGP public key inventory and toolchain visibility. It does not implement decryption, signature verification, signing, encryption, account binding, key discovery for delivery, or UI integration.

The diagnostics helper must not list secret keys, collect user ID values, prompt for passphrases, decrypt messages, sign messages, encrypt messages, or run from a browser request handler. Its output is limited to public key fingerprints, public key metadata, user ID counts, subkey counts, toolchain status, and explicit safety invariant booleans.

Slice 3 remains responsible for account capability binding by explicit configured fingerprints and fail-closed ambiguous-key behavior.

<!-- OSMAP:V12-SLICE2-DIAGNOSTICS:END -->

<!-- OSMAP:V12-SLICE3-ACCOUNT-BINDING:START -->

## Slice 3 account fingerprint binding status

Slice 3 adds account fingerprint binding validation only. It proves that OpenPGP capability must be configured by explicit full fingerprints and that email-only matching, user-ID matching, short key IDs, duplicate account bindings, and missing inventory fingerprints fail closed.

Slice 3 still does not implement decryption, signature verification, signing, encryption, helper cryptographic operations, passphrase handling, PGP/MIME parsing, or browser UI integration.

<!-- OSMAP:V12-SLICE3-ACCOUNT-BINDING:END -->

<!-- OSMAP:V12-SLICE4-HELPER-PROTOCOL:START -->

## Slice 4 helper protocol status

Slice 4 adds a testable non-cryptographic OpenPGP helper protocol scaffold. It proves that later helper work must consume validated account fingerprints, reject unknown operations, keep browser request handlers away from key material, and avoid plaintext, passphrase, private-key, raw-message, or trusted-HTML fields in protocol evidence.

Slice 4 still does not implement decryption, signature verification, signing, encryption, helper cryptographic operations, passphrase handling, GPGME runtime integration, PGP/MIME parsing, or browser UI integration.

<!-- OSMAP:V12-SLICE4-HELPER-PROTOCOL:END -->

<!-- OSMAP:V12-SLICE5-GPGME-READINESS:START -->

## Slice 5 GPGME readiness status

Slice 5 adds a GPGME readiness and dependency metadata gate. It proves that later cryptographic helper work must require GPGME readiness and must not fall back to direct browser-facing `gpg` command execution.

Slice 5 still does not implement decryption, signature verification, signing, encryption, helper cryptographic operations, passphrase handling, PGP/MIME parsing, GPGME runtime cryptographic integration, or browser UI integration.

<!-- OSMAP:V12-SLICE5-GPGME-READINESS:END -->

<!-- OSMAP:V12-SLICE6-GPGME-AVAILABILITY:START -->

## Slice 6 GPGME availability status

Slice 6 adds an operator-controlled GPGME availability and dependency proof gate. It proves that later cryptographic helper work must start from available GPGME development metadata and must not fall back to direct browser-facing `gpg` command execution.

Slice 6 still does not implement decryption, signature verification, signing, encryption, helper cryptographic operations, passphrase handling, PGP/MIME parsing, GPGME runtime cryptographic integration, or browser UI integration.

<!-- OSMAP:V12-SLICE6-GPGME-AVAILABILITY:END -->
