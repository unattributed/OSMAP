# V12 OpenPGP Rust helper client boundary

V12 Slice 9 adds the typed Rust application-side boundary used to prepare helper invocation requests. This slice is still non-cryptographic.

The boundary defines:

- a fixed helper protocol mode argument;
- typed allowed operations: `capability_status`, `diagnostic_ping`, and `policy_check`;
- stdin-only JSON request planning;
- bounded request, stdout, and stderr sizes;
- timeout policy metadata;
- fail-closed treatment for nonzero helper exit, malformed JSON, oversized stdout, and oversized stderr.

The Slice 9 Rust boundary does not spawn the helper process. It prepares and validates invocation shape only. Process execution remains outside this slice to avoid expanding direct command-execution surfaces before the helper privilege and runtime boundary is reviewed.

Slice 9 does not implement OpenPGP decryption, signature verification, signing, encryption, PGP/MIME parsing, passphrase handling, secret-key listing, private-key access, decrypted-content rendering, browser UI integration, or direct `gpg` cryptographic fallback.
<!-- OSMAP:V12-SLICE10-HELPER-CLIENT-INTEGRATION:START -->

## Slice 10 integration gate

The Rust helper client boundary is now covered by a V12 integration gate. The gate validates check wiring and policy invariants only. It does not enable process spawning or cryptographic operations.

<!-- OSMAP:V12-SLICE10-HELPER-CLIENT-INTEGRATION:END -->
