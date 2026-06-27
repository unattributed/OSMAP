# V12 OpenPGP helper client integration gate

V12 Slice 10 adds an integration gate for the helper client boundary introduced in Slice 9.

The gate proves that the OpenPGP helper path remains bounded and non-cryptographic at the application integration layer. It checks that:

- the protocol-only helper invocation scaffold exists;
- the typed Rust helper client module exists and is exposed by `src/lib.rs`;
- the Rust and helper request fields, versioned schemas, limits, and operations
  agree;
- the Rust boundary has executable tests for valid, malformed, duplicate,
  unknown-field, wrong-schema, wrong-operation, runtime-crypto, nonzero-exit,
  stderr, and oversized-response cases;
- V12 checks include the Rust helper-client gate and this integration gate;
- the full security check includes the integration gate;
- browser-facing handlers are not wired to OpenPGP helper code;
- helper process spawning is still disabled by policy;
- runtime cryptographic operations are still disabled by policy.

Slice 10 does not implement decryption, signature verification, signing, encryption, PGP/MIME parsing, passphrase handling, secret-key access, helper process spawning, browser UI integration, or decrypted-content rendering.
