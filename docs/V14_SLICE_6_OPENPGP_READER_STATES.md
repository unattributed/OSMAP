# V14 Slice 6 OpenPGP Reader States

## Status

V14 Slice 6 adds UI-only OpenPGP reader-state presentation to the authenticated message reader. The slice is intentionally narrow: it makes OpenPGP state and claim boundaries visible without changing mail retrieval, MIME parsing, OpenPGP runtime behavior, deployment posture, live-host configuration, or production service behavior.

## Functional acceptance

- The message reader shows an OpenPGP reader-state panel near the Protected by Default trust strip.
- The panel explicitly marks the current state model as UI-only.
- The reader exposes bounded states for encrypted, decrypted locally, signature, signer, and missing-key conditions.
- The current UI states say that no account OpenPGP capability is configured for the reader session and that no decrypt, verify, key discovery, private-key access, or passphrase handling was attempted.
- The existing Reading Pane heading, body panel, attachment list, reply, forward, archive, delete-to-trash, and move controls remain present.

## Security acceptance

- This slice makes no OpenPGP runtime capability change and does not expand V12 OpenPGP claims.
- OpenPGP controls appear only when account capability is configured.
- Accounts without configured capability must not show controls that imply signing, encryption, decryption, verification, key discovery, or key-management support.
- Verified signatures do not make content safe.
- Future decrypted content must still pass Protected by Default rendering.
- The slice does not implement decrypt, verify, sign, encrypt, PGP/MIME parsing, passphrase handling, private-key access, key discovery, decrypted rendering, plaintext logging, or helper invocation.
- The slice adds no runtime JavaScript, frontend framework, npm/node/Vite/Webpack chain, external CDN, remote asset fetch, or new dependency.
- V4 hostile-message route compatibility and the exact body-panel marker remain passing.

## Governance acceptance

- No release-readiness claim is expanded by this slice.
- No OpenPGP runtime claim is expanded by this slice.
- V10 generated registers are refreshed only for source drift.
- `v14-check` must include `osmap-v14-openpgp-reader-states-gate.sh`.
- GitHub Actions remains the merge gate.

## Non-goals

This slice does not implement OpenPGP decrypt, verify, sign, encrypt, PGP/MIME parsing, passphrase handling, private-key access, browser OpenPGP controls, key discovery, decrypted rendering, live-host deployment, nginx changes, Postfix changes, or Dovecot changes.

- Future decrypted content remains future decrypted content for claim-boundary purposes and must still pass Protected by Default rendering before browser display.
