# V14 Slice 5 Modern Reader and Protected by Default Trust Strip

## Status

V14 Slice 5 modernizes the authenticated message reader and adds a visible Protected by Default trust strip. The slice is intentionally narrow: it improves reader clarity and evidence visibility without changing mail retrieval, message parsing, OpenPGP runtime behavior, deployment posture, or production host configuration.

## Functional acceptance

- The message reader has a clearer hierarchy for subject, sender, mailbox, UID, received time, MIME type, body source, rendering mode, and HTML presence.
- The reader displays a Protected by Default trust strip before the message summary and body.
- The reader exposes explicit remote-content status, protected rendering status, source-view escaping, attachment metadata, and body rendering boundaries.
- Reply, forward, archive, delete-to-trash, and move actions remain present and continue to use the existing route behavior.
- Attachment metadata remains bounded by the existing attachment metadata display cap.

## Security acceptance

- Verified signatures do not make content safe.
- Rendered content and future decrypted content must still pass protected rendering.
- Remote content remains blocked by policy and is not loaded by the browser.
- Source view and body rendering remain explicit, escaped, authorized, and bounded.
- This slice makes no OpenPGP runtime capability change and does not expand V12 OpenPGP claims.
- This slice adds no runtime JavaScript, frontend framework, npm/node/Vite/Webpack chain, external CDN, remote asset fetch, or new dependency.
- State-changing reader actions remain POST and CSRF-bound through existing forms.
- V4 hostile-message route compatibility must remain passing.

## Governance acceptance

- No release-readiness claim is expanded by this slice.
- No OpenPGP runtime claim is expanded by this slice.
- V10 generated registers are refreshed only when source drift occurs.
- `v14-check` must include `osmap-v14-reader-trust-strip-gate.sh`.
- GitHub Actions remains the merge gate.

## Non-goals

This slice does not implement OpenPGP decrypt, verify, sign, encrypt, PGP/MIME parsing, passphrase handling, private-key access, browser OpenPGP controls, key discovery, decrypted rendering, live-host deployment, nginx changes, Postfix changes, or Dovecot changes.
