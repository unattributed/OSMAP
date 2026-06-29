# V14 Slice 7 — Compose OpenPGP Controls

## Scope

This slice adds UI-only OpenPGP controls to the authenticated compose page. It is a presentation and governance slice only.

## Functional acceptance

- The compose page renders an OpenPGP compose controls panel.
- The panel is explicitly marked with `data-openpgp-compose-controls="ui-only"`.
- Encrypt, sign, and recipient-key controls are visible only as disabled future account-controlled actions.
- Existing send, save-draft, attachment, source-attachment, recipient, subject, and body fields remain unchanged.

## Security acceptance

- This slice makes no OpenPGP runtime capability change.
- No encrypt, sign, key lookup, private-key access, passphrase handling, or message mutation is attempted.
- The OpenPGP controls do not submit OpenPGP form names and do not route to any OpenPGP endpoint.
- Send Message and Save Draft remain unchanged plaintext submission paths in this slice.
- No decrypted plaintext, passphrases, private keys, recipient-key material, or sensitive message body content is logged.
- No runtime JavaScript, frontend framework, npm/node build chain, external CDN, live-host change, deployment change, nginx change, Postfix change, or Dovecot change is introduced.

## Governance acceptance

- The V14 gate set is extended with `maint/security/osmap-v14-compose-openpgp-controls-gate.sh`.
- V10 governance registers are refreshed to include this UI-only slice without expanding release or cryptographic claims.
- V12 OpenPGP boundaries remain authoritative: configured account capability and later runtime evidence are required before any encrypt/sign behavior can be claimed.

## Non-claims

This slice does not claim encryption, signing, verification, decryption, key discovery, key upload, key trust, passphrase handling, recipient-key resolution, or outbound OpenPGP enforcement.

- This slice adds no runtime JavaScript, no frontend framework, no npm/node build chain, no external CDN, and no client-side OpenPGP execution.
