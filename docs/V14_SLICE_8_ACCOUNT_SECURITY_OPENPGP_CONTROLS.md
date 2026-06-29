# V14 Slice 8 Account Security OpenPGP Controls

## Scope

This slice adds an Account Security panel to the authenticated settings page with UI-only OpenPGP account controls. It is presentation-only and does not enable, configure, or claim OpenPGP runtime behavior.

## Functional acceptance

- The existing settings page remains authenticated and CSRF-bound.
- Existing HTML display preference and archive shortcut controls remain unchanged.
- A visible Account Security section displays OpenPGP account capability status and disabled future controls.
- The controls are disabled and submit no OpenPGP form fields.

## Security boundary

- No OpenPGP runtime capability change.
- No key discovery, key import, private-key access, passphrase handling, signing, encryption, decryption, verification, or message mutation.
- No runtime JavaScript, frontend framework, npm/node build chain, external CDN, or client-side OpenPGP execution.
- Protected by Default remains the browser-display boundary; verified signatures would not make content safe in later slices.

## Governance

This slice preserves the V12 OpenPGP claim boundary and provides only account-security UI placeholders for later configured-account work. Any future runtime OpenPGP account controls require separate policy, helper, audit, and rendering evidence.

- This slice adds no runtime JavaScript, no frontend framework, no npm/node build chain, no external CDN, and no client-side OpenPGP execution.
