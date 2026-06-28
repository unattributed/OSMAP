# V14 Slice 2 CSS and Local Icon Foundation

## Status

V14 Slice 2 adds the first runtime UI foundation for the Streamline WebUI and OpenPGP UX sprint. The slice is intentionally narrow and does not change mail, authentication, OpenPGP runtime behavior, deployment posture, or production host configuration.

## Scope

This slice provides:

- shared CSS primitives for local inline SVG icons
- navigation hover and active-state styling for the authenticated app header
- a local inline SVG shield mark for the OSMAP brand in the authenticated shell
- documentation and a gate for the CSS and icon foundation

The implementation remains server-rendered Rust HTML. It does not introduce JavaScript, an npm or node build chain, frontend frameworks, external CDNs, web fonts, remote images, or additional dependencies.

## Security boundary

The icon foundation is local template markup only. SVG paths are static, fixed strings emitted by the Rust UI helpers. No user-controlled field is inserted into SVG attributes or path data.

The approved V14 images under `docs/design/v14-approved-ui-reference/` remain design references only. They are not runtime browser assets and are not permission to weaken CSP, add JavaScript, or add a frontend build pipeline.

## OpenPGP UX boundary

This slice does not enable OpenPGP decrypt, verify, sign, encrypt, PGP/MIME parsing, passphrase handling, private-key access, browser OpenPGP controls, key discovery, or decrypted rendering. Future OpenPGP UX slices must preserve the V12 non-cryptographic boundary until runtime crypto work is explicitly implemented and reviewed.

Verified signatures do not make content safe. Decrypted content must still pass through protected rendering. Source view remains explicit, escaped, authorized, and bounded.

## Validation

Expected local validation for this slice:

- `git diff --check`
- `make v14-check`
- `cargo check`
- targeted browser/UI rendering tests

GitHub Actions remains the merge gate before this slice is merged to `origin/main`.

## Slice 2 no runtime script and asset boundary

- CSS-only: this slice adds styling and local inline SVG structure only.
- No JavaScript is introduced or required by this slice.
- The local inline SVG foundation performs no runtime asset fetch.
- Runtime UI remains server-rendered Rust HTML under the existing restrictive CSP.
