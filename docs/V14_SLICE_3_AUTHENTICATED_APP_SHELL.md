# V14 Slice 3 Authenticated App Shell

## Status

V14 Slice 3 turns the authenticated app shell into a reviewable, accessible, server-rendered unit. It builds on Slice 1 design constraints and Slice 2 CSS foundations without changing mail retrieval, message rendering, authentication, OpenPGP runtime behavior, deployment posture, or live host configuration.

## Functional acceptance

This slice provides a coherent authenticated shell on server-rendered pages that use the shared `page-shell` layout:

- a skip link targeting `#main-content` for keyboard and assistive-technology navigation
- a banner-marked authenticated header with OSMAP brand, primary navigation, visible session status, visible signed-in identity, and CSRF-bound logout
- active navigation states through `aria-current="page"`
- route-level rendered HTML evidence through the existing V4 hostile-message route assurance test report

## Security acceptance

This slice preserves the security model:

- no runtime JavaScript is introduced
- no frontend framework, npm/node build chain, external CDN, web font, remote image, or new dependency is introduced
- no route-backed SVG auto-fetch surface is added to hostile-message views
- the existing restrictive CSP/browser-boundary invariants remain enforced
- protected rendering is not bypassed and message body rendering remains server-side
- logout remains POST-only and CSRF-bound

## Governance acceptance

This slice does not expand release claims. It does not claim full Roundcube parity, broad public release readiness, or a completed OpenPGP implementation. It adds no OpenPGP runtime capability and does not enable decrypt, verify, sign, encrypt, PGP/MIME parsing, passphrase handling, private-key access, key discovery, browser OpenPGP controls, or decrypted rendering.

If Rust source movement changes generated V10 assumption inventories, the slice refreshes only the generated governance registers and keeps the claims boundary synchronized with those generated hashes. GitHub Actions remains the merge gate.

## V4 hostile-message route compatibility

Authenticated message routes retain the V4 hostile-content zero auto-fetch-surface invariant. The authenticated shell must not add runtime SVG, script, remote asset fetches, browser-side messaging APIs, or unsafe browser API references to route-backed message views unless that assurance model is explicitly updated with evidence.

## Expected validation

- `git diff --check`
- `make v14-check`
- `make v10-check`
- `cargo check`
- `cargo test html_response_accepts_typed_template_output_and_escapes_title --lib`
- `cargo test --test v4_hostile_assurance -- v4_hostile_content_assurance_corpus_gate`
