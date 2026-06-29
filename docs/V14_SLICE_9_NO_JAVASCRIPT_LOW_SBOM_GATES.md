# V14 Slice 9 No-JavaScript and Low-SBOM Gates

## Purpose

Slice 9 adds repository-owned gates that keep V14 aligned with the approved
server-rendered WebUI security posture. The slice is intentionally evidence and
governance focused: it does not redesign pages, add runtime OpenPGP capability,
or introduce new dependencies.

This slice is the V14 low-SBOM boundary check. It keeps the authenticated UI on
server-rendered Rust HTML, local CSS, existing Rust dependencies, and restrictive
browser policy instead of adding JavaScript, frontend frameworks, CDNs, or a
node-based build chain.

## Scope

This slice adds a V14 gate that verifies:

- no runtime JavaScript is introduced into the browser UI;
- no Node, npm, Vite, Webpack, React, Vue, Svelte, Alpine, htmx, WASM, or
  frontend build chain artifacts are tracked;
- runtime HTML responses retain the restrictive browser Content Security Policy;
- runtime UI source remains free of script tags, inline event handlers,
  `javascript:` URLs, and remote asset surfaces;
- the Cargo dependency footprint remains small and reviewable.

## Security boundary

No OpenPGP runtime capability change is made by this slice. It does not enable
decrypt, verify, sign, encrypt, PGP/MIME parsing, passphrase handling,
private-key access, key discovery, or decrypted-content rendering.

No runtime JavaScript, frontend framework, npm/node build chain, external CDN,
remote stylesheet, webfont CDN, remote image dependency, or client-side OpenPGP
execution is introduced.

The gate is source-aware. It checks runtime UI files and dependency manifests,
while avoiding broad false-positive scans over hostile-content fixtures,
sanitation tests, and documentation examples that intentionally mention unsafe
strings such as `javascript:` or `<script>`.

## Acceptance evidence

Slice 9 is acceptable only when all of the following pass from the branch:

- `make v14-check`
- `make v10-check`
- `cargo check`
- `sh maint/security/osmap-v14-no-js-low-sbom-gate.sh`
- full `make security-check`

## Non-goals

- No visual redesign.
- No authenticated route behavior change.
- No new Rust crate dependency.
- No OpenPGP runtime capability expansion.
- No deployment, live host, nginx, Postfix, or Dovecot change.
