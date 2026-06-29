# V14 Slice 10 Accessibility Responsive Pass

## Purpose

Slice 10 performs a narrow accessibility and responsive-layout pass for the V14
authenticated WebUI work. It does not redefine project supply-chain, SBOM, or frontend policy; it verifies this slice remains inside the existing V14 boundary.

## Scope

This slice adds:

- explicit accessible names for bounded bulk message-selection checkboxes;
- a small-screen CSS rule for table spacing, toolbar stacking, and button width;
- an executable V14 accessibility/responsive gate registered in `make v14-check`.

## Security boundary

No OpenPGP runtime capability change is made by this slice. It does not enable
decrypt, verify, sign, encrypt, PGP/MIME parsing, passphrase handling,
private-key access, key discovery, or decrypted-content rendering.

No runtime JavaScript, frontend framework, npm/node build chain, external CDN,
remote stylesheet, remote image dependency, or client-side OpenPGP execution is
introduced.

## Acceptance evidence

Slice 10 is acceptable only when all of the following pass from the branch:

- `sh maint/security/osmap-v14-accessibility-responsive-gate.sh`
- `make v14-check`
- `make v10-check`
- `cargo check`
- full `make security-check`

## Non-goals

- No visual redesign.
- No authenticated route behavior change.
- No new Rust crate dependency.
- No OpenPGP runtime capability expansion.
- No deployment, live host, nginx, Postfix, or Dovecot change.
