# OSMAP Agent Notes

This repository is the OpenBSD Secure Mail Access Platform. Treat it as a
security-sensitive mail application with a live validation target at
`mail.blackbagsecurity.com`.

## Working Rules

- Keep changes small, reviewed, and aligned with the existing Rust, shell, and
  documentation patterns.
- Do not commit secrets, credentials, TOTP material, cookies, CSRF tokens,
  private message bodies, attachment bodies, provider tokens, or host-private
  keys.
- Update release, WSTG, and decision evidence when a change affects a security
  boundary, user workflow, deployment posture, or release claim.
- Preserve unrelated local or remote worktree changes unless the operator
  explicitly asks to remove them.

## Validation

- Developer gate: `make security-check`.
- Strict V3 gate: `OSMAP_SECURITY_PROFILE=release make release-check`.
- The strict release gate requires current cargo, supply-chain, WSTG,
  authenticated WSTG, TLS, resource-control, MIME/HTML, pilot rehearsal, and
  sanitized archive evidence.
- Credential-backed WSTG evidence must use `--release --prompt-auth` and must
  not store reusable credentials in the repository.

## Mail Host

- Keep the standard host checkout at `~/OSMAP` on `mail.blackbagsecurity.com`
  synced to the branch being validated.
- Prefer the LAN SSH target when WAN hairpinning from the workstation is blocked.
- Use temporary validation credentials and controlled validation accounts for
  live evidence, restoring or removing them afterward.

## Evidence

- Committed evidence should be sanitized and reproducible enough for review.
- Live evidence reports must state the assessed commit and pass their release
  validators before being used for a release claim.
- If a new commit changes only evidence or agent guidance, refresh any
  commit-pinned release reports before claiming the full release gate passes for
  that new commit.
