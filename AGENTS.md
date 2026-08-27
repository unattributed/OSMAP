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
- For completed development changes, finish with a signed Git commit, verify
  the signature, and stop for operator review before any push or synchronization.

## Git and signing workflow

Git is the authoritative record of completed development work.

All Codex-authored commits must be OpenPGP signed with the Shopkeeper signing
key:

    F55E404E91A0753701F91B01A7228D3FB5084B34

Use an explicitly signed commit and a concise lowercase commit message:

    git commit -S F55E404E91A0753701F91B01A7228D3FB5084B34 -m "<lowercase commit message>"

Do not create unsigned commits.

Do not automatically push, pull, synchronize, force push, rewrite published
history, amend existing commits, or resolve branch divergence. Remote writes
require explicit operator approval.

Do not create or switch branches unless the task requires it or the operator
explicitly approves it.

Before every command that may trigger an encrypted private-key passphrase
prompt, including signed commits, direct GPG operations, SSH authentication,
and SSH-backed Git fetch or push operations, use this checkpoint:

    echo
    echo "============================================================"
    echo "PRIVATE KEY PASSPHRASE MAY BE REQUIRED"
    echo "============================================================"
    echo "Retrieve the required passphrase from Proton Pass and copy it"
    echo "to the system clipboard."
    echo
    read -r -p "Press Enter when the passphrase is ready in the clipboard..."
    echo

After each commit, verify:

    git verify-commit HEAD
    git status --short --branch
    git show --show-signature --stat --oneline HEAD

Then stop and report the commit SHA, signature result, changed files, working
tree state, and ahead/behind state. The operator must be able to inspect the
outgoing commit in VSCodium before approving synchronization.

Only an explicit instruction such as "push", "sync", or "push this commit"
authorizes a remote write.

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
