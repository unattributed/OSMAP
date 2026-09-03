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

    git commit --gpg-sign=F55E404E91A0753701F91B01A7228D3FB5084B34 -m "<lowercase commit message>"

Do not create unsigned commits.

Do not automatically push, pull, synchronize, force push, rewrite published
history, amend existing commits, or resolve branch divergence. Remote writes
require explicit operator approval.

Do not create or switch branches unless the task requires it or the operator
explicitly approves it.

GitHub SSH transport on a qualified operator workstation is intentionally
passwordless. If SSH unexpectedly requests a private-key passphrase, stop and
report workstation bootstrap noncompliance. Do not retrieve a Proton Pass secret
for GitHub SSH.

Before every command that may trigger the Shopkeeper OpenPGP private-key
passphrase, including signed commits, direct GPG operations, or signing-key
unlock operations, use this checkpoint:

    echo
    echo "============================================================"
    echo "OPENPGP PRIVATE KEY PASSPHRASE MAY BE REQUIRED"
    echo "============================================================"
    echo "Retrieve the Shopkeeper OpenPGP passphrase from Proton Pass"
    echo "and copy it to the system clipboard."
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

After an approved push, refresh `origin` and prove local/remote SHA equality
before reporting synchronization as successful:

    git fetch --prune origin
    git rev-parse HEAD
    git rev-parse origin/main
    git status --short --branch

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

## Sprint Artifact And Evidence SOP

This repository uses sprint-scoped artifact storage for all operator deliveries and retained evidence.

- Do not write new sprint delivery or evidence artifacts directly into `/home/foo/Downloads`.
- Before creating the first retained artifact for a sprint, create one stable sprint root at `/home/foo/Downloads/<sprint-id>/`.
- Create the sprint root with owner-only permissions where practical, for example `mkdir -p "$SPRINT_ROOT"` followed by `chmod 700 "$SPRINT_ROOT"`.
- Keep every retained artifact associated with that sprint under the sprint root, including delivery `.tar.gz` bundles, portable `.tar.gz.sha256` sidecars, evidence archives, evidence sidecars, terminal logs, status files, manifests, extracted operator bundles, and related handoff files.
- Reuse the same sprint root across slices, retries, resumptions, and evidence refreshes belonging to that sprint instead of returning to the top-level Downloads directory.
- Operator bundles must default retained output variables such as `OUT_ROOT`, evidence directories, archive paths, sidecars, logs, and status paths to the sprint root rather than directly to `$HOME/Downloads`.
- SHA-256 sidecars must remain portable by containing the archive basename, never an absolute path.
- Temporary build/runtime scratch that does not need retention should use `/tmp` or another purpose-specific temporary location rather than the sprint artifact directory.
- Do not move, rename, inspect, or delete unrelated pre-existing Downloads content merely to enforce this layout.
- When a historical sprint has no previously defined directory name, choose a concise stable slug and record it in the operator bundle. For the current PR #56 Slice 00 workstream, use `/home/foo/Downloads/osmap-pr56-slice-00/`.

This layout is mandatory for newly generated sprint artifacts. Existing top-level Downloads artifacts may remain in place unless a separate bounded cleanup or archival operation is explicitly authorized.
