# OSMAP Agent Notes

## Current bounded closeout — 2026-10-17

**S04-01 complete (R4 narrowed scope).** Operator `S04_01_UAT=PASS` follows
matching installed QA and independent audit GO. Finalize the signed closeout
records only. All other slices remain stopped, including S04-02; eleven required
controls in nine Sprint S04/epic follow-ups remain open. This acceptance does not
restart password change, TOTP management, recovery or other engineering. Preserve
R2/R3/R4 references and scope. Normal signature verification and operator source
review before any push/synchronization remain mandatory.

## Historical operator stop — 2026-10-17

Development and all delegated engineering/review workers are stopped. The
operator subsequently authorized only updating documentation, committing all
repository changes with verified Shopkeeper signatures and synchronizing the
current UX branch to GitHub. Do not interpret that preservation request, a
heartbeat, a historical continuation or an old work order as permission to
restart implementation, native/live tests, deployment or host synchronization.
Normal mandatory commit/push hooks remain required. Further development needs
new explicit operator authorization. See `docs/UX_STOPPED_HANDOFF_20261017.md`.

This repository is the OpenBSD Secure Mail Access Platform. Treat it as a
security-sensitive mail application with a live validation target at
`mail.blackbagsecurity.com`.

## Full-functional UX epic execution

For work assigned to the OSMAP-UX epic, read
`docs/UX_FULL_FUNCTIONAL_EPIC.md`, `docs/UX_FULL_FUNCTIONAL_SLICES.md`,
`docs/UX_AGENT_EXECUTION_CONTRACT.md`, and `docs/UX_EXECUTION_LEDGER.md`
before task edits. Verify the operator-accepted signed plan anchor and
`docs/UX_PLAN_SHA256SUMS`; if no anchor is accepted, do not start implementation.
Keep progress in the ledger, not the frozen plan. Plan changes require the
documented operator-approved amendment process. A planning request does not
authorize live mutation, runtime cryptography, deployment or synchronization.
These epic-specific rules do not override higher-priority instructions or the
operator's explicit instructions.

## Coordinated agent development

The operator's 2026-10-15 strict project-manager direction makes the delivery
policy in `docs/OSMAP_AGENT_FRAMEWORK_ADOPTION.md` mandatory for this epic.
Its one active work order lives in `docs/UX_EXECUTION_LEDGER.md` and is checked
by the existing developer gate. Within repository instructions this policy
controls agent execution; system/developer instructions, direct operator
directions and the frozen R2/R3 product/security obligations retain precedence.
Agents cannot park active work, substitute checkpoints for functional closure,
or invent prerequisite approvals. A concrete blocker is recorded while useful
independent authorized work continues; an explicit operator pause is immediate.

The operator's 2026-10-14 end-to-end delegation and approved auditor corrections
are codified in `docs/UX_PLAN_AMENDMENT_R3.md`. Agents own implementation,
technical decisions, integration, essential QA, independent audit coordination
and authorized delivery. Follow the current ledger's technical dependencies;
pending human acceptance does not halt independent engineering. Invite the
operator only when all agent-owned development, matching deployed QA and
independent audit requirements PASS for that exact scope. Never use operator
UAT to troubleshoot unfinished engineering. Preserve the original R2 anchor
and its byte-exact references alongside the signed R3 execution supplement.

When adding or optimizing a backend trait operation, verify its delegation
through the actual browser Runtime wrapper with a distinguishing regression.
Concrete helper/native tests alone do not qualify a wrapper's inherited default.
The 2026-10-15 folder-facts repair demonstrated this integration gap; reuse
unchanged backend evidence and test the changed composition, without a new QA
framework or blanket repeat of passing workflows.

For OpenBSD integration, check the actual command/syscall contract before
modelling it in a local fake. `ps -p` takes one PID. Empty unveil permissions
hide ancestor pathname metadata; they are not read or stat grants. Keep protected
pre-seal checks and qualify the changed sealed path on OpenBSD. Preserve useful
bounded synthetic failure diagnostics so hashes alone do not force repeated runs.
Construct subprocess fixtures through fixed cfg(test) command builders in
`src/auth.rs`, matching the existing command-creation boundary. Keep literal
programs/arguments and caller-independent fixture scripts; inspect both the
CWE guard and legacy security-check consumer before a full gate. Do not weaken
production command guards or introduce caller-selected commands to pass tests.
When adapting a qualifier, check its executed admission and success consumers
with one matching receipt and a changed count/cleanup refusal. Exact source
pins alone do not establish compatible result schemas. For nested source carriers,
compare every emitted, received and embedded pin registry to the same frozen
input map and execute the actual local admission chain before host dispatch.
The October16 stale remote registry failure is the concrete regression; AST
parity or an outer manifest alone cannot establish nested admission parity.
For native uploads that preserve permissions, preflight every transferred leaf's
owner, single link, exact private mode, size and hash before transfer. Create
retained native artifacts with a private umask. The October16 candidate build
refused inherited group-writable archive permissions before compilation; do not
relax remote custody guards or misreport that refusal as a compiler defect.

For operator-authorized multi-agent work, apply
`docs/AGENT_DEVELOPMENT_FRAMEWORK.md` and its OSMAP mapping in
`docs/OSMAP_AGENT_FRAMEWORK_ADOPTION.md`. Assign project management, Scrum
coordination, development, independent QA, security review and technical writing
responsibilities explicitly; activate agents only for actionable assignments.
For an existing idle or completed worker, use `followup_task` to dispatch work;
`send_message` alone does not start a turn. Confirm the worker reports running
before recording an assignment as active or waiting for its result. If the
worker is absent from the current team, reconcile retained files and dispatch
the remaining concrete task rather than assuming historical work is continuing.
Use the existing execution ledger, decision log and UAT record rather than
creating a parallel status system. Required user journeys need frontend,
backend, persistence and actual integration evidence before readiness claims.
Component tests, page rendering and service health alone do not qualify UAT.
An unresolved failure of a required journey blocks that journey's readiness.
This framework does not change the frozen UX plan or authorize application,
policy, deployment or external side effects beyond the operator's instructions.


The operator's 2026-10-15 accountability policy in the existing framework
adoption document is mandatory. Before an expensive/native action, run the
existing validator with `--work-order-only --pre-action`: one functional exit
and owner, UTC-started bounded investigation, honest full-action wall-clock
records, whole producer/cleanup/consumer review and changed retry/reassessment
records are required. Package renaming cannot reset the functional boundary.
Preserve historical facts and continue independent authorized work.

The operator's 2026-10-16 slice delivery SOP applies to every OSMAP-UX slice.
Before implementation or continuation, define and verify the active ledger's
`slice_contract`: pinned readable design specification, exact original outcome
mapping, planned positive/negative tests, prerequisites, expected and preserved
results, owners and independent reviewers. Use the existing validator/gates;
planned work is not execution. Fulfil the contract through actual code,
matching integration/installed QA, independent audit and recovery, then minimal
separate human acceptance. Keep decisions and results current; preserve the
frozen epic and all obligations. See `docs/OSMAP_AGENT_FRAMEWORK_ADOPTION.md`.
This codification is epic-wide; future slices are specified before they start,
not retroactively declared complete. Routine technical decisions remain delegated.

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
  The latest operator-supplied AGENTS instructions supersede the older
  2026-10-01 automatic-sync default. Local source delivery, synchronization,
  deployment and operator acceptance remain distinct.

## Git and signing workflow

Git is the authoritative record of completed development work.

All Codex-authored commits must be OpenPGP signed with the Shopkeeper signing
key:

    F55E404E91A0753701F91B01A7228D3FB5084B34

Use an explicitly signed commit with a concise lowercase subject and a short
body that gives collaborating developers useful context: what behavior changed,
why it changed, and the relevant validation or remaining limit. Never put
secrets, protected mail content, or unverified completion claims in the body.
For example:

    git commit --gpg-sign=F55E404E91A0753701F91B01A7228D3FB5084B34 \
      -m "<lowercase subject>" -m "<context for collaborators>"

Do not create unsigned commits.

Do not automatically push, pull, synchronize, force push, rewrite published
history, amend existing commits or resolve branch divergence. Only an explicit
instruction such as “push” or “sync” authorizes a remote write after signed
review. R4 scope approval is not push approval. If a separately authorized push
gate fails, fix the issue without bypassing checks or forcing the update.

Do not create or switch branches unless the task requires it or the operator
explicitly approves it.

GitHub SSH transport on a qualified operator workstation is intentionally
passwordless. If SSH unexpectedly requests a private-key passphrase, stop and
report workstation bootstrap noncompliance. Do not retrieve a Proton Pass secret
for GitHub SSH.

Use the configured workstation `gpg-agent` for Shopkeeper signing. The operator
superseded the manual clipboard/Proton Pass checkpoint on 2026-09-14.

- Do not ask for a clipboard-readiness confirmation before signing.
- Do not retrieve, print, or pass the private-key passphrase through shell
  arguments, environment variables, repository files, logs, or chat.
- Use the agent's existing credential cache. Noninteractive signing may use
  `gpg --batch --pinentry-mode error`; if the agent cannot sign, report the
  concrete failure rather than creating an unsigned commit or bypassing checks.
- This removes only the manual signing checkpoint. Signature verification and
  operator review before synchronization remain required; UX acceptance is a
  separate outcome.

After each commit, verify:

    git verify-commit HEAD
    git status --short --branch
    git show --show-signature --stat --oneline HEAD

Then report the commit SHA, signature result, changed files, working-tree state
and ahead/behind state for operator inspection. Do not push or synchronize until
explicitly authorized. Human acceptance remains separate from source review.

After each push, refresh `origin` and prove local/remote SHA equality
before reporting synchronization as successful:

    git fetch --prune origin
    git rev-parse HEAD
    git rev-parse "origin/$(git branch --show-current)"
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
- `mail.blackbagsecurity.com` now denotes the Vultr mail instance. The former
  on-premises host is `obsd1.blackbagsecurity.com` at `192.168.1.44`, with local
  `/etc/hosts` alias `mail-source-grace` on the operator workstation.
- Do not substitute the former LAN host for current production validation.
  Verify target identity explicitly; historical LAN-host evidence does not
  qualify the migrated instance.
- The operator explicitly selected `obsd1.blackbagsecurity.com` at
  `192.168.1.44` as the validation target for the current TOTP lifecycle sprint.
  Use that IP for this sprint, with the expected hostname `obsd1.blackbagsecurity.com`.
  Do not contact Vultr for this sprint unless separately instructed. Label all
  resulting host evidence as obsd1 evidence, not Vultr qualification.
- The operator granted full authority to operate on obsd1 for this sprint.
  Use that authority for in-scope preparation and controlled validation while
  preserving unrelated state. It does not supply recovery identity/session/
  containment attestations or waive signed-commit review before synchronization.
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
- When a historical sprint has no previously defined directory name, choose a concise stable slug and record it in the operator bundle. For the historical PR #56 Slice 00 workstream, use `/home/foo/Downloads/osmap-pr56-slice-00/`.
- The approved TOTP lifecycle continuation (Slices 02–04) uses
  `/home/foo/Downloads/osmap-totp-lifecycle/` throughout implementation and
  closeout. The PR #56 directory above remains the historical Slice 00 root.

This layout is mandatory for newly generated sprint artifacts. Existing top-level Downloads artifacts may remain in place unless a separate bounded cleanup or archival operation is explicitly authorized.
