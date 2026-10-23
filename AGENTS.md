# OSMAP Agent Notes

## Operator ruling — simplify test machinery and test product contracts, 2026-10-23

Codex-created test and execution machinery must not become a substitute product
or a prerequisite invented by the machinery itself.  The required outcome is a
working OSMAP journey.  Use the smallest test that exercises the changed product
boundary, then advance to the next functional boundary.  A carrier, compiler,
source map, receipt, ledger declaration, review or diagnostic is evidence about
the test; none is a product acceptance result.

The following assumptions are explicitly rejected unless a product/API contract
in the repository independently requires them:

- an exact OpenBSD, MariaDB, Python or package patch release on hosts that are
  deliberately kept current with stable updates;
- a fixed free-memory floor, full-build prerequisite, two-host topology, public
  mail-service outage, historical ledger clock or agent-created approval window;
- exact output text, row count or serialized field not required by the product
  interface; and
- completion of a role roster, historical reassessment ceremony or prose record
  as proof that a safe, directly authorized product test may run.

Check semantic capabilities and the actual schema/configuration consumed by the
product. Preserve observed versions as evidence, not compatibility predicates.
Active OSMAP and mail-stack code must not parse, compare, validate the format of,
or branch on the OpenBSD release string, and must not default to a
release-numbered OpenBSD image or build helper. Requiring the OpenBSD operating
system remains valid; compatibility is established by the concrete APIs,
commands, schema and confinement behavior the product actually uses.
Execution utilities must use explicit checks, not Python `assert`, and must
return the structured failure code and cleanup disposition that caused refusal.
Before host use, exercise the real producer output through the real consumer,
including the failure and cleanup path; comparing source hashes or reviewing the
two programs separately is insufficient.

`maint/ux/validate_acceptance.py --pre-action` is a narrow consistency check for
the recorded action ID, source, recipe, target, prerequisites, runtime bound and
any explicit operator expiry.  It is not an authority ledger, evidence review or
truth oracle.  Historical accounting and independent review remain available for
post-result reconciliation, but they must not create a new dispatch prerequisite.
The full regression/release gates remain delivery gates; do not run broad
unchanged suites between each progressive functional milestone.

## Operator ruling — remove elapsed-clock execution-authority expiry, 2026-10-23

The operator has rejected the agent-created governance rule that treated a
ledger wall-clock deadline as expiration of operator authority. Direct operator
authorization remains effective for the stated action until that action is
completed, explicitly revoked, or reaches a substantive safety stop. Calendar
time and idle time are evidence/accounting fields, not dispatch authority.
An expiration or finite window explicitly imposed by the operator remains an
authorization condition unless the operator supersedes it. Record its actual
expiry as `operator_expires_at` on the planned action and enforce it before
dispatch; do not invent that field from an agent-created historical clock.
The carrier's operation and cleanup must fit any such explicit window.

Do not block an otherwise authorized action because historical `deadline_at`, `not_after`
or cumulative elapsed arithmetic has passed. Do not ask the operator to renew
authority solely because a clock advanced. Continue to preserve measured actual
elapsed time and all historical failures. Product and process safety limits
remain: fixed application deadlines, bounded I/O and cleanup, exact source and
target admission, independent review, failure stops, no ambiguous credential
retry, and the operator's public-service boundaries.

## Operator ruling — abandon the added memory requirement, 2026-10-21

The operator has abandoned the team-imposed 6 GiB free-RAM admission
requirement. It is not an OSMAP runtime, build or S04-02 acceptance requirement.
Do not restore it through a renamed recipe or substitute another unmeasured
fixed free-memory floor. A full optimized library-test build is not a blanket
completion prerequisite; use the build/test configuration required by the
specific functional or release claim. Retain necessary functional/security
tests, normal delivery hooks and matching evidence for production artifacts.

Preserve attempt113's actual precompiler refusal and attempt109's compiler
failure as history. The retired guard does not establish inadequate server
capacity. Existing reviewed private carriers containing that guard are retired
execution methods, not templates for future dispatch. Preserve their exact
bytes and receipts; replace the method through the existing work order when
further execution is authorized. This ruling does not itself claim a build or
journey PASS, enable qualification flags, renew an expired execution window or
authorize public mail-service/configuration changes.

## Current GitHub preservation SOP — operator direction, 2026-10-21

The operator requires all public-safe repository work to be saved to GitHub
as part of normal delivery. This is standing authorization to commit and push
to the current approved branch after independent source review, mandatory
checks, Shopkeeper signing and signature verification; no additional operator
source-review pause is required before routine synchronization. This direction
supersedes older manual push-approval clauses below and in execution documents,
without editing frozen plan bytes or changing functional acceptance.

Before a delivery or planned agent handoff, inventory tracked and untracked
repository changes. Preserve and include all public-safe work, including code,
tests, documentation, generated evidence and outstanding ledger updates, in
signed checkpoints and ordinary non-forced pushes. Inspect content before
staging; secrets, private mail, credentials and raw private artifacts remain
excluded under the existing rules. Do not silently leave eligible work local
or describe it as backed up while it is uncommitted or ahead of GitHub.

Run normal commit and push hooks without bypass. After each push, fetch origin
and prove exact local/remote SHA equality and zero ahead/behind before claiming
preservation complete. On failed checks, transport, divergence or expiry,
preserve the failure and report exactly what remains local; do not force,
rewrite history or replenish an exhausted allowance. Explicit operator holds
override automatic dispatch. GitHub preservation does not authorize host
deployment, live account operations or acceptance of unfinished functionality.

## Current operator boundary — frontend work without mail downtime, 2026-10-19

The operator permits starting, stopping and restarting OSMAP as needed; the
mail backend must remain available and is not a separate UX workstream. Do not
infer that frontend authority permits stopping public mail for UX tests. The
operator's connection-refused report was confirmed: Dovecot was down. Original
mail configuration and client TLS access have been restored. The operator has
now explicitly rejected the test design that required backend downtime: OSMAP
is the web frontend. Retire that fixture/cold-cutover path. New S04-02 development
and tests must not stop, start, restart or reload public Dovecot, Postfix or
MariaDB, or change their public configuration. Use existing bounded account
operations and the smallest necessary OSMAP integration changes. Source review
must verify the actual reachable dispatch path, not just a written prohibition.
The historical outage's precise cause remains UNKNOWN; do not repeat its setup
to investigate it. Necessary incident restoration is separately authorized.
Preserve the exact failed fixture/retained-state evidence and do not replay its
expired profile or already completed restoration effects. The explicit latest
instruction to complete S04-02 resumes source work; it does not authorize a
new live action merely by changing an allowance or a qualification flag.

## Mandatory delivery SOP — all OSMAP development, 2026-10-19

The operator explicitly requires regimented delivery for all OSMAP development,
including work outside the UX epic. Apply the delivery SOP in
`docs/AGENT_DEVELOPMENT_FRAMEWORK.md` before implementation or continuation.
The lead integration/delivery agent owns enforcement and must block its own or
a subagent's noncompliant action. The delivery controller independently checks
that enforcement; assigning that role does not transfer accountability to it or
to the operator. Higher-priority instructions and explicit operator directions
retain precedence.

Define one observable outcome, scope, actual environment prerequisites, minimum
tests, expected results, owners, cumulative allowance and failure stop rule in
the existing work order. Verify the relevant installed schema/configuration/
utility contract before composing dependent code or an expensive test fixture.
A known unsupported prerequisite blocks dependent execution; an author's PASS,
source hash or structurally valid declaration is not proof that it was resolved.
Use working application/backend paths and the smallest demonstrated correction.
Do not introduce another general QA framework or repeat matching passing tests.

Two failures at the same functional boundary stop further workflow retries for
combined independent reassessment. A renamed package or completed reassessment
does not reset cumulative cost or replenish an allowance. No automatic or
agent-only increase of an exhausted delivery allowance is permitted. Report the
concrete blocker and bounded next proposal; only necessary, finite safe
disposition of already-owned effects continues under existing authority. Never
renew an expired fixture or infer cleanup from a stopped transport.

Close only against the defined outcome and matching functional/security
evidence. Preserve failures, actual elapsed work and UNKNOWN costs. Apply normal
signed-commit, review, synchronization and minimal human-acceptance rules.
Policy text is not proof of runtime enforcement: the lead and independent
reviewer must inspect the actual prerequisite evidence and dispatch decision.

## Current S04-02 regimented resumption — 2026-10-19

Latest19:32UTC operator direction resumes completion of Sprint S04 with the
existing developers, independent QA and delivery controller. Keep one active
integration objective: S04-02, followed by S04-03/S04-04 and accepted R4 retained
Sprint obligations. Earlier local source-preservation-only holds are historical.
The current ledger's fresh, finite, independently reviewed recipe remains
mandatory before a host action. No public mail downtime or configuration
mutation is permitted; source preservation does not qualify the password form.

The operator explicitly resumed S04-02, approved the execution guardrails and
requested managed implementation, independent QA and delivery-control agents.
`/root` owns the single canonical Git/host/native queue and current ledger;
`/root/password_engineer` prepares isolated product changes,
`/root/guardrails_engineer` owns the existing acceptance validator/tests and the
separately isolated HTTP fixture integration; it does not independently approve
its own changes,
and `/root/delivery_controller` independently checks scope, evidence, effort,
producer/cleanup/consumer compatibility and installed readiness. Historical
agent names and pause/resumption snapshots below are provenance.

The one active ledger work order and its execution_contract govern S04-02.
Before each expensive/native action, the actual checked dispatcher must call
the existing validator with the exact --attempt-id. PAUSED/BLOCKED,
mismatched source/action, missing prerequisites or out-of-scope
recipes refuse before dispatch. Preserve cumulative effort/history across
workers and attempts; independent reassessment does not erase elapsed work.
Use source-backed environment facts and fixed operation recipes; a newly
discovered assumption is a named gap, not authority to expand infrastructure.
Retain all20 obligations and nine scenarios, matching passing evidence and
operator-account preservation. No new dependency or general QA framework.
Operator UAT follows all required agent-owned passes and independent review.
Normal signed commits, independent review and the current GitHub preservation
SOP apply; operator functional acceptance remains separate.

Only S04-02 resumes. Respect the operator's single completion-message request,
except a concrete blocker requiring operator action. This paragraph records
authorization and policy; it does not claim deployed functionality or that
validator declarations prove evidence truth.

## Current bounded resumption — 2026-10-18

The operator explicitly resumed S04-02 and requested subagents to complete its
nine defined test scenarios. Follow the current active work order and
`docs/UX_SLICE_S04_02.md`. OSMAP-owned Rust implements workflow/helpers, with
fixed bounded existing MariaDB/Dovecot utilities and no new dependencies.
S04-01 stays accepted; other stopped slices do not resume. Historical stop and
closeout text below is provenance. The operator's latest all-work delegation
now assigns `/root/s04_readiness` the single canonical integration, host and Git
execution queue for S04-02; `/root` coordinates, `/root/password_delivery_engineer`
prepares isolated changes and `/root/account_backend` independently reviews.
The operator explicitly authorized current UX-branch push and implementation on
obsd1 against the authoritative mail backend. Do not duplicate the execution queue.
Normal signed source review before any remote synchronization remains required.

## Historical bounded closeout — 2026-10-17

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

For guarded subprocess launches, audit the complete outer guardian, fixture and
helper/client exec chain. Blocking stop signals around Popen is inherited by the
child; restoring the parent mask or signal dispositions does not repair that
child mask. Restore the intended child mask at every changed exec boundary,
preserve unrelated mask state, and use one bounded nested discriminator. Do not
infer a unique historical request failure from a separate shutdown-mask defect.

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
A source author reporting that a review was requested does not establish an
active reviewer. At each frozen handoff, root must dispatch the concrete review
with followup_task and verify running state before waiting. Review-request
messages are advisory; root retains queue ownership and cannot count idle time
as active review. The 2026-10-18 retained-state observer handoff lapse is preserved.
Use the existing execution ledger, decision log and UAT record rather than
creating a parallel status system. Required user journeys need frontend,
backend, persistence and actual integration evidence before readiness claims.
Component tests, page rendering and service health alone do not qualify UAT.
An unresolved failure of a required journey blocks that journey's readiness.
This framework does not change the frozen UX plan or authorize application,
policy, deployment or external side effects beyond the operator's instructions.


Before an expensive/native action, the existing validator may be run with
`--work-order-only --pre-action` as the narrow consistency check defined above.
The actual dispatcher must still bind the exact action, source, recipe and target
and stop if that check refuses.  Do not make historical attempt accounting,
review prose or a complete work-order schema part of this mechanical admission.
Preserve historical facts after the result; package renaming does not erase a
product failure.  Create one concise dispatch/result receipt rather than a new
carrier or ledger layer for each progressive milestone.
The 2026-10-18 compiler2 sequencing deviation remains retained; no retrospective
pre-action PASS may be claimed.
On OpenBSD, do not use getsid(target_pid) across a born child session as a
cleanup authority: the platform contract restricts foreign-session queries,
and session-leader exit can erase the session ID reported by process inventory.
Do not infer historical descendant absence from a PID/SID or accept ESRCH as
proof. Preserve uncertainty, use matching executed control flow plus fresh
namespace/executable/FD/principal ownership for any reviewed recovery, and never
signal a historical PID. The S04-02 native SQL/hash attempt2 wrapper missed this
contract; retain its failure and observed cleanup uncertainty.

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
  the signature, then push through normal hooks under the standing GitHub
  preservation SOP and prove fresh remote equality. Preserve all public-safe
  repository work before the delivery handoff. Source synchronization,
  deployment and operator functional acceptance remain distinct.

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

The operator's standing GitHub preservation instruction authorizes routine
push/synchronization of reviewed, signed work on the current approved branch.
Do not automatically pull, force push, rewrite published history, amend existing
commits or resolve branch divergence. If a push gate fails, preserve the result
and fix the demonstrated issue within the current work order without bypassing
checks or forcing the update. An explicit operator hold takes precedence.

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
- This removes only the manual signing checkpoint. Signature verification,
  independent source review and normal hooks remain required before automatic
  synchronization; operator UX acceptance is a separate outcome.

After each commit, verify:

    git verify-commit HEAD
    git status --short --branch
    git show --show-signature --stat --oneline HEAD

Then report the commit SHA, signature result, changed files, working-tree state
and ahead/behind state for operator inspection. Complete routine synchronization
under the standing GitHub preservation SOP before the delivery handoff. Human
functional acceptance remains separate from source review and synchronization.

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

## Direct delivery and evidence discipline

For an active delivery, follow the existing mutable SOP in
`docs/AGENT_DEVELOPMENT_FRAMEWORK.md`. Each step must fix a demonstrated defect,
answer one necessary question, or verify a required acceptance result. Before
code, state the expected result, essential checks, technical operation bound and
stop condition. Reuse passing checks when their source and relevant boundary are
unchanged; run changed-boundary checks and normal delivery gates at delivery,
not between every unchanged progressive milestone.

Qualify deadlines with the actual intended deployment build profile and artifact
kind, checked from the compiler receipt. Emit safe, actionable, bounded error
categories; report functional failure and cleanup disposition separately. Preserve
same-objective cumulative failure/time history across names, windows and retries.
Two failed attempts at one boundary require combined independent reassessment
before another changed action, using the existing validator and ledger.

Review a frozen producer/cleanup/consumer chain once. Permit only validated
receipt-derived scalar bindings afterward; a semantic/body/source change requires
review of that change. Keep reviewed source, installed workflow, slice acceptance
and human UAT distinct. These instructions add review policy, not new automation
or another approval checkpoint; the SOP identifies the existing mechanical checks
and their limits. Do not alter frozen plan anchors or manifests to record progress.
