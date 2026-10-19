# Functional delivery framework for collaborating agents

Version 1, 2026-10-03. A portable operating framework for development teams using
agents. Adapt the repository, tooling, deployment targets and security rules;
retain the outcome and accountability rules below.

## Mandatory OSMAP delivery SOP — 2026-10-19

The operator applies this SOP to **all OSMAP development**, not only the current
UX epic. It supplements the existing work order, acceptance records and gates;
it creates no parallel planning system or QA framework. Keep accepted product
requirements, repository signing/review rules and higher-priority instructions.
For a documentation-only or similarly limited task, scope prerequisites and
checks to that change; do not contact a live host merely to satisfy this policy.

**Accountable owner:** the lead integration/delivery agent (`/root` in the current
team) enforces the SOP, including against its own proposed actions. The delivery
controller independently verifies compliance and records a refusal when evidence
is missing. Developers provide source and results; they do not approve their own
independent review. The operator is not the team's process monitor or engineering
troubleshooter.

1. **Define the exit before work.** In the existing work order record the one
   user-observable outcome, included/excluded work, preservation requirements,
   source baseline, owners, cumulative elapsed allowance and stop condition.
   Map each required test to prerequisite, action, expected result and actual
   evidence. Planned tests remain NOT RUN. Retain required security outcomes;
   simplify implementation and evidence collection rather than removing them.
2. **Establish the real prerequisites first.** For each changed dependency,
   record the relevant target identity, installed version, schema/configuration,
   exact utility/API contract and authority. Privately inspect real configuration
   where required; never export credentials. Verify a narrow read-only or
   controlled discriminator before building dependent integration or fixtures.
   Reuse matching evidence. A mock of an assumed platform interface is not that
   verification. Mark irrelevant prerequisites not applicable with a reason.
3. **Carry contradictions forward as blockers.** An unsupported configuration,
   unresolved failure or missing authority in earlier evidence must appear in
   the next dependent work order and review. Resolve it with actual evidence
   before dispatch. The lead and controller inspect that evidence directly;
   author reports, manifests and declaration validators cannot supply its truth.
   Review must cover the successful functional path as well as source custody,
   refusal and cleanup.
4. **Implement the smallest complete correction.** Extend the existing working
   application/backend path. Every new helper, service, protocol or test carrier
   needs a demonstrated requirement and an integration/maintenance justification.
   Delegate bounded tasks with file ownership and a measurable exit; keep one
   integration owner and one live/native queue. A diagnostic or fixture repair
   is a prerequisite, not a delivered product capability.
5. **Test only what establishes the exit.** Use focused changed-behaviour tests,
   required security boundaries and existing mandatory repository hooks. Preserve
   matching passes; repeat only when a relevant change or unresolved failure
   invalidates them. Qualify the actual frontend/backend/persistence journey
   before installed readiness. Source, build, native, installed and human
   outcomes remain distinct. No test-count, health or page-rendering substitute.
6. **Enforce the cost and failure stops.** Count all work at the same functional
   boundary across agents, renamed packages, retries and interruptions. Record
   full-action elapsed time or UNKNOWN; never invent token or monetary costs.
   Two failures stop further workflow retries until one combined independent
   reassessment identifies the failed assumption, smallest changed action and
   its distinguishing test. Reassessment does not replenish the allowance.
   An exhausted allowance cannot be increased automatically or by agents alone:
   record the blocker and a bounded proposal for the operator. Necessary safe
   disposition of already-owned effects remains permitted within explicit finite
   recovery bounds; it does not authorize another workflow or expired lease.
7. **Close against observations.** Independently reconcile each required test
   with exact actual evidence and unresolved findings. Preserve failed attempts
   and partial/uncertain effects. Complete normal signed source admission and
   authorized delivery. Offer only the defined minimal human judgment after
   agent-owned implementation, matching functional QA and independent review
   pass. Update the existing ledger, decisions and issues to the same scope.

The existing validator can reject inconsistent declarations, expired allowances
and mismatched planned actions where its checked dispatcher is used. It cannot
prove an omitted environmental fact or truthful review. Those checks remain
explicit lead/controller responsibilities. Do not describe this SOP as an
unbypassable system-level control or as proof that a slice is complete.

The S04-02 configuration error is a retained example: a 10:57 readiness record
already identified an unsupported Dovecot SQL connection configuration, yet
later integration/build admission did not carry that blocker forward. The
schema and MariaDB utility path being known did not qualify the new connection
reader. The elementary actual-configuration test belonged before dependent
composition. Earlier reviews and elapsed work are not retrospectively compliant.

## Purpose and operating principle (framework)

Deliver usable frontend-to-backend behaviour while preserving the application's
working functions and security boundaries. A page, control, build, helper test,
service check or commit is an intermediate result unless it establishes the
promised user outcome. More agents or tests do not make incomplete evidence
complete.

Use existing requirements, backlog, execution ledger and decision log. Do not
create parallel status systems, recurring ceremonies or approval checkpoints
merely to operate this framework. Routine engineering inside the user's scope
proceeds autonomously. Repository rules and explicit user authority determine
what can be changed, deployed, synchronized or submitted externally. A role
assignment supplies responsibility, not additional access or authorization.

## Six roles and their deliverables

| Role | Responsibility and authority inside assigned scope | Required deliverable | Boundary |
| --- | --- | --- | --- |
| Project manager | Translate the user's intended outcome into prioritized acceptance requirements; preserve scope, existing working functions and approved design; resolve product conflicts using existing authority. | A short epic outcome map: required journeys, sprint ownership, dependencies, agreed expectations and unresolved decisions. Maintain it in the existing backlog/ledger. | Cannot redefine a failure as success, remove an unmet requirement or accept on the user's behalf. |
| Scrum leader | Convert prioritized outcomes into bounded work orders; assign agents, enforce file ownership, unblock dependencies and reconcile handoffs. Focus compute on the next unresolved outcome. | Current slice assignment, dependency state, acceptance checklist and next concrete action. Record handoffs and failures in the existing ledger. | Cannot close a journey using component-only evidence, waive security review or silently change approved scope/order. |
| Assigned developers, plural | Implement the complete assigned behaviour across necessary frontend/backend boundaries; preserve invariants, add focused regressions and provide a reviewable change. Parallelize independent file-owned tasks. | Source changes, relevant tests, migration/recovery handling, source identity and concise validation/limits handoff. | Do not edit, stage or commit another owner's changes unless explicitly assigned integration responsibility for those changes. Do not deploy outside authority or certify their own independent QA/security review. |
| QA testers | Independently exercise the actual journey and its changed boundary, including normal use, selected optional features and dependency failures. Verify approved design and interaction, not only returned markup. | Reproducible results for exact source/build/configuration/data scope, observed outcomes and a concise executable UAT. | Fixture/preparation evidence establishes only its exercised scope; it cannot alone establish external delivery, the complete deployed user journey or human acceptance. |
| Security code review auditors | Independently inspect changed trust boundaries, failure semantics, secrets handling and regressions. Challenge the adequacy of the proposed evidence and account for actual configuration. | Prioritized findings with source anchors, consequence, remediation and verification; explicit review scope and residual limits. | Review must not be performed by the author of the assessed implementation. Security review cannot replace functional QA, and cannot invent policy restrictions to manufacture a pass. |
| Technical writer | Keep changed behaviour, decisions, operational prerequisites, recovery and UAT instructions current in the same delivery. Reconcile claims against evidence and remove stale advice. | Updated documentation, decision/ledger entries and completion wording matching actual results. | Cannot claim unexecuted tests, deployment or acceptance; cannot fill missing evidence with reassuring prose. |

The parent/orchestrator retains end-to-end accountability for assignments,
integration, claims and completion. Delegation does not transfer that obligation
to the user or to a subagent. A dedicated technical auditor may investigate
cross-cutting failure independently of the development team.

Roles need not be six permanently running processes. Keep the project manager
and Scrum responsibilities explicitly named; activate developers, QA, security
and writing only when there is concrete work. If staffing requires one agent to
hold several roles, record that arrangement and preserve independence: another
agent reviews its implementation. A self-check is useful but not independent.
When the user requests dedicated role subagents, retain distinct named role
holders and rotate their active turns rather than merging the requested roles.

## Bounded orchestration and compute use

1. Inspect current repository, instructions, actual deployment and existing
   evidence before assigning work. Preserve unrelated changes. Reuse completed
   work instead of implementing it again.
2. Choose the smallest complete user journey that advances the agreed outcome.
   Identify its frontend, backend, configuration and data dependencies. Do not
   split by screen appearance if doing so leaves the outcome unusable.
3. Name owners for files and interfaces. Use multiple developer agents where
   tasks are genuinely independent; serialize edits to a shared module. A single
   integration owner stages, verifies and commits the combined change.
   That owner coordinates Git/index, generated records, deployment and shared
   service mutations; delegate a specific operation explicitly rather than
   allowing concurrent writers. Give parallel tests isolated namespaces and a
   cleanup owner: disjoint source files alone do not prevent runtime races.
4. Limit active agents to available concurrency and useful independent work.
   Queue roles rather than overloading the host. A completed agent can be
   reactivated for follow-up review; avoid duplicating context-heavy audits.
5. Run tests appropriate to the changed boundary and repository-required gates.
   Repeat passed checks only after relevant changes, a changed deployment or
   unresolved evidence invalidates the result. Do not spend compute retesting
   public-key availability when the failing stage is policy or submission.
   Developers run their focused checks; the integration owner runs aggregate
   gates on the frozen combined candidate. Avoid parallel duplicate full suites;
   retain mandatory commit/push hooks and other repository-required repetitions.
6. Require actionable handoffs: what changed, exact source/build, results,
   limits, findings and the next dependency. No generic “looks good” verdict.
7. Stop unrelated development during a user-requested audit/pause. Resuming
   follows the user's direction and existing authority, not agent optimism.

For a four-slot runtime with dedicated management agents, a short planning phase
can use parent/integrator, project manager, Scrum leader and one developer.
Implementation can use parent, Scrum leader and two developers with disjoint
file ownership while the project manager is idle. Freeze the candidate before
review, then schedule parent, independent QA, security review and writer as
needed. Role responsibilities continue while their agent is idle; agent counts
do not establish useful parallelism.
This framework does not promise execution while its runtime is unavailable.
After interruption, reconcile the ledger, current source/runtime and possible
side effects before retrying.

Three enforceable checkpoints keep the framework operational: **before task
dispatch**, the Scrum leader records a matching work order and owners; **before
completion**, the parent reconciles independent QA/security findings and exact
journey results; **on reported failure**, the parent reopens the affected result
and assigns root-cause work. Missing evidence changes the claim or blocks that
case; it cannot be replaced by another agent's agreement.


Accountability uses the existing work order and gate: name one functional exit
and owner, a UTC-started bounded investigation and actual full-action elapsed
wall-clock or explicit UNKNOWN/UNMEASURED. Do not invent token/compute cost or
sum host intervals into an unmeasured delivery duration. Before an expensive or
native action, independently review the whole successful producer → cleanup →
consumer path. Every failed/unconfirmed retry names its concrete change. After
two unreviewed failures at the same functional boundary, record a combined
independent reassessment and next action before proceeding; successor/package
renaming and fixture/product labels do not reset it. Completed reassessment may
start an investigation only within the remaining authorized allowance; it does
not extend an exhausted delivery budget. All prior IDs/facts stay retained.
Fixture repair is distinct from product delivery. Pre-adoption history remains
historical, not retrospectively compliant. Validate declarations honestly: a
structural gate cannot prove evidence truth, complete history or useful software.
Do not add a separate board, runner, routine approval or repeat QA campaign.

## Close the workflow, not just its components

Use these execution rules within the existing scope, ledger and review gates;
they add no status board, approval ceremony or acceptance requirement:

- **Keep one active integration objective.** Developers can work in parallel on
  its independent dependencies. Every component handoff names the remaining
  connection to the promised user outcome and its owner. The parent completes
  that connection; accumulating reviewed helpers is not the objective.
- **Probe the riskiest real dependency early.** Before expanding implementation,
  check the applicable native API, runtime version, transport, schema and
  configured authority with the smallest authorized discriminating probe.
  Establish actual behaviour before building a large fixture around an assumed
  platform interface. Keep its scope explicit; a probe is not workflow QA.
  Carry already measured platform limitations into subsequent work orders and
  reviews. Reuse the existing qualified compatibility path rather than writing
  the unsupported interface again. Include a discriminator for the interface
  being absent; a method-bearing mock cannot establish native compatibility.
  A known source/platform contradiction should be fixed before another host
  invocation, without repeating a native failure merely to rediscover it.
- **Reuse working paths first.** Compare a gap with the existing application
  and deployed backend. Extend the narrowest suitable path. Introduce a helper,
  protocol or service only for a demonstrated functional or security need;
  explain the need and the integration cost in the existing decision record.
- **Test the successful outcome as well as refusal.** A negative security test
  cannot qualify a feature whose successful path has not run. Exercise the
  actual frontend-to-backend boundary before asking the user to qualify it.
  Keep required provider observations pending when outside agent authority.
- **Diagnose a failed attempt before another attempt.** Retain the failing
  case, stage and bounded sanitized diagnostic. Fix missing diagnostics before
  repeating a fixture whose cause is unknown. Change only a justified boundary;
  preserve original assertions, budgets and security requirements. Two failed
  attempts at the same boundary trigger parent/independent-review reassessment
  of the fixture and architecture before further iteration, not a new ceremony.
- **Freeze once, review the delta, then integrate.** Native execution uses
  immutable exact inputs, a single executor and explicit cleanup ownership.
  Never edit a packaged candidate during execution. Run focused developer
  checks and one matching aggregate integration pass; repeat only for relevant
  changes, unresolved failures or mandatory repository hooks. Do not add full
  suite repetitions merely to count another review.
- **Treat interruption accurately.** Network reachability, agent/model capacity,
  host execution and application failures are different causes. Reconcile
  possible side effects, then retry the interrupted assignment when safe.
  A capacity failure does not diagnose the user's internet or the application.
  Reuse or reassign the bounded task instead of restarting the epic.

At each handoff, the Scrum leader identifies the next executable step toward the
same outcome, removes duplicate assignments and escalates only a concrete
dependency needing the user's action. Progress reports lead with delivered
behaviour and remaining acceptance; commit and test counts are supporting facts,
not substitutes for usability. Retain the user's requested message frequency.

## Work order: one entry in the existing ledger

Use this short record before implementation; link existing requirements instead
of copying them:

```text
Slice / sprint / requirement references:
User journey and observable success:
Existing working behaviour that must remain working:
Approved design / policy expectation:
Baseline source, build and relevant configuration/data scope:
Assigned role holders; developer file ownership and integration owner:
Dependencies and existing authority for source, deployment and side effects:
Focused tests and required repository gates:
QA/security review target; recovery or rollback where applicable:
UAT cases, required observations and unresolved limits:
Investigation budget/checkpoint and failure stop rule:
Shared service/test namespace and cleanup owner:
```

Tests must discriminate the requirement from the current defect. Include a
counterfactual at the changed boundary: for example, an ordinary operation must
remain usable with an optional feature disabled, while requesting that feature
must fail safely if its required dependency is missing. Never bypass an
intentionally required policy to label the ordinary operation successful.

## Evidence facts and claim levels

Track these as separate facts; they are not interchangeable labels:

| Proof or claim | Evidence required | What it does not establish |
| --- | --- | --- |
| Source tested | Exact source revision and actual focused/required test results, including failures and skips. | Native behaviour, installation, external integration or usable browser flow. |
| Native validated | Matching source tested on the required operating system/runtime with relevant isolation and dependencies. | Deployment of that binary or actual user journey. |
| Deployed | Installed build identity and relevant configuration correspond to the assessed candidate. | Functional success or UAT readiness. |
| QA verified | Independent execution of the promised journey in the applicable environment, using the right configuration/data, with observed results. | User acceptance or untested providers/accounts/modes. |
| UAT ready | Required engineering, security and QA evidence for the stated scope passes; exact human steps and expected outcomes are actionable; remaining human/provider observations are explicitly pending. | The user has accepted the sprint or a pending external observation has passed. |
| User accepted | The user's actual acceptance reference and recorded UAT outcomes satisfy that scope. | Other sprints, environments or the entire application are accepted. |

If a remaining provider observation is itself a required success criterion and
no matching engineering integration result exists, record a handoff for first
human qualification rather than UAT ready for that journey.

UAT readiness requires a runnable independently QA-verified path in the declared
matching environment. Legitimate human-only prerequisites and final usability
judgments can remain pending, with their exact scope stated. If a required
integration is unverified or a known user failure persists, label that case
blocked/not ready. A limited handoff for first human qualification must say
precisely what remains unverified; availability of a test plan is not whole-sprint
readiness.

Use `not run`, `pass`, `fail`, `blocked` and `unknown` for individual cases. A
skipped required case is not a pass. Keep component deliveries useful and
reviewable without calling their parent workflow complete. Sprint completion
requires its required journeys to satisfy their defined acceptance; epic
completion requires all required sprint outcomes and unresolved findings to be
reconciled. Never infer either from commit titles or test counts.

For each result, retain a compact sanitized record:

```text
Case ID / requirement / owner / timestamp:
Source revision; installed build identity where relevant:
Environment; relevant configuration/policy revision; fixture or account scope:
Starting conditions and actions actually executed:
Expected result; observed result; pass/fail/blocked/unknown:
Evidence reference; findings and residual limits:
Submission/side-effect identity and reconciliation status where relevant:
```

Record only the configuration relevant to the outcome; redact secrets, tokens,
private content and personal data. Use fingerprints, revisions, counts, hashes
and finite stage/reason codes where suitable. A build plus the wrong account
policy or fixture does not prove the user's journey.

## Required functional coverage

Apply this matrix to the changed journey, adapting names to the application:

| Scenario | Required question |
| --- | --- |
| Normal use | Does the baseline operation work under the intended permitted configuration? |
| Optional feature off | Does disabling an optional feature preserve the baseline operation without requiring that feature's private resources? |
| Feature selected or policy required | Does the full selected behaviour execute, and is the output observable at its real destination? |
| Missing, locked or failing dependency | Does the affected operation refuse safely, preserve user work and identify the actual stage without silently downgrading? |
| Saved/resumed/retried state | Do persisted choices, changed configuration and recovery work without stale loops or duplicate side effects? |
| Actual configuration and data | Does the deployed path use the user's intended authority/data source, account, policy and runtime rather than a convenient fixture? |
| Security and design | Do ownership, authentication, bounds and isolation remain intact, and do approved controls work visibly with accessible/error states? |

For external side effects distinguish prepared, dispatched, accepted by the
transport, stored and observed at the destination. “Submitted” is not
“received.” Do not automatically repeat an ambiguous operation. Reconcile its
known identity and read-only records first; retain unknown status if the
outcome cannot be established. Coordinate a single actor for each actual
submission, including user-controlled UAT, so agents do not send in parallel.

## A user failure reopens readiness

A credible failed UAT attempt immediately reopens the affected case and
readiness claim. Preserve earlier valid evidence with its scope; it does not
overrule the failure. The Scrum leader assigns investigation and the parent
owns resolution. Capture the actual operation, source/build, policy/state and
failure stage, then implement or reconcile the diagnosed cause and verify that
same journey. Do not rename the failure a successful negative test when the
promised outcome was success.

Keep unsaved work recoverable. Do not repeatedly ask the user to reopen, unlock,
reconfigure or try again without establishing that the requested action addresses
the current diagnosed cause. If a secret, hardware action or inaccessible
provider observation genuinely requires the user, finish independent work and
provide one specific action with its reason and expected result. Human UAT is
acceptance, not a substitute for engineering diagnosis.

## Commit, documentation and delivery

Use the repository's signing, review, synchronization and deployment rules and
the user's standing authority. Keep reviewable commits contextual: behaviour,
reason, relevant validation and limits. Keep decisions and operational/UAT
documentation current in the same delivery; separate documentation-only
delivery from runtime readiness. Do not add signing or approval requirements
to a repository that does not require them, or waive those that it does.

Use one completion message per agreed slice/sprint; exceptions are genuine
blockers or required human interaction. State what works, what was actually
verified, exact delivered identity, concise UAT and remaining limits. During
unchanged ongoing work, stay quiet according to the user's communication
preference and applicable higher-priority instructions.

Concise UAT template:

```text
Scope and readiness: [slice/sprint; engineering/QA state; pending acceptance]
Candidate/environment: [source/build, URL or entry point, relevant account/policy]
Prerequisites: [only those needed, with verified status or explicit pending step]
1. [Action] -> [observable expected result]
2. [Action] -> [observable expected result]
3. [Action] -> [observable expected result]
Pass criteria: [complete outcome, including destination/storage if required]
Observed results: [case IDs; actual results, or not run for human UAT]
Limits: [remaining modes/providers/acceptance, without unsupported claims]
Failure handling: [preserve work; reference/finite reason; no blind resubmission]
```

## Reusable assignment prompts

Each prompt inherits the bounded work order, repository rules and current user
authority. Substitute concrete references; never delegate an undefined epic.

- **Project manager:** “Map the user's required outcomes to existing epic/sprint
  records. Identify working invariants, acceptance gaps, intended policy and
  approved-design constraints. Prioritize the next complete journey. Preserve
  scope; do not create a parallel backlog or claim user acceptance.”
- **Scrum leader:** “Assign this slice's independent tasks and file ownership.
  Coordinate dependencies, integration and independent reviews. Keep one ledger
  current, reopen failed cases and return the next concrete unresolved action.
  Do not close the workflow from component passes.”
- **Developer:** "Implement [behaviour] in [owned files], preserving [invariants].
  Coordinate [interface] with [owner]. Add focused regressions for [defect] and
  run assigned focused checks; hand off aggregate gates to the integration owner.
  Return diff/source identity, actual results, limits and
  dependencies. Do not edit another owner's files or certify independent QA.”
- **QA tester:** “Independently exercise [journey] against [candidate/config/data].
  Cover baseline, optional-off, selected feature, dependency failure and saved
  state as relevant. Check real interaction/design and required integration
  outcomes. Return reproducible observed results and concise UAT; mark pending
  provider/human observations explicitly.”
- **Security auditor:** “Review [candidate diff and boundary] independently of
  its author. Check authorization, isolation, bounds, secrets, failure behaviour
  and regression evidence. Challenge whether tests cover the actual journey and
  policy. Return actionable findings, scope and residual limits.”
- **Technical writer:** “Update existing change, decision, operational and UAT
  documentation for [delivery]. Reconcile each claim against actual results,
  replace superseded recovery advice and distinguish component/deployment/UAT
  states. Return changed documents and unresolved evidence; invent no outcomes.”

## Portable repository adoption

Place this document in the repository's documentation directory, adapt its
record paths to existing conventions and add a discoverable instruction such
as the following to that repository's agent entry point:

```text
For multi-agent development, read docs/AGENT_DEVELOPMENT_FRAMEWORK.md.
Before dispatch, record the user journey, preserved invariant, file ownership,
applicable authority and acceptance cases in the existing execution record.
Before completion, reconcile independent QA/security results for the actual
candidate and configuration. A known failed required journey is not ready.
Keep documentation and decisions current in the same delivery. A failed UAT
reopens the affected case and assigns engineering investigation.
Use existing repository gates, signing/synchronization rules and user authority;
this framework introduces no additional approval checkpoints.
```

This is a reusable adoption snippet, not a global installation. The parent must
actually create bounded assignments, obtain the relevant independent reviews and
enforce the checkpoints; writing this document alone does not launch a team or
prove a development outcome.

## Direct delivery lessons applied to S04-02

### Operator-approved executable guardrails — 2026-10-19

S04-02 uses its existing active ledger work order plus an execution_contract:
two explicitly identified environments with dated sanitized evidence; demonstrated
gaps mapped to the unchanged nine scenarios; fixed source/discovery/native/install
recipes with permitted paths, commands, privileges, prerequisites and expected
observations; a cumulative remaining-work allowance and an exact planned action.
Use the existing acceptance validator, not another board or execution framework.

The actual dispatcher checks --work-order-only --pre-action --attempt-id before
SSH/spawn and aborts on refusal, timeout or missing output. PAUSED/BLOCKED cannot
dispatch development. Native/install authority requires matching PASS environment
and prerequisite artifact pins; bounded read-only discovery may resolve explicitly
PENDING facts. Declaration validation and file hashes do not establish facts are
true; the independent reviewer inspects their contents and actual consumer.

Root retains one objective and service/native queue. The independent delivery
controller checks useful progress, exact cleanup and all failed-boundary history.
The initial resumed allowance is7200seconds from the ledger's recorded UTC start,
with1800second investigations. It includes integration/review/build/publication
time across workers; parallel wall-clock is not added twice. Historical token and
monetary costs and unmeasured intervals remain UNKNOWN. Increasing an exhausted
allowance requires explicit operator authorization and preserves cumulative
consumed time, original action/fixture deadlines and prior failures. Root and
controller cannot replenish it themselves. Necessary safe disposition of owned
effects remains separately bounded; it does not authorize a workflow retry or
fixture renewal. No silent clock reset.

Before coding, record the smallest demonstrated gap and its discriminating test.
Reuse working Rust, standard backend utilities and matching passes. Qualify one
complete controlled installed journey for overlapping scenarios; retain distinct
replay/race and interruption checks. Do not build unrelated targets or introduce
diagnostics without an unanswered causal question. Required installed QA and
independent audit precede minimal separate owner UAT. No source-only acceptance.

Use one small delivery loop: fix a demonstrated defect, answer one necessary
causal question, or verify an existing acceptance result. Before changing code,
record the expected observation, essential changed-boundary checks, finite time
allowance and stop condition in the existing work order/design record. Do not
substitute new diagnostic mechanisms for a working user journey. Reuse still-valid
passing checks; retain the normal mandatory commit and push gates.

Record and check the actual deployment Cargo profile and artifact kind. A debug
build can establish functionality but cannot qualify production deadlines. Keep
full security checks while investigating performance. Error categories must be
payload-free, finite and actionable; diagnostic output must not prevent cleanup.
Keep functional PASS/FAIL/UNKNOWN separate from cleanup PASS/FAIL/UNKNOWN.

The same password objective retains cumulative failed attempts and elapsed-time
history across packet names and continuation windows. Record actual measured
segments and UNKNOWN gaps honestly; neither renaming work nor acknowledging a
review erases its cost or failed outcome. After two failures at the same functional
boundary, combine the evidence and independently reassess the next changed action.
Preserve the original nine S04-02 scenarios as the end-to-end exit; a component
pass does not replace them or authorize a slice-completion claim.

Review the exact frozen producer, cleanup and consumer chain once. Later actual
hash/size/path/lease substitutions require deterministic binding checks against
receipts. Review any nonbinding semantic change before execution. Controlled native
qualification may precede final VERIFIED-to-COMMITTED admission under the existing
contract, with signed-base and candidate identities explicit. Final completed
source still requires normal signing, push authority and fresh remote equality.

Existing enforcement and review-policy limits:

| Rule | Existing mechanism and limit |
| --- | --- |
| Bounded declared action, owner and combined failures | `maint/ux/validate_acceptance.py --work-order-only --pre-action` checks the declared current window, stable boundary, exact failed IDs and independent reassessment including the executor. It does not infer that a renamed boundary is semantically the same objective or measure all historical wall time; preserving that identity and cumulative history is review policy. |
| Profile, artifact and runtime bindings | The current reviewed native compiler/transport receipts check actual release profile, real helper versus libtest kind, source/artifact hashes and held file leases. Future carriers must retain those reviewed checks; this document adds no universal profile validator. |
| Required checks and source preservation | Existing normal commit/push hooks run the repository gates; signature and fresh tracked-branch equality are verified separately. Choosing essential changed-boundary tests and avoiding redundant unchanged runs remains review policy. |
| Safe diagnostics and cleanup | Current reviewed closed consumers reject unknown/error payloads and retain cleanup uncertainty. Newly reviewed causal diagnostics separate client category, terminal helper scope and owned pre-stop status; native qualification is still pending. These are scoped mechanisms, not a claim that every application error is instrumented. |
| Source, installed workflow and acceptance | Existing acceptance validation checks declaration/scope consistency, not evidence truth. Independent observation, the original nine scenarios and operator UAT determine delivery readiness. Source-only synchronization cannot close S04-02. |

These lessons extend the existing work-order schema and acceptance validator,
with updates to the mutable SOP and AGENTS. They create no parallel governance
framework, test matrix, approval flow or frozen-plan edit.
Current S04-02 sequence is one bounded C04 causal observation, the demonstrated
repair, then the original full installed password workflow and independent review.
