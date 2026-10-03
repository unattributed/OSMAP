# OSMAP adoption of the functional agent framework

2026-10-03. Applies the portable
[agent development framework](AGENT_DEVELOPMENT_FRAMEWORK.md) to the approved
OSMAP full-functional UX epic. This is an execution/documentation framework,
not a replacement epic, plan amendment, application repair or deployment.

## Existing authority and records

The approved design, requirements, slice IDs and accepted signed plan remain
authoritative. Read the epic, slice catalog, execution contract and current
ledger before work; verify their existing trust anchor/manifests as required.
This adoption does not edit frozen plan files, loosen security requirements,
reorder slices or create additional approval checkpoints. Direct user direction
supersedes conflicting historical execution defaults within its authorized
scope; record that authority in the existing ledger.

The user explicitly authorized collaborating agents and immediate GitHub
synchronization of completed signed commits. Current AGENTS.md records that
source workflow. Git synchronization is separate from installation, functional
QA and user acceptance. Keep Shopkeeper signatures and contextual commit bodies;
verify signatures and source synchronization without claiming runtime repair.

Retain the existing `NOT_STARTED -> IN_PROGRESS -> VERIFIED -> COMMITTED ->
ACCEPTED` state machine, with `BLOCKED` preserving the prior state. Record
synchronization, deployment, QA results and human UAT as separate fields; the
framework's evidence levels do not create another status board.

Use existing records instead of parallel project administration:

| Framework record | Existing OSMAP location |
| --- | --- |
| Requirements, approved design and sprint scope | `docs/UX_FULL_FUNCTIONAL_EPIC.md`, `docs/UX_FULL_FUNCTIONAL_SLICES.md`, frozen approved design bundle and `maint/ux/approved_pages.json` |
| Work orders, assignments, state and actual results | `docs/UX_EXECUTION_LEDGER.md` and linked sprint-root evidence |
| Technical/product decisions and authority | `docs/DECISION_LOG.md` and existing `docs/UX_DECISIONS.md` records |
| Required coding/security/native gates | `AGENTS.md`, `docs/UX_AGENT_EXECUTION_CONTRACT.md`, Makefile entry points and boundary-specific gate instructions |
| Operator UAT steps/results | Current sprint-root `UAT.md`, linked from the ledger |
| Independent failure/historical review | S05 sprint-root `AUDIT.md` and `HISTORICAL_MAIN_COMPARISON.md`; preserve these completed reports |

Retain new S05 artifacts beneath the existing owner-only
`/home/foo/Downloads/osmap-ux-s05/` root. Keep secrets and protected mail outside
Git and retained evidence. Record sanitized identity, revisions, hashes, finite
failure reasons and outcome metadata.

## Role deployment for this epic

Name the project manager, Scrum leader, developer owners, independent QA and
security reviewers, writer and parent integration owner in the next ledger work
order. This document defines assignments, not evidence that those agents are
currently running. The parent remains accountable for integration and claims.
On application resumption, assign dedicated project-manager and Scrum-leader
subagents; rotate their active turns around development and independent review
so management responsibilities do not consume all available process slots.

- The **project manager** keeps the agreed ordinary and protected mail outcomes
  visible, reconciles intended recipient policy and approved design, and tracks
  outstanding acceptance across existing sprints.
- The **Scrum leader** chooses the next authorized slice work, coordinates file
  ownership and dependencies, and refuses to equate an engineering checkpoint
  with a completed mail journey.
- **Developer agents** implement distinct owned boundaries where they can work
  independently: for example, diagnostic/backend behaviour and UI persistence.
  Shared gateways/models have one editing owner. Do not invent parallel work or
  change slice order just to increase active agent counts.
- **QA testers** verify real usable controls and matching browser-to-backend
  outcomes on the development candidate, plus focused native regression cases.
  Synthetic accounts, local SMTP sinks and preparation probes retain their
  useful but limited scope.
- **Security auditors** independently review changed trust boundaries, policy
  semantics, GPG/helper isolation and failure behaviour. The technical auditor
  can additionally review failure attribution and acceptance evidence.
- The **technical writer** keeps ledger, decisions, prerequisites, recovery and
  UAT current, and removes superseded instructions without rewriting historical
  outcomes. Documentation must not imply pending receipt or user acceptance.

Use available concurrency efficiently: active implementation plus independent
review when there is concrete work; queue roles otherwise. Do not require six
simultaneous agents or repeat passed audits after documentation-only changes.

## Baseline functions to preserve

Historical pre-V14 source and recorded pilot evidence support usable ordinary
mail. They do not qualify today's migrated host or protected-mail integration.
Preserve these behaviours while completing the approved UX:

- Authenticated users can read authoritative mailbox data and perform permitted
  ordinary Compose, Draft, Reply/Forward and attachment Send operations.
- Optional OpenPGP choices being Off do not require private signing/decryption
  resources. A deliberately Required account/recipient policy is still enforced;
  reconcile that rule with the expected outcome before offering a success UAT.
- Selected protection is honoured without fallback to plaintext. Missing or
  locked resources produce an attributable refusal and preserve user work.
- Persisted choices and binding revisions can be recovered without stale loops;
  accepted or ambiguous submissions cannot be silently duplicated.
- Submission, authoritative Sent storage and destination receipt remain distinct
  results. An accepted transport handoff cannot imply recipient decryption or
  signature verification.
- Approved controls have working backend behaviour, accessible interaction and
  truthful state. Painted or disabled placeholders remain incomplete.

Continue required Rust/security gates, relevant V12/V14 and native OpenBSD
verification for affected boundaries. Strict release evidence remains separate;
this framework cannot convert development checks into a release qualification.

## Acceptance reset established by the audit

The audit records current ordinary Proton Send failure and unaccepted protected
delivery. Preserve valid component results, but keep these journeys unresolved
until matching evidence exists. The latest reported plaintext Send failure is
not a successful negative test: its intended outcome was ordinary mail.
The matched `/send` 503 occurred at 06:18:00 UTC on October 3, 2026, after the
assessed deployment. This supersedes the earlier ledger/UAT statement that no
operator Send had occurred after deployment; preserve that old entry as history
and link the correction rather than treating it as current evidence.

At the assessed binding revision 5, account signing/encryption were Optional
and Proton recipient encryption was Required. Earlier bootstrap/metadata were
Optional; the actor who changed the recipient requirement is unknown. This is
a dated audit observation, not a permanent configuration assertion. Reinspect
actual state before any authorized repair; do not assume an unlock will resolve
an all-off policy refusal or attribute the policy change without evidence.

The ordinary Send expectation and required-recipient policy must be reconciled
using the user's intended behaviour and existing typed revision-checked
operation. Preserve approved fingerprints and unrelated state. This adoption
performs no policy update, private-key operation, service restart or Send.

Use a bounded next work order, when application work is authorized to resume:

| Journey | Observable pass criteria | Current acceptance at adoption |
| --- | --- | --- |
| Fresh ordinary Duncan-to-Proton message, all protections Off | Permitted policy; one browser Send; attributable accepted result; readable authoritative Sent copy; actual recipient receipt. No private-key unlock prerequisite for ordinary bytes. | Failed/unaccepted; configuration expectation requires reconciliation. |
| Saved Draft ordinary Send | Saved recipients/body/attachment/choices survive resume; one accepted submission, correct Sent copy and receipt; no stale-revision loop. | Unaccepted. |
| Encrypt-only Proton Send | Stored approved recipient certificate is used; browser-selected encryption reaches actual submission and destination; Proton decrypts expected content. | Preparation/public encryption proof exists; actual protected delivery remains unaccepted. |
| Signed, encrypted, self-readable Send | Exact account signing key and approved recipient key; decrypted content and verified signature at recipient; readable encrypted authoritative Sent. | Native crypto proof exists at recorded unlock time; complete journey remains unaccepted. |
| Encrypted return to Duncan | Authoritative Inbox receives return; reader decrypts and reports actual signature state safely. | Unaccepted. |
| Public-key lifecycle | Human fresh-auth import/bind/change/remove operations persist their actual intended results, with invalid/stale requests refused safely. | Human UAT remains unaccepted. |

This list focuses the audit's unresolved journeys; it neither removes other
epic requirements nor changes their slice ownership or acceptance order. QA must
record exact source, installed build, relevant policy revision, account/data
scope, executed actions and actual outcome. Do not rely on historical deployment
snapshots or `PASS` labels from a different journey.

The development frontend is `obsd1.blackbagsecurity.com`; mailbox reads and Sent
storage must use authoritative `mail.blackbagsecurity.com` data under the current
approved integration. Submission and mailbox storage are distinct paths. Verify
their actual identities/configuration instead of assuming that the old hostname
or a healthy service means the intended backend is in use.

The user controls the next actual external Send under the current direction.
Do not submit a parallel agent email, execute obsolete probes or automatically
repeat an ambiguous attempt. Arrange one bounded user action only after the
team has established its prerequisites and expected result; engineers own
diagnosis and reconciliation rather than asking the user to babysit retries.

## UAT and completion contract

The next UAT handoff must identify its exact tested scope and pending human or
provider observations. If those observations cannot be made by agents within
authority, mark them pending and explain the single necessary step. Do not
declare all Send repaired, a sprint accepted or the epic complete from fixtures,
helper crypto, preparation, HTML, service health or source/binary parity.

Each test has observable expectations and retained results. A failed user
attempt reopens readiness immediately and creates a root-cause engineering task;
previous passes remain scoped records rather than rebuttals to the user.
Keep draft content and selected protections through failure/recovery. Do not
offer the same unlock/reopen advice again without new evidence that it addresses
the diagnosed failure.

Use the framework's concise UAT template. A normal completion message gives:
the delivered behaviour and candidate, actual relevant verification, a few exact
browser actions with expected results, pending acceptance and verified limits.
Respect the user's single completion-message preference, with genuine blocker
or necessary human-interaction exceptions. Documentation-only completion reports
this framework delivery, not application repair or readiness.
