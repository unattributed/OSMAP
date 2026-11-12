# Proposed R4 — bounded S04-01 Settings/session delivery

**PROPOSED; NOT ACCEPTED OR ACTIVE. No completion is conferred by this document.**

This revision supersedes the preliminary unaccepted draft in `675844f`: that
draft separated work units but did not actually narrow the slice closure gate.
The corrected scope below separates required epic follow-ups from that gate.

Prepared on 2026-10-17 (America/Toronto) against signed source
`8e47119be63a79695cd95b34b8ca8e66f56b9e1c` on `feat/ux-completion-20260929`.
Operator direction: “Prepare a narrow scope amendment; preserve remaining epic
requirements.” That authorizes preparation of this concrete proposal, not its
activation, a new deployment, synchronization or resumption of stopped slices.

## Decision requested and old/new scope

Accept a revision-specific narrowing of S04-01, with required residual work
owned separately at epic level:

- **Before:** one 57-control delivery boundary combines Settings/session work
  with quota, operational facts, language/delete preferences and account-lifecycle
  destinations. Missing dependent backends prevent the entire boundary closing.
- **Proposed S04-01 (R4 narrowed scope):** the 46 controls listed below cover
  existing Settings navigation, implemented preferences, accurate security/session
  facts, session controls, fixed-offset mail display and saved-value Reset. Their
  original positive/negative tests and security requirements are unchanged.
- **Proposed OSMAP-UX/F1–F9:** nine REQUIRED OPEN epic follow-ups preserve the
  other 11 controls, unchanged acceptance criteria and named dependencies below.
  Effective ownership is epic integration/root; original S04-01 ownership stays
  historical provenance. These are epic work packages, not extra parent slices
  and not optional product requirements.

**On approval, R4 supersedes only the effective S04-01 acceptance boundary.**
S04-01 (R4 narrowed scope) may close after its 46 unchanged applicable controls
and engineering/installed/audit/human exits pass. The 11 required follow-ups are
outside this revised slice closure gate, but continue to block epic/release
acceptance. Use the exact completion label “S04-01 complete (R4 narrowed scope)”
with the retained-follow-up count. Never represent that as completion of the
original R2 57-control scope, its deferred functions or the epic. This is an
actual acceptance-boundary change requiring approval, not merely the bounded
implementation units already permitted by R3.

No approved control or legacy case is deleted: all 403 obligations, 110 legacy
cases and 48 parent slice identifiers remain accounted for. Current results stay
43 partially verified approved controls, 11 blocked approved controls and three
unchanged legacy rows for this original scope. Approval alone passes nothing.
Original owner mappings remain unchanged while proposed; after approval, an
explicit R4 ownership/scope overlay controls revised closure while preserving
R2 history. S04-02 and all other stopped work remain stopped.

F1–F9 remain explicit required work in Sprint S04's remaining-work accounting,
outside the narrowed S04-01 slice gate. Sprint S04 cannot close until its other
required slices and these follow-ups pass. F6's S08-01 backend dependency stays
visible; closing a narrowed slice must not orphan that cross-sprint obligation.

## Why this partition is needed

The single checklist reconciled retained implementation and evidence before new
work. It found concrete timezone and Reset gaps, now implemented in the signed
source above, while the 11 separately named requirements still need distinct
authorities or product decisions. Continuing to investigate those dependencies
inside one Settings/session delivery expands its cost and makes its outcome
unclear. The amendment separates accountable functional exits and retains every
requirement. It does not reinterpret Unknown/disabled states as positive proof.

## Core design and essential verification

Reuse the current Rust Runtime gateway, private per-account preference files,
SessionService and existing mail commands. Do not replace account administration,
add a second storage authority or change mail-service/cryptographic policies.

| Core outcome | Required action and expected result | Relevant negative/recovery boundary |
| --- | --- | --- |
| Discoverable owned Settings | Authenticate, navigate/search supported sections and open the named existing pages; section, heading and account context agree. | Expired/foreign/hostile input cannot reveal another account or execute an action. |
| Implemented preferences work | Save each included preference, reload/restart where relevant and observe its named owning workflow; saved independent preferences remain intact. | Invalid, stale, corrupt, forged and missing-CSRF changes preserve prior/account-B state and report refusal or uncertainty honestly. |
| Timezone and Reset | Save the supported fixed UTC offset and inspect the included mail views; Reset discards unsaved General edits and reloads saved values without writes. | Preserve canonical times, filtering/sorting, message bytes, explicit no-DST semantics and corruption/uncertain-save behavior. |
| Accurate security and session facts | Show actual factors/events/device/browser/activity/current-state data or the specifically permitted Unknown; session counts match owned sessions. | Do not derive trust/health from uptime or fabricate missing facts; preserve escaping and no remote active content. |
| Bounded session management | Exercise included selected/other-session controls, verify affected browser-session denial, current/unselected/Bob preservation and truthful IMAP/SMTP scope. | Keep session authorization, stale/concurrent behavior and cleanup; never imply browser revocation closes mail protocols unless separately proved. |

The exact acceptance tests remain the existing per-control positive/negative
records in `maint/ux/acceptance.json` and the outcome/action/expected/actual rows
in `docs/UX_SLICE_S04_01.md`. This table organizes those tests; it does not replace
any control-specific expected result. Positive permanent-delete policy proof
remains inspect/Cancel/Confirm under policy, not an invented preference to bypass
confirmation. Unsigned ordinary signatures/footers are not OpenPGP signatures.

**Engineering exit:** every core obligation has matching applicable
frontend/backend/persistence evidence, changed security-boundary coverage,
installed functional QA, independent audit with no unresolved required finding,
and verified cleanup or a specifically safe retained-state disposition. Reuse
matching evidence; reconcile source changes and run only missing or affected
checks plus mandatory repository hooks. Do not rerun 403 cases or a full old
browser/native suite solely to fill a register. A mandatory native exclusion is
not native execution; source-only, prior-source and installed outcomes stay
separate. The 43 partial rows do not yet establish this exit.

**Human exit:** only after the engineering exit, request one concise combined
remaining usability judgment for the exact installed version. Reuse the recorded
TOTP, Folders, attachment and protected-mail observations only for their actual
scope; no new credential change/provider Send/private unlock is implied.

## Lossless deferred-requirement register

All entries below are **REQUIRED OPEN epic work**, effectively owned by epic
integration/root after approved R4 activation, outside revised S04-01 closure.
Original R2 S04-01 ownership stays historical provenance. Named dependency owners
identify required deliverables, not authorization to resume them. Before any follow-up starts, use the existing slice SOP to fix
one outcome, finite investigation budget, action/expected/actual checklist,
changed-boundary tests, independent reviewer and safe recovery. Evidence scope
and actual result remain explicit.

### OSMAP-UX/F1 — Language

- Original controls: `R2-11-005`.
- Owner/dependency: Epic/root preference integration (original S04-01).
- Defined outcome: Implement supported language selection and persistence; first define the supported language set and translated surfaces, not a decorative selector.
- Required action/expected result: Save a supported language, reload/fresh login and inspect its defined surfaces. Unsupported/forged/stale saves preserve both accounts and unrelated preferences.
- Actual: OPEN; retain current BLOCKED results and existing evidence limits.

### OSMAP-UX/F2 — Saved delete behavior

- Original controls: `R2-11-012`, `R2-16-007`.
- Owner/dependency: Epic/root preference integration (original S04-01); existing S02-03 mail commands.
- Defined outcome: Persist the finite permitted delete action and apply it through the existing message command path. Permanent deletion remains separately policy-permitted and confirmed.
- Required action/expected result: Save a permitted choice, delete one controlled message and verify the exact destination/disposition; refuse invalid/stale/cross-account changes. Preserve inspect/Cancel/Confirm and retention restrictions.
- Actual: OPEN; retain current BLOCKED results and existing evidence limits.

### OSMAP-UX/F3 — Measured service status and details

- Original controls: `R2-01-028`.
- Owner/dependency: Epic/root status integration (original S04-01).
- Defined outcome: Use bounded, named service measurements with provenance, age and scope; details must agree with the measurements.
- Required action/expected result: Known healthy/degraded measurements produce matching status/details; missing/stale authority stays Unknown. Uptime alone cannot prove mail delivery or workflow health.
- Actual: OPEN; retain current BLOCKED results and existing evidence limits.

### OSMAP-UX/F4 — Backup metadata

- Original controls: `R2-01-029`.
- Owner/dependency: Epic/root status integration (original S04-01).
- Defined outcome: Read the actual authorized backup record, timestamp, outcome and covered scope; no backup execution or new backup service is implied.
- Required action/expected result: A controlled known record renders its exact timestamp/outcome/scope; absent/stale/foreign records cannot invent a successful backup or expose private paths.
- Actual: OPEN; retain current BLOCKED results and existing evidence limits.

### OSMAP-UX/F5 — Update metadata

- Original controls: `R2-01-030`.
- Owner/dependency: Epic/root status integration (original S04-01).
- Defined outcome: Compare authoritative installed and available version metadata under a defined freshness/source policy; this does not install updates.
- Required action/expected result: Controlled known versions produce the expected current/update-available result; missing/stale/untrusted metadata stays Unknown and triggers no installation.
- Actual: OPEN; retain current BLOCKED results and existing evidence limits.

### OSMAP-UX/F6 — Shared storage and Manage Storage

- Original controls: `R2-01-026`, `R2-01-027`.
- Owner/dependency: Epic/root UI integration (original S04-01); S08-01 authoritative shared quota/retention.
- Defined outcome: Expose reconciled mail/document usage and genuine owned management controls only after S08-01 establishes quota authority and concurrent reservation semantics.
- Required action/expected result: Known totals/category sums match authoritative usage; management opens actual owned controls. Missing authority refuses writes; concurrent mail/document writes cannot bypass the limit.
- Actual: OPEN; retain current BLOCKED results and existing evidence limits.

### OSMAP-UX/F7 — Password workflow entry

- Original controls: `R2-11-024`.
- Owner/dependency: Epic/root entry integration (original S04-01); S04-02 authoritative password workflow.
- Defined outcome: Open the genuine own-account workflow and accurately state effects and required step-up. The entry control does not require repeating a successful password mutation.
- Required action/expected result: Authenticated own-account navigation reaches the qualified workflow with actual safeguards; expired/foreign contexts refuse. Do not qualify the positive with a disabled button or generic authentication page.
- Actual: OPEN; retain current BLOCKED results and existing evidence limits.

### OSMAP-UX/F8 — TOTP workflow entry

- Original controls: `R2-11-025`.
- Owner/dependency: Epic/root entry integration (original S04-01); existing TOTP lifecycle authority.
- Defined outcome: Open the actual factor-management workflow with current enrollment state and safeguards. Reuse the recorded operator TOTP_ROTATION=PASS only for its demonstrated scope.
- Required action/expected result: Current own-account navigation/state matches the actual lifecycle route; unavailable/foreign contexts refuse. Do not repeat factor rotation or infer recovery acceptance from the historical PASS.
- Actual: OPEN; retain current BLOCKED results and existing evidence limits.

### OSMAP-UX/F9 — Recovery workflow entry

- Original controls: `R2-11-026`.
- Owner/dependency: Epic/root entry integration (original S04-01); S04-03 contact proof and applicable S04-04 policy.
- Defined outcome: Open genuine contact/coordinator management with actual proof state; preserve independent identity checks and no email-only MFA bypass.
- Required action/expected result: Qualified contact/proof states and owned navigation match the real workflow; pending/expired/replayed/foreign states refuse or remain explicitly pending. The entry check does not duplicate a real-user recovery.
- Actual: OPEN; retain current BLOCKED results and existing evidence limits.

No proposed follow-up is reassigned to the password slice merely because its
owning preference is unfinished. Epic integration/root owns each follow-up exit;
the original S04-01 mapping must not silently reintroduce these 11 controls into
the accepted R4 slice closure gate. Operational facts must have an explicit narrow
measurement interface and cannot introduce a general command runner. Required
quota/lifecycle backends remain accountable in their existing owning slices;
The named epic follow-ups own their visible integration, not duplicate backend implementations.

## Exact core-control inventory

The following IDs are the remaining 46 controls; the union of this list and the
11 follow-up IDs is exactly the original 57, with no overlap. Original wording,
expectations and result states remain unchanged. Original owning-slice mappings
stay historical provenance; the explicit approved R4 overlay would govern
revised closure.

| Control | Original control label |
| --- | --- |
| `UX09-001` | A1/C1/I1 Security |
| `UX09-002` | A4 settings heading |
| `UX11-001` | A11 password status |
| `R2-01-014` | Account security status |
| `R2-10-001` | Settings section selection |
| `R2-10-002` | Security page role |
| `R2-10-011` | Manage active sessions |
| `R2-10-012` | Recent security events |
| `R2-11-004` | Timezone |
| `R2-11-007` | Density |
| `R2-11-008` | Reader layout |
| `R2-11-009` | Configure Appearance |
| `R2-11-010` | Default start page |
| `R2-11-011` | Archive folder |
| `R2-11-013` | Mark-read policy |
| `R2-11-019` | Remote-content enforced state |
| `R2-11-020` | Sanitization enforced state |
| `R2-11-021` | CSP enforced state |
| `R2-11-022` | Source isolation state |
| `R2-11-030` | Save changes |
| `R2-11-031` | Reset section |
| `R2-12-005` | Density |
| `R2-12-006` | Font size |
| `R2-12-007` | Reader layout |
| `R2-12-008` | Show avatars |
| `R2-12-009` | Message preview |
| `R2-12-010` | Actual selected-state preview |
| `R2-12-011` | Save changes |
| `R2-14-001` | Default start page |
| `R2-14-011` | Sent folder |
| `R2-14-012` | Drafts folder |
| `R2-15-002` | Reply placement |
| `R2-15-003` | Include signature |
| `R2-16-005` | Archive folder |
| `R2-16-006` | Bin folder |
| `R2-16-008` | Permanent-delete confirmation policy |
| `R2-20-005` | Active session count |
| `R2-20-006` | Manage sessions |
| `R2-24-001` | Sign out all other sessions |
| `R2-24-002` | Actual device metadata |
| `R2-24-003` | Actual browser metadata |
| `R2-24-004` | Known location or unknown |
| `R2-24-005` | Last activity |
| `R2-24-006` | Current/active state |
| `R2-24-007` | Revoke selected session |
| `R2-24-008` | Browser versus IMAP/SMTP revocation scope |

## Closure equations after accepted activation

- Revised S04-01 closure: all 46 listed controls meet unchanged applicable
  functional, security, installed, independent-audit and human exits.
- Sprint S04 closure: its revised parent slices and all nine required follow-up
  packages pass their applicable criteria; pending backend dependencies block it.
- Epic/release closure: all 403 original obligations, including all 11 required
  follow-ups, and 110 legacy cases pass their applicable criteria; all 48 revised
  parent slices and required epic work packages are dispositioned as accepted.
- Neither equation is satisfied by current PARTIAL/BLOCKED rows or approval of
  this proposal. The original R2 full-57 scope is not retroactively called complete.

## Dependencies, sequencing and cost control

1. Review this concrete proposal. No affected engineering/host action proceeds
   on an unaccepted R4 scope. Preparation does not restart stopped dependencies.
2. If accepted, activate a separate signed planning revision and only then
   specify the current core installed/evidence reconciliation work order.
3. Close only demonstrated core gaps, reuse matching retained passes, qualify
   the exact installation and independently audit that bounded exit.
4. Request minimum remaining human judgment after all agent-owned passes.
5. Plan one follow-up at a time when the operator resumes its relevant scope;
   preserve its dependency wait rather than repeatedly rerunning primitives.
   A newly discovered core gap remains in the core until repaired or explicitly
   amended; do not keep shrinking the core to match passing tests.

The existing one integration owner, one host/native queue, UTC-started finite
investigation, two-failure reassessment and mandatory hooks remain binding.
No new QA framework, duplicate issue register, blanket rebuild or scope-based
failure-history reset is introduced. Forecast the next actual missing work after
reconciliation; no unsupported total completion date is asserted here.

## Security, rollback and activation consequences

No code, authentication, privilege, CSRF, concurrency, recovery, quota, retention,
cryptographic or permanent-delete safeguard changes in this proposal. Deferred
positive controls stay openly unavailable until qualified. Existing usable
features remain usable; this proposal does not disable them or erase prior
operator results. No service, account, credential, key or mail mutation occurs.

R2 anchor `6b3ce8fff27ca3dabf87039d54098bd9967a2e42`, R3 introducing anchor
`f2a117c17dbd93b634f9914c5608473dc682d8e0`, all frozen reference bytes and
`docs/UX_PLAN_SHA256SUMS` stay unchanged while this is proposed. Acceptance and
requirements registers remain byte-for-byte unchanged by this planning draft.

After explicit operator approval of this text: preserve the approval reference
in the ledger, publish the accepted R4 supplement in a separate signed planning
commit with its manifest entry, preserve the old signed revisions, and verify
the new accepted anchor. Update the existing acceptance/work-order validator
and focused policy tests to recognize only that approved lossless partition:
46 controls close revised S04-01; all 403 original obligations, including the
11 required follow-ups, still gate epic/release acceptance and their nine work
packages remain mandatory for Sprint S04 closure. Reject unapproved
scope overrides, omitted/duplicated IDs and upgrades of partial/blocked rows.
Use the existing validator and register, not a parallel QA framework. Do not
activate the revised work order until these existing-policy checks pass.
Do not retroactively upgrade acceptance results. Stop for the
required signed-commit review before synchronization; host delivery requires
its own matching authorized work order. Approval of a plan is not a deployment.

If rejected or withdrawn before activation, leave R2/R3 and the full original 57-control boundary
in force; retain this proposal and its rejection disposition as history. No
runtime rollback is needed because the proposal changes no runtime state. Any
future accepted-plan rollback preserves requirement/result history and restores
the previous work-order boundary without undoing unrelated working code.
