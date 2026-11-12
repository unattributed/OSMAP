# OSMAP UX revision 5 — accepted S09/S10 privacy boundary

## Operator approval and authority

**Accepted on 2026-11-12 (America/Toronto).** The operator answered
“Approve R5 proposal” to the explicit question asking whether to keep the
per-message remote-content exception disabled, close S09 after UI evidence
reconciliation, and require all ten PAGE-18 security tests in S10 before epic
and release acceptance. This is approval of the exact prior proposal
`docs/UX_PLAN_AMENDMENT_R5_PROPOSED.md`, SHA-256
`e4cf065f0c354204523ac0494ad1b791042b4ecf1dc903467bbb6f9316ab6653`.
Its proposal-only wording remains historical provenance. The introducing
Shopkeeper-signed planning commit and manifest pin this accepted supplement;
approval alone does not pass a test or close S09.

## Effective requirement and retained controls

R5 supersedes only the S09/S10 boundary described in the approved proposal.
The signed R2/R3/R4 plan, approved reference images, 403 control IDs, 110
immutable legacy rows and original acceptance history remain preserved.

- S09-01 through S09-04 close against verified final UI, truthful policy
  presentation, source-backed routes, exact installed Web binary/source tie,
  independent UX/accessibility review and the operator's complete S09 UAT.
  Reconcile UX09-007, UX09-008 and UX17-003 in the ledger without changing
  their historical rows. S09 closure is not an assertion that the PAGE-18
  adversarial security controls passed.
- R2-18-003's effective positive requirement is a disabled, no-bypass
  per-message remote-content policy: protected rendering blocks remote
  resources for every message, and the unavailable exception control explains
  that truth accessibly. The account's plain/protected-HTML preference is
  separate. S10-01 must test the effective positive behavior through an
  actual-helper owned-message journey, including zero prohibited external
  requests. Its failure-state negative must show explicit unavailability for
  missing metadata, locked helper, malformed protected MIME or tampered
  signature without opening remote resources or changing another account's
  preference. A future exception needs a separately approved security design.
- All ten R2-18-001 through R2-18-010 remain required, open and blocking for
  epic/release acceptance. S10-01 owns their actual-helper, controlled-account
  positive/negative execution. R2-18-010 includes expired/foreign navigation,
  long hostile label and keyboard-focus recovery. S10-02 owns independent
  local-synthetic security review, findings repair and retest. Its review is
  distinct from S10-01 runtime proof. No current `NOT_YET_ACCEPTED` result is
  changed by this amendment.

## Admission, evidence and rollback

Verify the original plan manifest entries, this supplement and the proposal
digest, the introducing commit's Shopkeeper signature, and the active work
order before recording R5 as the effective boundary. The ledger records the
operator approval and separate S09 closure evidence. The acceptance validator
is a consistency check, not evidence truth or functional acceptance.

No host, account, mail service, key or product source is changed by this
planning supplement. If R5 admission fails, retain the failure and keep S09
open under the prior signed plan while correcting the specific plan defect.
Any later rollback requires an approved amendment; preserve this signed
history and all ten security obligations. Sprint S10, the epic and the release
cannot close while their retained security controls lack matching proof.
