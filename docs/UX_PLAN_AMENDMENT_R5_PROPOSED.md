# Proposed R5 — S09 privacy boundary and S10 security proof

**PROPOSED; NOT ACCEPTED OR ACTIVE. This document does not close S09 or pass a control.**

Prepared 2026-11-12 (America/Toronto) against signed UX-branch HEAD
`ae3386c5b9ad5a477cbddfb3b879202a7a07c02e`. The operator reports that
all S09 human UAT is complete. The loaded obsd1 Web binary is bound to source
`09d880f1657cb2753fee3605859220ad46eaec8b`; source-backed browser
captures exercise 55 actual BrowserApp routes. Those observations establish
the UI/UAT boundary, not adversarial content or cross-account security results.

## Decision requested

Approve a narrow S09/S10 acceptance-boundary change for PAGE-18 while keeping
every security obligation required before epic and release acceptance:

1. **Per-message remote-content exception (R2-18-003).** The current positive
   criterion says to exercise a documented per-message exception. The shipped
   Privacy control is disabled and explicitly says exceptions are unavailable.
   Proposed final S09 behavior: remote resources remain blocked for every
   message, with no per-message bypass; the unavailable control and explanation
   must remain truthful, keyboard accessible, and distinct from the account's
   plain/protected-HTML preference. Replace the positive exception action with
   an actual-helper, owned-message test of the disabled, no-bypass policy and
   zero external requests. Retain a failure-state negative: unavailable
   metadata, locked helper, malformed protected MIME or tampered signature
   must show explicit unavailability without enabling remote resources or
   changing another account's preference. R2-18-003 remains unaccepted until
   those positive and negative checks pass in S10-01 and independent S10-02
   review passes. A future exception requires its own approved security design,
   implementation and new positive/negative tests.
2. **Adversarial PAGE-18 runtime proof (R2-18-001, 002, 004–010).** S09 retains
   the rendered policy-card/reference comparison, source-backed route tests,
   truthful unavailable/failure copy and owner accessibility UAT. Move the
   existing control-specific hostile-message, tracker, CSP, source, active
   attachment, filename, inline-content and Protected-by-Default explanation
   positive/negative execution to S10-01's actual-helper/disposable-account
   journey and S10-02's independent local-synthetic
   security review. Their current `NOT_YET_ACCEPTED` results stay open until
   matching evidence passes. No status is changed by approving this proposal.
3. **PAGE-18 scope explanation (R2-18-010).** S09 verifies the visible text
   accurately explains what “Protected by Default” covers and avoids implying
   OpenPGP verification or message encryption. R2-18-010 itself stays open to
   S10-01: its full negative check must cover expired/foreign navigation, a
   long hostile label and keyboard-focus recovery as well as the positive
   authenticated explanation. Owner UAT and a static capture do not pass it.

UX09-007 fingerprint copy/select, UX09-008 OpenPGP footer/settings and UX17-003
keyboard/focus retain their existing immutable historical rows. Reconcile their
current implementation, route-test and owner-UAT evidence in the execution
ledger; do not rewrite those legacy rows or count their old statuses as current
functional test results.

## Reason and security impact

The reader strips remote images, styles, iframes, scripts and active attributes.
Allowing a per-message remote-resource exception would create a tracking and
content-execution boundary that the current UI and backend do not implement.
Accepting the explicit no-bypass behavior keeps the safer existing policy and
removes an unusable placeholder from the required success claim. The separate
S10 work remains mandatory because a static policy badge or sanitizer unit test
cannot prove live hostile-content containment.

## Dependencies and tests

- Before S09 closure: independently verify the installed-binary/source tie,
  route-backed S09 visual matrix, owner-reported complete S09 UAT, PAGE-18
  truthful policy copy and disabled exception presentation, and the three
  legacy control evidence mappings. The ten PAGE-18 security control results
  remain open. Do not require a second owner login or repeat unchanged broad
  suites solely for this UI boundary.
- Before S10-01 acceptance: use exact-owned controlled accounts and messages
  through actual helpers to inspect one hostile HTML/tracker/active-attachment
  journey, safe source/download headers and bytes, path-like filename,
  zero prohibited external browser requests, disabled no-bypass policy and
  failed/foreign states, including the full R2-18-010 hostile-label/focus case.
- Before S10-02 acceptance: independently review authorization, rendering,
  CSP, parser/resource bounds and cross-account WSTG with local synthetic
  tests; fix and retest findings. S10-01 owns actual-helper execution.
- Before epic/release acceptance: all retained PAGE-18 controls need passing
  control-specific positive and negative evidence. S09 closure under R5 must
  never be reported as S10 security assurance or as full epic completion.

## Rollback and record consequences

The proposal makes no runtime, account, mail-service or source-code change.
If rejected, original S09-03 criteria remain active: implement and qualify a
secure per-message exception before S09 closes, plus complete the original
PAGE-18 runtime tests in S09. If accepted, create a separate signed R5 planning
supplement and manifest update under `UX_AGENT_EXECUTION_CONTRACT.md`, preserving
the signed R2/R3/R4 history. Update the active work order and acceptance
accounting only after that signed anchor is verified; retain all original
case/control IDs and their historical results. An approval alone passes no test.
