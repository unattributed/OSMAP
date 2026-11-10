# S08-05 — Logo continuity

## Current outcome — 2026-11-10

Use the existing login shield/keyhole logo on every page with the shared OSMAP
header. The owner clarified that this is a simple logo-continuity correction.
Keep existing wording, navigation, authentication and page behaviour. Adjust
only the logo sizing needed by the existing header. No new module, dependency,
backend operation or page redesign is required.

Original S08 remains owner-accepted and closed. S08-06 icon display mode and
S08-07 Junk remain separate queued extensions before S09. Documents remains
removed. The November 9 wider branding plan and partial edit are retained under
`/home/foo/Downloads/osmap-ux-s08/s08-05/`; they are historical inputs, not
requirements to change the tagline or run a new page-by-page test campaign.

## Work and checks

Reuse one trusted static SVG in the login renderer and shared authenticated
header, covering welcome and ordinary pages. Existing branded Settings, reader,
source/error, folder, notification, Snooze and Outbox renderers use that header.
Unbranded responses do not gain a new header.

Use one focused regression comparing the actual logo in login, welcome and
ordinary headers while preserving the home link and existing copy. Check the
existing synthetic page renderer and a desktop/narrow browser view, including
light/dark appearance. Run the normal delivery hooks and affected UI gates.
Qualify the matching OpenBSD Web build and Web-only installation with the
existing rollback, loaded-binary and preservation checks. Then offer a short
owner visual check; owner acceptance is separate.

Root owns source, Git, host integration and writing. The dedicated
`/root/s08_scrum` coordinates; `/root/s08_delivery_review` supplies independent
QA/security/delivery review. Preserve failures and unknown historical cost.
Two failures at the same boundary stop retries for combined reassessment.
Reuse existing tooling and evidence; no new test framework or Python tooling.

Engineering status: UAT_READY for the logo-only extension, as recorded below.
Owner acceptance remains PENDING. Normal signed publication is pending at this
source freeze; its final outcome requires the actual Git and fresh-fetch receipt.

## Engineering result — 2026-11-10

The exact retained login SVG is now reused by the existing shared header.
Welcome and ordinary-page wording, home/logout links and page behaviour remain
unchanged. No UI module, backend operation, dependency or service was added.

Focused renderer parity:1PASS; existing synthetic-route baseline:1PASS; exact
hostile SVG consumer:1PASS, including duplicate/altered/message-contained logo
refusals. Actual synthetic Edge checks pass for12 routes and8 desktop/narrow
light/dark layouts. Matching OpenBSD renderer:1PASS; Web candidate build PASS.
Web-only installation loads SHA256
`f6768bb2caa050eb46e05536b47e67008bc62d2de0a265bc5c88cac96516c7a3`.
Loaded-executable/readiness checks pass, including read-only epoch1PASS and
anonymous live HTTPS login using the exact shared logo. Configuration, owner
messages/epoch, helper/account/GPG and public-mail PIDs are preserved at install.
All528 compiler inputs still match the frozen native candidate.

Preflight found the account service already stopped; its earlier stop cause is
UNKNOWN. One independently reviewed bounded start restored that existing OSMAP
service without configuration/account/public-mail changes. No login password or
TOTP was submitted. Private logs remain on the host; only fixed outcomes and
stream accounting are retained here.

Independent source, hostile-consumer, browser/native/installation/readiness and
scope review gives GO for this logo-only delivery. Ordinary signed commit/push
hooks and fresh origin equality remain pending at this source freeze. Their
actual result will establish publication through Git history and the retained
delivery receipt; owner visual acceptance remains PENDING.

### Preserved failed or unqualified observations

- Two early hostile selectors selected zero tests: NOT_QUALIFIED, not PASS.
  Independent reassessment bound the exact name from the real test inventory;
  the corrected exact invocation passes1/0.
- Native first dispatch refused script mode0644 before extraction/compilation.
  Fresh stat and absent extraction verify this cause. Its captured stream is
  empty because the preflight test had no diagnostic output. Exact newly owned
  script custody was corrected to0600; the next bounded build passes.
- First V10 run refused derived inventory drift. Unchanged generators refreshed
  current count13114 and hashes; refined high0/medium3 remains unchanged.
- Added-slice catalogue/empty requirement declarations refused. Independent
  reassessment uses actual parent S01-02/UX01-006 for traceability while retaining
  all27 original parent obligations separately PENDING. Logo evidence does not
  close or reaccept that parent. No validator or frozen plan was changed.
- Aggregate V14 remains FAIL on two preexisting reader/OpenPGP scaffold literal
  checks. Baseline source already replaced those future/UI-only claims with
  actual protected rendering. The logo's affected foundation/auth-shell/list
  checks pass; the remaining inspected compose/account-controls/no-JS/
  accessibility/final-closeout checks also pass separately. No aggregate V14 or
  production-release PASS is claimed, and unrelated gate rewrites are deferred.

Evidence: `/home/foo/Downloads/osmap-ux-s08/s08-05/`. Historical wider plan and
partial header diff are also losslessly preserved with readback hashes under
`docs/reconciliation/20261110/`. The separate source worktree is untouched.
Native candidate/source and exact old-binary rollback remain privately retained;
no uncertain resources were removed. Historical cumulative effort is UNKNOWN.

Owner check after publication: refresh login and an internal page, including a
narrow window. The shield/keyhole should match throughout and navigation should
remain usable. This invitation is not recorded owner acceptance.

Signing history: the first normal commit hook passed, then cache-only Shopkeeper
signing refused with fixed `No pinentry`; no commit was created. The owner
subsequently confirmed the normal local GPG warm-up succeeded. The next signed
commit uses that existing agent cache; no passphrase is read or retained here.

The standalone normal developer security-check completed with exit0 after the
signing-cache refusal:2351 Rust library PASS/0FAIL/90explicit ignores, strict
Clippy, formatting and all remaining normal checks. Reported local nginx and
credential/native coverage skips remain unclaimed. The mandatory commit/push
hooks remain enabled; this result does not bypass them or pass aggregate V14.
