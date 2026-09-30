# OSMAP UX execution ledger

## Initial planning record — 2026-09-15

- Epic: OSMAP-UX, proposed plan revision 1.
- Operator requested full-functional UX/backend/OpenPGP planning with every-page
  dark mode. This record does not claim execution authorization for a slice.
- Source baseline: `b97d65c0f03c695ae11dbfe029d1926027f54409`.
- Accepted plan trust anchor: **PENDING operator acceptance of signed delivery**.
- S00–S11: **NOT_STARTED**, four slices each, 48 remaining.
- Current implementation slice: none. First candidate: **S00-01**.
- D01–D06: unresolved; recommendations are not approvals.
- Live authority for this epic: none recorded. No Vultr or obsd1 mutation.
- Existing local host alias/environment edits: unrelated; preserve and exclude.
- TOTP recovery/cleanup follow-ups have retained evidence in
  `/home/foo/Downloads/osmap-totp-lifecycle/`; bringing those facts into the
  repository is scoped to S00-04, not silently claimed by this planning delivery.
- Roundcube removal: operator-reported current fact; no restoration/migration work.
- Planning evidence root: `/home/foo/Downloads/osmap-ux-s00/`.
- Next action: review signed plan; accept anchor and assign S00-01.

## Append-only execution entry template

Copy the following for each transition. Do not replace historical observations
with later outcomes. Correct errors using a new entry referencing the old one.

- Timestamp / slice / previous state / new state:
- Operator instruction and accepted plan commit:
- Dependencies and approved Dxx records:
- Work-order allowed files, behavior and exclusions:
- Live target/account/action/window authority (or NONE):
- Tests: exact commands, statuses, findings, optional skips:
- Evidence: paths, SHA-256, assessed source and runtime hashes:
- Migration/rollback and cleanup/retained state:
- Signed delivery SHA and signature result:
- Operator acceptance reference:
- Sync approval/state/local-remote equality:
- Deployment approval/state (separate from sync):
- Blocker or exact next safe action:

## Autonomous engineering mandate — 2026-09-29

- Operator instruction: complete as much of the UX epic, sprints and slices as
  possible in the day-long work window; "you own this engineering entirely";
  full authority on parrot-2TB and obsd1.blackbagsecurity.com; check-in at
  midnight October 1 (America/Toronto). This explicit implementation mandate
  supersedes the original planning-only scope and per-slice stop-and-wait
  workflow. It delegates engineering decisions and continued implementation.
- Accepted execution baseline: signed plan commit
  `74522e5f99024720a3c47a3744207ff453de5731`, Shopkeeper signature verified;
  current manifest equals the signed manifest and all three plan hashes pass.
  Plan revision 1 remains unchanged. This records authority to execute, not
  retrospective human usability acceptance or a completed release.
- Source baseline: `2a6993fe7df42a57f0cbb5fe3e33e331b400fef9`; clean checkout
  at intake. Task branch: `feat/ux-completion-20260929`; prior signed portability
  change preserved. No remote write or production qualification is inferred.
- Review checkpoints become signed, evidence-backed local deliveries followed
  by continued work under the mandate. Human-only identity/accessibility
  acceptance remains pending wherever required. No subagents are authorized.
- Host authority: local engineering on parrot-2TB and bounded implementation,
  synthetic qualification and reversible OSMAP deployment on obsd1 only.
  Each live work order must identify accounts, operations, rollback and cleanup
  before mutation. Vultr and real external recipients remain excluded.

### S00-01 work order — IN_PROGRESS

- Base and trust anchor: as above. Dependencies: verified plan and operator
  implementation mandate. No runtime or live mutation in this slice.
- Allowed files: this ledger; `docs/UX_S00_INTAKE.md`; documentation index and
  governance classification needed for that document; `src/http/ux_fixtures.rs`
  and its test-only module declaration in `src/http.rs`; test-only screenshot
  tooling under `maint/ux/`. Runtime behavior is excluded.
- Deliverable: hash and inspect the four exact source images; enumerate their
  controls, existing routes/pages/errors and source/test anchors; capture
  synthetic baseline pages using real route rendering with a test gateway.
- Fixtures: synthetic `.test` identities and mail only, no host connection;
  redact fixture session/CSRF values from retained HTML; no secrets or real mail.
- Evidence root: `/home/foo/Downloads/osmap-ux-s00/run-20260929/`.
- Validation: fixture route status/CSP assertions, local browser screenshots,
  `git diff --check`, `make security-check`, `make acceptance-check`,
  `make v10-check`, `make v14-check`; actual exit status retained. Optional
  environment skips remain explicit. No strict-release claim.
- Rollback: source-only revert of the signed slice; no state migration.
- Next: complete intake and baseline evidence, sign delivery, then continue
  S00-02 under the explicit autonomous mandate.

### S00-01 verification — 2026-09-29 — VERIFIED

- Four original reference hashes match the plan; individually inspected.
  `UX_S00_INTAKE.md` records every pictured control, routes, actual gaps and
  existing behavioral anchors. Source/Reply All are absent despite historical
  claims. No runtime behavior changed.
- Fifteen synthetic route cases passed, with 45 Edge 154.0.4258.37 screenshots
  at 360/768/1440 pixels. Retained route/capture JSON manifests contain content
  hashes. Visual inspection confirms the reader grid problem and mobile empty
  drafts overflow (534 pixels at a 360-pixel viewport), carried to S01/S02.
- `cargo test --lib ux_synthetic_route_baselines`, `cargo fmt --check`,
  `git diff --check`, `make acceptance-check` (including actual
  `make security-check`, V10/V11/V12/V13), `make v10-check` and
  `make v14-check` passed. Logs and `.exit` files are in the S00 run's `gates/`.
  Rust 1.94.1 / Cargo 1.94.1 / external test-only Playwright 1.58.0.
- The initial gate attempt failed on audit-inventory drift after five fixture
  expectations were added. Refreshed the existing generated V10 registers and
  linked claims hashes using their source scanners: 739 assumptions, zero
  high-relevance runtime entries after refinement. No scanner assertion was
  weakened. These three generated register files are within the work order's
  necessary governance-classification scope.
- Optional V15 nginx runtime check skipped because nginx is unavailable on the
  workstation. Authenticated WSTG skip-policy self-tests passed; no live
  authenticated WSTG or strict release is claimed. No live state touched.
- Signing checkpoint follows; delivery SHA is recorded in the next append-only
  entry. Continued engineering is authorized by the mandate; final human
  acceptance remains distinct. Sync/deployment: not performed.

### S00-01 delivery / S00-02 work order — 2026-09-29

- S00-01: COMMITTED and accepted for continued engineering under the delegated
  mandate, without claiming independent human acceptance. Signed delivery
  `167ab90`; Shopkeeper signature verified; worktree clean after delivery.
  `origin/main...HEAD` is checked locally; no fetch/push/deployment performed.
- Baseline route manifest SHA-256:
  `1afbc1f36fbb818fdd8d28d6495ae23d0ff000244e5c97b5133d60f716f255b8`;
  screenshot capture manifest:
  `d58923350a9346fb8f6e070fe686e360f28f9e9b58f30fc0d131bdf051a064f7`.
- S00-02: IN_PROGRESS. Base `167ab90`, unchanged signed plan anchor.
  Allowed files: `docs/UX_DECISIONS.md`, index and this ledger. Resolve D01/D02/
  D03 within the delegated engineering authority: preserve script-free CSP,
  full navigation with context, host-helper plaintext location, private-key
  custody, initial interoperability profile and concrete runtime budgets.
- Scope: decision records only; no helper/runtime/key/host mutation. Evidence:
  current source inspection and primary RFC/GPGME specifications linked in the
  decisions. No new dependency is introduced by writing an architecture record.
- Tests: documentation/governance, `git diff --check`, `make acceptance-check`,
  `make v10-check`, `make v14-check`, mandatory pre-commit `make security-check`.
  Documentation-only rollback; no state migration. Human-only recovery and
  independent usability acceptance remain outside delegated engineering claims.

### S00-02 verification — 2026-09-29 — VERIFIED

- D01/D02/D03 recorded in `UX_DECISIONS.md` using delegated engineering
  authority. Native HTML/full navigation, honest host-side decryption location,
  isolated GPGME execution, no web private-key/passphrase flow, explicit key
  bindings and bounded initial PGP/MIME profile are fixed for implementation.
  These decisions add no runtime cryptographic capability.
- `make acceptance-check` (including `make security-check`), `make v10-check`,
  `make v14-check`, `git diff --check` and unchanged-plan checksum verification
  passed. Evidence: S00 run `gates/s00-02-*`; only the previously documented
  optional workstation nginx runtime check is skipped. No strict-release claim.
- No live writes, migrations, secrets or new runtime dependencies. Signed
  delivery checkpoint follows; the next entry records its verified SHA.

### S00-02 delivery / S00-03 work order — 2026-09-29

- S00-02 signed delivery `1866f6b`, Shopkeeper signature verified; clean
  worktree. Accepted for continued engineering under delegated authority;
  no independent human/release acceptance claimed. No sync or deployment.
- S00-03: IN_PROGRESS; base `1866f6b`, unchanged plan anchor. Allowed files:
  append D04/D05/D06 and threat/migration map in `UX_DECISIONS.md`, this ledger
  and documentation index if needed. Concrete account-helper authority, finite
  ancillary actions, quotas/retention/time limits and exact host scope required.
- Scope: documentation and bounded read-only obsd1 preflight only. Strict SSH
  confirmed target identity, clean baseline checkout and healthy OSMAP services.
  Sanitized driver-only inspection confirmed Dovecot SQL passdb and running
  mysqld/Dovecot; no database credentials or query values were exported. An
  initial guessed doveconf executable path was absent; command discovery
  resolved it. No mutation occurred in either preflight.
- Tests: `git diff --check`, `make acceptance-check`, `make v10-check`,
  `make v14-check`, pre-commit `make security-check`. No state migration;
  source-only rollback. Human identity evidence remains a separate requirement.

### S00-03 verification — 2026-09-29 — VERIFIED

- D04/D05/D06 now fix the authoritative account-helper boundary, human recovery
  requirements, finite action inventory, per-account quotas/retention, scheduler
  uncertainty policy, privilege/threat map and reversible obsd1 scope.
- `make acceptance-check` (with `make security-check`), `make v10-check`,
  `make v14-check`, `git diff --check` and original plan checksums passed.
  Logs are `gates/s00-03-*` under the S00 run. Optional workstation nginx
  runtime check remains skipped; no new release or cryptographic claim.
- No account/credential/service mutation, new runtime dependency or migration.
  Signed decision delivery follows; independent human requirements stay open.

### S00-03 delivery / S00-04 work order — 2026-09-29

- S00-03 signed delivery `53d3655`, verified Shopkeeper signature and clean
  worktree. Accepted for continued delegated engineering; no human recovery,
  independent usability, release, sync or deployment acceptance is inferred.
- S00-04: IN_PROGRESS; base `53d3655`, original plan anchor unchanged. Allowed
  files: `docs/UX_S00_ACCEPTANCE.md`, `maint/ux/acceptance.json`, synthetic
  fixture module and test gateway in `src/http.rs`, intake factual corrections,
  ledger, README/current-status/limitations/index, and necessary generated V10
  audit registers. No runtime changes or live writes.
- Deliverable: 110 stable control cases across UX01–17, positive/negative
  designs and evidence fields; additional empty/error route fixtures; baseline
  visual evidence and truthful prior-TOTP reconciliation. Missing historical
  Downloads evidence stays missing, not silently reconstructed.
- Test matrix: 360/768/1440 baseline screenshots; route status/CSP and no-script
  assertions; matrix coverage/schema check; `git diff --check`, formatting,
  `make acceptance-check`, `make v10-check`, `make v14-check`, signed pre-commit
  `make security-check`. S00 evidence root remains stable. No state migration;
  source-only rollback. Next engineering sprint is S01 appearance and shell.

### S00-04 verification — 2026-09-29 — VERIFIED

- 110 unique control cases cover all 17 parents, each linked to a shared
  positive/negative design and owning slice. Every status remains
  `NOT_YET_ACCEPTED`; no baseline screenshot is a functionality acceptance.
- The real router rendered 20 synthetic states and 60 screenshots at
  360/768/1440 pixels. Additional empty-mailbox and attachment-unavailable
  images were inspected; the latter demonstrates the current missing error
  heading/navigation. These join the previously inspected baseline defects.
- Acceptance fixture route manifest SHA-256:
  `8853f3ee11decb0d7f0b09f7b1f0affc43959b86876236a5f8d701528b952fc1`.
  Screenshot capture manifest SHA-256:
  `1d11756b8b16ff08ad69e16fc8e19aa8927c640bc6156bbebc2fb07451d51add`.
- Fixture assertions, matrix schema/coverage, `make acceptance-check`,
  `make v10-check`, `make v14-check`, formatting, `git diff --check` and
  original plan checksums passed. Logs remain in S00 `gates/s00-04-*`.
  Generated V10 registers reflect test-only source changes without relaxing
  a gate. Optional local nginx check remains skipped; no release claim.
- Historical TOTP raw artifacts remain unavailable as documented. Intake
  creates no runtime capability, host mutation, migration or human attestation.
  Signed delivery follows, then S01 begins under the existing mandate.

### S00-04 delivery / S01-01 work order — 2026-09-29

- S00-04 signed delivery `85e1701`, verified Shopkeeper signature, clean
  worktree; all four intake slices are complete for delegated engineering.
  No GitHub synchronization, deployment, human or strict-release acceptance.
- S01-01: IN_PROGRESS; base `85e1701`, frozen plan anchor unchanged. Allowed
  files: new appearance module and form route, lib/HTTP modules and gateway,
  shared UI/CSS, focused tests/fixtures/capture harness, ledger/current status/
  limitations/index and generated V10 registers. No runtime dependencies.
- Deliver light/dark/system tokens, strict account sidecar, authenticated
  same-origin CSRF write and typed presentation cookie. Login restores account
  choice; cookie retains colours through HTML redirects/errors/logout. Invalid
  cookie defaults to system; malformed record displays safe fallback with an
  audit event. No security setting format, grant, crypto or authority change.
- Budgets: 64-byte sidecar, 512-byte two-field write form, existing session
  validation and request limits. Atomic private-file replacement; concurrent
  account/security writes isolated by file. Old binaries ignore the new
  sidecar and cookie; source rollback needs no destructive state migration.
- Verify persistence/restart, account isolation, malformed/symlink/duplicate
  and concurrent records, session/CSRF/origin/form failures, login precedence,
  HTML versus download handling, actual route screenshots in both OS schemes;
  common acceptance/V10/V14 gates and signed pre-commit security gate.
  Retained evidence: `/home/foo/Downloads/osmap-ux-s01/run-20260929/`.

### S01-01 work-order refinement — 2026-09-29

- Include `maint/wstg-testing-pack/osmap-browser-attack-surface.json` in the
  allowed evidence files for the new form route. The first acceptance run
  correctly rejected its omission (`missing_from_inventory`); preserve this
  enforcement and register the route/query fields before rerunning. New route
  auth/origin/CSRF cases are exercised by focused tests; inventory registration
  is not live WSTG qualification.

### S01-01 verification — 2026-09-29 — VERIFIED

- Implemented native Light/Dark/System settings, account-isolated 64-byte
  versioned sidecars, atomic private-file saves, login/account precedence and
  host-only HttpOnly/SameSite presentation cookies. No JavaScript, runtime
  dependency, security-setting rewrite or cryptographic capability added.
- Ten focused appearance tests pass; the full library result is 556 passed,
  four existing ignored tests. Coverage includes bounded form/session/origin/
  CSRF rejection, duplicate/malformed records/cookies, account isolation and
  restart, 16 concurrent writers, symlink refusal, store failure, navigation/
  logout/login precedence and unchanged plain/download payloads.
- Captured 120 synthetic screenshots: all 20 route states at 1440 pixels in
  all three preferences and both OS schemes. Computed theme/background values
  match in every case, with zero scripts, external requests or overflow.
  Visually inspected dark settings and system-dark login. Full every-page
  responsive, keyboard and contrast inspection remains S01-04.
- Corrected the inventory omission reported by the first acceptance run.
  `make acceptance-check` rerun, V10/V14, clippy with warnings denied,
  formatting, diff whitespace and original plan hashes pass. Evidence is
  S01 `gates/s01-01-*` and `themes/{light,dark,system}/screenshots/capture.json`.
  No native-host or strict-release qualification is inferred.
- Rollback: previous signed source ignores sidecars and cookies; old security
  settings remain unchanged. Signed delivery follows before S01-02 shell work.

### S01-01 delivery / S01-02 work order — 2026-09-29

- S01-01 signed delivery `46c9d6b`, verified Shopkeeper signature and clean
  worktree. Accepted for continued engineering under delegated authority;
  no synchronization, deployment or independent human acceptance.
- S01-02: IN_PROGRESS; base `46c9d6b`, unchanged frozen plan. Allowed files:
  shared UI/CSS, mailbox navigation route/dispatcher/imports, focused shell
  tests/fixtures/browser capture, ledger/current status and generated V10/WSTG
  route inventory. No runtime dependencies, new persistence or host writes.
- Deliver local named SVG rail, current-page state, native details collapse
  and account menu, CSRF logout, Inbox/Sent/Drafts/Archive/Bin navigation and
  Settings/Sessions. Archive resolves only the authenticated saved existing
  mailbox. Missing configuration/folder/backend has an explicit actionable
  state. Documents/notifications remain their later owning slices.
- Move shared navigation before the main landmark so Skip to content actually
  bypasses it. Native collapse is per-page; mobile expansion overlays the rail
  without shrinking content into an unusable column. Preserve full accessible
  identity while wrapping/truncating visually long names.
- Test exact navigation and archive/session/input boundaries, escaped long
  identity, keyboard skip/disclosures/menu, widths 360/768/1440 in representative
  themes, no external fetch/script, common acceptance/V10/V14 and mandatory
  pre-commit security checks. Source-only rollback; retain S01 evidence root.

### S01-02 gate refinement — 2026-09-29

- Include `tests/v4_hostile_assurance.rs` in allowed files. Its old whole-page
  auto-fetch counter counts every SVG, including the newly required static
  application icons. Retain the absolute prohibition inside message content;
  allow only strictly validated path/circle/rect geometry in the trusted shell
  before the main landmark. Add negative checks for active/linked/foreign SVG
  content. No renderer allowlist or CSP change is authorized by this refinement.
- Browser interaction checks found the mobile account popover extending beyond
  the left edge, and narrow settings metadata becoming a one-character column.
  Anchor the menu to the header and stack metadata at small widths. Re-run
  keyboard/menu and responsive evidence before delivery.

### S01-02 verification — 2026-09-29 — VERIFIED

- Added the native collapsible icon rail, selected state, real mailbox/compose/
  draft/settings/session links, account disclosure with full identity and
  CSRF-bound logout. Skip navigation now precedes and bypasses the header.
  Archive navigation checks the saved account setting and actual folder list;
  unset, missing and unavailable states have distinct messages and navigation.
- Full library: 559 passed, four existing ignored. Focused shell tests cover
  routes/selected state, auth and strict shortcut query, stale/unset/backend
  archive cases and escaped long identity. V4 hostile-content corpus plus the
  new strict local-vector negative test pass; SVG remains forbidden in mail.
- Browser evidence: 25 synthetic route states; first 150-capture matrix exposed
  the known reader/draft overflow, plus the new mobile menu issue. Corrected
  menu anchoring and narrow metadata. Twelve final keyboard interaction cases
  (normal/long identity, three widths, both OS themes) pass skip/focus/native
  collapse and account-menu containment with zero settings overflow. Inspected
  small dark account menu and expanded desktop rail images. Final captures are
  S01 `shell-rerun/interaction` and `shell-rerun/screenshots`.
- The reader and draft table retain their baseline narrow-screen overflow;
  these are explicitly carried into the shared component/responsive slices,
  not represented as full every-page acceptance. Documents and notifications
  remain their named later slices.
- `make acceptance-check` rerun, V10/V14, strict clippy, formatting, diff and
  frozen-plan hashes pass. First failed gate and browser logs are retained.
  No renderer/CSP weakening, state migration, native-host/release claim or
  deployment. Signed checkpoint follows before S01-03.

### S01-02 delivery / S01-03 work order — 2026-09-29

- S01-02 signed delivery `8161dd8`, Shopkeeper signature verified, clean
  worktree. Continue delegated engineering; no synchronization/deployment.
- S01-03: IN_PROGRESS; base `8161dd8`. Allowed: shared UI/CSS/HTML response
  helper, HTTP route copy/imports/test modules, fixture/browser harness,
  V14 exact-copy gates where misleading labels change, generated V10 registers,
  ledger/current status/limitations and control acceptance evidence.
- Deliver compact native protection/unavailable-state disclosures, useful
  error headings and return navigation, user-facing copy, shared settings
  cards/forms, truthful principles strip and no search on Settings. Preserve
  unavailable OpenPGP controls without submitted fields or cryptographic claims.
- Correct legacy false source availability and ambiguous decryption-location
  labels; update those exact-string gates while retaining CSP, sanitization,
  field/route prohibitions and negative controls. Historical V14 documents
  remain historical. Remove development-slice commentary from normal flows.
- Reflow reader state panels outside the three-pane grid and contain the
  drafts table. Full coordinated selection/list behavior remains S02. Verify
  no duplicate main/title, escaped content, truthful capability/crypto labels,
  small-screen reader/draft containment and native disclosure interaction.
- Existing S01 evidence root; no new dependencies, persistence, backend
  capabilities or host changes. Source rollback only. Run common gates,
  focused browser checks and mandatory signed pre-commit security gate.

### S01-03 test-location refinement — 2026-09-29

- The V12 integration inventory treats every `.rs` below `src/http/` as a
  browser handler and rejects even the word OpenPGP. New UI assertion tests
  were therefore misclassified as helper integration. Collocate these tests
  with the top-level HTTP/UI modules as `src/http_component_tests.rs`, included
  only from the existing `#[cfg(test)]` module. They only assert rendered labels
  and error landmarks; no helper call or runtime module was added. The V12
  gate and its runtime prohibitions remain unchanged.

### S01-03 verification — 2026-09-30 UTC

- Shared fragment errors now have one main landmark, escaped title, heading
  and return action. Settings cards, compact unavailable-feature disclosures
  and truthful protection labels replace developer commentary. Native account
  and protection menus are mutually exclusive. Reader metadata panels sit
  above the three-column content grid; draft tables scroll inside their region.
- Library tests: 561 passed, four existing ignored, no failures. V4 hostile
  assurance: two passed. Strict clippy, formatting, V10, V14, diff and frozen
  plan hashes pass. Full `make acceptance-check` rerun passes after the
  documented test-location correction; the initial failure log is retained.
- Browser evidence: 48 selected-route screenshots across light/dark OS schemes
  and 360/768/1440 widths, plus 12 keyboard menu cases, all pass with no page
  overflow. Inspected desktop settings/reader and narrow settings/reader.
  A final mobile header adjustment was checked in four normal/long-identity
  settings captures and four keyboard cases, again without overflow.
- Evidence: S01 `components/screenshots-rerun`, `components/final-mobile` and
  `gates/s01-03-*`. Full route/theme audit, independent human accessibility
  acceptance and native-host qualification remain pending. No deployment.
- S01-03: IMPLEMENTED_VERIFIED_LOCAL; mandatory signed pre-commit checkpoint
  follows. Continue S01-04 under delegated engineering authority.

### S01-03 delivery / S01-04 work order — 2026-09-30 UTC

- S01-03 signed checkpoint `99cf86b`; Shopkeeper signature verified, clean
  worktree, locally eight commits ahead of the recorded origin/main. No sync.
- S01-04: IN_PROGRESS; base `99cf86b`. Allowed: shared CSS/HTML templates,
  appearance tests, test-only HTTP gateway/loopback server, fixture and browser
  audit harnesses, generated V10 registers and current UX evidence/status files.
- Audit all 25 synthetic HTML states at 360/768/1440 CSS pixels, all three
  saved preferences and both OS schemes. Add 200% reflow simulation (half CSS
  viewport with doubled device scale, explicitly distinct from native browser
  zoom), forced-colours and Firefox checks. Fix demonstrated layout/contrast
  defects without script/runtime dependencies or changes to message authority.
- Add a bounded opt-in loopback fixture server (180 seconds, 200 connections,
  two fixed synthetic accounts, real appearance store, no runtime gateway) for
  native form/redirect/cookie, logout/login, account isolation and process
  restart checks. No browser storage or filled login forms retained.
- Prove concurrent appearance and legacy settings writes preserve independent
  records. Add computed text/meaningful UI contrast checks and inspect captures;
  distinguish automation from independent assistive-technology acceptance.
- Evidence remains in the S01 root. No live mail, host/service changes or
  deployment in this slice. Source-only rollback. Run focused tests, common
  acceptance/security gates and signed checkpoint; native OpenBSD qualification
  gets a separately recorded isolated-host work order after signed source.

### S01-04 verification — 2026-09-30 UTC

- Library suite: 562 passed, zero failed, five ignored. Four ignored tests
  pre-existed; the fifth is the new explicitly launched loopback fixture server.
  Its real router/form/cookie and AppearanceStore workflow passes six journeys:
  navigation/reload, logout presentation, account preference precedence on
  login, changing OS preference, account isolation and process restart.
  Authentication is a fixed test gateway, not live password/TOTP evidence.
- Concurrent legacy settings/appearance writes pass 32 synchronized rounds;
  legacy bytes remain unchanged on appearance-only saves and both final records
  reload independently. No old settings-format migration is required.
- Final application-source matrix: 450 standard captures and 450 at simulated
  200% reflow, covering 25 current HTML states, three preferences, two OS schemes
  and 360/768/1440 physical widths. Standard widths are CSS pixels; the reflow
  simulation halves the CSS width and doubles device scale. It is not native
  browser zoom. No page overflow, script, landmark, preference, colour or
  measured flat-text/meaningful UI contrast failures remain.
- Added 54 verified forced-colour captures, 54 Firefox captures and 24 expanded
  disclosure captures. Across the retained passing reports: 1,032 route-state
  captures and 108 native keyboard cases, with 1,248 image hashes verified
  including menu/expanded-navigation captures. Edge 154.0.4258.37 and Firefox
  155.0; external Playwright 1.58.0 remains test-only.
- Fixed demonstrated 180-CSS-pixel layout faults: collapsed navigation moves
  above the page, the identity menu retains usable width, reader attachment
  tracks no longer force the page wider, and labels wrap. Scrollable mailbox,
  search and session tables now have named keyboard-focusable regions and
  visible focus. Arrow-key horizontal scrolling is verified.
- Inspected contact sheets for all 25 light/dark desktop states plus individual
  narrow settings/reader, forced-colour settings and Firefox reader captures.
  This is engineering visual review, not independent human accessibility or
  exact final-picture acceptance. The protected indicator remains a text badge;
  icon fidelity remains explicit in the acceptance matrix.
- Retained diagnostic failures: initial very-narrow overflow (14 then two),
  an expanding-details locator that changed its own index, and Edge retaining
  the forced-colour media query while losing its actual palette after later
  navigation. The harness now reapplies that emulation and asserts actual
  black/white system palette, media queries and focus; verified forced-colour
  screenshots were inspected. Earlier forced-colour reports are superseded.
- `make acceptance-check`, strict clippy, formatting, V10, V14, diff and frozen
  plan hashes pass. Public-send wrapper regression output is from configured
  fake curl/MariaDB/doveadm executables; no live account or message was changed.
- Evidence index: S01 `audit/summary-final.json`, SHA-256
  `1f11907dcc3f2b4da6c5dd953caf4626e04bcb8c8ec6e98a644765026d273db6`.
  Per-report hashes, source hashes, image hashes and explicit limitations are
  retained. The legacy `view=source` fixture still records a reader response;
  actual original-source functionality belongs to S02-04.
- S01-04: IMPLEMENTED_VERIFIED_LOCAL. Independent human acceptance, native
  qualification and deployment remain separate. Mandatory signed checkpoint
  follows before isolated native qualification and continued S02 engineering.

### S01 native qualification work order — approved delegated scope

- After the S01-04 signed checkpoint, archive that exact committed tree and
  record its full SHA and archive SHA-256. Verify target hostname through the
  existing strict-host-key SSH connection to foo@192.168.1.44:
  `obsd1.blackbagsecurity.com`. Production Vultr is excluded.
- Create only a new owner-private `~/osmap-ux-s01-20260930-*` qualification
  directory. Upload/extract the checked source archive there, preserving
  `~/OSMAP`, live configurations, accounts, factors, services and mail stores.
  Account: nonprivileged `foo`; no real mailbox credential or host-private key.
- Run locked/offline native library and hostile-rendering tests with a target
  directory inside that qualification root, two build jobs and reduced process
  priority. The existing native Cargo registry may be read, not replaced.
  Confirm host/tool versions, matching archive bytes and service health before
  and after. No install, service restart, firewall change or deployment.
- Retain sanitized logs and hashes beneath the S01 evidence root. Leave the
  explicitly named source/build directory for subsequent epic qualification;
  it contains no credentials or real mail. Cleanup is limited to owned scratch
  when safe; no shared caches or unrelated checkout are deleted. If native
  failures occur, diagnose/fix locally and sign the correction before retry.

### S01 delivery and native result / S02-01 work order — 2026-09-30 UTC

- Signed source `eb0277d75ce8af24f60d6d46cfa149b7363df10a`; Shopkeeper
  signature verified, clean checkpoint, nine commits ahead of recorded
  origin/main and zero behind. No GitHub synchronization or deployment.
- Native locked/offline qualification PASS on verified obsd1/OpenBSD 7.9:
  library 562 passed/five explicitly ignored, hostile-rendering corpus two
  passed. Source archive SHA-256
  `4e62e302d10fd987e8200e942847d2bf6480e0c7def5f44563ddbc5332c9497f`.
  Qualification directory `/home/foo/osmap-ux-s01-20260930-9xFTBZoA` retained
  with source and its own target cache. Standard `~/OSMAP` remains clean at
  `2a6993fe7df42a57f0cbb5fe3e33e331b400fef9`; both OSMAP services healthy
  before/after. No live mail, account or service mutation. S01 `native/result.json`
  and `qualification.log` record evidence; log SHA-256
  `7cfd011eaac84c99314fb5c847cc3c070ff0bf454bab5fb1d50a9094854d4883`.
- S02-01: IN_PROGRESS; base `eb0277d`. Allowed: mailbox models/parsers/backends
  and helper protocol/client/dispatch; HTTP gateway/routes/UI/shared CSS;
  rendering metadata; bounded list-state/metadata modules; test fixtures and
  browser harness; route inventory, generated assumption registers and current
  UX status/evidence. Existing auth/CSRF/CSP/helper privilege gates stay intact.
- First implementation checkpoint: typed unread/star filters, explicit stable
  sorting, 50-row pagination within existing fetch limits, selected-row state,
  preserved bounded list/search parameters and compact truthful row indicators.
  Filter/sort/page controls must have actual server effects, including empty
  and invalid states. Existing 2,000-message/250-search-result caps stay explicit.
- Remaining required S02-01 work: trustworthy mailbox/message version metadata,
  bounded attachment metadata, real read/unread/star updates, signed helper
  grants binding every mutation field, stale/duplicate/concurrent refusal and
  native disposable qualification. Checkpoints do not count as slice acceptance.
- Dovecot 2.3.21.1 installed on obsd1. Its official tagged source
  `src/lib-storage/mail-search-register-human.c` registers both GUID and
  MAILBOX-GUID search keys (the local man page omits GUID). Use exact mailbox
  and message identity plus UID for mutations, not a read-then-write UID-only
  check. Source reference:
  https://github.com/dovecot/core/blob/2.3.21.1/src/lib-storage/mail-search-register-human.c
  Native behavior must still be qualified with disposable content before use.
- S02 retained evidence root: `/home/foo/Downloads/osmap-ux-s02/run-20260930/`.
  No host mutation for the initial source checkpoint. A separate exact
  disposable-native fixture work order precedes any new host action. No real
  recipient, account password/factor, cryptography, package/service/firewall
  change or deployment. Source rollback; no persistent list preference migration.
- Verify focused positive/negative state tests, route/browser fixtures, common
  gates, hostile-content containment and signed reviewable checkpoints. Continue
  through required S02-01 backend/native work before claiming its completion.

### S02-01 checkpoint A — list navigation and presentation

- Real All/Unread/Starred filtering, explicit default received-descending
  ordering, deterministic mailbox/UID ties, 50-row pages and bounded query
  state. Sort/filter/search/page links preserve appropriate context; new
  filters/searches reset the page. Selection requires mailbox plus UID.
  Out-of-range current pages adjust visibly; invalid page/filter/partial
  selections fail with 400. Actual IMAP flags drive read/star indicators.
- Existing backend bounds remain 2,000 messages/250 search results. Pagination
  windows already bounded successful responses; a real backend exceeding its
  configured cap still refuses. This is not full mailbox server-side pagination.
  Legacy wide tables and independent bulk controls remain pending S02-02/03.
- Library: 568 passed, zero failed, five explicitly ignored. Strict clippy
  passed. Five real-router synthetic Edge journeys verify non-overlapping
  pages, history, filters, sort/reload, selected identity and search context.
  No real account/mail authentication or mutation backend is involved.
- 92 captures: 60 normal, 20 simulated 200% reflow, 12 actual forced-colour
  palette. No detected document overflow, computed text/UI contrast failure
  or script content. All 92 image hashes verified. Desktop selected, narrow
  search and forced-colour selected states inspected visually. Human screen
  reader acceptance and reference layout fidelity remain separate.
- Evidence: S02 `checkpoint-a-summary.json`, SHA-256
  `93991cc7d5ca7826da94bf2bfe0d455aeabc0070aa282a9e3abc5ef3a0b66642`.
  Initial library failures were four obsolete default-order/page-size test
  expectations; first browser failure was the harness using `date` instead
  of the documented `received` key. Corrected reruns are retained separately.
- Common acceptance, V14, formatting, diff and frozen-plan checks pass.
  Mandatory signed checkpoint follows. S02-01 remains IN_PROGRESS for trusted
  metadata, actual flag writes, stale identity and native qualification.
