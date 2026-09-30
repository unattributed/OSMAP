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

### S02-01 checkpoint B / disposable native-format qualification work order

- Checkpoint A signed as `c1a9f9e`; Shopkeeper signature and clean tree verified.
  Ten commits ahead of recorded origin/main, zero behind; no synchronization.
- Continue trusted metadata and flag work. Dovecot's unquoted flow formatter
  mixes message-supplied text with structural fields; it must not become an
  authority source for a new mutation. Use bounded strict JSON decoding for
  native fetch responses before accepting mailbox/message GUIDs. Duplicate
  fields, inconsistent IDs, malformed metadata and unknown states fail closed.
  Keep raw fetch content out of diagnostics. Native GUID+mailbox-GUID+UID
  predicates bind the mutation itself. Only Seen and Flagged desired states
  are in scope; preserve other flags and refuse stale identities.
- Before implementation depends on the native format, create one new
  owner-private `~/osmap-ux-s02-native-*` directory on verified obsd1. Run only
  nonprivileged `foo` commands with an explicit standalone `-c` configuration,
  owned mail_home/mail_location/base_dir/state_dir and no includes, plugins,
  network listeners, SQL userdb/passdb or existing Dovecot sockets. Do not use
  `-u`, `-A`, `-F`, a live account, root, system configuration or daemon startup.
- Inside that directory, create a disposable Maildir and synthetic RFC 5322
  messages, then use native doveadm fetch/save/flags/search only against that
  Maildir. Verify JSON values/escaping, GUID identity, BODYSTRUCTURE, add/remove
  Seen/Flagged, exact wrong-GUID refusal/no other-message changes, duplicate
  desired-state behavior and bounded output. No external delivery. Retain
  synthetic fixtures, commands, sanitized results and hashes under the S02
  evidence root. If standalone isolation cannot be proven, stop that approach
  and select another isolated method before running mail operations.
- Inspect explicit configuration and runtime paths before the first write.
  Check standard checkout and OSMAP service health before/after. Only the new
  owned fixture directory may be removed after results are retained. This
  research qualifies the native command substrate, not the later Rust/helper
  implementation or production deployment; those require separate exact-SHA
  native regression checks after signed source delivery.
- Implementation also includes atomic quota reservation in the existing
  throttle service, a narrow flag route/gateway, bounded internal return URLs,
  helper/client dispatch and dedicated synthetic tests. A shared native flag
  gate refuses overlapping operations; one three-second deadline covers read,
  write and confirmation. Existing mail-action quotas are reserved atomically
  before external writes and store errors refuse the action. An unconfirmed
  result is explicit and never triggers an automatic retry.
- Native substrate PASS in `/home/foo/osmap-ux-s02-native-fVcDLRfM` with two
  synthetic messages and restored initial flags. Structured fetch values are
  strings; GUID is a Maildir filename; BODYSTRUCTURE omits outer parentheses.
  Wrong message GUID matched no message; missing mailbox GUID returned 255
  without a change. Native body fetch normalizes line endings to LF. Host UTC
  agrees with workstation; its display timezone is +07, not clock skew.
  Services and standard checkout unchanged. `native-substrate/result.json`
  SHA-256 `35a3e87b7c5eb16aab65455f98da24fdefcb6f1d5df869d34db076d91426ce67`.
  Standalone config required a nonempty loopback `listen` value; no daemon was
  started. Initial configuration and nonexistent-GUID expectation failures are
  retained, with the actual safe refusal recorded. Rust/helper proof remains
  required separately; these command checks are not full feature acceptance.

### S02-01 checkpoint B — trusted state controls

- Strict bounded JSON replaces ambiguous flow output for native list/search/
  reader fetches. Mailbox GUID, opaque message GUID and UID are checked against
  the requested account/mailbox/message. Attachment counts come from bounded
  BODYSTRUCTURE; unsupported or malformed metadata remains unknown, not zero.
- Read/unread and star/unstar use explicit desired states through POST-only
  forms with CSRF and same-origin checks. The helper grant binds account,
  mailbox, UID, both GUIDs, flag and desired value. Only Seen and Flagged are
  accepted; native add/remove preserves other flags. Duplicate requests return
  already-set; stale identities and concurrent operations refuse. Post-write
  uncertainty is explicit, with no automatic retry. Redirect context is rebuilt
  from a bounded internal GET allowlist. Helper replies reject duplicate control
  fields, cross-operation fields and mismatched confirmations.
- Existing shared mail-action quotas are reserved atomically before writes.
  Locked quotas, unavailable stores and missing configured helper authority
  refuse without a direct fallback. One native three-second deadline covers
  read, write and confirmation; helper transport deadlines are checked.
- Library 587 passed, zero failed, six explicitly ignored (including the new
  opt-in native fixture). Strict all-target clippy passes. Six browser state
  journeys and five navigation journeys pass against the real router and
  synthetic gateway. These cover duplicates, stale identity, account separation,
  CSRF, origin, list/filter context and keyboard star activation.
- 32 current captures: 12 normal, four simulated 200% reflow, eight forced
  colours and eight Firefox. No detected overflow or computed contrast failure;
  all image hashes checked. Desktop light and narrow dark reader inspected.
  The first normal set is superseded because its selected fixture fell outside
  the visible page; corrected fixture uses visible UID 125. Legacy tables and
  metadata-heavy reader remain pending, so S02-01 is still IN_PROGRESS.
- Evidence: S02 `checkpoint-b-summary.json`, SHA-256
  `1e1109b48e89ef6a5e066d0dd26683af75e1e5612dcc1519f0f23dd0e0752ae5`.
  Full common acceptance, V14, formatting, diff and frozen-plan checks PASS.
  Initial test/build/clippy and stale generated-register failures
  are retained alongside corrected reruns. No production claim or deployment.

### Exact checkpoint B native work order

- After a signed clean B checkpoint, archive its exact full SHA, hash the archive
  and transfer only to a new owner-private `~/osmap-ux-s02-*` source directory on
  hostname-verified obsd1. Preserve standard `~/OSMAP`, accounts and services.
  Use the prior owned S01 target cache solely to reduce compilation time; two
  jobs, reduced process priority, locked/offline dependencies.
- Run all native library tests, V4 hostile rendering and the explicit ignored
  `isolated_openbsd_json_and_signed_flag_helper` test. That test creates only a
  new 0700 `/tmp/osmap-ux-native-*` root with 0600 standalone configuration and
  public synthetic grant material, owned runtime/state/home/Maildir paths, no
  includes/plugins/daemon/real credentials, and no live SQL/userdb socket.
- The test-only executor prepends that standalone configuration and removes
  `-u` only for the fixed synthetic account, using the current unprivileged OS
  user. Production fetch/flag argv and GUID predicates otherwise remain intact.
  Exercise structured list/view, attachment counts, signed local helper writes,
  duplicates, incorrect GUIDs/UID, other-message isolation and restored flags.
  Remove only the test-owned fixture tree; retain exact-source logs and hashes
  under S02. Verify standard checkout and OSMAP service health before/after.

### S02-01 checkpoint C work order — compact message rows

- Following signed checkpoint B, finish S02-01 presentation in `src/http_ui.rs`,
  shared CSS, mail-list helpers, route/fixture tests and browser harnesses. Keep
  actual backend identity, filtering, pagination and state writes from A/B.
- Replace the wide diagnostic table presentation with compact sender/subject/
  date/state rows aligned with the supplied inbox reference. Use actual metadata,
  explicit unknown values, accessible names and visible selected/unread states.
  Avoid invented body previews, avatar identities or cryptographic assurance.
  Preserve all existing authorized actions; bulk workflow consolidation remains
  S02-03. Local no-script native forms and keyboard interaction remain D01.
- Verify empty, single and many rows, long/hostile values, selected identity,
  filter/sort/page behaviour, narrow layouts, contrast, forced colours and
  native state controls. Exact B native qualification may run independently in
  its owned source tree. C remains source-only until its own signed checkpoint;
  S02-02 coordinated reader work follows S02-01 verification.

### S02-01 checkpoint C — compact rows and native fixture correction

- B signed as `8d3211a33d062b88364acb7ea9eaa11f848ed565`, Shopkeeper verified,
  clean checkpoint, eleven ahead/zero behind recorded origin/main. No sync.
  Archive SHA-256 `210f6e305f81f543f63ead329663908871986d6f86dc62bad2bc970155fb9e3a`;
  native source `/home/foo/osmap-ux-s02-20260930-t9Ay09V1`. Native library 587
  passed/six ignored; V4 hostile rendering two passed. Standard checkout and
  OSMAP services unchanged. The dedicated native mail fixture failed before
  its first save; this is not a native helper feature PASS.
- Diagnosis: the production executor intentionally clears inherited environment;
  standalone no-userdb doveadm requires USER. Read-only reproduction returned
  status 64. Supplying only the fixture OS username then exposed inherited
  directory GID 0, whereas the actual process UID/GID is 1000/1000. Test adapter
  now obtains current OS identity through fixed `id` options, sets only USER
  through fixed `/usr/bin/env`, and uses process GID in its standalone config.
  Production executor restrictions remain intact. Failed owner-private scratch
  removed after its configuration/diagnosis were retained under `native-b`.
- Mailbox/search tables are now semantic compact lists with actual sender,
  subject, received timestamp, unread/selected state, read/star controls and
  attachment metadata. Headers are escaped; long sender/subject previews are
  bounded visually with full text in More. No body preview or avatar identity
  is invented. Unavailable legacy metadata remains explicit. Sort, search
  options and secondary actions use keyboard-operable native disclosures.
- Existing bulk form associations are preserved and tested; consolidation and
  strengthened move semantics remain S02-03. Six navigation and six state-control
  browser journeys pass, including keyboard disclosure, distinct selection
  forms, sort/filter/page state, CSRF/stale/account isolation and unknown outcome.
- Library 588 passed/zero failed/six ignored; strict all-target clippy passes.
  Current visual evidence: 74 full-page captures (30 system, eight saved-theme,
  12 simulated 200% reflow, eight expanded, eight forced-colour, eight Firefox)
  plus 12 viewport review captures. No detected overflow or computed contrast
  failure; all image hashes checked. Selected desktop and long-header narrow
  states visually inspected. Earlier C captures are superseded by the verified
  set after reducing repeated status text and bounding header previews.
- Evidence: `checkpoint-c-summary.json`, SHA-256
  `1071f6b891ad9cdf3f40f17bf111bcb2b35e6b28ccb6d7fe6e06f7ecb738f54d`.
  Full common acceptance, V14, formatting, diff and frozen-plan checks PASS.
  Corrected native fixture qualification must use the next signed exact source.
  S02-01 remains pending that result and the remaining per-control inventory.
  Retry the recorded native work order with a new private source directory,
  unchanged standard checkout/services and the same owned target cache.

### S02-01 checkpoint D work order — finish the control inventory

- Reconcile all thirteen S02-01 acceptance rows before claiming the slice.
  The remaining items are actual bounded body previews, safe sender initials,
  a bounded select-all/none menu, and a finite global search/shortcut menu.
  No invented preview, cryptographic state, sender trust or arbitrary command
  interpreter. Initials derive from the displayed untrusted sender header;
  they are decorative text and never a verified avatar or profile photo.
- Allowed: native fetch/JSON and helper read metadata, message metadata bounds,
  list view state, shared shell/UI/CSS, mail routes, fixtures/browser/native
  tests, route inventory if needed, generated evidence and current UX records.
  Native Dovecot's tagged fetch implementation supports `body.preview` and
  `body.snippet`; qualify preview behaviour only on the retained synthetic
  standalone Maildir before using it. Keep preview content out of diagnostics.
- Preview text is bounded, escaped and hidden for encrypted-body indicators;
  no body fetch per row, external resources or new crypto authority. Preserve
  the existing native/helper byte, row and time limits; no full-mailbox scale
  claim beyond those limits. Add native preview proof to the exact signed test.
- Selection is presentation state over the current bounded page. Native GET
  selection controls do not authorize a mutation; existing POST action and
  ownership checks still apply. Move/archive consolidation and stale-safe
  mutation semantics remain S02-03. A search menu exposes only reviewed existing
  navigation destinations and the existing search route. Settings omits search.
- Verify global-header impact across authenticated pages, keyboard disclosures,
  theme/reflow/contrast, unknown/encrypted/long previews, no active content,
  current-page selection bounds and helper/native metadata interoperability.
  S02-02 coordinated reader work follows these S02-01 checks, rather than
  treating a partial control inventory as slice completion.

### Exact checkpoint C native result — 2026-09-30

- C signed as `b39542c3a7a2336380509c76df655064cb7b92a9`; Shopkeeper
  verified; clean delivery; twelve ahead/zero behind recorded origin/main.
  Archive SHA-256 `3fe72b7d93d230e0168094f51293750875d63d6402f5bafa5f59f6f31ab759aa`.
  Native owned source: `/home/foo/osmap-ux-s02-20260930-dOvDJkan`.
- Native library 588 passed/six ignored; hostile rendering two passed. The
  explicitly invoked isolated signed-helper test now passes, including actual
  Dovecot JSON identity/attachment data, Seen/Flagged add/remove, duplicates,
  stale GUID/UID refusal, neighbour-message isolation and restored flags. The
  disposable test tree was removed. Standard checkout and services unchanged.
  Qualification log SHA-256
  `10ecb31b45d51499a4de7c724653758051b46071cf111d43e3d92a561dba9e20`.

### S02-01 checkpoint D — remaining list controls verified locally

- Native `body.preview` joins the existing bounded structured fetch, with no
  per-row body fetch. A read-only probe on the retained synthetic standalone
  Maildir returned actual snippets and unchanged flags. Tagged Dovecot source
  and probe evidence are under S02 `native-preview/`. Production mailbox,
  SQL authority and daemon configuration were not used.
- Preview is optional, escaped, whitespace-normalized and bounded to 160
  Unicode scalar values/640 bytes. Invalid/over-limit BODYSTRUCTURE, encrypted
  MIME including nested messages, and PGP armour suppress it. Strict helper
  metadata rejects oversized/control-bearing previews; older read responses
  remain readable with unknown preview. No decryption or sender trust inferred.
- Decorative sender initials derive only from the displayed header. Native
  selection menus select all current-page rows when at most ten, otherwise
  explicitly the first ten, for one existing action. Clear/page changes remove
  selection; GET does not mutate mail. Existing CSRF-bound POST limits remain.
- Global Search opens a native form and seven finite navigation shortcuts,
  with browser access key S and keyboard disclosure. It shares the mutually
  exclusive toolbar menu group and is absent on Settings. No command interpreter,
  script, new resource origin or new route was added.
- Library 593 passed/zero failed/six ignored; strict all-target clippy passes.
  Nine list/navigation browser journeys and six state-control journeys pass.
  82 viewport captures cover system/saved themes, responsive layouts, simulated
  200% reflow, forced colours and Firefox; 88 additional shell captures verify
  keyboard menus and bounded panels. DOM audits cover the full page. No detected
  overflow/contrast failures; all 170 image hashes verified. Desktop list,
  narrow hostile-text state and narrow open search menu visually inspected.
- Evidence: `checkpoint-d-summary.json`, SHA-256
  `cf8b1f814fd7dac290df769e5770d1772d560bacfd7f21a2cbfed2dac6338f8a`.
  Initial compile/assertion/fixture-name failures are retained alongside passing
  corrected runs. Exact D native qualification follows a signed clean source
  checkpoint using the unchanged native work order and a new owned directory.
  S02-01 retains the existing 2,000-list/250-search backend result caps; this is
  not full backend pagination or large-mailbox performance qualification.
  Independent human/final visual and release acceptance remain pending.
- Full `make acceptance-check`, V14, formatting, diff and frozen-plan checks
  PASS for D. Existing generated V10 assumption inventories/hashes refreshed
  from the final Rust source. No validation rule or original plan was weakened.

### S02-01 delivery / S02-02 work order — 2026-09-30

- D signed as `a86e40e11b02ee4161d143c13d88dfdb87585f50`, Shopkeeper
  verified; clean checkpoint; thirteen ahead/zero behind recorded origin/main.
  Exact source archive SHA-256
  `d873547d83b090a196f9838ac8bb730246c84ee146188b5187a9b4a70bf8350f`;
  native source `/home/foo/osmap-ux-s02-20260930-VjsBr4EF`.
- Exact D native library 593 passed/six ignored; hostile rendering two passed;
  isolated signed-helper test passed, including actual native preview metadata.
  Test mailbox flags restored and disposable fixture tree removed. Standard
  checkout/services unchanged. Detailed result/log hashes are retained under
  S02 `native-d/`. S02-01 engineering is delivered within its explicit result,
  preview and action limits; final pictured icon fidelity and independent human
  acceptance remain S09. No deployment, synchronization or live-account claim.
- S02-02 IN_PROGRESS under D01. Allowed: list/navigation models, mail route
  handlers, shared UI/CSS, synthetic route/browser fixtures and tests, current
  status/acceptance/ledger and generated source evidence. Reuse the existing
  authorized message renderer and read helper; no new mutation or crypto path.
- Coordinate mailbox/search lists with a selected reading pane. Preserve
  compatible query/filter/sort/page context in bounded URLs and history.
  Resolve selection from the current authenticated filtered result set before
  paging; compare fresh stored message identity before displaying its body.
  Off-page selection may remain visible with a locate link; absent/stale or
  mismatched account/folder identity shows a clear unavailable state, not a
  previous body. Folder/account navigation starts with current account state.
- Keep one main landmark and native keyboard controls. Desktop shows list and
  reader together; narrow selected views prioritize the body and provide Back
  to list. Move technical metadata/secondary actions into disclosures, preserve
  existing forms/renderer protections and put the body before attachments.
  Existing standalone message URLs remain functional. No script/dependency.
- Proof: current-result identity binding, stale/mismatch/no-session refusal,
  released request budgets, compatible filters/sorts/pages, history/reload,
  fresh account/folder switch, mobile/keyboard order and body visibility;
  theme/reflow/forced-colour/Firefox and hostile-rendering regression. Local
  and exact native source checks precede the next signed slice delivery.

### S02-02 checkpoint E — coordinated reader verified locally

- Mailbox/search responses now combine the current bounded list and selected
  reader. Selection resolves against the filtered result set before paging and
  requires fresh account, mailbox, UID and both stored GUIDs to agree with the
  fetched message. Missing, excluded, changed or mismatched identity never
  exposes the body. Legacy rows without identity keep their standalone links.
- Sort/filter/page links and search forms preserve compatible selection. An
  off-page reader has a locate link; Back to list clears only selection while
  retaining query/scope/field/sort/filter/page. Folder navigation clears it.
  Full navigation and per-request authorization remain D01; no script or
  browser-side content cache was introduced. Selected reads acquire/release the
  existing nonblocking mailbox budget, including denial paths.
- Desktop shows list and reader together. Narrow selected views prioritize the
  reader and hide list controls from focus order. A shared safe reader fragment
  also serves existing standalone message URLs. Body precedes attachments;
  secondary moves and technical metadata use native disclosures. Long subject
  and sender headings are visually bounded with full escaped text in Message
  details. Existing renderer, body preference, downloads and forms are retained.
- Library 596 passed/zero failed/six ignored; strict all-target clippy passes.
  Six reader journeys pass in each of Edge and Firefox, covering keyboard
  focus, filtering/sorting, off-page selection, query changes, identical UIDs
  across folders, Back/reload, account switching through history and narrow
  keyboard return. Nine list and six state-control journeys also pass.
- Final visual evidence: 86 captures, including eight full-page expanded-control
  captures, across light/dark/system, saved preferences, responsive widths,
  simulated 200% reflow, forced colours and Firefox. No detected overflow or
  computed contrast failures; all image hashes checked. Final desktop, narrow
  dark search reader and narrow long-subject state visually inspected.
- Initial narrow toolbar overflow was caused by inherited column-direction
  flex styling and corrected with explicit reader action layout. The expanded
  harness now operates on visible disclosures, respecting the narrow hidden
  list. Old V8 UI-copy assertions were updated to the current explicit
  `Plain text message` and `Remote content blocked` labels; all body-selection,
  sanitization, malformed MIME and preference assertions remain intact. Initial
  failures and superseded captures are retained separately from the final set.
- Evidence: S02 `checkpoint-e-summary.json`, SHA-256
  `35fff5b20b2153688ab2621f844927301ce198570293c4954dc9aa0a3e152951`.
  Exact D native log SHA-256 is
  `9d45ead089fa7b3832e782fdc861d33faeb49cece7274ec92a991429648e9103`.
  The previous work-order wording about native checks before signing is clarified:
  local checks precede the signed checkpoint; native qualification uses that
  clean signed exact source archive and follows signing, as for C/D. E native
  qualification remains pending. Human acceptance and deployment remain separate.
- Final common acceptance, V14, formatting, diff and frozen-plan checks PASS.
  Existing V10 inventories/hashes were refreshed from the final Rust source;
  the earlier common-gate attempts are superseded by the final passing run.

### S02-02 delivery / S02-03 work order — 2026-09-30

- E signed as `da16175e84dabbeaa9b091343d05665d199a06c7`, Shopkeeper
  verified; clean checkpoint; fourteen ahead/zero behind recorded origin/main.
  Exact archive SHA-256
  `05104b36fe6da6383b799b33fe3539279a14f22df8bb91bd398654b6931e9f21`;
  native source `/home/foo/osmap-ux-s02-20260930-kSg9jZTl`. Native library,
  hostile-rendering and explicit isolated signed-helper checks pass. Standard
  checkout and services unchanged; temporary native mail fixture removed.
  Native log SHA-256
  `b15b5c00650f8a281f45db684e2764d7d314908ccc3b0088c7e0f49e706edc34`.
  Human acceptance, sync and deployment remain separate and pending.
- S02-03 IN_PROGRESS under D01/D05/D06 and the operator's day-long engineering
  mandate. Allowed: mailbox move model/backend/helper protocol and clients;
  browser gateway, move/bulk routes, list/reader forms, navigation and CSS;
  synthetic/native/browser tests, generated evidence and current progress docs.
  Strengthen existing move operations with mandatory stored mailbox/message
  identity. Old forms/helpers must refuse unsupported identities; no fallback.
- Confirm native move semantics first in a new owner-private standalone
  synthetic Maildir on obsd1. Use only its explicit temporary configuration,
  current OS identity and no `-u`/SQL/daemon; move synthetic messages between
  fixture folders and restore/remove the fixture. Never touch live account
  mail, services, firewall, packages, host configuration or standard checkout.
- Bind pre-read, native mutation query and confirmation to stored identity;
  bounded shared mutation gate/deadline; reserve mail-action quota atomically
  and fail closed. Missing/stale/duplicate identity does not issue a write.
  An unconfirmed write is explicitly unknown, with no automatic retry.
- Consolidate bounded selection (maximum ten) into native forms, with explicit
  existing destination, Archive, Bin and Restore to Inbox semantics. Bin means
  a reversible move to an existing Trash mailbox; no permanent delete command.
  Validate CSRF, account ownership, names and every selected identity before
  acting. Sequential bulk work stops on failure; show confirmed, uncertain and
  unattempted counts, and provide read-only reconciliation navigation.
- Preserve bounded mailbox/search context where possible, clear moved selection
  and recalculate rows/counts from fresh reads. Unknown metadata disables action
  controls honestly. Proof includes stale/replay/mismatch/limits/partial failure,
  signed-helper field binding and fail-closed responses, native move/restore and
  neighbour preservation, keyboard/mobile/browser/theming regressions and the
  common gates. No new dependency, script permission, cryptography or deployment.
  Native exact-source qualification follows each clean signed checkpoint.

### S02-03 checkpoint F — reversible identity-bound moves verified locally

- Replaced the old exit-code-only move backend with stored mailbox/message
  generation checks before mutation, exact account/folder/UID/GUID predicates
  on `doveadm move`, and confirmation that the source identity disappeared and
  one matching identity reached the destination. Existing destination copies,
  stale/duplicate/mismatched identity and a busy gate refuse before writing.
  One three-second native deadline covers all five operations. Flags and moves
  share a nonblocking mutation gate in both direct and helper runtimes.
- Mandatory identities are bound into the signed helper request and echoed in
  a strict bounded confirmation. Old forms/helpers refuse without fallback.
  The browser gateway now reserves the shared action quota atomically; storage
  failure refuses. Failed or uncertain writes consume their reservation and
  are never retried automatically. Native diagnostics cannot leak body output.
- One visible checkbox group supports move, configured Archive, Bin to existing
  Trash and Restore to Inbox. Maximum ten source-mailbox identities; canonical
  UID/key matching, explicit allowed fields and a 16 KiB form bound. Sequential
  bulk processing stops at the first failure or before starting another item
  after the configured deadline; an active bounded gateway operation can finish
  or return unknown. Failure UI states confirmed, uncertain and unattempted
  work and offers read-only source/destination reconciliation. No permanent
  delete operation. Metadata-unavailable rows/readers do not offer moves.
- Successful full navigation clears selection and obtains fresh rows/counts
  while preserving bounded query/filter/sort/page context. Caller-controlled
  `moved_to`/`moved_count` query values no longer assert mutation success.
  The synthetic gateway now preserves moved identities/flags and creates new
  destination UIDs; browser account isolation and stale form tests use that
  state rather than a success-only stub.
- Actual Dovecot semantics were measured first in a new standalone obsd1
  fixture: GUID preservation through Archive/Trash/Inbox, changed restored UID,
  stale original identity no-op and unchanged neighbour. Fixture removed;
  no live account, userdb, daemon or host configuration touched. Probe SHA-256
  `ae2e480246f40c3a75be5fabe52f351e1585b4b42a33143c5ad92d5bdd56cd35`.
  The ignored signed-helper native test now covers the same reversible path;
  its exact F run remains pending until signing.
- Library 607 passed/zero failed/six ignored; strict all-target/all-feature
  clippy, full common acceptance, final V14, formatting, diff and frozen-plan
  checks PASS. V10 generated inventories were refreshed from current Rust.
  Two V14 static layout checks were adapted from separate archive checkboxes
  to the shared named native selection, archive action and bound/keyboard
  checks. CSP, no-script, sanitization, body and mutation assertions remain.
  The generic Rust method name `fetch` triggered the browser execution-sink
  guard; naming it `read_summary` resolves that false positive without changing
  the guard. Initial failures are retained with the passing corrected runs.
- Five complete move browser journeys pass in each of Edge/Firefox; nine list,
  six reader and six read/star journeys pass. 94 visual captures pass across
  light/dark/system, saved preferences, responsive widths, simulated 200%
  reflow, forced colours and Firefox; eight expanded full-page captures included.
  All image hashes verified. Selected list, narrow partial-result page and
  expanded narrow dark Bin reader were visually inspected. The first move
  harness's logout/cleanup mistakes were corrected; its owned residual fixture
  process was terminated, and both passing runs cleanly removed their state.
- Evidence: S02 `checkpoint-f-summary.json`, SHA-256
  `60454a3b67ced64cc42c1499f619ec8eef1a76bd6bb882e8a0b76740825fba4c`.
  Historical live archive/move/throttle/resource validators still encode the
  previous form contract; adapt them in S10 before credential-backed live
  qualification. They were not run and are not current UX qualification.
  No persistent state migration, deployment or synchronization occurred.
  Independent human and full release acceptance remain pending.

### S02-03 delivery / S02-04 work order — 2026-09-30

- Exact signed F `f2b2665fd0a93fb24f023e98986ace9fe5bcc7b5` passed
  native OpenBSD qualification: 607 library tests, two hostile-rendering tests
  and the isolated signed-helper flags plus reversible move test. Source archive
  SHA-256 `9f9f621b828fa83a8f1c10ce112f42d02812bdab93783eba0c53af1a4ed5d7d7`;
  qualification log `2e6b4689bca70ca009561cb83a81d6a1c2a41cf2d725a846d6f189aedc3cb931`.
  Owned snapshot `/home/foo/osmap-ux-s02-20260930-UdhgLP7n`; standard checkout
  and services unchanged, disposable Maildir removed. S02-03 engineering delivered.
- S02-04 IN_PROGRESS under D01/D06. Allowed: bounded authenticated source
  retrieval/rendering, reader links, attachment identity/response checks,
  empty/error/read-only retry states, synthetic browser and native tests,
  generated gate inventories and evidence records. Reuse the existing configured
  message-view helper for raw text; never decode active source into browser HTML.
  A source page represents stored headers and MIME body text, not a claim of
  byte-exact original wire export. Preserve existing body/attachment/filename
  bounds and no-store/CSP protections. Bind new source/download links to stored
  identities where available; no extra native mutation or automatic POST retry.
  Reply-all and full compose identity/draft work remain S03. Retain evidence
  under the existing S02 owner-private root. No deployment or synchronization.

### S02-04 checkpoint G — source and bounded content verified locally

- `/message?view=source` now reads bounded stored headers/MIME body through the
  configured message-view backend and renders escaped text in the authenticated
  no-store/CSP shell. Account, session, mailbox, canonical u32 UID, body/header
  bounds and supplied stored identities are checked before exposure. Source
  navigation returns to the selected reader/filter/sort context. Unknown view
  modes and unsafe return destinations refuse before reading. Source is not
  byte-exact original wire export; existing native decoding/line-ending limits
  are explicit, and the route never substitutes decrypted content.
- Current-identity reader links bind source and attachment downloads to both
  stored GUIDs. Bound downloads decode one checked snapshot with the existing
  bounded MIME attachment service; no second read can change its identity.
  Missing configured-helper credentials remain fail closed, with no fallback.
  Attachment responses retain forced download/no-store/nosniff/same-origin
  policy and add sandbox CSP. Unversioned compatibility reads retain current-
  UID semantics and do not claim stale-identity protection. Legacy helper
  metadata absence keeps the source control unavailable. Limits remain 64 KiB
  headers, 512 KiB MIME body, 256 KiB decoded attachment and bounded filenames.
- Reader details now include bounded decoded To/Cc text, escaped at rendering.
  Standalone reader and legacy attachment responses also verify returned
  account/mailbox/UID (and attachment part). Empty mailbox/search provide useful
  navigation; reader/source/attachment failures provide contextual return and
  explicit read-only retry where appropriate. Reply/forward open compose without
  submission; reply-all and full compose work remain S03.
- 611 library tests, strict all-target/all-feature clippy, full common
  acceptance, V14, formatting/diff and frozen-plan checks PASS. Five content
  journeys pass in each of Edge and Firefox; six reader journeys pass. 108
  image hashes verify across responsive light/dark/system, saved preferences,
  simulated 200% reflow, forced colours, expanded details and Firefox. Zero
  recorded overflow/contrast/outside-request failures. Narrow dark long source,
  medium light recovery and expanded narrow dark reader were visually reviewed.
- The initial V11 run correctly rejected a runtime `expect`; the error path now
  uses an explicit `Result`, and the unchanged gate passes. Initial component
  tests were updated for actual source availability/contextual recovery while
  preserving unknown-metadata and cryptography non-claims. Native fixture
  extension covers signed-helper raw source, byte-exact decoded synthetic
  attachment and unchanged flags; exact G execution follows signing.
- Evidence: `checkpoint-g-summary.json`, SHA-256
  `d2f8e7196989fe49c28527884b6a0d4d2e04d36ceaf0caafd7587b0a5a83e5a4`.
  S02 acceptance rows are IMPLEMENTED_VERIFIED_LOCAL, not independent human
  acceptance. No live account, external recipient, deployment or synchronization.

### S02-04 delivery / S03-01 work order — 2026-09-30

- Signed G `61bfb092b0da75eb98b1b1867accf603c2d57732` passed exact native
  qualification on obsd1: 611 library tests, two hostile-rendering tests and
  the signed-helper source/attachment/flags/move fixture. Source archive
  `c63483faa682928dd9242884be9569dba238a1c1a7dc4771ea0f9e63882e660a`;
  log `6f8975d626ce16d11d4fc6306a3d117cd8ffd9ee4416075ac7e6ee640c2df083`.
  Owned source `/home/foo/osmap-ux-s02-20260930-6zRLWnWI`; fixture removed and
  standard checkout/services unchanged. S02 engineering delivered. Human,
  live-mail release and deployment acceptance remain pending.
- S03-01 IN_PROGRESS under D01/D05/D06. Allowed: compose/reader addressing,
  current canonical sender allowlist, Reply-To/reply-all/dedup/self-exclusion,
  original-header-bound threading, existing draft serialization needed to
  retain that context, account-private contacts/address selection, submission
  header construction, route/helper boundaries, bounded tests and evidence.
  Checkpoint A addresses identities/replies/threading first; contacts and full
  S03-01 acceptance follow. Never accept arbitrary From impersonation or raw
  client-supplied threading headers as original-message authority. Preserve
  legacy draft readability; new metadata is explicitly versioned and bounded.
  Do not silently convert failed/unknown submission or failed Sent storage into
  success. Dedicated concurrency/formatting/upload/send reconciliation work
  remains S03-02/03/04. No real recipients, private mail or external delivery.
- S03 evidence root: `/home/foo/Downloads/osmap-ux-s03/run-20260930`, owner
  private. Qualification uses local sinks and new isolated native fixtures;
  no standard checkout sync or production deployment. RFC 5322 sections 3.6.2
  and 3.6.4 are the addressing/threading reference; conservative unsupported
  syntax must be explicit rather than guessed.

### S03-01 checkpoint A — identities, reply addressing and threading

- The compose form shows the authenticated canonical account as its sole
  permitted From identity. Forged sender/unknown header fields are refused
  before saving or submitting. Authenticated send/save now check the session
  before multipart parsing, then enforce the existing CSRF/origin boundary.
  Reader Reply/Reply all/Forward links carry current stored identities;
  mismatched account/mailbox/UID/version refuses before quoting content.
- A shared bounded parser accepts bare addresses and display names, including
  quoted commas. Controls, malformed/ambiguous syntax and unsupported groups,
  comments, quoted local parts, domain literals or SMTPUTF8 addresses refuse.
  Sixteen entered addresses across To/Cc/Bcc remain the cap. Stable envelope
  deduplication folds domain case only, preserves local-part case and retains
  To/Cc roles. Reply-To takes precedence over From. Reply all excludes the
  canonical sender, removes duplicate To/Cc targets and never imports Bcc.
  Oversized or unsupported originals require manual recipient selection.
- New reply references bind mailbox, canonical u32 UID and both stored GUIDs.
  Save/send re-read through the configured source gateway and verify account,
  session, mailbox, UID, GUIDs and header bound before deriving thread headers.
  Client-supplied In-Reply-To/References are never accepted. Thread headers are
  generated from validated ID atoms and emitted in plain and multipart output.
  Message-ID is capped at 254 bytes, threading input at 4096 bytes and history
  at 20 references, retaining root and recent ancestry. Invalid threading is
  omitted with compose context; forward has no reply thread. Legacy metadata
  absence cannot supply the current-identity thread reference path.
- Draft metadata v4 preserves validated server-owned thread context across
  save/resume/send, even after the original is unavailable. Readers retain
  v1-v3 compatibility; duplicate, incomplete, injected and downgraded new fields
  refuse. Editing a saved draft cannot replace its original reply reference.
  Existing draft concurrency/quota and send-outcome work remains S03-02/04.
  Sendmail arguments now terminate options before envelope recipients. Public
  OpenSMTPD source supports that interface; no actual MTA delivery is claimed.
- 623 library tests (six opt-in tests ignored), strict all-target/all-feature
  Clippy, common acceptance, V14, formatting/diff and frozen-plan checks PASS.
  Five synthetic reply journeys pass in each of Edge and Firefox, including
  save/resume/Bcc privacy, quoted display-name submission to a local sink and
  cross-account reader-link refusal. 54 image hashes verify across light/dark,
  responsive, forced colours, simulated 200% reflow and Firefox; zero recorded
  overflow/contrast/outside-request failures. Narrow dark reply-all and wide
  light compose were visually reviewed. Body labels now exclude quoted textarea
  content; browser validation caught and verified that correction.
- The static WSTG evidence collector follows the extracted address/threading
  modules and requires their current guards; a negative test proves missing
  address validation fails. It no longer claims all display names are invalid.
  This refresh preserves the evidence gate rather than grandfathering a removed
  marker. Native fixture extension checks real stored Reply-To/To/Cc/threading
  through signed helper IPC; exact execution follows signing.
- Evidence: `checkpoint-a-summary.json`, SHA-256
  `564cded31ab54e8c1e4f3f685795f8f626b31c49110fff80a6a791b9aecbffa1`.
  Contacts and full S03-01 acceptance remain pending. Source attachment layout,
  draft revision/retention, formatting and send/Sent reconciliation remain later
  S03 work. No live account, external recipient, deployment or synchronization.

### S03-01 checkpoint B work order — account-private contacts

- Signed A `bf20f08a77cec24420e7dedcd982260368f26a78` has a good Shopkeeper
  signature and clean checkpoint. Exact source archive
  `1b0b5c06d82417e59e6a92545a754aaf3553c25e7de853c988d90ea7277a32f3`
  is qualifying in owned `/home/foo/osmap-ux-s03-20260930-V6sghO6y` on obsd1;
  no standard checkout or live service mutation.
- Continue S03-01 under D05: at most 200 account-private contacts, display names
  at most 100 bytes, conservative bounded address validation, explicit selection
  into To/Cc/Bcc, no harvesting or trust inference. Mutations require session,
  CSRF, same-origin, account ownership and serialized revision checks. Use a
  versioned owner-only store below the existing settings state boundary;
  fail closed for malformed, stale, busy, symlinked or unsafe state.
- Allowed files: bounded account-file storage, contacts model/store, reviewed
  OpenBSD nonblocking lock wrapper, gateway/routes/UI/fixtures, acceptance and
  assurance inventories, tests and this ledger. Contact selection explicitly
  saves the composed draft so uploaded files and reply context can survive the
  server round trip. Full draft concurrency/retention remains S03-02. Qualify
  owner isolation, stale writes, quota/validation failures, keyboard/reflow,
  restart persistence and native storage before claiming delivery. No live
  contact data, external notices, address verification or message delivery.

### Revision-2 approved-reference amendment — 2026-09-30 UTC

- Operator correction: "these mockup images are the approved UX design in
  /osmap-ux-final-approved-20260919/images/", followed by "alright continue
  working". This supplies explicit authority for the separate revision-2
  planning amendment and continuation under the day-long engineering mandate.
  Messages are limited to slice completion, sprint completion and epic status.
- The previous work used the four revision-1 annotated references. No final-
  approved-bundle visual conformity is claimed for S00–S03-01A. Functional
  tests retain their stated scope; S01/S02 layout comparison is reopened.
- Exact archive SHA-256:
  `072bb9545b1ccd3be1370ee75003d5b97d297061c09eb4482e7faaf07160bdce`.
  Outer sidecar and all 27 inner files passed integrity verification; all
  25 PNGs were individually inspected. Exact files are retained under
  `docs/design/osmap-ux-final-approved-20260919/`; Login/TOTP have no new PNG.
- Scope: the three frozen plan documents, this ledger, revision-2 amendment,
  approved reference files, page/control acceptance inventory, current status,
  decisions and documentation index/classification. No runtime source change,
  state migration, host mutation, deployment or synchronization in this commit.
  Prior signed anchor `74522e5f99024720a3c47a3744207ff453de5731` verified and
  its manifest passed before authorized revision. New anchor follows signing.
- Source is signed S03-01A `bf20f08a77cec24420e7dedcd982260368f26a78`.
  Unfinished agent-authored S03-01B changes to 14 named files are preserved
  with hashes and a resume patch under S03
  `worktree-preservation-before-reference-r2/`; worktree was clean before the
  planning amendment. Restore only those changes after signing and preserve
  this new ledger entry. The amendment records requirement/test/rollback impacts.
- S03-01A exact native qualification also completed: 623 library tests, two
  hostile-rendering tests and the signed-helper reply/header fixture passed.
  Archive `1b0b5c06d82417e59e6a92545a754aaf3553c25e7de853c988d90ea7277a32f3`;
  log `56be4fa370f00e967a9ebe641573e36472c081b39e738ac83fa4d9231219636b`.
  Owned source `/home/foo/osmap-ux-s03-20260930-V6sghO6y`; standard checkout/
  services unchanged and disposable fixture removed. This is behavioural
  native evidence, not final-reference visual or production release acceptance.
- Revision-2 planning validation: 27 pages and 403 unique control IDs verified;
  the previous 110 acceptance cases remain byte-equivalent as parsed objects.
  Both plan and nested reference manifests pass, with no runtime source diff.
  Full `make acceptance-check` (security/V10/V11/V12/V13), `make v14-check`,
  documentation guard and diff checks PASS. The first signing attempt correctly
  refused two unindexed bundle Markdown files; their exact paths are now in
  the documentation index and the unchanged guard passes. Logs remain under
  S00 `approved-reference-reconciliation/`. No strict-release claim.

### Revision-2 delivery and practical UX continuation

- Accepted engineering anchor: `6b3ce8fff27ca3dabf87039d54098bd9967a2e42`,
  verified Shopkeeper signature; clean checkpoint, 18 ahead/0 behind recorded
  origin/main. No synchronization. Native nginx edge check remains unavailable
  locally; no release claim. Preserved S03-01B files restored with exact hashes.
- Latest operator direction allocates at most 10% to governance and 90% to UX.
  Continue contact interaction and approved compose/shared-shell implementation,
  focused behaviour/browser tests and required signing gates; no further plan
  expansion. Source boundary includes existing S03 files and shared UI/CSS/tests.

### S03-01B — contacts and practical composer checkpoint — 2026-09-30 UTC

- Implemented explicit private contact create/edit/remove and To/Cc/Bcc selection,
  bounded to 200 entries with owner isolation, revision checks, nonblocking locks,
  atomic private storage and constant error/audit messages. Selection saves the
  draft with existing text, reply context and uploads; it cannot submit mail.
- Shared shell now follows the final labelled sidebar/header proportions and
  persistent search. Compose has horizontal fields, Cc/Bcc disclosures, keyboard
  Expand/Restore and save-on-Minimize. Draft rows show escaped subjects, recipient
  summaries, attachment counts and readable UTC dates; never Bcc or message bodies.
  Login/TOTP styling remains unchanged. Final visual parity remains incomplete.
- Linux: 632 library tests PASS, six existing ignored fixtures; strict all-target/
  all-feature Clippy, formatting, diff, full acceptance and V14 gates PASS.
  Edge/Firefox contact journeys each PASS eight checks; Edge reply, appearance and
  list regression journeys PASS 5/6/9 checks. All browser traffic is loopback-only.
  Visual audit: 42 light/dark captures at 360/768/1600, zero overflow/text/UI contrast
  failures; 12 forced-colour captures PASS. Artifacts: S03 run-20260930 browser-b-*,
  visual-b*, fixtures-b and gates/*-b.log. Native qualification follows signing.
- Known remaining work: incomplete draft saves, draft concurrency/retention,
  attachment removal and preserved failed uploads, authoring tools, protection
  controls and full approved page comparisons. No runtime crypto, live contact
  data, external delivery, deployment or Git synchronization claimed.

### S01/S02 final-reference layout reconciliation — in progress

- S03-01B signed delivery `dfe6ba8ffb92b6a31f9bf316d6a06732f2f48673`
  verified; clean checkpoint, 19 ahead/0 behind recorded origin/main. Native
  qualification uses its isolated source archive; no deployment or sync.
- Continue the revision-2 ordered reconciliation in existing UI/CSS, view models
  and browser/route fixtures: full-width aligned mailbox rows, approved reader
  hierarchy and shared header. Preserve all bound mail actions, account isolation,
  query/selection state, retained authentication and truthful unknown statuses.
  Verify real navigation, narrow layout, contrast and existing gates before signing.
- Implemented aligned full-width desktop message rows, sender/subject/preview/
  attachment/security/date columns, native action menus and compact list toolbar.
  Reader now follows the approved header/status/body/attachments/reply hierarchy;
  existing account-bound navigation, filters, selection and mutations are retained.
- Validation: full acceptance, V14, strict Clippy, formatting and diff checks PASS.
  The hostile-content corpus body selector was updated for the accessible hidden
  heading; its unchanged inert-content assertions pass. Edge list/move journeys
  PASS 9/5; Edge and Firefox reader journeys PASS six each. Visual evidence under
  S02 run-20260930 final-reference-* includes 36 light/dark captures, 12 forced-
  colour, 12 reflow-simulation and eight final reader views; zero overflow,
  sidebar overlap or audited contrast failures. No whole-page acceptance claim:
  Documents/notices/theme shortcuts, extra filters and runtime crypto remain open.
- S03-01B native result: 632 library tests plus two hostile-rendering tests and
  the native signed-helper fixture PASS; standard obsd1 checkout/services unchanged.
  Archive `2b8818fd8d885d41ae5d5da3f60d216b763662649fd57e8101786f54022b6032`;
  log `98123411214df03a48a4a24459227dfd73ea7cd6004f2ab98a530541d91dc687`.

### S03-02A — resumable unfinished drafts and revision checks

- Continue practical draft work after the signed S01/S02 layout checkpoint:
  separate stored authoring fields from validated Send requests, preserve empty/
  partial recipients, add explicit save/delete/send revision checks and confirmed
  discard, enforce approved draft count/byte limits and retain legacy readability.
  Allowed boundaries are draft model/store, existing HTTP/gateway/view models,
  fixtures/tests and corresponding inventories. No live draft data or delivery.
- Required proof: blank/partial and maximum-body save/restart/resume, stale tabs,
  owner isolation, invalid Send refusal, quota/busy/storage failures and native
  storage tests. Preserve reply metadata and attachments. Autosave, failed-upload
  preservation and remaining authoring actions stay open until separately verified.
- Implemented separate unfinished-draft validation, exact To/Cc/Bcc text storage,
  v5 revision checks for Save/Send/Discard, 50 drafts/50 MiB account bounds and
  1 MiB encoded metadata. Legacy v1-v4 records remain readable and migrate only
  on save. Account locks refuse promptly; reads check private regular files and
  bounded attachment sizes. Adding uploads retains previously saved uploads.
- Conflict forms preserve posted text and offer a separate saved-version tab;
  failed forms retain source-attachment selection and explain upload reselection.
  Draft list no longer accepts query-string assertions that a save/delete occurred.
- Linux: 644 library tests PASS (six existing ignored); 41 draft-focused checks,
  strict Clippy, formatting and diff checks PASS. Edge/Firefox draft journeys each
  PASS seven checks using real file storage and a process restart. Contact/reply
  regressions PASS eight/five. Visual audit: 12 light/dark views and eight forced-
  colour views PASS without overflow or audited contrast failures. Artifacts:
  S03 run-20260930 drafts-a-*, fixtures-c, visual-c* and gates/*-c.log.
- Full acceptance and V14 gates PASS. Native qualification follows the signed
  checkpoint using an isolated source archive; this is not a deployment.
- Still open: interrupted-write recovery, autosave, attachment removal/failed-
  upload persistence, draft filters/sort/selection and stable source-message
  attachment references. No deployment, external email or Git synchronization.
