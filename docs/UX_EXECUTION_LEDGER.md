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
