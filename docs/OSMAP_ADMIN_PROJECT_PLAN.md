# OSMAP-ADMIN project plan

Status: proposed design and delivery plan, 2026-11-13. This document authorizes no host change, account mutation, migration, deployment, or PostfixAdmin retirement. Each implementation slice needs its own bounded work order, review, and acceptance evidence.

## Outcome and existing boundaries

Build a separate, Rust-only OSMAP-ADMIN control plane for each OSMAP + OpenBSD Mailstack installation. It will eventually replace the administrative functions actually needed from PostfixAdmin while OSMAP remains the public webmail and user self-service application. Postfix and Dovecot continue to route, deliver, authenticate, and serve mail using their configured SQL lookups; they do not call either administrative web application at delivery time.

The current engineering request in [ADMINISTRATIVE_USER_MANAGEMENT_ENGINEERING_REQUEST.md](ADMINISTRATIVE_USER_MANAGEMENT_ENGINEERING_REQUEST.md) remains the governing scope and retirement gate. [V3_IDENTITY_LIFECYCLE_EVIDENCE.md](V3_IDENTITY_LIFECYCLE_EVIDENCE.md) describes the present OSMAP browser as mailbox-user only; this project must keep administrative routes and sessions out of that public surface. The present TOTP file and replay stores are described in [TOTP_SECRET_MANAGEMENT_MODEL.md](TOTP_SECRET_MANAGEMENT_MODEL.md). Existing operator provisioning, rotation, revocation, and recovery are bounded interim workflows, not a browser factor-lifecycle service or production qualification for a new host. Historical host evidence must be rechecked against the selected installation before implementation or cutover.

The Toronto `postfixadmin` database is the live mail-account authority in the documented topology. obsd1's writable `postfixadmin` development database is separate; its read-only Toronto reference replica is not selected by the application. Neither is a production migration target by implication. Keep Toronto authoritative and preserve the one-way reference boundary described in [the local development record](UX_S04_02_LOCAL_DEVELOPMENT_20261025.md) and [replica notes](../maint/development-db/README.md).

### Fixed product decisions

| Concern | Plan |
| --- | --- |
| Applications | One Rust workspace where practical, separate OSMAP and OSMAP-ADMIN processes, shared reviewed crates for identity normalization, validation, TOTP, session/CSRF patterns, rendering, and typed protocols. Extract rather than copy; select libraries after inspecting the current workspace. |
| Administrative entry | Private loopback/WireGuard HTTPS listener by default, distinct host/path policy, origin/Host checks, independent admin login and session. No inheritance of webmail authority. Public OSMAP routing does not expose admin routes. |
| Mail-account authority | Exactly one authoritative database and one designated administrative writer per installation at a time. Postfix and Dovecot receive narrow lookup grants; OSMAP receives no general account-table write or schema privilege. |
| Fresh installation | Native `osmap_mail` MariaDB database, created and migrated by a local Rust bootstrap/migration utility after MariaDB itself is initialized by supported vendor tooling. No PHP or PostfixAdmin prerequisite. |
| Existing installation | Start with a read-only PostfixAdmin-schema compatibility adapter and verified lookup contract; authorize writes only at a controlled single-writer gate. A later reviewed migration may move authority to `osmap_mail`. No independent parallel account database and no dual-write. |
| Factors | Reuse OSMAP's verifier, protected secret storage, and replay rules. Account/enrollment metadata may be in SQL; TOTP seeds and accepted counters stay in the protected factor/replay stores unless a separately reviewed migration changes that contract. |
| Administration identities | Model admins separately from mailboxes. The first system admin can be created before any domain/mailbox exists. Admin credentials, factors, sessions, and role grants have their own namespace and confinement, even when shared Rust code implements them. |

## System design and ownership

```text
Private HTTPS -> OSMAP-ADMIN web (unprivileged; admin session/CSRF)
                    -> typed Unix socket -> scoped Rust account service
                                           -> authoritative MariaDB account tables
                                           -> protected factor service/store
                    -> bounded audit records
Public HTTPS  -> OSMAP webmail -> existing Dovecot/auth and mail helpers
Postfix/Dovecot -> narrow SQL lookup identities -> same authoritative account tables
```

The web process has no SQL schema/write credentials, TOTP directory write access, shell control, or host configuration authority. Socket peer identity, protocol version, operation, actor/session scope, target identity, expected revision, and request ID are checked again by the service; the web process's role claim alone is insufficient. Distinct local OS and SQL principals separate web, account writer, schema migrator, factor handler, Postfix lookup, Dovecot lookup, and audit custody. Constrain each process with only the needed OpenBSD `pledge`/`unveil` capabilities and file access; verify actual installed capability rather than an OpenBSD release string. Secrets and raw private diagnostics never enter URLs, logs, audit, or retained evidence.

The service owns transactional domain/mailbox/alias/role mutations and password-hash updates. The local bootstrap/migrator alone owns database creation, DDL, and SQL grant lifecycle. Postfix and Dovecot own routing/authentication semantics; the installer renders and validates their lookup configuration but neither web process becomes a mail transport. OSMAP's public account identity continues to come from Dovecot, while its selected native account/credential helpers must be inventoried and kept on the same authority. Admin-only identity is verified by a separate admin credential backend and shared MFA implementation, with no implicit mapping from a mailbox login. Mailbox users manage only allowed own-account settings in OSMAP; the admin plane cannot read private mail or OpenPGP private keys.

### Data model and SQL contracts

The implementation must inventory the installed PostfixAdmin schema, effective Postfix maps, Dovecot passdb/userdb, password schemes, maildir ownership, quota plugin, optional tables/triggers, and enabled features before freezing migrations. The published mailstack Phase 03 prepares SQL and PostfixAdmin configuration; it does **not** establish a guaranteed automated schema deployment. [MAIL_STORAGE.md](../maint/openbsd/MAIL_STORAGE.md) documents an existing `mailbox` lookup with `username`, `maildir`, `quota`, and `active`; these are compatibility contracts to verify on the target, not permission to assume every installation has that exact schema or UID/GID.

| Logical entity | Required fields/invariants | Authority and consumers |
| --- | --- | --- |
| Domain | Canonical name, active state, limits/policy, revision, timestamps; unique name | Account service writes; Postfix domain lookup reads |
| Mailbox | Canonical full address, domain FK, compatible password hash, active/delivery state, stable maildir, quota, revision; unique address | Account service writes; Postfix recipient and Dovecot passdb/userdb read |
| Alias/alias domain | Canonical source, ordered validated destinations or target domain, active state, revision; cycle and catch-all policy | Account service writes; Postfix alias maps read |
| Admin identity and role grant | Stable admin ID, credential hash, enabled/locked state, system/domain scope, target domain FK, revision; no mailbox dependency | Admin credential service and authorization engine only |
| Enrollment | Opaque subject ID, factor type/store reference, pending/active/revoked state, token digest/expiry/consumption, revision | Account/factor services; never stores TOTP seed or code |
| Audit and migration ledger | Actor, role, operation, canonical target, request ID, before/after digest or revision, result/uncertainty, schema version | Protected append-oriented audit and migration tools |

Decide exact physical tables, column types, hash format, and SQL view/query strategy from the inventoried source schema and installed Postfix/Dovecot behavior. Versioned migrations must be ordered, checksummed, idempotent on retry only when prior state is proven, and refuse unknown schema versions. Database identifiers and grants must be explicit; migration must not silently replace an existing database. Use a protected backup and restore point before each DDL batch because MariaDB DDL is not generally transactionally reversible. Keep mailbox content and filesystem ownership outside schema migrations.

## First install and enrollment journeys

1. The installer verifies an empty target, supported MariaDB initialization facilities, intended local socket, mailstack SQL lookup capabilities, service identities, storage paths, and private listener. It initializes MariaDB through vendor facilities only where needed; it refuses a populated or ambiguously owned target.
2. A privileged local Rust `init` command creates `osmap_mail`, narrow SQL identities/grants, and applies versioned schema migrations. It renders Postfix and Dovecot SQL lookup configurations for review, validates syntax and queries against disposable records, and records a non-secret schema receipt. Service activation is a separate deployment step.
3. A local, one-shot Rust `bootstrap-admin` command creates the first pending system-admin identity independently of mailbox creation. It establishes an admin password using a reviewed verifier/hash policy and produces a TOTP enrollment on a trusted local terminal. Only after proof of possession of a fresh code, protected no-overwrite factor installation, and readback does it activate the admin and close the one-shot bootstrap capability. Interruption, concurrent invocations, and partial factor installation fail closed and require local reconciliation; no web-accessible unauthenticated bootstrap endpoint exists.
4. The admin signs in through the private listener with its own password, TOTP, and bounded session, then creates the first domain and mailbox. The account service records account metadata and compatible password hash, validates the Postfix recipient and Dovecot userdb/passdb projections, and leaves OSMAP browser access pending until user MFA enrollment succeeds.
5. A mailbox owner receives a short-lived, single-use setup authorization through a verified independent channel that works before mailbox access. Store only its digest, scope, expiry, and consumption state. A restricted OSMAP enrollment session can establish/verify a user-held TOTP seed but cannot read mail or obtain an ordinary session. The factor service installs it without overwriting another factor; verification and activation are coupled through explicit state reconciliation. An administrator normally never learns the user's seed. Revoke setup tokens after success, expiry, password change, or suspicious reuse.

Use the established canonical mailbox identity and TOTP file naming for mailbox users. A separate admin subject namespace must avoid collision with mailbox filenames, replay counters, and sessions. Existing factor files are never silently renamed or imported. Rotation, revocation, lost-device recovery, missing-factor reconciliation, and session revocation need separate, reviewed transitions; the current operator recovery SOP's signed attestation is not proof that external identity and containment controls were performed. Account disablement, admin-role change, password reset, and factor replacement must invalidate affected sessions according to an explicit, tested rule. Do not reset replay state to make an enrollment or recovery pass.

## Authorization and privilege matrix

Every operation is deny-by-default and checks role, target domain, subject identity, fresh authentication, object revision, and server-side canonicalization. The service enforces the same policy as the UI.

| Operation | System admin | Domain admin | Mailbox user |
| --- | --- | --- | --- |
| Create/retire domains; global policy; grant system admin | Allowed with step-up and audit | Denied | Denied |
| Manage mailbox, alias, quota, domain settings | Allowed in managed installation | Assigned domains only; no cross-domain target/destination expansion | Denied |
| Grant/revoke domain admin | Allowed with step-up | Denied in initial release | Denied |
| Reset credential or initiate factor recovery | Allowed with separate identity/containment procedure and step-up | Assigned-domain mailbox only if expressly enabled by policy; never system admin | Own-account recovery through separately approved path only |
| View mail, private keys, TOTP seed or accepted counter | Denied | Denied | Own mail via OSMAP only; seed never retrievable |
| Change own password/settings | Own admin credential through admin plane | Own admin credential through admin plane | Own permitted settings through OSMAP |

Deletion is staged: disable delivery/authentication as specified, retain mailbox data, provide a reviewed export/retention decision, then allow separate irreversible purge authority. A domain admin may set an external forwarding destination when policy permits, but may only administer the source address in an assigned domain; the destination grants no authority over its domain. Audit denials as well as successful high-risk changes without logging secrets.

## Phased work and dependency gates

Each phase produces a reviewable artifact and tests the smallest real changed boundary. Phase completion is not installed or production acceptance. The implementation order may split into smaller work orders without relaxing dependencies.

| Phase | Deliverable and dependency | Exit evidence |
| --- | --- | --- |
| 0. Inventory/contract | Current source and target branch review; installed feature-parity matrix (P0 core, P1 supported services, P2 optional), exact Postfix/Dovecot SQL queries, schema, hash schemes, TOTP/session contracts, trust map, threat model. No host mutation. | Reviewed compatibility decisions and named unknowns; each required PostfixAdmin workflow has a disposition. |
| 1. Shared foundation | Extract reusable Rust components; admin identity/session/MFA backend; typed socket protocol and scoped helper; read-only compatibility adapter; audit shape. Depends on Phase 0 contracts. | Private admin sign-in using a disposable seeded test identity and read-only domain/mailbox/alias view; forged scope, cross-domain and ordinary OSMAP session denied. No first-install claim. |
| 2. Native bootstrap | Versioned `osmap_mail` schema, grant provisioning, local first-admin bootstrap, fresh-install mailstack config renderer. Depends on isolated service boundary. | From clean disposable OpenBSD/MariaDB environment, create and sign in as the first admin without PHP; verify SQL lookup fixtures, idempotent/partial-failure refusal, and restore. Domain/mailbox creation follows in Phase 3. |
| 3. Core writer | Domain, mailbox, alias, quota, password, status, admin-role mutations with revisions and audit; existing-schema adapter only after single-writer gate. | Actual Postfix recipient/alias routing, Dovecot auth/userdb and quota enforcement using controlled records; negative scope/race tests; no other account or mail data changed. OSMAP login for newly provisioned users follows in Phase 4. |
| 4. Enrollment/lifecycle | Restricted mailbox enrollment, admin step-up, session invalidation, governed rotation/revocation/recovery integration. Depends on Phase 3 account states and existing factor contract. Update the present WSTG identity and TOTP contracts/probes to admit only this restricted route while ordinary signup and browser account provisioning remain denied. | First-user and existing-user password-plus-TOTP OSMAP journeys, replay/race/expired-token/refusal and partial-state reconciliation on isolated target. |
| 5. Parity/operations | Required alias domains, vacation, export/restore, native CLI, optional DKIM/application passwords only where installed services support them; read-only mailstack diagnostics first. | Every P0 workflow passes; each P1/P2 item either demonstrated or explicitly deferred with operator acceptance. No private mail/key access. |
| 6. Migration/cutover | Production-representative rehearsal, one-writer cutover from PostfixAdmin, optional `osmap_mail` migration, rollback exercise, operator procedures. Depends on Phases 0–5 and independent review. | Reconciled source/target counts and semantic digests, representative live mail/account journeys, backup restore, rollback with post-cutover-write reconciliation, explicit operator acceptance. |
| 7. Retirement | Separate reviewed PostfixAdmin retirement change. Depends on stable cutover and recovery readiness. | No remaining required PostfixAdmin workflow, stale route, PHP-only dependency, scheduled job, or excessive SQL grant; retained rollback artifacts protected. |

### Parity inventory to complete in Phase 0

P0: hosted domains and limits; mailboxes and compatible password hashes; aliases including multi-recipient forwarding and catch-all; quotas and active state; system/domain admins; audit; first-admin/user enrollment; password change/reset and factor lifecycle. P1, where installed: alias domains, vacation/Sieve, domain quotas, export/restore, CLI, DKIM metadata and protected key operations, forwarding self-service. P2, only with an installed backend and separate threat review: fetchmail, transport/backup-MX rules, application passwords, broadcast, and restricted API. Do not replicate permissive MFA bypass or legacy XML-RPC merely for apparent parity. Record installed version and enabled features as dated observations, not compatibility predicates.

## Existing-install migration and rollback

1. On an isolated, production-representative copy, inventory the source schema, constraints, rows, SQL views, grants, Postfix maps, Dovecot queries, and mailbox paths. Preserve private dumps and hashes outside the repository. Build a field-level mapping for domains, mailbox password hashes, alias multiplicity, quotas, active flags, administrators, and optional features. Mark unrepresentable data as a blocker rather than dropping it.
2. Run the compatibility adapter read-only against the existing `postfixadmin` schema. Compare Rust projections to effective Postfix/Dovecot lookups. For any existing-schema write trial, designate exactly one active administrative writer, restrict PostfixAdmin writes, record a snapshot/checkpoint, and verify semantic effects. End the trial or restore writer ownership explicitly.
3. For a native-database transition, use a new, empty `osmap_mail` database with versioned schema. Import a consistent source snapshot, preserve password hashes and maildir values, compare full key sets and deterministic row digests plus functional lookup results, then capture/reconcile changes since the snapshot under a bounded write-freeze. Do not replicate or dual-write both authorities.
4. In a separately authorized maintenance action, back up and prove restoration, lock administrative writes, switch Postfix, Dovecot, and the selected OSMAP native account/credential helpers together to the verified authority, start the designated OSMAP-ADMIN writer, and perform representative routing, delivery, login, quota, alias, factor, and admin-scope checks. Preserve all mailbox bytes, identities, and ownership; no generic storage copy is implied.
5. If the new authority fails, stop new administrative writes, preserve evidence and both databases, and restore the prior configuration/authority only after reconciling any post-switch account and mail changes. Never blindly point services at a stale snapshot. If state is ambiguous, retain containment and escalate for an explicit decision. PostfixAdmin remains installed and recoverable until a separate retirement review.

Backups must include account data, schema/migration ledger, protected factor files, replay/session state where needed for safe restoration, mail configuration, and an independently verified restore procedure. Keep credential hashes, factor bodies, private mailbox content, and recovery approvals out of public artifacts. A successful SQL copy alone is not a rollback proof.

## Acceptance and delivery evidence

- **Functional:** Fresh installation reaches first admin login and first mailbox password-plus-TOTP login without PostfixAdmin. Existing installation preserves all required management functions. Creating/disabling a domain or mailbox, changing credentials/quota, and creating multi-destination/catch-all aliases has the expected native Postfix/Dovecot behavior, not just SQL rows or page output.
- **Security:** Ordinary OSMAP sessions cannot become admin sessions; domain admins cannot cross scope; privilege and socket checks resist forged actor/target, stale revision, replay, CSRF, Host/origin confusion, malformed requests, and concurrent requests. Seeds/codes/passwords are absent from URLs, audit, logs, evidence, and browser persistence. Factor no-overwrite, replay, revocation, and recovery limits remain intact.
- **Operations:** The only writer is identifiable at every stage. Migration and fresh bootstrap refuse unknown or partially populated targets. Backup/restore, SQL/config rollback, session/factor-state reconciliation, and interrupted-operation handling are exercised on a disposable OpenBSD target. No public mail-service downtime is invented as a test prerequisite.
- **Review:** Focused unit and integration checks exercise the changed contract, then normal repository delivery gates and independent source/security review. Native installation and controlled acceptance are separate evidence. Record PASS/FAIL/UNKNOWN/NOT RUN precisely; no obsd1 result is called Toronto qualification. Production cutover, owner UAT, and PostfixAdmin retirement require their own explicit decisions.

## Open decisions for Phase 0

Verify the installed PostfixAdmin feature set and effective SQL contracts; choose the physical native schema and compatibility views; select admin password-hash/verifier policy and factor namespace; determine the independent first-user setup channel; decide whether any domain admin may initiate factor recovery; and identify the exact mailstack installer/configuration ownership. These are implementation gates to resolve with observed configuration and explicit product decisions, not assumptions that delay this documentation plan.

## Read-only compatibility adapter slice — 2026-11-14

- **Outcome and scope:** Internal Rust reads of scoped PostfixAdmin domains, mailboxes, aliases and alias-domain mappings, preserving stored active flags, paths and quota values. No admin login, browser route, database writer, migration or Toronto deployment is included.
- **Owner and review:** `/root` owns source, the single obsd1 fixture and Git delivery; an independent source reviewer checks SQL, scope, privacy, bounds and schema compatibility. Stop after two failures at the same functional boundary for reassessment; no automatic allowance increase. One isolated native fixture and one ordinary delivery gate are the intended expensive actions.
- **Prerequisites:** Toronto Phase 0 metadata reports `toronto-20261114T091715Z.txt` and `toronto-gaps-20261114T131148Z.txt` establish the reference columns and effective lookup semantics. Upstream PostfixAdmin revision `bff07294ddade24cbac3cdd65e6ead597cab1d71` was checked for relevant domain, mailbox, alias, alias-domain and upgrade definitions. obsd1's development MariaDB is separate from Toronto's read-only reference replica.
- **Minimum evidence and result:** Focused Rust tests cover scoped reads, absent/empty/invalid inputs and bounded error parsing. An isolated obsd1 MariaDB fixture exercised all four real SQL projections, missing-column and unavailable refusals, and column-level read grants that denied password selection and an update. The temporary database and SQL user were removed and absence read back. These results do not qualify a production admin caller or the fixed deployment config path.
- **PR #88 reconciliation, 2026-11-16:** Integrate `main` at `18cde0f` into the existing published branch and regenerate the sole conflicting V10 inventory from the combined source. Root owns integration/Git; the independent adapter reviewer checks the final delta and delivery evidence. The six-file adapter delta preserves the Toronto edge work already merged through #89 and the later #90/#91 work. Adapter bytes and existing command execution sources match the tested adapter commit, so the isolated obsd1 SQL evidence is retained. Four Rust adapter tests, formatting, strict Clippy, the CWE guard regression and V11 inventory consumer pass; independent reconciliation review finds no blocker. Exit requires normal signed commit/push hooks, the required status on the exact published head and protected linear integration. GitHub squash integration preserves the Shopkeeper-signed source commits on the PR branch and yields a separate GitHub-signed linear commit on `main`. Two failures at the same boundary require reassessment; no native action or new fixture is planned. Full delivery and merge results remain pending until executed.
- **Signing stop:** The first reconciliation commit attempt passed the normal pre-commit check but exited 128 because the configured Shopkeeper GPG agent could not sign noninteractively (`No pinentry`). No commit or remote update was created. The operator subsequently completed the native agent warm-up and reported successful cached signing checks; delivery resumes through normal signing without bypass.
- **OSMAP naming, 2026-11-16:** At the operator's direction, name the internal Rust component `admin_directory`, describing its OSMAP responsibility rather than the predecessor application. Root owns the module/guard rename and signed delivery; independent review checks that executable statements and fixed SQL remain identical. Retain the actual existing database selector as a connection contract until a separately reviewed migration. Refresh the existing exact-source guard and generated inventory for the new path. The minimum checks are the four renamed module tests, formatting, Clippy, guard and inventory consumers, independent review and normal delivery hooks. Reuse prior native SQL evidence because queries, command arguments and execution are unchanged. Two failures at the same boundary stop retries for reassessment; no host action or database rename is included.

## Authenticated domain-read slice — 2026-11-16

Root owns the single source/native/Git queue; the independent adapter reviewer
checks implementation, native evidence and delivery. Exit: an internal Rust
backend verifies an independently seeded admin password plus TOTP, issues an
admin-only session, resolves current grants and returns one authorized domain
through `admin_directory`. Wrong/replayed factors, mailbox tokens, expired or
revoked sessions and removed/foreign grants must refuse. Client inputs never
contain role grants or allowed-domain lists. Reuse TOTP replay, sessions and login
throttling; use only fixed SELECTs on the existing admin, domain_admins and domain
tables. No listener, UI, writer, bootstrap, production operation or schema
migration is included. Separate trusted backend construction and private state
roots are exercised by Rust tests, not represented as an installed admin daemon.

obsd1 read-only metadata confirms separate admin credentials and domain-grant
columns. OpenBSD `crypt_checkpass` is the native password boundary; admit a bounded
bcrypt work factor, keep credentials in memory and reuse no mailbox password.
The first tests cover successful authentication/read and cross-domain refusal;
then exercise replay, current-grant removal, expiry/revocation, input limits and
safe backend failures. Validate actual SQL/password/TOTP/session composition on
one disposable obsd1 database with restricted SELECT grants and private state,
retaining sanitized outcomes before exact-owned cleanup. Native compilation is
bounded to 600 seconds and fixture execution to 120 seconds. The investigation
checkpoint is four hours; two failures at the same boundary stop retries for
independent reassessment, with no automatic allowance increase. Focused source
checks precede a signed native checkpoint; normal hooks, final independent review
and verified GitHub delivery follow. All results are NOT RUN until observed.

Source progression: the initial boundary test refuses to compile before the
implementation exists. The first implemented run reveals a fixture TOTP-file
format error and a missing explicit legacy `ALL` refusal; their distinguishing
retests pass. Independent review then identifies snapshot-only session revival.
Reuse `PrivateAccountFile` to persist a monotonically increasing generation for
each observed credential/grant/factor snapshot, and bind it through the existing
session epoch authority. Removal observed by a request followed by restoration
cannot revive an old token. Unobserved external changes restored between reads
cannot be detected by this read-only slice; later controlled writers must advance
revocation state synchronously. Use the OS real UID for this local backend's
throttle source; a future remote entry must provide independently verified peer
context. Per-call fixed diagnostics preserve backend unavailability through the
generic session consumer. Native results remain pending. Password verification
currently admits only independently seeded bcrypt cost 12; it does not qualify
unknown existing admin hash schemes or system-admin/legacy `ALL` semantics.

Eight focused source tests pass; three separately ignored tests await the native
fixture. Formatting, strict Clippy, exact-source CWE guard regression, generated
inventory/V11 consumer and documentation governance pass. Independent source
review approves the bounded internal scope. The generation record includes a
random instance ID so loss followed by recreation cannot revive an old session;
validation never initializes missing generation state. These passes qualify the
local composition only; native password and SQL results remain NOT RUN.

Native qualification at signed source
[`3fc3f16`](https://github.com/unattributed/OSMAP/commit/3fc3f163fac09243cdfac1cbfec1aaedfdb6af95)
passes on obsd1. Cargo reports 2m59s for the isolated test-profile build; the
libtest SHA-256 is
`ed629abb6dbdbfa5447e0367d39a6d328ec13413959933baee85acd080290893`.
Eight focused native tests pass with the three separately gated fixture tests
ignored in that run. Explicit fixture invocations then pass real bcrypt/TOTP,
authorized SQL read, unknown/wrong-password and replay/foreign-domain refusals,
session validation in a second process, grant removal refusal, and continued
old-session refusal after the grant is restored. The test-only executor selects
the isolated database/config; the actual prepared queries and system command
runner execute unchanged. This does not qualify the production configuration.

Agent-executed permission checks confirm an allowed SELECT and specific MariaDB
1142/1143 refusals for the factor column, mailbox password and UPDATE. A verified
foreign OS UID cannot read the private connection file. Independent review
reads the native result logs and sanitized permission receipt before exact-owned
cleanup. Database/account absence and native scratch removal are read back.
Permission receipt SHA-256:
`65c1cded5776757585f7ee0860ad846a61bf7e802b7ee18c592c1d64b5123f27`;
cleanup receipt:
`2fbef09880b13dd387e60d2f7658a69d1b951d237823284a790dd8ca631209b6`.
Private logs are under `Downloads/osmap-admin-adapter/admin-access-native/`.
Initial failed local synthetic-fixture roots were retained by the test harness;
their exact names were not emitted, so local failed-fixture cleanup is UNKNOWN.
Native cleanup is separately confirmed. Full delivery-gate results remain pending.

## Toronto compatibility slice — 2026-11-16

Outcome: qualify development against Toronto's observed credential/schema/role
contracts and execute the changed Rust backend on Toronto, not infer portability
from obsd1 alone. Read-only observations find active `$2y$10$` credentials,
consistent `superadmin=1` plus active `ALL`, supported login/grant bounds and
missing `/etc/osmap/admin-read-mariadb.cnf`. Preserve source hash bytes; adapt only
a verification copy of the documented equivalent bcrypt marker in memory. Admit
costs 10–12 and refuse ambiguous/unsupported markers and excessive work factors.
System domain reads require both active role indicators; either alone refuses.

Root owns source, both native queues and Git; the independent adapter reviewer
owns source/result review. First tests must fail on the observed hash/role gaps.
Then qualify wrong passwords, unsupported costs/markers, inconsistent roles,
demotion/reinstatement refusal, TOTP replay and persisted sessions. Reuse existing
Rust/native fixtures. Use an independently generated synthetic `$2y$10$` hash,
never a production hash/password/factor. Validate the actual fixed SELECT contract
read-only against Toronto with a NULL predicate that cannot return an account. Execute the
backend on obsd1, then on Toronto against its installed MariaDB binary in a
temporary separate Unix-socket-only instance with production-shaped schema and
restricted fixture grants. Do not change production databases/users, installed
configuration, services, mail accounts or factors. Commit a private-client/grant
example for later deployment; do not describe it as installed configuration.

Use signed reviewed source before transfer, one-job/debug0 native compilation
bounded to 600 seconds per host and fixture phases bounded to 120 seconds.
Toronto's build-user hard data limit needs the previously proven privileged
limit setup followed by dropping groups/GID/UID before Cargo. The temporary
database has no TCP listener and uses explicit small buffers and connection
bounds. Retain/read back sanitized diagnostics and hashes before exact-owned
cleanup. Two failures at one boundary stop retries for independent reassessment;
the investigation checkpoint is four hours without automatic allowance growth.
Focused checks precede normal signed delivery hooks, independent result review,
exact-head status and protected integration. Results remain NOT RUN until observed.

Source observations: both new hash/role regressions fail against the prior code.
The correction passes 12 focused tests, with nine gated native tests still
ignored locally, plus formatting, strict Clippy, exact-source guard regression,
inventory validation and independent source review. The exact fixed SELECT runs
on Toronto's installed schema with NULL binding, exit 0 and zero stdout/stderr
bytes; this is schema compatibility, not successful production authentication.
Independent Linux libcrypt vectors use explicit `$2y$10$` and `$2b$12$` settings,
including UTF-8 input. An initial generator-default assumption produced a
different marker and was refused before use; the explicit setting corrects the
fixture method. The Toronto standard Cargo-cache preflight refuses before
compilation because that cache is absent; a private locked fetch supplies the
same dependencies. No new product dependency is added. An initial documentation
check names an absent program (exit 2); the existing shell governance guard then
passes. These preparation failures are separate from product qualification.

### Native compatibility results

Both hosts compile and execute signed source
`e799b36b7bb44a31f510a2fa3d27c697d0ff0600`, archived as
`5242aed6c96d4245ab8d2fd8b7cf524fc884a3b5feb4b4d7ad67b1648ce8e89d`.
The root private retained evidence directory is
`/home/foo/Downloads/osmap-admin-adapter/toronto-compatibility/`.
All 17 entries in each host's `evidence.sha256` are read back and verified locally.

| Actual result | obsd1 | Toronto |
| --- | --- | --- |
| One-job/debug0 native library-test compilation | PASS, 2m59s | PASS, 9m40s |
| Focused source regressions | 12 PASS, 9 gated tests ignored | 12 PASS, 9 gated tests ignored |
| Independently generated ASCII/UTF-8 `$2y$10$` and `$2b$12$` vectors, correct/wrong password, unchanged hash bytes | PASS | PASS |
| Password + independent TOTP, replay denial, exact domain read/cross-domain refusal, second-process session read | PASS | PASS |
| Both system indicators, foreign-domain read and second-process session read | PASS | PASS |
| Flag-only and ALL-only fresh login refusal | PASS | PASS |
| Observed demotion and restored-role old-session refusal; restored fresh TOTP login/read | PASS | PASS |
| Exact permitted SQL columns; factor/mailbox-secret/update denied; confirmed foreign-UID private-profile refusal | PASS | PASS |
| Separate private socket/datadir/fresh server PID; networking disabled | PASS | PASS |

Each host runs 12 native test invocations, including repeated refusal cases;
these are functional phase observations, not 12 distinct native test functions.
Coarse role-state receipts distinguish baseline `0,0`, system `1,1`, flag-only
`1,0`, ALL-only `0,1` and restored `1,1`. The explicit-domain revoke/restore
sequence also refuses the old token; final database readback confirms its grant
is present. Do not infer historical grant-state snapshots from identical test
markers alone. The prior authenticated-read slice retains the separate grant
restoration evidence.

The host evidence-index SHA-256 values are
`d7b5bbec3318d273f351a839dbb105f583567e3e16e8de24e5b813f4a13df513`
(obsd1) and
`6173c51ef0d3433cdd36485a728203c72963d0e1ed6f55ab43eaaeb4c25fa653`
(Toronto). Toronto's contract receipt is
`aa61b9ce49b346010072cbf2fc4b469396131990bf734265771c5c192a0aa0c3`.
Native libtest SHA-256 values remain in the matching retained identity receipts;
different native artifacts need not be byte-identical to qualify their shared
source contract. Whole-slice elapsed/token/monetary cost is UNKNOWN; the actual
compiler elapsed observations above are retained without resetting failure or
cumulative effort history. The four-hour investigation checkpoint is unchanged.

Independent source and both-host result review PASS. Both exact private servers
shut down; fresh PID/socket/process observations confirm absence. Shutdown
receipts are downloaded and hash-read back before removal, then each exact-owned
scratch root is removed and absence confirmed. The shared shutdown-receipt hash
is `286c676e0896492b85051fad0f0dd052e8d8d4a95802f5be55238874daa1ee6a`.
Earlier unnamed local RED-test fixture cleanup remains UNKNOWN, as retained in
the preceding slice; do not infer its cleanup from these two native cleanups.
Final evidence-only signing, the normal pre-push developer gate and protected
GitHub integration remain pending. Production SQL-profile installation remains
unimplemented.
These results qualify the internal Rust backend against Toronto's observed
contracts and installed native utilities. They do not authenticate a live admin,
install a service, expose a network entry, qualify an admin UI or refresh a
strict-release claim. Existing public MariaDB/Postfix/Dovecot services,
configuration, databases, accounts and factors are not changed.

Delivery gate follow-up: the first normal push is refused by the full Rust suite
(2395 PASS, two FAIL, 100 ignored), before remote synchronization. The failed
configured-auth fallback test passes its one isolated discriminator; its original
missed-marker cause is UNKNOWN because the old assertion retains neither case
nor source-owned audit action codes and removes its fixture before asserting.
The scheduled-outbox test uses a fixture-start timestamp to validate a restored
draft stamped by a later runtime wall clock, allowing `InvalidIntent` on a second
boundary. The bounded correction is test-only: validate restored state at the saved
draft timestamp and deliberately separate source/runtime timestamps; add fixed
case/action diagnostics to the auth assertion without changing expectations.
Minimum checks are the two affected test groups, formatting/Clippy/guard and the
normal push gate. The changed scheduling and auth groups PASS (12 and eight
tests), with formatting, strict library/tests Clippy and source review. Auth
failures now preserve the exact private fixture and fixed boolean case/action
codes; scheduled panics also emit their exact retained synthetic fixture root.
The earlier failed scheduled fixture root was not emitted, so its cleanup stays
UNKNOWN. Arbitrary event fields and native output remain private. Independently
review this correction; do not change runtime auth, scheduling or any native-qualified admin source, or rerun matching native
qualifications. Preserve the first full-gate log and initial missing observation.

### Operator-requested Argon2id investigation — 2026-11-16

The operator additionally requests investigation of Argon2id for stronger email
password storage. This is read-only research and a bounded synthetic native
discriminator, not migration or permission to change a stored credential.
Toronto's installed Dovecot advertises ARGON2ID. Aggregate-only SQL finds 14
active mailbox rows: one Argon2id and 13 bcrypt; the one active admin is bcrypt.
No hash, account name or factor is retained. Its SQL default is BLF-CRYPT;
Dovecot's explicit `{ARGON2ID}` per-row prefix overrides that default. Merely
changing the default would not convert existing bcrypt hashes and can break
bare bcrypt rows.

The existing Rust mailbox password backend already calls fixed `doveadm -O pw
-s ARGON2ID` and admits newly generated `m=65536,t=3,p=1` replacements. This is
source capability, not proof that all installed password-writing paths use it.
A synthetic long-input generate/verify/final-byte-negative discriminator on
Toronto returns 0/0/75 with those parameters (64 MiB, three passes, one lane),
approximately 328/338/330 ms during the compatibility build. These are three
single samples, not a latency/concurrency capacity benchmark or live login.
The first investigation shell wrapper refused dollar expansion before SQL;
the unprivileged scheme list also reported a stats-socket permission failure.
The corrected fixed Python stdin SQL and privileged read-only scheme listing
succeed. No account authentication or credential write was dispatched.

[OWASP prefers Argon2id](https://cheatsheetseries.owasp.org/cheatsheets/Password_Storage_Cheat_Sheet.html)
for new password storage; bcrypt cost 10 meets its legacy minimum. Argon2id's
memory cost improves resistance to offline guessing after a hash leak; it does
not replace TLS, TOTP or online abuse controls. This recommendation is not an
independently established compliance obligation for this installation.
[Dovecot documents mixed schemes through explicit prefixes](https://doc.dovecot.org/2.3/configuration_manual/authentication/password_schemes/).

Proposed next bounded implementation: qualify independent admin Argon2id
verification while retaining legacy bcrypt verification, using an established
Rust implementation or reviewed native library rather than custom cryptography.
The current OpenBSD `crypt_checkpass` admin path is bcrypt-only and will refuse
Argon2id until changed. Keep admin identity/factors separate from mailbox
authentication; adding PHP or depending on the predecessor application is not
required. Admit bounded PHC parameters before allocating memory, address uniform
unknown-user work and throttle identity, and test native known vectors, wrong
passwords, long UTF-8 tail changes, malformed/excessive parameters and mixed
legacy sessions on both hosts. No dependency or verifier is added by this
investigation.

Before any migration, inventory each installed verifier and password writer
(IMAP, SMTP SASL, OSMAP login, password reset/change, admin enrollment/reset and
provisioning); qualify the actual SQL prefix handling and long-input contract.
Benchmark chosen parameters and concurrent authentication on Toronto within
existing service limits. Reuse the existing 64 MiB/three-pass candidate if that
evidence supports it; do not turn it into a fixed host-memory prerequisite.
Preserve mixed-scheme reads and choose exactly one coordinated writer. Generate
Argon2id only when the actual password is supplied during an authorized
change/reset or a separately designed authenticated rehash; a bcrypt hash cannot
be converted into the corresponding Argon2id hash. The read-only admin slice
must not acquire an implicit login-time write. Use exact conditional updates,
session revocation and recovery evidence, and ensure rollback software still
verifies Argon2id rows. Migration and production acceptance remain unimplemented.
