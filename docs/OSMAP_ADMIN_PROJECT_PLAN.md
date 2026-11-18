# OSMAP-ADMIN project plan

Status: design baseline dated 2026-11-13, with the operator-requested execution roadmap dated 2026-11-17 below. The roadmap organizes implementation; it does not assert that specified features or tests are complete. This document authorizes no host change, account mutation, migration, deployment, or PostfixAdmin retirement. Each implementation slice needs its own bounded work order, review, and acceptance evidence.

## Outcome and existing boundaries

Build a separate, Rust-only OSMAP-ADMIN control plane for each OSMAP + OpenBSD Mailstack installation. It will eventually replace the administrative functions actually needed from PostfixAdmin while OSMAP remains the public webmail and user self-service application. Postfix and Dovecot continue to route, deliver, authenticate, and serve mail using their configured SQL lookups; they do not call either administrative web application at delivery time.

**Epic acceptance has two required entry paths:** an already installed
openbsd-mailstack/OSMAP system with empty account authority reaches independent
first-admin, first-domain and first-mailbox operation; an existing populated
installation reaches equivalent Rust administration with preserved mail,
credentials/factors, one writer and proven continuity/rollback. Both consume the
enhanced existing mailstack bootstrap. The future full-stack installation
gateway and optional WireGuard client provisioning remain outside this epic's
current delivery scope. Approved basic pages and the final login design are
retained; missing write/security capabilities are scheduled below.

The current engineering request in [ADMINISTRATIVE_USER_MANAGEMENT_ENGINEERING_REQUEST.md](ADMINISTRATIVE_USER_MANAGEMENT_ENGINEERING_REQUEST.md) remains the governing scope and retirement gate. [V3_IDENTITY_LIFECYCLE_EVIDENCE.md](V3_IDENTITY_LIFECYCLE_EVIDENCE.md) describes the present OSMAP browser as mailbox-user only; this project must keep administrative routes and sessions out of that public surface. The present TOTP file and replay stores are described in [TOTP_SECRET_MANAGEMENT_MODEL.md](TOTP_SECRET_MANAGEMENT_MODEL.md). Existing operator provisioning, rotation, revocation, and recovery are bounded interim workflows, not a browser factor-lifecycle service or production qualification for a new host. Historical host evidence must be rechecked against the selected installation before implementation or cutover.

The Toronto `postfixadmin` database is the live mail-account authority in the documented topology. obsd1's writable `postfixadmin` development database is separate; its read-only Toronto reference replica is not selected by the application. Neither is a production migration target by implication. Keep Toronto authoritative and preserve the one-way reference boundary described in [the local development record](UX_S04_02_LOCAL_DEVELOPMENT_20261025.md) and [replica notes](../maint/development-db/README.md).

### Fixed product decisions

| Concern | Plan |
| --- | --- |
| Applications | One Rust workspace where practical, separate OSMAP and OSMAP-ADMIN processes, shared reviewed crates for identity normalization, validation, TOTP, session/CSRF patterns, rendering, and typed protocols. Extract rather than copy; select libraries after inspecting the current workspace. |
| Administrative entry | Private HTTPS on loopback or an existing operator-admitted private boundary, distinct host/path policy, origin/Host checks, independent admin login and session. No inheritance of webmail authority. Public OSMAP routing does not expose admin routes. Provisioning new WireGuard client access is deferred, not an installation prerequisite. |
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

These are legacy-parity inventory priorities. The integrated security catalogue
below adds its own baseline release requirements; a legacy module's P1/P2 label
does not make an applicable baseline security control optional.

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

## Execution roadmap — 2026-11-17

The operator prioritizes usable replacement functionality: **qualify the private
admin pages -> initialize/adopt authority and bootstrap the first admin -> create
a domain from scratch -> create a controlled mailbox -> prove native
authentication and message delivery**, followed by the scheduled management,
security and replacement gates below. This section is the single sprint/slice
execution index and current work-order location for OSMAP-ADMIN. The phase table,
architecture, UX catalogue and acceptance specification remain requirement
sources; no second backlog, QA framework or execution ledger is introduced.

The roadmap maps the existing specifications rather than replacing them:

- **U:** [UX specification](OSMAP_ADMIN_UX_SPECIFICATION.md), including `UX-A0`
  through `UX-A8` and the named `UX-WF` workflows.
- **T:** [test and acceptance plan](OSMAP_ADMIN_TEST_AND_ACCEPTANCE_PLAN.md).
  Every `T:` reference below names an existing case or inclusive case range.
- **P:** [replacement parity inventory, issue #85](https://github.com/unattributed/OSMAP/issues/85),
  inspected 2026-11-17. Its `SEC` IDs differ from the test plan's `SEC` IDs;
  keep the prefixes when recording results. UX-specification `UX-xx` assertions
  likewise differ from test-plan `T:UX-xx`; an unqualified ID is insufficient.

Sprint IDs are stable work groups, not a strict numeric execution order, dates,
estimates or automatic live authority. The selected sequence and technical
dependencies below control dispatch. A sprint closes on its defined product outcome and applicable adverse
cases, matching native/browser evidence, independent review and separate operator
acceptance. A source checkpoint, backend test or completed planning task cannot
close a product sprint. Split a selected slice further only when its one outcome
and all original obligations remain traceable here.

### Current baseline and work selection

Assessed source baseline: `475b0d60c8a05c032ec99307d75023c37e850dc7`,
[merged PR #95](https://github.com/unattributed/OSMAP/pull/95). Source inspection
finds internal `admin_access` and `admin_directory`, not an admin executable or
browser entry. The following are **retrospective index labels**, not a claim
that older work ran under this newly named sprint structure.

| Foundation record | Implementation/source delivery | Native qualification | Product/operator acceptance |
| --- | --- | --- | --- |
| ADM-F01: scoped directory projections, including OSMAP-owned naming | DELIVERED; PRs [#88](https://github.com/unattributed/OSMAP/pull/88) and [#93](https://github.com/unattributed/OSMAP/pull/93); domain/mailbox/alias/alias-domain readers | PASS for isolated obsd1 SQL projections and permission refusals; later Toronto observations do not extend every projection's scope automatically | No browser/listener or mailbox-management acceptance |
| ADM-F02: independent admin password/TOTP/session and authenticated domain read | DELIVERED; [PR #94](https://github.com/unattributed/OSMAP/pull/94) | PASS for the recorded isolated obsd1 credential/SQL/session journey | Internal backend only; no private HTTP sign-in acceptance |
| ADM-F03: Toronto credential/role compatibility | DELIVERED; PR #95; tested signed source `e799b36b7bb44a31f510a2fa3d27c697d0ff0600` | PASS for the recorded obsd1 and Toronto private fixtures; native credential, role, session and permission cases, with cleanup | No production profile, installed admin service, writer or UI acceptance |

These records supply partial Phase 0/1 evidence. **No product sprint below is
complete.** The production `/etc/osmap/admin-read-mariadb.cnf` was absent at the
last Toronto observation; the current local-UID throttle is not verified client
identity for HTTP. Read-only authority snapshots also cannot detect an external
change reversed between observations. A coordinated writer must invalidate
authority synchronously before its mutation is accepted. Preserve these gaps
and all historical failures/UNKNOWN cleanup records in successor work orders.

| Current work | Status and boundary |
| --- | --- |
| ADM-PLAN-01: execution-roadmap reconciliation | Documentation delivery complete in [PR #96](https://github.com/unattributed/OSMAP/pull/96); no product implementation started |
| ADM-PLAN-02: admin Argon2id feature assignment | Documentation-only amendment below; no product implementation started |
| Current product slice | **ADM-S04-01**, initial user enrollment: IN_PROGRESS. The owner rejected the separate invitation journey; it is disabled and its parallel private runtime is stopped. Corrected source reuses Forgot password with the administrator's offline-confirmed recovery email. Source checks and installed qualification are recorded in the correction below; the corrected first-enrollment/Inbox journey is NOT_RUN and NOT_ACCEPTED. Automatic native account registration is still unmet. Historical native passes do not qualify this changed composition. |
| Previous product slice | ADM-S01-02 DELIVERED through [PR #99](https://github.com/unattributed/OSMAP/pull/99), main `8e8294f`; bounded development/isolated mail qualification PASS; basic pages approved, text/icon refinement owner acceptance NOT_ACCEPTED |
| Earlier product slice | ADM-S01-01 DELIVERED; isolated development/mail qualification PASS; final login design owner-approved; whole-slice operator acceptance NOT_ACCEPTED |
| Selected slice / next boundary | ADM-S04-01 is explicitly approved and brought forward after ADM-S01-03: admin-TOTP pending creation with an offline-confirmed recovery email -> existing Forgot password -> six-digit email proof -> restricted password/first-TOTP enrollment -> actual native OSMAP login. Existing native registration and rollout prerequisites must be met before setup. ADM-S01-04 message delivery remains subsequent work. |
| Other product slices | NOT_STARTED, development and mail native/browser tests NOT_RUN, operator acceptance NOT_ACCEPTED |
| Admin Argon2id credential feature | SCHEDULED within **ADM-S04-02**; implementation NOT_STARTED, development/mail tests NOT_RUN, acceptance NOT_ACCEPTED; not a prerequisite for ADM-S01 |
| ADM-PLAN-03: integrated epic scope | Documentation-only integration of bootstrap, domain/virtual-address/admin management and all 18 security catalogue categories into the sprint/slice index below; no new product work is started or accepted by this amendment |

For future results maintain four separate fields per slice: **implementation**
(`NOT_STARTED`, `IN_PROGRESS`, `DELIVERED`), **development qualification**,
**mail qualification** (individual T-case result, source/environment/evidence and
limits for each), and **operator acceptance**
(`NOT_ACCEPTED` or the actual acceptance reference). The defaults above apply to
every future row until a result is recorded. Reusing a foundation PASS means only
the same tested boundary; it does not mark an entire T-case or UX slice PASS.

### Environment and dependency rules

Use the existing test plan's `E0`–`E5` environments, with actual host, database,
service namespace and source identity on every result. `E0` is local source
testing; `E1` is a disposable native installation; `E2` is an isolated existing
schema; `E3` is development integration; `E4` is production read-only preflight;
`E5` is a separately authorized production installation/cutover or smoke action.

**Mandatory acceptance target, operator direction 2026-11-17:** development must
work on `mail.blackbagsecurity.com`, also called **mail** or Toronto, as well as
the obsd1 development environment. Every functional slice needs matching
end-to-end positive and refusal evidence on mail before operator acceptance.
An obsd1 PASS, matching schema, compiled binary or isolated libtest run on mail
cannot substitute for that installed, runnable admin journey. Record the
verified mail host identity, assessed source, installed candidate digest,
private entry/configuration, data authority, native service path, actual result
and cleanup. Missing mail evidence leaves mail qualification NOT_RUN/BLOCKED and
the slice NOT_ACCEPTED; successful development may still be source-delivered.

For Sprint ADM-S01, develop in isolated E2/E3 with a synthetic seeded admin,
controlled existing domain and private factor/session/SQL/native resources.
Then demonstrate the same browser -> installed Rust service -> selected SQL
journey on mail, including native mail where that slice requires it. Early mail
qualification may use an explicitly isolated private
candidate and test authority on that host: use installed Postfix/Dovecot binaries
in separate private instances, or equivalently proven isolated configuration,
services and sockets bound only to that test authority. Public daemons keep their
existing configuration and live account authority. Inspect actual isolation
support before dependent execution. The candidate must exercise the working
product, not only a backend fixture; label the isolated authority explicitly.
This proves the declared mail
candidate journey, not integration with Toronto's live account authority.
Live-authority acceptance still requires the later authorized E5 handover and
smoke evidence; it is not an early-sprint dependency cycle.

Use focused source checks during development, reuse unchanged passing evidence,
and verify current APIs/schema/configuration rather than patch strings. Inspect
isolation facilities and actual native contracts before dependent fixtures. If
safe mail-host execution is unavailable, record the precise blocker and continue
independent source work without claiming acceptance or disrupting public mail.
This requirement does not authorize deployment, account mutation or an outage;
each future mail action still needs its bounded authorized execution recipe.

Early **existing-schema lab** work and **fresh installation** have different
dependencies. The historical Phase 1 reader/sign-in lab permits a seeded test
admin; retain its matching evidence. The selected empty-authority domain journey
must instead consume the real schema/grant and first-admin bootstrap sub-slices
below. It need not wait for every later migration/upgrade/restore obligation of
ADM-S05 to finish. This ordering uses the existing
[Path A / Path B distinction](OSMAP_ADMIN_MIGRATION_AND_ROLLBACK.md#3-two-independently-approvable-migration-paths).
It does not waive Phase 2 or UX-A4's fresh-install gate; bring their required
bootstrap implementation forward rather than substituting manual SQL seeding.

Before any lab write, prove one designated lab writer, compatible SQL/native
contracts, narrow grants, audit/revision/idempotency behaviour and recoverable
owned fixtures. No live writer credential is adopted or fenced by this roadmap.
Production Path A handover and optional Path B migration occur only in ADM-S07
after their own rehearsals and explicit authorization. Existing public Postfix,
Dovecot and MariaDB remain available; no stop/restart/reload or public
configuration change is introduced as a development-test prerequisite.

### Sprint ADM-S01 — first working mailbox-management journey

**Exit:** an admin completes the private sign-in, permitted mailbox list,
controlled creation, native authentication and Postfix-to-Dovecot delivery
journey in development and on the matching installed private candidate on mail.
The table's E1/E2/E3 targets describe development; mandatory mail qualification
above also applies to each slice. Keep ordinary OSMAP browser
access pending until owner-held TOTP enrollment; this milestone does not claim
that later enrollment journey. Sprint implementation is IN_PROGRESS with the
partial qualified/accepted scope recorded above; the complete sprint journey,
mail qualification and sprint acceptance remain incomplete.

| Slice and dependency | Target and existing UX mapping | Observable positive result | Required adverse counterpart and acceptance mapping |
| --- | --- | --- | --- |
| **ADM-S01-01 Private admin sign-in**; reuse ADM-F02/F03, inspect selected entry/config contracts | E0 -> isolated E2/E3 private HTTPS/service; UX-A0, UX-A1, UX-A2; UX-WF-01, UX-WF-15 | Password + TOTP produces a service-authorized admin session, a scope-bearing landing page and working logout; private state persists across the relevant restart | Wrong/replayed factor, mailbox cookie, forged service actor, foreign origin and untrusted client-address headers refuse. T:F-04, T:SEC-01–06, T:SEC-08, T:SEC-11, T:INT-14, T:INT-17–20, T:INT-23, T:UX-01–04, T:UX-09 |
| **ADM-S01-02 Authorized overview/domain/mailbox views and own display Settings**; depends on ADM-S01-01 | E2/E3 real reader + browser; UX-A3, UX-WF-15 | Authorized domain counts/list/detail, mailbox navigation and truthful empty/unavailable states match metadata without hash exposure; own theme/density/font and Text labels/Icons save and persist with old-record compatibility and the approved final login preserved | Domain substitution, foreign counts/details, SQL/HTML inputs, unauthorized writes and invalid preference/CSRF refuse; unavailable is not empty, and display settings confer no authority. T:F-07, T:F-30, T:F-32, T:MIG-06, T:SEC-07, T:SEC-09, T:SEC-13, T:SEC-18–21, T:UX-01–05, T:UX-07–11, T:UX-14 |
| **ADM-S01-03 Controlled mailbox creation**; depends on ADM-S01-02, ADM-S01-03a writer/native contracts and a qualified target domain (ADM-S02-01 for the fresh path) | E2/E3 designated lab writer only; UX-A5, UX-WF-04, UX-WF-14 | Browser form -> scoped Rust service -> known committed mailbox, self-delivery alias, Maildir/UID/quota projection and audited receipt; new credential generation reuses the qualified supported scheme; browser MFA stays pending | Duplicate/canonical collision, foreign domain, stale revision, missing step-up/CSRF, competing writer, invalid quota and repeated/ambiguous operation refuse or retain reconciliation state without duplicate or partial success. T:F-08–09, T:F-26, T:F-31–32, T:DB-04–10, T:DB-13–15, T:DB-19, T:SEC-07, T:SEC-09, T:SEC-11–14, T:SEC-26–28, T:UX-06–10, T:RES-03–05 |
| **ADM-S01-04 Authenticate and deliver to the created mailbox**; depends on ADM-S01-03 | E1 or E2/E3 with actual isolated Postfix/Dovecot; UX-A5 result readback, UX-A8 matching journey | Fresh native authentication succeeds; a uniquely correlated harmless local message traverses Postfix -> LMTP and is observed in the intended Maildir; the UI's reported result matches readback | Wrong/unknown credentials, unknown recipient and cross-mailbox storage access refuse; missing delivery remains FAIL/UNCERTAIN even if SMTP accepted or SQL committed. No unrestricted OSMAP session before owner MFA. T:INT-01–09, T:INT-13, T:INT-22, T:INT-26, T:SEC-30, T:UX-09–10 |

Before ADM-S01-03 specify the lab's native-auth/delivery policy while browser MFA
is pending. The first milestone permits that native test capability only in its
declared isolated policy. If native access requires owner enrollment, creation
retains a pending/inactive account, and ADM-S01-04 additionally depends on
ADM-S04-01 for that created account. Bring enrollment forward after ADM-S01-03,
before testing native access; never bypass mandatory enrollment or create a
circular prerequisite. Production policy is not changed by the lab choice.
Credential probes use a
reviewed private input method, never plaintext command arguments or logs.

### Remaining product sprints and slices

All rows retain the default NOT_STARTED / NOT_RUN / NOT_ACCEPTED state. The
mandatory mail qualification rule applies to each functional slice in addition
to the development target shown below. Technical dependencies
are conjunctive; a later sprint may reuse matching results but cannot claim its
exit from its predecessor's narrower evidence. Each row is expanded into the
current work order when selected, not into a new design document. A row marked
"scheduled after" expresses product priority rather than an additional technical
prerequisite; required safety and interface dependencies are named separately.

| Sprint and product exit | Slice / dependencies / target | Existing UX and acceptance mapping | Positive / negative product observations |
| --- | --- | --- | --- |
| **ADM-S02 Domain and mailbox management**: supported settings have proven native effects | **ADM-S02-01** domain create/edit/disable; selected next after the approved-page text/icon refinement. Requires ADM-S05-01a -> ADM-S05-02a -> ADM-S01-03a; does not depend on a pre-existing mailbox or completion of their parent journeys; E2/E3 | UX-A5; UX-WF-02, UX-WF-03; T:F-01–06, T:DB-04–07, T:INT-03, T:SEC-07, T:SEC-09, T:UX-06–10 | Empty authority reaches first admin/domain; domain form changes actual Postfix recognition and preserves dependants; duplicate, invalid or unauthorized change leaves authority intact |
| ADM-S02 | **ADM-S02-02** mailbox display/state/password operations; depends on ADM-S01-03 and verified native/session contracts; scheduled after ADM-S02-01; E2/E3 | UX-A5, UX-A6; UX-WF-08–09; T:F-13–14, T:F-16–17, T:F-26, T:INT-06, T:INT-15, T:SEC-05, T:SEC-12–15, T:RES-02, T:RES-08 | Edit/reset/disable/reactivate has documented native-auth, delivery and session effects; old password, stale step-up, forbidden target and accidental factor reactivation refuse |
| ADM-S02 | **ADM-S02-03** domain limits, mailbox quota/usage; depends on ADM-S01-03 writer and verified quota consumers; scheduled after ADM-S02-02; E2/E3 bounded data | UX-A5, UX-A7; UX-WF-06; T:F-22–23, T:INT-07, T:INT-10–11, T:UX-08–10 | Quota/limits persist with correct units and real over-limit enforcement; limit races/overflow refuse, unknown usage is displayed as unavailable |
| ADM-S02 | **ADM-S02-04 Domain DNS readiness and SPF**; after ADM-S01-04; requires ADM-S02-01 and a scoped DNS/observation contract; E2/E3 controlled DNS | UX-A5, UX-A7; UX-WF-03, UX-WF-13; T:F-36, T:SEC-09, T:SEC-18, T:SEC-28, T:INT-03, T:INT-24 | Generated MX/address/SPF records and native domain readiness agree with observed DNS; SPF scope/lookup limits and pending propagation are truthful; foreign-zone writes and unsupported publication refuse |
| ADM-S02 | **ADM-S02-05 DKIM lifecycle**; depends on ADM-S02-04 and a protected installed signer/key operation; E2/E3 | UX-A5, UX-A7; UX-WF-03, UX-WF-13, UX-WF-14; T:F-37, T:SEC-09, T:SEC-24, T:SEC-28, T:REC-15 | Real outgoing mail verifies against the selected public DNS key; generation, rotation and retirement preserve custody/continuity; missing signer, foreign domain or private-key export refuses |
| ADM-S02 | **ADM-S02-06 DMARC policy and reporting**; depends on ADM-S02-04, ADM-S02-05 and qualified receiver/report inputs; E2/E3 | UX-A5, UX-A7; UX-WF-03, UX-WF-13; T:F-38, T:SEC-18, T:SEC-21, T:SEC-28, T:RES-09 | Sender alignment/reporting and deliberate policy rollout have native observations; unsupported tags, unsafe report input and premature enforcement refuse or remain pending |
| **ADM-S03 Alias and routing administration**: required forwarding works without losing local delivery | **ADM-S03-01** alias list/create/edit/disable/remove and multi-recipient forwarding; depends on ADM-S01-03 writer and verified map/alias contracts; scheduled after ADM-S02-03; E2/E3 | UX-A3, UX-A5; UX-WF-07; T:F-18–19, T:F-21, T:INT-04–05, T:SEC-09, T:SEC-32, T:RES-01 | Native map expansion and bounded local delivery match source/destinations; loop, foreign-source edit, reserved/self-alias removal and conflicting revision refuse |
| ADM-S03 | **ADM-S03-02** installed catch-all/alias-domain variants; depends on ADM-S03-01; E2/E3 | UX-A5, UX-A7; UX-WF-07; T:F-20–21, T:F-33, T:INT-03–05 | Enabled required variants have real routing proof; collisions/unsupported variants are refused, and any nonapplicability/deferment has explicit installed-feature disposition |
| **ADM-S04 Identity and retention lifecycle**: users/admins enroll and recover safely; retirement preserves ownership | **ADM-S04-01** owner enrollment and first OSMAP login; depends on ADM-S01-03; normally scheduled here, brought forward before ADM-S01-04 if its pending-MFA policy requires; E2/E3 | UX-A6; UX-WF-05; T:F-09–12, T:F-34, T:INT-12–13, T:SEC-16–17, T:SEC-34, T:UX-12, T:RES-06–07 | Independently delivered single-use setup and user-held TOTP reach owned OSMAP Inbox; expired/replayed/cross-account setup and factor overwrite refuse |
| ADM-S04 | **ADM-S04-02** administrator enrollment, grants and own credential lifecycle, including Argon2id; depends on ADM-S01-01 and service-held writer/epoch contracts; scheduled after ADM-S04-01; E2/E3 | UX-A6; UX-WF-11, UX-WF-15; T:F-04, T:F-14, T:F-24–26, T:F-35, T:SEC-05, T:SEC-10–16, T:SEC-31, T:REC-09 | New/explicitly changed admin credentials use qualified Argon2id with legacy bcrypt verification retained; domain grants and revocation work; wrong/unsupported hashes, excessive work, privilege escalation and old-session resurrection refuse |
| ADM-S04 | **ADM-S04-03** factor rotation/revocation/recovery; depends on ADM-S04-02; E2/E3 | UX-A6; UX-WF-10; T:F-12, T:F-15, T:SEC-14–17, T:SEC-28, T:SEC-31, T:REC-05–09, T:RES-02, T:RES-06–08 | Approved transition has safe factor/replay/session readback; missing attestation, concurrent reset and interrupted follow-up stay refused or contained |
| ADM-S04 | **ADM-S04-04** mailbox/domain retirement and address reissue; depends on ADM-S02-02, ADM-S03-02 and ADM-S04-03; E1/E2 synthetic retained mail | UX-A6, UX-A7; UX-WF-12; T:F-27–29, T:DB-05, T:INT-11, T:REC-10, T:REC-19 | Staged retirement preserves mail/history and reissue gives a new owner no prior access; dependent domains, unsafe purge and inherited identity refuse |
| **ADM-S05 Existing-mailstack bootstrap and application lifecycle**: Rust admin authority reaches the working admin/user journey without PHP; OS/package installation is excluded | **ADM-S05-01** native schema/grants/migrations; requires reviewed DDL/grants/projections, actual MariaDB capabilities and restore. Bring required bootstrap portions forward before first-domain creation; retain remaining migration/upgrade/restore obligations for this slice; E1 empty disposable authority | UX-A4; T:F-01, T:F-43, T:DB-01–03, T:DB-08–11, T:DB-16–20, T:OPS-01–03, T:REC-02–04 | Vendor-initialized MariaDB plus Rust migrator produces correct native projections; populated/unknown/checksum-mismatched or interrupted schema refuses or restores |
| ADM-S05 | **ADM-S05-02** offline first admin and clean first domain/mailbox/enrollment. First-admin bootstrap portion precedes ADM-S02-01 and requires only the qualified schema/grant/factor authority, not a domain/mailbox. The complete user journey additionally depends on ADM-S01-04, ADM-S02-01, ADM-S04-01 and ADM-S04-02; E1 | UX-A4, UX-A6; UX-WF-02; T:F-02–04, T:F-08–12, T:F-35, T:INT-05–08, T:INT-12–14, T:OPS-03 | First admin exists before a mailbox; private UI then provisions/enrolls a working user; concurrent/repeated/partial bootstrap and public bootstrap route refuse |
| **ADM-S06 Replacement parity and operations**: every required feature and recovery path has a disposition and evidence | **ADM-S06-01** scoped audit/search, native CLI and installed conditional modules; depends on ADM-S02-03, ADM-S03-02 and ADM-S04-04 operations; scheduled after ADM-S05-02; E1/E2/E3 | UX-A7; UX-WF-13–15; T:F-26, T:F-30–34, T:SEC-25–28, T:UX-03–05, T:UX-13–14 | Browser and CLI reach the same scoped service; audit/journal distinguish known/uncertain effects; each required optional backend works; secret/foreign audit access and unsupported actions refuse |
| ADM-S06 | **ADM-S06-02** backup/restore, service/upgrade and continuity; depends on ADM-S06-01 and ADM-S05-02; E1/E3 | UX-A7, UX-A8; T:DB-18, T:INT-15–26, T:REC-01–20, T:OPS-01–10, T:RES-09–16 | Actual isolated restore and maintenance preserve mail, factors, writer authority and public/native journeys; stale data, unknown compatibility and split authority prevent promotion |
| ADM-S06 | **ADM-S06-04 TLS, MTA-STS and TLS reporting**; depends on ADM-S06-01 and verified certificate/policy/report consumers; E2/E3 | UX-A7, UX-A8; UX-WF-13, UX-WF-14; T:F-39, T:SEC-23, T:SEC-29, T:INT-17, T:INT-18, T:INT-22–24, T:OPS-01–10 | Actual HTTPS, IMAP/submission TLS, MTA-STS policy and bounded TLS-RPT observations match displayed status; wrong/expired certificate, broken policy fetch and hostile report refuse or report unavailable without false protection claims |
| ADM-S06 | **ADM-S06-05 DNSSEC/DANE and conditional REQUIRETLS**; depends on ADM-S02-04 and ADM-S06-04, with actual DNSSEC/SMTP capabilities; E2/E3 | UX-A7, UX-A8; UX-WF-13, UX-WF-14; T:F-40, T:SEC-09, T:SEC-29, T:INT-24, T:INT-26 | Validating DNS and actual SMTP peers prove supported TLSA/policy effects and safe rollover; bogus DNSSEC, stale TLSA and unsupported per-message enforcement refuse; any conditional nonapplicability is explicit |
| ADM-S06 | **ADM-S06-06 Message-encryption integration**; depends on ADM-S06-01 and the qualified OSMAP key/message workflow; storage recovery uses ADM-S06-02; E2/E3 owned synthetic mail | UX-A7, UX-A8; UX-WF-13, UX-WF-14; T:F-41, T:SEC-20, T:SEC-24, T:INT-20, T:INT-24, T:REC-15 | User encryption/signature and key expiry/revocation observations are truthful while admins cannot obtain private keys/mail; unsupported S/MIME or server-side storage claims remain conditional/unavailable |
| ADM-S06 | **ADM-S06-07 Mail abuse, content safety and privacy controls**; depends on ADM-S03-01, ADM-S03-02, ADM-S06-01 and installed filtering/OSMAP consumers; E2/E3 | UX-A7, UX-A8; UX-WF-13, UX-WF-14; T:F-42, T:SEC-18–21, T:SEC-28, T:INT-24, T:INT-26, T:RES-01–16 | Scoped filtering/quarantine/limits and browser privacy status have actual consumer proof; unauthorized release/forwarding, unsafe rendering and unavailable scanners never appear as a safety PASS |
| ADM-S06 | **ADM-S06-03** release-candidate end-to-end/security/accessibility and owner UAT; depends on ADM-S05-01, ADM-S05-02, ADM-S06-02, ADM-S06-04–07, ADM-S02-04–06 and all required management/lifecycle outcomes; E1/E3, E4 read-only | UX-A8 and all required UX-WF; T:UX-01–14, applicable T:SEC-01–36 and T:RES-01–16; test-plan G0–G5 | Both entry paths, applicable security catalogue controls, WSTG, direct-service negatives and accessible browser journeys pass for the exact candidate; required FAIL/NOT_RUN/UNCERTAIN blocks release; conditional omissions need accepted dispositions |
| **ADM-S07 Production replacement and retirement**: transfer one writer, prove continuity, then retire the old interface | **ADM-S07-01** Path A representative rehearsal; depends on ADM-S06-03; E2/E3 | UX-A7, UX-A8; T:MIG-01–11, T:MIG-17–18, T:DB-12, T:REC-11–12 | Legacy writer fencing, Rust writes, native mail and rollback before/after new writes are proven; stale writer connections and unreconciled rollback refuse |
| ADM-S07 | **ADM-S07-02** separately authorized Path A installation/cutover; depends on ADM-S07-01 and explicit production authority; E4 -> E5 | UX-A7, UX-A8; T:MIG-07–11, T:INT-15–26, T:PROD-01–18 | Exact installed Rust writer and private UI pass approved smoke/observation with one mail authority; any ambiguous writer, regression or unsafe rollback prevents acceptance |
| ADM-S07 | **ADM-S07-03** optional Path B data-authority migration; depends on ADM-S06-03, ADM-S05-02 and explicit Path B selection; its own E2/E3 full rehearsal before authorized E5 | UX-A4, UX-A7, UX-A8; T:MIG-12–17, T:DB-12, T:REC-02–04, T:REC-11–12, T:PROD-01–18 | Reconciled native authority and every consumer converge with preserved mail/state; deltas, interrupted switches and unsafe downgrade refuse. Path B may replace ADM-S07-02 only under an explicit approved alternate cutover; retaining the existing database is valid Path A |
| ADM-S07 | **ADM-S07-04** separately authorized retirement; depends on accepted ADM-S07-02, or selected/accepted ADM-S07-03, stable observation and retained recovery; E4 -> E5 | UX-A7, UX-A8; T:MIG-18–20, T:F-33, T:INT-24–25, T:PROD-16–18 | Required functions, jobs, grants and routes no longer depend on the old interface/PHP; only approved legacy components retire; remaining dependency, missing parity or unsafe recovery blocks retirement |

### Integrated epic sequence and bootstrap sub-slices — 2026-11-17

The current epic has **seven sprint groups and 29 top-level slices**. Preserve
the 22 original slice IDs; the seven added security slices are ADM-S02-04–06
and ADM-S06-04–07. Three named prerequisite sub-slices make the first-domain
dependency concrete without creating another bootstrap epic or test framework.
Their implementation, development/mail qualification and owner acceptance are
all NOT_STARTED / NOT_RUN / NOT_ACCEPTED at this planning checkpoint.

| Named sub-slice / parent | Dependency and target | Observable result / required refusal | Existing acceptance mapping |
| --- | --- | --- | --- |
| **ADM-S05-01a Authority initialization or adoption inspection** / ADM-S05-01 | Installed mailstack/OSMAP, actual MariaDB/socket/profile/lookup contracts; E1/E2/E3 | Actual mailstack bootstrap calls the Rust authority initializer: an empty target receives the complete reviewed schema/projections and narrow grants; populated authority is inspected/preserved, never silently reinitialized. Unknown/partial schema and rerun credential overwrite refuse or reconcile. | UX-A4; UX-WF-02; T:F-01, T:F-43, T:DB-01–03, T:DB-08–11, T:DB-16–20, T:REC-02–04 |
| **ADM-S05-02a Independent first administrator** / ADM-S05-02 | ADM-S05-01a, protected credential/factor/session stores and a qualified verifier; E1/E2/E3 | Fresh empty authority establishes one administrator and MFA locally before any domain/mailbox, then private sign-in succeeds. Existing adoption uses the reviewed existing identity/enrollment path without overwriting credentials/factors. Concurrent/repeated bootstrap or an unauthenticated public bootstrap refuses. | UX-A4, UX-A6; UX-WF-01, UX-WF-02; T:F-02–04, T:F-43, T:INT-14, T:INT-19, T:INT-20, T:SEC-01–06, T:SEC-14–17 |
| **ADM-S01-03a Shared account-writer foundation** / ADM-S01-03 | Existing qualified authority/admin, or ADM-S05-01a and ADM-S05-02a for a fresh authority; actual write/native/audit contracts; E2/E3 | A designated protected writer, current authority, narrow SQL grants, revision/idempotency and durable result/recovery contracts support mailbox creation (qualified in ADM-S01-03) and the later domain operation (ADM-S02-01). A competing writer, stale actor, duplicate request or uncertain submission refuses or remains explicitly unconfirmed. Production fencing stays in ADM-S07. | UX-A5, UX-A7; UX-WF-14, UX-WF-15; T:F-26, T:F-31, T:F-32, T:F-43, T:DB-04–15, T:DB-19, T:SEC-07, T:SEC-09, T:SEC-11–14, T:SEC-26–28, T:RES-03–05 |

Sub-slice delivery is not completion of its whole parent. In particular,
ADM-S05-02's later mailbox/enrollment journey still needs ADM-S02-01,
ADM-S01-03, ADM-S01-04 and the applicable identity slices; those outcomes are not inputs
to ADM-S05-02a. The first admin uses a currently qualified supported credential
policy; Argon2id-specific F-35 acceptance remains owned by ADM-S04-02 rather
than being falsely inferred from bootstrap or made a circular prerequisite.
T:F-43 is the joint bootstrap-to-domain integration result, completed after
ADM-S02-01. Each prerequisite closes against its own listed boundary cases and
matching stage evidence; the future whole F-43 PASS is not a dispatch condition
for implementing those prerequisites or domain creation.

Execute in this order, selecting only one concrete work order at a time:

1. Reconcile outstanding ADM-S01-02 matching mail/owner qualification without
   discarding the approved basic pages or final login.
2. For the selected first-domain outcome, execute ADM-S05-01a -> ADM-S05-02a ->
   ADM-S01-03a -> ADM-S02-01. The named prerequisites belong to that outcome.
3. Execute ADM-S01-03 controlled mailbox creation, required owner enrollment
   and ADM-S01-04 native authentication/delivery. Both fresh and existing entry
   paths must reach the working mailbox milestone.
4. Complete domain/mailbox management (ADM-S02), routing (ADM-S03), administrator
   setup/modification and identity lifecycle (ADM-S04), including the scheduled
   Argon2id feature. The virtual list must expose real mailbox and alias actions,
   not only the currently approved domain chooser.
5. Finish remaining ADM-S05 lifecycle obligations and ADM-S06 operational and
   security slices according to their actual dependencies; then ADM-S06-03
   assesses every required path/control and accepted conditional disposition.
6. ADM-S07 rehearses and separately authorizes production handover and retirement
   with preserved mail, credentials/factors and rollback. No PHP setup or old
   admin runtime remains a dependency of an accepted Rust replacement path.

Each row's E1/E2/E3 target describes development. Matching installed private
product/native/browser evidence on **mail.blackbagsecurity.com (mail)** is also
required before slice acceptance; obsd1 alone never supplies it. A conditional
control must be implemented/tested when applicable or have an explicit accepted
nonapplicability/deferment; do not move baseline controls into optional modules.
The full-stack installer and optional WireGuard client provisioning have no
active slice, dependency or acceptance requirement in this epic's current scope.

### Security catalogue to sprint/slice crosswalk

The [18-category catalogue](OSMAP_ADMIN_SECURITY_MODEL.md#131-operator-requested-security-function-catalogue--2026-11-17)
remains the control definition. This table assigns its delivery and verification
owners; all unimplemented controls retain NOT_STARTED / NOT_RUN results.

| Catalogue category | Delivery owner / supporting slice | Required acceptance cases |
| --- | --- | --- |
| Domain/routing readiness; SPF | ADM-S02-04; domain writer ADM-S02-01 | T:F-36, T:INT-03, T:INT-04, T:INT-24 |
| DKIM signing/verification | ADM-S02-05 | T:F-37, T:SEC-09, T:SEC-24, T:SEC-28 |
| DMARC policy/reporting | ADM-S02-06 | T:F-38, T:SEC-18, T:SEC-21, T:SEC-28 |
| HTTPS and native-client TLS; MTA-STS; TLS reporting | ADM-S06-04 | T:F-39, T:SEC-23, T:SEC-29, T:INT-17, T:INT-18, T:INT-22–24 |
| DNSSEC/DANE; conditional REQUIRETLS | ADM-S06-05 | T:F-40, T:INT-24, T:INT-26, T:SEC-29 |
| Forwarding authentication and conditional ARC/SRS | ADM-S03-01, ADM-S03-02; transport support ADM-S06-04 | T:F-18–21, T:F-33, T:INT-04, T:INT-05 |
| Message encryption/signatures; conditional S/MIME | ADM-S06-06, reusing the actual qualified OSMAP workflow | T:F-41, T:SEC-20, T:SEC-24, T:INT-20, T:INT-24 |
| Stored data and backup encryption | ADM-S06-02; integration ADM-S06-06 | T:REC-02–04, T:REC-15, T:DB-18, T:F-41 |
| Account authentication/MFA and Argon2id | ADM-S01-01; ADM-S04-01–03; first-admin ADM-S05-02a | T:F-02–04, T:F-09–15, T:F-35, T:F-43, T:SEC-01–06, T:SEC-14–17 |
| Administrator least privilege and safe administration | ADM-S04-02, ADM-S04-03; writer ADM-S01-03a | T:F-24–26, T:F-35, T:SEC-09–13, T:SEC-25 |
| Mail abuse/filtering; browser message safety/privacy | ADM-S06-07, reusing native filtering and OSMAP controls | T:F-42, T:SEC-18–21, T:SEC-28, T:INT-24, T:INT-26 |
| Safe changes/audit/recovery; operational assurance | ADM-S01-03a; ADM-S06-01, ADM-S06-02; cutover ADM-S07 | T:F-26, T:F-31, T:F-43, T:DB-12–15, T:DB-18, T:REC-01–20, T:OPS-01–10 |

ADM-PLAN-03 is a documentation-only incorporation based on b28a4d9. Root owns
the existing plan/test/decision updates and Git delivery; adapter_review checks
dependency order, IDs, all 18 control owners and honest statuses independently.
Minimum checks are reference resolution, unique/count-consistent cases and
slices, complete catalogue coverage, local links and normal mandatory hooks.
No host action, runtime test, new Python or new QA/status framework is needed.
Preserve historical receipts, including their former slice/case counts; this
amendment does not retroactively qualify any product or expand live authority.

### ADM-S04-02 feature — Argon2id administrator credentials

The assignment and validation paragraphs below retain the historical
ADM-PLAN-02 checkpoint. Its old slice counts/selection and chronological
bootstrap dependency are superseded by the integrated execution index above;
its Argon2id product/security obligations remain required.

The operator assigns the earlier standalone enhancement to the existing
administrator enrollment, grants and own-credential lifecycle slice. It is a
planned feature of ADM-S04-02, not a new slice, separate implementation objective
or dependency of the first mailbox-management milestone. The roadmap remains
seven product sprints and 22 slices; ADM-S01-01 remains selected next.

**Observable outcome:** a newly enrolled admin, or an admin completing an
authorized password change/reset, receives an Argon2id credential and can sign
in with password plus independent TOTP. Existing supported bcrypt admins still
sign in during mixed-scheme operation. Preserve imported credential bytes until
an explicit credential transition; read-only login does not silently write or
rehash them. Bulk migration is outside this feature and needs its own reviewed
writer/reconciliation work order.

Use an established reviewed Rust implementation or native cryptographic library,
with admin identity, factor, session and hash authority separate from mailbox
authentication. No PHP or predecessor application dependency is introduced.
Define the admin's stored encoding and supported input limits explicitly; do not
assume the mailbox's Dovecot scheme prefix is the admin encoding. The old
bcrypt-only 72-byte input guard must not truncate a newly supported Argon2id
password. Admit bounded PHC parameters before expensive allocation/work, with
target measurements and concurrency bounds on obsd1 and mail; historical single
samples or package scheme lists are not capacity qualification. Keep generic
denials, verified-client throttling and bounded unknown-user work intact.

**Acceptance mapping:** UX-A6, UX-WF-01, UX-WF-11, UX-WF-15;
T:F-04, **T:F-35**, T:SEC-02–05, T:SEC-14–15, T:SEC-21,
T:SEC-26–31, T:REC-09. P:SEC-01 and P:ADM-07–08 gain this explicit owner.
Qualify these cases as part of ADM-S04-02, using the existing service, browser
and native tests rather than another test framework:

- Positive: Argon2id enrollment and explicit credential change, password + TOTP
  sign-in, independently generated vectors and supported legacy bcrypt login.
  Persist and resume the correct state through service restart.
- Negative: wrong password/code, TOTP replay, changed final byte/codepoint of a
  long ASCII/UTF-8 password, malformed/unsupported encoding and excessive PHC
  parameters refuse without truncation, resource abuse or secret disclosure.
- Mutation/recovery: authorized change accepts the new credential, rejects the
  old credential and invalidates affected sessions through the writer/epoch
  contract. Interrupted/unknown writes stay contained and are not retried
  blindly; compatible rollback continues to verify retained Argon2id credentials.
- Targets/results: development qualification and the matching installed private
  candidate journey on **mail.blackbagsecurity.com (mail)** are both required
  before acceptance. Implementation NOT_STARTED; all feature cases NOT_RUN in
  development and on mail; operator acceptance NOT_ACCEPTED. No credentials are
  changed by this planning amendment.

Fresh-install ADM-S05-02 consumes the qualified admin credential facility from
ADM-S04-02 for first-admin creation. This dependency does not move it ahead of
ADM-S01 or authorize any live enrollment, reset, profile change or migration.

ADM-PLAN-02 scope is this feature assignment and test/lifecycle/decision
cross-references only, based on `a57edd3590972e3ec223f336a76139716e00f04c`.
`/root` owns writing/integration/Git and `/root/adapter_review` independently
checks placement, dependencies and acceptance claims. Minimum checks are mapped
case references, unchanged slice/first-milestone order, local links, historical
record preservation, documentation governance and normal hooks. One bounded
documentation amendment and normal delivery are planned; retain failures/actual
effort, and stop after two failures at a boundary for independent reassessment
without automatic allowance growth. No runtime or host qualification is run.
Documentation checks and independent placement/dependency review PASS: all 215
acceptance cases and 82 parity IDs resolve, slice count remains 22, the selected
ADM-S01-01 and historical result bytes are unchanged. Normal signed delivery
and exact remote identity are recorded in the final PR receipt; feature tests
remain NOT_RUN.

### Replacement coverage and completion accounting

This ownership map carries the whole issue #85 inventory into the sprint plan.
It is scheduling, not an assertion that any feature is installed, implemented or
excluded. Before a slice is implemented, classify its actual target's features
and expand its tests using the existing catalogue. Conditional P1/P2 items
require implementation/native proof when selected or an explicit operator
disposition; P0 obligations cannot silently move to an enhancement backlog.

| Parity IDs (P namespace) | Owning slices |
| --- | --- |
| P:DOM-01; P:USR-01; P:ADM-01–02, P:ADM-07, P:ADM-10 | ADM-S01-01–02; extend admin lifecycle in ADM-S04-02 |
| P:USR-02–03, P:USR-15; P:SEC-01, P:SEC-09–10, P:SEC-13–14; P:ADM-09, P:SYS-05 | ADM-S01-03–04 and all later mutations; admin Argon2id credentials in ADM-S04-02; audit browsing in ADM-S06-01 |
| P:DOM-02–03, P:DOM-05–09; P:USR-04–08, P:USR-10–11 | ADM-S02-01–03; conditional native support must be proven |
| P:ALS-01–11 | ADM-S03-01–02, including required reserved/self-delivery aliases |
| P:USR-09, P:USR-14; P:DOM-04; P:ADM-03–06, P:ADM-08; P:SEC-02–08 | ADM-S04-01–04; independent invitation channel and last-admin safety retained |
| P:DOM-10–12; P:USR-12–13; P:SEC-11–12; P:MAIL-01–07; P:SYS-01–04, P:SYS-07–13 | ADM-S06-01 inventories/disposes installed parity; applicable domain/transport/encryption/filtering implementation is owned by ADM-S02-04–06 and ADM-S06-04–07. SYS-08 native Rust CLI is P0 and cannot be deferred as optional; baseline catalogue controls remain required |
| P:SYS-06 | ADM-S05-01 and ADM-S06-02 restore proof; ADM-S07 rehearses the exact selected cutover/retirement state |

Appearance, forms, audit, ownership, secret handling, bounded work, no-JavaScript
use, accessibility, direct-service refusal and rollback are tested as each
relevant slice is developed. ADM-S06-03 completes the release-wide assessment;
it does not postpone known security obligations until the end. Applicable
test-plan cases outside a row's minimum mapping remain in scope. Every adopted
feature ultimately maps source/route/service -> P/U requirement -> T-case ->
exact result/evidence/defect. Acceptance IDs are reusable assertions, not a rule
to rerun every unchanged passing workflow at each slice.

### Selected next slice contract — ADM-S01-01

- **Outcome:** in the isolated private admin UI, a seeded admin signs in with
  password plus TOTP, sees its current scope, resumes the session through the
  relevant service restart, and logs out. This is the first connected component
  of ADM-S01, not an accepted mailbox-management sprint by itself.
- **Owner:** `/root` owns project/Scrum coordination, source integration, technical
  writing and the sole Git/native queue. `/root/adapter_review` supplies
  independent QA/security/delivery review when dispatched; it is not assumed
  active from a historical name. Assign implementation file ownership when the
  source work order is actually started. User UAT follows matching engineering
  and independent QA, never unfinished troubleshooting.
- **Starting source and reuse:** use the assessed baseline above, then pin the
  actual selected implementation revision. Reuse admin access, TOTP replay,
  session/epoch/private-file primitives and presentation-only OSMAP patterns.
  The public mailbox login, routes, session keys and approved images retain
  their existing contract. No new theme or general test framework.
- **Prerequisites to observe:** exact service/listener/SQL-profile ownership,
  typed peer credentials, private TLS/origin configuration, protected synthetic
  factor custody and bounded verified client identity. The existing local-UID
  throttle and trusted constructor are not HTTP authority. The current dummy
  verification uses cost 12 while supported real credentials may use cost 10;
  define and test bounded indistinguishable denial work before remote sign-in
  (T:SEC-03), without making Argon2id admin support a prerequisite. Keep session/grant
  decisions in the trusted service, with no SQL/factor privileges in the Web.
  Inspect the reachable native exec/confinement path before dependent fixtures;
  no release-string or fixed RAM-floor predicates.
- **Positive/negative tests:** run the ADM-S01-01 mapped assertions through actual
  browser -> service -> fixture authority, plus direct service denials. Include
  correct and wrong password/TOTP, replay, cookie/token crossover, forged actor,
  untrusted forwarded peer headers, expiry/logout, persistence and unavailable
  SQL/factor/service state. Show generic safe failure without false empty/success
  states or credentials in URLs/logs. Qualify actual OpenBSD custody/confinement
  and the chosen private entry; an HTML screenshot alone is insufficient.
- **Targets and effects:** E0 first, then the isolated E2/E3 development path and
  the matching installed private candidate journey on mail before acceptance.
  No production account, factor, SQL grant, public service or configuration
  mutation is admitted by this planning work. A future bounded execution recipe
  records exact target, authority, runtime/cleanup bounds and recovery before use.
- **Results/status:** implementation IN_PROGRESS; mapped integration/native/
  browser cases NOT_RUN separately in development and on mail; operator
  acceptance NOT_ACCEPTED. No new admin UI is
  running. Future known gaps name a concrete owner/next action without hiding
  completed useful work or marking a declaration as a result.

### ADM-S01-01 implementation work order — 2026-11-17

The operator starts Sprint ADM-S01 with its first slice. Source baseline is
`ed816927cd8ea8c6dead1afb1f9d14655364d3fe`. At the start, implementation was
IN_PROGRESS and native/browser cases were NOT_RUN. The qualified result below
updates those engineering fields; operator acceptance remains NOT_ACCEPTED. Earlier planning-only restrictions
describe those completed documentation changes, not a renewed source hold.

**One observable outcome:** a real browser reaches private HTTPS, submits a
seeded synthetic admin password and TOTP, sees server-derived current scope,
resumes after the trusted service restarts and logs out. Complete this actual
browser -> private web -> trusted service -> isolated SQL/factor/session path
on obsd1 development and mail separately; no result substitutes for the other.

**Owners/files:** `/root` is accountable for project/Scrum coordination, backend
changes, native confinement, integration, documentation and the sole Git/host
queue. `/root/admin_ui_engineer` owns the new presentation module and its focused
tests; `/root/admin_transport_engineer` owns the bounded typed transport/config
and tests under the agreed interface. They are activated only by concrete
dispatch. `/root/adapter_review` independently reviews source, prerequisites,
functional evidence and delivery; it does not approve its own code. Preserve
the current public OSMAP UI/routes/session authority and unrelated state.

**Inspected prerequisites:** fresh SSH readback identifies
`obsd1.blackbagsecurity.com` and `mail.blackbagsecurity.com`, native OpenBSD,
MariaDB/Python/Cargo/nginx/OpenSSL/user-management tools and noninteractive
privileged setup. Both production admin SQL profiles are absent. Toronto's
build-user hard data limit needs the previously demonstrated privileged limit
setup followed by dropping groups/GID/UID before Cargo. Observed versions/limits
are evidence, not release-string or fixed-free-memory predicates. Reuse the
reviewed schema/query and private fixture setup contracts from ADM-F02/F03;
verify current native command, socket, owner/mode and parser/consumer contracts
before dependent execution. Python Playwright is absent from the default system
interpreter; use or prepare an isolated test environment with the existing UX
workflow style and installed browser, not a new product dependency/framework.

**Smallest composition:** a separate `osmap-admin` Rust entry has private web
and trusted-service modes. Reuse the bounded HTTP/form parser, escaping/CSP/CSS,
private record/session/TOTP/throttle code and deadline-framed Unix transport.
Private nginx terminates TLS and connects only to a custody-checked web Unix
socket; web authenticates the proxy peer UID before accepting its overwritten
single-client-address header. Never inherit the public webmail parser's generic
loopback forwarded-header trust. Web and service have separate OS identities,
while the isolated nginx and Web share one dedicated unprivileged Web UID;
configuration rejects a different proxy UID because its socket is private 0600.
Neither Web inputs nor cookies can assert grants or a serialized session.
The service authenticates Web's Unix UID, owns per-login/per-peer throttling and one bounded global worker,
resolves current scope on every landing/resume, and validates bounded fixed
login/scope/logout operations. HTTP cookies are admin-only, Secure, HttpOnly and
SameSite with exact Host/Origin checks and login/logout CSRF. No JS dependency,
mailbox route, SQL privilege or protected factor access is given to Web.

**Changed backend boundary:** add current-scope session readback, trusted peer
context and bounded equivalent bcrypt work across supported costs for known and
unknown users. Keep stored credentials unchanged. The isolated candidate uses
a protected operator/service-selected SQL profile and database through the same
fixed queries/command runner; a request cannot choose SQL, programs or paths.
The narrow SQL and native execution guard changes require exact independent
source review. OpenBSD service/web sealing must match the actually reachable
program/dependency/socket paths; qualification is withheld until those paths
and UID separation are exercised natively.

**Progressive checks:** establish a distinguishing RED boundary first; use
focused Rust HTTP/RPC/session/peer/CSRF/denial-work tests, then one exact-source
native browser journey per host. Positive sign-in/scope/persistence/logout and
negative wrong/replayed factor, mailbox-cookie crossover, forged actor/peer/
forwarded headers, foreign Host/Origin, CSRF, expiry, changed grants and missing
SQL/factor/service are the mapped S01-01 cases. Inspect actual installed custody
and confinement as well as UI results. Diagnostics export only fixed source
codes/outcomes/stream counts; never retain credentials, factor codes, bearer or
CSRF values in public evidence. Keep failed owned resources and actionable
private diagnostics until durable sanitized readback/hash allows exact cleanup.

**Execution and preservation:** use independent private SQL/nginx/socket/state
instances and temporary role identities only. No public service is stopped,
restarted, reloaded or reconfigured, no live account/factor or production grant
changes, and no fixture reaches a reference replica. Root owns setup/cleanup;
source review and verified Shopkeeper checkpoint precede native transfer. Each
native compile is bounded to 600 seconds, each focused probe to 120 seconds and
each browser journey to 300 seconds, with a finite 120-second disposition phase.
The cumulative first investigation checkpoint is four hours, retaining actual
elapsed work, UNKNOWN preparation cost and every failure across workers; no
automatic allowance increase. Two failures at one boundary stop retries for
combined independent reassessment. Authority does not expire by an invented
ledger clock. Run full suites only through normal delivery gates after focused
passes; verify remote exact-head equality and protected integration. Retained
artifacts use `/home/foo/Downloads/osmap-admin-s01/` throughout this sprint.

**Progressive source results:** the first distinguishing scope/resume test was
RED because the backend operation did not exist. Two subsequent compilation
attempts exposed UI formatting and byte-slice helper integration errors. Their
combined independent reassessment approved the exact source corrections before
the next compile; no test or native execution occurred in those failures. The
first executed focused suite compiled and passed 66 cases, with two failures and
12 native-only cases ignored. One failure exposed the real parser/router
contract: `/admin/` is not normalized. Reuse the parser unchanged and make the
landing path `/admin`; a distinguishing real-parser regression checks both
paths. The other failure counted shared CSS rather than the actual navigation;
scope the assertion to navigation markup. These are retained source results,
not native qualification. Focused logs remain under the sprint artifact root;
native/browser results and independent final review are still outstanding.

The corrected focused run passes **73 cases, zero failures, 12 native-only
cases ignored**, in 11.37 seconds. Strict non-test/all-target Clippy passes in
13.37 seconds after promoting the existing effective-GID getter from test-only
to Unix runtime visibility. Preserve the intermediate compilation failure from
an overlapping transport edit and the non-test getter refusal separately; an
independent combined reassessment approved those bounded corrections. Static
guard refusals exposed inert forbidden-option and program-path test literals;
retain them and change only those counterexample values, preserving strict
guards. Reviewed source has no remaining executable-source blocker. Added two
OpenBSD-only ignored tests apply the exact Web/service seals in separate
processes and check allowed namespace access against unrelated readable paths;
their native results remain NOT_RUN at this source checkpoint.

The first signed source checkpoint is
`f027e0626d412111922001b13fae9bf44cdd1285`. Its normal pre-push hook refused a
formatting difference in the last inert test-fixture edit; no remote update
occurred. Apply the formatter and regenerate inventory in a separate signed
follow-up, preserving the original checkpoint and refusal. Native dispatch
remains pending the corrected exact source/archive admission and reviewed
private recipes. This formatting refusal is not a native/product failure.

The corrected checkpoint `d525058370083788df4c30c9faaa58a317566336` passed
formatting; its second normal push stopped at the existing V15 manifest-digest
gate. The new binary target did not change dependencies, features or lockfile.
Refresh only the existing manifest baseline and target review, after combined
independent reassessment of both hook refusals. The exact V15 gate and regression
pass. One signed metadata follow-up and normal push retry are approved; no
hook bypass, history rewrite or allowance reset follows. Native candidate builds
assess d525's exact executable source; subsequent metadata/evidence-only commits
must prove the executable/configuration sources remain byte-identical before
reusing those results.

**Native progression and retained failures:** d525 builds on obsd1 (executable
61.856 s; selected-test binary 93.078 s) and mail (executable 198.326 s after a
locked cache fetch; selected-test binary 300.808 s). Mail's first offline attempt
refused a missing local `ammonia` index entry before compilation; its original
receipt/log remain separate from the passing retry. The first private obsd1
setup exposed the installed help command's successful-capability exit status 1,
then inherited SQL child NOFILE 128 versus the working operator profile 512.
The remaining read-only system-table refusal was retained rather than attributed
uniquely to that warning. A narrow OpenBSD discriminator proved `getcwd` failed
under the root-owned 0711 ancestor and passed under protected 0755; fresh SQL
initialization then passed. Original failed data and probe results were archived,
read back and hashed before exact owned principal/namespace disposition.

Reuse the now-working isolated SQL, profiles and certificate. Private nginx needs
all compiled-module temporary directories placed under its own prefix; repair
that boundary without recreating the database. Mail's existing loopback 18443
listener remains untouched: use verified-free remote 18445 with local 18443
forwarded to it, preserving the selected browser Host/origin. These are observed
candidate contracts, not host-version or blanket resource-floor requirements.

The first actual Rust service start reached its locked native READY boundary.
The plain-pipe controller then received stdin EOF and requested shutdown; the
service exited 1 with its owned socket retained. The specific leaf's `rw` unveil
rule overrides its parent's `rwc` and lacks removal authority. Correct only the
service-owned leaf to `rwc`, keep peer/SQL socket grants unchanged, distinguish
stat/unlink diagnostics, and add a native disposable-endpoint removal regression
under the exact seal. Web intentionally retains its endpoint for root disposition;
the controller must observe that actual contract and must not require an invented
Web READY string. A local PTY producer/consumer check passes for the next bounded
interactive controller. No authentication, browser or product acceptance result
is promoted by these startup/build/prerequisite observations.

The corrected obsd1 source `cca12d172a56480cdda6e1c6e428e5b0b8a456cb`
builds its executable in 40.417 s and selected-test binary in 94.104 s. Both
native confinement probes pass, including removal of the disposable service
endpoint. Controlled Web/service shutdown returns zero, and the service removes
its own endpoint. The retained Web endpoint is matched to its born identity;
its metadata is durably read back and hashed before exact passive removal.
These are native lifecycle results, not an authenticated browser PASS.

Two custom mail source transfers stop at 60/120 s; standard SFTP also stops at
120 s with a retained partial file. Fresh readback proves its 9,139,200-byte
prefix matches the source. The reason for the earlier transport completion
failures is unobserved; no bandwidth or EOF cause is asserted. Independent
combined reassessment approves a prefix-verified bounded resume, but that resume
is not run: the browser finding below requires newer source. Preserve the
partial and all failures. For the next signed source, archive the complete
build inputs (`Cargo.toml`, `Cargo.lock`, `build.rs`, `rust-toolchain.toml`,
`LICENSE`, `src`, `maint`, `tests`), omitting unrelated delivery documents and
images. The sizing archive is 3,822,408 bytes; all 218 literal includes resolve
inside it. Keep exact commit/archive admission and extracted-file verification.

The first obsd1 browser attempt proves strict TLS and foreign-origin rejection,
then stops before authentication at the Host probe. Node's overridden Host does
not supply an HTTP observation. A changed probe keeps the trusted TLS identity,
sends a credential-free foreign HTTP Host and observes native HTTP 403. The
second browser attempt then stops at normal form submission: wrong-password
submission returns 403 before its expected authentication-denial result.
A secret-free actual-browser discriminator proves `no-referrer` sends opaque
`Origin: null`, whereas `same-origin` sends the required origin. Its first
fixture failure and the passing RED/GREEN observations are retained separately.
Change only admin document/redirect referrer policy; preserve exact-origin
admission, including explicit null-origin refusal before RPC. Browser sign-in,
restart and logout remain unqualified until the corrected path runs on each
host. No accepted TOTP or session is claimed from these stopped attempts.

### ADM-S01-01 qualified result — 2026-11-17

**Implementation DELIVERED; isolated development qualification PASS; isolated
mail qualification PASS; operator acceptance NOT_ACCEPTED.** Assessed product
source is signed `e685f9080dede9acc6e1bcd927ba23135a9965a0`. This is a working
private sign-in/scope/logout slice, not completion of Sprint ADM-S01, an installed
production admin service, mailbox management or predecessor retirement.

The final native executable is 5,230,832 bytes, SHA-256
`da45db21021a10fe3a164c9d516ff3b1545ef4ef684f011005c028968e0f4627`.
Its compiled revision and root-owned single-link installed bytes are verified on
both hosts. The prior source builds independently on both hosts with identical
executable/test hashes. The final one-line Rust brand-layout change builds on
obsd1 in 39.21 s; copy that exact artifact to mail and qualify its actual native
execution. No host-version assumption or additional native test build substitutes
for the separately observed mail journey. Unchanged confinement/backend evidence
is reused with its actual source identity.

| Observed boundary | obsd1 | mail.blackbagsecurity.com |
| --- | --- | --- |
| Actual browser: private TLS -> password/TOTP -> authorized scope | PASS | PASS |
| Service restart preserves session; logout rejects old session | PASS | PASS |
| Foreign Host/Origin, CSRF and mailbox-cookie crossover | PASS | PASS |
| Generic wrong-password/wrong-TOTP denial and accepted-factor replay refusal | PASS | PASS |
| Secure admin cookie policy; readable current scope and full brand at 1440 px | PASS | PASS |
| Wrong Unix UID and unknown actor fields | PASS | PASS |
| Grant revoke/restore and factor loss/restore do not revive old authority | PASS | PASS |
| SQL loss returns unavailable; restoration preserves the eligible session | PASS | PASS |
| Matching unchanged native confinement probes | PASS | PASS |
| Product shutdown, passive endpoint disposition and private fixture cleanup | PASS | PASS |

Each final browser result contains 12 checks: obsd1 41.622 s, mail 66.136 s.
Both screenshots have SHA-256
`a9bb342b8dd710e5ef1508c4ed75236e9a861993e9d4744f4ad01142c869fed6`.
Independent review verifies the rendered full brand after the first screenshot
exposed clipping under the rail; a single admin-only Rust style correction fixes
it. Each native authority/refusal result has six passing checks, confirmed
restoration of its own effects and no retained uncertainty. Obsd1's earlier
passing refusal result is reused across that presentation-only change. The
unavailable-service HTTP branch and expiry behavior also have focused Rust
regressions; the table does not claim every negative permutation was repeated
through the installed browser or that the full WSTG/release programme passed.

Browser result hashes are respectively
`9ccfe6b82f8bedb091da06d242b515ac96d8377914dd8ee365882095fb31c44a`
and `72f90a8bf856df0aa14183837f0066f5f7297d815b4d45e307b95095f3286efe`.
Both fixed native-refusal outputs hash to
`728bd767ab5f970df92652a6c8684e09305ce015a544dd7a8a7aa5fe7b8e3395`.
Raw evidence stays private under `Downloads/osmap-admin-s01/`.

Preserve all earlier failures. Further local carrier syntax/stage refusals occur
before transfer; native `timeout` refuses session-leader process-group setup
before compilation, then works as a shell child. A raw executable transfer stops
at 120 s; a fresh standard gzip/SCP transfer succeeds and the decompressed bytes
match the signed-source artifact. No failed partial is executed. After the
operator's simplification direction, write no additional Python: keep product
changes in Rust and reuse existing tools plus standard native commands.

The cleanup helper refuses its nginx process-title comparison before daemon
mutation because native `ps` appends `(nginx)`. Preserve that refusal, then use
fresh exact private UID/argv/pidfile checks and native nginx quit. Verify the
private SQL datadir/socket/networking identity before shutdown. Both hosts prove
private process/endpoint absence, exact temporary principal/group removal and
root-only retained namespace custody after physical tree checks. The working
data/source namespaces remain retained; they are not claimed deleted. Evidence
archives are read back and hashed independently. Toronto's public Dovecot,
Postfix, MariaDB and nginx checks remain PASS, matching the pre-action baseline;
no public service/configuration, live account or factor is changed.

The first retained artifact is at 18:48 UTC; both functional journeys, refusal
cases and owned fixture disposition finish by 22:46 UTC. Earlier preparation
cost is UNKNOWN and all attempts remain cumulative. The four-hour investigation
checkpoint closes with no further product investigation or allowance increase;
only bounded evidence, review and mandatory signed Git delivery remain. Normal
delivery hooks are separate from native product qualification. ADM-S01-02 is
the next selected slice and remains NOT_STARTED; the first mailbox-management
milestone and the other three ADM-S01 slices remain incomplete.

### ADM-S01-02 lean implementation work order — 2026-11-17

**Focused resumption — 2026-11-17:** the operator directs completion of this
slice, not bootstrap/domain writers. Baseline a0f1c35; reuse the independently
reviewed ba360305 product and obsd1 binary SHA-256
`879d1bec355584a850f995ab67565de0a443410dc92e8f1029297f4d94d8f494`.
Root owns the sole host/Git queue and result writing; adapter_review independently
checks dispatch and results. Required exit is the installed private mail browser
journey through overview/counts, domain/mailbox list/filter/detail and persistent
Text labels/Icons, with current-scope, private-reader-loss, direct-write and
preference/CSRF refusals. Reuse matching obsd1 and S01-01 evidence; no full repeat
of authentication tests, public mail changes, new Python or test framework.

Read-only preflight verifies mail.blackbagsecurity.com through the established
216.128.179.75 route, noninteractive privilege and running public daemons. The
earlier `/var/osmap-adm-s01` namespace is root-sealed with its temporary roles
removed: preserve it. Use one fresh exact-owned `/var/osmap-adm-s01-02` fixture,
socket-only private SQL and loopback nginx, after actual utility/listener/schema/
reader-grant admission and independent dispatch review. The same reviewed
binary is copied with hash/version admission; do not rebuild unchanged code.
Verify the TLS Host/Origin/proxy path before browser use; a certificate warning
requires operator handling. Mutations apply only to fixture records/resources.
Individual setup actions retain the existing 120-second bound; browser actions
retain 300 seconds plus finite cleanup. Preserve cumulative history/UNKNOWN
costs and measure new elapsed work; this resumption does not erase or replenish
past effort. Two failures at one boundary stop retries for independent
reassessment. Retain bounded private diagnostics before cleanup; uncertain owned
state remains retained. The only final human judgment outstanding for the new
presentation is separate from its agent-owned qualification. The later final
login approval preserves the approved design, without retroactively claiming an
owner repetition of every S01-01 journey. Delivery uses existing signed hooks,
ordinary push and fresh remote equality; mail results remain NOT_RUN until run.

The operator subsequently retains obsd1 as the development host and browser
address, rejecting loopback URLs. Preserve normal obsd1 application/backend
state. For the bounded mail qualification only, use the existing trusted
`https://obsd1.blackbagsecurity.com/admin` entry with its source-IP restriction,
temporarily selecting the isolated mail upstream through SSH. Admit and retain
the exact old route/public upstream certificate, test the new upstream before
switching, and restore/read back the original route after the browser journey.
Only the obsd1 admin frontend routing changes temporarily; no public mail daemon,
mail authority, new exposed port or firewall rule changes. Keep the isolated mail
Web's exact origin/Host policy aligned with that hostname. A synthetic domain
description distinguishes mail data from the unchanged obsd1 fixture. This is
mail qualification through the obsd1 entry, not relocation of development or a
live-authority cutover. Independent review covers this concrete route and its
finite restoration before dispatch.

**Mail progression checkpoint — 2026-11-17:** the unchanged reviewed binary is
installed in the separate private mail namespace; its actual service/Web/SQL
path signs in and returns the scoped overview (two domains, 12 mailboxes, two
forwarding sources), domain detail, mailbox page/filter/detail, empty 200 and
foreign 404. Restricted password-column SELECT and UPDATE refuse. A well-formed
mailbox POST returns 405; malformed preferences/CSRF refuse, and a wrong
well-shaped CSRF returns denial while a subsequent eligible GET is 200 with
unchanged preferences. These are native HTTP results, not browser acceptance.

Private reader SELECT loss reaches the expected 503. Its first restoration
consumer incorrectly compares serialized SHOW GRANTS row order, reports
`original_status=1 cleanup=UNCONFIRMED authority=UNKNOWN`, and is preserved.
Independent readback compares the complete unordered grant lines and proves
equality; a later eligible mailbox GET 200 and active-grant count one reconcile
restoration. Do not repeat that REVOKE. The separate remaining fixture domain
grant-loss operation returns 303, restores the exact grant with count readback,
and reports original status zero with no pending recovery.

The loopback browser entry stops at its certificate warning. The operator
instead requires the existing obsd1 hostname/development host. A reviewed
private mail-origin change fails at its bundled installation phase; the exact
failed command/first HTTP status is UNKNOWN because that invocation did not
retain them. Preserve this missing observation and failed receipt. Later
config/process/socket readback and strict-TLS Host=obsd1 login 200 establish
current private availability only. No stop/install/reload repeat or obsd1 route
switch occurs. The original obsd1 route hash is unchanged; admin/public login
HTTP 200 and public mail daemon checks pass. Private q2 service/Web/nginx/SQL and
their isolated authority remain intentionally ACTIVE pending the next scope
decision; no final cleanup or browser PASS is claimed.

The operator observes that the pages remain shallow: Overview/Domains largely
share a read-only list, and missing writers are still missing. No presentation
work is added. A production read-only preflight observes five domain records,
14 mailbox records and 49 alias records, plus the six required mailbox columns;
alias rows are not forwarding-source counts. No production write, new grant,
credential/factor change or deployment occurs. The question whether to use real
production metadata through obsd1 or deploy production administration remains
pending. The current executor shares one protected database/profile for admin
authority and directory reads; do not substitute production credentials or grant
development identities production authority implicitly. Mail browser qualification
and full ADM-S01-02 completion remain pending. Retain the private evidence under
the existing sprint root, with regular owner-only single-link artifacts. The
first retained artifact is 13:54:58 UTC; observation through 14:32:33 UTC is
37 minutes 35 seconds, with earlier preparation cost UNKNOWN and prior history
unchanged. This checkpoint is source/evidence preservation, not product closure.

**Isolated mail qualification result — 2026-11-17:** the operator clarifies that
the goal is confidence in later deployment on mail and follows the recommendation
to retain obsd1 development with isolated qualification on mail. A permanent
production-data connection is not added to development. The same ba360305 source
and `879d1bec...` binary run on mail; application/build inputs are unchanged
through the documentation checkpoints. Read-only production preflight confirms
all 29 source-consumed columns across admin, grants, domains, mailboxes and aliases.
It does not qualify production service grants, identities, configuration or writes.

The actual browser uses the trusted canonical obsd1 HTTPS entry, temporarily
forwarded only for qualification to the mail Web/service/private SQL stack. It
observes the scoped 2/12/2 overview, unique mail-host domain description, domain
metadata, mailbox pages 1/2, user11 filtering/quota sort and stable opaque detail.
Two direct navigation-completion waits time out; immediate later accessibility
readbacks independently show the correct empty-domain and foreign-not-found
pages. Preserve both helper failures, not retroactive successful navigation calls.
Independent combined reassessment admits click navigation without replaying GETs.

The next visible link returns 502. Stop without credential retry and restore the
original obsd1 route. The reverse SSH connection reports that its local target
is absent; the original local forward has exited zero without an observed cause.
The edge reports a closed upstream TLS handshake. Preserve the 502 and unknown
forward-exit cause separately. One reviewed native managed SSH replacement passes
master/listener/pinned-TLS checks; first-cycle route evidence is archived and
independently read back before guarded resumption. No fixture or allowance resets.

Resume only the remaining boundary: sign in, open Settings, observe Text labels,
save Icons with Appearance saved, log out, sign in with a fresh factor, and read
Icons still selected in Settings. Final logout returns the approved login.
Native private preference readback is icons/system/comfortable/medium. Reuse the
matching obsd1 keyboard/touch-emulation and unchanged authentication/confinement
evidence rather than repeating them on mail. Nine retained images and their
portable hash manifest, the native archive and actual result receive independent
review. Physical-device UAT and a release-wide security pass are not inferred.

Restore and read back the exact original obsd1 route, stop only the private q2
Web/service/nginx/SQL, verify process/socket absence, remove its exact temporary
principals and seal its retained namespace under root. The native evidence
archive is read back with SHA-256
`ff3d7f7f76620b18c354f967c3fe2be2a0f00954d6efb3042f11947b04126b18`
before endpoint/principal disposition. Close both owned forwards and verify their
listeners absent. With the mail candidate stopped, the normal obsd1 admin/public
login routes still return 200; public mail daemons remain running. Cleanup PASS
establishes only that disposition, separately from the observed product results.

Engineering and bounded isolated mail qualification are DELIVERED/PASS. Preserve
basic-page/final-login approval; text/icon owner acceptance is still pending.
Source delivery/protected integration use the normal exact-head checks and are
recorded in the PR receipt. No domain/mailbox writer, bootstrap, production
deployment or full-replacement claim follows. The selected next product journey
remains first-domain creation through its three named bootstrap/writer prerequisites.

The operator applies the S01 lessons and authorizes the next mailbox-list slice
(called “adm-s02” in chat). Baseline is signed main
`f7e7b87197013aa41a00a920cf60a00b317dd77a`. One observable outcome:
private sign-in -> choose an authorized domain -> bounded mailbox list,
filter/sort/page and stable detail -> truthful empty/missing/unavailable states.
Map UX-A3, F-07/F-30/F-32 and the S01-02 security/integration/UX IDs above.
Display only observed configured metadata; native auth/delivery, usage, display
name and MFA observations absent from this reader remain explicitly unknown.

Reuse the existing scoped directory SELECT, admin sessions/current authority,
typed socket, strict HTTP and OSMAP presentation. Each operation validates the
supplied session context and current grants before directory reads. Filter and
paginate the complete existing bounded inventory (maximum 100 rows, ten per
page); excess capacity is an explicit refusal, never a truncated or empty list.
Detail IDs are stable username digests, reselected only within current scope.
Omit maildir, credentials and hashes from transport/browser. Keep fixed directory
SQL output at its existing 64 KiB bound, identity-query/stdin bounds at 16 KiB
and RPC at 8 KiB. No writer, enrollment, new dependency, Python or general QA
framework is introduced.

Root owns implementation, writing and the sole Git/host queue; adapter_review
independently reviews the candidate and observed results. Establish one RED
backend test using a non-default live session context. Minimum changed-boundary
checks: scoped projection/page/filter/detail, foreign and revoked scope, missing
versus empty/unavailable/capacity, maximum RPC shape, escaped inputs and direct
write refusal. Use focused existing Rust suites, then a complete browser journey
on obsd1 before promoting the reviewed byte-identical candidate to mail. Check
visual layout in that journey. Reuse unchanged auth/confinement evidence.

Before native use verify actual mailbox columns and restricted SELECT grants
in the new isolated fixture. Preserve the old root-only retained fixture by
exact ownership before preparing fresh disposable SQL/roles/private nginx;
use demonstrated existing tools and standard commands. Keep all retained work
under `Downloads/osmap-admin-s01/slice02/`. No public mail service/configuration,
production account or factor changes are authorized. Record actual results and
failures here, not another planning document. Native compile bounds remain
600 s, fixture actions 120 s and browser journey 300 s plus finite cleanup.
Initial investigation checkpoint: two hours, retaining measured and UNKNOWN
cost across attempts; no automatic allowance growth or clock-based authority
expiry. Two failures at a boundary require combined independent reassessment.
Finish independent result review, normal signed hooks/push, exact remote parity
and protected integration. Operator acceptance remains a separate result.

Source progression: the new live-context mailbox test is RED on the prior
backend and GREEN after composition. The first integrated focused run passes
76 cases and exposes three test-assumption failures: two retained UI checks ban
the newly implemented route, and one incorrectly assumes the existing bearer
session is IP-bound. Combined independent reassessment approves correcting those
expectations without changing authentication policy. Review also removes an
unverified quota-byte label. The next focused run passes 82 cases, zero failures,
with 12 native-only cases ignored. Maximum DTO serialization fits the existing
8 KiB frame. Source review GO admits only the exact new Rust source digest in
the existing guard; no Python logic or framework is added.

The reviewed candidate is Shopkeeper-signed
`428c9e0434ff6098c975a0ea2ec9ed305243aeab`, preserved on the ordinary topic
branch with the mandatory pre-push `make security-check` PASS and fresh exact
remote equality (zero ahead/behind). Draft [PR #99](https://github.com/unattributed/OSMAP/pull/99)
remains unmerged. The obsd1 executable reports that revision, SHA-256
`2188257edd7ec357c26fa779499451b18ec65f4731f2152457bfeca92c15da4c`;
the bounded native binary build passes in 40.63 seconds. No full native test
library build is introduced.

The actual private SQL contract admits the required mailbox projection and
refuses password-column SELECT and UPDATE. Native HTTPS requests through the
installed Web/service/SQL path observe sign-in, the 12-row scoped inventory,
ten-row pagination, filtering, quota sorting, opaque detail, an authorized empty
domain and uniform foreign-domain 404. Responses exclude the seeded credential
and maildir. Unauthenticated/invalid sessions redirect to sign-in, duplicate
query keys refuse and a well-formed direct write returns 405. These are native
HTTP observations, not browser acceptance or complete native qualification.
Unchanged authentication and confinement evidence remains reused within its
original scope; the new mailbox backend-loss and live grant-revocation cases
remain unobserved natively.

The 900-second SSH forward expires before two later requests, which return
transport failure without reaching the product. Preserve that failure;
independent reassessment permits one 30-minute replacement forward, with no
cost or authority reset. An expired idle session redirects before a fresh,
successful synthetic login. The browser stops at its private self-signed TLS
warning. Computer-use policy requires the operator to handle that warning;
the handoff is pending. Do not bypass it or infer a browser PASS from curl.
Mail promotion remains NOT_RUN until the planned obsd1 browser journey passes.

At the handoff observation (2026-11-17 03:23:45 UTC), the fresh isolated obsd1
fixture `/var/osmap-adm-s01` (device 1028, inode 3836160) remains ACTIVE, including
its private SQL, loopback TLS proxy and Rust service/Web roles. Cleanup is
NOT_RUN; no cleanup PASS is claimed. The previous root-only fixture is preserved
as `/var/osmap-adm-s01-retained-20261117`. Retained private results are under
`Downloads/osmap-admin-s01/slice02/`. Normal obsd1 Dovecot, Postfix, MariaDB and
nginx health checks pass; public configuration/accounts/factors are unchanged.
The replacement local forward expires around 03:46 UTC; that is a transport
limit, not expiration of operator authority. Preserve measured build/test times,
the transport failure and UNKNOWN total effort; do not replenish the two-hour
initial investigation checkpoint. Browser, mail, final cleanup and operator
acceptance remain outstanding.

Operator routing correction, 2026-11-17: the expired workstation forward makes
the loopback handoff unavailable. The operator requests the real private
candidate at `https://obsd1.blackbagsecurity.com/admin/login`. Reuse the existing
valid hostname certificate and nginx listener, adding only an `/admin` route
restricted to the workstation's verified LAN address. Resolve that hostname
directly to obsd1 on this workstation so access does not depend on a timed
forward or admit the router's indistinguishable NAT clients. Preserve the exact
prior workstation resolution and nginx/Web configurations before changing them.
Root owns dispatch; adapter_review independently reviews configuration and the
result. The existing Rust candidate and isolated SQL authority stay unchanged.

Update the private Web origin and fixed proxy Host together; retain verified TLS
on the loopback upstream, existing proxy UID/socket custody and header rewriting.
The inner proxy continues to report its actual loopback TLS peer: this isolated
route does not qualify end-client address propagation or production throttling.
Check nginx syntax before its reload, valid hostname TLS/login, a refused
non-admitted route, exact Origin handling and the ordinary frontend/mail health.
Then continue the actual browser mailbox journey. Only the OSMAP Web process and
nginx configuration may restart/reload for this correction; no public Postfix,
Dovecot or MariaDB change. Preserve the unreachable-forward result and the
unsupported native `openssl x509 -ext` inspection option as preparation failures;
the supported certificate query succeeds without any certificate change.
Each configuration action remains bounded to 120 seconds with exact backups and
rollback; two failures at the same boundary stop for combined reassessment.
This correction changes routing, not authority, cumulative effort or acceptance.

The hostname route now returns the real browser sign-in without a certificate
warning. Non-admitted NAT clients, including spoofed client-address headers,
receive 403; the alternate Host receives 421. Ordinary frontend login remains
200 and all normal mail-service checks pass. Browser password/TOTP, authorized
inventory, pagination, filter, quota sorting, detail, empty and foreign-domain
refusal are observed. The narrow-rail visual check reveals clipped bare labels;
reuse the existing icon/presentation-label markup in `admin_ui.rs`, run its
existing focused tests and qualify the changed rendering natively. No new test
scaffolding, authentication change or blanket native-test rebuild is needed.

Preserve two visual failures: the initial bare labels clip at 744 pixels, and
candidate `91102357` wraps them into narrow fragments. Stop further visual
retries for combined independent reassessment. The actual shared CSS requires
the existing main application's `rail-disclosure`, `shell-icon` and `rail-label`
structure; presentation labels alone do not supply that contract. Independent
reassessment approves reusing the fixed icon helper and native disclosure in
an admin-only rail. Qualify collapsed/expanded navigation at 744 and 360 pixels;
do not infer its PASS from source. This does not reset failures or cumulative
effort. Candidate 91102357's Cargo output reports a 39.34-second successful
build, while its launcher later returns 143 with no termination-source
observation. Retain that UNKNOWN transport cause; fresh revision/hash readback
confirms the resulting artifact without another build attempt.

The rail source change passes seven UI tests and strict Clippy. Its first V10
consumer check refuses source-digest drift; regenerate through the existing
producer and verify the real consumer before native dispatch. Commit e2a3c2e0's
body incorrectly records that check as passing; retain this correction and the
actual failed result rather than rewriting the signed commit. No native build
uses the stale inventory.

The corrected shared rail at `088d3f23` builds natively in 39.91 seconds,
launcher exit 0, executable SHA-256
`adb0823e624db93020ced98c40d22f07c60242b84b103b93e35d7c89ec107dca`.
The actual browser shows usable collapsed icons and readable expanded labels at
744 pixels; at 360 pixels the disclosure hides/shows the links and both overview
and domain-selection navigation work. The viewport is restored. Resident backend
source 428c9e04 is unchanged and its matching functional evidence is reused.

Operator presentation correction: reuse the ordinary OSMAP login screen for
`/admin/login`, changing admin copy while preserving the distinct admin form
action/fields, CSRF, cookie purpose, credentials and factors. Reuse the existing
Rust renderer through two fixed entry points, with no caller-selected routes or
new framework. Ordinary login markup/contract remains the default; admin copy
must make the separate administrator account clear and must not offer an
unimplemented admin recovery link. Run the existing login/UI contract tests,
strict Clippy and one installed browser sign-in after the presentation change;
reuse unchanged list/backend/security observations. The screenshot's real
mailbox credentials cannot authenticate the synthetic-only admin authority.
Check the ordinary login's installed backend read-only and clarify which page
failed; do not capture, replay or change the operator's password/TOTP.

The operator subsequently confirms ordinary mailbox login succeeds and requests
the owner address as an OSMAP-ADMIN administrator. Stop mailbox-login diagnosis.
Provision only that new administrator in the currently selected isolated admin
authority, with the two matching system-role indicators, an independently random
password hashed by the installed native bcrypt utility, and a fresh independent
TOTP factor under existing service custody. The verified private SQL datadir,
socket and disabled networking must match before writing; refuse an existing
principal/factor rather than reset it. Preserve native state/readback and qualify
actual owner sign-in. Do not change mailbox credentials, factors, public SQL or
mail services. Deliver password and authenticator registration only through an
owner-only local setup artifact under the sprint root, never Git, command
arguments, environment, logs or chat. The owner must import the new administrator
factor into their authenticator; ordinary mailbox registration is not changed.
This provides owner access to the isolated read-only candidate and its selected
data; it does not promote the test authority to live mail administration.

Owner provisioning observes private SQL admission, principal absence, native
bcrypt cost 12, exact service-owned factor custody and a committed/read-back
pair of system-role indicators. Password-hash and factor bytes are downloaded
privately, compared and hash-read back before any source disposal. No secret is
exported to Git, logs or chat. The shared login change passes seven admin UI cases, eleven Web cases,
the existing shared-brand public-render case and strict all-target Clippy; the
regenerated V10 record passes its real consumer. Actual owner login and installed
shared-login screenshots remain pending at this source checkpoint.

Final obsd1 continuation: Web candidate
`f21b026883df7dfe4986b1ccc6b394c9d732c8f8` builds in 40.43 seconds with launcher
exit 0, installed executable SHA-256
`aa891651a0004323a0d3f2602118e2cdc974f082187778a75b972a7ced728b0c`.
The actual browser shows the reused OSMAP login screen with admin-specific copy,
then the requested owner signs in with the new password and TOTP. Current scope
reports System administrator; choosing the test domain returns its 12-mailbox
inventory. The unchanged resident service/backend remains assessed source
428c9e04; no backend-module change or new library-test build is claimed.
Login, scope and inventory screenshots are retained privately under the sprint
root. The ordinary and admin login GETs both return 200; at 07:39:21 UTC normal
OSMAP, Dovecot, Postfix, MariaDB and nginx health checks all pass.

The local owner-only password/QR setup is delivered for a separate password-
manager entry. User import of that registration and operator functional
acceptance are not inferred from agent sign-in. Uploaded provisioning inputs are
removed only after exact private readback/hash verification; the committed owner
authority and factor remain active. At the operator's request the candidate,
private SQL/roles/proxy and hostname route remain ACTIVE for access, rather than
being removed as a disposable test. This is intentional retained disposition,
not cleanup PASS or a production installation. Prior failed results and UNKNOWN
costs remain; no allowance or authority clock is reset. Mail qualification stays
NOT_RUN, draft PR #99 remains unmerged, and ADM-S01-02 is not accepted.

### Approved catalogue and priority-page refinement — 2026-11-17

The operator approves the function catalogue and its explicit implementation
statuses, and prioritizes Overview, Domain administration pages and Settings
with the same feel as OSMAP. Continue ADM-S01-02 with one observable journey:
owner sign-in -> permitted domain overview with actual mailbox/forward counts
-> domain detail and mailbox navigation -> own Settings save and readback.
Use existing welcome cards/tables, responsive admin shell, shared appearance
enums and private atomic account records. Domain create/edit remains the
catalogue's planned writer work; no enabled mutation control is invented for
the currently read-only SQL authority. Preserve the owner account and its
private registration, working sign-in, mailbox journey and public services.

Root owns implementation/host/Git; adapter_review independently reviews source
and results. Baseline is signed 47582e5. Relevant installed contracts are
observed: the real domain schema has description/created/modified and the alias
schema address/goto/domain/active; the selected private schema lacks those
metadata columns and alias table. Extend only that exact private fixture and
its SELECT projection to qualify these reads. Existing domain.mailboxes/aliases
are limits, not counts. Count actual mailbox rows and non-self forwarding
address records, once per source; do not infer counts from truncated lists.
Preserve unknown creation metadata as unknown. Scope all queries in the service;
system enumeration follows the existing two-indicator system authorization.

Minimum checks are one distinguishing backend RED/GREEN, actual dispatch and
bounded wire shape, foreign/revoked scope, zero-versus-unavailable, isolated
own-preference save with CSRF/enum refusal, and the real browser journey with
desktop/narrow rendering and a fresh-session preference readback. Reuse matching
authentication/confinement evidence. No new dependency, Python logic or test
framework. Retain artifacts under the existing sprint root's domain-overview
directory. Native build remains 600 seconds and individual fixture actions
120 seconds. Initial review checkpoint is two hours of this explicitly added
scope, retaining prior failures/cost and UNKNOWN totals without automatic
allowance growth; two failures at one boundary stop for combined reassessment.
Qualify obsd1 first and record mail separately; no obsd1-only acceptance claim.
Normal independent review, verified Shopkeeper signing/hooks/push and exact
remote equality remain delivery requirements.

The distinguishing backend test first failed because the new operations did not
exist. The implementation then passed that test. Preserve the integrated compile
failure and the five stale landing-page/navigation/logout assertions; combined
independent reassessment approved their narrow correction and the self-only
forwarding count. The corrected focused run passes 85 tests (12 native/explicit
tests ignored), and the new maximum domain page fits and roundtrips within the
existing 8192-byte RPC frame. Strict Clippy passes. These are source checks.

Before fixture extension, verify the exact private root and SQL socket/datadir,
then read back and hash the domain-table backup. Actual Rust-produced prepared
queries execute as the installed restricted reader: example.test has 12 mailbox
rows and two configured forwarding source addresses, while system enumeration
has three domains and includes a genuine zero-count domain. Self-only duplicate
destinations and empty destinations do not count; a mixed list and a disabled
forward each count once. Core and nullable metadata projections pass. Temporarily
removing only the private alias SELECT grant makes the same query refuse with
exit 1 and zero stdout; restoring the exact grant restores the original result.
No owner password, factor, role or mailbox data changes. Native application and
browser qualification of this refinement remain NOT_RUN at this checkpoint.

The signed 4ca8757 candidate builds natively in 40.38 seconds and runs both
private processes with binary SHA-256
`970f0bc3efb9628533842a28f2080e25e16d2ae4b0058caaa0f1c63a32a3d480`.
The owner browser observes three domains, 13 mailbox addresses and three
forwarding addresses, opens example.test metadata and follows its mailbox link.
Search with no match remains distinct from unavailable. Appearance save, logout
and fresh sign-in retain light/compact/large in both the overview and Settings;
restore the original system/comfortable/medium values afterward. Account and
system-information sections work. A private alias SELECT withdrawal displays
unavailable, and restoration recovers the existing authenticated journey.
Public frontend/mail services remain healthy and unchanged.

Visual review at desktop and 360 pixels identifies a metric wrapper mismatch,
the absent Settings CSS ancestor and narrow header wrapping. Reuse the existing
OSMAP metric/icon and Settings wrappers, plus wrapping on the own account label.
Preserve the initial malformed resize screenshot, the uppercase AX versus DOM
locator miss and unsupported attribute-inspection diagnostic as observation
limits, not successful visual evidence. The small presentation correction also
has an initial missing-import compile refusal, retained before correction.
Rebuild and inspect the changed installed presentation; do not repeat matching
SQL, authentication or preference persistence tests. No acceptance or cost reset.

The reviewed presentation correction is signed e3a7ab4. Its native build passes
in 40.56 seconds; the installed Web binary SHA-256 is
`2b34afc11ad99bfef36d2e9150a1e9100bbabb1f69f3afc4b2c5c6cc2e3389e0`.
Only Web restarts for this correction; the resident 4ca8757 backend and its
matching unchanged SQL/authentication/persistence results remain applicable.
Desktop Overview shows all three metric cards and the complete domain table.
Viewport-only Settings screenshots at 1280 and 360 pixels show the shared theme
grid, controls and full account label correctly. Measured narrow text ends at
332.2 pixels inside the 345-pixel header (360-pixel viewport with scrollbar).
The malformed full-page image is a capture limitation, not evidence of a
26-pixel product layout: desktop main/content bounds are 1060/767.2 pixels and
the matching viewport image is readable. Retain both failed images and these
distinguishing observations. Navigation disclosure and working links remain
observed. Restore the browser viewport and retain the active owner-accessible
candidate. Independent review and normal Git delivery reconcile this result;
mail qualification and operator acceptance remain pending. This is an installed
obsd1 refinement, not completion of ADM-S01-02 or the replacement milestone.

Owner acceptance, 2026-11-17: following delivery checkpoint 449ceef, the operator
confirms, "this functionality works." Record owner UAT PASS for the delivered
obsd1 domain overview, domain information/mailbox navigation and Settings
functionality described above. This is the owner's confirmation of the delivered
functionality, not a claim that the owner individually repeated every agent-owned
security or refusal test. Installed Web remains e3a7ab4 with the unchanged
4ca8757 backend. Preserve the active owner account and candidate.

This documentation-only follow-up records the acceptance in the existing plan,
test record and decision log, independently reviews that wording, and preserves
it through normal signed delivery. No product or host action, discretionary test
rerun, new artifact framework or expanded acceptance scope is needed. Mail
qualification remains NOT_RUN; domain/forward writers and credential lifecycle
remain planned. The confirmation does not waive the required mail evidence or
complete ADM-S01-02, production readiness or the replacement milestone.

### One active slice, work orders and delivery

### Approved page baseline and text/icon refinement — 2026-11-17

The operator's five page references approve basic functionality of the current
pages and fully approve the login page in its final state. Preserve that login
rendering and sign-in contract. The mailbox reference currently shows the domain
chooser, not a complete virtual-address management workspace; do not treat it as
acceptance of the missing writer functions.

Continue the active slice with one bounded outcome: own admin Settings selects
Text labels or Icons, saves it, and the authenticated admin pages follow the
same shared OSMAP desktop/touch/keyboard rules across a fresh session. Reuse
PresentationStyle, presentation_label and the existing CSS. Old private
preferences/cookie records default to text labels; invalid choices refuse.
Root owns implementation/host/Git and adapter_review independently reviews.
Baseline b0e349a; preserve all matching backend/owner acceptance evidence.
Minimum checks: one changed-boundary RED/GREEN, old-record compatibility,
enum/CSRF refusal, label/accessibility and login isolation, then native browser
save/readback and desktop/narrow observation. No new Python, dependency or test
framework. Keep native build at 600 seconds and individual fixture actions at
120 seconds; preserve cumulative history/UNKNOWN costs and the existing two-
failure independent-reassessment stop. Use the existing sprint artifact root.

The operator additionally requires complete domain creation/configuration,
virtual mailbox/forward administration, administrator setup/modification and a
security-function catalogue. Reconcile these requirements into the existing
writer/domain/routing/identity slices and security model; they are not supplied
by the currently SELECT-only pages or an enabled-looking button. Mail native
qualification remains required separately from this obsd1 refinement.

Installed presentation result: signed ba360305a2961453e1e791812d0fadf5f1e290e8
builds natively in 40.41 seconds. Both isolated admin processes use artifact
SHA-256 `879d1bec355584a850f995ab67565de0a443410dc92e8f1029297f4d94d8f494`.
Old preferences load as Text labels. The actual owner browser saves Icons,
uses overview/domain/mailbox controls, exposes the keyboard-focused Domains
label, switches back to Text labels, and retains Icons after logout and fresh
password/TOTP sign-in. Leave the requested Icons mode selected with the other
appearance preferences unchanged. The approved login remains visually unchanged.
At 360 pixels, touch emulation keeps visible labels and expanded navigation;
this is emulation evidence, not physical-device UAT. Touch and viewport overrides
are restored. The initial 759-pixel reference-tab viewport observation is retained
as a setup limitation; corrected 1280-pixel DOM and viewport images establish
desktop rendering. Independent source and image/result review are GO for this
obsd1 scope. Reuse unchanged SQL/authentication evidence. Public mail/frontend
services stay healthy; the private candidate/owner account remain ACTIVE.
The expected missing-field RED and the whole-body CSS assertion failure are
retained; the latter is corrected to inspect only the login root tag and passes.
Strict Clippy and the existing inventory producer/consumer pass. Mail, release
and owner acceptance of this new refinement remain pending. Bootstrap/domain
writers are selected next, not implemented by this presentation change.

The operator explicitly selects **Create a domain from scratch** as the next
complete write journey. This supersedes the table's earlier chronological
mailbox-first priority, not the required writer/authority/security contracts.
An existing mailbox or the old application must not be a bootstrap prerequisite.
Bring the minimum native schema/grant initialization and offline first-admin
sub-slices ADM-S05-01a and ADM-S05-02a forward into the domain outcome; retain their parents' remaining
installation/upgrade/enrollment acceptance obligations. Then reuse that writer
foundation for ADM-S01-03. Domain creation does not depend on completion of a
mailbox-creation journey or of the entire later standalone-installation sprint.

**Both entry paths are required.** For an already installed openbsd-mailstack
and OSMAP system with no managed accounts, enhance the existing bootstrap so
Rust can initialize/verify the admin authority and least-privilege grants,
establish a first administrator with MFA independently of any mailbox, and reach
first-domain then first-mailbox creation. For an existing populated installation,
inspect/adopt the actual compatible authority, preserve mail/credentials/factors,
fence the old writer before enabling Rust writes, and prove continuity before
retirement. Keep the existing database name when required; no PHP runtime or
legacy setup page may be required by the new admin path.

Inspection of openbsd-mailstack at commit
`70c3d799bc13b7f00f49ee4d86557f3216827d4d` identifies concrete integration points:
[Phase 02](https://github.com/unattributed/openbsd-mailstack/blob/70c3d799bc13b7f00f49ee4d86557f3216827d4d/docs/phases/phase-02-mariadb-baseline.md),
[Phase 03](https://github.com/unattributed/openbsd-mailstack/blob/70c3d799bc13b7f00f49ee4d86557f3216827d4d/docs/phases/phase-03-postfixadmin-and-sql-wiring.md)
and the [lab seeder](https://github.com/unattributed/openbsd-mailstack/blob/70c3d799bc13b7f00f49ee4d86557f3216827d4d/scripts/bootstrap/seed-lab-runtime-state.ksh).
Phase 03 expects legacy setup inputs. The seeder creates mail routing tables,
but not the admin/grant authority consumed by Rust, and its mailbox table omits
the smtp_active projection consumed by the current reader. It also uses broad
SQL grants and upserts initial mailbox passwords. Do not execute or wrap that
seeder as an adoption path: replace these bootstrap effects with typed,
least-privilege, empty-versus-populated Rust operations and explicit refusal of
unknown/partial state. Preserve existing credentials on rerun. Do not carry its
release/package pins into compatibility admission. These are inspected gaps,
not an implemented bootstrap enhancement or a native fresh-install PASS.

The future full-stack installation gateway, OS/package deployment and optional
WireGuard access for native clients are explicitly OUT OF SCOPE now. Enhancing
the existing mailstack's admin bootstrap is IN SCOPE; building a second general
installer is not required to deliver it.

### Required write functionality and parity scope — 2026-11-17

The referenced domain and virtual-list pages redirect to authenticated legacy
login in the agent browser. Read-only installed handler inspection on mail
establishes the field definitions below; enabled optional flags, rendered-page
parity and native effects still need qualification when each writer is selected.
No installed PHP code, hook or endpoint becomes a Rust runtime dependency.

| Existing slice | Required product functionality | Matching positive/refusal observations |
| --- | --- | --- |
| ADM-S02-01, brought forward as selected next | Create a domain with name, description, active state, mailbox/alias limits, per-mailbox/domain quota with verified units, supported transport, backup-MX policy and previewed default aliases. Show server-owned creation/modification dates. Include password-expiry policy only where its installed consumer is qualified. Link domain-admin assignment and DNS/security setup. DNS publication is an explicit configured integration or operator action; pending DNS is displayed honestly rather than preventing configuration drafts. | Empty authority reaches first admin/domain without an existing mailbox or legacy setup; persisted domain/default aliases are consistent and the actual Postfix lookup recognizes the configured domain. Duplicate/invalid names, foreign administrator, unapproved transport, quota overflow, partial initialization and concurrent submission refuse or reconcile without damaging existing data. Map UX-WF-02, UX-WF-03, existing T:F-01–06 and T:DB/INT/SEC cases. |
| ADM-S01-03, ADM-S02-02, ADM-S02-03, ADM-S03-01, ADM-S03-02 | A real per-domain virtual-address workspace, rather than only the domain chooser: mailbox and alias lists, create/edit/disable/reactivate, mailbox display name and quota/usage, password/reset/enrollment, SMTP authorization, forwarding recipients and keep-local-copy, catch-all, alias domains and installed vacation/Sieve. Dates and routing state remain visible; recovery contacts follow the approved identity policy. Retirement preserves mail and uses the existing lifecycle rather than immediate destructive deletion. | Native authentication, local/external routing and delivery reflect each supported action; self-forwarding loops, foreign targets, reserved address damage, duplicate addresses, stale revisions and violated limits refuse. Units/usage and optional backend effects require native proof. Reuse mapped UX-WF-04–10/12 and existing T:F/INT/SEC/REC cases. |
| ADM-S04-02, ADM-S04-03 | Settings has a system-administrator-only Administrators section: create/list/edit identities independently of mailboxes, select system/domain role and exact domain grants, activate/disable, enroll password/MFA securely, rotate/recover credentials under policy, revoke sessions and audit changes. Own appearance/account preferences remain separate. Argon2id stays part of this credential feature with compatible legacy verification. | Creation and grant changes work through the protected service; unauthorized elevation, last-system-admin lockout, expired/reused enrollment and stale-session resurrection refuse. Role changes invalidate authority before success. No password/hash/TOTP secret is returned in list views or audit. Reuse UX-WF-11, UX-WF-15 and existing T:F-04, T:F-24–26, T:F-35, T:SEC and T:REC cases. |
| ADM-S06-01, ADM-S06-02 plus each affected domain/identity slice | Domain security/DNS and encryption controls follow the catalogue in OSMAP_ADMIN_SECURITY_MODEL.md, beginning with observed status and evidence. Each writable control requires its fixed protected backend and actual consumer test before enablement. | Distinguish configured, DNS-observed, native-verified, unavailable and pending states. A saved switch or generated key is not proof of signing, encryption, enforcement or recovery. |

Only the selected product slice may transition to IN_PROGRESS. Its concrete
work order extends the contract above in this document, records file owners,
actual prerequisites, expected tests, recovery/cleanup, evidence and cumulative
effort/allowance, and names the next observable boundary. Other slice status
remains NOT_STARTED. Useful independent review may run on that same objective;
there is one canonical Git/host queue. A prerequisite implementation belongs to
the active product outcome, not a competing indefinitely active infrastructure
sprint. Reordering dependencies requires an explicit recorded reason and keeps
all required parity/acceptance obligations.

Apply the S05 method: inspect/reuse -> establish one distinguishing functional
test -> smallest complete change -> actual backend/browser validation ->
independent review -> signed delivery. Preserve failures and actual elapsed
work; two failures at the same boundary stop retries for combined independent
reassessment. No renamed attempt or retrospective review resets cost or expands
an exhausted allowance. No invented elapsed-clock expiry of operator authority.
Before cleanup retain bounded sanitized diagnostics, read them back and verify
hashes; unknown effects remain contained and are not blindly retried.

Use existing focused checks while progressing; full developer/release suites
remain the normal delivery/release gates. A matching passing native boundary
need not be repeated for a documentation or presentation-only change. Preserve
public-safe work with verified Shopkeeper signatures and ordinary hooks, exact
remote SHA/zero-ahead-behind verification and protected PR integration. Source
delivery, native qualification, installed QA, operator acceptance and production
authority remain distinct fields. Release requires the existing applicable
G0–G6 gates, with G6 reserved for explicitly authorized production acceptance,
not merely completion of this table.

ADM-PLAN-01's bounded work order is **documentation only**: `/root` edits this
plan, its existing UX/test cross-references and chronological decision log;
`/root/adapter_review` independently checks mappings, dependency/authority and
result claims. Baseline is the clean assessed commit above. Minimum checks are
case-ID/dependency/link consistency, historical-record preservation, Markdown
diff review, the existing documentation governance guard and mandatory hooks.
No discretionary Cargo/native/host campaign is needed. Cumulative scope is one
roadmap reconciliation and normal reviewed delivery, retaining any demonstrated
gate failure/repair; two failures at one boundary require reassessment, with no
automatic allowance increase. Earlier preparation elapsed is UNKNOWN; measured
planning observation starts 2026-11-16T17:14:36Z. Implementation and production
tests stay NOT_RUN. The signed checkpoint and PR receipt will record actual
documentation checks, review, delivery and final source identity separately.

**ADM-PLAN-01 documentation result:** case-reference checks PASS for all 214
test-plan cases, all 82 parity IDs, the named UX references and 22 unique product
slices; 62 local document targets resolve. Historical slice-record bytes are
unchanged. Markdown diff and the existing documentation governance guard PASS.
Independent dependency/scope/mapping review PASS, including mandatory mail
acceptance and the separate native-bootstrap/Path B routes. These are document
checks, not executed product tests. Normal signing/push hooks, protected
integration and exact remote identity are recorded in the final PR receipt;
product/native/browser tests for the new slices remain NOT_RUN.

The later Argon2id investigation is retained as history. Its suggested standalone
verifier priority is superseded by this operator-directed product sequence.
Its feature is now explicitly scheduled within ADM-S04-02 above.
Argon2id generation for a new mailbox may reuse the existing qualified facility;
adding admin Argon2id verification, migrating existing hashes, optional schema
Path B and optional modules are not prerequisites invented for ADM-S01.

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

The second normal push passes the full Rust suite (2397 PASS, 100 ignored),
strict Clippy and supply-chain checks, then refuses one of 642 Python account
regressions. Independent reassessment identifies a fixture mode assumption:
`mkdir(mode=0750)` under the push's private-artifact `umask 077` creates `0700`;
the real startup custody guard correctly refuses it. Correct only the existing
directory fixture with explicit `chmod(0750)`; all four module tests PASS under
both umasks 077 and 022 before a reviewed normal gate retry. Preserve the second
gate; no runtime custody policy, native qualification or allowance is changed.

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

## ADM-S01-03 work order — 2026-11-18

**Opening state: IN_PROGRESS; functional/native/owner acceptance NOT_RUN.** Baseline
`8e8294f939357c2e5c89409e03d2c3d181ec5a18`. The operator selected controlled
mailbox creation. Root owns integration, implementation, documentation and the
single host/Git queue; admin_ui_engineer owns the existing Web/RPC/presentation
composition; adapter_review independently checks prerequisites, source and
matching qualification. No new Python or general test machinery is authorized.

**Outcome:** at the obsd1 development address, an authorized admin submits a
mailbox form with fresh TOTP; the protected Rust service commits exactly one
mailbox, its local-delivery alias and a durable operation/audit record, and the
result matches database and installed Postfix/Dovecot lookup projections. Qualify
the same reviewed build on mail against isolated authority. Actual authentication
and message delivery remain ADM-S01-04. Browser access stays MFA pending. Native
auth/delivery capability is permitted only in the isolated lab policy, without
changing production enrollment policy. Do not reuse the previously exposed owner
fixture credentials for writer access; controlled qualification uses fresh
credentials and factors in private sprint storage.

**Boundary:** existing isolated domain only; opt-in protected writer profile,
explicit holder/epoch and domain admission, atomic journal, revisions and current
actor checks. Reader credentials remain read-only. No production account writes,
legacy-writer fencing/cutover, public mail configuration changes or backend
restart/reload. Fresh bootstrap/first domain, enrollment and account edits retain
their existing slice ownership. Preserve the approved login and display settings.

**Prerequisites and tests:** verify real schema/defaults/unique keys/InnoDB,
maildir and UID convention, quota units and native password scheme before dependent
code. Test browser -> RPC -> service -> transaction -> post-commit readback, then
native projections. Exercise duplicate/case collision, invalid quota, foreign or
revoked scope, stale revision, missing CSRF/fresh factor, competing holder and
ambiguous submission; no automatic replay or partial-success claim. Use existing
Rust tests and mandatory delivery hooks, not repeated broad suites between
milestones. Mappings remain the S01-03 row's T:F/DB/SEC/UX/RES cases. Planned tests
remain NOT_RUN until observed.

**Effort and stops:** retain actual measured command durations and failures under
`/home/foo/Downloads/osmap-admin-s01/slice03/`; total elapsed and token cost are
UNKNOWN until measured, with no invented authority clock or replenished allowance.
Two failures at one functional boundary stop retries for combined independent
reassessment. Preserve earliest sanitized failure separately from cleanup and
uncertain submission. Close only after matching independent review, signed source
and normal GitHub preservation; source delivery is separate from owner acceptance
and production readiness.

Source prerequisite result: production table metadata confirms InnoDB and the
address unique key; installed Dovecot projects `domain/local/` under `/var/vmail`
with UID/GID 2000 and advertises Argon2id. Read-only inspection of the installed
legacy configuration and its domain/mailbox consumers confirms **1,024,000**
bytes per domain-limit unit. This differs from MiB. The writer therefore requires
an explicit adopted domain unit; the new form's MiB values become mailbox bytes
and are compared to domain limits after conversion. No PHP code is executed or
linked by OSMAP-ADMIN. The first private SQL preflight used an incorrect effective
root principal for the existing foo socket-auth profile and refused; running as
its intended foo principal succeeded. A missing remote `rg` was handled with
native `awk`. These are retained preflight failures, not mailbox-create attempts.

### ADM-S01-03 engineering qualification — 2026-11-18

**Engineering and isolated native/browser qualification: PASS. Owner acceptance:
NOT_ACCEPTED. Production writer/cutover: NOT_DEPLOYED.** Runtime source
`d40ad6494ff0d7bbba64c9b1a04177390594f615`; identical OpenBSD binary on both hosts:
`bab7b8e024dad0d0b93a2e1bcd6ba88e9a9bfeb05db5d9d5eef0cdff72396ba1`.
Source integration will be recorded by the associated protected PR/delivery
receipt after delivery; this runtime pin identifies the assessed code,
independently of later prose.

The browser journey committed a controlled mailbox, its self-delivery alias and
operation journal on obsd1 and on the isolated candidate actually running on
mail. The latter retained the obsd1 HTTPS address, with strict upstream TLS and a
fixed mail-fixture response marker proving the selected backend before sign-in.
Copies of actual production table definitions, not production account data,
qualified the adopted schema, collation and unique-key contracts.

The first obsd1 operation committed but returned UNCONFIRMED because a native
collation comparison refused during readback. The fixed byte comparison was
independently reviewed and qualified. Reconciliation of the original operation
returned its verified receipt without another transaction, row or revision
increment. A fresh browser operation then configured 97 MiB / 101,711,872 bytes;
98 MiB refused against the installed legacy maximum of 100 units at 1,024,000
bytes/unit. Other native refusals covered CSRF, invalid quota, foreign scope,
wrong/replayed TOTP, stale revision, canonical collision, competing holder and
revoked authority. Restoring a grant did not resurrect the old session. A bounded
native locking-read/concurrent-revocation discriminator retained the active grant
and refused its competing update. Mail additionally exercised CSRF/factor replay,
foreign scope and canonical collision against its own private authority.

Installed Postfix mysql lookups returned the created mailbox path, protected
self-delivery alias and active domain. The installed Dovecot SQL projections
returned the compatible Argon2id shape privately, matching home/mail paths,
UID/GID 2000 and stored quota bytes on both hosts. These are lookup/configuration
results: actual native authentication, Postfix-to-LMTP delivery, quota enforcement
and owner-held mailbox MFA are not inferred. ADM-S01-04 remains NOT_STARTED.

Retain the two compiler allocation failures, first unconfirmed operation,
preparation/refusal diagnostics and hostname certificate failures. The corrected
compiler used the independently reviewed, measured process limit, not a memory
admission floor. The userdb read-only probes also exposed a shell serialization
mistake on both hosts; file/stdin dispatch passed, but it preceded independent
reassessment. Preserve this sequencing deviation without retrospective admission
or repetition of matching passes. Private evidence and status observations live
under `/home/foo/Downloads/osmap-admin-s01/slice03/`; no credentials, factors,
cookies or native SQL error text belong in Git.

The operator chose restoration of the existing duncan login and retention of the
qualified writer candidate for separate acceptance. The exposed earlier identity
is not admitted as a writer. Runtime restoration/cleanup and normal signed GitHub
delivery are recorded with their actual outcomes below; source qualification does
not substitute for those results. The fresh-authority bootstrap/first-domain
chain remains planned; this existing-domain slice does not complete it.

### Final admin revision guard and retained-state disposition

The final backend review found that `admin.modified` participates in session
invalidation but was not part of the locked SQL actor predicate. The corrected
runtime is **`a8b86483751102ec2c7025d82d5ab94cfeecd538`**, native binary
**`09a73f45dc87367abdf319a2fff098287217d7687a48f4141ee1c7c4bfe9a869`**.
It captures that value from the same authority lookup and compares it under the
admin row lock. Focused access tests passed (24, with nine explicit native
ignores); the native build passed in 50.44 seconds. The form, RPC, presentation,
hash runner and native lookup code are byte unchanged from the browser-qualified
revision, so those matching passes are reused.

The final binary created accounts through the real Web/service/SQL path on both
hosts (HTTP 201). A distinguishing native revocation test held an uncommitted
metadata-only admin update, observed the actual writer admin SELECT in InnoDB
LOCK WAIT, and then committed the metadata revision. Creation refused with 403;
mailbox, alias and operation counts stayed 3/3/3 and writer revision stayed 4.
The admin remained active with unchanged role. This tests the locked comparison,
not an earlier session refusal. The existing DATETIME precision is shared with
session fingerprinting; no stronger timestamp guarantee is claimed.

The operator's original obsd1 Web configuration and original admin state are
restored; `/admin/login` and ordinary `/login` return 200. The qualified writer
is retained separately, stopped and protected by a root-only ancestor. No writer
access was added to the exposed earlier identity. Temporary hostname routing and
SSH forwards were removed. Mail qualification and root-sealed retained-state
cleanup are recorded in the final delivery receipt; they do not imply production
writer deployment or ADM-S01-04 authentication/delivery acceptance.

Final disposition readback passed independently of functional qualification.
On mail, all exact-owned private Web/service/nginx/SQL processes and sockets are
absent; the retained namespace is root-owned mode 0700, files 0600, and temporary
OS roles/groups are removed. Its final binary hash matches the qualified artifact.
Public Postfix, Dovecot, MariaDB and nginx health checks pass. On obsd1, the
original Web configuration and route hashes match the saved originals, temporary
upstream trust is absent, and the new writer is stopped behind a root-only
ancestor. The original reader's shared SQL/OS roles remain intact. Both temporary
SSH control sockets are absent. Owner sign-in itself was not repeated.

Cleanup history includes two admission-only serialization refusals, independent
reassessment, and an additional unchanged-script refusal after a local edit
builder failed without stopping its caller. The corrected producer/consumer
probe passed, including a changed-value refusal. Cleanup then stopped the private
processes, but OpenBSD rejected the combined `chown -Rh` flags. A finite seal-only
resumption verified the exact retained anchor and process/socket absence, sealed
the ancestor first, used the demonstrated `chown -R` contract, removed the
temporary roles and obtained the final readback above. Preserve these failures
and the sequencing deviation; no retrospective admission PASS or new functional
retry is implied. Signed delivery uses the normal hook once for the final source;
the final GitHub identity and gate result belong in the delivery receipt.

### ADM-S01-03 live UAT correction — 2026-11-18

Owner sign-in PASS; Open creation FAIL. The selected obsd1 route still runs the
earlier read-only build while the qualified writer is stopped. This reopens
installed creation readiness; prior isolated engineering evidence remains valid
for its exact candidate, not the owner's selected route. The owner also rejects
duplicate Overview/Domains and Mailboxes navigation that leads to Domains.

One outcome: at the usual obsd1 admin address, the established owner development
administrator opens a real mailbox workspace and creates one controlled mailbox
in the isolated existing domain. The final operator direction requires the saved
development password/TOTP; the earlier replacement registration is historical and
is restored below. Keep the username, approved login design, appearance preferences
and real mailbox credentials unchanged. Preserve configuration for rollback.
Production data/configuration and public backend services remain outside this
action. Domain/mailbox editing is not implemented or claimed by S01-03.

Root owns work order, credentials, native/deployment/Git queue and evidence;
admin_ui_engineer owns the three existing UI/router files and focused navigation
checks; adapter_review independently reviews source, native admission and results.
Use the existing protected reader/writer, SQL/factor custody and native build
method. First verify retained schema, role/config/path/socket contracts. Reuse
the matching mailbox transaction, hash and mail-host evidence. Required new
observations: distinct working navigation; old isolated admin credentials no
longer admitted to writer; fresh duncan login; authenticated creation form and
one committed mailbox visible after readback. Browser review uses actual pages,
not markup alone. Existing security, signing and normal delivery hooks remain.
Preserve failure history and UNKNOWN total cost, record measured commands, and
stop after two failures at the same boundary for independent reassessment. Do
not add Python, dependencies, a new harness or a repeat of unchanged broad tests
between milestones. Owner acceptance stays open until actually given.

### Required replacement-function map and first-user TOTP — 2026-11-18

The operator requires creation of admins, domains/subdomains, mailboxes,
aliases/forwarders and initial OSMAP-user TOTP. Read-only inspection of the
installed `/var/www/postfixadmin/model` on mail confirms the functions below;
model presence alone does not prove optional enablement. This maps the existing
catalogue and slices, not a second backlog. Product Rust has no PHP dependency.

| Installed reference | Required replacement and owning slice | Current boundary |
| --- | --- | --- |
| Admin identity/password, system role, domain assignments, active state, recovery fields and dates | Create/enroll/edit administrators and revoke scope, ADM-S04-02/03; independent first admin ADM-S05-02a | Sign-in/role reads implemented. This fresh duncan registration is operator provisioning, not browser admin creation. |
| Domain description, mailbox/alias limits, mailbox/domain quotas, transport, backup-MX, default aliases, active state and dates | Create/edit domains and independently hosted subdomains, ADM-S02-01; quota/usage ADM-S02-03; DNS readiness ADM-S02-04 | Reads implemented; writer not implemented. Subdomains are explicit hosted FQDNs; wildcard acceptance or DNS publication is not implied. |
| Mailbox address/name/password, quota, active/SMTP flags, welcome mail, recovery fields and dates | Create mailbox ADM-S01-03; edit/reset/disable/reactivate ADM-S02-02/03 | Isolated creation qualified; live route correction active. Editing and native authentication/delivery remain unaccepted. |
| Alias source, multiple recipients, keep-local-copy, active state; catch-all and alias-domain target | Create/edit aliases and local/external forwarders with real routing, ADM-S03-01/02 | Reader projections implemented; mutation/routing journeys not implemented. Protect mailbox self-delivery mappings. |
| Vacation, Fetchmail and DKIM/signing handlers | Installed-backend parity/disposition under existing optional/security catalogue, ADM-S02-05/ADM-S06 | Source presence observed; enablement, backend support and delivery require actual evidence. |
| Added initial TOTP requirement | ADM-S04-01, brought forward before ADM-S01-04 where required: pending mailbox with administrator-recorded recovery email -> existing Forgot password and six-digit proof -> user password and proved authenticator -> protected no-overwrite installation -> native password-plus-TOTP reaches owned Inbox | Corrected source IN_PROGRESS; automatic native registration and installed journey unmet. Expired/replayed/cross-account setup and existing-factor overwrite refuse; seeds/counters stay out of SQL/audit. |

Acceptance needs persisted changes and native effects. Reuse OSMAP's app shell,
welcome/settings components and text/icon preference. Overview summarizes;
Domains manages hosted domains; Mailboxes opens its own workspace. Unimplemented
operations are stated plainly, without controls lacking working handlers. Finish
the live S01-03 correction before opening the next writer/enrollment slice.

Live correction result: signed source `b8dc4f543bdd05c107624470fe1d0d865240f435`,
OpenBSD binary `84f9c621f9dbaf948f41c8090fd9ea14d222e06cd4cbb275b5aa0ba202e46c92`,
is ACTIVE at the ordinary obsd1 admin address. The approved fresh duncan admin
and ALL grant read back 1/1 in isolated authority; fixture SQL profile credentials
are refreshed. Original configuration/binary backups have durable matching hashes.
Fresh duncan browser sign-in, distinct Overview/Domains/Mailboxes, domain selection
and the real Create mailbox form pass. The prior password returns 401 on this
writer. Current credentials reach HTTP 303 login, HTTP 200 creation form and HTTP
201 committed creation for `uat-live-owner@example.test`, quota 10,485,760 bytes.
Independent SQL readback returns exactly one mailbox/self-alias/operation, the
recorded duncan actor, expected name/path/flags and writer revision 5. The actual
browser filter shows that address once after the write; QA signs out afterward.
The unchanged creation-form/post/transaction and prior mail-host evidence are
reused; this is new obsd1 UI/identity/installation evidence, not a new mail-host
UI qualification or native authentication/delivery claim. Owner acceptance remains
open. Private setup/QR and results are in the existing slice03 `live-uat` directory.

Retain two build failures and the independently reviewed successful 58.20-second
child-limit/cache correction. Registration completed before activation, which
first refused a filename guard that incorrectly excluded the `.totp` suffix;
there were no activation effects at that refusal. The earlier read-only probe
made the same refusal, but its trailing hash consumer missed the terminal PASS.
After combined independent reassessment, the exact factor-name guard passed the
actual admission and rejected a changed value. One corrected activation then
passed. Registration was not repeated. A browser locator failed to click Cancel;
fresh accessibility state and its exposed link completed navigation. Preserve
these diagnostics separately from the product passes and all previous failures.

Latest operator correction: reuse the established duncan development password
and TOTP already saved in Proton Pass; do not create replacements. Restore the
exact original private password hash and factor into the active isolated writer,
preserving the greater consumed replay counter and existing appearance settings.
Actual saved-password/current-TOTP sign-in returns 303, the creation form returns
200, and the replaced password returns 401. QA logs out. No new credentials are
generated by this restoration; the earlier replacement handoff is retired.
The new UI and writer remain active. This supersedes the fresh-registration
handoff above without removing its history. Keep a straight line: one real
management feature through the established development login, matching native
proof, independent review and delivery; then the next function in the parity
map. Do not introduce credential churn, decorative controls or another plan.

## ADM-S04-01 work order — 2026-11-18

The owner accepts the S01-03 configuration-creation journey shown for
`pr101@empty.test`, quota 20 MiB. This PASS does not qualify native authentication,
delivery or initial user MFA. The approved next outcome is one pending mailbox
created with administrator TOTP, independent external-contact verification, a
restricted user-chosen password/TOTP setup, protected initial installation and
a fresh login to the owned OSMAP Inbox through its actual backend.

Baseline: merged `9eb3f76952f94c9f6015b31e84ee5df8863f510b`. Root owns integration,
native/Git execution and delivery; a bounded Rust engineer owns initial setup
storage; adapter_review independently assesses the source and actual results.
Preserve the approved login, saved owner development admin password/TOTP,
appearance and ordinary mailbox access. No new Python, dependencies or general
test framework. Public mail-daemon/configuration changes and passkeys are outside
this work. Use obsd1 as the development host/address; inspect actual contracts
before composing dependent integration. Existing recovery requires a previously
installed factor and must retain that restriction. Never manufacture a prior
factor/hash to admit first enrollment.

| Required boundary | Prerequisite and action | Expected result | Actual |
| --- | --- | --- | --- |
| Pending creation and setup authority | Current scoped writer, real schema, fresh admin TOTP; create one controlled pending account with an external contact | Non-secret receipt; no usable native password or ordinary user session; existing account/factor refuses | PASS for actual HTTPS creation 201 and private SQL readback: one disabled mailbox, disabled SMTP and self-alias. Saved admin credentials preserved. |
| Independent recipient proof | Server-held approved contact, bounded invitation delivery and verification | Restricted, expiring, single-use setup authority bound to the pending account; wrong/expired/replayed/cross-account proof refuses | Owner confirms the first email arrived; its invitation is retired. One distinct controlled account's corrected standard-HTTPS invitation is accepted by SMTP; receipt and recipient-controlled token redemption PENDING. Local purpose/account/expiry/replay cases PASS. |
| Initial password and factor | User-chosen password, proved authenticator, protected absent-factor store and real password authority | Counter consumed, factor never overwrites, activation read back; ambiguity remains contained | Private native producer/installer/password/SQL activation/readback PASS; owner setup PENDING. No-overwrite/partial-state refusal cases PASS locally. |
| Working OSMAP user | Matching native passdb/userdb/Maildir and browser Runtime | Fresh password plus a later TOTP reaches only the owned Inbox; pending/old/unknown credentials refuse | Standard HTTPS 443 password/TOTP login 303 and owned Inbox 200 PASS at 5fed618. Probe logged out and disabled. Earlier status 75 cause remains UNKNOWN; native text was discarded by its old consumer. Owner first login PENDING; no production or message-delivery qualification. |
| Delivery | Independent source/security review, focused Rust contracts and mandatory normal hooks | Signed reviewed checkpoint, signature verification, ordinary GitHub push and exact remote equality; native and owner acceptance stated separately | Reviewed signed checkpoints 2221f55 and 5cf7461 published through normal full push gates; exact remote equality confirmed. Final result-record checkpoint pending. |

Prior total elapsed effort remains UNKNOWN. Preserve measured new actions and
earliest sanitized failure separately from cleanup and authoritative-state
certainty. Two failures at the same boundary stop retries for combined independent
reassessment. Do not expand an exhausted allowance or invent a new prerequisite.
Native account activation is not qualified by source, SQL creation or rendering.

Read-only readiness established: obsd1's public mail daemons and ordinary OSMAP
remain running; the active admin fixture is a separate private MariaDB authority.
Its writer has creation grants but lacks the password/active-flag and operation
credential-digest UPDATE grants required by setup. Existing native Dovecot supports
the SQL/auth-client/userdb interfaces; observed version is evidence, not admission.
The ordinary frontend uses remote authoritative-mail relays. Therefore the first
login must use an isolated actual Dovecot + existing OSMAP frontend/helper candidate,
not falsely qualify the private SQL fixture against the ordinary relay.

Next native preparation `ADM-S04-01-private-passdb-preflight1`: root owns one
new exact `/var/osmap-adm-s04-01` namespace on obsd1, with private Dovecot config,
run/state/mail paths and a fixture-only SQL reader. Validate the actual installed
configuration/SQL connection before dependent execution. Existing `_osmap`/vmail
principals may be reused with private paths and keys; no public daemon or mail
configuration changes. Stop on collision or failed semantic readiness and retain
sanitized stage plus private output. Source-native synchronization follows a
reviewed signed checkpoint. External invitation delivery awaits the owner's
selected contact; no mail has been sent by this slice.

Preparation result: private reader creation/query and Dovecot configuration parse
PASS; exact root namespace identity retained privately. Auth worker and browser
were NOT_RUN by that parser check. Next action
`ADM-S04-01-private-userdb-check1` starts only that private Dovecot instance and
uses the actual unmodified Doveadm userdb/create/list commands as vmail for the
existing synthetic configuration-accepted account. Before the Inbox write,
require exact private home/mail location and UID/GID 2000:2000. Retain the private
master/state and earliest bounded failure; no public mail control/configuration
operation. Primary authentication and new-user browser login remain separate.

The first private userdb attempt starts the private master but userdb exits 75.
Retained native diagnostics identify `EMFILE` (too many open files); the SSH-root
process has soft/hard descriptor limits 128/1024. No Inbox write occurred because
the userdb prerequisite did not pass. Public services and the active admin login
are unchanged. Preserve this failure independently of any later private-instance
stop/restart. A bounded process-local correction using the existing hard limit,
followed by one actual private userdb/storage discriminator, is under independent
review; do not call the earlier parser/reader passes functional authentication.

Combined reassessment preserves the userdb/EMFILE failure and the separate
asynchronous-stop observation refusal. Fresh namespace/config, process inventory
and refused stale-socket connections resolve the private shutdown observation;
there is no repeated stop, historical PID signal or socket unlink. One start-only
continuation sets the private process soft descriptor limit to its existing hard
limit. Its immediate readiness guard also observes too early; fresh readback
then confirms the new private master/listeners without another start. Actual
SQL userdb subsequently returns the exact private home/mail and 2000:2000; actual
native Inbox create/list PASS. These results qualify private userdb/storage only,
not a password or browser login. Public services remain OK.

Source checkpoint `2221f55c74cfd6f6613fdb3d1c4929a7b6096380` has a verified
Shopkeeper signature. Independent source review and focused Rust/Clippy checks
pass; normal GitHub push gates are running. Next bounded native build action
uses its exact private-mode archive and the already demonstrated obsd1 cache,
foo Cargo home and child-local data limit, offline/locked with one job, for only
`osmap-admin` and `osmap`. Stop on build failure; preserve diagnostics and do not
repeat a full test/build or infer native enrollment from compilation. The provided
external invitation destination remains private and outside Git.

Native runtime preparation installs the signed binaries under the new private
namespace and parses the frontend/helper configuration as their actual roles.
The file service reaches sealed readiness with root:service-group socket 0660;
the mailbox helper reaches its 2000:1002 socket and the user frontend serves its
login. Preserve the first invalid pipelined SMTP probe; a sequential existing
SMTP client observes greeting/EHLO/DSN successfully without sending a message.
The external test contact has been supplied privately; no invitation is sent yet.

Private proxy preparation first refuses an assumed proxy UID; copying the actual
working Web identities resolves that mismatch. The native Nginx parser requires
its private temp directories and creates an empty PID leaf during validation;
preserve the invalid absent-PID guard separately from service readiness. Its
OpenBSD worker chroot then requires the private Web endpoint inside that prefix.
The correction preserves confinement and all public routes. The private TLS
listener is bound to the obsd1 LAN address. One runtime PF rule admits only the
operator workstation to its development TLS port; all 17 existing anchor rules
read back identically, with no table/state flush or public mail-daemon change.

One ignored native contract test now exercises the changed producer/consumer:
controlled disabled fixture -> real restricted enrollment store -> proved code
-> real privileged installer -> real password/activation/readback. It admits only
the fixed private SQL/schema/socket and backend UID. It sends no mail, creates
no administrator, leaves failure state retained, and writes a mode-0600 private
receipt for a subsequent actual HTTP password/TOTP/owned-Inbox test. That receipt
is never public evidence. The running owner admin service remains on its working
configuration while the test uses a separate protected qualification config.
The new source delta is test-only; production runtime bytes match `2221f55`.
Native test execution and ordinary first login are NOT_RUN at this checkpoint.

The private HTTPS admin login now returns 200 through the preserved Nginx worker
chroot. Web shutdown leaves its owned Unix socket behind; the original wait for
automatic removal and a subsequent over-narrow parent-mode guard both refused.
Combined independent reassessment confirmed the actual 0750 parent contract,
fresh process absence and refused connection. Only that pinned obsolete socket
was removed; the new endpoint is inside the private proxy prefix. The ordinary
owner admin route and saved credentials remain unchanged.

Signed checkpoint `5cf7461d467d3a2eff7ec7aab3c48126af7970e3` adds only the
opt-in native test and evidence. Its native compilation fails with ENOSPC on
the host's `/tmp` filesystem before test execution. Moving its scratch cache to
`/var/tmp` does not resolve this: fresh observation shows that path is a symlink
to `/tmp`, and the second compiler attempt also fails before execution. Preserve
both failures; the earlier free-space observation for `/var` did not establish
the filesystem backing `/var/tmp`. Combined reassessment must verify the actual
destination device and put compiler temporary output there as well before one
corrected compile. No test account has been created or invitation sent. The
fixture-only writer's five activation column grants and protected qualification
configuration are installed; they are prerequisites, not activation evidence.

The corrected compiler action verifies both target and temporary directories on
the actual `/var` device, distinct from `/tmp`. Compilation PASS in 2m04s. The
single ignored native test then PASS in 0.53s against signed `5cf7461`; installed
private runtime source remains `2221f55` (the second delta is test-only).
It exercises the actual privileged socket installer, password hashing, activation
transaction and readback. Separate ordinary HTTPS password/later-TOTP login
returns 303, and the owned Inbox returns 200 with the expected identity and real
mailbox list. This is actual private Dovecot/frontend/helper evidence, not a
Toronto or public delivery claim. Log out the test session and disable that exact
probe account; retain its private factor and diagnostics without automatic reuse.

Independent review then admits the development admin service/Web upgrade. The
existing database, profiles, writer identity, state, socket and admin roster are
preserved. Actual saved administrator login returns 303 and the new creation form
returns 200. Private before/after readback confirms identical admin password
digests and factor bytes; no replacement credentials or registration are made.
The actual creation form, authorized with a later administrator TOTP, creates one
controlled pending mailbox and accepts one SMTP setup invitation to the owner's
privately supplied external contact. The retained mail transport observation
confirms remote-MX acceptance; recipient receipt remains unconfirmed. SQL
readback confirms disabled password/SMTP
access and one self-alias while setup is pending. External recipient delivery,
the owner-controlled password/authenticator enrollment and owner first login are
still PENDING. Do not resend or replay an unconfirmed/expired invitation through
an invented retry path. Public mail daemons/configuration remain unchanged.

The owner confirms external invitation receipt with a screenshot but rejects the
added development HTTPS port. This is not setup acceptance. Correct the active
slice to use the existing obsd1 HTTPS 443 entry point and existing ordinary web
listener; remove the added test TCP listeners and their exact temporary PF rule.
Use the existing admin proxy with a private Unix endpoint that is reachable from
the main proxy's actual chroot, preserving the Rust Web peer identity. The obsd1
ordinary frontend will deliberately serve the isolated development authority;
the authoritative production host and its public mail services remain untouched.
Preserve the original frontend/configuration for restoration.

Initial invitation origins now require a plain HTTPS hostname without an explicit
port, shared by configuration admission and SMTP submission. The email identifies
the account and setup page explicitly. Focused wire/invalid-origin regression
passes. The original controlled account remains disabled with its expired/exposed
invitation retained privately; there is no automatic reissue or state deletion.
Use a distinct controlled account only after the corrected 443 journey is ready.
This does not add a resend facility or replace the saved administrator credentials.
Corrected native installation/routing and owner acceptance are pending.

Standard-route correction: signed `2c53596` compiles natively in 52.34s. The
existing private admin proxy now listens on a Unix socket reachable from the main
proxy's verified chroot and UID. Preserve its first 403: Unix peer metadata is
not an IP address. A protected fixed local-hop header preserves the previous
loopback-hop identity. Preserve the first HTTPS 502, whose error record names the
old upstream during graceful reload. Fresh worker observation and actual HTTPS
admin login then PASS on standard 443. Backups are hash-verified; retain the
unsupported checksum invocation and Cargo-source hard-link guard refusals as
pre-effect staging failures. Installed binary leaves remain root-owned,
single-link and byte-matched.

The obsd1 development frontend now uses its existing web listener with the
isolated authority and standard hostname. Both login pages return 200. All added
test TCP listeners are stopped, and the exact temporary PF rule is removed;
the original 17-rule anchor reads back identically. Production mail is unchanged.
One authenticated check of this changed 443 composition fails with native auth
status 75 before a session. This is a backend error, not credential/TOTP denial.
Actual direct auth as the same UID, including matching arguments and cleared
environment, succeeds. The sealed frontend boundary remains unresolved; the
earlier private Inbox PASS does not qualify this corrected route. Existing error
consumption retained status but discarded the native diagnostic. Extend that
consumer only with fixed failure classes and stream byte counts, preserving
authentication decisions and private-output exclusion. Its private-marker
regression passes. No replacement invitation is sent before the corrected
authenticated journey passes; owner acceptance remains pending.

Signed diagnostic checkpoint `5fed618` compiles natively in 51.80s. Its next
actual standard-HTTPS password/TOTP check PASS (303); the owned Inbox PASS (200)
with the expected identity and real mailbox list, then logout PASS (303). Disable
the exact probe again. The diagnostic changes no authentication decision, so do
not attribute that pass or the earlier failure to a unique fix. The original
status-75 cause remains UNKNOWN because its old consumer discarded native text;
future unexpected exits now retain fixed classes and bounded stream accounting.

After those agent-owned checks and independent review, the saved administrator
signs in on standard 443 and authorizes one distinct controlled pending account
with a later fresh TOTP. Creation returns 201 and SMTP accepts its corrected
invitation with explicit account/code instructions and a plain HTTPS setup URL.
SQL readback confirms one disabled mailbox/SMTP record, self-alias and matching
operation digest. The original pending account remains disabled and untouched;
this is not reissue. The owner is asked to complete the restricted setup and
ordinary login through obsd1's normal HTTPS address. Corrected invitation receipt,
recipient-controlled verification, owner enrollment and first-login acceptance
remain PENDING. No additional port or replacement admin registration is used.

### Operator correction — reuse Forgot password, 2026-11-18

The owner rejects the separate invitation page and elaborate development fixture;
the previous invitation journey is **NOT_ACCEPTED**, not merely awaiting UAT.
Restore the original working OSMAP frontend and original admin writer configuration,
disable the invitation feature and stop its parallel private Dovecot, helper and
factor processes. Retain source, disabled pending accounts and failure evidence.
Those restoration readbacks PASS; the normal HTTPS addresses and saved admin
credentials are preserved. No more invitation or test-environment work is authorized
by this slice. The earlier native passes remain evidence of their limited scope.

The replacement business rule is explicit: the administrator establishes identity
and obtains the intended user's recovery email **offline**, then records it when
creating the new pending mailbox. Reuse OSMAP's existing **Forgot password**
routes, six-digit mail code, restricted recovery cookie, password form and local
TOTP enrollment. The email-code proof establishes control of the administrator's
recorded contact. No existing user password or factor is required for this
specifically authorized initial purpose. Existing-account recovery retains its
current eligibility and real prior-factor requirement.

Root owns integration, native authority and delivery; the Rust engineer extends
the existing recovery store and bounded native SQL backend; the UI engineer reuses
OSMAP's actual shield, controls and enrollment store; the independent reviewer
checks the trust boundary. One product outcome: admin-TOTP pending creation with
the offline-confirmed recovery address -> existing Forgot password -> six-digit
proof -> user password and proved initial TOTP -> ordinary native login. Store
the pending contact with its creation operation in the native account authority;
do not treat browser settings, a fabricated factor or missing factor alone as
bootstrap authority. Reuse the existing privileged account service and installer
utility in-process; retire the separate invitation store/page and standalone
factor service. No new Python, dependencies, services, ports or test framework.

Minimum checks: the existing shared recovery store accepts the initial purpose
only with a typed pending operation/revision and genuine native absence; registered
recovery cannot select it. Expired/wrong/replayed email proofs and changed
provisioning metadata refuse. The same native password backend gains a distinct
pending-account CAS; counter/factor publication precedes SQL activation, and SQL
activation consumes the provisioning row atomically. Reuse actual OSMAP form and
menu classes; leave the approved login unchanged. Run focused existing Rust tests,
one matching product composition test, independent review and mandatory delivery
hooks. Native qualification must use the existing deployment/backend contract;
do not create another fixture or claim production from a source test. Preserve
prior costs as UNKNOWN and all failures; two failures at the same boundary still
require combined reassessment.

Native integration gap found during independent review: the existing root account
service and admission service use equal fixed account rosters, and the frontend
may select one exact rollout account. A pending SQL row does not register a new
identity with either roster. Both initial setup and completed-contact recovery
now require the same roster/rollout admission before SQL eligibility. This
prevents completing setup for an identity whose ordinary login will refuse.
Automatic native account registration remains **NOT_IMPLEMENTED**; the corrected
installed enrollment/Inbox journey is **NOT_RUN**, not awaiting owner UAT. Do not
switch all existing users to native rollout as a shortcut. Keep `initial_setup`
false until matching real registration and backend prerequisites are satisfied.

The admin shell reuses the actual OSMAP shield, account menu, rail and controls.
Creation, Cancel, domain selection, save and return actions use the shared icon
labels; the existing Appearance icon/text choice also applies to the HTTP 201
creation receipt. The approved login renderer is unchanged. This is source
alignment, not new browser appearance acceptance.

Corrected source checks: shared recovery store 20 PASS; native access composition
5 PASS; password backend 17 PASS; epoch store 11 PASS; authenticator enrollment
9 PASS; factor replacement 10 PASS (one native-only case ignored); initial file
publication 5 PASS. The HTTP recovery scope passes all 11 cases after retaining
the earlier copy-assertion failure: the revised explanatory text had removed the
existing generic non-enumerating phrase, which is restored. Admin-filtered checks
pass 108 cases with 12 native-only cases ignored. A focused actual HTTP 201 receipt
regression also confirms the icon preference is applied. Strict all-target Clippy
passes; mandatory commit/push results and remote identity are delivery evidence,
not native qualification. Private terminal logs remain under the existing sprint
artifact root; no credentials, recovery addresses or raw mail are added to Git.
