# OSMAP-ADMIN project plan

Status: design baseline dated 2026-11-13, with the operator-requested execution roadmap dated 2026-11-17 below. The roadmap organizes implementation; it does not assert that specified features or tests are complete. This document authorizes no host change, account mutation, migration, deployment, or PostfixAdmin retirement. Each implementation slice needs its own bounded work order, review, and acceptance evidence.

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

## Execution roadmap — 2026-11-17

The operator prioritizes usable replacement functionality: **private admin
sign-in -> authorized mailbox list -> create a controlled mailbox -> prove native
authentication and message delivery**. This section is the single sprint/slice
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

Sprint numbers express delivery order, not dates, estimates or automatic live
authority. A sprint closes on its defined product outcome and applicable adverse
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
| Active product implementation slice | **NONE**; maximum one at a time |
| Selected next product slice | **ADM-S01-01**, private admin sign-in; NOT_STARTED |
| Other product slices | NOT_STARTED, development and mail native/browser tests NOT_RUN, operator acceptance NOT_ACCEPTED |
| Admin Argon2id credential feature | SCHEDULED within **ADM-S04-02**; implementation NOT_STARTED, development/mail tests NOT_RUN, acceptance NOT_ACCEPTED; not a prerequisite for ADM-S01 |

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
dependencies. Phase 1 already permits a seeded test admin. Such a lab can reach
the first mailbox journey without first building the native `osmap_mail`
migrator. This delivery ordering uses the existing
[Path A / Path B distinction](OSMAP_ADMIN_MIGRATION_AND_ROLLBACK.md#3-two-independently-approvable-migration-paths).
It does not waive Phase 2: native schema creation and offline first-admin
bootstrap remain required for clean-install acceptance in ADM-S05 and the full
replacement release. UX-A4's fresh-install gate is still enforced for that path.

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
that later enrollment journey. Status: NOT_STARTED / NOT_RUN / NOT_ACCEPTED.

| Slice and dependency | Target and existing UX mapping | Observable positive result | Required adverse counterpart and acceptance mapping |
| --- | --- | --- | --- |
| **ADM-S01-01 Private admin sign-in**; reuse ADM-F02/F03, inspect selected entry/config contracts | E0 -> isolated E2/E3 private HTTPS/service; UX-A0, UX-A1, UX-A2; UX-WF-01, UX-WF-15 | Password + TOTP produces a service-authorized admin session, a scope-bearing landing page and working logout; private state persists across the relevant restart | Wrong/replayed factor, mailbox cookie, forged service actor, foreign origin and untrusted client-address headers refuse. T:F-04, T:SEC-01–06, T:SEC-08, T:SEC-11, T:INT-14, T:INT-17–20, T:INT-23, T:UX-01–04, T:UX-09 |
| **ADM-S01-02 Authorized mailbox list**; depends on ADM-S01-01 | E2/E3 real reader + browser; UX-A3 | Choose an authorized existing domain; bounded list/filter/detail and truthful empty/unavailable states match authoritative metadata without password/hash exposure | Domain substitution, foreign counts/details, SQL/HTML inputs and read-only direct POST refuse; unavailable backend is not an empty list. T:F-07, T:F-30, T:F-32, T:MIG-06, T:SEC-09, T:SEC-13, T:SEC-18–21, T:UX-07–11 |
| **ADM-S01-03 Controlled mailbox creation**; depends on ADM-S01-02 and verified lab writer/native contracts | E2/E3 designated lab writer only; UX-A5, UX-WF-04, UX-WF-14 | Browser form -> scoped Rust service -> known committed mailbox, self-delivery alias, Maildir/UID/quota projection and audited receipt; new credential generation reuses the qualified supported scheme; browser MFA stays pending | Duplicate/canonical collision, foreign domain, stale revision, missing step-up/CSRF, competing writer, invalid quota and repeated/ambiguous operation refuse or retain reconciliation state without duplicate or partial success. T:F-08–09, T:F-26, T:F-31–32, T:DB-04–10, T:DB-13–15, T:DB-19, T:SEC-07, T:SEC-09, T:SEC-11–14, T:SEC-26–28, T:UX-06–10, T:RES-03–05 |
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
| **ADM-S02 Domain and mailbox management**: supported settings have proven native effects | **ADM-S02-01** domain create/edit/disable; depends on ADM-S01-03 auth/writer foundation; scheduled after ADM-S01-04; E2/E3 | UX-A5; UX-WF-03; T:F-05–06, T:DB-04–07, T:INT-03, T:SEC-07, T:SEC-09, T:UX-06–10 | Domain form changes actual Postfix recognition and preserves dependants; duplicate, invalid or unauthorized change leaves authority intact |
| ADM-S02 | **ADM-S02-02** mailbox display/state/password operations; depends on ADM-S01-03 and verified native/session contracts; scheduled after ADM-S02-01; E2/E3 | UX-A5, UX-A6; UX-WF-08–09; T:F-13–14, T:F-16–17, T:F-26, T:INT-06, T:INT-15, T:SEC-05, T:SEC-12–15, T:RES-02, T:RES-08 | Edit/reset/disable/reactivate has documented native-auth, delivery and session effects; old password, stale step-up, forbidden target and accidental factor reactivation refuse |
| ADM-S02 | **ADM-S02-03** domain limits, mailbox quota/usage; depends on ADM-S01-03 writer and verified quota consumers; scheduled after ADM-S02-02; E2/E3 bounded data | UX-A5, UX-A7; UX-WF-06; T:F-22–23, T:INT-07, T:INT-10–11, T:UX-08–10 | Quota/limits persist with correct units and real over-limit enforcement; limit races/overflow refuse, unknown usage is displayed as unavailable |
| **ADM-S03 Alias and routing administration**: required forwarding works without losing local delivery | **ADM-S03-01** alias list/create/edit/disable/remove and multi-recipient forwarding; depends on ADM-S01-03 writer and verified map/alias contracts; scheduled after ADM-S02-03; E2/E3 | UX-A3, UX-A5; UX-WF-07; T:F-18–19, T:F-21, T:INT-04–05, T:SEC-09, T:SEC-32, T:RES-01 | Native map expansion and bounded local delivery match source/destinations; loop, foreign-source edit, reserved/self-alias removal and conflicting revision refuse |
| ADM-S03 | **ADM-S03-02** installed catch-all/alias-domain variants; depends on ADM-S03-01; E2/E3 | UX-A5, UX-A7; UX-WF-07; T:F-20–21, T:F-33, T:INT-03–05 | Enabled required variants have real routing proof; collisions/unsupported variants are refused, and any nonapplicability/deferment has explicit installed-feature disposition |
| **ADM-S04 Identity and retention lifecycle**: users/admins enroll and recover safely; retirement preserves ownership | **ADM-S04-01** owner enrollment and first OSMAP login; depends on ADM-S01-03; normally scheduled here, brought forward before ADM-S01-04 if its pending-MFA policy requires; E2/E3 | UX-A6; UX-WF-05; T:F-09–12, T:F-34, T:INT-12–13, T:SEC-16–17, T:SEC-34, T:UX-12, T:RES-06–07 | Independently delivered single-use setup and user-held TOTP reach owned OSMAP Inbox; expired/replayed/cross-account setup and factor overwrite refuse |
| ADM-S04 | **ADM-S04-02** administrator enrollment, grants and own credential lifecycle, including Argon2id; depends on ADM-S01-01 and service-held writer/epoch contracts; scheduled after ADM-S04-01; E2/E3 | UX-A6; UX-WF-11, UX-WF-15; T:F-04, T:F-14, T:F-24–26, T:F-35, T:SEC-05, T:SEC-10–16, T:SEC-31, T:REC-09 | New/explicitly changed admin credentials use qualified Argon2id with legacy bcrypt verification retained; domain grants and revocation work; wrong/unsupported hashes, excessive work, privilege escalation and old-session resurrection refuse |
| ADM-S04 | **ADM-S04-03** factor rotation/revocation/recovery; depends on ADM-S04-02; E2/E3 | UX-A6; UX-WF-10; T:F-12, T:F-15, T:SEC-14–17, T:SEC-28, T:SEC-31, T:REC-05–09, T:RES-02, T:RES-06–08 | Approved transition has safe factor/replay/session readback; missing attestation, concurrent reset and interrupted follow-up stay refused or contained |
| ADM-S04 | **ADM-S04-04** mailbox/domain retirement and address reissue; depends on ADM-S02-02, ADM-S03-02 and ADM-S04-03; E1/E2 synthetic retained mail | UX-A6, UX-A7; UX-WF-12; T:F-27–29, T:DB-05, T:INT-11, T:REC-10, T:REC-19 | Staged retirement preserves mail/history and reissue gives a new owner no prior access; dependent domains, unsafe purge and inherited identity refuse |
| **ADM-S05 Standalone Rust installation**: clean installation reaches the same working admin/user journey without PHP | **ADM-S05-01** native schema/grants/migrations; requires reviewed DDL/grants/projections, actual MariaDB capabilities and restore; scheduled after ADM-S04-04; E1 empty disposable authority | UX-A4; T:F-01, T:DB-01–03, T:DB-08–11, T:DB-16–20, T:OPS-01–03, T:REC-02–04 | Vendor-initialized MariaDB plus Rust migrator produces correct native projections; populated/unknown/checksum-mismatched or interrupted schema refuses or restores |
| ADM-S05 | **ADM-S05-02** offline first admin and clean first domain/mailbox/enrollment; depends on ADM-S05-01, ADM-S01-04, ADM-S02-01, ADM-S04-01 and ADM-S04-02; E1 | UX-A4, UX-A6; UX-WF-02; T:F-02–04, T:F-08–12, T:F-35, T:INT-05–08, T:INT-12–14, T:OPS-03 | First admin exists before a mailbox; private UI then provisions/enrolls a working user; concurrent/repeated/partial bootstrap and public bootstrap route refuse |
| **ADM-S06 Replacement parity and operations**: every required feature and recovery path has a disposition and evidence | **ADM-S06-01** scoped audit/search, native CLI and installed conditional modules; depends on ADM-S02-03, ADM-S03-02 and ADM-S04-04 operations; scheduled after ADM-S05-02; E1/E2/E3 | UX-A7; UX-WF-13–15; T:F-26, T:F-30–34, T:SEC-25–28, T:UX-03–05, T:UX-13–14 | Browser and CLI reach the same scoped service; audit/journal distinguish known/uncertain effects; each required optional backend works; secret/foreign audit access and unsupported actions refuse |
| ADM-S06 | **ADM-S06-02** backup/restore, service/upgrade and continuity; depends on ADM-S06-01 and ADM-S05-02; E1/E3 | UX-A7, UX-A8; T:DB-18, T:INT-15–26, T:REC-01–20, T:OPS-01–10, T:RES-09–16 | Actual isolated restore and maintenance preserve mail, factors, writer authority and public/native journeys; stale data, unknown compatibility and split authority prevent promotion |
| ADM-S06 | **ADM-S06-03** release-candidate end-to-end/security/accessibility and owner UAT; depends on ADM-S06-02; E1/E3, E4 read-only | UX-A8 and all implemented UX-WF; T:UX-01–14, applicable T:SEC-01–36 and T:RES-01–16; test-plan G0–G5 | Applicable workflows, WSTG, direct-service negatives and accessible browser journey pass for the exact candidate; any required FAIL/NOT_RUN/UNCERTAIN blocks that release claim |
| **ADM-S07 Production replacement and retirement**: transfer one writer, prove continuity, then retire the old interface | **ADM-S07-01** Path A representative rehearsal; depends on ADM-S06-03; E2/E3 | UX-A7, UX-A8; T:MIG-01–11, T:MIG-17–18, T:DB-12, T:REC-11–12 | Legacy writer fencing, Rust writes, native mail and rollback before/after new writes are proven; stale writer connections and unreconciled rollback refuse |
| ADM-S07 | **ADM-S07-02** separately authorized Path A installation/cutover; depends on ADM-S07-01 and explicit production authority; E4 -> E5 | UX-A7, UX-A8; T:MIG-07–11, T:INT-15–26, T:PROD-01–18 | Exact installed Rust writer and private UI pass approved smoke/observation with one mail authority; any ambiguous writer, regression or unsafe rollback prevents acceptance |
| ADM-S07 | **ADM-S07-03** optional Path B data-authority migration; depends on ADM-S06-03, ADM-S05-02 and explicit Path B selection; its own E2/E3 full rehearsal before authorized E5 | UX-A4, UX-A7, UX-A8; T:MIG-12–17, T:DB-12, T:REC-02–04, T:REC-11–12, T:PROD-01–18 | Reconciled native authority and every consumer converge with preserved mail/state; deltas, interrupted switches and unsafe downgrade refuse. Path B may replace ADM-S07-02 only under an explicit approved alternate cutover; retaining the existing database is valid Path A |
| ADM-S07 | **ADM-S07-04** separately authorized retirement; depends on accepted ADM-S07-02, or selected/accepted ADM-S07-03, stable observation and retained recovery; E4 -> E5 | UX-A7, UX-A8; T:MIG-18–20, T:F-33, T:INT-24–25, T:PROD-16–18 | Required functions, jobs, grants and routes no longer depend on the old interface/PHP; only approved legacy components retire; remaining dependency, missing parity or unsafe recovery blocks retirement |

### ADM-S04-02 feature — Argon2id administrator credentials

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
| P:DOM-10–12; P:USR-12–13; P:SEC-11–12; P:MAIL-01–07; P:SYS-01–04, P:SYS-07–13 | ADM-S06-01 conditional feature disposition/implementation; SYS-08 native Rust CLI is P0 and cannot be deferred as optional |
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
- **Results/status:** implementation NOT_STARTED; mapped integration/native/
  browser cases NOT_RUN separately in development and on mail; operator
  acceptance NOT_ACCEPTED. No new admin UI is
  running. Future known gaps name a concrete owner/next action without hiding
  completed useful work or marking a declaration as a result.

### One active slice, work orders and delivery

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
