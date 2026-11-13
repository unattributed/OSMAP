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
3. A local, one-shot Rust `bootstrap-admin` command creates the first disabled system-admin identity independently of mailbox creation. It establishes an admin password using a reviewed verifier/hash policy and produces a TOTP enrollment on a trusted local terminal. Only after proof of possession of a fresh code, protected no-overwrite factor installation, and readback does it activate the admin and close the one-shot bootstrap capability. Interruption, concurrent invocations, and partial factor installation fail closed and require local reconciliation; no web-accessible unauthenticated bootstrap endpoint exists.
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
