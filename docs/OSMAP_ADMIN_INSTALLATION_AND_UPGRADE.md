# OSMAP-ADMIN Installation, Upgrade, and Recovery

**Repository path:** `docs/OSMAP_ADMIN_INSTALLATION_AND_UPGRADE.md`\
**Project:** OSMAP-ADMIN, OSMAP, and OpenBSD Mailstack\
**Version:** 0.1.0\
**Date:** 2026-11-13\
**Status:** Proposed, implementation-oriented operations specification. No installation, migration, production cutover, or PostfixAdmin retirement is authorized by this document.\
**Primary concerns:** Components, configuration, security, and repeatable verification.

> **Important status distinction:** The existing `openbsd-mailstack` installation scripts and OSMAP runtime are real repository assets. The native OSMAP-ADMIN installer, first-admin bootstrap, SQL schema migrations, and admin services described below are **target interfaces to implement**, not commands that are already available. Do not paste proposed commands onto a production host. This document specifies how they must behave and how their implementation will be qualified.

## 1. Purpose and governing documents

This specification defines the install, upgrade, maintenance, and recovery contract for a complete OpenBSD mail system that uses OSMAP for user webmail and OSMAP-ADMIN as the private administrative control plane. It is intended for clean deployments, existing PostfixAdmin-backed installations, and restoration of previously qualified systems.

Read it together with:

- [OSMAP-ADMIN project plan](OSMAP_ADMIN_PROJECT_PLAN.md), [system architecture](OSMAP_ADMIN_SYSTEM_ARCHITECTURE.md), [database design](OSMAP_ADMIN_DATABASE_DESIGN.md), [identity lifecycle](OSMAP_ADMIN_IDENTITY_LIFECYCLE.md), [security model](OSMAP_ADMIN_SECURITY_MODEL.md), and [UX specification](OSMAP_ADMIN_UX_SPECIFICATION.md).
- [Administrative engineering request](ADMINISTRATIVE_USER_MANAGEMENT_ENGINEERING_REQUEST.md), [PostfixAdmin parity issue #85](https://github.com/unattributed/OSMAP/issues/85), and [signed plan PR #84](https://github.com/unattributed/OSMAP/pull/84).
- [OSMAP OpenBSD deployment](DEPLOYMENT_OPENBSD.md), [OSMAP OpenBSD service integration](../maint/openbsd/README.md), [mail storage and quota](../maint/openbsd/MAIL_STORAGE.md), and [TOTP secret model](TOTP_SECRET_MANAGEMENT_MODEL.md).
- [`openbsd-mailstack`](https://github.com/unattributed/openbsd-mailstack) installation [index](https://github.com/unattributed/openbsd-mailstack/blob/main/docs/install/README.md), [install order](https://github.com/unattributed/openbsd-mailstack/blob/main/docs/install/09-install-order-and-phase-sequence.md), [core runtime renderer](https://github.com/unattributed/openbsd-mailstack/blob/main/docs/configuration/core-runtime-and-config-wiring.md), [SQL foundation](https://github.com/unattributed/openbsd-mailstack/blob/main/docs/03-mariadb-and-sql-foundation.md), [maintenance](https://github.com/unattributed/openbsd-mailstack/blob/main/docs/16-maintenance-upgrades-regression-and-rollback.md), and [backup/DR](https://github.com/unattributed/openbsd-mailstack/blob/main/docs/12-backup-and-disaster-recovery.md).
- [`openbsd-self-hosting`](https://github.com/unattributed/openbsd-self-hosting) for authorized, site-specific operational configuration; its private content must not be reproduced in the public OSMAP repository.

The public `openbsd-mailstack` repository supplies the **component topology, templates, and staged operator procedures**. Its OpenBSD 7.9 and PostfixAdmin/Roundcube references are historical implementation baselines, not permanent OSMAP-ADMIN version requirements or proof that a current live host still has those components. The private repository supplies deployment-specific context, not an alternative application identity authority.

## 2. Non-negotiable installation invariants

1. Discover the actual host release, package builds, configuration, service identities, active listeners, and SQL lookups at the time of installation or upgrade. Never infer them from an old repository document.
2. An installation must have **one authoritative mail-account database** and **one designated account writer** at any instant. Postfix and Dovecot remain SQL lookup consumers and native mail services; neither requires OSMAP-ADMIN to be online for an existing valid message to route or an existing account to authenticate.
3. The OSMAP webmail process and OSMAP-ADMIN web process remain distinct. The public mailbox-user session and TOTP factor never confer administrative privilege.
4. Fresh installations use the planned, versioned Rust-managed `osmap_mail` schema, with no PHP/PostfixAdmin prerequisite. A fresh installer may initialize the MariaDB *server* only through tools supported by the selected installed package, then the Rust migrator establishes the application schema.
5. Existing PostfixAdmin-backed deployments keep their selected, operational `postfixadmin` authority until a separately approved, rehearsed, single-writer cutover. No automatic import, schema replacement, or parallel database writer.
6. OSMAP's existing protected TOTP secret and replay stores remain authoritative for mailbox-user MFA; admin factors use a separate protected namespace. Database schema installation does not reset replay counters or silently rotate factors.
7. Existing account password hashes, canonical account identifiers, Maildir paths, quotas, alias semantics, message bytes, UIDVALIDITY, message UIDs, flags, subscriptions, and native identities must remain intact unless a separately authorized operation explicitly changes them.
8. The web tier has no privileged SQL write grant, database DDL grant, host shell authority, or TOTP store write access. The scoped Rust account service owns runtime account mutations; a separate, locally invoked migrator owns DDL and SQL grants.
9. Installation, release promotion, package update, schema migration, mail-account migration, recovery, and PostfixAdmin retirement are **separate decisions**. Running `syspatch` or `pkg_add -u` never implies permission to run a schema migration or switch databases.
10. A claim of success needs observed **Postfix routing, Dovecot authentication/userdb/quota, OSMAP login, private admin authorization, and restoration** as applicable. Package installation, green service status, or an HTTP 200 alone is not proof.

## 3. Component ownership and integration contracts

| Component | Owner / upstream | Configuration contract | Security and acceptance requirements |
| --- | --- | --- | --- |
| OpenBSD base, PF, `rcctl`, `doas`, `syslog`, `newsyslog` | OpenBSD Project / host operator | Actual release, kernel, errata, account UIDs/groups, service and firewall configuration | Trusted update source, limited control plane, non-root daemons, auditability, boot recovery |
| `openbsd-mailstack` deployment tooling | `unattributed/openbsd-mailstack` | Operator-input files, ignored `.work/` render trees, inspected staged configs, phase checks | Never treat sanitized example configs as live configs; no unreviewed overwrites |
| MariaDB | MariaDB Foundation and server maintainers / host operator | Actual socket, datadir, engine/version, backup mechanism, one selected account schema | Local-only or controlled access, explicit grants, verified backup/restore, no duplicate writers |
| Postfix | Wietse Venema and Postfix maintainers / mailstack operator | Effective `main.cf`, `master.cf`, SQL maps, submission/relay, aliases, queue | Narrow SQL lookups, strict recipient/routing tests, no implicit queue loss |
| Dovecot | Dovecot maintainers / mailstack operator | Installed passdb/userdb, auth and userdb sockets, Maildir/quota/Sieve configuration | Password hash compatibility, file UID/GID correctness, actual quota enforcement |
| nginx/TLS, PF/WireGuard | Respective project maintainers / host operator | Distinct public OSMAP and private admin routing; trusted hostnames and TLS | Admin is inaccessible from public OSMAP route; origin/Host, CSRF and network gate checks |
| Rspamd, Redis, ClamAV, FreshClam, optional OpenDKIM, relay | Respective maintainers / mailstack operator | Actual installed integrations and policy; optional modules only if enabled | Maintain anti-abuse semantics and avoid falsely marking unsupported components healthy |
| OSMAP `serve` | `unattributed/OSMAP` | Existing `_osmap` runtime and loopback browser listener | User-only sessions, Dovecot-backed identity, no admin route or SQL schema grant |
| OSMAP `mailbox-helper` and account-password services | `unattributed/OSMAP` | Permissioned local sockets, current Dovecot config/auth-bound state | Correct peer identity, narrow capabilities, account/session freshness; no competing account writer |
| OSMAP-ADMIN web (planned) | OSMAP-ADMIN | Dedicated private listener and admin session origin; Rust server-rendered OSMAP UX components | No mail-reading privilege or SQL write credentials; no public self-service bootstrap |
| OSMAP-ADMIN account/factor services (planned) | OSMAP-ADMIN | Typed local protocol, dedicated OS/SQL principals, protected factor store | Independently authorize role, target, revision, step-up and writer epoch on each operation |
| Rust schema migrator / `bootstrap-admin` (planned) | OSMAP-ADMIN | Local, one-shot, operator-authorized schema/grant/first-admin operations | Refuse unknown schema and partial bootstrap; privilege ends after run |
| Site-specific monitoring, backups, relay and recovery | `openbsd-self-hosting` or operator-owned infrastructure | Private paths, restore keys, topology, scheduled jobs and alerts | Must not leak private data into public repos or depend on historical host assumptions |

### 3.1 Configuration source precedence

The running host configuration and its authenticated service/process observations are the **current operational fact**. Signed, reviewed repository configuration is the **intended design**. Differences must be inventoried and resolved before any overwrite.

1. Preserve the target host's active configuration and record its state without exposing secrets.
2. Check the selected, versioned release and the operator-approved deployment profile.
3. Render new candidate configs into a private, ignored directory, then diff them against the actual configuration with secrets protected.
4. Apply only the explicitly approved changed files and grants. Never deploy a whole historical `rootfs` tree onto an active system merely to install OSMAP-ADMIN.
5. After application, compare the effective running configuration and service behavior, not just candidate template bytes.

`openbsd-mailstack` stages operator render output under `.work/runtime/rootfs/` and keeps `services/generated/rootfs/` as a **sanitized tracked example**. Its current public phase 03 and phase 08 include PostfixAdmin and Roundcube assets. A **new native OSMAP profile must be implemented and validated** before any unattended clean-install phase runner can be claimed to provision a PostfixAdmin-free OSMAP-ADMIN host. Until then, stage and reconcile each applicable phase; do not run the full legacy profile blindly.

## 4. Release-aware discovery and compatibility gate

OpenBSD has approximately semiannual release cycles; package updates follow the release/ports ecosystem and security and maintenance work. As of this document's date, OpenBSD **8.0** is the newly released stable generation (2026-10-20); the public mailstack repository still explicitly targets **7.9**. **Neither an 8.0 deployment pass nor a 7.9-to-8.0 in-place upgrade has been established for OSMAP-ADMIN.** Select support based on tests for the chosen target, not release-name matching.

### 4.1 Safe read-only host inventory

The following commands are illustrative **read-only discovery steps** for a suitably authorized OpenBSD operator. Run only on a selected host; review output before sharing because paths, hostnames and package inventory may be sensitive.

```sh
uname -a
sysctl kern.version
machine
pkg_info -a
pkg_info -mz
syspatch -l
syspatch -c
rcctl ls all
rcctl check mysqld
rcctl check postfix
rcctl check dovecot
rcctl check nginx
postconf -n
postfix check
doveconf -n
nginx -t
```

Not every command or daemon will exist on every installation, and `rcctl check` may return failure when a service is intentionally absent. The procedure must classify **not installed**, **disabled by design**, **present but failing**, and **unverified** separately. Do not assume package names or service identifiers from the examples; inspect the installed package service scripts and actual running processes.

For production diagnostics, collect **sanitized** output. In particular, do not publish `doveconf -n`, SQL map files, runtime environment files, credentials, client secrets, peer addresses, private grant keys, or raw service logs without review.

### 4.2 Versioned compatibility record

Each target produces a dated, immutable manifest with:

- OS release, architecture, kernel, patch list, and package origin/repository policy.
- Package name, full package version and flavor for MariaDB, Postfix, Dovecot, nginx and each required filtering component.
- Rust compiler/build toolchain pin, OSMAP commit, OSMAP-ADMIN commit, binary hashes, and configuration profile revision.
- Selected SQL schema version and migration checksums; Postfix SQL map and Dovecot passdb/userdb query dialects.
- Actual auth socket names/permissions, Maildir UID/GID, quota backend, TOTP paths and factor/replay formats.
- Verification result per feature and host, with **PASS / FAIL / UNKNOWN / NOT RUN** and sanitized evidence identifiers.

A new OpenBSD release or package build enters the supported matrix only after targeted tests, particularly if Dovecot changes configuration syntax or MariaDB upgrade changes catalog or data semantics. Do not silently pin stale package builds to satisfy the document.

## 5. Deployment modes and decision tree

| Mode | Entry condition | Database | Writer | Activation |
| --- | --- | --- | --- | --- |
| Clean lab install | Disposable OpenBSD instance, no existing mail identities or mail data | New `osmap_mail` (planned) | Rust account service after verified bootstrap | Lab-only until component and security tests pass |
| Clean production install | Operator-approved empty target, full restore plan, qualified release/profile | New `osmap_mail` | Rust account service | Separately approved deployment and first-admin acceptance |
| Existing PostfixAdmin installation | Existing operational mailserver and `postfixadmin` authority | Keep `postfixadmin` | Existing designated writer during read-only OSMAP-ADMIN rollout | No change of authority in initial deployment |
| Approved existing-schema writer takeover | Inventoried backend, reversible write freeze, approved cutover | Existing `postfixadmin` | Exactly one newly designated Rust writer | Explicit proof of competing-writer disablement |
| Approved native-schema migration | Rehearsed full mapping and reconciliation, write-freeze, restore gate | Move from `postfixadmin` to `osmap_mail` | Rust writer only after all consumers switch together | Separate maintenance change; PostfixAdmin remains recoverable |
| Restore / disaster recovery | Known good backup and explicit authority checkpoint | Restored chosen authority | Writer disabled until reconciliation and ownership proven | Controlled resumption after cross-service tests |

**Special Toronto/obsd1 rule:** Toronto's selected `postfixadmin` database remains authoritative. obsd1 has a separate writable development database and a read-only Toronto reference replica. Do not use the replica as a write target, assume its freshness, or treat obsd1 qualification as Toronto production acceptance.

## 6. Clean OpenBSD installation: ordered runbook

### Stage 0: Operator prerequisites and safety controls

Record intended hostname/domains, network plan, external DNS/relay accounts as used, service ownership, administrator identity and trusted out-of-band recovery channel. Confirm physical or console recovery, disk/filesystem capacity, storage encryption/backup custody and approved exposure policy. Select a supported OpenBSD release **only after** a compatibility matrix exists. Confirm a valid snapshot/restore path even for a new installation.

Use the [`openbsd-mailstack` install guide](https://github.com/unattributed/openbsd-mailstack/blob/main/docs/install/README.md) and its [QEMU-first path](https://github.com/unattributed/openbsd-mailstack/blob/main/docs/install/10-qemu-first-validation-path.md) for the host and mail substrate; these are reference workflows and must be adapted for native OSMAP-ADMIN rather than enabling legacy PHP application components by default.

**Gate:** the intended host is empty or fully inventoried, no old mail authority exists, package origins are trusted, time synchronization works, operator access is recoverable, and a bounded change window is approved.

### Stage 1: Host and essential network substrate

1. Install and patch the selected OpenBSD release using OpenBSD Project instructions appropriate to that release and architecture.
2. Establish operator SSH access, `doas`, PF default-deny rules, resolver, NTP/time policy, TLS/ACME and, where selected, WireGuard private administrative access.
3. Confirm no OSMAP-ADMIN TCP listener is public. Admin is loopback or explicitly private WireGuard HTTPS only; do not share a public OSMAP route.
4. Create distinct service identities, directories, socket access groups and log ownership after determining actual host UID/GID availability. Existing `_osmap` and `vmail` ownership must not be blindly reassigned.
5. Record tested restart and console recovery paths before enabling background services.

**Gate:** host network and firewall verification, trusted TLS, no unapproved admin listener, correct service confinement and logging.

### Stage 2: Install and validate mailstack components

Use the `openbsd-mailstack` phases as a **component dependency map**, not an instruction to deploy deprecated application components:

| Existing phase | Use in native OSMAP-ADMIN installation |
| --- | --- |
| 00 / 01, foundation and network | Retain validated input, PF, DNS, WireGuard and host patterns, subject to current OpenBSD release |
| 02, MariaDB foundation | Reuse service prerequisites and host SQL initialization checks; do **not** assume schema created |
| 03, PostfixAdmin | **Replace with native `osmap_mail` bootstrap profile**; skip PHP app setup, legacy setup password and PostfixAdmin schema on clean installs |
| 04, Postfix | Render SQL virtual domain, mailbox and alias maps against tested native projections |
| 05, Dovecot | Render tested SQL passdb/userdb, auth/userdb socket, Maildir, quota and Sieve rules |
| 06 / 07, TLS and filtering | Retain qualified components and per-version config syntax; use installed backends only |
| 08, Roundcube/PostfixAdmin web | **Replace with OSMAP public listener and OSMAP-ADMIN private listener**; do not install old PHP webapps as a native prerequisite |
| 09 through 17, DNS, operations, backup, monitoring, maintenance, security | Reuse appropriate verified modules and private operator inputs, without overwrite or phantom feature assertions |

Until the replacement profile is implemented and tested, this remains a **manual, staged installation plan** and not a promise that the current phase runner already supports a native no-PHP install.

In the repository, the real current renderer and checker commands are:

```sh
./scripts/install/render-core-runtime-configs.ksh
./scripts/verify/verify-rendered-config-integrity.ksh
 ./scripts/verify/run-post-install-checks.ksh --repo-only
```

These commands are to be run **from the `openbsd-mailstack` checkout**, not the OSMAP checkout. The first command may render site-specific secrets into gitignored `.work/runtime/rootfs/`; review before any copy or publication. The complete legacy phase application and `install-core-runtime-configs.ksh` are **not** approved clean OSMAP-ADMIN shortcuts.

**Gate:** exact Postfix and Dovecot packages/config syntax and SQL lookup integration are proven against the selected installation, and there is no dependency on a missing PostfixAdmin schema.

### Stage 3: MariaDB server bootstrap

1. Identify the installed MariaDB package version, command set, initialized data directory and actual local socket. Refuse ambiguous, populated or replicated targets without a reviewed existing-install path.
2. Use the version-appropriate, vendor-supported initialization process for a **new MariaDB instance**. Do not invent a universal `mysql_install_db` or `mariadb-install-db` command for every release.
3. Configure local socket access or tightly bounded transport; secure administrative account custody; prohibit remote root/admin access by default.
4. Verify server startup, selected storage engine, transaction behavior, character set/collation policy, SQL mode and filesystem owner. Define and test MariaDB backup/restore before schema creation.
5. Record the actual database version, selected socket, path, backup method and operator principal in a private host inventory.

**Gate:** clean MariaDB service and tested empty-instance restore path. No OSMAP-ADMIN schema exists yet, and no mail account authority is active.

### Stage 4: Native OSMAP-ADMIN schema, grants and integration (future installer)

The planned privileged local Rust migration utility must:

1. Require an explicit **fresh** installation mode and prove the intended `osmap_mail` schema is absent or exactly the expected empty bootstrap state. Refuse wrong host, wrong socket, unknown schema version, partial target or existing `postfixadmin` production authority.
2. Create the native schema in ordered, checksummed versions described in [database design](OSMAP_ADMIN_DATABASE_DESIGN.md), with a durable migration ledger and per-step verification. MariaDB DDL is not assumed transactionally reversible.
3. Create distinct restricted SQL identities for Postfix read projections, Dovecot passdb/userdb projections, the Rust writer and the locally invoked migrator. Revoke broad bootstrap privileges from runtime services.
4. Create distinct admin-identity/authorization state independently from mailbox rows, plus audit/operation journal and writer-epoch state.
5. Render or provide inspected, version-specific Postfix/Dovecot SQL lookup configurations without activating unverified changes. Validate recipient aliases and disabled states with disposable records.
6. Record a non-secret schema receipt with schema version, migration checksums, compatible application version and SQL grant *shape* without emitting credentials.

**Gate:** schema and grants verified, representative SQL projections match native behavior, only the designated account writer has runtime mutation privileges, and migration can be recovered from tested backups.

### Stage 5: Install OSMAP runtimes

1. Build or install a reviewed, version-pinned OSMAP binary and its required local support assets. Use the actual repository build/release and OpenBSD deployment instructions; never install an arbitrary workstation debug build as production evidence.
2. Keep `osmap_serve` running as the existing `_osmap` identity, loopback-only behind nginx. Start `osmap_mailbox_helper` at its isolated mailbox authority, normally `vmail`, using the verified Dovecot auth/userdb socket configuration.
3. Preserve established state roots, account epoch/credential-freshness policy, the protected TOTP secret directory, and separate replay store. Do not create blanket world-readable directories.
4. Ensure OSMAP's selected password-change/account service refers to the same authoritative database as the new Rust writer. No competing general account writer may remain.
5. Establish the OSMAP public route and browser identity, sessions and TOTP only after real Dovecot-backed login verification.

**Gate:** OSMAP's public browser path remains mailbox-user-only, helper socket ownership is correct, password/TOTP login works, and an unrelated local process cannot use the privileged mailbox helper.

### Stage 6: Install separate OSMAP-ADMIN runtimes (future implementation)

1. Install the reviewed admin web binary and typed account/factor services as **separate processes**, using independent OpenBSD users, sockets and state roots selected from the actual host.
2. Start scoped account and factor services before the admin web process; check peer identity, fixed protocol version, origin and bounded requests. Apply tested `pledge`/`unveil` and effective file/socket grants.
3. Configure a separate private nginx origin/hostname or equivalently isolated private route, with TLS, correct Host/origin/CSRF checks, HSTS where applicable, and PF/WireGuard access restrictions. Do not route public OSMAP paths to the admin process.
4. Give the web process **no** MariaDB writer password, DDL privilege, factor directory write privilege, direct mail content permission or ability to execute arbitrary mailstack commands.
5. Ensure service startup failures remain visible and do not open a fallback public listener or unauthenticated admin initialization endpoint.

**Gate:** separate admin authentication/sessions, private reachability, direct socket authorization refusal, and no privileged credential exposure in web process environment or logs.

### Stage 7: Bootstrap the first administrator (future implementation)

The first administrator can be created **before any domain or mailbox exists**. The bootstrap operation must be a local, one-shot privileged Rust command, not an unauthenticated browser route.

Required journey:

1. Confirm installed schema version, selected writer epoch, empty admin registry and authorized operator execution context.
2. Create an initially disabled **system administrator** identity, independent of any mailbox address, with a verified password-hash scheme and protected credential entry.
3. Generate a distinct, protected admin TOTP secret in the separate admin factor namespace. Present the enrollment material **only** via the trusted local setup session; do not persist it in terminal logs, URL, repository or audit.
4. Require a fresh TOTP proof, then atomically or through explicit recoverable steps activate the admin identity. Do not reset replay state or overwrite an existing factor.
5. Close and invalidate the one-shot bootstrap privilege, verify that a second bootstrap attempt refuses, and record non-secret audit correlation.
6. Sign in over the private admin surface with password and TOTP. Verify system scope through a read-only request and one authorized disposable action in a lab, plus direct-protocol denial for unprivileged clients.

**Gate:** first admin authenticated through the private control plane, no default credentials, and no web-accessible emergency first-admin bypass. Interrupted bootstrap requires local reconciliation and fails closed.

### Stage 8: First domain, mailbox, user TOTP, and end-to-end mail acceptance

1. Create the first domain with the authorized admin and confirm Postfix's **effective** virtual domain lookup, not only a new SQL row.
2. Create a disposable mailbox, compatible Dovecot password hash, stable Maildir mapping, required local-delivery alias and quota policy. Confirm effective Postfix recipient and Dovecot passdb/userdb results.
3. Establish a short-lived, one-time user setup authorization through a channel independent of prior mailbox access. The user enrolls their own TOTP seed; the administrator must not normally see it.
4. Distinguish pending **OSMAP browser** enrollment from native IMAP/SMTP credential availability. Browser MFA does not automatically protect native clients; test documented pending-native policy.
5. Verify actual browser password-plus-TOTP login, replay refusal, correct mailbox ownership, local test message delivery, alias/forward handling, quota enforcement, and session invalidation after the reviewed test credential change.
6. Remove only disposable fixtures under an authorized cleanup plan. Preserve postmaster/system aliases and all actual user mail data.

**Gate:** administrator and mailbox-user workflows pass separately, Postfix/Dovecot/OSMAP use one account authority, and recovery backups have a repeatable restore result.

## 7. Existing OpenBSD and PostfixAdmin-backed installation

**Default: non-mutating discovery.** Do not treat the established Toronto mailserver as a fresh install or run Phase 02/03/08 scripts to overwrite its database and web routes.

1. Inventory the real host, installed PostfixAdmin version/features, SQL tables/views/triggers/grants and all Postfix/Dovecot queries. Preserve secret-safe configuration and validated backup copies.
2. Identify every account writer: PostfixAdmin UI/API, OSMAP's password-change helper, SQL scripts, cron tasks, CLI utilities, and any administrative automation. The single-writer gate is **not** achieved by changing a banner or database name.
3. Deploy a **read-only** Rust compatibility adapter and private admin UI in a disposable rehearsal or authorized host view. Compare domain/mailbox/alias/active/quota projections to effective Postfix and Dovecot behavior.
4. Exercise admin login, factor namespace, RBAC, cross-domain refusal and audit without changing live domain/mailbox records.
5. If taking over writes against the **existing** `postfixadmin` schema, separately freeze legacy account writes, prove all alternate writers disabled or routed through the one Rust service, then enable the scoped writer at a recorded authority epoch. Maintain rollback readiness.
6. If changing to native `osmap_mail`, use a **separate** migration plan: consistent source snapshot, import, field-level semantic mapping, full key/digest reconciliation, bounded write-freeze, exact SQL consumer switch, negative and positive tests, rollback with post-switch delta handling.
7. Keep PostfixAdmin installed and recoverable until a **distinct retirement review** confirms parity, no remaining required PHP-only workflow, removal of old routes/grants and backup/restore success.

Never silently rewrite historical password hashes, account names, Maildir paths or TOTP files. Unrepresentable legacy rows and features are blocking, not reasons to drop data. The obsd1 Toronto reference replica remains read-only and cannot be promoted implicitly.

## 8. Routine weekly OpenBSD maintenance

**Established operator cadence:** `syspatch` and `pkg_add -u` are run **weekly**. Preserve that schedule. For critical security advisories, do not defer a necessary fix simply because the weekly window has not arrived; use a separately controlled expedited update.

OpenBSD distinguishes base-system errata from packages. `syspatch` applies supported binary patches to an official installed release; `pkg_add -u` searches for newer installed packages and their dependencies. Neither substitutes for a major OpenBSD release upgrade. Package availability and behavior follow the installed release and package repository. See [OpenBSD `syspatch(8)`](https://man.openbsd.org/syspatch) and [package FAQ](https://www.openbsd.org/faq/faq15.html).

### 8.1 Weekly preflight, before any changes

- Confirm target host, remote console/access and time window, free space, backup health and current mail queue state. Capture actual service/payload versions and DB schema version.
- Inspect planned errata and package candidates, especially MariaDB, Postfix, Dovecot, nginx, TLS libraries and Rust-linked dependencies. Incompatible changes require explicit testing; a routine weekly run does not waive this gate.
- Verify that the account writer and database authority are known, and no OSMAP-ADMIN migration/retirement task is scheduled implicitly.
- Take and test the appropriate **pre-update recovery point** for changes that can affect persistent state. A MariaDB data-format-changing upgrade needs a separately rehearsed restoration path, not just a binary copy.
- Ensure there is a bounded fallback path and a way to reauthenticate after package daemon restarts or a reboot.

### 8.2 Weekly commands and sequencing

On the **authorized OpenBSD host** (not on the developer workstation), the established operator operations are:

```sh
# Preflight, read only
syspatch -c
syspatch -l
pkg_info -a
postfix check
doveconf -n

# Apply, privileged, only after preflight and recovery checks
doas syspatch
doas pkg_add -u
```

`pkg_add -u` may update multiple dependencies, require operator choices, and change daemon binaries or startup assumptions. Use the installed OpenBSD documentation and observe command exit codes and messages. `syspatch` may require reboot to activate kernel/library fixes. The exact package action and reboot decision belong to the selected host's current advisories, not to this Markdown file.

The existing [`openbsd-mailstack` maintenance wrappers](https://github.com/unattributed/openbsd-mailstack/blob/main/docs/16-maintenance-upgrades-regression-and-rollback.md) may be used when current and reviewed. They must not add an unapproved automatic MariaDB major upgrade, schema migration, PostfixAdmin installation, account write, or OSMAP-ADMIN privilege change.

### 8.3 Weekly postflight and release gate

- Record the actual errata and updated package versions, and whether restart or reboot was performed; verify the resulting running process versions, not package metadata alone.
- Test MariaDB startup and **read-only** schema/lookup compatibility. If MariaDB's own on-disk/system-table upgrade is required, stop and follow the separate major database upgrade protocol in section 9.
- Run `postfix check`, check queue and controlled recipient/alias routing, and confirm submission behavior. Validate the installed Dovecot config with `doveconf -n`, test controlled userdb/passdb lookups and quota; handle installed version-specific CLI differences.
- Check nginx syntax and exact public OSMAP versus private admin route isolation; verify TLS, PF/WireGuard policy and unexpected-listener refusal.
- Verify OSMAP and OSMAP-ADMIN service startup, Unix socket ownership, admin RBAC, session invalidation, TOTP replay guarantees, and at least one controlled password-plus-TOTP path using a disposable account where permitted.
- Check audit and monitoring output, backup status, and unchanged single-writer status. **Do not classify a page load, database service ping, or a UI status label as proof of mail-service correctness.**
- Record PASS/FAIL/UNKNOWN/NOT RUN, anomalies and the selected corrective action. A failure does not trigger a blind schema downgrade or database swap.

### 8.4 Weekly maintenance checklist

| Check | Required outcome |
| --- | --- |
| Base patches | `syspatch` result, installed patches and reboot requirement recorded |
| Package updates | Full updated package set, dependencies and exceptions recorded |
| Configuration | No unreviewed changes to SQL maps, passdb/userdb, nginx, PF or service environments |
| MariaDB | Selected schema readable, correct writer and lookup grants, no automatic DDL |
| Postfix | Config check and controlled recipient, alias and delivery checks |
| Dovecot | Auth/userdb, Maildir, and quota behavior verified with installed-version commands |
| OSMAP | Public mailbox-user login, mail helper and session state functional |
| OSMAP-ADMIN | Private login, admin MFA, role/scope checks, no public exposure |
| Security | File/socket permissions, TOTP custody, audit records, firewall and TLS maintained |
| Recoverability | Valid restorable pre-change state and documented post-change decision |

## 9. Planned component upgrades, schema migrations, and release upgrades

### 9.1 Classify the change before executing

| Change | Permitted under normal weekly maintenance? | Additional approval/gate |
| --- | --- | --- |
| OpenBSD base `syspatch` within selected release | Yes, under established weekly window | Reboot/compatibility and postflight checks |
| Installed package `pkg_add -u` | Yes, under weekly window for reviewed compatible updates | Dependency/daemon and mailstack regression; stop on unverified major behavior change |
| OpenBSD 7.9 to 8.0 or future release upgrade | **No, separate planned release upgrade** | Official adjacent-release guide, QEMU rehearsal, remote console, backups, config merge and package upgrade |
| MariaDB major upgrade | **No, separate database upgrade** | Vendor upgrade path, complete backup + restore test, system-table/data-format compatibility and app regression |
| Dovecot 2.3 to 2.4-style configuration transition or other incompatible change | **No, separate compatibility change** | Effective SQL query, auth socket, password-scheme, quota, userdb and tool syntax verification |
| OSMAP/OSMAP-ADMIN binary update without schema change | Separate signed application deployment | API/IPC backward compatibility, session and factor preservation, rollback binary pair |
| OSMAP-ADMIN DDL or grants change | **Never implicit** | Signed migration, checksums, backup, exclusive migrator, readback and replay refusal |
| PostfixAdmin to `osmap_mail` account-authority migration | **Never implicit** | Full one-writer cutover, semantic reconciliation, rollback and explicit operator acceptance |

### 9.2 OpenBSD release-to-release upgrade

For OpenBSD 7.9 to 8.0, follow the official [7.9-to-8.0 upgrade guide](https://www.openbsd.org/faq/upgrade80.html). OpenBSD supports adjacent-release upgrades; the guide covers `sysupgrade`, `sysmerge`, configuration changes, package upgrades and reboot. Later release upgrades must use that release's actual guide. Do **not** attempt to implement a release upgrade with `syspatch` alone.

Before promotion, use a representative OpenBSD QEMU guest to rehearse all selected components and the installed OSMAP/OSMAP-ADMIN binaries. Confirm Dovecot and Postfix syntax, MariaDB data compatibility, service IDs, TLS, PF rules, rc script invocation, package hooks and OpenBSD confinement. Only then schedule the host upgrade with console/boot recovery and post-upgrade validation. Production mail preservation takes priority over feature activation.

### 9.3 MariaDB database server upgrade

A database server upgrade is not the same as an OSMAP-ADMIN schema migration. Read the selected vendor [MariaDB upgrade guidance](https://mariadb.com/docs/server/server-management/install-and-upgrade-mariadb/upgrading) and [`mariadb-upgrade` reference](https://mariadb.com/docs/server/clients-and-utilities/deployment-tools/mariadb-upgrade). Record whether the actual version transition requires `mariadb-upgrade`, data layout changes, engine/collation transformations, or downtime. Perform a complete, successfully **restored** backup on a representative target before attempting production.

Do not mix MariaDB major version changes with an OSMAP-ADMIN account-authority switch in one unbounded operation. Keep OSMAP-ADMIN account writes disabled or explicitly contained while state is unknown; ensure Postfix and Dovecot reader access matches the chosen change plan.

### 9.4 OSMAP-ADMIN schema/application upgrade

The intended Rust migrator must execute versioned, immutable, checksummed DDL steps with explicit preconditions and postconditions. Unknown versions, gaps, missing checksums, concurrent migration attempts and partial prior runs must fail closed. Runtime account writer credentials never run migrations.

Preferred approach: additive/compatible schema expansion, deployment of readers and services that recognize both old and new fields, verified rollout, then a separately reviewed contract/removal step. No automatic reverse DDL. All runtime protocol changes must be version-negotiated or deployed atomically at the local socket boundary. Session and factor stores require compatibility testing and never silent zeroing of replay counters.

### 9.5 Password change path after Dovecot configuration updates

OSMAP's selected native password-change/account service pins observed Dovecot configuration/authority. A Dovecot config change can invalidate that observation even when nginx responds normally. Follow the installed [OSMAP account authority refresh procedure](../maint/openbsd/README.md#account-authority-after-dovecot-configuration-changes) and verify that old/new password acceptance, session revocation and unrelated-user preservation still hold. This must not silently reactivate disabled password-change functionality or invent acceptance beyond the current qualified deployment.

## 10. Backup, restore and disaster recovery

### 10.1 Backup units and confidentiality

Back up, with access controls and a complete manifest:

1. OpenBSD base/package inventories, verified service binaries, rc scripts, PF/WireGuard/nginx, TLS configuration and host-specific operator inputs.
2. Authoritative MariaDB data, exact schema/migration ledgers, selected grants (sanitized for evidence), configuration, and position/checkpoint needed to reconcile later writes.
3. Postfix/Dovecot configuration, mail queue state where required, Maildir contents, userdb mapping, message/index/control identity, quota/Sieve state and user file ownership.
4. OSMAP binary/configuration, browser session/credential-epoch state, protected mailbox-user TOTP seeds and independent replay counters.
5. OSMAP-ADMIN binaries/configuration, admin identities and grants, admin-factor protected store, admin sessions, writer-epoch state, operation journal and audit integrity chain.
6. Recovery attestations, encryption keys and off-host restoration metadata under private operator custody. Do not insert secrets, hashes of low-entropy credentials, or sensitive raw logs into Git evidence.

The existing `openbsd-mailstack` scripts include `scripts/ops/backup-config.ksh`, `backup-mariadb.ksh`, `backup-mailstack.ksh`, `verify-backup-set.ksh`, and a conservative staged `restore-mailstack.ksh`. They require **extension and review** for native `osmap_mail`, new Rust service identities, admin factor/replay state, and any newly versioned schema. A historical passing backup does not cover new components by implication.

### 10.2 Recovery classification

| Failure | First protective action | Recovery rule |
| --- | --- | --- |
| Admin web unavailable, mail functioning | Keep public mail services and SQL authority unchanged; inspect private listener, service state and audit | Recover only admin web binary/socket/config; no database rollback |
| Rust writer unavailable | Prevent competing writes; preserve requested-operation journal | Reconcile ambiguous operations before retry, no PostfixAdmin dual-write fallback |
| MariaDB unavailable/corrupt | Contain writer; preserve data directories and logs; assess Postfix/Dovecot failure semantics | Restore from proven backup into isolated target, reconcile mail/identity deltas before authority switch |
| Dovecot auth/userdb mismatch after update | Stop unsafe account mutations; inspect effective config and auth sockets | Restore compatible config/service pairing and revalidate identities/quotas |
| TOTP secret or replay mismatch | Contain browser/admin activation and recovery path; preserve factor store | Never regenerate, overwrite or clear accepted counters to force success |
| Failed schema migration | Stop migrator and writer, preserve evidence and exact version ledger | Restore from pre-migration backup or apply separately reviewed forward repair; never assume reverse DDL |
| Incomplete first-admin bootstrap | Disable admin session activation, seal one-shot state | Local-only reconcile or restore; no default bypass credentials |
| Failed PostfixAdmin-to-native authority switch | Freeze all writers; capture post-switch writes and both database states | Restore only after reconciling deltas and changing all Postfix/Dovecot/OSMAP consumers together |
| Package/OpenBSD release regression | Preserve Maildir/database, record installed binary and configuration state | Use tested restore/rebuild; package downgrade may not reverse database on-disk changes |
| Full host loss | Isolate recovered instance/network and preserve backups | Rebuild host with matching qualified components, restore data/factors, test before public cutover |

### 10.3 Rehearsed recovery sequence

1. Declare incident/change scope, record last known writer epoch and trusted backup/checkpoint. Suspend administrative changes, not necessarily mail flow, while assessing safety.
2. Restore into a **disposable isolated OpenBSD target** using the intended package/build and file ownership. Keep external SMTP destinations and public listeners disconnected until authorized.
3. Restore database, configurations, mail data, TOTP seeds/replay state, audit ledger and operational keys **as a consistent authority point**. Do not reset a second-factor replay counter, invent new account IDs, or reuse a retired Maildir path.
4. Validate schema/checksum and writer fencing, Postfix recipient/alias maps, Dovecot auth/userdb/quota, OSMAP login/session effects and OSMAP-ADMIN admin login/scope.
5. Compare message identity and filesystem attributes, account counts, aliases, quotas, hashes and protected factor references to the recorded backup point. Reconcile writes/queue deliveries after that point before enabling the writer.
6. Activate the recovered instance only through an approved operational change. Preserve prior hosts and backups as read-only evidence until the operator accepts final state.

**Critical:** A simple SQL dump is not sufficient to recover mail data, TOTP, replay state, session epochs or admin authorization. A successful package reinstall is not a complete system recovery.

## 11. Monitoring, security and integrity after deployment

The selected deployment must expose non-secret, actionable health on:

- OpenBSD update/errata status, package age and a **weekly maintenance run outcome**.
- MariaDB engine/version, schema version and checksum, connection failures, backup/restore freshness and selected authority.
- Rust account writer health, fencing epoch, operation journal's pending/unknown outcomes and refusal of unknown schema.
- Postfix queue depth, recipient lookup failures, alias recursion, submission/relay failures and observed transport.
- Dovecot passdb/userdb/auth socket health, mailbox storage ownership, quota enforcement and login failure trends.
- OSMAP and OSMAP-ADMIN listeners, session revocation and bounded authentication failures; verify admin private-only exposure.
- Service user/socket modes and changes to `pledge`/`unveil` policy, PF rules, nginx routing and TLS certificate validity.
- Backup completeness and last **verified restoration**, not just backup file age.

Alerts distinguish a missing optional component from a required failed component. Audit logs carry actor, operation, target, scope, request ID, result and uncertainty, **not** passwords, TOTP codes/seeds, setup tokens, private keys or raw SQL credentials.

## 12. Acceptance gates

Use distinct evidence sets for **laboratory**, **installed host**, **operator UAT**, **production rollout**, and **retirement**. A code review or synthetic test does not satisfy another lane.

| ID | Acceptance requirement | Evidence |
| --- | --- | --- |
| INST-01 | Supported OpenBSD and component versions identified from target | Dated compatibility manifest and official release documentation |
| INST-02 | Native clean install succeeds without PostfixAdmin/PHP | Isolated fresh OpenBSD restore/rebuild, schema and services functional |
| INST-03 | Historic mailstack renderer not applied blindly | Approved native profile and staged config diff; old webapp phases excluded |
| INST-04 | MariaDB server initialized using supported installed tools | Server state, grants, backup and restore verified |
| INST-05 | Rust migrator creates `osmap_mail` exactly once | Version/checksum ledger, retry/partial-state refusal |
| INST-06 | Postfix virtual domain, mailbox and alias queries work | Native lookup and controlled delivery evidence |
| INST-07 | Dovecot passdb/userdb, Maildir and quota behave correctly | Real auth, path/UID/GID and over-quota refusal tests |
| INST-08 | First admin can be created before any mailbox | Local-only password+TOTP bootstrap with replay and second-run refusal |
| INST-09 | OSMAP-ADMIN web is private and independently authenticated | External-deny and WireGuard/loopback allow results; separate cookies/sessions |
| INST-10 | Rust web tier lacks privileged data/file grants | SQL grant audit, OS user/socket tests and confinement checks |
| INST-11 | Domain administrator cannot cross assigned domain | Direct service call negative tests, forged scope and stale revision denial |
| INST-12 | New mailbox user completes independently verified TOTP enrollment | Token expiry/replay refusal and user-held TOTP activation |
| INST-13 | Browser enrollment and native IMAP/SMTP states are not conflated | Pending-MFA versus native-client behavior demonstrated |
| INST-14 | OSMAP password change/session effects remain truthful | Authenticated old/new credential test, scope and session epoch evidence |
| INST-15 | Exactly one effective account writer | Writer inventory, SQL grants, fencing tests including legacy tool refusal |
| INST-16 | Existing `postfixadmin` retained until separately authorized switch | Read-only compatibility and no-change evidence |
| INST-17 | PostfixAdmin migration preserves hashes, aliases, quotas, mailbox identity | Full source/target semantic reconciliation and live sample behaviors |
| INST-18 | Weekly `syspatch` and `pkg_add -u` preserve operation | Before/after versions, patch list, regression and recovery decision |
| INST-19 | OpenBSD version upgrade separately qualified | Official adjacent-release guide + QEMU rehearsal and host acceptance |
| INST-20 | MariaDB major upgrade separately qualified | Full backup, successful restore, vendor upgrade procedure, app regression |
| INST-21 | OSMAP and admin sessions/factors survive intended updates | Replay, credential-freshness, revocation and recovery checks |
| INST-22 | Backup can restore complete integrated stack | Database, mail bytes, factors, audit, configs, identities, tested recovery |
| INST-23 | Partial/unknown install/migration state fails closed | Concurrency, interrupted DDL, missing file, wrong schema and wrong writer tests |
| INST-24 | Sensitive values absent from artifacts, logs and Git | Sanitized evidence review and secret scanning |
| INST-25 | Separate PostfixAdmin retirement gate satisfied | Operator acceptance, route/grant/job inventory, restore and monitoring |

No installation can be marked `PASS` while a required test remains `UNKNOWN` or `NOT RUN`. Report each incomplete test honestly and preserve observed evidence without overstating its portability to another host or release.

## 13. Required implementation artifacts and responsibilities

Before implementing this runbook as unattended automation, deliver:

1. **Native installation profile** in `openbsd-mailstack` that explicitly excludes PostfixAdmin/Roundcube from clean OSMAP-ADMIN installs, retains needed mail components, and validates rendered SQL maps without public credentials.
2. **Rust OSMAP-ADMIN migrator and bootstrap CLI** with version/host preflight, schema/checksum ledger, narrow SQL grants and local one-shot first-admin TOTP; command names and options to be frozen in a separately reviewed CLI specification.
3. **OSMAP-ADMIN OpenBSD service packaging and rc scripts** for web, account and factor services, including socket modes, `pledge`/`unveil` profiles and private nginx/PF integration.
4. **Compatibility manifest generator and gate**, resolving the actual OpenBSD and package versions, effective Postfix/Dovecot queries, SQL schema and application binary versions.
5. **Weekly maintenance integration**, preserving operator `syspatch` and `pkg_add -u` workflow with component-specific regression, alerts, and deliberate major-version escalation.
6. **Combined backup and restore tests**, extended to `osmap_mail`, admin identities/roles, audit, TOTP secret/replay stores, OSMAP state, Maildir and runtime configuration.
7. **Clean-install and existing-install E2E tests**, including admin/user MFA, schema failure, migration rehearsal, backup restore and single-writer proof.
8. **Public/private configuration partition**, with public-safe documentation in OSMAP and `openbsd-mailstack`, and secret/live host details retained only in approved private operator storage.

These are requirements for future engineering slices, **not assertions that the current repositories already implement all eight**.

## 14. Reference documentation and source of trust

**Primary vendor/maintainer documentation:**

- OpenBSD Project: [OpenBSD 8.0 release](https://www.openbsd.org/80.html), [7.9-to-8.0 upgrade guide](https://www.openbsd.org/faq/upgrade80.html), [`syspatch(8)`](https://man.openbsd.org/syspatch), [`pkg_add(1)`](https://man.openbsd.org/pkg_add), [package FAQ](https://www.openbsd.org/faq/faq15.html), [`rcctl(8)`](https://man.openbsd.org/rcctl), [`pledge(2)`](https://man.openbsd.org/pledge), [`unveil(2)`](https://man.openbsd.org/unveil).
- MariaDB Server maintainers: [deployment and upgrades](https://mariadb.com/docs/server/server-management/install-and-upgrade-mariadb), [upgrade guidance](https://mariadb.com/docs/server/server-management/install-and-upgrade-mariadb/upgrading), [`mariadb-upgrade`](https://mariadb.com/docs/server/clients-and-utilities/deployment-tools/mariadb-upgrade), [installation/upgrade best practices](https://mariadb.com/docs/server/server-management/install-and-upgrade-mariadb/deployment-general-installing-and-upgrading-instructions/best-practices).
- Postfix maintainers: [SQL lookup documentation](https://www.postfix.org/MYSQL_README.html) and [`postconf(5)`](https://www.postfix.org/postconf.5.html).
- Dovecot maintainers: [released documentation](https://doc.dovecot.org/latest/), [`doveadm auth`](https://doc.dovecot.org/main/core/man/doveadm-auth.1.html), and [`doveadm user`](https://doc.dovecot.org/main/core/man/doveadm-user.1.html). Use documentation matching the actual installed version; Dovecot's `main` docs may differ from a deployed version.
- OSMAP project: [GitHub repository](https://github.com/unattributed/OSMAP) and [OpenBSD deployment](DEPLOYMENT_OPENBSD.md).
- OpenBSD Mailstack project: [GitHub repository](https://github.com/unattributed/openbsd-mailstack), [install sequence](https://github.com/unattributed/openbsd-mailstack/blob/main/docs/install/09-install-order-and-phase-sequence.md) and [weekly maintenance guidance](https://github.com/unattributed/openbsd-mailstack/blob/main/docs/16-maintenance-upgrades-regression-and-rollback.md).

**Evidence rule:** The repository's current installation documents provide source-level planning evidence. Official upstream documentation governs tool semantics. Only target-host observations and tested recovery can establish that a particular binary/package/configuration combination is qualified on a particular OpenBSD installation.

---

**Proposed commit message:** `docs: specify osmap-admin installation upgrades and recovery with mailstack integration`
