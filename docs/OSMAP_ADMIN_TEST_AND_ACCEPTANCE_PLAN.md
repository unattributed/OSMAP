# OSMAP-ADMIN Test and Acceptance Plan

**Status:** Proposed acceptance baseline, version 0.1.0\
**Date:** 2026-11-13\
**Repository destination:** `docs/OSMAP_ADMIN_TEST_AND_ACCEPTANCE_PLAN.md`\
**Scope:** Functional, integration, security, OWASP WSTG, failure/recovery, migration and production acceptance\
**Product state:** Specification only. No claim that OSMAP-ADMIN services, APIs or test cases are implemented, executed or accepted.

## 1. Purpose, authority and interpretation

This document defines how to prove that OSMAP-ADMIN works as a secure administrative control plane for OSMAP and an OpenBSD mailstack. It is an executable test specification: test IDs, prerequisites, actions, authoritative observations, negative paths, expected results, evidence and release decisions. A test harness, passing unit suite, source inspection, screenshot or SQL row alone is **not** a completed native user journey.

The following OSMAP repository documents define the design contracts. When implementation changes one of them, reconcile this plan instead of silently weakening an expected outcome:

1. `docs/OSMAP_ADMIN_PROJECT_PLAN.md`, on the approved project-plan branch and tracked for integration into the repository.
2. `docs/OSMAP_ADMIN_SYSTEM_ARCHITECTURE.md`.
3. `docs/OSMAP_ADMIN_DATABASE_DESIGN.md`.
4. `docs/OSMAP_ADMIN_IDENTITY_LIFECYCLE.md`.
5. `docs/OSMAP_ADMIN_SECURITY_MODEL.md`.
6. `docs/OSMAP_ADMIN_UX_SPECIFICATION.md`.
7. `docs/OSMAP_ADMIN_INSTALLATION_AND_UPGRADE.md`.
8. `docs/OSMAP_ADMIN_MIGRATION_AND_ROLLBACK.md`.
9. `docs/ADMINISTRATIVE_USER_MANAGEMENT_ENGINEERING_REQUEST.md`, `docs/TOTP_SECRET_MANAGEMENT_MODEL.md`, `docs/UX_FULL_FUNCTIONAL_EPIC.md`, `docs/UX_DECISIONS.md` and the locked UX reference bundle.
10. PostfixAdmin functional parity and acceptance inventory in OSMAP GitHub issue #85.

These seven preceding OSMAP-ADMIN files are locally authored design artifacts. Their repository destinations are intended paths, not proof that they have already been committed. The plan must be reconciled to the exact committed source revision before engineering tests begin.

**Primary cross-project boundary:** `openbsd-mailstack` provides components, configuration patterns, maintenance and public-safe installer examples. `openbsd-self-hosting` provides private deployment-specific context. OSMAP owns the existing browser, credential and factor integrations. OSMAP-ADMIN owns a new private administrative service and, only after explicit cutover, administrative account mutations. The installed OpenBSD, package and schema capabilities determine compatibility; historical release numbers do not.

### 1.1 Acceptance invariants

- Exactly **one authoritative mail-account database** and **one designated administrative writer** per installation. PostfixAdmin, OSMAP credential helpers, maintenance automation and OSMAP-ADMIN must be inventoried and fenced as applicable.
- Postfix and Dovecot consume narrowly granted SQL lookups against that same authority. No mail transport process calls the OSMAP-ADMIN web frontend to deliver or authenticate mail.
- OSMAP remains mailbox-owner webmail. OSMAP-ADMIN has separate administrator identities, factors, sessions, origin, privileges and audit. A mailbox cookie cannot become an administrator credential.
- OSMAP browser TOTP does **not** automatically enforce MFA for native IMAP/SMTP. Record and test the installed native authentication policy separately.
- No administrative web process has account-table write grants, schema DDL, mail content, private OpenPGP key or arbitrary shell access.
- Every successful mutation has an authenticated, authorized, auditable and idempotent account-service result, SQL readback and applicable native lookup result. A multi-store intermediate state is not success.
- Existing mail, Maildir identities, password hashes, virtual domains, aliases, quotas, TOTP stores, accepted factor counters and active connection limitations are preserved or explicitly dispositioned through a separately approved change.
- PostfixAdmin writer handover, native-schema migration, legacy-interface retirement, OpenBSD release upgrade and weekly package maintenance are **distinct changes** with distinct tests.
- No live operator action, account change, migration, writer cutover or service restart is authorized merely by the existence of this document.

## 2. Test method and result semantics

### 2.1 Result vocabulary

| Status | Exact meaning |
| --- | --- |
| `PASS` | The asserted product outcome, negative counterpart and required authoritative readback have been observed on the named environment and version. |
| `FAIL` | A required expectation was contradicted; preserve the earliest relevant failure and exact impacted boundary. |
| `BLOCKED` | A specific prerequisite or test fixture is unavailable. Record its owner, cause and untested assertion. Do not convert to PASS. |
| `NOT_RUN` | Not attempted; no conclusion about implementation quality. |
| `NOT_APPLICABLE` | An explicitly absent capability or deployment mode is proven outside scope with a rationale. |
| `UNCERTAIN` | The effect could have committed but cannot be proved. Contain, reconcile, and prevent blind retries. |

For each test, record **expected**, **observed**, **authoritative proof**, **cleanup**, and **result**. A test that only checks HTTP 200/303, a simulated object or a green UI banner cannot close a database, SMTP, IMAP, MFA, rollback or recovery assertion.

### 2.2 Minimum test record

```text
case_id:
design_requirement:
test_run_id:
environment_and_host_role:
source_commit_and_signed_artifact_digest:
installed_os_arch_and_component_versions_observed:
config_and_schema_fingerprint_redacted:
identity_role_scope_and_fixture_ids:
preconditions:
actions_and_failure_injection_if_any:
expected_http_or_service_result:
expected_authoritative_sql_or_factor_state:
expected_postfix_dovecot_or_os_observation:
actual_result_and_first_failure:
audit_or_operation_id:
sanitized_evidence_locations_and_checksums:
cleanup_result_and_remaining_owned_artifacts:
status:
reviewer_and_date:
```

Use fixed error codes and bounded diagnostic classes, not raw mail, passwords, TOTP seeds, cookies, tokens, SQL credentials or private key material. Retain the first failure before cleanup. Cleanup PASS never turns a functional FAIL into PASS. Record the actual command/process exit status and important negative observations.

### 2.3 Test sequence, without unnecessary gates

1. Inspect the changed source and selected host integration contract; identify the smallest test for the changed product boundary.
2. Run focused Rust unit/property/contract tests and the smallest actual integration journey that proves the change.
3. Expand into end-to-end positive and adverse journeys on disposable accounts and the installed integration environment.
4. At release, run the full applicable regression, WSTG, migration, recovery and host evidence gates.
5. Before promotion, independently verify the exact binaries, configuration, grants, effective service state and remaining defects.

Do not add artificial memory limits, fixed patch-level requirements, expired calendar-based authority, blanket full recompilation between milestones or unnecessary mail outages. Respect the existing OSMAP `AGENTS.md` ruling that tests prove the **product**, rather than merely validating the test machinery.

## 3. Environments, scope and authorization

| Environment | Purpose | Permitted outcomes | Restrictions |
| --- | --- | --- | --- |
| `E0` Rust local/unit | Parsers, normalization, authz, state machines, SQL models and rendering | Fast deterministic unit and property tests | No claim of live SQL, mail or host qualification. |
| `E1` Disposable OpenBSD lab, preferably QEMU | Full fresh install, grants, mail delivery, failures, restores and destructive security tests | Native end-to-end product and fault tests | All accounts, domains, credentials, mail and backups synthetic. |
| `E2` Isolated PostfixAdmin compatibility fixture | Realistic legacy schema copies and controlled writer/cutover rehearsals | Path A and Path B data/migration proof | Snapshot and sanitize; never modify Toronto reference or live shared state. |
| `E3` Development integration host | Actual Rust, MariaDB, Postfix, Dovecot, nginx, PF/WireGuard and OSMAP | Installed-host functional/regression acceptance | Development database remains independent; a Toronto reference replica is read-only. |
| `E4` Production read-only preflight | Actual versions, maps, grants, routes, integrity, backups, access controls | Nonmutating compatibility and release readiness facts | No production account creation, password reset, migration, destructive tests or service interruption. |
| `E5` Production after separately authorized installation/cutover | Limited synthetic smoke, actual readback, monitoring and rollback readiness | Production acceptance for selected mode | Explicit scoped authorization, controlled fixtures, retained recovery capability. |

Capture the actual host role in every record. **obsd1 is not Toronto**. A PASS on obsd1, on a read-only reference replica, in an HTTP mock, or against a legacy sample schema is not proof about the Toronto production writer. Never route development write traffic to a production-referenced SQL identity.

### 3.1 Fixtures and identities

Create a dedicated, safely disposable test domain `a.test.invalid` and second domain `b.test.invalid` (or locally delegated equivalent), with valid synthetic mail addresses and an isolated MX/transport policy. The `.invalid` domain names are documentation placeholders; the lab must use a routing arrangement that works locally without sending test mail to real external recipients. Define:

- `SA1`, `SA2`: two independent system administrators, with separate TOTP and recovery authority.
- `DA-A`, `DA-B`: domain administrators scoped only to A and B.
- `U-A1`, `U-A2`, `U-B1`: mailbox users; one enrolled, one pending, one enrolled in the other domain.
- `U-SUSP`, `U-RET`, `U-REISSUE`: suspended, retired and address-reissue cases.
- Alias fixtures: local delivery alias, multi-recipient, external forward, catch-all, alias domain, loop, collision and disabled domain.
- Distinct Maildirs with known message byte digests, UIDVALIDITY, UIDNEXT, flags, subscriptions and quotas; keep baseline copies outside the tested root.
- Protected factor material and replay state under the selected independent test identity namespaces. Never reuse real TOTP secrets.
- Disposable native IMAP and SMTP client contexts, alternate browser sessions, stale session tokens, stale revisions and two concurrent writer requests.

Track fixture ownership, creation and cleanup. Never assume a fixture is disposable based solely on its name; prove its target account ID, database, host, Maildir and retention boundaries before mutation.

## 4. Traceability and feature coverage

Every implemented route, typed service operation, SQL table/projection, role capability, lifecycle transition, Postfix/Dovecot integration and recovery operation needs at least one positive and one adverse test where the operation has a security or data-integrity consequence. The coverage inventory must map:

`source file/route or command -> requirement ID -> test case ID -> environment -> execution evidence -> defect or acceptance disposition`.

Also map every applicable item of GitHub issue #85 by its feature family: `DOM`, `USR`, `ALS`, `ADM`, `SEC`, `MAIL`, `SYS`. Do not claim PostfixAdmin parity merely because common domain/mailbox/alias CRUD works. For each feature mark `implemented-and-tested`, `not-applicable-by-accepted-decision`, `blocked`, or `missing`. Unsupported legacy optional modules cannot be silently described as retired.

| Design source | Required proof families |
| --- | --- |
| System architecture | Separate process identities, Unix socket trust, private listener, SQL/native data flow, no mailbox-content access. |
| Database design | Versioned schema, table relationships, unique/canonical keys, grants, writer fencing, operation journal, backup. |
| Identity lifecycle | Provisioning, pending/enrolled TOTP, password update, native/client effects, suspension, recovery, reissue, retirement. |
| Security model | Authentication, RBAC, per-object scope, step-up, sessions, audit, threat mitigations, denial by direct service client. |
| UX specification | Reused OSMAP presentation system, native server forms, accessibility, honest states, no-JavaScript workflows. |
| Installation and upgrade | Components, effective configuration, package maintenance, first-admin bootstrap, upgrades and full recovery. |
| Migration and rollback | Data preservation, Path A writer handover, Path B schema transition, unknown-state recovery, retirement. |

## 5. Functional acceptance cases

Each table row is an independently identifiable test. Tests involving mail-account mutation require account-service receipt, authoritative readback and native lookup observation unless the row describes a pre-commit refusal.

| ID | Action and expected product result |
| --- | --- |
| F-01 | Local fresh install with empty MariaDB authority creates `osmap_mail` using the reviewed migrator, version/grant records and no PostfixAdmin/PHP dependency. |
| F-02 | Offline first-admin bootstrap is available before a mailbox/domain exists; disabled admin becomes active only after verified own password and TOTP possession. |
| F-03 | A repeated, interrupted or concurrent first-admin bootstrap does not create a second uncontrolled superuser or expose a web bootstrap endpoint. |
| F-04 | Separate administrator password+TOTP login issues an admin-scoped session; wrong/absent factor denies access and leaves no privileged session. |
| F-05 | Add, inspect, modify and disable a hosted domain; the relevant Postfix domain projection changes as expected, including after restart. |
| F-06 | Duplicate or canonically equivalent domain names are rejected without a second row, alias collision or misleading UI receipt. |
| F-07 | Domain admin can list and manage assigned domains only; foreign domain detail, count and search filters do not leak data. |
| F-08 | Create mailbox with compatible initial password hash, native maildir, quota and expected self-delivery alias, without giving the admin a browser session as that mailbox. |
| F-09 | A newly created mailbox remains browser MFA pending until a user-held factor has been verified through a restricted setup journey. |
| F-10 | Pending enrollment invitation is scoped, short-lived, single-use, non-reusable, independently delivered and cannot read mail or administer accounts. |
| F-11 | Owner enrollment verifies a new TOTP factor and persists replay protection; an attempted repeat of an accepted time step fails. |
| F-12 | Existing active mailbox factor is not silently overwritten by new enrollment; explicit rotation handles previous factor and epoch effects. |
| F-13 | User password change accepts current credential and new policy-compliant credential; Dovecot accepts new and rejects old on a fresh native auth request. |
| F-14 | Admin password reset follows attested authorization and step-up; it neither discloses the old hash nor bypasses the account's MFA lifecycle. |
| F-15 | TOTP recovery without proof or signed/scoped operator action fails; approved recovery leaves factors and sessions in a contained state. |
| F-16 | Suspend mailbox and verify distinct effects on browser admission, new native IMAP/SMTP authentication and delivery as configured. Existing native sessions are treated honestly. |
| F-17 | Reactivation restores only explicitly approved planes and does not reactivate an unverified browser factor. |
| F-18 | Create alias with one or several destinations; native Postfix map yields the exact intended expansion in the fixture. |
| F-19 | Modify, disable and remove alias; Postfix map no longer uses revoked expansion after documented cache/service effects. |
| F-20 | Catch-all and alias-domain behaviour matches enabled policy, ordering and collision rules; unsupported variants are not offered as working actions. |
| F-21 | Reject alias loops, invalid recipient domains, protected delivery self-alias removal and unauthorized external forwarding. |
| F-22 | Mailbox quota updates preserve units and zero/unlimited semantics; native Dovecot reports the limit and actual enforcement is tested separately. |
| F-23 | Display storage usage as measured, configured or unavailable; never misstate missing usage as zero. |
| F-24 | Create domain admin with one scoped grant; role upgrades/downgrades and removal take effect on next service request and revoke relevant sessions. |
| F-25 | Prevent removal or lockout of the last recoverable system administrator without approved break-glass policy. |
| F-26 | Password, MFA, grant, suspension and recovery events generate bounded audit and journal records linked to the correct actor and target. |
| F-27 | Retire account with explicit retention and dependency review; preserve Maildir and factor history according to policy rather than implicitly deleting. |
| F-28 | Reissue retired address to a new owner without inheriting old Maildir, sessions, factor seeds, recovery tokens or mailbox identity. |
| F-29 | Domain retirement checks dependent mailboxes, aliases and queued effects, then refuses unsafe removal until disposition is reviewed. |
| F-30 | Lists, filtering, pagination, sorting and detail links return stable authorized objects despite concurrent updates or missing backend data. |
| F-31 | No operation reports success on unknown native write status; user sees a specific pending reconciliation state and correlation ID. |
| F-32 | Read-only legacy compatibility mode permits inventory but refuses every direct or browser write path. |
| F-33 | Every implemented optional PostfixAdmin-equivalent feature has positive, negative and native-consumer proof; omitted items have explicit operator disposition. |
| F-34 | Mailbox self-service actions remain in OSMAP, not copied into privileged admin capabilities or converted into mail-content access. |

## 6. Database and writer acceptance cases

| ID | Action and expected result |
| --- | --- |
| DB-01 | MariaDB is discovered by actual installed version and capabilities, not a frozen package string; unsupported features fail before changes. |
| DB-02 | Fresh-init refuses an existing populated or ambiguously owned schema; no implicit drop, truncate, replacement or second authority. |
| DB-03 | Versioned ordered DDL creates exactly reviewed objects, constraints, indexes and migration ledger; checksums are checked on every startup. |
| DB-04 | Duplicate canonical address, alias source, domain and role grant violate reviewed uniqueness rules, even with parallel requests. |
| DB-05 | Cross-domain or orphaned foreign keys are rejected; selected retirement policy does not cascade-delete immutable audit or Maildir. |
| DB-06 | Table and protocol schema reject invalid UTF-8, unsupported character forms, control bytes and overlong identifiers consistently. |
| DB-07 | SQL projections for Postfix and Dovecot are tested with enabled/disabled domain, mailbox and alias fixtures, not only `SELECT 1`. |
| DB-08 | `SHOW GRANTS` and actual connection probes prove Postfix/Dovecot cannot INSERT/UPDATE/DELETE/ALTER admin or mail-account tables. |
| DB-09 | Web SQL identity has no account write/DDL or migration grant; only account service can mutate mail account records. |
| DB-10 | Writer identity has only approved DML on needed objects and cannot perform DDL, account grants or read protected factor files. |
| DB-11 | Migrator has separately scoped DDL/grant authority and cannot be reached through any browser route or normal service socket. |
| DB-12 | PostfixAdmin credentials and independent password helpers cannot write after Path A handover; a stale open connection is also challenged. |
| DB-13 | Writer epoch/fence and expected revision reject stale, concurrent and duplicate mutations without lost unrelated state. |
| DB-14 | Repeated operation ID returns same known receipt only; altered arguments under same ID are rejected and logged. |
| DB-15 | SQL commit plus journal records preserve the exact result; an interrupted factor/session follow-up leaves a recoverable reconciliation record. |
| DB-16 | Unknown migration version or changed checksum fails closed before normal service writes are enabled. |
| DB-17 | Deliberately interrupted DDL rehearsal restores from a verified backup; do not assume transaction rollback of DDL. |
| DB-18 | Backup and isolated restore preserve schema, records, constraints, writer state, factor references and operation/audit continuity. |
| DB-19 | Password storage uses verified installed Dovecot-compatible schemes and never logs or exposes hashes to ordinary admin views. |
| DB-20 | Migration and native schema version readers fail rather than silently assume missing optional fields or fabricated defaults. |

## 7. Postfix, Dovecot, OSMAP and host integration cases

| ID | Native integration and expected result |
| --- | --- |
| INT-01 | Inspect effective `postconf -n`, `postconf -M`, SQL map configuration and mail transport mapping before asserting recipient/alias behaviour. |
| INT-02 | Inspect effective `doveconf -n`, passdb/userdb drivers, mail storage, quota plugins, auth sockets and installed Dovecot syntax. |
| INT-03 | Prove effective recipient-domain acceptance and rejection with real Postfix SQL map lookups on disposable addresses. |
| INT-04 | Prove exact mailbox address and alias expansion with native Postfix map queries, including disabled/unknown sources. |
| INT-05 | Deliver a harmless locally generated message to an owned synthetic mailbox through Postfix -> Dovecot LMTP and observe Maildir receipt. |
| INT-06 | Native Dovecot password and full-login lookup accept the correct credential and reject incorrect, old, disabled and unknown identities. |
| INT-07 | Dovecot userdb returns the correct home, mail location, actual numeric UID/GID and quota policy for each synthetic mailbox. |
| INT-08 | Different users resolve to different Maildirs with no overlap; browser-provided paths or UIDs cannot choose mailbox storage. |
| INT-09 | Native IMAP reads only its authenticated mailbox; cross-mailbox mailbox-helper requests and forged caller UIDs are denied. |
| INT-10 | Quota over-limit denial is observed through the installed native backend using bounded disposable data; configuration alone is insufficient. |
| INT-11 | Existing Maildir flags, UIDVALIDITY, UIDNEXT, message UIDs, GUIDs and subscriptions survive account/schema changes that should preserve content. |
| INT-12 | OSMAP mailbox login performs actual password+TOTP authentication, then loads owned Inbox through its existing Dovecot/helper path. |
| INT-13 | Pending browser TOTP blocks an ordinary OSMAP session even if native mail authentication is explicitly enabled by policy. |
| INT-14 | Admin-only identity cannot authenticate to native mailbox or obtain an OSMAP mailbox session merely because it is an admin. |
| INT-15 | OSMAP's existing password-change service uses the selected single-writer contract after cutover or is correctly disabled/rewired. |
| INT-16 | Refresh dependencies after approved Dovecot configuration changes; the account-password helper must not continue with a stale authority snapshot. |
| INT-17 | Actual installed nginx/PF/WireGuard expose admin HTTPS only on the configured private boundary; public OSMAP remains independently available. |
| INT-18 | Admin web service binds only the intended loopback listener behind TLS termination; direct unintended WAN reachability fails. |
| INT-19 | Unix socket file ownership, parent directory traversal, peer credentials and typed protocol reject an unrelated local OS identity. |
| INT-20 | Admin web process cannot read Maildir, factor private files or OpenPGP private keys, even when presented with manipulated object IDs. |
| INT-21 | Service startup/stop order and `rcctl` health reflect actual installed rc.d service identity; no historic version-specific names are assumed. |
| INT-22 | Postfix and Dovecot continue to route and authenticate mail during admin service restart or private UI outage; no runtime admin-web dependency. |
| INT-23 | TLS/Host/Origin policy rejects unexpected host, HTTP downgrade and untrusted proxy headers without harming the public OSMAP origin. |
| INT-24 | Existing public OSMAP user journeys, native SMTP/IMAP and mail queue function after each admin release, schema read-mode change and rollback. |
| INT-25 | Cross-project configuration render and installed files are diffed for semantics, owners, modes, secrets and unintended legacy PostfixAdmin/Roundcube activation. |
| INT-26 | Backend errors, timeouts and lookup partial failures produce bounded actionable errors without credential or Maildir disclosure. |

**Practical verification:** Use actual installed vendor commands and sockets. Dovecot documents `doveadm auth test`, `doveadm auth login` and `doveadm user`, but credentials passed as shell arguments can leak to shell history/process inspection; use an approved ephemeral secure method. Prefer disposable local mail with actual message delivery and readback. Never enable Dovecot plaintext password debug logging as a routine test.

## 8. Authentication, authorization and security cases

All security rows require both browser route testing and, wherever reachable, **direct account-service** negative testing. Prevent a false PASS caused only by a hidden UI button or reverse-proxy denial.

| ID | Adversarial case and expected denial or containment |
| --- | --- |
| SEC-01 | Public OSMAP cookie sent to an admin origin/route is denied; admin cookies do not work on ordinary OSMAP routes. |
| SEC-02 | Password-only, wrong TOTP, expired code, replayed code, unavailable factor store and out-of-window time are denied. |
| SEC-03 | Admin identity enumeration, timing, login-rate and credential-stuffing attempts receive bounded, indistinguishable responses. |
| SEC-04 | Session token fixation fails; new login and MFA step-up rotate or bind the expected session state. |
| SEC-05 | Logout, expiry, password reset, factor revocation and role downgrade invalidate appropriate admin sessions and epochs. |
| SEC-06 | Admin session cookie is Secure, HttpOnly, correctly scoped and SameSite; no token appears in URL or response HTML. |
| SEC-07 | Every state-changing browser route validates CSRF and exact origin/Host; GET and HEAD cannot cause mutation. |
| SEC-08 | A foreign origin, hostile forwarded headers or public host alias cannot bypass the private listener policy. |
| SEC-09 | Domain A admin cannot read, create, modify, delete or count domain B mailboxes, aliases, audit or policy. |
| SEC-10 | A domain admin cannot grant system admin, assign foreign domains or revoke the final viable system-admin recovery route. |
| SEC-11 | Forged actor, role, domain, session, approval, step-up, writer epoch or target ID in a direct socket request is denied. |
| SEC-12 | Stale grant removal is effective while an old browser page or socket client remains open; authorization is rechecked on commit. |
| SEC-13 | Object reference tampering cannot access unassigned domains, retired identities, seed file references or other users' records. |
| SEC-14 | Every sensitive mutation requires the selected fresh MFA step-up; old step-up proof is scope/operation/expiry bound. |
| SEC-15 | Password reset, factor recovery, external forwarding and administrator grant changes have reviewable independent approval where policy requires. |
| SEC-16 | Concurrent recovery, reset and enrollment submissions cannot result in two active seeds or resurrect a revoked replay state. |
| SEC-17 | Pending invitation, recovery token and setup URL replay or cross-account substitution are denied with no mailbox-read capability. |
| SEC-18 | SQL injection, wildcard abuse, sort-injection and query-length boundary probes cannot alter SQL structure or leak extra rows. |
| SEC-19 | HTML/attribute/URL injection through domain, alias, display name, audit text and failure description is escaped in all views. |
| SEC-20 | Server-rendered no-JavaScript views do not introduce required scripts, remote CSS/fonts, dynamic unsafe HTML or unauthorized CSP relaxation. |
| SEC-21 | Request-body, concurrent-work, memory, query, result and response-size limits prevent resource-exhaustion without harming normal flows. |
| SEC-22 | `pledge`/`unveil` and OS user separation are verified on the actual host against attempted file, socket and program access. |
| SEC-23 | Public and private nginx/PF rules deny direct access to admin Unix socket, raw service port, database port and administrative debug surfaces. |
| SEC-24 | Postfix/Dovecot SQL users cannot query or change credential hashes or administrator secrets outside their essential projections. |
| SEC-25 | Unauthorized or malformed protocol messages cannot invoke arbitrary SQL, schema operations, shell commands or mailbox content reads. |
| SEC-26 | Audit events use stable actor/target IDs, correct decision and accurate result, with no untrusted newline forging or raw secrets. |
| SEC-27 | Truncation, deletion, rewrite or storage-unavailable conditions on mandatory audit evidence prevent or quarantine high-risk mutation. |
| SEC-28 | Recovery and maintenance logs retain useful redacted diagnostics without passwords, TOTP codes, secret file paths, raw headers or private mail. |
| SEC-29 | TLS cipher/protocol/certificate and reverse-proxy controls conform to actual supported OpenBSD/nginx policy; plaintext admin credentials never traverse HTTP. |
| SEC-30 | Admin authorization continues to fail closed during MariaDB, audit, factor, clock, helper or writer-fence partial outage. |
| SEC-31 | Password hash updates and accepted TOTP counter state cannot be rolled back silently to restore a known rejected credential/code. |
| SEC-32 | External forwarding controls do not allow an untrusted domain admin to hide or bypass configured review/notification policy. |
| SEC-33 | Backup and restore identities cannot turn host root/DBA access into an assumed application-level RBAC guarantee; residual privileged risks are documented. |
| SEC-34 | Browser cache and sensitive page responses do not retain factor QR, recovery token or secret-bearing form content after enrollment. |
| SEC-35 | High-risk admin actions cannot be requested through the mailbox UI, shared sign-on confusion, public redirects or open return URLs. |
| SEC-36 | Security event alerting detects repeated login failures, cross-domain denials, unexpected grants, writer conflict and backup/audit integrity loss. |

## 9. OWASP WSTG methodology and coverage

**Baseline:** OWASP Web Security Testing Guide v4.2, selected by explicit versioned URL and ID namespace, with current upstream additions evaluated for applicability. WSTG is a testing methodology, not a certification or substitute for project-specific Rust/SQL/native mail abuse tests. OWASP ASVS 5.0.0 is a complementary requirements reference, not proof that controls are implemented.

Use the exact WSTG scenario catalogue for the selected version and record case-by-case applicability. The coverage below supplies the category-level minimum; enumerate all applicable published scenario IDs in the execution worksheet rather than assuming a category header equals exhaustive coverage.

| WSTG v4.2 area | OSMAP-ADMIN scope and required probes | Local test coverage |
| --- | --- | --- |
| 4.1 Information Gathering (`INFO`) | Public route discovery, server/version leakage, index/debug/health endpoints, admin URL predictability, robots, public source/config references. | SEC-08, SEC-23, INT-17, INT-18 |
| 4.2 Configuration and Deployment (`CONF`) | Admin interface enumeration, backups and old files, unwanted methods, sensitive transport, insecure headers and private listener exposure. | SEC-07, SEC-23, SEC-29, INT-17, INT-23, INT-25 |
| 4.3 Identity Management (`IDNT`) | Admin and mailbox identity namespaces, role registration, account enumeration, predictable identities, inconsistent canonicalization. | F-02, F-06, F-24, SEC-01, SEC-03 |
| 4.4 Authentication (`ATHN`) | MFA bypass, weak alternate channel, recovery/reset, brute force, credential transport, password policy and setup-token possession. | F-04, F-10 to F-15, SEC-02, SEC-03, SEC-14 to SEC-17 |
| 4.5 Authorization (`ATHZ`) | Directory/path traversal, role elevation, horizontal and vertical object access, direct socket bypass, domain scope and stale grants. | F-07, SEC-09 to SEC-13, SEC-20, SEC-25 |
| 4.6 Session Management (`SESS`) | Session fixation, cookie flags, CSRF, logout, idle/absolute expiry, step-up, revocation, competing sessions. | SEC-04 to SEC-08, SEC-14, SEC-35 |
| 4.7 Input Validation (`INPV`) | SQL injection, stored/reflected HTML, canonicalization, malicious URL/header, CRLF, input boundaries, parameter and duplicate-field pollution. | DB-06, SEC-18 to SEC-21, UX-08 |
| 4.8 Error Handling (`ERRH`) | SQL/service exception disclosure, verbose diagnostics, inconsistent HTTP errors, unavailable backend and partial-operation truthfulness. | INT-26, SEC-28, UX-09, RES-09 |
| 4.9 Weak Cryptography (`CRYP`) | Credential and recovery protection, TLS, hash scheme compatibility, factor seed custody, signed artifact evidence and backup encryption. | DB-19, SEC-02, SEC-24, SEC-29, REC-15 |
| 4.10 Business Logic (`BUSL`) | State transition bypass, writer races, invitation/recovery replay, privilege scope, quota abuse, alias forwarding and retirement reissue. | F-09 to F-11, F-16 to F-29, DB-12 to DB-15, SEC-15 to SEC-17 |
| 4.11 Client-side (`CLNT`) | CSP, framing, DOM-free server forms, unsafe redirects, autocomplete, UI trust claims, rendering and caching. | SEC-19, SEC-20, SEC-34, SEC-35, UX-01 to UX-14 |

**Additional relevant coverage:** Review WSTG's current development API testing section for parity with typed Unix socket operations, even though the pinned v4.2 category index is browser-oriented. The local protocol-specific tests SEC-11, SEC-25, DB-14 and RES-11 are mandatory independently of the published WSTG index. If no file upload exists on the admin surface, record WSTG upload scenarios as `NOT_APPLICABLE` with code/route evidence; do not create test-only upload functionality. Do not mistake a WSTG SQL-injection result for proof of race, quota, DB grants or writer fencing.

**Representative versioned scenario references:** WSTG-v42-ATHZ-04 (insecure direct object references), WSTG-v42-BUSL-09 (malicious file upload, only where applicable). Actual scenario links and test IDs must come from OWASP's versioned index. Avoid inventing case IDs from memory.

### 9.1 Complete WSTG v4.2 scenario worksheet

The following inventory is transcribed from the **published OWASP v4.2 category indexes** as checked on 2026-11-13. The titles below are concise labels of their testing intent. Each row is a **test mapping**, not a claim it passed. `Conditional` means the applicable technology must first be inventoried. If absent, record `NOT_APPLICABLE` with code, route, runtime and configuration evidence; otherwise execute the scenario. All other scenarios must be given an individual result or an explicit documented limitation.

This inventory covers the top-level v4.2 test scenarios. For SQL injection, test the MySQL/MariaDB-specific subscenario of `INPV-05`; the other SQL engines and NoSQL/ORM subscenarios need an evidence-based applicability decision. For code injection, explicitly check the local/remote file inclusion subscenarios under `INPV-11`.

**INFO: 10 scenarios**

| Versioned WSTG ID | Scenario intent | Local test references |
| --- | --- | --- |
| `WSTG-v42-INFO-01` | Search-engine discovery and information leakage. Public route reconnaissance with safe external vantage. | SEC-23; INT-17 |
| `WSTG-v42-INFO-02` | Fingerprint web server. Review truthful or suppressed server disclosure. | SEC-23; INT-23 |
| `WSTG-v42-INFO-03` | Webserver metafiles. robots, sitemap, archives and policy files. | SEC-23; INT-25 |
| `WSTG-v42-INFO-04` | Enumerate applications. Unexpected administrative components denied. | SEC-23; INT-17 |
| `WSTG-v42-INFO-05` | Webpage information leakage. HTML and response metadata redacted. | SEC-28; UX-13 |
| `WSTG-v42-INFO-06` | Identify entry points. All routes, query parameters and socket operations. | SEC-07; SEC-25 |
| `WSTG-v42-INFO-07` | Map execution paths. Each privileged state-transition path. | SEC-11; RES-03 |
| `WSTG-v42-INFO-08` | Fingerprint web framework. Rust-rendered stack and exposure. | SEC-20; SEC-23 |
| `WSTG-v42-INFO-09` | Fingerprint web application. Version and admin origin leakage. | INT-17; SEC-23 |
| `WSTG-v42-INFO-10` | Map application architecture. Process, listener and SQL boundaries. | INT-17; INT-19 |

**CONF: 11 scenarios**

| Versioned WSTG ID | Scenario intent | Local test references |
| --- | --- | --- |
| `WSTG-v42-CONF-01` | Network infrastructure configuration. PF and WireGuard boundaries. | INT-17; SEC-23 |
| `WSTG-v42-CONF-02` | Application platform configuration. OpenBSD, nginx, Rust services and MariaDB. | INT-21; OPS-04 |
| `WSTG-v42-CONF-03` | Sensitive file extension handling. No direct export of scripts or configuration. | SEC-23; SEC-28 |
| `WSTG-v42-CONF-04` | Old backup or unreferenced files. Backups inaccessible over HTTP. | SEC-23; REC-15 |
| `WSTG-v42-CONF-05` | Admin interface enumeration. Private admin route is not public. | INT-17; SEC-23 |
| `WSTG-v42-CONF-06` | HTTP methods. No GET/HEAD or method-override writes. | SEC-07; UX-08 |
| `WSTG-v42-CONF-07` | HTTP Strict Transport Security. Private HTTPS policy at selected origin. | SEC-29; INT-23 |
| `WSTG-v42-CONF-08` | RIA cross-domain policy. Conditional: prove no Flash/Silverlight policy if absent. | SEC-20; INT-25 |
| `WSTG-v42-CONF-09` | File permissions. Actual OS principals and file modes. | INT-19; SEC-22 |
| `WSTG-v42-CONF-10` | Subdomain takeover. Conditional: actual DNS names and ownership. | INT-17; INT-23 |
| `WSTG-v42-CONF-11` | Cloud storage. Conditional: prove no cloud storage if absent. | REC-15; SEC-23 |

**IDNT: 5 scenarios**

| Versioned WSTG ID | Scenario intent | Local test references |
| --- | --- | --- |
| `WSTG-v42-IDNT-01` | Role definitions. System/domain/mailbox identity matrix. | SEC-09; SEC-10 |
| `WSTG-v42-IDNT-02` | User registration process. Offline admin bootstrap; restricted user setup. | F-02; F-10 |
| `WSTG-v42-IDNT-03` | Account provisioning. Create, pending, activation and native readback. | F-08; F-09 |
| `WSTG-v42-IDNT-04` | Account enumeration. No username existence oracle. | SEC-03; UX-09 |
| `WSTG-v42-IDNT-05` | Username policy. Canonical uniqueness and length/collision. | DB-04; DB-06 |

**ATHN: 10 scenarios**

| Versioned WSTG ID | Scenario intent | Local test references |
| --- | --- | --- |
| `WSTG-v42-ATHN-01` | Credentials over encrypted channel. Admin login and factor always protected. | SEC-29; INT-23 |
| `WSTG-v42-ATHN-02` | Default credentials. No shipped or permanent bootstrap account. | F-02; SEC-02 |
| `WSTG-v42-ATHN-03` | Weak lockout. Bounded attempts and account availability. | SEC-03; SEC-21 |
| `WSTG-v42-ATHN-04` | Authentication bypass. All direct and web paths. | SEC-01; SEC-02 |
| `WSTG-v42-ATHN-05` | Remember-password feature. Conditional: verify absent or secure if present. | SEC-06; SEC-34 |
| `WSTG-v42-ATHN-06` | Browser cache weaknesses. Secret and session cache handling. | SEC-34; UX-12 |
| `WSTG-v42-ATHN-07` | Weak password policy. Stored verifier and reset policy. | F-13; DB-19 |
| `WSTG-v42-ATHN-08` | Weak security questions. Conditional: absence of weak knowledge-based recovery. | F-15; SEC-15 |
| `WSTG-v42-ATHN-09` | Weak password reset/change. Attested reset, native old/new proof. | F-13; F-14 |
| `WSTG-v42-ATHN-10` | Weaker alternate channel. Socket, API, user app and native client distinctions. | SEC-01; INT-14 |

**ATHZ: 4 scenarios**

| Versioned WSTG ID | Scenario intent | Local test references |
| --- | --- | --- |
| `WSTG-v42-ATHZ-01` | Directory traversal/file inclusion. No arbitrary path read or asset escape. | SEC-20; SEC-25 |
| `WSTG-v42-ATHZ-02` | Authorization-schema bypass. Service check independent of UI. | SEC-09; SEC-11 |
| `WSTG-v42-ATHZ-03` | Privilege escalation. Role changes and stale sessions. | SEC-10; SEC-12 |
| `WSTG-v42-ATHZ-04` | Insecure direct object references. Foreign domain, mailbox, alias and audit IDs. | SEC-09; SEC-13 |

**SESS: 9 scenarios**

| Versioned WSTG ID | Scenario intent | Local test references |
| --- | --- | --- |
| `WSTG-v42-SESS-01` | Session-management scheme. Opaque tokens and server-validated epochs. | SEC-04; SEC-05 |
| `WSTG-v42-SESS-02` | Cookie attributes. Secure, HttpOnly, origin scope and SameSite. | SEC-06; SEC-34 |
| `WSTG-v42-SESS-03` | Session fixation. Rotate at login, factor and role changes. | SEC-04; SEC-05 |
| `WSTG-v42-SESS-04` | Exposed session variables. No URL, logs or HTML token leakage. | SEC-06; SEC-28 |
| `WSTG-v42-SESS-05` | CSRF. Every state-changing action. | SEC-07; SEC-08 |
| `WSTG-v42-SESS-06` | Logout. Revoked session immediately unusable. | SEC-05; UX-10 |
| `WSTG-v42-SESS-07` | Session timeout. Idle, absolute and step-up expiration. | SEC-05; SEC-14 |
| `WSTG-v42-SESS-08` | Session puzzling. Auth-state and factor-state confusion. | SEC-01; SEC-04 |
| `WSTG-v42-SESS-09` | Session hijacking. Stolen token revocation and containment. | SEC-05; SEC-06 |

**INPV: 19 scenarios**

| Versioned WSTG ID | Scenario intent | Local test references |
| --- | --- | --- |
| `WSTG-v42-INPV-01` | Reflected cross-site scripting. Query, error and search rendering. | SEC-19; UX-08 |
| `WSTG-v42-INPV-02` | Stored cross-site scripting. Alias, domain, display name and audit text. | SEC-19; UX-13 |
| `WSTG-v42-INPV-03` | HTTP verb tampering. Unsupported methods have no effects. | SEC-07; UX-08 |
| `WSTG-v42-INPV-04` | HTTP parameter pollution. Duplicate and inconsistent form fields. | UX-08; SEC-18 |
| `WSTG-v42-INPV-05` | SQL injection. MariaDB-aware SQL/path/query contexts; subcase MySQL. | SEC-18; DB-07 |
| `WSTG-v42-INPV-06` | LDAP injection. Conditional: LDAP backend absent unless discovered. | SEC-18; INT-25 |
| `WSTG-v42-INPV-07` | XML injection. Conditional: no XML parser/endpoint unless discovered. | SEC-18; INT-25 |
| `WSTG-v42-INPV-08` | SSI injection. Conditional: no SSI processing unless discovered. | SEC-20; INT-25 |
| `WSTG-v42-INPV-09` | XPath injection. Conditional: no XPath engine unless discovered. | SEC-18; INT-25 |
| `WSTG-v42-INPV-10` | IMAP/SMTP injection. Alias and address data cannot become protocol syntax. | F-18; INT-04 |
| `WSTG-v42-INPV-11` | Code injection. No dynamic script execution or local/remote include. | SEC-25; SEC-22 |
| `WSTG-v42-INPV-12` | Command injection. No arbitrary helper or shell invocation. | SEC-25; INT-20 |
| `WSTG-v42-INPV-13` | Format-string injection. Logging and native format handling. | SEC-28; INT-26 |
| `WSTG-v42-INPV-14` | Incubated vulnerability. Deferred rendering/audit/job outputs. | SEC-19; SEC-26 |
| `WSTG-v42-INPV-15` | HTTP request splitting/smuggling. Proxy/upstream parser disagreement. | INT-23; SEC-08 |
| `WSTG-v42-INPV-16` | Incoming HTTP request anomalies. Boundaries, malformed body/header framing. | SEC-07; SEC-21 |
| `WSTG-v42-INPV-17` | Host header injection. Strict allowed Host and origin. | SEC-08; INT-23 |
| `WSTG-v42-INPV-18` | Server-side template injection. Typed escaping in server-rendered templates. | SEC-19; SEC-20 |
| `WSTG-v42-INPV-19` | Server-side request forgery. Conditional: no arbitrary outbound URL fetch. | SEC-25; SEC-32 |

**ERRH: 2 scenarios**

| Versioned WSTG ID | Scenario intent | Local test references |
| --- | --- | --- |
| `WSTG-v42-ERRH-01` | Improper error handling. Fail-closed response and uncertainty. | INT-26; RES-09 |
| `WSTG-v42-ERRH-02` | Stack traces. No internals in HTTP, audit or exports. | SEC-28; UX-09 |

**CRYP: 4 scenarios**

| Versioned WSTG ID | Scenario intent | Local test references |
| --- | --- | --- |
| `WSTG-v42-CRYP-01` | Weak transport layer security. Installed nginx TLS and cert semantics. | SEC-29; INT-23 |
| `WSTG-v42-CRYP-02` | Padding oracle. Conditional: inspect actual encrypted tokens/backup formats. | SEC-29; REC-15 |
| `WSTG-v42-CRYP-03` | Sensitive data over plaintext. No credential/factor or token leakage. | SEC-29; SEC-28 |
| `WSTG-v42-CRYP-04` | Weak encryption. Hash protection, backup encryption and approved primitives. | DB-19; REC-15 |

**BUSL: 9 scenarios**

| Versioned WSTG ID | Scenario intent | Local test references |
| --- | --- | --- |
| `WSTG-v42-BUSL-01` | Business-logic data validation. Canonical domain, mailbox, alias and quota policy. | F-06; F-21 |
| `WSTG-v42-BUSL-02` | Forge requests. CSRF, step-up, origin and direct protocol. | SEC-07; SEC-11 |
| `WSTG-v42-BUSL-03` | Integrity checks. Revisions, checksums and reconciliation. | DB-13; MIG-04 |
| `WSTG-v42-BUSL-04` | Process timing. Race at writer, authorization and factor boundary. | RES-01; SEC-12 |
| `WSTG-v42-BUSL-05` | Repeated-function limits. Idempotency and one-time invitations. | DB-14; F-10 |
| `WSTG-v42-BUSL-06` | Workflow circumvention. No bypass of enrollment, recovery or retirement. | F-09; F-15 |
| `WSTG-v42-BUSL-07` | Application misuse. Forwarding abuse, rate limits and scope. | SEC-21; SEC-32 |
| `WSTG-v42-BUSL-08` | Unexpected file upload. Conditional: no upload endpoint unless implemented. | SEC-25; SEC-23 |
| `WSTG-v42-BUSL-09` | Malicious file upload. Conditional: no upload endpoint unless implemented. | SEC-25; SEC-23 |

**CLNT: 13 scenarios**

| Versioned WSTG ID | Scenario intent | Local test references |
| --- | --- | --- |
| `WSTG-v42-CLNT-01` | DOM-based XSS. Conditional: no JavaScript DOM manipulation. | SEC-20; UX-06 |
| `WSTG-v42-CLNT-02` | JavaScript execution. No required JavaScript or CSP relaxation. | SEC-20; UX-06 |
| `WSTG-v42-CLNT-03` | HTML injection. Contextual output escaping. | SEC-19; UX-08 |
| `WSTG-v42-CLNT-04` | Client-side URL redirect. Bounded return destination policy. | SEC-35; INT-23 |
| `WSTG-v42-CLNT-05` | CSS injection. Untrusted fields cannot inject styles. | SEC-19; UX-03 |
| `WSTG-v42-CLNT-06` | Client-side resource manipulation. No remote dependencies or untrusted assets. | SEC-20; SEC-23 |
| `WSTG-v42-CLNT-07` | CORS. No privileged cross-origin browser access. | SEC-08; INT-23 |
| `WSTG-v42-CLNT-08` | Cross-site Flashing. Conditional: no Flash technology. | SEC-20; INT-25 |
| `WSTG-v42-CLNT-09` | Clickjacking. CSP frame-ancestors and headers. | SEC-29; INT-23 |
| `WSTG-v42-CLNT-10` | WebSockets. Conditional: no WebSocket endpoints. | SEC-25; INT-18 |
| `WSTG-v42-CLNT-11` | Web messaging. Conditional: no postMessage handling. | SEC-20; UX-06 |
| `WSTG-v42-CLNT-12` | Browser storage. No sensitive persistent browser token store. | SEC-06; SEC-34 |
| `WSTG-v42-CLNT-13` | Cross-site script inclusion. No remote script or unsafe JSONP. | SEC-20; INT-25 |

**Full scenario execution rule:** Record a result for each of these 96 published top-level scenario IDs, plus applicable subscenarios and the newer API category where the actual implementation has interfaces. A release gate cannot be marked "full WSTG" if it only reports the category roll-up. Tests may share captured traffic or fixtures, but no scenario may be silently skipped.

## 10. Existing OSMAP UX reuse and accessibility

| ID | Acceptance expectation |
| --- | --- |
| UX-01 | Admin shell reuses audited OSMAP CSS tokens, native rail/topbar, Settings-style forms, cards, tables, notices and focus behaviour without inheriting mailbox authority. |
| UX-02 | OSMAP approved public login/TOTP pages and other locked UX output are unchanged unless separately approved. |
| UX-03 | Light, dark and system appearances, density and fonts produce readable persistent admin views with isolated preference state. |
| UX-04 | Keyboard-only navigation, skip link, single `aria-current` destination, labelled search and form controls all work. |
| UX-05 | All essential controls remain accessible at 360, 768 and 1440 CSS pixels, 200% zoom and forced-colours. |
| UX-06 | Create, update, recovery and confirmation forms complete with JavaScript disabled and no remote UI dependencies. |
| UX-07 | Error summaries link to invalid fields and preserve only safe form data; secrets/codes are never repopulated. |
| UX-08 | Duplicate, malformed, overlong, Unicode-confusable, missing and stale revision inputs are server-validated with no mutation. |
| UX-09 | Unauthorized, unconfigured, locked, unavailable, `UNCERTAIN` and stale-state errors are truthful, bounded and keyboard accessible. |
| UX-10 | Confirmations show canonical target, impact, scope and expected revision; return from POST uses safe redirection and authoritative readback. |
| UX-11 | Domain admin never sees foreign counts, action buttons, links or object data, and hidden controls do not replace service authorization. |
| UX-12 | Factor enrollment screen displays required setup secret only to intended party within the approved one-time window; no cached or logged copy. |
| UX-13 | Auditor can navigate redacted events without privileged SQL, secret file or mail-content exposure. |
| UX-14 | Visual references are compared with current actual OSMAP patterns and new approved admin captures, not falsely claimed approved by the old 25 PNGs. |

Compare new admin screens with `src/http_support.rs`, `src/http_ui.rs`, `src/settings_ui.rs`, `src/settings_general_ui.rs`, `src/http/header_theme.rs` and the frozen `docs/design/osmap-ux-final-approved-20260919/` bundle. Reuse presentation contracts only. Both applications retain independent security and session records.

## 11. Concurrency, interruption and resource resilience

| ID | Action and acceptance condition |
| --- | --- |
| RES-01 | Two admins change the same alias with the same revision: one approved result, one explicit conflict, no lost unrelated data. |
| RES-02 | Two admins try concurrent password/factor resets: one serialized result, remaining request refused or explicitly reconciled. |
| RES-03 | Repeat an operation after a dropped HTTP response: idempotency journal identifies committed/failed/unknown state, never blindly double-writes. |
| RES-04 | Restart account service before SQL commit; no partial row or success receipt survives. |
| RES-05 | Restart account service after SQL commit but before response; readback and journal reconstruct the exact single effect. |
| RES-06 | Interrupt after SQL commit but before factor file install; account remains contained and has a repairable journal result. |
| RES-07 | Interrupt after factor install but before activation; no unrestricted browser session; factor state is reconciled, not overwritten. |
| RES-08 | Interrupt revocation after session epoch change; old admin and user tokens are not accepted by a restarted service. |
| RES-09 | Simulate SQL/socket/backend timeout; bounded failure, no false green banner and no unobserved implicit retry. |
| RES-10 | Drop audit destination during sensitive change; fail closed or durable pending record according to approved transaction design. |
| RES-11 | Replayed/unknown typed protocol version or invalid length is rejected before allocating excessive memory or touching SQL. |
| RES-12 | Simulated storage exhaustion does not destroy existing Maildir or audit and distinguishes usable recovery from false completion. |
| RES-13 | Wrong clock and expired invitation challenge cannot bypass TOTP window or recover used setup tokens. |
| RES-14 | Restart nginx/admin only and verify ongoing SMTP/IMAP and public OSMAP remain available. |
| RES-15 | Writer service loses SQL connectivity mid-cutover: no opportunistic fallback to legacy writer or replica. |
| RES-16 | A stale worker connection remains after grant revocation: it cannot commit an unauthorized change. |

Inject destructive faults only against dedicated isolated fixtures and recovery copies. Record exact failure injection position, persisted output and which state source resolved uncertainty.

## 12. Migration, handover and PostfixAdmin retirement tests

Run **Path A** and **Path B** independently. Do not infer Path B success from a functioning Path A admin UI.

| ID | Test and acceptance result |
| --- | --- |
| MIG-01 | Inventory actual legacy tables, rows, triggers, domain limits, mailbox records, alias and alias-domain forms, password schemes and configured Postfix/Dovecot queries. |
| MIG-02 | Produce and verify coherent backup units for SQL, Maildir, factors/replay, user sessions where required, auth helper state, configs, packages and writer journal. |
| MIG-03 | Restore backup into isolated host and prove it is writable/consistent enough for recovery, not simply that an archive file exists. |
| MIG-04 | Compare canonical domain/mailbox/alias counts and per-record fingerprints before any authority change, including disabled and unusual legacy rows. |
| MIG-05 | Validate supported and unknown PostfixAdmin extensions; unknown columns, hash schemes, triggers or unsupported settings halt before mutation. |
| MIG-06 | Path A read-only adapter gives scoped admin inventory without modifying legacy SQL. |
| MIG-07 | Enumerate and fence all writers: PostfixAdmin UI, SQL credentials, OSMAP password helper, scheduled tools and stale transactions. |
| MIG-08 | Path A single-writer cutover proves legacy write attempts fail, new Rust writer succeeds and native Postfix/Dovecot queries continue unchanged. |
| MIG-09 | Path A creates/updates a disposable account then proves login, local delivery, alias and quota results on installed native services. |
| MIG-10 | Path A rollback before new writes restores legacy writer safely without account mutation loss. |
| MIG-11 | Path A rollback after a new Rust write reconciles the new record and the exact writer epoch before legacy writes resume. |
| MIG-12 | Path B migrates entire compatible authority to native `osmap_mail` in isolated rehearsal; all required tables and metadata reconcile. |
| MIG-13 | Path B correctly rewires every Postfix SQL map, Dovecot passdb/userdb and OSMAP native credential helper to **one** new authority. |
| MIG-14 | Path B proves source and target parity for disabled users, password schemes, aliases, recipient acceptance, maildir paths, quota and actual stored mail. |
| MIG-15 | Deliberately interrupt Path B cutover at each service switch; detect split authority and refuse promotion. |
| MIG-16 | Path B rollback after any new writes performs forward/reverse delta reconciliation, protects Maildir and never blindly restores a stale SQL backup. |
| MIG-17 | On rollback, revoked old credentials, TOTP replay state and new recoveries are reconciled before any ordinary session resumes. |
| MIG-18 | PostfixAdmin remains installed/read-only or isolated through observation; successful writer cutover does not itself authorize package/UI retirement. |
| MIG-19 | Separate PostfixAdmin retirement rehearsal verifies no live SQL writers, web routes, cron jobs, dependencies, backups or emergency restore plans still require it. |
| MIG-20 | Final retirement preserves required archives and rollback evidence, removes only explicitly approved components and re-runs native mail acceptance. |

A migration PASS requires a matched signed source baseline and fixture manifest, scoped operator authorization, readback of the authoritative writer, no simultaneous active competing writer, actual native mail proof and a documented usable recovery path.

## 13. Recovery and disaster recovery scenarios

| ID | Scenario and authoritative recovery expectation |
| --- | --- |
| REC-01 | Restore only OSMAP-ADMIN binary/config after failed deployment; older compatible binary starts without changing account authority. |
| REC-02 | Restore MariaDB after fixture corruption; all mail-account, grant, journal and migration ledger state matches the selected recovery point. |
| REC-03 | Detect incompatible code/schema downgrade and refuse unsafe service start rather than corrupting migrated data. |
| REC-04 | Recover from interrupted DDL using pre-change backup and actual post-restore schema checks. |
| REC-05 | Restore factor files and accepted TOTP replay counters together; previously accepted codes are not accepted a second time. |
| REC-06 | Reconstruct missing factor file with a controlled re-enrollment process, not an empty-seed fallback or silent factor reset. |
| REC-07 | Recover password-helper trust/config after Dovecot change; new and old password outcomes reflect authoritative hash state. |
| REC-08 | Recover after loss of first admin's factor using separately attested offline process, preserving immutable audit and last-admin safety. |
| REC-09 | Restore an admin session store; expired/revoked sessions do not become valid through restoration. |
| REC-10 | Restore a retired address and ensure new owner cannot access prior Maildir or factor/session state. |
| REC-11 | Recover a writer conflict with precise operation-state reconciliation and recheck of revoked legacy write credentials. |
| REC-12 | Recover after interrupted Postfix/Dovecot SQL-map update without split database authority. |
| REC-13 | Recover from nginx/PF/private-listener misconfiguration with private access restored and no accidental public admin exposure. |
| REC-14 | Recover normal mail delivery while OSMAP-ADMIN stays stopped; no dependence on control-plane availability. |
| REC-15 | Validate integrity, encryption/access controls and actual decryptability of protected backup sets using operator-held recovery secrets. |
| REC-16 | Restore actual Maildir bytes, UIDVALIDITY, GUID/UID identity, subscriptions, flags, quota and ownership on an isolated target. |
| REC-17 | Simulate audit store outage and reconstruct immutable audit continuity or explicitly identify lost evidence and block unsafe promotion. |
| REC-18 | Recover from weekly `syspatch` or `pkg_add -u` compatibility failure without automatic schema migration or unsafe package rollback claim. |
| REC-19 | Verify that restoration to older source data cannot silently resurrect suspended user access, revoked grants or recovered passwords. |
| REC-20 | After full isolated disaster restore, successfully perform admin sign-in, mailbox login+TOTP, local delivery, IMAP read, alias and quota tests. |

**Recovery completion criteria:** record recovery point, source and target digests, writer epoch, retained delta, authoritative SQL version, factor/session state, native authentication and delivery result, confidentiality status and any unresolved uncertainty. Never claim a production RTO/RPO from one untimed isolated rehearsal; report observed times and operator-defined objectives separately.

## 14. Installation, upgrade and weekly maintenance tests

| ID | Scenario and expected result |
| --- | --- |
| OPS-01 | Clean OpenBSD discovery records actual `uname`, `sysctl`, installed `pkg_info`, MariaDB, Postfix, Dovecot, nginx and security tooling before selecting a supported deployment path. |
| OPS-02 | Reviewed `openbsd-mailstack` render/install components do not invoke legacy Roundcube/PostfixAdmin installation in the native OSMAP profile. |
| OPS-03 | Fresh initialization creates SQL schema/grants and first admin once, but does not expose the admin web interface publicly or run unreviewed legacy migrations. |
| OPS-04 | Service ownership, rc scripts, directory modes, socket grants, secret paths, PF, nginx and TLS are inspected on target, not inferred from example configs. |
| OPS-05 | Weekly maintenance preflight checks backup/restore readiness, current writer state, actual package updates and any schema ABI dependency. |
| OPS-06 | Apply regular `syspatch` and `pkg_add -u` under existing weekly operating practice, then verify OSMAP-ADMIN, OSMAP, MariaDB, Postfix, Dovecot and private edge. |
| OPS-07 | Weekly maintenance does not automatically run MariaDB DDL, first-admin bootstrap, writer cutover, host release upgrade or legacy retirement. |
| OPS-08 | An OpenBSD release upgrade and a MariaDB major upgrade are separately rehearsed and gated by observed API/config/schema behaviour. |
| OPS-09 | Dependency drift, Postfix map format, Dovecot auth syntax and SQL grant changes are caught by semantic tests instead of frozen package patch versions. |
| OPS-10 | If a package update changes native authentication or delivery, record the failed contract, preserve recoverability and do not certify the admin release. |

Use OpenBSD's documented `syspatch` and `pkg_add -u` semantics for the **installed supported release**, not an old hard-coded `7.9` package set. Treat an update report and actual installed system acceptance as separate observations.

## 15. Production acceptance and release decision

### 15.1 Pre-production release gates

| Gate | Required objective proof |
| --- | --- |
| `G0` Contract freeze | Target deployment mode, installed service/schema inventory, issue #85 feature disposition, relevant design decisions and known unknowns. |
| `G1` Source integrity | Reviewed signed source/build, focused unit/property tests, applicable project security checks and no secret-bearing code/evidence. |
| `G2` Native integration | Admin auth, grants, SQL service writer, actual Postfix/Dovecot mail path, user browser login+TOTP and isolated service privilege checks. |
| `G3` Security | Applicable WSTG-v4.2 scenario matrix complete, direct socket/service adversarial testing, no unresolved critical/high authorization or credential flaw. |
| `G4` Recoverability | At least one successful isolated full restore and the applicable writer/schema rollback rehearsal with after-write reconciliation. |
| `G5` Production preflight | Current live inventory, protected restore point, read-only compatibility and installed configuration checks, known non-destructive smoke plan. |
| `G6` Approved release | Operator-authorized deployment/cutover, private-only admin exposure, live synthetic smoke with authoritative readback and recorded go/no-go. |

A source-only release cannot assert `G2`, `G4` or `G6` merely because CI passed. A routine admin UI update may reuse still-current evidence for unchanged components, but must rerun tests for affected trust, schema, writer and native contracts.

### 15.2 Production smoke suite

| ID | Production assertion, only when separately authorized |
| --- | --- |
| PROD-01 | Confirm production host identity, current source build, installed binary digest, service versions, schema checksum and authoritative DB without changing state. |
| PROD-02 | Confirm backup archives and off-host recovery material are available, encrypted and recently restored in an isolated test. |
| PROD-03 | Verify active Postfix/Dovecot SQL map destinations and no unintended reference to development or replica DB. |
| PROD-04 | Confirm designated writer and all legacy/other DML grants are fenced; inspect effective grants, not labels. |
| PROD-05 | Check public admin URL/port cannot be reached from an untrusted network; private WireGuard route and TLS work. |
| PROD-06 | Check public OSMAP login and owned mailbox journey are unaffected and native SMTP/IMAP remain functioning. |
| PROD-07 | Confirm admin-only password+TOTP login works and a mailbox-user cookie is rejected at the admin boundary. |
| PROD-08 | Confirm domain admin sees only assigned domains; foreign ID/search result is denied without leakage. |
| PROD-09 | On explicitly approved synthetic records, create a mailbox and verify native Dovecot userdb/passdb and Postfix delivery. |
| PROD-10 | On explicitly approved synthetic records, create/update an alias and verify recipient expansion, then revert safely. |
| PROD-11 | On explicitly approved synthetic records, complete restricted owner TOTP enrollment and ordinary OSMAP login. |
| PROD-12 | On explicitly approved synthetic records, change password and verify new native login/old credential rejection on fresh session. |
| PROD-13 | Confirm audit event/result/journal references are complete, redacted, correlated and protected. |
| PROD-14 | Confirm SQL/IMAP/SMTP/firewall listeners and running OS principals match planned components and configuration. |
| PROD-15 | Confirm status and monitoring distinguish backend unavailable, unknown quota, pending MFA and uncertain operation from success. |
| PROD-16 | Verify no real Maildir, existing factor, aliases, queued message, DNS or user credentials were altered by synthetic test. |
| PROD-17 | Confirm rollback method still works for the exact installed binary/config/schema and has a process for reconciling post-cutover writes. |
| PROD-18 | Record release decision, operator, scope, environment, known limitations, retained defects and separately authorized retirement status. |

No uncontrolled live password/factor rotation, network flooding, destructive restore, fault injection, bulk account creation or intentionally bad migration is part of this smoke suite. Those require isolated environments. Use a dedicated synthetic fixture only with authorization and a reliable cleanup plan.

### 15.3 Go/no-go rules

**NO-GO** when any of the following is true:

- Competing account writers remain capable of DML or the authoritative database is ambiguous.
- Unresolved authentication, authorization, factor, session, audit integrity, secret exposure or private listener flaw has critical or high impact.
- Postfix/Dovecot effective lookups, delivery or OSMAP login regress unexpectedly.
- Migration mapping is unverified or rollback after new writes cannot reconcile actual state.
- Needed recovery materials are missing, untested or corrupt.
- Required tests are `BLOCKED`, `NOT_RUN`, `UNCERTAIN` or `FAIL` for a production-critical claimed capability.
- Actual host configuration deviates materially from the reviewed security or package compatibility contract.
- The proposed release silently enables browser, SQL, storage or network capabilities outside its approved scope.

Medium/low defects can be recorded and accepted only if they do not invalidate a non-negotiable security or data-integrity assertion. No arbitrary percentage of passing tests substitutes for these conditions.

**GO** requires each applicable release gate to have current specific evidence for the selected install mode, no unaccepted critical/high defect, tested rollback and an explicit recorded release decision. This document alone cannot grant live-change authorization or decommission PostfixAdmin.

## 16. Implementation hooks and test ownership

### 16.1 Existing OSMAP test entrypoints, not new admin evidence

The source repository currently exposes focused and release-oriented commands including:

```sh
make test
make lint
make fmt-check
make security-check
make v14-check
make acceptance-check
```

These are **existing OSMAP** entrypoints. They prove only their documented scope and must not be relabelled as OSMAP-ADMIN integration results. Reuse the underlying test discipline and presentational regression gates when shared code changes. Implement dedicated OSMAP-ADMIN Rust unit/integration tests, typed-socket negative tests and native OpenBSD acceptance scripts as the services are built, with stable explicit case IDs from this plan. Do not invent operational scripts or report their future names as existing commands.

The public `openbsd-mailstack` project has non-destructive validation entrypoints such as:

```sh
./scripts/verify/run-post-install-checks.ksh
./scripts/verify/verify-rendered-config-integrity.ksh
./scripts/verify/verify-host-service-integrity.ksh
```

Run commands from the matching repository root, first inspecting their exact current content and selected mode. Their PASS does not assert OSMAP-ADMIN functional acceptance. The private `openbsd-self-hosting` repository may contain more deployment-specific tests and credentials, but none of that private material belongs in a public OSMAP test report.

### 16.2 Engineering implementation order

1. Build deterministic identity, domain, alias, quota and grant validation unit tests.
2. Build SQLite-free or MariaDB-backed schema tests matching the actual MariaDB contract and writer identity; never substitute a second SQL engine for native SQL semantics.
3. Implement direct account-service protocol tests with peer identity, request scopes, revisions and idempotency.
4. Test fresh install/first admin and native Postfix/Dovecot lookups on disposable OpenBSD installation.
5. Add OSMAP shared UX and session regression while implementing isolated admin browser pages.
6. Add legacy adapter, Path A handover and then independent Path B migration/rollback rehearsals.
7. Execute threat-driven WSTG, direct service tests, backup/recovery and production preflight.

### 16.3 Defect record

Minimum defect fields: `finding_id`, case ID, affected version and environment, exact boundary, actual vs expected, exploitation or failure consequence, reproducible bounded steps, screenshots/config excerpts with secrets redacted, authoritative proof, priority, remediation commit, regression test and retest result. Do not close a defect merely because a UI message or unit test now passes. Retest the original failing native boundary.

## 17. Final test summary template

```text
release_and_commit:
mode: native_fresh_install | legacy_schema_writer_handover | native_schema_migration
host_and_environment:
observed_component_and_config_matrix:
issue_85_feature_parity_dispositions:
functional_test_statuses:
database_and_writer_statuses:
postfix_dovecot_osmap_native_statuses:
security_and_wstg_v42_coverage:
ux_and_accessibility_statuses:
migration_and_rollback_statuses:
backup_and_full_restore_statuses:
production_smoke_statuses:
open_findings_and_blocked_capabilities:
uncertain_or_unreconciled_operations:
post_install_actual_writer_and_schema:
postfixadmin_retirement_status: not_authorized | separately_authorized | complete
release_decision: go | no_go
approver_and_timestamp:
sanitized_evidence_manifest_and_checksums:
```

The accepted system is one where a new domain/mailbox can be created, administered, authenticated and served through **real Postfix, Dovecot and OSMAP**, with verified privilege separation, single-writer ownership, preserved data, and a demonstrated path to recover safely from interrupted changes. Everything else is supporting evidence.

## 18. Official sources and repository anchors

### Original standards and vendor maintainers

- OWASP Foundation, [Web Security Testing Guide, pinned v4.2](https://wstg.owasp.org/v4.2/4-Web_Application_Security_Testing/) and [WSTG versioning guidance](https://wstg.owasp.org/).
- OWASP Foundation, [Application Security Verification Standard 5.0.0](https://asvs.owasp.org/).
- OpenBSD Project, [System Management and `syspatch` guidance](https://www.openbsd.org/faq/faq10.html), [`syspatch(8)`](https://man.openbsd.org/syspatch.8) and [`pkg_add(1)`](https://man.openbsd.org/pkg_add.1).
- Postfix Project, [MySQL lookup support](https://www.postfix.org/MYSQL_README.html) and [Postfix documentation](https://www.postfix.org/documentation.html).
- Dovecot Project, [SQL authentication, Dovecot 2.3](https://doc.dovecot.org/2.3/configuration_manual/authentication/sql/), [Dovecot 2.3 auth debugging and native `doveadm` checks](https://doc.dovecot.org/2.3/admin_manual/debugging/debugging_authentication/) and [current Dovecot documentation](https://doc.dovecot.org/).
- MariaDB Foundation and MariaDB plc, [MariaDB documentation](https://mariadb.com/docs/) (DDL implicit commit, grant semantics and installed-version migration syntax must be verified against the selected release).
- PostfixAdmin maintainers, [PostfixAdmin upstream](https://github.com/postfixadmin/postfixadmin).

### Project-controlled sources

- [OSMAP GitHub repository](https://github.com/unattributed/OSMAP), [OSMAP-ADMIN project plan PR #84](https://github.com/unattributed/OSMAP/pull/84), [PostfixAdmin parity issue #85](https://github.com/unattributed/OSMAP/issues/85).
- [openbsd-mailstack](https://github.com/unattributed/openbsd-mailstack), especially `docs/install/`, `docs/03-mariadb-and-sql-foundation.md`, `docs/05-postfix-core-and-sql-integration.md`, `docs/06-dovecot-auth-and-mailbox-delivery.md`, `docs/16-maintenance-upgrades-regression-and-rollback.md`, `docs/production-mail-blackbagsecurity.md` and `scripts/verify/`.
- `openbsd-self-hosting`: private operator-owned project, read only for test-plan context, never a public source of credentials or raw operational evidence.
- Current OSMAP `AGENTS.md`, `Makefile`, `maint/security/`, `maint/ux/`, `maint/openbsd/MAIL_STORAGE.md`, `docs/UX_DECISIONS.md` and exact current source/test revisions.

**Change discipline:** Update this plan whenever a supported feature, backend integration, authorization contract, risk treatment or recovery model changes. Preserve the mapping from claims to actual evidence. Proposed tests become accepted results only after execution on a named environment and review of the source-of-truth state.
