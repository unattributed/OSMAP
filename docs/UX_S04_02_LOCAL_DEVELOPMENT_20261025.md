# S04-02 local development and database authority — 2026-10-25

## Current result and boundary

**The authority split is confirmed and an isolated read-only reference replica is
running. Fully local OSMAP development onboarding and human acceptance remain
pending. This is not production password-change readiness or a production S04
PASS.** Earlier controlled obsd1 transaction/session results retain their original
scope; they did not establish that a real mailbox used Toronto's credential
authority.

The operator selected obsd1 for all OSMAP UX development, with local authentication,
mailbox access and controlled development accounts. Toronto remains the live mail
authority. Remote-provider implementation was stopped before any such provider
or remote password-mutation route was implemented. The reference replica is not
the development application's database.

## Failure, analysis and smallest correction

1. A real operator login incident exposed different credentials in the two
   databases. Toronto reflected the recent administrative reset; obsd1's local
   row was old. Both instances were writable, had server ID 1 and binary logging
   disabled, and had no configured replication channel. A hostname or matching
   schema name did not make their data the same authority.
2. The configured native account pair selected local SQL and local Dovecot.
   Preserving a legacy relay path elsewhere in the environment did not preserve
   the authentication route selected by that pair. Local epoch 0, null change
   time, no consumed intents and no uncertainty marker did not establish a
   successful OSMAP write to Toronto. The generic unconfirmed result screen,
   without verified time, was also insufficient evidence of a completed write.
3. The exact previous relay environment was restored with the same ordinary Web
   image. Their identities are recorded below. Actual HTTP
   readiness returned. This restoration did not reset credentials, epochs,
   factors or stored sessions, and preserved the operator's Toronto reset.
4. A source regression demonstrated that production configuration accepted a
   native local account runtime combined with known remote auth/mailbox bridge
   paths. The correction refuses either exact known bridge path before startup,
   including rollout configurations. Local native and relay-only controls pass;
   unfamiliar Unix paths are not classified by assumption. RED, GREEN and normal
   compilation evidence are retained. **The corrected source guard is not yet a
   newly built/deployed native runtime claim.**
5. A shared-instance schema rewrite was reviewed, then superseded because
   qualified DDL could address development data. The selected correction uses a
   separate local MariaDB instance with a separate OS principal and datadir,
   retaining the source schema name without rewriting it.

## Installed database separation

| Role | Actual authority and interface | Isolation |
| --- | --- | --- |
| Toronto live mail | Authoritative `postfixadmin`; local source SQL listener | One-way source only; no channel writes back |
| obsd1 writable development | Existing `postfixadmin`, `/var/run/mysql/mysql.sock`, original port 3306 service | Existing native helper and local Dovecot route; original `_mysql` instance retained |
| obsd1 reference replica | `postfixadmin`, `/var/run/mysql-osmap-replica/mysql.sock`, loopback port 3307, server ID 44 | `_osmapdbrepl` UID 1007, `/var/mysql-osmap-replica`, `read_only=ON`; not selected by the application |

The original development database was not refreshed from production data. The
replica contains private production account data and credential hashes; these
are privileged reference material, never test credentials or public evidence.
Source application SQL accounts were not imported. A separate SELECT-only
baseline account could read, while a write was denied; error 1142/1290 observations
are retained. Privileged administration and the replication applier remain
trusted writers of the reference instance.

The explicit database-replication task included one planned Toronto MariaDB
restart at approximately 18:03 UTC. It enabled ROW binary logging, server ID 1,
seven-day retention and `sync_binlog=1`. The operator credential/status row
matched its pre-action observation, and a Dovecot userdb check passed. Postfix
and Dovecot were checked, not restarted. The initial native RC process check
preceded Unix-socket readiness: the immediate SQL query returned error 2002.
That failed observation remains retained. A later readiness read succeeded on
the same new database process; no second restart was used to erase the failure.

The consistent seed used `osmap-source-bin.000001`, position 757 from the
snapshot's own receipt. Both replication threads subsequently reported running,
with no IO/SQL error and observed lag 0. All 17 source/baseline extended table
checksums matched. These are actual snapshot/channel observations; lag 0 alone
would not establish health or data equality.

## Transport recovery and preservation

The dedicated `_osmaprepl` SSH identity uses a pinned Toronto host key and only
the fixed loopback port 13306 to Toronto port 3306 forward. It does not reuse application
auth/mailbox/admission/mutation keys. The remote account restricts forwarding
and denies shell/subsystem sessions. The replica has its own normal RC service;
its distinct vendor-symlink argv avoids selecting the original database service.

The reconnecting tunnel wrapper records private SSH diagnostics from child birth,
waits for its current child and reconnects after a five-second backoff. The actual
owned-child-loss test observed a replacement child and restored transport.
Wrapper shutdown reaped its child and removed the listener; stop/start then
resumed the replication channel without SQL reset. This qualifies the observed
failure/recovery sequence, not every future network outage or update condition.

Backups, earlier bootstrap refusals, the source socket-readiness failure and all
superseded review records remain private evidence. No failure is relabelled as
PASS, and no unobserved historical process signal is assigned a cause. Replica
health does not authorize modifying an uncertain credential transaction.

## Remaining local application work

The public [development environment example](../maint/openbsd/osmap-serve-development.env.example)
specifies the existing obsd1 HTTPS edge, production runtime safeguards, enforced
confinement, fixed local native sockets and isolated qualified state. The local
mailbox helper was observed as vmail UID 2000 with the local userdb/maildir mapping;
its exact grant needs the protected Web-readable copy described in the private
setup plan. Example/source review is complete; installation/onboarding is not.

Before local UX readiness:

- Bind both actual native allowlists, remove only the four incident-added real
  mailbox identities from those policy arrays, retain the exact five controlled
  identities, and add one fresh synthetic `@osmap-password.invalid` account.
  Preserve all old real and controlled SQL, epochs, locks, markers, factors,
  replay counters and sessions as evidence.
- Provision only that fresh local account, random password, independent random
  TOTP secret and local maildir. Deliver onboarding through an operator-owned
  0600 file under a private directory; never publish credentials or substitute
  production hashes. No production message import, external delivery or real-user
  OpenPGP operation is part of this setup.
- Install the source-bound ordinary local profile and perform the actual normal
  MFA login, local mailbox navigation and required password/epoch/session journey
  on the development dataset. Preserve the one-operation/no-ambiguous-retry rule.
- Reconcile installed evidence and only then conduct the separate human T09
  review. Earlier controlled QA and a healthy reference replica do not replace it.

## Evidence references

Private artifacts are retained under
`/home/foo/Downloads/osmap-ux-s04/installed-integration-20261025/operator-login-incident01/`.
This report publishes references and digests only, not raw diagnostics, private
administrative screenshots, credentials, hashes of individual passwords or keys.

| Artifact | SHA256 |
| --- | --- |
| Restored ordinary Web image | `f48d04463a868180cd49d1a3d6a085e023280343db9da6fccda773ce36a1353f` |
| Restored original relay environment | `92a3073166a337ab975377cdbfeca0c90b2cff0a2f97cf03092bcf3617b5d8c4` |
| `authority-source-independent-review.json` | `22cb6d9332517d993d4bf8ccb143bafceac27d9ce14cf5050bcc81ff00c49c98` |
| `config-guard-independent-review.json` | `016afe0eb849eb080d7d60f15886847eae9179ffeb725fed9ae8ba259fda3b78` |
| `replication-source-activate01.actual.log` — retains initial readiness refusal | `62d84359c8e6dba6e3c8b501e1387f88731384f8385dc7ca94021cbf4560f839` |
| `replication-source-readiness-reconciliation.actual.log` | `ad975b7d59706b16be11340f8ebdf2ed9245f5876f3ae46f21d11f5785f67a8b` |
| `replica-seed-data-comparison.json` | `75d42b1d3e5bfc39f6851dc525e7df0f1806ccb62950870c8524192e8c21b018` |
| Source and replica 17-table checksum files — matching file digests | `186f3f2b75d9b358a8b26944b89fbfc353ab658e2984a967851d8669f854043f` |
| `replica-readonly-qualification02.actual.log` | `83884ba57a1babb5301308e488b077b20b2779d3cc15f365c58b2958418ee3fc` |
| `replica-transport-recovery-test01.actual.log` | `5b2741b8c4655bca62808b6383092ff9a2c6a7d6c74e22a5f3f3105577dac7eb` |
