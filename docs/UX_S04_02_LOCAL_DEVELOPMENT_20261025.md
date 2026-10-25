# S04-02 local development and database authority — 2026-10-25

## Current result and boundary

**The stock-bcrypt compatibility defect is corrected and native-qualified.**
The updated ordinary helper completed one real controlled stock-format password
change through the normal HTTPS application. Owner retry is ready; Duncan's
current password and TOTP remain unchanged by qualification. Owner login and
page access are confirmed; the earlier owner's refused change remains a known
no-write result, and human T09 acceptance is pending.

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
   compilation evidence are retained. Ordinary native Web build06 subsequently
   completed from signed source `8f3ce62`; its matching image is now installed
   and separately qualified by the ordinary local application observations below.
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

The replica applied an authorized source log rotation to
`osmap-source-bin.000002`, position 400. Its own stop/start then automatically
resumed both replication threads while the original development database process
remained unchanged. Both replica services were enabled and their configured boot
order places the tunnel before the replica. **No system reboot was performed;**
configured boot persistence is distinct from an observed reboot recovery.

Backups, earlier bootstrap refusals, the source socket-readiness failure and all
superseded review records remain private evidence. No failure is relabelled as
PASS, and no unobserved historical process signal is assigned a cause. Replica
health does not authorize modifying an uncertain credential transaction.

## Installed local application result

The [development environment](../maint/openbsd/osmap-serve-development.env.example)
is installed behind the existing HTTPS edge with production runtime safeguards,
enforced confinement, local native account sockets and local Dovecot/mailbox
helper. The Web grant copy matches the existing local helper's bytes, and its
observed peer is vmail UID 2000. The application does not select the read-only
replica or Toronto bridge endpoints.

Only the four incident-added real identities were removed from both native
allowlists. Their rows, epochs, factors and other evidence were retained. The
five controlled identities remain, with one fresh synthetic development account
added, giving identical six-account policies. One initial local mailbox-row
birth provisioned a random password, independent random TOTP seed and local
synthetic Maildir. The owner receives these in a 0600 onboarding file under the
private sprint directory. No production hash or mail content was imported, and
no external message was sent.

The first cutover stopped at Web bootstrap because root-to-Web `doas` required
authentication. Native `su` under root was observed to select UID 1001; a guarded
residue-only recovery then completed bootstrap and the main Web start. It did
not replay the SQL insert, configuration publication or unsafe-log fixture.
The matching loaded Web PID 59501 returned HTTP 200 and certificate-verified
canonical HTTPS 200. Root helper PID 31435 uses the unchanged qualified `0f95…`
service binary and new `766c…` RC. The owned unsafe-log symlink was refused with
no helper birth and an unchanged canary; ordinary startup then held descriptors
1 and 2 on the protected root-0600 log inode.

A normal browser password-plus-TOTP login succeeded at 19:06:36 UTC. The local
Inbox showed the synthetic message. Both Security and Authentication & Recovery
opened the enabled empty password form, all three visibility controls toggled
independently, and Cancel returned to Security. The unchanged account correctly
showed Last change unknown. This onboarding check submitted zero password-change
POSTs. Existing controlled T03–T05 mutation, epoch/session and containment results
are reused because their product paths/helper are unchanged; no further mutation
was needed to repair access or repeat those successful tests.

Readback preserved all prior local mailbox rows and 51 protected files. The
fresh row is unchanged after login, epoch 0 is active, the uncertainty marker is
absent, and the ordinary login created its TOTP replay counter. Both replica
threads still run with zero errors and zero lag. The first read-only environment
observer matched the bridge name in a comment; its assignment-only correction
passed without changing the installed application. Both observations are retained.

Human T09 remains pending. Use the [short owner review](UX_S04_02_T09_ACCEPTANCE_20261025.md)
with the separate development credentials. S04-02 is not ACCEPTED until the owner
records that usability result.

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
| `replica-persistence-and-boot01.actual.log` | `aaa188288dff2fb6acb565a7db9e0db719427e6c69015e6c54f2013b5ba0d3e7` |

Native build06 evidence is retained in the sibling `build06/` directory.
`native-build.log` has SHA256
`f1f52ec16a00cc19768ef8a55129cda5bd7516e568d4787cb485ee65b842992b`;
the ordinary Web image has SHA256
`2678b7308fdc4231bef42e0bfe8df1c49c04eee545ffa89d10eeaace7c26bcd5`.
The build uses the unoptimized development profile and does not rebuild the
ordinary helper or supply an installed journey result.

Final installed local-development evidence is retained in the sibling
`local-development01/` directory. Its independent actual review is
`actual-final-independent-review.json`, SHA256
`c22836d797c8917cfaf4c85d5bca851d43727de0b0bf0b700ef4cd768178676c`,
pinning 20 current artifacts. This is the current profile's readiness review,
separate from the earlier controlled 20-requirement acceptance mapping and from
human T09. The original initial-cutover failure, residue-only recovery, corrected
read-only observation and private resource backups are retained independently.
The matching `reconciliation.corrected.actual.json` has SHA256
`18a34ad83182ec48d162d677f9ba30e9037baeb74bec6b6f0ec4eeab3d9f4a7c`.

## Stock bcrypt compatibility failure and correction

The operator confirmed normal login and password-page access after the requested
local credential synchronization. Their following password-change attempt was a
known no-write refusal. The helper's bounded snapshot-read diagnostic records SQL
status 0, 140 stdout bytes, zero stderr bytes and parser phase 9. That phase checks
the stored hash language: the imported valid 60-byte bcrypt lacked the BLF scheme
prefix required by the reader. The current row remained unchanged at epoch 1,
active with no uncertainty marker. The operator made no new PostfixAdmin change.

The source correction recognizes the stock raw bcrypt representation for reads
and exact conditional comparisons, without adding a prefix or changing original
bytes. Native credential authentication still governs password interpretation,
and new hashes remain Argon2id-only. Public-fixture RED/GREEN regressions cover
read, exact CAS, zero-row conflict, malformed encodings and replacement-output
refusal. Matching ordinary helper installation and controlled native qualification
are the next checks; the owner's candidate password is neither retained nor replayed.

## Installed stock-format qualification

Signed source `67148da77971da244618d5f6f89a717af7b322c4` produced ordinary helper
`be7c6b40b25e5fe88d3a39dbb49e1881a7a2d76a2bef415b063b5ac51396029c`.
The original helper is backed up. The Web image remains `2678b730…`; its process
was restarted after the helper published both fixed socket leaves so that native
client custody captures their new identities. Configuration and protected account
state passed upgrade preservation. No credential write was part of installation.

The existing twenty-request ordinary HTTP driver was reused with only fixed
fresh account names and canonical HTTPS URL/Host/Origin changes. A fresh controlled
target began with a real unprefixed bcrypt hash; its control began with Argon2id.
One password POST completed at 2026-10-25 21:01:10 UTC. Independent SQL and Store
readbacks verified replacement Argon2id, active epoch 1, two old sessions revoked,
new session valid, unchanged control and exact rendered authoritative time. The
old password was refused before the replacement was accepted. Result capability
isolation, reload and four Security/Authentication history views passed.

The policy scope was temporarily seven to nine, then restored byte-exactly to
seven. The updated helper, both bound sockets, normal Web and HTTPS200 passed
restoration. All prior SQL rows and account-state/marker/factor/replay/key and
session-authority invariants passed preservation, including Duncan and retained
containment evidence. Fixture data is retained and its two accounts removed from
native enrollment. No real-user password-change request was dispatched during this qualification.

Private evidence is in `bare-bcrypt-compatibility-20261025-01/ordinary01/` beneath
the existing integration artifact root. `actual-result.json` SHA256 is
`3d1ce50b6be398e890379af81fbc3ee9e3e6c21707b7e8c7c22138efe0f03e3f`.
Local protocol preflight exposed a Python module-name collision before any host
credential operation. The private procedure was renamed and the actual checks
were rerun from the real working directory. The old script and first failure are
retained. This test-runner correction is separate from the product hash parser.

Owner retry uses the unchanged current credential and fresh TOTP in a newly
loaded form. Saving a new local password belongs in the separate obsd1 development
entry; Toronto remains the production authority. Human T09 is still pending.

The independent actual qualification review is `ordinary01/actual-independent-review.json`,
SHA256 `0408ff37e1c44c10efd0c522b0052c7f94f3eddf14fea5a2437fa2cb2cea6f38`.
It confirms native functional PASS separately from restoration PASS, with 62
protected files and six preexisting session-authority invariants preserved.
