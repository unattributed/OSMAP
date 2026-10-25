# Local development database and isolated Toronto replica

Keep `mail.blackbagsecurity.com` authoritative. A separate MariaDB instance on
obsd1 receives its `postfixadmin` database as a read-only baseline, retaining that
schema name. The original instance at `/var/run/mysql/mysql.sock` and its writable
`postfixadmin` development dataset remain untouched. There is no channel back to
Toronto. These are configuration examples, not an automatic installer.

| Role | Socket/listener | Datadir |
| --- | --- | --- |
| Existing writable development | `/var/run/mysql/mysql.sock`, existing3306 binding | Existing, unchanged |
| Separate read-only baseline | `/var/run/mysql-osmap-replica/mysql.sock`, `127.0.0.1:3307` | `/var/mysql-osmap-replica` |
| Source transport on obsd1 | `127.0.0.1:13306` forwards to Toronto3306 | Separate SSH material |

The helper fixes local `postfixadmin` at the original socket; Dovecot route
admission fixes the same schema. The replica socket is never selected by the
application. Any future baseline-to-development refresh is separate and must
preserve local fixtures, epochs, sessions and divergent test passwords. Database
replication alone does not switch auth/mailbox relays or qualify local UX.

## Separate instances

Merge [source-mysqld.cnf.example](source-mysqld.cnf.example) into Toronto's existing
configuration after review. Enabling binary logging requires a separately planned
MariaDB startup/restart; these artifacts perform neither. Preserve other settings.
Inspect actual ROW logging, distinct server IDs and classic binlog file/position
support afterward. No new log storage engine or version-string gate is introduced.
Keep source logs through seed/catch-up, then apply a disk-aware retention policy.
A dump with no connected replication channel is only a snapshot.

Install [replica-mysqld.cnf.example](replica-mysqld.cnf.example) separately as
`/etc/osmap-db-replica.cnf`, root:`_osmapdbrepl`,0640. Do **not** merge it into the original
instance's configuration. It fixes data/socket/listener/log/PID paths, server ID44,
`read_only=ON` and `replicate_do_db=postfixadmin`. There is no database rewrite.
Qualified source DDL stays in this separate instance rather than addressing local
UX data in a shared engine. The applier and privileged administration are trusted;
baseline inspection uses a SELECT-only account without read-only bypass.
Do not import source users/grants, triggers, routines or events.

Refuse an existing datadir or unexpected channel. Root first creates a fresh
`/var/mysql-osmap-replica`, owned `_osmapdbrepl:_osmapdbrepl`,0700, then initializes only it:

```sh
/usr/local/bin/mariadb-install-db --defaults-file=/etc/osmap-db-replica.cnf \
  --user=_osmapdbrepl --datadir=/var/mysql-osmap-replica \
  --auth-root-authentication-method=socket \
  --auth-root-socket-user=_osmapdbrepl --skip-test-db
```

Confirm the installed initializer supports these explicit socket-authentication
options before initializing. The dedicated `_osmapdbrepl` OS principal keeps the
replica separate from the original server's `_mysql` identity.
Use socket-authenticated root administration on the new socket; do not reuse the
original instance's credentials/system tables. Inspect resulting accounts/grants
and refuse unexpected anonymous access before exposing its listener.
See [mariadb-install-db](https://mariadb.com/docs/server/clients-and-utilities/deployment-tools/mariadb-install-db).

The [replica RC script](rc.d/osmap_db_replica) uses a root-owned symlink in a
protected root-owned directory:

```text
/usr/local/libexec/osmap-db-replica/mariadbd -> /usr/local/libexec/mariadbd
```

It follows vendor updates without copying executable bytes. Keep original
`/etc/rc.d/mysqld` unchanged. Its generic vendor-path process expression must not
match the new instance; the new service selects the distinct argv path and exact
defaults file. Prove actual argv/pgrep separation and both loaded executables
before any stop/restart operation. PID files alone do not establish ownership.
The new service recreates only its own private runtime directory after boot; it
does not initialize data or remove stale sockets. Retain normal OpenBSD RC startup
rather than replacing its monitor shell with an `exec` override.

## Dedicated SSH tunnel

The [tunnel RC script](rc.d/osmap_db_replica_tunnel) uses a dedicated local
`_osmaprepl` principal and new purpose-specific key. Install its root-owned
[wrapper](libexec/osmap-db-replica-tunnel-run.ksh) at
`/usr/local/libexec/osmap-db-replica/osmap-db-replica-tunnel-run.ksh` in the
protected root-owned directory. Never reuse auth/mailbox/admission/mutation
identities or multiplex control sockets.

The RC service tracks the persistent wrapper, which waits for its one SSH child
and reconnects after a five-second backoff. TERM/HUP/INT stop reconnection,
forward TERM only to the current owned child and wait/reap it. This restarts only
transport: it does not reset a replication channel, skip SQL errors, change
positions, or repeat an application operation. Provision private log directory
`/var/log/osmap-db-replica`, `_osmaprepl`,0700, and `tunnel.log`, same owner,0600.
The wrapper validates custody and captures every SSH stderr from child birth,
including pre-listener failures. Raw SSH diagnostics remain private. Preserve
and rotate that log through normal operations; never export it without review.

| Path | Custody |
| --- | --- |
| `/var/lib/osmap-db-replica` | Physical protected directory, no group/other write |
| `/var/lib/osmap-db-replica/keys` | `_osmaprepl`,0700 |
| `/var/lib/osmap-db-replica/keys/replication` | `_osmaprepl`,0600 private key |
| `/var/lib/osmap-db-replica/known_hosts` | Root-owned,0640, tunnel-group readable, independently pinned Toronto key |

The fixed tunnel is obsd1 `127.0.0.1:13306` to Toronto `127.0.0.1:3306`, at
`216.128.179.75` through a separate remote `_osmaprepl` account. Provision the
protected authorized key with `restrict,port-forwarding,permitopen="127.0.0.1:3306"`
and validate this account's effective SSH policy:

```text
Match User _osmaprepl
    AllowTcpForwarding local
    AllowStreamLocalForwarding no
    PermitOpen 127.0.0.1:3306
    PermitListen none
    MaxSessions 0
```

This allows `ssh -N`, refusing shell/subsystem sessions and reverse forwarding;
`permitopen` alone does not disable reverse forwarding. There is no password
fallback, shared master or mail-service dependency. Occupied local ports refuse
startup. SSH liveness does not prove replication connectivity.
See [sshd key options](https://man.openbsd.org/sshd.8) and
[sshd configuration](https://man.openbsd.org/sshd_config).

Provision a separate Toronto SQL replication account restricted to the observed
loopback TCP peer and the required replication privilege, with no table-write or
administrative grant. Keep its separate password out of argv, environment, public
SQL, logs and evidence. Configure the connection privately through a root-owned
descriptor/stdin, and protect persisted connection metadata in the new datadir.
SQL authenticates the forwarded connection independently of SSH.

## One-time seed and positional channel

Preserve original instance identity/configuration/grants and complete local dev
row digests. Bootstrap and qualify the separate empty instance before production
source changes. Recheck transactional engines and unsafe objects; the initial
observed schema was InnoDB with no triggers/routines/events. Refuse an unexpected
baseline/channel. Retain partial imports for reconciliation rather than retrying.

Use a protected source option file as the first client option:

```sh
umask 077
/usr/local/bin/mariadb-dump --defaults-file=/root/osmap-replica-source.cnf \
  --single-transaction --master-data=2 --hex-blob \
  --skip-triggers --skip-routines --skip-events --skip-add-drop-table \
  postfixadmin > /var/backups/osmap-postfixadmin-seed.sql
```

Use that snapshot's commented file/position, not a later status sample. Consistent
coordinates briefly require the dump's lock; exclude concurrent DDL. This private
dump contains account data/password hashes: protect transfer/storage/disposition.
Do not dump/import `mysql` or use `--all-databases`. Create only `postfixadmin` in
the new instance and inspect the single-schema dump before importing it:

```sh
/usr/local/bin/mariadb --defaults-file=/etc/osmap-db-replica.cnf --user=root \
  --database=postfixadmin < /var/backups/osmap-postfixadmin-seed.sql
```

The explicit defaults file's `[client]` selects the replica socket. Verify its
server ID and socket before creating/importing; never fall back to the original
instance. Privileged root can bypass replica read-only for this seed.

Privately configure `MASTER_HOST='127.0.0.1'`, `MASTER_PORT=13306`, the dedicated
SQL username/password, exact snapshot `MASTER_LOG_FILE`/`MASTER_LOG_POS`, and
explicit `MASTER_USE_GTID=no`. Start the channel after the tunnel is ready.
Never use `RESET MASTER`, skipped events or guessed positions as recovery.
Source schema events no longer share a database engine with local UX data;
ordinary replication errors still require reconciliation.
See [mariadb-dump](https://mariadb.com/docs/server/clients-and-utilities/backup-restore-and-import-clients/mariadb-dump),
[CHANGE MASTER TO](https://mariadb.com/docs/server/reference/sql-statements/administrative-sql-statements/replication-statements/change-master-to)
and [replication filters](https://mariadb.com/docs/server/ha-and-performance/standard-replication/replication-filters).

## Qualification and operation

Observe both threads running, no IO/SQL error, source/applied coordinates, filter,
actual read-only value and meaningful lag. Zero lag alone is insufficient. Compare
source/baseline schema, counts and deterministic complete row digests at a
consistent checkpoint. Prove an unprivileged baseline account cannot write.
Recheck original instance identity/config/grants/dev rows against saved evidence.

Use an authorized source binlog rotation and observe replica progress to that
file/position without changing a production row. Keep instance, tunnel, replication
and preservation outcomes distinct. At boot the tunnel precedes expected replica
IO connectivity; retain normal reconnection. Add no mail-service restart dependency.
Local UX readiness separately requires local authentication, mailbox authority,
password mutation, epoch/session and browser evidence on the original writable
dataset. A reference replica neither qualifies those journeys nor changes Toronto
passwords.
