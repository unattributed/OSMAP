# Persistent guarded mutation service (disabled source increment)

The earlier `serve_native` accepted one connection and exited; the actual local
RED reproduces service exit after one completed public request. This increment
adds a persistent serial listener on the exact separately granted purpose
socket. It retains the same inode and supervisor across new authenticated
connections; idle polling never supplies a new operation deadline. A refused
connection closes without reconnecting, replaying its bytes or resetting stores.
Each new request still passes actual peer and independent guarded MAC/action
checks. Durable intent/replay decisions remain the worker's existing authority;
service persistence itself supplies no replay exemption or credential writer.

The granted parent/socket are checked before each accept and accepted connection.
Socket replacement causes service refusal and the replacement inode is preserved.
An uncertain owned-worker cleanup stops admission and retains the exact unreaped
child owner; no terminal reply, reset, automatic retry or restarted instance is
claimed from that outcome. Shutdown closes the listener and unlinks only its own
inode. Native startup still requires the false dependency/confinement/grant gates;
private fixture listeners remain unchanged and cannot run this persistent path.

The new fixed service entry admits no caller-selected arguments, files, account
or endpoint. It disables core dumps before private bootstrap/key loading; child
workers inherit that limit. SIGTERM/SIGINT remove future admission, while an
already admitted operation keeps its original bounded deadline. Forced service
termination, remote issuer death, nested native worker watchdog and cross-host
stop/clock behaviour still require native qualification. The rc.d source does
not configure an automatic restart or install/enable a service.

Actual local verification: old service RED1, same lifecycle countercase GREEN1,
eight new service cases and26 preserved granted/supervisor/native cases PASS.
After the narrow core-limit addition, the exact changed signal/core case passed
again; no unrelated tests were rerun. Public local files/Unix sockets and child
pipes prove persistence, idle/refusal behaviour, uncertainty, inode retention,
graceful admission stop and default-off boundaries. Workers in the service
fixtures return public transport responses without native SQL/current-password
or mail effects; this is not password-change success, native qualification or
human UAT. Native profile confinement, connector grant/SSH route and complete
SMTP containment remain open; no operator credential/config/service was changed.

## Paired browser client configuration (source-only, 2026-10-15)

The browser now distinguishes absent account configuration (legacy mode), a
complete but unavailable configuration (refuse authentication/session admission),
and a qualified Ready capability owning both admission and mutation clients.
It never enables admission alone or falls back after configured construction
fails. The complete group is:

- `OSMAP_ACCOUNT_ADMISSION_SOCKET`
- `OSMAP_ACCOUNT_ADMISSION_KEY_FILE`
- `OSMAP_ACCOUNT_ADMISSION_HELPER_UID`
- `OSMAP_ACCOUNT_MUTATION_SOCKET`
- `OSMAP_ACCOUNT_MUTATION_KEY_FILE`
- `OSMAP_ACCOUNT_MUTATION_SESSION_PROOF_KEY_FILE`
- `OSMAP_ACCOUNT_MUTATION_HELPER_UID`

Partial configuration, malformed/relative/shared paths and invalid explicit peer
UIDs are refused. The two typed clients must load three distinct purpose keys;
password completion uses the mutation client owned by that same capability.
Configuration Debug output is redacted. Existing native qualification gates
remain false, so configuring this group currently refuses rather than enabling
password changes. No deployed environment, grant, key, account or service was
changed. Actual peer/relay/native factory and full required containment must be
qualified, and the new paths admitted to the real OpenBSD confinement, before
installation/activation. Existing legacy cookies do not become epoch-bound:
configured-unavailable/Ready admission rejects them without rewriting records.

## Private primary command source (not provisioned)

The mutation-only primary command selects the separate fixed
`/var/dovecot/osmap-account-auth-client` listener and dedicated `_osmapprimary`
identity. Existing ordinary auth-client0600 is untouched. The account-bound
producer requires exact public executable/library/module custody, private socket
DAC plus a separately measured kernel peer, then irreversible private IDs before
locked confinement. Neither the listener nor identity is currently provisioned;
PEER_BIND_UID remains None and the source profile registry remains empty. Local
construction tests cannot authorize production authentication or activation.
