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

## Password browser entry (source-only)

GET/POST `/settings/password` uses the same qualified paired capability as login,
fresh step-up and stored-session completion. The browser derives availability
from that capability and an epoch-bound authenticated session. It never accepts
a caller-selected account, endpoint or writer. One original60s deadline spans
validation/preparation/completion; a completion error is unconfirmed, clears the
cookie and provides no repeat form. This does not establish server-side revocation
on uncertainty. Missing native qualification keeps the form unavailable.

The fixed visibility-only script has a page-specific exact hash CSP and no
network/storage permission. Server128-scalar/512UTF8 policy is authoritative;
HTML new/confirmation limits256 UTF-16 units so astral Unicode values fit.
Password history remains Unknown until an authoritative event supplies it.

## Shared SMTP control authority (source-only)

`smtp_control_startup.py` loads the existing fixed private bootstrap and distinct
control-purpose key without requiring a live control socket. Broker startup can
therefore obtain the same immutable authority before creating its endpoint;
guarded mutation independently validates that endpoint and rechecks both file
custody and accounts/keys. The loader creates no directory, key, socket or record.
Native broker, peer/CPID/TCP inspector and full workflow qualification remain
required; all native activation flags stay closed. Include this module in every
matching source/deployment manifest that imports the guarded builder.

The fixed public SQL/hash graph records now pin the October15 measured loader
cache. Only that leaf's content, size and timestamps changed in the read-only
comparison; all28 other public objects and ancestry matched. This refresh keeps
the same paths, permissions and custody checks, and does not explain the cache's
change origin or qualify the earlier failed SQL/primary command outcomes.

MariaDB11.4.12 unconditionally probes stdin window size even in batch mode.
The fixed SQL graph therefore admits tty; hash and primary do not inherit it.
This promise also permits broader tty ioctls, revoke with rpath and hidden libc
/dev/tty access that unveil cannot block. SQL retains pipe-only standard FDs,
close-fds, exact private config/socket and a fresh inherited session without a
controlling terminal; no terminal-device path is added. Native qualification
must bind actual child session/PGID/PPID to its born driver and retain all
original controls/proofs. The compatibility source does not enable a profile,
service, form or complete password workflow.

`smtp_auth_broker.py` supplies the disabled concrete dedicated-backend handler
and front acceptor. `smtp_native_peer.py` derives fixed standard-master process,
birth, executable and complete TCP ownership, then prepares a fresh inspector
under each AUTH's original3s budget. The single shared control/epoch registry
registers before credential forwarding and retains successful channels for
later password cutoff. Front listen follows an internal actual-control-listen
barrier; stop/EOF closes only owned channels/endpoints, retaining uncertainty.
Dedicated backend `/var/dovecot/osmap-account-smtp/auth.sock` and front
`/var/spool/postfix/osmap-account-smtp/auth.sock` are fixed source contracts,
not assumed provisioned paths. Backend kernel peer is None; routing/topology/
control/broker gates remain closed until matching native qualification.

The separate primary graph now permits only the existing null leafrwc with
wpath/cpath, required by Doveadm's mandatory initialization/default debug sink.
Primary retains its fixed private identity drop, exact null/device-parent lease,
root-/dev DAC and locked graph. No recursive directory, tty or new path is added.
Unveil c intrinsically includes leaf mutation, so the private identity/DAC are
mandatory; qualification never removes/renames/creates the actual device or
writes it. Original primary proof/cases and a distinct existing-null proof remain
required before native admission. This source increment does not enable services.

## Private account admission endpoint, 2026-10-15

The paired browser Runtime also requires the persistent
`osmap_account_admission_helper` endpoint. Its fixed rc entry proposes
`/etc/osmap/account-admission.json` and `/etc/osmap/account-admission.key`;
this source contract does not provision those files or qualify a peer UID.
The existing native confinement gate remains false until actual composition
passes. Do not infer an enabled password workflow from either endpoint alone.

Admission preserves peer-before-read, authenticated request/replay checks,
two-connection bounds, cleanup quarantine and exact owned socket removal. The
internal worker receives the smaller remaining original connection deadline
and authenticated request expiry. Its actual fixed material/private-primary
factory uses that same budget while the durable account epoch lock remains
held. There is no ordinary broad-config authentication fallback or fresh
operation startup allowance. Startup custody covers the fixed 33-module import
closure and exact `python3` to `python3.13` engine lease; native dispatch
rechecks that engine lease under the original deadline. No caller module,
identity, program, path or readiness Boolean supplies native authority.

The primary loader also requires the fixed library search directory used by
the existing hash graph. Its read-only grant is recursive, while the reused
custody checks cover immediate entries and metadata. Private identity, empty
groups, DAC and outside-read denial remain necessary; neither descendant
immutability nor native authentication follows from this source increment.

Search ancestors use the same fixed identity/permission policy as ELF/module
ancestors; unrelated parent size/timestamp changes do not invalidate that
authority. Full search-directory/member custody and fixed leaf hashes remain.

The persistent Rust admission parent seals its purpose-specific policy after
publishing the exact owned socket and before accepting credentials. Only the
protected endpoint, fixed interpreter alias/target and empty-permission ancestor
visibility are admitted. Root cwd is established before sealing and verified
before spawn; no recursive `/` or `/usr` read grant is used. The finite public
connection entry remains unavailable so it cannot bypass server-owned sealing.
This is a parent boundary only. The exec'd Python worker requires separate
confinement; native flags and the password workflow remain disabled pending
actual composed qualification. Source construction does not provision anything.

## Paired obsd1 → Toronto service wiring (disabled, 2026-10-16)

The maintained admission and mutation relays are separate from the existing
ordinary auth/mailbox relays. Install their reviewed source only after matching
qualification: `maint/mail-backend/{admission_relay.py,mutation_relay.py}` maps to
`/usr/local/libexec/osmap/mail-backend/`, and their existing `rc.d` entries map to
`/etc/rc.d/osmap_admission_relay` and `/etc/rc.d/osmap_mutation_relay`. Both run as
obsd1 `_osmapbridge`; each authenticates the local `_osmap` peer UID1001 and uses
its own SSH identity (`keys/admission` versus `keys/mutation`). Keep the pinned
root-owned Toronto `known_hosts`, exact216.128.179.75 target and existing bridge
root0710/run2750/searchable `osmaprt` layout. These values require fresh public
principal, group, path and host-key observations; this document does not assert
that a service or key exists. No account-purpose SSH multiplex master is used.

Toronto's root-controlled restricted authorized-key records must bind the two
**different public keys** to the two root-owned fixed connector scripts, for
example the following non-secret record shapes. Resolve the active root-owned
AuthorizedKeysFile from the existing SSH configuration; do not put an editable
key grant in the web principal's writable state. These placeholders are not
installable keys:

```text
restrict,command="/usr/local/libexec/osmap/account-runtime/osmap_account_admission_connector" ssh-ed25519 <admission-public-key>
restrict,command="/usr/local/libexec/osmap/account-runtime/osmap_account_mutation_connector" ssh-ed25519 <mutation-public-key>
```

The scripts require the literal `SSH_ORIGINAL_COMMAND` purposes
`osmap-account-admission` and `osmap-account-mutation`, respectively. They exec
only `/usr/bin/nc -N -U` to `/var/run/osmap-account-admission/admission.sock` or
`/var/run/osmap-account-mutation/mutation.sock`. Endpoint/key/purpose substitution,
interactive commands, PTY, agent/X11 and TCP/StreamLocal forwarding are not
part of either grant. The Toronto connector is the existing `_osmap` principal;
the helper checks its actual kernel UID. Do not substitute the obsd1 relay UID
for that remote connector identity.

Admission's existing `Service` reader accepts a protected root-owned parent
with group-search permission, and publishes socket0660 with that parent's GID.
A root-owned0710 dedicated admission-group namespace can therefore supply
connector traversal without any permission-reader change. The group name
`_osmapadmission` is a proposed provisioning role, not a currently observed or
source-enforced principal. Keep all unrelated users out of this dedicated group.
The fixed admission JSON's fields remain `version`, `socket`,
`trusted_web_uid` (the **Toronto connector UID**), and `accounts`; its exact
socket must match the forced connector above. The rc entry reads root-private
`/etc/osmap/account-admission.json` and `/etc/osmap/account-admission.key`.
The mutation namespace and private `connector-grant.json` retain the existing
source-enforced `_osmapmutation` grant and trusted-relay UID rules. Both actual
workers use the same authoritative `/var/db/osmap-account/epoch`; no frontend
copy, separate authoritative epoch or automatic provision/reset is permitted.

Only an isolated, explicitly qualified pilot web environment should receive the
complete seven-field group below. Keep the existing Duncan/main web process in
legacy mode while this qualification is incomplete. The example key directory
belongs to the isolated pilot, with exactly its three purpose copies readable
only by the actual obsd1 web UID (regular, single-link0600 files under protected
ancestors). Corresponding raw bytes must match the authoritative root-private
admission, mutation and session-proof keys; relays receive none of those keys.
The helper UID fields are the freshly observed **local obsd1 `_osmapbridge`
UID**, because that process owns the local socket and is the client's Unix peer;
they are not the Toronto root-helper UID. Replace the numeric placeholders only
from that observation before using this as an environment file:

```text
OSMAP_ACCOUNT_ADMISSION_SOCKET=/var/lib/osmap-bridge/run/admission.sock
OSMAP_ACCOUNT_ADMISSION_KEY_FILE=/var/lib/osmap-password-pilot/secrets/admission.key
OSMAP_ACCOUNT_ADMISSION_HELPER_UID=<observed-local-bridge-uid>
OSMAP_ACCOUNT_MUTATION_SOCKET=/var/lib/osmap-bridge/run/mutation.sock
OSMAP_ACCOUNT_MUTATION_KEY_FILE=/var/lib/osmap-password-pilot/secrets/mutation.key
OSMAP_ACCOUNT_MUTATION_SESSION_PROOF_KEY_FILE=/var/lib/osmap-password-pilot/secrets/session-proof.key
OSMAP_ACCOUNT_MUTATION_HELPER_UID=<observed-local-bridge-uid>
```

The existing serve launcher exports every sourced variable; it does not need a
new environment pass-through path. Native gates remain false, so source or
configuration alone still refuses instead of enabling the password workflow.
Qualification must cover real paired SSH/peer/group/key/bootstrap routing,
original deadlines, full authenticated password outcome and owned rollback.

Mutation relay stop now follows its source-owned SIGTERM/SIGINT handler, stops
future admission and interrupts blocked receive/forward waits. Cancellation does
not cancel the remaining original resource deadline needed to kill/reap an
exact still-owned SSH group. Reaped numerical groups receive only an absence
probe. Cleanup uncertainty still latches unavailable with no terminal reply or
retry. Graceful stop removes only the exact owned listener inode and restores
its captured handlers. Forced termination can still leave uncertain state;
this change grants no historical-PID cleanup or automatic socket replacement.
One finite local oldRED/newGREEN control qualifies this changed source boundary,
not native SSH, remote worker termination or complete password delivery.
