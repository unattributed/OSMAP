# Existing private primary service binding — S04-02

Reuse `maint/account-runtime/dovecot-private-primary.conf` under the existing
authoritative Dovecot master. Its fixed extra `osmap-primary-auth` service runs
`auth -o auth_policy_server_url= -o auth_cache_size=0`. These process-local
overrides remove the callback/cache from the private auth process while leaving
the public auth process, authoritative passdb and userdb definitions unchanged.
No separate master, database configuration, password store, TLS setup, runtime
directory or RC service is needed. Do not treat a caller's `service=imap` field
as a public policy exemption.

The fixed listener remains `/var/dovecot/osmap-account-auth-client`, mode0660,
owner `_dovecot`, group `_osmapprimary`. Actual identities must come from current
native account lookup; historical UID518 does not establish a kernel binder.
The private purpose child uses only this socket and its existing public utility
graph. It receives no SQL configuration, DSN, keys or additional database grants.

Current missing producer/consumer integration is in
`src/account_password_native.rs` (`NativeProfile::Primary`, `observe`, `socket`)
and the existing `src/account_password_peer.rs::Startup`. NativeProfile currently
pins the utility graph and listener owner/group plus an unavailable
`PRIMARY_PEER_UID=None`; it does not yet bind this private service to the current
public master and accepting private auth process. Keep that gate unavailable
until actual matching native evidence exists.

Root must pin the installed parent configuration containing the exact existing
fragment, its protected owner/mode/inode/bounded bytes/hash, and complete
effective extra-service settings. Verify stock installed Dovecot accepts both
fixed `-o` overrides and that the private process actually receives empty policy
URL/cache0 while the public process retains its original policy/cache settings.
Effective private service must preserve its one-process configuration and fixed
listener with no extra public/inet listener or changed passdb/userdb. Parent
configuration and any included files must remain bound to current effective
bytes; an unchanged fragment alone cannot qualify changed surrounding settings.

Reuse Startup's actual master PID/birth/parent/text device+inode/hash and fresh
recheck. Capture the private auth worker's exact parent, birth, UID/GID and text
identity, and the master's ownership of the exact listener descriptor. A current
zero-byte connection must observe kernel PID/UID/GID matching this daemon
context; then bind the accepting private worker/descriptor to that context.
Master-created/chowned listener credentials can describe the binder, not the
later acceptor. Recheck process identity and reciprocal socket ownership before
each fixed primary dispatch under the same original deadline. A matching socket
owner or peer UID alone is insufficient. The root native observer must produce
this typed binding; neither browser PID fields nor a configuration-ready Boolean
can do so.

Use existing nine-scenario qualification. T03's controlled Alice/Bob journey
proves private current-password authentication, then old rejection/new acceptance
after actual Alice CAS while the shared account guard remains Pending; Bob
authentication stays unchanged. Public Pending authentication must still fail.
No mail session, provider message or operator password change belongs to this
private prerequisite. Source review and the fragment's presence are not native
or installed PASS.

Root installs only the missing existing fragment using the maintained bounded
configuration helper and preserved original bytes/metadata, syntax-checks, then
performs the controlled private-service observation. Existing public configuration
and unrelated services remain preserved. Never unlink a live listener or signal
an historical PID. Any failure retains actual disposition and restores only
exactly owned changed configuration; rollback success requires matching live
service/configuration evidence. No execution or flag activation is performed by
this source contract.
