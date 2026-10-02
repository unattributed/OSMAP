# obsd1 web to Toronto mail backend

The browser runtime remains on `obsd1.blackbagsecurity.com`. Two separate
unprivileged relays connect its `_osmap` runtime to the authoritative
`mail.blackbagsecurity.com` Dovecot auth listener and OSMAP mailbox helper. The
relays do not expose TCP mail ports or accept a client-selected destination.
The existing browser sendmail path remains on obsd1/Brevo; this transport does
not claim Toronto SMTP submission. The mailbox helper's Sent append, folder,
message, search, and mutation operations run on Toronto.

Install `relay.py` as
`/usr/local/libexec/osmap/mail-backend/relay.py` and the two `rc.d` scripts as
`/etc/rc.d/osmap_auth_relay` and `/etc/rc.d/osmap_mailbox_relay`. Run the
services as `_osmapbridge`, not as the web or mail-storage principal. The
scripts fix the remote address at `216.128.179.75`, the local trusted web UID
at `1001`, and every local path. Keep these values aligned with the actual
principals and pinned production SSH host key; do not substitute DNS or an
unqualified host.

Required obsd1 layout:

| Path | Ownership and mode | Purpose |
| --- | --- | --- |
| `/var/lib/osmap-bridge` | `_osmapbridge:osmaprt` `0710` | Private service root, group-searchable by web |
| `/var/lib/osmap-bridge/run` | `_osmapbridge:osmaprt` `2750` | Relay listeners; web has no directory write |
| `/var/lib/osmap-bridge/run/auth.sock` | `_osmapbridge:osmaprt` `0660` | Browser Dovecot auth path |
| `/var/lib/osmap-bridge/run/mailbox.sock` | `_osmapbridge:osmaprt` `0660` | Browser mailbox-helper path |
| `/var/lib/osmap-bridge/keys` | `_osmapbridge:_osmapbridge` `0700` | Separate `auth` and `mailbox` SSH identities, each `0600` |
| `/var/lib/osmap-bridge/control` | `_osmapbridge:_osmapbridge` `0700` | Separate `auth-ssh.sock` and `mailbox-ssh.sock` multiplexers |
| `/var/lib/osmap-bridge/known_hosts` | `root:_osmapbridge` `0640` | Pinned Toronto SSH host key; relay cannot change it |

The web `_osmap` principal needs membership in `osmaprt` to connect to the
listeners. The relay checks the native Unix peer effective UID with
`getpeereid` before opening SSH; socket permissions alone do not authorize a
request. On Toronto, each **distinct** root-controlled authorized-key entry
must use `restrict` and force `/usr/bin/nc -N -U` to exactly one corresponding
socket. The remote command supplied by this relay is the static `osmap-relay`
marker, never a path. Toronto's `_osmap` account has the minimum shell needed
for OpenSSH to execute the forced command. Do not permit interactive shell,
PTY, agent/X11 forwarding, or TCP/StreamLocal forwarding for these keys.

The mailbox helper additionally authenticates the SSH-side `_osmap` peer UID
against the owner of Toronto's `/var/run/osmap-auth` and verifies a short-lived
HMAC grant on every request. Its grant key must have identical **raw bytes** in
the protected obsd1 web and Toronto helper copies; the relay never reads it.
The browser client relies on the protected local relay, its pinned SSH host
key, and this helper authority check for response provenance. Keep the two
SSH control sockets purpose-specific: an SSH multiplexed session inherits its
master connection's forced-key authority and does not reauthenticate with a
different key.

Start both relay services and prove their peer-UID positive/negative controls,
auth response, mailbox-list response, and distinct remote forced destinations
before changing the obsd1 browser environment to the new sockets. Its local
TOTP store and OpenPGP services remain on obsd1. Set the browser's
`OSMAP_DOVEADM_AUTH_SOCKET_PATH` to
`/var/lib/osmap-bridge/run/auth.sock` and
`OSMAP_MAILBOX_HELPER_SOCKET_PATH` to
`/var/lib/osmap-bridge/run/mailbox.sock` together, then restart only the web
service. Retain its previous environment and the existing local helper for
rollback. The relay forwards binary bytes full duplex, closes SSH stdin only
after local EOF, continues reading the response, and imposes separate auth
and mailbox byte/deadline caps. It does not log passwords, grants, message
bodies, or remote SSH stderr.

If a relay is forcibly killed, inspect that service's process status before
removing only its stale listener socket. The relay refuses an existing socket
path on startup. For rollback, restore the previous obsd1 web environment,
restart web, then stop the two relays. Preserve production mailbox state and
the protected grant-key copies.

Focused checks:

```sh
python3 -m unittest -v maint/mail-backend/test_relay.py
ksh -n maint/mail-backend/rc.d/osmap_auth_relay
ksh -n maint/mail-backend/rc.d/osmap_mailbox_relay
```

The cross-principal `getpeereid` control in the test suite runs on OpenBSD
when invoked as root; the unprivileged run checks configuration and
cross-purpose rejection. Neither test contacts a mailbox.
