# OSMAP abandoned listener recovery

The five public/transport/crypto services need a root rc_pre hook because their Unix
listeners live in persistent /var/lib directories. A hard reboot cannot run
the normal service cleanup trap. Existing application startup refuses every
pre-existing socket; that refusal remains unchanged.

Before installing the updated relay rc.d files or running either OpenPGP
preparation script, install the reviewed `maint/service_socket_recovery.py` as
`/usr/local/libexec/osmap/service_socket_recovery.py`, root-owned, singly linked,
mode 0555, beneath root-owned non-writable directories. The OpenPGP preparers
refuse before publishing service files if this prerequisite is absent or has
unsafe custody. Relay rc_pre also fails closed if the helper is absent.
Existing OpenPGP installations receive only the additive fixed service rc_pre
hook; never rerun preparation over existing account homes or grant material.

The root-only helper accepts one of five fixed service names, not caller paths
or UIDs. It derives the existing bridge/GPG principal, exclusively locks a
fixed root-owned private lockfile, checks directory/socket custody, confirms
the exact service wrapper/child processes absent, and makes a zero-byte
250ms Unix connection probe. Only ECONNREFUSED can qualify abandonment.
It repeats process absence and exact inode/type/owner/mode/ctime checks before
unlinking that one socket. Live listeners, other errors, unexpected modes,
symlinks, files, FIFOs, foreign owners and changed identities refuse.
The fixed public modes include observed abandoned 0755 sockets; private parent
custody and current absence remain mandatory. Relay historical 0700 and current
0660 sockets are included. No key, policy, configuration or SSH control socket
is read or changed, no process is killed, and no protocol bytes are sent.

The crypto mapping covers only `/var/lib/osmap-gpg/run/crypto.sock` and its
fixed existing wrapper/helper processes. Its rc_pre hook also applies to a
manual start when that service is disabled at boot. This recovery does not
enable the service, start/unlock a mailbox key agent, or perform cryptography.
The existing disabled preparation and native operation-level key checks remain.

The helper's lock serializes its own bounded inspection/unlink critical section;
it is not authority for arbitrary competing manual root administration. A
caller replacing socket paths outside this contract must coordinate separately.
The normal daemons continue to bind exclusively and refuse replacements.

Focused local check:

    python3 -m unittest -v maint/test_service_socket_recovery.py

Real OpenBSD installed rc_pre/start qualification is separate from the local
portable Unix-socket controls. Restored daemon health is separate from actual
login/mailbox/Send/UAT, and signing/decryption can still require a mailbox agent
unlock. The workstation Git signing agent is unrelated to that mailbox agent.
