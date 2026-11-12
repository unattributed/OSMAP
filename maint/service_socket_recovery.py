#!/usr/local/bin/python3
"""Root rc_pre recovery of five fixed, abandoned OSMAP Unix listeners.

Never reads keys/configuration or sends protocol bytes. The unprivileged
daemons retain their existing refusal to replace any existing listener.
"""
import errno
import fcntl
import os
import pathlib
import pwd
import re
import socket
import stat
import subprocess
import sys

SERVICES = {
    "osmap_auth_relay": ("_osmapbridge", "/var/lib/osmap-bridge/run/auth.sock",
                         ("/usr/local/bin/python3 /usr/local/libexec/osmap/mail-backend/relay.py --purpose auth --listen ",), (0o600, 0o660, 0o700)),
    "osmap_mailbox_relay": ("_osmapbridge", "/var/lib/osmap-bridge/run/mailbox.sock",
                            ("/usr/local/bin/python3 /usr/local/libexec/osmap/mail-backend/relay.py --purpose mailbox --listen ",), (0o600, 0o660, 0o700)),
    "osmap_public_inventory": ("_osmapgpg", "/var/lib/osmap-gpg/run/inventory.sock",
                               ("/bin/ksh /var/lib/osmap-gpg/bin/osmap_public_inventory-run.ksh",
                                "/var/lib/osmap-gpg/bin/osmap_public_inventory_helper "), (0o600, 0o660, 0o755)),
    "osmap_public_admin": ("_osmapgpg", "/var/lib/osmap-gpg/run/admin.sock",
                           ("/bin/ksh /var/lib/osmap-gpg/bin/osmap_public_admin-run.ksh",
                            "/var/lib/osmap-gpg/bin/osmap_public_admin_helper "), (0o600, 0o660, 0o755)),
    "osmap_crypto": ("_osmapgpg", "/var/lib/osmap-gpg/run/crypto.sock",
                      ("/bin/ksh /var/lib/osmap-gpg/bin/osmap_crypto-run.ksh",
                       "/var/lib/osmap-gpg/bin/osmap_crypto_helper "), (0o600, 0o660, 0o755)),
}
LOCK = "/var/run/osmap-service-socket-recovery.lock"


class Refused(Exception):
    pass


def identity(metadata):
    return (metadata.st_dev, metadata.st_ino, metadata.st_uid, metadata.st_gid,
            metadata.st_mode, metadata.st_ctime_ns)


def absent_process(uid, prefixes):
    pattern = "^(" + "|".join(re.escape(prefix) + ".*" for prefix in prefixes) + ")$"
    result = subprocess.run(["/usr/bin/pgrep", "-u", str(uid), "-f", pattern],
                            stdin=subprocess.DEVNULL, stdout=subprocess.DEVNULL,
                            stderr=subprocess.DEVNULL, timeout=2)
    if result.returncode != 1:
        raise Refused("service process present or status unavailable")


def refused_connection(path):
    with socket.socket(socket.AF_UNIX, socket.SOCK_STREAM) as probe:
        probe.settimeout(0.25)
        try:
            probe.connect(str(path))
        except OSError as error:
            if error.errno == errno.ECONNREFUSED:
                return
            raise Refused("listener status unavailable") from None
    raise Refused("listener is live")


def recover(path, uid, prefixes, process_check=absent_process, probe=refused_connection,
            modes=(0o600, 0o660, 0o700)):
    path = pathlib.Path(path)
    parents = {}
    for parent in path.parents:
        metadata = parent.lstat()
        sticky_root = metadata.st_uid == 0 and metadata.st_mode & stat.S_ISVTX
        if not stat.S_ISDIR(metadata.st_mode) or metadata.st_uid not in (0, uid) or (metadata.st_mode & 0o022 and not sticky_root):
            raise Refused("listener parent custody refused")
        parents[parent] = identity(metadata)[:-1]
    if path.parent.lstat().st_uid != uid:
        raise Refused("listener parent owner refused")
    try:
        before = path.lstat()
    except FileNotFoundError:
        return "absent"
    if not stat.S_ISSOCK(before.st_mode) or before.st_uid != uid or stat.S_IMODE(before.st_mode) not in modes:
        raise Refused("listener custody refused")
    process_check(uid, prefixes)
    probe(path)
    process_check(uid, prefixes)
    if any(identity(parent.lstat())[:-1] != expected for parent, expected in parents.items()):
        raise Refused("listener parent changed during inspection")
    after = path.lstat()
    if identity(before) != identity(after):
        raise Refused("listener changed during inspection")
    path.unlink()
    return "recovered"


def main():
    if os.geteuid() != 0 or len(sys.argv) != 2 or sys.argv[1] not in SERVICES:
        raise Refused("root fixed service selection required")
    if not sys.platform.startswith("openbsd"):
        raise Refused("OpenBSD rc recovery only")
    service = sys.argv[1]
    owner, path, prefixes, modes = SERVICES[service]
    uid = pwd.getpwnam(owner).pw_uid
    for parent in pathlib.Path(LOCK).parents:
        metadata = parent.lstat()
        if not stat.S_ISDIR(metadata.st_mode) or metadata.st_uid != 0 or metadata.st_mode & 0o022:
            raise Refused("recovery lock parent custody refused")
    lock = os.open(LOCK, os.O_RDWR | os.O_CREAT | os.O_NOFOLLOW | os.O_NONBLOCK, 0o600)
    try:
        metadata = os.fstat(lock)
        if not stat.S_ISREG(metadata.st_mode) or metadata.st_uid != 0 or metadata.st_nlink != 1 or metadata.st_mode & 0o077:
            raise Refused("recovery lock custody refused")
        fcntl.flock(lock, fcntl.LOCK_EX | fcntl.LOCK_NB)
        recover(path, uid, prefixes, modes=modes)
    finally:
        os.close(lock)


if __name__ == "__main__":
    try:
        main()
    except (OSError, KeyError, Refused, subprocess.SubprocessError):
        print("OSMAP service socket recovery refused.", file=sys.stderr)
        sys.exit(1)
