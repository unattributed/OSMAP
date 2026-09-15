#!/usr/bin/env python3
"""Read-only, fixed-target guard for the obsd1 controlled MFA rehearsal.

Run on the target through strict SSH and noninteractive doas. Never print
session contents or exception diagnostics. This does not revoke sessions or
prevent another administrator from starting the service: serialize maintenance.
"""
import errno
import fcntl
import os
from pathlib import Path
import platform
import pwd
import re
import socket
import stat
import subprocess
import time

ACCOUNT = "osmap-helper-validation@blackbagsecurity.com"
HOSTNAME = "obsd1.blackbagsecurity.com"
SESSION_DIR = Path("/var/lib/osmap/sessions")
CONFIG = Path("/etc/osmap/osmap-serve.env")
FIELDS = {"session_id", "csrf_token", "canonical_username", "issued_at", "expires_at",
          "last_seen_at", "revoked_at", "remote_addr", "user_agent", "factor"}


class Refused(ValueError):
    pass


def require(condition):
    if not condition:
        raise Refused("rehearsal precondition not established")


def safe_ancestry(path, runtime_uid):
    for directory in (path, *path.parents):
        metadata = directory.lstat()
        require(stat.S_ISDIR(metadata.st_mode) and metadata.st_uid in (0, runtime_uid)
                and not metadata.st_mode & 0o022)


def read_regular(path, uid, private=True):
    fd = os.open(path, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK)
    with os.fdopen(fd, "rb") as source:
        metadata = os.fstat(source.fileno())
        require(stat.S_ISREG(metadata.st_mode) and metadata.st_uid == uid
                and metadata.st_nlink == 1 and metadata.st_size <= 16384
                and not metadata.st_mode & (0o077 if private else 0o022))
        data = source.read(16385)
    require(0 < len(data) <= 16384)
    return data.decode("utf-8")


def service_stopped():
    for command in (["/usr/sbin/rcctl", "check", "osmap_serve"],
                    ["/usr/bin/pgrep", "-f", r"(^|/)osmap serve([[:space:]]|$)"]):
        result = subprocess.run(command, stdout=subprocess.DEVNULL,
                                stderr=subprocess.DEVNULL, timeout=10, check=False)
        require(result.returncode == 1)
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as probe:
        probe.settimeout(2)
        require(probe.connect_ex(("127.0.0.1", 8080)) == errno.ECONNREFUSED)


def check_config(text):
    expected = {"OSMAP_SESSION_DIR": str(SESSION_DIR), "OSMAP_LISTEN_ADDR": "127.0.0.1:8080",
                "OSMAP_SESSION_LIFETIME_SECS": "43200", "OSMAP_SESSION_IDLE_TIMEOUT_SECS": "1800"}
    found = {}
    seen = set()
    for line in text.splitlines():
        if not line.strip() or line.lstrip().startswith("#"):
            continue
        # The launcher sources this file as shell. Refuse export statements,
        # substitutions, appended assignments and other executable syntax;
        # do not mistake an earlier literal for the effective runtime value.
        require(re.fullmatch(r"[A-Z][A-Z0-9_]*=[A-Za-z0-9_/:.,@+\-]*", line) is not None)
        key, separator, value = line.partition("=")
        require(key not in seen)
        seen.add(key)
        if key in expected:
            require(separator and key not in found)
            found[key] = value
    require(found == expected)


def parse_record(text, filename):
    record = {}
    for line in text.split("\n"):
        if not line:
            continue
        require(not any(ord(char) < 32 or ord(char) == 127 for char in line))
        key, separator, value = line.partition("=")
        require(separator and key in FIELDS and key not in record)
        record[key] = value
    require(set(record) == FIELDS)
    for key in ("session_id", "csrf_token"):
        require(re.fullmatch(r"[0-9a-fA-F]{64}", record[key]) is not None)
    require(filename == record["session_id"] + ".session")
    require(record["canonical_username"] and record["factor"] == "totp")
    for key in ("issued_at", "expires_at", "last_seen_at", "revoked_at"):
        if key == "revoked_at" and record[key] == "":
            record[key] = None
            continue
        require(re.fullmatch(r"[0-9]{1,20}", record[key]) is not None)
        record[key] = int(record[key])
        require(record[key] <= 2**64 - 1)
    require(record["issued_at"] <= record["last_seen_at"]
            and record["issued_at"] < record["expires_at"])
    return record


def check_records(directory, uid, now):
    total = revoked = expired = 0
    entries = []
    with os.scandir(directory) as iterator:
        for entry in iterator:
            require(len(entries) < 10000)
            entries.append(entry.name)
    for name in entries:
        if name == ".session-store.lock":
            continue
        require(re.fullmatch(r"[0-9a-fA-F]{64}\.session", name) is not None)
        record = parse_record(read_regular(directory / name, uid), name)
        if record["canonical_username"] != ACCOUNT:
            continue
        total += 1
        if record["revoked_at"] is not None:
            require(record["revoked_at"] <= now)
            revoked += 1
        else:
            require(record["expires_at"] <= now or record["last_seen_at"] + 1800 <= now)
            expired += 1
    return total, revoked, expired


def check_host():
    require(platform.system() == "OpenBSD" and socket.gethostname() == HOSTNAME
            and os.geteuid() == 0)
    uid = pwd.getpwnam("_osmap").pw_uid
    safe_ancestry(CONFIG.parent, uid)
    check_config(read_regular(CONFIG, 0, private=False))
    safe_ancestry(SESSION_DIR, uid)
    service_stopped()
    # Open only the existing runtime lock; never create or replace it.
    fd = os.open(SESSION_DIR / ".session-store.lock", os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK)
    with os.fdopen(fd, "rb") as lock:
        metadata = os.fstat(lock.fileno())
        require(stat.S_ISREG(metadata.st_mode) and metadata.st_uid == uid
                and metadata.st_nlink == 1 and not metadata.st_mode & 0o077)
        fcntl.flock(lock.fileno(), fcntl.LOCK_EX | fcntl.LOCK_NB)
        counts = check_records(SESSION_DIR, uid, int(time.time()))
        service_stopped()
    return counts


def main():
    try:
        total, revoked, expired = check_host()
    except (OSError, ValueError, KeyError, subprocess.SubprocessError):
        print("REHEARSAL_CONTAINMENT=REFUSED")
        return 1
    print("REHEARSAL_CONTAINMENT=PASS")
    print("browser_service_stopped=true")
    print(f"validation_session_records={total}")
    print(f"already_revoked_records={revoked}")
    print(f"expired_unrevoked_records={expired}")
    print("usable_validation_sessions=0")
    print("session_revocation_performed=false")
    print("scope=osmap_browser_only")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
