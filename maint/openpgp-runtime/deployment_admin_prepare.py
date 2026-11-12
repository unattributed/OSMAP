#!/usr/bin/env python3
"""Add the reviewed public-key administration helper to an existing obsd1 setup.

This is preparation only: it leaves all services disabled/stopped and does not
change the running web executable or environment. It never reads key material
from an operator terminal or prints grant bytes.
"""
import argparse
import grp
import hashlib
import json
import os
import pathlib
import pwd
import resource
import socket
import stat
import subprocess

HOST = "obsd1.blackbagsecurity.com"
ROOT = pathlib.Path("/var/lib/osmap-gpg")
SERVICE = "osmap_public_admin"
HELPER = "_osmapgpg"
WEB = "_osmap"


class PreparationGuardError(AssertionError):
    """Operational refusals remain active under interpreter optimization."""


def require(condition, code="ADMIN_PREPARATION_GUARD_REFUSED"):
    if not condition:
        raise PreparationGuardError(code)


def exclusive(path, content, uid, gid, mode=0o600):
    flags = os.O_WRONLY | os.O_CREAT | os.O_EXCL | getattr(os, "O_NOFOLLOW", 0)
    descriptor = os.open(path, flags, mode)
    with os.fdopen(descriptor, "wb") as output:
        output.write(content)
        os.fchown(output.fileno(), uid, gid)
        os.fchmod(output.fileno(), mode)
        output.flush()
        os.fsync(output.fileno())


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--prepare", action="store_true")
    parser.add_argument("--binary", type=pathlib.Path)
    parser.add_argument("--inventory-worker", type=pathlib.Path)
    parser.add_argument("--crypto-engine", type=pathlib.Path)
    parser.add_argument("--inventory-worker-sha256")
    parser.add_argument("--crypto-engine-sha256")
    args = parser.parse_args()
    require(os.geteuid() == 0 and socket.gethostname() == HOST, "ADMIN_PREPARE_AUTHORITY_REFUSED")
    resource.setrlimit(resource.RLIMIT_CORE, (0, 0))
    os.umask(0o077)
    receipt = ROOT / "admin-preparation.json"
    if not args.prepare:
        print(json.dumps({"target": HOST, "prepared": receipt.is_file(), "service": SERVICE}))
        return
    recovery = pathlib.Path("/usr/local/libexec/osmap/service_socket_recovery.py")
    require(recovery.resolve() == recovery, "ADMIN_PREPARE_RECOVERY_CUSTODY_REFUSED")
    for path in (recovery, *recovery.parents):
        metadata = path.lstat()
        require(metadata.st_uid == 0 and not metadata.st_mode & 0o022, "ADMIN_PREPARE_RECOVERY_CUSTODY_REFUSED")
        require(stat.S_ISREG(metadata.st_mode) if path == recovery else stat.S_ISDIR(metadata.st_mode), "ADMIN_PREPARE_RECOVERY_CUSTODY_REFUSED")
    require(recovery.stat().st_nlink == 1, "ADMIN_PREPARE_RECOVERY_CUSTODY_REFUSED")
    sources = {
        "osmap_public_admin_helper": args.binary,
        "admin-inventory-worker": args.inventory_worker,
        "admin-crypto-engine": args.crypto_engine,
    }
    for source in sources.values():
        require(source is not None and source.is_absolute() and source.resolve() == source, "ADMIN_PREPARE_SOURCE_CUSTODY_REFUSED")
        info = source.stat(follow_symlinks=False)
        require(stat.S_ISREG(info.st_mode) and 0 < info.st_size <= 64 * 1024 * 1024, "ADMIN_PREPARE_SOURCE_CUSTODY_REFUSED")
        require(info.st_mode & 0o111 and not info.st_mode & 0o022, "ADMIN_PREPARE_SOURCE_CUSTODY_REFUSED")
    require(ROOT.is_dir() and not receipt.exists(), "ADMIN_PREPARE_EXISTING_STATE_REFUSED")
    base = json.loads((ROOT / "preparation.json").read_text())
    require(base["target"] == HOST and base["version"] == 1, "ADMIN_PREPARE_BASE_REFUSED")
    helper = pwd.getpwnam(HELPER)
    web = pwd.getpwnam(WEB)
    group = grp.getgrnam("osmapgpg")
    require(base["helper_uid"] == helper.pw_uid and base["web_uid"] == web.pw_uid, "ADMIN_PREPARE_OWNER_REFUSED")
    require((ROOT / "config").stat().st_uid == helper.pw_uid, "ADMIN_PREPARE_OWNER_REFUSED")
    inventory = json.loads((ROOT / "config/inventory.json").read_text())
    require(inventory["version"] == 1 and inventory["trusted_web_uid"] == web.pw_uid, "ADMIN_PREPARE_INVENTORY_REFUSED")
    require(inventory["accounts"] and len(inventory["accounts"]) <= 128, "ADMIN_PREPARE_INVENTORY_REFUSED")
    require(all(set(item) == {"account", "home"} for item in inventory["accounts"]), "ADMIN_PREPARE_INVENTORY_REFUSED")
    for item in inventory["accounts"]:
        home = pathlib.Path(item["home"])
        require(home.is_dir() and home.stat().st_uid == helper.pw_uid, "ADMIN_PREPARE_HOME_REFUSED")
        require(home.is_relative_to(ROOT / "accounts") and home.resolve() == home, "ADMIN_PREPARE_HOME_REFUSED")
    expected_hashes = {
        "admin-inventory-worker": args.inventory_worker_sha256,
        "admin-crypto-engine": args.crypto_engine_sha256,
    }
    for option in expected_hashes.values():
        require(option and len(option) == 64 and all(c in "0123456789abcdef" for c in option), "ADMIN_PREPARE_PIN_REFUSED")
    binary = ROOT / "bin/osmap_public_admin_helper"
    worker = ROOT / "bin/admin-inventory-worker"
    engine = ROOT / "bin/admin-crypto-engine"
    state = ROOT / "admin-state"
    config = ROOT / "config/admin.json"
    helper_key = ROOT / "config/admin.key"
    web_key = pathlib.Path("/var/lib/osmap/secrets/openpgp-public-admin.key")
    wrapper = ROOT / "bin/osmap_public_admin-run.ksh"
    rc = pathlib.Path("/etc/rc.d/osmap_public_admin")
    pending = ROOT / "config/web-environment.pending"
    for path in (binary, worker, engine, state, config, helper_key, web_key, wrapper, rc):
        require(not path.exists() and not path.is_symlink(), "ADMIN_PREPARE_EXISTING_STATE_REFUSED")
    require(pending.is_file() and pending.stat().st_uid == helper.pw_uid, "ADMIN_PREPARE_PENDING_REFUSED")
    require(web_key.parent.is_dir() and web_key.parent.stat().st_uid == web.pw_uid, "ADMIN_PREPARE_SECRET_DIRECTORY_REFUSED")
    environment = pending.read_text()
    require("OSMAP_OPENPGP_PUBLIC_ADMIN_" not in environment, "ADMIN_PREPARE_EXISTING_CONFIGURATION_REFUSED")
    require(all(name in environment for name in ("OSMAP_OPENPGP_CRYPTO_SOCKET", "OSMAP_OPENPGP_INVENTORY_SOCKET")), "ADMIN_PREPARE_PENDING_REFUSED")
    digests = {}
    for name, source in sources.items():
        source_info = source.stat(follow_symlinks=False)
        source_fd = os.open(source, os.O_RDONLY | getattr(os, "O_NOFOLLOW", 0))
        require(os.fstat(source_fd).st_ino == source_info.st_ino and os.fstat(source_fd).st_dev == source_info.st_dev, "ADMIN_PREPARE_SOURCE_CHANGED")
        with os.fdopen(source_fd, "rb") as stream:
            candidate = stream.read(64 * 1024 * 1024 + 1)
        require(len(candidate) == source_info.st_size, "ADMIN_PREPARE_SOURCE_CHANGED")
        digest = hashlib.sha256(candidate).hexdigest()
        if name in expected_hashes:
            require(digest == expected_hashes[name], "ADMIN_PREPARE_PIN_MISMATCH")
        exclusive(ROOT / "bin" / name, candidate, helper.pw_uid, group.gr_gid, 0o700)
        digests[name] = digest
    state.mkdir(mode=0o700)
    state_fd = os.open(state, os.O_RDONLY | getattr(os, "O_DIRECTORY", 0) | getattr(os, "O_NOFOLLOW", 0))
    try:
        state_info = os.fstat(state_fd)
        require(stat.S_ISDIR(state_info.st_mode) and state_info.st_uid == 0, "ADMIN_PREPARE_STATE_CUSTODY_REFUSED")
        os.fchown(state_fd, helper.pw_uid, group.gr_gid)
        os.fchmod(state_fd, 0o700)
        os.fsync(state_fd)
    finally:
        os.close(state_fd)
    grant = os.urandom(32)
    exclusive(helper_key, grant, helper.pw_uid, group.gr_gid)
    exclusive(web_key, grant, web.pw_uid, web.pw_gid)
    settings = {
        "version": 1,
        "worker": str(worker),
        "engine": str(engine),
        "state_directory": str(state),
        "socket": str(ROOT / "run/admin.sock"),
        "trusted_web_uid": web.pw_uid,
        "accounts": inventory["accounts"],
    }
    exclusive(config, (json.dumps(settings, indent=2) + "\n").encode(), helper.pw_uid, group.gr_gid)
    wrapper_text = (
        "#!/bin/ksh\nset -eu\numask 077\nulimit -c 0\n"
        f'socket="{ROOT}/run/admin.sock"\n[ ! -e "$socket" ] || exit 1\n'
        f'"{binary}" "{config}" "{helper_key}" &\n'
        'child=$!\ncleanup() { kill "$child" 2>/dev/null || true; wait "$child" 2>/dev/null || true; [ ! -S "$socket" ] || rm -f "$socket"; }\n'
        'trap cleanup EXIT HUP INT TERM\nwait "$child"\n'
    )
    exclusive(wrapper, wrapper_text.encode(), helper.pw_uid, group.gr_gid, 0o700)
    # rc.subr defaults pexp to the wrapper path alone.  The running script's
    # full process arguments include the ksh interpreter.
    rc_text = f'#!/bin/ksh\ndaemon="{wrapper}"\ndaemon_user="{HELPER}"\nrc_bg=YES\nrc_reload=NO\n. /etc/rc.d/rc.subr\npexp="/bin/ksh {wrapper}"\n'
    rc_text += 'rc_pre() {\n /usr/local/bin/python3 /usr/local/libexec/osmap/service_socket_recovery.py osmap_public_admin\n}\nrc_cmd "$1"\n'
    exclusive(rc, rc_text.encode(), 0, 0, 0o555)
    subprocess.run(["/usr/sbin/rcctl", "disable", SERVICE], check=True, timeout=10)
    addition = (
        f"OSMAP_OPENPGP_PUBLIC_ADMIN_SOCKET={ROOT}/run/admin.sock\n"
        f"OSMAP_OPENPGP_PUBLIC_ADMIN_KEY_FILE={web_key}\n"
        f"OSMAP_OPENPGP_PUBLIC_ADMIN_HELPER_UID={helper.pw_uid}\n"
    )
    replacement = pending.with_name("web-environment.admin-pending")
    exclusive(replacement, (environment + addition).encode(), helper.pw_uid, group.gr_gid)
    os.replace(replacement, pending)
    result = {"version": 1, "target": HOST, "service": SERVICE, "enabled": False,
              "binary_sha256": digests, "accounts": len(inventory["accounts"]),
              "live_web_binary_and_environment_modified": False, "private_keys_modified": False}
    exclusive(receipt, (json.dumps(result, indent=2) + "\n").encode(), 0, 0)
    print(json.dumps(result, sort_keys=True))


if __name__ == "__main__":
    main()
