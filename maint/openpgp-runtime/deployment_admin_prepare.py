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
    assert os.geteuid() == 0 and socket.gethostname() == HOST, "obsd1 root-only preparation"
    resource.setrlimit(resource.RLIMIT_CORE, (0, 0))
    os.umask(0o077)
    receipt = ROOT / "admin-preparation.json"
    if not args.prepare:
        print(json.dumps({"target": HOST, "prepared": receipt.is_file(), "service": SERVICE}))
        return
    sources = {
        "osmap_public_admin_helper": args.binary,
        "admin-inventory-worker": args.inventory_worker,
        "admin-crypto-engine": args.crypto_engine,
    }
    for source in sources.values():
        assert source is not None and source.is_absolute() and source.resolve() == source
        info = source.stat(follow_symlinks=False)
        assert stat.S_ISREG(info.st_mode) and 0 < info.st_size <= 64 * 1024 * 1024
        assert info.st_mode & 0o111 and not info.st_mode & 0o022
    assert ROOT.is_dir() and not receipt.exists()
    base = json.loads((ROOT / "preparation.json").read_text())
    assert base["target"] == HOST and base["version"] == 1
    helper = pwd.getpwnam(HELPER)
    web = pwd.getpwnam(WEB)
    group = grp.getgrnam("osmapgpg")
    assert base["helper_uid"] == helper.pw_uid and base["web_uid"] == web.pw_uid
    assert (ROOT / "config").stat().st_uid == helper.pw_uid
    inventory = json.loads((ROOT / "config/inventory.json").read_text())
    assert inventory["version"] == 1 and inventory["trusted_web_uid"] == web.pw_uid
    assert inventory["accounts"] and len(inventory["accounts"]) <= 128
    assert all(set(item) == {"account", "home"} for item in inventory["accounts"])
    for item in inventory["accounts"]:
        home = pathlib.Path(item["home"])
        assert home.is_dir() and home.stat().st_uid == helper.pw_uid
        assert home.is_relative_to(ROOT / "accounts") and home.resolve() == home
    expected_hashes = {
        "admin-inventory-worker": args.inventory_worker_sha256,
        "admin-crypto-engine": args.crypto_engine_sha256,
    }
    for option in expected_hashes.values():
        assert option and len(option) == 64 and all(c in "0123456789abcdef" for c in option)
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
        assert not path.exists() and not path.is_symlink(), "existing admin state preserved"
    assert pending.is_file() and pending.stat().st_uid == helper.pw_uid
    assert web_key.parent.is_dir() and web_key.parent.stat().st_uid == web.pw_uid
    environment = pending.read_text()
    assert "OSMAP_OPENPGP_PUBLIC_ADMIN_" not in environment
    assert all(name in environment for name in ("OSMAP_OPENPGP_CRYPTO_SOCKET", "OSMAP_OPENPGP_INVENTORY_SOCKET"))
    digests = {}
    for name, source in sources.items():
        source_info = source.stat(follow_symlinks=False)
        source_fd = os.open(source, os.O_RDONLY | getattr(os, "O_NOFOLLOW", 0))
        assert os.fstat(source_fd).st_ino == source_info.st_ino and os.fstat(source_fd).st_dev == source_info.st_dev
        with os.fdopen(source_fd, "rb") as stream:
            candidate = stream.read(64 * 1024 * 1024 + 1)
        assert len(candidate) == source_info.st_size
        digest = hashlib.sha256(candidate).hexdigest()
        if name in expected_hashes:
            assert digest == expected_hashes[name], "worker differs from qualified native build"
        exclusive(ROOT / "bin" / name, candidate, helper.pw_uid, group.gr_gid, 0o700)
        digests[name] = digest
    state.mkdir(mode=0o700)
    state_fd = os.open(state, os.O_RDONLY | getattr(os, "O_DIRECTORY", 0) | getattr(os, "O_NOFOLLOW", 0))
    try:
        state_info = os.fstat(state_fd)
        assert stat.S_ISDIR(state_info.st_mode) and state_info.st_uid == 0
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
        "#!/bin/ksh\nset -eu\nulimit -c 0\n"
        f'socket="{ROOT}/run/admin.sock"\n[ ! -e "$socket" ] || exit 1\n'
        f'"{binary}" "{config}" "{helper_key}" &\n'
        'child=$!\ncleanup() { kill "$child" 2>/dev/null || true; wait "$child" 2>/dev/null || true; [ ! -S "$socket" ] || rm -f "$socket"; }\n'
        'trap cleanup EXIT HUP INT TERM\nwait "$child"\n'
    )
    exclusive(wrapper, wrapper_text.encode(), helper.pw_uid, group.gr_gid, 0o700)
    rc_text = f'#!/bin/ksh\ndaemon="{wrapper}"\ndaemon_user="{HELPER}"\nrc_bg=YES\nrc_reload=NO\n. /etc/rc.d/rc.subr\nrc_cmd "$1"\n'
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
