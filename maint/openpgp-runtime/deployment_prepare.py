#!/usr/bin/env python3
"""Prepare isolated development OpenPGP services on obsd1, without web restart.

Inputs are a reviewed native source/build and two public certificates. This
script never exports/imports secret keys, copies the running web binary, edits
its environment, or enables services. Existing provisioned state is preserved.
"""
import argparse
import grp
import hashlib
import json
import os
import pathlib
import pwd
import resource
import re
import shutil
import socket
import subprocess
import tempfile

HOST = "obsd1.blackbagsecurity.com"
ROOT = pathlib.Path("/var/lib/osmap-gpg")
HELPER = "_osmapgpg"
WEB = "_osmap"
GROUP = "osmapgpg"
DUNCAN = "E401B0FDCA3A712DE8E15BB23DAB198EA2E96BBE"
SIGNER = "83A5689C7C52CE43DB88C8A5322909FC05BF68BB"
PROTON = "C384498B2CC97D8D9EB7B20162C21B767540D006"


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--prepare", action="store_true")
    for name in ("source", "binaries", "duncan-public", "proton-public"):
        parser.add_argument("--" + name, type=pathlib.Path)
    for name in ("account", "test-account", "correspondent"):
        parser.add_argument("--" + name)
    args = parser.parse_args()
    assert os.geteuid() == 0 and socket.gethostname() == HOST, "obsd1 root-only deployment preparation"
    resource.setrlimit(resource.RLIMIT_CORE, (0, 0))
    os.umask(0o077)
    if not args.prepare:
        print(json.dumps({"target": HOST, "prepared": ROOT.exists(), "services": ["osmap_crypto", "osmap_public_inventory"], "activation": "separate operator step; running web unchanged"}))
        return
    assert all(getattr(args, n) for n in ("source", "binaries", "duncan_public", "proton_public"))
    addresses = [args.account, args.test_account, args.correspondent]
    assert all(address and len(address) <= 254 and re.fullmatch(r"[a-z0-9.!#$%&'*+/=?^_`{|}~-]+@[a-z0-9](?:[a-z0-9.-]*[a-z0-9])?", address) for address in addresses), "supply canonical operator-approved account and correspondent addresses"
    assert len(set(addresses)) == 3, "account and correspondent mappings must be distinct"
    accounts = addresses[:2]
    assert not ROOT.exists(), "existing development custody directory preserved; use status/SOP instead of overwrite"
    for path in (args.source, args.binaries, args.duncan_public, args.proton_public):
        assert path.is_absolute() and path.resolve() == path and path.exists()
    web = pwd.getpwnam(WEB)
    for name in (HELPER,):
        try:
            pwd.getpwnam(name)
            raise AssertionError("helper already exists; inspect existing deployment")
        except KeyError:
            pass
    try:
        grp.getgrnam(GROUP)
        raise AssertionError("socket group already exists; inspect existing deployment")
    except KeyError:
        pass
    for service in ("osmap_crypto", "osmap_public_inventory"):
        assert not pathlib.Path("/etc/rc.d", service).exists()
    pending = pathlib.Path("/var/lib/osmap/settings/openpgp-pending")
    assert not pending.exists() and not pending.is_symlink(), "existing pending bindings preserved"
    secrets = pathlib.Path("/var/lib/osmap/secrets")
    assert secrets.is_dir() and secrets.stat().st_uid == web.pw_uid
    for service in ("crypto", "inventory"):
        assert not (secrets / ("openpgp-" + service + ".key")).exists()

    def run(command, data=None, user=None, timeout=30, settings=None, cwd=None):
        def demote():
            identity = pwd.getpwnam(user)
            os.initgroups(user, identity.pw_gid)
            os.setgid(identity.pw_gid)
            os.setuid(identity.pw_uid)
        result = subprocess.run(list(map(str, command)), input=data, stdout=subprocess.PIPE, stderr=subprocess.PIPE,
                                timeout=timeout, env={"PATH": "/usr/local/bin:/usr/bin:/bin:/usr/sbin:/sbin", "LC_ALL": "C"} | (settings or {}),
                                preexec_fn=demote if user else None, cwd=cwd)
        assert result.returncode == 0, "preparation command refused: " + pathlib.Path(str(command[0])).name
        assert len(result.stdout) <= 65536
        return result.stdout

    def owned(path, uid, gid, mode):
        os.chown(path, uid, gid)
        path.chmod(mode)

    def write(path, content, uid, gid, mode=0o600):
        with path.open("xb") as f:
            f.write(content.encode() if isinstance(content, str) else content)
            f.flush()
            os.fsync(f.fileno())
        owned(path, uid, gid, mode)

    with tempfile.TemporaryDirectory(prefix="osmap-gpg-prepare-") as scratch:
        scratch = pathlib.Path(scratch)
        public_probe = scratch / "public-probe"
        public_probe.mkdir(mode=0o700)
        for path, expected in [(args.duncan_public, DUNCAN), (args.proton_public, PROTON)]:
            result = run(["/usr/local/bin/gpg", "--no-options", "--homedir", public_probe, "--batch", "--no-autostart", "--with-colons", "--show-keys", path])
            next_primary = False
            primary = []
            for line in result.decode().splitlines():
                fields = line.split(":")
                if fields[0] == "pub":
                    next_primary = True
                elif fields[0] == "fpr" and next_primary:
                    primary.append(fields[9])
                    next_primary = False
            assert primary == [expected], "public certificate primary mismatch"
        built = {}
        for label, source, libraries in [("crypto-worker", "crypto.c", ["-L/usr/local/lib", "-lgpgme", "-lgpg-error"]), ("crypto-engine", "crypto_engine.c", []), ("inventory-worker", "inventory.c", ["-L/usr/local/lib", "-lgpgme", "-lgpg-error"])]:
            destination = scratch / label
            run(["/usr/bin/cc", "-std=c99", "-Wall", "-Wextra", "-Werror", "-I/usr/local/include", args.source / "maint/openpgp-runtime" / source] + libraries + ["-o", destination])
            built[label] = destination
        for name in ("osmap_crypto_helper", "osmap_public_inventory_helper"):
            path = args.binaries / name
            assert path.is_file() and path.stat().st_mode & 0o111
            built[name] = path
        previous_groups = os.getgrouplist(WEB, web.pw_gid)
        run(["/usr/sbin/groupadd", GROUP])
        gid = grp.getgrnam(GROUP).gr_gid
        run(["/usr/sbin/useradd", "-g", GROUP, "-d", ROOT, "-s", "/sbin/nologin", HELPER])
        helper = pwd.getpwnam(HELPER)
        memberships = sorted(set(grp.getgrgid(g).gr_name for g in previous_groups if g != web.pw_gid) | {GROUP})
        run(["/usr/sbin/usermod", "-G", ",".join(memberships), WEB])
        ROOT.mkdir(mode=0o755)
        ROOT.chmod(0o755)
        for directory, mode in [("bin", 0o700), ("config", 0o700), ("accounts", 0o700), ("run", 0o750)]:
            p = ROOT / directory
            p.mkdir()
            owned(p, helper.pw_uid, gid, mode)
        hashes = {}
        for name, path in built.items():
            destination = ROOT / "bin" / name
            shutil.copyfile(path, destination)
            owned(destination, helper.pw_uid, gid, 0o700)
            hashes[name] = hashlib.sha256(destination.read_bytes()).hexdigest()
        homes = []
        for label in ("duncan", "osmap-test"):
            home = ROOT / "accounts" / label
            home.mkdir()
            owned(home, helper.pw_uid, gid, 0o700)
            homes.append(home)
            for public in (args.duncan_public, args.proton_public):
                # Only public bytes cross stdin. No private material or agent
                # startup is needed to build this bounded public inventory.
                run(["/usr/local/bin/gpg", "--no-options", "--homedir", home, "--batch", "--no-autostart", "--pinentry-mode", "error", "--import"], data=public.read_bytes(), user=HELPER)
            for name in ("pubring.kbx", "trustdb.gpg"):
                assert (home / name).is_file() and (home / name).stat().st_mode & 0o077 == 0
            assert not (home / "private-keys-v1.d").exists() or not list((home / "private-keys-v1.d").iterdir())
            actual = json.loads(run([ROOT / "bin/inventory-worker", home], user=HELPER, settings={"GNUPGHOME": str(home)}, cwd=home))
            assert actual["ok"] and {key["primary"]["fingerprint"] for key in actual["keys"]} == {DUNCAN, PROTON}
        config_root = ROOT / "config"
        settings = {}
        for label in ("crypto", "inventory"):
            key = os.urandom(32)
            write(config_root / (label + ".key"), key, helper.pw_uid, gid)
            web_key = secrets / ("openpgp-" + label + ".key")
            write(web_key, key, web.pw_uid, web.pw_gid)
            settings.update({"OSMAP_OPENPGP_" + label.upper() + "_SOCKET": str(ROOT / "run" / (label + ".sock")), "OSMAP_OPENPGP_" + label.upper() + "_KEY_FILE": str(web_key), "OSMAP_OPENPGP_" + label.upper() + "_HELPER_UID": str(helper.pw_uid)})
        common = {"version": 1, "trusted_web_uid": web.pw_uid}
        crypto = common | {"worker": str(ROOT / "bin/crypto-worker"), "engine": str(ROOT / "bin/crypto-engine"), "socket": str(ROOT / "run/crypto.sock"), "accounts": [
            {"account": accounts[0], "home": str(homes[0]), "signer_fingerprint": SIGNER, "decrypt_fingerprints": [DUNCAN], "recipient_fingerprints": [DUNCAN, PROTON]},
            {"account": accounts[1], "home": str(homes[1]), "signer_fingerprint": None, "decrypt_fingerprints": [], "recipient_fingerprints": [DUNCAN, PROTON]}]}
        inventory = common | {"worker": str(ROOT / "bin/inventory-worker"), "engine": "/usr/local/bin/gpg", "socket": str(ROOT / "run/inventory.sock"), "accounts": [{"account": account, "home": str(home)} for account, home in zip(accounts, homes)]}
        for label, value in [("crypto", crypto), ("inventory", inventory)]:
            write(config_root / (label + ".json"), json.dumps(value, indent=2) + "\n", helper.pw_uid, gid)
        pending.mkdir()
        owned(pending, web.pw_uid, web.pw_gid, 0o700)
        for label, own in [("duncan", {"primary_fingerprint": DUNCAN, "signing_fingerprint": SIGNER, "decrypt_primary_fingerprints": [DUNCAN]}), ("osmap-test", None)]:
            recipients = [{"address": args.correspondent, "primary_fingerprint": PROTON, "encryption": "optional"}]
            if label == "osmap-test":
                recipients.append({"address": accounts[0], "primary_fingerprint": DUNCAN, "encryption": "optional"})
            write(pending / (label + ".json"), json.dumps({"account_binding": own, "recipient_bindings": recipients, "policy": {"signing": "optional", "encryption": "optional"}}, indent=2) + "\n", web.pw_uid, web.pw_gid)
        write(config_root / "web-environment.pending", "".join(k + "=" + v + "\n" for k, v in settings.items()), helper.pw_uid, gid)
        for label, service, binary in [("crypto", "osmap_crypto", "osmap_crypto_helper"), ("inventory", "osmap_public_inventory", "osmap_public_inventory_helper")]:
            wrapper = ROOT / "bin" / (service + "-run.ksh")
            content = '#!/bin/ksh\nset -eu\nulimit -c 0\nsocket="' + str(ROOT / "run" / (label + ".sock")) + '"\n[ ! -e "$socket" ] || exit 1\n"' + str(ROOT / "bin" / binary) + '" "' + str(config_root / (label + ".json")) + '" "' + str(config_root / (label + ".key")) + '" &\nchild=$!\ncleanup() { kill "$child" 2>/dev/null || true; wait "$child" 2>/dev/null || true; [ ! -S "$socket" ] || rm -f "$socket"; }\ntrap cleanup EXIT HUP INT TERM\nwait "$child"\n'
            write(wrapper, content, helper.pw_uid, gid, 0o700)
            rc = '#!/bin/ksh\ndaemon="' + str(wrapper) + '"\ndaemon_user="' + HELPER + '"\nrc_bg=YES\nrc_reload=NO\n. /etc/rc.d/rc.subr\nrc_cmd "$1"\n'
            write(pathlib.Path("/etc/rc.d", service), rc, 0, 0, 0o555)
            run(["/usr/sbin/rcctl", "disable", service])
        receipt = {"version": 1, "target": HOST, "helper_uid": helper.pw_uid, "web_uid": web.pw_uid, "socket_group": GROUP, "previous_web_group_ids": previous_groups, "binary_sha256": hashes, "public_fingerprints": [DUNCAN, PROTON], "services_enabled": False, "live_web_binary_and_environment_modified": False, "private_keys_provisioned": False}
        write(ROOT / "preparation.json", json.dumps(receipt, indent=2) + "\n", 0, 0)
        print(json.dumps(receipt, sort_keys=True))


if __name__ == "__main__":
    main()
