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
import stat
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


class PreparationGuardError(AssertionError):
    """Operational refusals remain active under interpreter optimization."""


def require(condition, code="PREPARATION_GUARD_REFUSED"):
    if not condition:
        raise PreparationGuardError(code)


def crypto_service_scripts():
    """Let rc.subr own the foreground listener, without a shell supervisor.

    A stopped helper can leave its socket inode behind. The existing root
    rc_pre recovery is the only component allowed to remove that dead socket.
    """
    wrapper = ROOT / "bin/osmap_crypto-run.ksh"
    binary = ROOT / "bin/osmap_crypto_helper"
    config = ROOT / "config/crypto.json"
    key = ROOT / "config/crypto.key"
    content = (
        '#!/bin/ksh\nset -eu\nulimit -c 0\n'
        f'socket="{ROOT}/run/crypto.sock"\n'
        '[ ! -e "$socket" ] || exit 1\n'
        f'exec "{binary}" "{config}" "{key}"\n'
    )
    # These fixed paths contain only dots requiring escaping in the exact
    # extended regular expression used by rc.subr's pgrep/pkill -xf.
    process = f"{binary} {config} {key}".replace(".", r"\.")
    rc = (
        f'#!/bin/ksh\ndaemon="{wrapper}"\ndaemon_user="{HELPER}"\n'
        'rc_bg=YES\nrc_reload=NO\n. /etc/rc.d/rc.subr\n'
        f'pexp="{process}"\n'
        'rc_pre() {\n'
        ' /usr/local/bin/python3 /usr/local/libexec/osmap/service_socket_recovery.py osmap_crypto\n'
        '}\nrc_cmd "$1"\n'
    )
    return content, rc


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--prepare", action="store_true")
    for name in ("source", "binaries", "duncan-public", "proton-public"):
        parser.add_argument("--" + name, type=pathlib.Path)
    for name in ("account", "test-account", "correspondent"):
        parser.add_argument("--" + name)
    args = parser.parse_args()
    require(os.geteuid() == 0 and socket.gethostname() == HOST, "PREPARE_AUTHORITY_REFUSED")
    resource.setrlimit(resource.RLIMIT_CORE, (0, 0))
    os.umask(0o077)
    if not args.prepare:
        print(json.dumps({"target": HOST, "prepared": ROOT.exists(), "services": ["osmap_crypto", "osmap_public_inventory"], "activation": "separate operator step; running web unchanged"}))
        return
    recovery = pathlib.Path("/usr/local/libexec/osmap/service_socket_recovery.py")
    require(recovery.resolve() == recovery, "PREPARE_RECOVERY_CUSTODY_REFUSED")
    for path in (recovery, *recovery.parents):
        metadata = path.lstat()
        require(metadata.st_uid == 0 and not metadata.st_mode & 0o022, "PREPARE_RECOVERY_CUSTODY_REFUSED")
        require(stat.S_ISREG(metadata.st_mode) if path == recovery else stat.S_ISDIR(metadata.st_mode), "PREPARE_RECOVERY_CUSTODY_REFUSED")
    require(recovery.stat().st_nlink == 1, "PREPARE_RECOVERY_CUSTODY_REFUSED")
    require(all(getattr(args, n) for n in ("source", "binaries", "duncan_public", "proton_public")), "PREPARE_INPUT_REFUSED")
    addresses = [args.account, args.test_account, args.correspondent]
    require(all(address and len(address) <= 254 and re.fullmatch(r"[a-z0-9.!#$%&'*+/=?^_`{|}~-]+@[a-z0-9](?:[a-z0-9.-]*[a-z0-9])?", address) for address in addresses), "PREPARE_ADDRESS_REFUSED")
    require(len(set(addresses)) == 3, "PREPARE_ADDRESS_REFUSED")
    accounts = addresses[:2]
    require(not ROOT.exists(), "PREPARE_EXISTING_CUSTODY_REFUSED")
    for path in (args.source, args.binaries, args.duncan_public, args.proton_public):
        require(path.is_absolute() and path.resolve() == path and path.exists(), "PREPARE_INPUT_CUSTODY_REFUSED")
    web = pwd.getpwnam(WEB)
    for name in (HELPER,):
        try:
            pwd.getpwnam(name)
            raise PreparationGuardError("PREPARE_EXISTING_HELPER_REFUSED")
        except KeyError:
            pass
    try:
        grp.getgrnam(GROUP)
        raise PreparationGuardError("PREPARE_EXISTING_GROUP_REFUSED")
    except KeyError:
        pass
    for service in ("osmap_crypto", "osmap_public_inventory"):
        require(not pathlib.Path("/etc/rc.d", service).exists(), "PREPARE_EXISTING_SERVICE_REFUSED")
    pending = pathlib.Path("/var/lib/osmap/settings/openpgp-pending")
    require(not pending.exists() and not pending.is_symlink(), "PREPARE_EXISTING_BINDINGS_REFUSED")
    secrets = pathlib.Path("/var/lib/osmap/secrets")
    require(secrets.is_dir() and secrets.stat().st_uid == web.pw_uid, "PREPARE_SECRET_DIRECTORY_REFUSED")
    for service in ("crypto", "inventory"):
        require(not (secrets / ("openpgp-" + service + ".key")).exists(), "PREPARE_EXISTING_GRANT_REFUSED")

    def run(command, data=None, user=None, timeout=30, settings=None, cwd=None):
        def demote():
            identity = pwd.getpwnam(user)
            os.initgroups(user, identity.pw_gid)
            os.setgid(identity.pw_gid)
            os.setuid(identity.pw_uid)
        result = subprocess.run(list(map(str, command)), input=data, stdout=subprocess.PIPE, stderr=subprocess.PIPE,
                                timeout=timeout, env={"PATH": "/usr/local/bin:/usr/bin:/bin:/usr/sbin:/sbin", "LC_ALL": "C"} | (settings or {}),
                                preexec_fn=demote if user else None, cwd=cwd)
        require(result.returncode == 0, "PREPARE_COMMAND_REFUSED")
        require(len(result.stdout) <= 65536, "PREPARE_COMMAND_OUTPUT_REFUSED")
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
            require(primary == [expected], "PREPARE_PUBLIC_FINGERPRINT_REFUSED")
        built = {}
        for label, source, libraries in [("crypto-worker", "crypto.c", ["-L/usr/local/lib", "-lgpgme", "-lgpg-error"]), ("crypto-engine", "crypto_engine.c", []), ("inventory-worker", "inventory.c", ["-L/usr/local/lib", "-lgpgme", "-lgpg-error"])]:
            destination = scratch / label
            run(["/usr/bin/cc", "-std=c99", "-Wall", "-Wextra", "-Werror", "-I/usr/local/include", args.source / "maint/openpgp-runtime" / source] + libraries + ["-o", destination])
            built[label] = destination
        for name in ("osmap_crypto_helper", "osmap_public_inventory_helper"):
            path = args.binaries / name
            require(path.is_file() and path.stat().st_mode & 0o111, "PREPARE_BINARY_REFUSED")
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
                require((home / name).is_file() and (home / name).stat().st_mode & 0o077 == 0, "PREPARE_PUBLIC_STORE_REFUSED")
            require(not (home / "private-keys-v1.d").exists() or not list((home / "private-keys-v1.d").iterdir()), "PREPARE_PRIVATE_MATERIAL_REFUSED")
            actual = json.loads(run([ROOT / "bin/inventory-worker", home], user=HELPER, settings={"GNUPGHOME": str(home)}, cwd=home))
            require(actual["ok"] and {key["primary"]["fingerprint"] for key in actual["keys"]} == {DUNCAN, PROTON}, "PREPARE_PUBLIC_INVENTORY_REFUSED")
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
            # The script runs under ksh.  rc.subr's default pexp is the
            # wrapper path alone, which cannot match its process arguments.
            rc = '#!/bin/ksh\ndaemon="' + str(wrapper) + '"\ndaemon_user="' + HELPER + '"\nrc_bg=YES\nrc_reload=NO\n. /etc/rc.d/rc.subr\npexp="/bin/ksh ' + str(wrapper) + '"\n'
            # Both fixed services recover only independently proved abandoned listeners.
            rc += 'rc_pre() {\n /usr/local/bin/python3 /usr/local/libexec/osmap/service_socket_recovery.py ' + service + '\n}\n'
            rc += 'rc_cmd "$1"\n'
            if service == "osmap_crypto":
                content, rc = crypto_service_scripts()
            write(wrapper, content, helper.pw_uid, gid, 0o700)
            write(pathlib.Path("/etc/rc.d", service), rc, 0, 0, 0o555)
            run(["/usr/sbin/rcctl", "disable", service])
        receipt = {"version": 1, "target": HOST, "helper_uid": helper.pw_uid, "web_uid": web.pw_uid, "socket_group": GROUP, "previous_web_group_ids": previous_groups, "binary_sha256": hashes, "public_fingerprints": [DUNCAN, PROTON], "services_enabled": False, "live_web_binary_and_environment_modified": False, "private_keys_provisioned": False}
        write(ROOT / "preparation.json", json.dumps(receipt, indent=2) + "\n", 0, 0)
        print(json.dumps(receipt, sort_keys=True))


if __name__ == "__main__":
    main()
