#!/usr/bin/env python3
"""Disposable OpenBSD service-principal qualification of production helper APIs.

Run as root with explicit candidate source, native lib-test and helper binaries.
Only synthetic key material is created. Logs contain checks/booleans only; each
agent/process and each unique temporary principal is removed in finally.
"""
import argparse
import errno
import hashlib
import json
import os
import pathlib
import pwd
import resource
import shutil
import signal
import socket
import subprocess
import tempfile
import time


def main():
    parser = argparse.ArgumentParser()
    for name in ("source", "test-binary", "crypto-helper", "inventory-helper"):
        parser.add_argument("--" + name, required=True, type=pathlib.Path)
    args = parser.parse_args()
    assert os.geteuid() == 0 and socket.gethostname() == "obsd1.blackbagsecurity.com"
    for path in vars(args).values():
        assert path.is_absolute() and path.exists()
    os.umask(0o077)
    resource.setrlimit(resource.RLIMIT_CORE, (0, 0))
    root = pathlib.Path(tempfile.mkdtemp(prefix="osmap-principal-fixture-"))
    root.chmod(0o755)
    suffix = str(os.getpid())
    group = "osmq" + suffix
    names = {role: group + role[0] for role in ("helper", "web", "unauthorized")}
    created = []
    group_created = False
    homes = []
    processes = []
    checks = {}
    started = time.monotonic()
    env = {"PATH": "/usr/local/bin:/usr/bin:/bin:/usr/sbin:/sbin", "LC_ALL": "C", "HOME": str(root / "never-default")}

    def demote(user):
        identity = pwd.getpwnam(user)
        def apply():
            os.initgroups(user, identity.pw_gid)
            os.setgid(identity.pw_gid)
            os.setuid(identity.pw_uid)
        return apply

    def run(command, data=b"", user=None, settings=None, timeout=30, pass_fds=()):
        assert time.monotonic() - started < 240, "overall principal deadline"
        command = list(map(str, command))
        settings = env | (settings or {})
        result = subprocess.run(command, input=data, stdout=subprocess.PIPE, stderr=subprocess.PIPE,
                                env=settings, timeout=timeout, pass_fds=pass_fds,
                                preexec_fn=demote(user) if user else None)
        return result

    def ok(command, **kwargs):
        result = run(command, **kwargs)
        if result.returncode and pathlib.Path(str(command[0])).name == "tests":
            for line in (result.stdout + result.stderr).decode(errors="replace").splitlines():
                if "panicked at" in line or "assertion" in line or "called `" in line or "stdout limit error:" in line:
                    print(line, flush=True)
        assert result.returncode == 0, "principal command refused: " + pathlib.Path(str(command[0])).name
        return result.stdout

    def owned(path, uid, gid, mode):
        os.chown(path, uid, gid)
        path.chmod(mode)
        return path

    def gpg(home, arguments, data=b""):
        # Empty synthetic passphrase through standard input, never arguments.
        return ok(["/usr/local/bin/gpg", "--no-options", "--homedir", home, "--batch", "--pinentry-mode", "loopback", "--passphrase-fd", "0"] + arguments,
                  data=data if data else b"\n", user=names["helper"], timeout=60)

    def stop(process):
        if process.poll() is None:
            os.killpg(process.pid, signal.SIGKILL)
        process.wait(timeout=10)

    try:
        ok(["/usr/sbin/groupadd", group])
        group_created = True
        for role, name in names.items():
            private = root / role
            private.mkdir()
            ok(["/usr/sbin/useradd", "-g", group, "-d", private, "-s", "/sbin/nologin", name])
            created.append(name)
            identity = pwd.getpwnam(name)
            owned(private, identity.pw_uid, identity.pw_gid, 0o700)
        hu = pwd.getpwnam(names["helper"])
        web = pwd.getpwnam(names["web"])
        assert hu.pw_uid != web.pw_uid != pwd.getpwnam(names["unauthorized"]).pw_uid
        checks["three_distinct_disposable_principals"] = True
        helper_root = root / "helper"
        transport = root / "transport"
        transport.mkdir()
        owned(transport, hu.pw_uid, hu.pw_gid, 0o750)
        binaries = {}
        for label, source in [("tests", args.test_binary), ("crypto-service", args.crypto_helper), ("inventory-service", args.inventory_helper)]:
            destination = root / label
            shutil.copyfile(source, destination)
            destination.chmod(0o755)
            binaries[label] = destination
        for label, source, libs in [("worker", "crypto.c", ["-L/usr/local/lib", "-lgpgme", "-lgpg-error"]),
                                    ("engine", "crypto_engine.c", []),
                                    ("inventory", "inventory.c", ["-L/usr/local/lib", "-lgpgme", "-lgpg-error"])]:
            destination = helper_root / label
            ok(["/usr/bin/cc", "-std=c99", "-Wall", "-Wextra", "-Werror", "-I/usr/local/include", args.source / "maint/openpgp-runtime" / source] + libs + ["-o", destination])
            owned(destination, hu.pw_uid, hu.pw_gid, 0o700)
            binaries[label] = destination
        fingerprints = {}
        for account in ("alice", "bob"):
            home = helper_root / account
            home.mkdir()
            owned(home, hu.pw_uid, hu.pw_gid, 0o700)
            homes.append(home)
            gpg(home, ["--quick-generate-key", "Synthetic " + account + " <" + account + "@fixture.test>", "ed25519", "cert,sign", "0"])
            fingerprints[account] = next(line.split(":")[9] for line in gpg(home, ["--with-colons", "--list-keys"]).decode().splitlines() if line.startswith("fpr:"))
            gpg(home, ["--quick-add-key", fingerprints[account], "cv25519", "encrypt", "0"])
        for recipient, sender in [(0, 1), (1, 0)]:
            public = gpg(homes[sender], ["--export", fingerprints[("alice", "bob")[sender]]])
            # import has no passphrase prompt; avoid consuming public input as passphrase
            ok(["/usr/local/bin/gpg", "--no-options", "--homedir", homes[recipient], "--batch", "--import"], data=public, user=names["helper"])
        for home in homes:
            for name in ("pubring.kbx", "trustdb.gpg"):
                assert (home / name).stat().st_mode & 0o077 == 0
        private_key = next((homes[0] / "private-keys-v1.d").glob("*.key"))
        # A positive unrestricted file open first establishes the descriptor
        # capability; exact worker startup closes it before confinement/key load.
        for label, implementation in [("crypto", "crypto.c"), ("inventory", "inventory.c")]:
            probe_source = root / (label + "-fd-probe.c")
            include = args.source / "maint/openpgp-runtime" / implementation
            setup = "close_inherited_descriptors();" if label == "crypto" else "closefrom(3);"
            confinement = "confine(argv[1],argv[2],1)" if label == "crypto" else "confine(argv[1])"
            probe_source.write_text('#define main hidden_worker_main\n#include "' + str(include) + '"\n#undef main\n#include <fcntl.h>\n#include <errno.h>\n#include <sys/wait.h>\nint main(int argc,char **argv){if(argc!=4)return 1;int fd=open(argv[3],O_RDONLY);if(fd<3||fcntl(fd,F_GETFD)<0)return 2;' + setup + 'if(fcntl(fd,F_GETFD)>=0||errno!=EBADF)return 3;if(!' + confinement + ')return 4;if(open(argv[3],O_RDONLY)>=0)return 5;pid_t child=fork();if(child<0)return 6;if(!child){_exit(fcntl(fd,F_GETFD)<0&&errno==EBADF?0:7);}int status;if(waitpid(child,&status,0)!=child||!WIFEXITED(status)||WEXITSTATUS(status))return 8;return 0;}\n')
            probe = helper_root / (label + "-fd-probe")
            ok(["/usr/bin/cc", "-std=c99", "-Wall", "-Wextra", "-Werror", "-I/usr/local/include", probe_source, "-L/usr/local/lib", "-lgpgme", "-lgpg-error", "-o", probe])
            owned(probe, hu.pw_uid, hu.pw_gid, 0o700)
            ok([probe, homes[0], binaries["engine"], private_key], user=names["helper"])
            checks[label + "_inherited_fd_closed_and_private_file_denied"] = True
        inventory = json.loads(ok([binaries["inventory"], homes[0]], user=names["helper"]))
        assert inventory["ok"] is True and len(inventory["keys"]) == 2
        assert all(k["primary"]["fingerprint"] in fingerprints.values() for k in inventory["keys"])
        checks["native_public_inventory_after_private_file_confinement"] = True
        key = os.urandom(32)
        keys = {}
        for role, name in names.items():
            identity = pwd.getpwnam(name)
            path = root / role / "authentication.key"
            path.write_bytes(key)
            owned(path, identity.pw_uid, identity.pw_gid, 0o600)
            keys[role] = path
        mapping = [{"account": account, "home": str(home), "signer_fingerprint": fingerprints[account], "decrypt_fingerprints": [fingerprints[account]], "recipient_fingerprints": list(fingerprints.values())} for account, home in zip(("alice", "bob"), homes)]
        crypto_socket = transport / "crypto.sock"
        crypto_config = helper_root / "crypto.json"
        crypto_config.write_text(json.dumps({"version": 1, "worker": str(binaries["worker"]), "engine": str(binaries["engine"]), "socket": str(crypto_socket), "trusted_web_uid": web.pw_uid, "accounts": mapping}))
        owned(crypto_config, hu.pw_uid, hu.pw_gid, 0o600)
        invocation = [str(binaries["crypto-service"]), str(crypto_config), str(keys["helper"])]
        process = subprocess.Popen(invocation, env=env, stdin=subprocess.DEVNULL, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL, start_new_session=True, preexec_fn=demote(names["helper"]))
        processes.append(process)
        deadline = time.monotonic() + 8
        while not crypto_socket.exists() and process.poll() is None and time.monotonic() < deadline:
            time.sleep(0.02)
        assert crypto_socket.exists() and process.poll() is None, "production Service.serve did not start"
        assert crypto_socket.stat().st_uid == hu.pw_uid and crypto_socket.stat().st_mode & 0o777 == 0o660
        checks["production_service_serve_separate_uid_socket_permissions"] = True
        inventory_socket = transport / "inventory.sock"
        inventory_config = helper_root / "inventory.json"
        inventory_config.write_text(json.dumps({"version": 1, "worker": str(binaries["inventory"]), "engine": "/usr/local/bin/gpg", "socket": str(inventory_socket), "trusted_web_uid": web.pw_uid, "accounts": [{"account": account, "home": str(home)} for account, home in zip(("alice", "bob"), homes)]}))
        owned(inventory_config, hu.pw_uid, hu.pw_gid, 0o600)
        inventory_process = subprocess.Popen([str(binaries["inventory-service"]), str(inventory_config), str(keys["helper"])], env=env, stdin=subprocess.DEVNULL, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL, start_new_session=True, preexec_fn=demote(names["helper"]))
        processes.append(inventory_process)
        deadline = time.monotonic() + 8
        while not inventory_socket.exists() and inventory_process.poll() is None and time.monotonic() < deadline:
            time.sleep(0.02)
        assert inventory_socket.exists() and inventory_process.poll() is None, "production inventory Service.serve did not start"
        assert inventory_socket.stat().st_uid == hu.pw_uid and inventory_socket.stat().st_mode & 0o777 == 0o660
        checks["production_inventory_service_serve_separate_uid_socket_permissions"] = True
        settings = {"OSMAP_CRYPTO_PRINCIPAL_INVENTORY_SOCKET": str(inventory_socket), "OSMAP_CRYPTO_PRINCIPAL_SOCKET": str(crypto_socket), "OSMAP_CRYPTO_PRINCIPAL_HELPER_UID": str(hu.pw_uid), "OSMAP_CRYPTO_PRINCIPAL_ALICE_FP": fingerprints["alice"], "OSMAP_CRYPTO_PRINCIPAL_BOB_FP": fingerprints["bob"], "OSMAP_CRYPTO_PRINCIPAL_ALICE_HOME": str(homes[0]), "OSMAP_CRYPTO_PRINCIPAL_BOB_HOME": str(homes[1])}
        for role, mode in [("web", "authorized"), ("unauthorized", "peer_denied")]:
            current = settings | {"OSMAP_CRYPTO_PRINCIPAL_KEY": str(keys[role]), "OSMAP_CRYPTO_PRINCIPAL_MODE": mode}
            for label, test in [("crypto", "openpgp_crypto_runtime::tests::native_crypto_principal_client"), ("inventory", "openpgp_inventory_runtime::tests::native_inventory_principal_client")]:
                output = ok([binaries["tests"], test, "--exact", "--ignored", "--test-threads=1"], user=names[role], settings=current)
                assert b"1 passed; 0 failed" in output
                checks[label + "_" + mode + "_actual_client"] = True
        output = ok([binaries["tests"], "openpgp_crypto_process::tests::duplex_stdin_deadlines_limits_and_descendant_cleanup", "--exact", "--test-threads=1"], user=names["helper"])
        assert b"1 passed; 0 failed" in output
        checks["native_duplex_deadline_output_limits_descendant_cleanup"] = True
        assert not (root / "never-default").exists()
        checks["no_default_home_created"] = True
        assert ok(["/sbin/sysctl", "-n", "vm.swapencrypt.enable"]).strip() == b"1"
        checks["native_swap_encryption_enabled"] = True
        print(json.dumps({"target": "obsd1.blackbagsecurity.com", "provisional_candidate": True, "checks": checks, "all_passed": all(checks.values())}, sort_keys=True), flush=True)
    finally:
        for process in reversed(processes):
            stop(process)
        for home in homes:
            run(["/usr/local/bin/gpgconf", "--homedir", home, "--kill", "gpg-agent"], user=names["helper"])
        # pgrep sees any surviving worker/agent/fixture descendants, including
        # a process whose parent exited and whose descriptors were closed.
        for name in reversed(created):
            uid = pwd.getpwnam(name).pw_uid
            deadline = time.monotonic() + 2
            while run(["/usr/bin/pgrep", "-u", str(uid)]).returncode == 0 and time.monotonic() < deadline:
                time.sleep(0.02)
            assert run(["/usr/bin/pgrep", "-u", str(uid)]).returncode == 1, "temporary principal still owns live processes"
            ok(["/usr/sbin/userdel", name])
            try:
                pwd.getpwnam(name)
                raise AssertionError("temporary principal remains")
            except KeyError:
                pass
        if group_created:
            ok(["/usr/sbin/groupdel", group])
        assert root.name.startswith("osmap-principal-fixture-") and root.parent == pathlib.Path("/tmp")
        shutil.rmtree(root)
        print("temporary_services_agents_principals_scratch_cleanup=PASS", flush=True)


if __name__ == "__main__":
    main()
