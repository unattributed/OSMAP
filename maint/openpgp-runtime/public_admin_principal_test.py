#!/usr/bin/env python3
"""Disposable obsd1 public-admin RPC qualification; never touches live services.

Root creates three temporary principals. Synthetic public/secret fixture inputs
are removed with scratch; evidence contains check booleans/source hashes only.
A provisional candidate qualification flag is required to start Service.serve.
"""
import argparse
import hashlib
import json
import os
import pathlib
import pwd
import resource
import shutil
import signal
import socket
import stat
import subprocess
import tempfile
import time


def main():
    parser = argparse.ArgumentParser()
    for name in ("source", "test-binary", "admin-helper"):
        parser.add_argument("--" + name, required=True, type=pathlib.Path)
    for name in ("inventory-worker", "crypto-engine"):
        parser.add_argument("--" + name, type=pathlib.Path)
        parser.add_argument("--" + name + "-sha256")
    args = parser.parse_args()
    assert os.geteuid() == 0 and socket.gethostname() == "obsd1.blackbagsecurity.com"
    for path in (args.source, args.test_binary, args.admin_helper):
        assert path.is_absolute() and path.resolve() == path and path.exists()
    supplied = (args.inventory_worker, args.crypto_engine,
                args.inventory_worker_sha256, args.crypto_engine_sha256)
    assert all(value is None for value in supplied) or all(value is not None for value in supplied), \
        "prebuilt workers require both binaries and both expected SHA-256 digests"
    prebuilt = all(value is not None for value in supplied)
    if prebuilt:
        for path, expected in ((args.inventory_worker, args.inventory_worker_sha256),
                               (args.crypto_engine, args.crypto_engine_sha256)):
            assert path.is_absolute() and path.resolve() == path, "prebuilt worker must use a canonical absolute path"
            info = path.stat(follow_symlinks=False)
            assert stat.S_ISREG(info.st_mode) and 0 < info.st_size <= 64 * 1024 * 1024, \
                "prebuilt worker must be a bounded regular file"
            assert info.st_mode & 0o111 and not info.st_mode & 0o022, \
                "prebuilt worker must be executable and not group/world writable"
            assert len(expected) == 64 and all(char in "0123456789abcdef" for char in expected), \
                "prebuilt worker requires a lowercase SHA-256 digest"
            assert hashlib.sha256(path.read_bytes()).hexdigest() == expected, \
                "prebuilt worker does not match its expected SHA-256 digest"
    os.umask(0o077)
    resource.setrlimit(resource.RLIMIT_CORE, (0, 0))
    root = pathlib.Path(tempfile.mkdtemp(prefix="osmap-admin-principal-"))
    root.chmod(0o755)
    group = "osma" + str(os.getpid())
    names = {role: group + role[0] for role in ("helper", "web", "unauthorized")}
    created, homes, processes = [], [], []
    group_created = False
    checks = {}
    started = time.monotonic()
    cleaning = False
    env = {"PATH": "/usr/local/bin:/usr/bin:/bin:/usr/sbin:/sbin", "LC_ALL": "C", "HOME": str(root / "never-default")}
    test = "openpgp_public_admin_runtime::tests::native_public_admin_principal_client"

    def demote(user):
        identity = pwd.getpwnam(user)
        def apply():
            os.initgroups(user, identity.pw_gid)
            os.setgid(identity.pw_gid)
            os.setuid(identity.pw_uid)
        return apply

    def run(command, data=b"", user=None, settings=None, timeout=30):
        assert cleaning or time.monotonic() - started < 240, "overall native fixture deadline"
        return subprocess.run(list(map(str, command)), input=data, capture_output=True,
                              env=env | (settings or {}), timeout=timeout,
                              preexec_fn=demote(user) if user else None)

    def ok(command, **kwargs):
        result = run(command, **kwargs)
        if result.returncode and pathlib.Path(str(command[0])).name == "tests":
            for line in (result.stdout + result.stderr).decode(errors="replace").splitlines():
                if "panicked at" in line or "assertion" in line or "called `" in line:
                    print(line, flush=True)
        assert result.returncode == 0, "native fixture command refused: " + pathlib.Path(str(command[0])).name
        return result.stdout

    def owned(path, identity, mode):
        os.chown(path, identity.pw_uid, identity.pw_gid)
        path.chmod(mode)
        return path

    def write(path, data, identity):
        with path.open("xb") as file:
            file.write(data)
            os.fchown(file.fileno(), identity.pw_uid, identity.pw_gid)
            os.fchmod(file.fileno(), 0o600)
        return path

    def gpg(home, arguments):
        return ok(["/usr/local/bin/gpg", "--no-options", "--homedir", home, "--batch",
                   "--pinentry-mode", "loopback", "--passphrase-fd", "0"] + arguments,
                  data=b"\n", user=names["helper"], timeout=60)

    def stop(process):
        try:
            os.killpg(process.pid, signal.SIGKILL)
        except ProcessLookupError:
            pass
        process.wait(timeout=10)

    def interrupted(signum, _frame):
        raise SystemExit("native fixture interrupted: " + str(signum))

    for signum in (signal.SIGTERM, signal.SIGHUP):
        signal.signal(signum, interrupted)

    def fixture(mode, user):
        result = run([root / "tests", test, "--exact", "--ignored", "--test-threads=1"],
                     user=user, settings=settings | {"OSMAP_PUBLIC_ADMIN_PRINCIPAL_MODE": mode}, timeout=90)
        if result.returncode:
            for line in (result.stdout + result.stderr).decode(errors="replace").splitlines():
                if "panicked at" in line or "assertion" in line or "called `" in line:
                    print(line, flush=True)
        assert result.returncode == 0 and b"1 passed; 0 failed" in result.stdout, "actual principal fixture refused: " + mode

    try:
        listing = ok([args.test_binary, "--list", test])
        assert (test + ": test").encode() in listing, "zero-test proof refused"
        print(json.dumps({"native_test_binary_sha256": hashlib.sha256(args.test_binary.read_bytes()).hexdigest(),
                          "native_admin_binary_sha256": hashlib.sha256(args.admin_helper.read_bytes()).hexdigest(),
                          "source_sha256": {name: hashlib.sha256((args.source / name).read_bytes()).hexdigest() for name in
                                            ("src/openpgp_public_admin_protocol.rs", "src/openpgp_public_admin_runtime.rs",
                                             "src/openpgp_public_admin_runtime_tests.rs", "src/openpgp_public_admin.rs",
                                             "maint/openpgp-runtime/inventory.c", "maint/openpgp-runtime/crypto_engine.c")}}), flush=True)
        ok(["/usr/sbin/groupadd", group])
        group_created = True
        for role, name in names.items():
            home = root / role
            home.mkdir()
            ok(["/usr/sbin/useradd", "-g", group, "-d", home, "-s", "/sbin/nologin", name])
            created.append(name)
            owned(home, pwd.getpwnam(name), 0o700)
        helper, web, unauthorized = [pwd.getpwnam(names[role]) for role in ("helper", "web", "unauthorized")]
        assert len({helper.pw_uid, web.pw_uid, unauthorized.pw_uid}) == 3
        checks["three_distinct_principals"] = True
        helper_root = root / "helper"
        transport = root / "transport"
        transport.mkdir()
        owned(transport, helper, 0o750)
        state = helper_root / "state"
        state.mkdir()
        owned(state, helper, 0o700)
        for label, source in [("tests", args.test_binary), ("admin-service", args.admin_helper)]:
            destination = root / label
            shutil.copyfile(source, destination)
            destination.chmod(0o755)
        binaries = {}
        for label, source, libs in [("inventory", "inventory.c", ["-L/usr/local/lib", "-lgpgme", "-lgpg-error"]),
                                    ("engine", "crypto_engine.c", [])]:
            destination = helper_root / label
            if prebuilt:
                supplied_path = args.inventory_worker if label == "inventory" else args.crypto_engine
                expected_hash = args.inventory_worker_sha256 if label == "inventory" else args.crypto_engine_sha256
                shutil.copyfile(supplied_path, destination)
                assert hashlib.sha256(destination.read_bytes()).hexdigest() == expected_hash, \
                    "copied prebuilt worker differs from qualified SHA-256 digest"
            else:
                ok(["/usr/bin/cc", "-std=c99", "-Wall", "-Wextra", "-Werror", "-I/usr/local/include",
                    args.source / "maint/openpgp-runtime" / source] + libs + ["-o", destination])
            binaries[label] = owned(destination, helper, 0o700)
        worker_hashes = {label: hashlib.sha256(path.read_bytes()).hexdigest()
                         for label, path in binaries.items()}
        print(json.dumps({"qualified_inventory_worker_sha256": worker_hashes["inventory"],
                          "qualified_crypto_engine_sha256": worker_hashes["engine"],
                          "prebuilt_workers": prebuilt}, sort_keys=True), flush=True)
        fingerprints = {}
        for account in ("alice", "bob"):
            home = helper_root / account
            home.mkdir()
            owned(home, helper, 0o700)
            homes.append(home)
            gpg(home, ["--quick-generate-key", "Synthetic " + account + " <" + account + "@fixture.test>", "ed25519", "cert,sign", "0"])
            listed = gpg(home, ["--with-colons", "--list-keys"]).decode()
            fingerprints[account] = next(line.split(":")[9] for line in listed.splitlines() if line.startswith("fpr:"))
            gpg(home, ["--quick-add-key", fingerprints[account], "cv25519", "encrypt", "0"])
        certificate = write(root / "web" / "public.asc", gpg(homes[1], ["--armor", "--export", fingerprints["bob"]]), web)
        secret_certificate = write(root / "web" / "synthetic-secret.asc", gpg(homes[1], ["--armor", "--export-secret-keys", fingerprints["bob"]]), web)
        grant = os.urandom(32)
        helper_key = write(helper_root / "grant", grant, helper)
        web_key = write(root / "web" / "grant", grant, web)
        unauthorized_key = write(root / "unauthorized" / "grant", grant, unauthorized)
        address = transport / "admin.sock"
        config = write(helper_root / "config", json.dumps({"version": 1, "worker": str(binaries["inventory"]),
                    "engine": str(binaries["engine"]), "state_directory": str(state), "socket": str(address),
                    "trusted_web_uid": web.pw_uid, "accounts": [{"account": name, "home": str(home)}
                                                              for name, home in zip(("alice", "bob"), homes)]}).encode(), helper)
        settings = {"OSMAP_PUBLIC_ADMIN_PRINCIPAL_SOCKET": str(address), "OSMAP_PUBLIC_ADMIN_PRINCIPAL_KEY": str(web_key),
                    "OSMAP_PUBLIC_ADMIN_PRINCIPAL_HELPER_UID": str(helper.pw_uid),
                    "OSMAP_PUBLIC_ADMIN_PRINCIPAL_ALICE_FP": fingerprints["alice"], "OSMAP_PUBLIC_ADMIN_PRINCIPAL_BOB_FP": fingerprints["bob"],
                    "OSMAP_PUBLIC_ADMIN_PRINCIPAL_ALICE_HOME": str(homes[0]), "OSMAP_PUBLIC_ADMIN_PRINCIPAL_BOB_HOME": str(homes[1]),
                    "OSMAP_PUBLIC_ADMIN_PRINCIPAL_CERTIFICATE": str(certificate), "OSMAP_PUBLIC_ADMIN_PRINCIPAL_SECRET_CERTIFICATE": str(secret_certificate),
                    "OSMAP_PUBLIC_ADMIN_PRINCIPAL_REPLAY_FILE": str(root / "web" / "replay")}

        def start():
            process = subprocess.Popen([str(root / "admin-service"), str(config), str(helper_key)],
                                       stdin=subprocess.DEVNULL, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL,
                                       env=env, start_new_session=True, preexec_fn=demote(names["helper"]))
            processes.append(process)
            until = time.monotonic() + 5
            while not address.exists() and process.poll() is None and time.monotonic() < until:
                time.sleep(0.02)
            assert address.exists() and process.poll() is None, "actual Service.serve startup refused"
            return process

        process = start()
        originals = {home: ((home / "trustdb.gpg").read_bytes(),
                           {path.name: path.read_bytes() for path in (home / "private-keys-v1.d").glob("*.key")}) for home in homes}
        fixture("authorized", names["web"])
        checks["actual_service_client_public_import_remove_cas"] = True
        checks["private_primary_remove_and_secret_certificate_import_refused"] = True
        checks["web_keybox_dac_denial_and_cross_account_isolation"] = True
        settings["OSMAP_PUBLIC_ADMIN_PRINCIPAL_KEY"] = str(unauthorized_key)
        before = [(home / "pubring.kbx").read_bytes() for home in homes]
        fixture("peer_denied", names["unauthorized"])
        assert before == [(home / "pubring.kbx").read_bytes() for home in homes]
        checks["unauthorized_peer_with_same_hmac_refused"] = True
        settings["OSMAP_PUBLIC_ADMIN_PRINCIPAL_KEY"] = str(web_key)
        fixture("consume_once", names["web"])
        stop(process)
        address.unlink()
        process = start()
        before = [(home / "pubring.kbx").read_bytes() for home in homes]
        fixture("replay_after_restart", names["web"])
        assert before == [(home / "pubring.kbx").read_bytes() for home in homes]
        checks["durable_mutation_replay_refused_after_actual_helper_restart"] = True
        for home, (trust, private) in originals.items():
            assert trust == (home / "trustdb.gpg").read_bytes()
            assert private == {path.name: path.read_bytes() for path in (home / "private-keys-v1.d").glob("*.key")}
        checks["trustdb_and_private_files_unchanged"] = True
    finally:
        cleaning = True
        for process in processes:
            stop(process)
        for home in homes:
            result = run(["/usr/local/bin/gpgconf", "--homedir", home, "--kill", "gpg-agent"], user=names["helper"], timeout=15)
            assert result.returncode == 0, "disposable agent cleanup refused"
        # Every UID was created solely for this fixture. Reap any persistent
        # worker/agent descendant before releasing its UID; no live UID selected.
        for name in created:
            uid = pwd.getpwnam(name).pw_uid
            result = run(["/usr/bin/pkill", "-KILL", "-u", str(uid)])
            assert result.returncode in (0, 1), "disposable process cleanup refused"
            until = time.monotonic() + 3
            while run(["/usr/bin/pgrep", "-u", str(uid)]).returncode == 0 and time.monotonic() < until:
                time.sleep(0.02)
            assert run(["/usr/bin/pgrep", "-u", str(uid)]).returncode == 1, "persistent disposable descendants"
        for name in reversed(created):
            ok(["/usr/sbin/userdel", name])
        if group_created:
            ok(["/usr/sbin/groupdel", group])
        shutil.rmtree(root)
        assert not root.exists()
        checks["temporary_services_agents_principals_and_scratch_removed"] = True
    print(json.dumps({"public_admin_native_principal": "PASS", "checks": checks,
                      "qualified_inventory_worker_sha256": worker_hashes["inventory"],
                      "qualified_crypto_engine_sha256": worker_hashes["engine"],
                      "prebuilt_workers": prebuilt}, sort_keys=True), flush=True)


if __name__ == "__main__":
    main()
