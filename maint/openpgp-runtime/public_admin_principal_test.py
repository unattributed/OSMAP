#!/usr/bin/env python3
"""Disposable obsd1 public-admin RPC qualification; never touches live services.

Root creates three temporary principals. Synthetic public/secret fixture inputs
remain in private scratch pending external evidence readback. Public diagnostics
contain fixed codes, counts and hashes; cleanup disposition is reported separately.
"""
import argparse
import errno
import hashlib
import grp
import json
import os
import pathlib
import pwd
import resource
import selectors
import shutil
import signal
import socket
import stat
import subprocess
import tempfile
import time


class Refused(Exception):
    """Only source-owned codes and bounded accounting cross the runner boundary."""
    def __init__(self, code, counts=None, reported=False):
        super().__init__(code)
        self.code, self.counts, self.reported = code, counts or {}, reported


def require(condition, code):
    if not condition:
        raise Refused(code)


def pinned_file(path, expected, executable=False):
    require(path.is_absolute() and path.resolve() == path, "PIN_PATH_REFUSED")
    info = path.lstat()
    require(stat.S_ISREG(info.st_mode) and not info.st_mode & 0o022, "PIN_CUSTODY_REFUSED")
    require(not executable or info.st_mode & 0o111, "PIN_EXECUTABLE_REFUSED")
    require(len(expected) == 64 and all(c in "0123456789abcdef" for c in expected), "PIN_DIGEST_REFUSED")
    require(hashlib.sha256(path.read_bytes()).hexdigest() == expected, "PIN_MISMATCH")


def stop_owned(process, deadline=None):
    until = time.monotonic() + 5 if deadline is None else deadline
    # returncode None still denotes our unreaped child. Never signal after reap.
    if process.returncode is None:
        require(time.monotonic() < until, "OWNED_STOP_DEADLINE")
        try:
            os.killpg(process.pid, signal.SIGTERM)
        except ProcessLookupError:
            pass
        try:
            process.wait(timeout=max(0.001, min(2, until - time.monotonic())))
        except subprocess.TimeoutExpired:
            require(time.monotonic() < until, "OWNED_STOP_DEADLINE")
            try:
                os.killpg(process.pid, signal.SIGKILL)
            except ProcessLookupError:
                pass
            process.wait(timeout=max(0.001, until - time.monotonic()))


def bounded_command(command, data=b"", *, env, timeout, preexec_fn=None, pass_fds=(), cwd=None):
    """The existing command seam, with bounded duplex pipes and private output."""
    require(len(data) <= 65536 and 0 < timeout <= 90, "COMMAND_BOUNDS_REFUSED")
    process = subprocess.Popen(list(map(str, command)), stdin=subprocess.PIPE,
                               stdout=subprocess.PIPE, stderr=subprocess.PIPE, env=env,
                               preexec_fn=preexec_fn, pass_fds=pass_fds, cwd=cwd,
                               start_new_session=True)
    output = {"stdout": bytearray(), "stderr": bytearray()}
    counts = {"stdout_bytes": 0, "stderr_bytes": 0, "child_reaped": False}
    until = time.monotonic() + timeout
    position = 0
    try:
        with selectors.DefaultSelector() as selector:
            for name, stream in (("stdout", process.stdout), ("stderr", process.stderr)):
                os.set_blocking(stream.fileno(), False)
                selector.register(stream, selectors.EVENT_READ, name)
            if data:
                os.set_blocking(process.stdin.fileno(), False)
                selector.register(process.stdin, selectors.EVENT_WRITE, "stdin")
            else:
                process.stdin.close()
            while selector.get_map():
                remaining = until - time.monotonic()
                require(remaining > 0, "COMMAND_TIMEOUT")
                for key, _ in selector.select(min(remaining, 0.05)):
                    stream, name = key.fileobj, key.data
                    if name == "stdin":
                        try:
                            position += os.write(stream.fileno(), data[position:position + 8192])
                        except BrokenPipeError:
                            selector.unregister(stream)
                            stream.close()
                            continue
                        if position == len(data):
                            selector.unregister(stream)
                            stream.close()
                        continue
                    chunk = os.read(stream.fileno(), 8192)
                    if not chunk:
                        selector.unregister(stream)
                        stream.close()
                        continue
                    counts[name + "_bytes"] += len(chunk)
                    require(counts[name + "_bytes"] <= 131072, "COMMAND_OUTPUT_LIMIT")
                    output[name].extend(chunk)
            remaining = until - time.monotonic()
            require(remaining > 0, "COMMAND_TIMEOUT")
            try:
                status = process.wait(timeout=remaining)
            except subprocess.TimeoutExpired as error:
                raise Refused("COMMAND_TIMEOUT") from error
        counts["child_reaped"] = True
        return subprocess.CompletedProcess(command, status, bytes(output["stdout"]), bytes(output["stderr"]))
    except BaseException as error:
        try:
            stop_owned(process)
        except BaseException:
            counts["stop_disposition"] = "UNCONFIRMED"
        counts["child_reaped"] = process.returncode is not None
        if isinstance(error, Refused):
            error.counts = counts
        error.private_output = {name: bytes(value) for name, value in output.items()}
        raise
    finally:
        for stream in (process.stdin, process.stdout, process.stderr):
            stream.close()


def service_log_counts(processes):
    counts = {"stdout_bytes": 0, "stderr_bytes": 0}
    for process in processes:
        for name in ("stdout", "stderr"):
            stream = getattr(process, name)
            os.set_blocking(stream.fileno(), False)
            data = bytearray()
            try:
                while True:
                    chunk = os.read(stream.fileno(), 8192)
                    if not chunk:
                        break
                    data.extend(chunk)
                    counts[name + "_bytes"] += len(chunk)
                    require(len(data) <= 131072, "SERVICE_LOG_LIMIT")
                require(b"disposable principal fixture" not in data
                        and b"OSMAP_S05_04_DIAGNOSTIC_SECRET" not in data, "SERVICE_LOG_SECRET_MARKER")
            except BlockingIOError as error:
                raise Refused("SERVICE_LOG_EOF_UNCONFIRMED", dict(counts)) from error
            except Refused as error:
                error.counts = dict(counts)
                raise
            finally:
                stream.close()
    return counts


def main():
    parser = argparse.ArgumentParser()
    for name in ("source", "test-binary", "admin-helper"):
        parser.add_argument("--" + name, required=True, type=pathlib.Path)
    for name in ("test-binary", "admin-helper", "inventory-source", "engine-source"):
        parser.add_argument("--" + name + "-sha256", required=True)
    for name in ("inventory-worker", "crypto-engine"):
        parser.add_argument("--" + name, type=pathlib.Path)
        parser.add_argument("--" + name + "-sha256")
    args = parser.parse_args()
    require(os.geteuid() == 0 and socket.gethostname() == "obsd1.blackbagsecurity.com", "NATIVE_TARGET_REFUSED")
    for path in (args.source, args.test_binary, args.admin_helper):
        require(path.is_absolute() and path.resolve() == path and path.exists(), "SOURCE_PATH_REFUSED")
    for name in ("test_binary", "admin_helper"):
        pinned_file(getattr(args, name), getattr(args, name + "_sha256"), True)
    for name, leaf in (("inventory", "inventory.c"), ("engine", "crypto_engine.c")):
        pinned_file(args.source / "maint/openpgp-runtime" / leaf, getattr(args, name + "_source_sha256"))
    supplied = (args.inventory_worker, args.crypto_engine,
                args.inventory_worker_sha256, args.crypto_engine_sha256)
    require(all(value is None for value in supplied) or all(value is not None for value in supplied), "PREBUILT_PIN_PAIR_REFUSED")
    prebuilt = all(value is not None for value in supplied)
    if prebuilt:
        for path, expected in ((args.inventory_worker, args.inventory_worker_sha256),
                               (args.crypto_engine, args.crypto_engine_sha256)):
            require(path.is_absolute() and path.resolve() == path, "PREBUILT_PATH_REFUSED")
            info = path.stat(follow_symlinks=False)
            require(stat.S_ISREG(info.st_mode) and 0 < info.st_size <= 64 * 1024 * 1024, "PREBUILT_FILE_REFUSED")
            require(info.st_mode & 0o111 and not info.st_mode & 0o022, "PREBUILT_MODE_REFUSED")
            require(len(expected) == 64 and all(char in "0123456789abcdef" for char in expected), "PREBUILT_DIGEST_REFUSED")
            require(hashlib.sha256(path.read_bytes()).hexdigest() == expected, "PREBUILT_PIN_MISMATCH")
    os.umask(0o077)
    resource.setrlimit(resource.RLIMIT_CORE, (0, 0))
    root = pathlib.Path(tempfile.mkdtemp(prefix="osmap-admin-principal-"))
    root.chmod(0o755)
    group = "osma" + str(os.getpid())
    names = {role: group + role[0] for role in ("helper", "web", "unauthorized")}
    created, homes, processes = [], [], []
    identities = {}
    group_created = False
    creation_uncertain = False
    checks = {}
    started = time.monotonic()
    cleaning = False
    cleanup_until = None
    last_command = {}
    last_output = {}
    private_command_evidence = {}
    failure = None
    cleanup_errors = []
    log_counts = None
    root_identity = (root.stat().st_dev, root.stat().st_ino)
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
        remaining = (cleanup_until if cleaning else started + 240) - time.monotonic()
        require(remaining > 0, "PRINCIPAL_DEADLINE")
        timeout = min(timeout, remaining)
        operation = {"cc": "COMPILE", "gpg": "GPG", "gpgconf": "AGENT_STOP", "tests": "LIBTEST", "osmap-libtest": "LIBTEST", "python3": "PEER_REACHABILITY", "groupadd": "GROUP_CREATE", "useradd": "USER_CREATE", "userdel": "USER_REMOVE", "groupdel": "GROUP_REMOVE", "pkill": "UID_PROCESS_STOP", "pgrep": "UID_PROCESS_CHECK", "sysctl": "SWAP_CHECK"}.get(pathlib.Path(str(command[0])).name, "FIXTURE_PROBE")
        last_command.clear()
        last_command.update(operation=operation)
        last_output.clear()
        try:
            result = bounded_command(command, data, env=env | (settings or {}), timeout=timeout,
                                     cwd=root, preexec_fn=demote(user) if user else None)
        except BaseException as error:
            last_output.update(getattr(error, "private_output", {}))
            if isinstance(error, Refused):
                error.counts = {"operation": operation, **error.counts}
            raise
        last_output.update(stdout=result.stdout, stderr=result.stderr)
        last_command.clear()
        last_command.update(operation=operation, exit=result.returncode, stdout_bytes=len(result.stdout), stderr_bytes=len(result.stderr), child_reaped=True)
        return result

    def ok(command, **kwargs):
        result = run(command, **kwargs)
        require(result.returncode == 0, "PRINCIPAL_COMMAND_REFUSED")
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
        stop_owned(process, cleanup_until if cleaning else started + 240)

    def interrupted(signum, _frame):
        raise Refused("PRINCIPAL_INTERRUPTED")

    for signum in (signal.SIGINT, signal.SIGTERM, signal.SIGHUP):
        signal.signal(signum, interrupted)

    def fixture(mode, user):
        result = run([root / "tests", test, "--exact", "--ignored", "--test-threads=1"],
                     user=user, settings=settings | {"OSMAP_PUBLIC_ADMIN_PRINCIPAL_MODE": mode}, timeout=90)
        require(result.returncode == 0 and b"1 passed; 0 failed" in result.stdout, "NATIVE_CLIENT_REFUSED")

    try:
        source_directory = root / "sources"
        source_directory.mkdir(mode=0o700)
        for name, leaf in (("inventory", "inventory.c"), ("engine", "crypto_engine.c")):
            shutil.copyfile(args.source / "maint/openpgp-runtime" / leaf, source_directory / leaf)
            pinned_file(source_directory / leaf, getattr(args, name + "_source_sha256"))
        shutil.copyfile(args.test_binary, root / "tests")
        (root / "tests").chmod(0o755)
        pinned_file(root / "tests", args.test_binary_sha256, True)
        listing = ok([root / "tests", "--list", "--exact", test])
        require((test + ": test").encode() in listing.splitlines(), "ZERO_TEST_REFUSED")
        print(json.dumps({"native_test_binary_sha256": hashlib.sha256(args.test_binary.read_bytes()).hexdigest(),
                          "native_admin_binary_sha256": hashlib.sha256(args.admin_helper.read_bytes()).hexdigest(),
                          "source_sha256": {name: hashlib.sha256((args.source / name).read_bytes()).hexdigest() for name in
                                            ("src/openpgp_public_admin_protocol.rs", "src/openpgp_public_admin_runtime.rs",
                                             "src/openpgp_public_admin_runtime_tests.rs", "src/openpgp_public_admin.rs",
                                             "maint/openpgp-runtime/inventory.c", "maint/openpgp-runtime/crypto_engine.c")}}), flush=True)
        try:
            grp.getgrnam(group)
        except KeyError:
            pass
        else:
            raise Refused("DISPOSABLE_GROUP_ALREADY_EXISTS")
        creation_uncertain = True
        ok(["/usr/sbin/groupadd", group])
        group_created = True
        group_gid = grp.getgrnam(group).gr_gid
        creation_uncertain = False
        for role, name in names.items():
            home = root / role
            home.mkdir()
            try:
                pwd.getpwnam(name)
            except KeyError:
                pass
            else:
                raise Refused("DISPOSABLE_USER_ALREADY_EXISTS")
            creation_uncertain = True
            ok(["/usr/sbin/useradd", "-g", group, "-d", home, "-s", "/sbin/nologin", name])
            created.append(name)
            identity = pwd.getpwnam(name)
            require(identity.pw_gid == group_gid and identity.pw_dir == str(home), "DISPOSABLE_USER_IDENTITY_REFUSED")
            identities[name] = (identity.pw_uid, identity.pw_gid, identity.pw_dir)
            creation_uncertain = False
            owned(home, identity, 0o700)
        helper, web, unauthorized = [pwd.getpwnam(names[role]) for role in ("helper", "web", "unauthorized")]
        require(len({helper.pw_uid, web.pw_uid, unauthorized.pw_uid}) == 3, "DISTINCT_UIDS_REFUSED")
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
            pinned_file(destination, args.test_binary_sha256 if label == "tests" else args.admin_helper_sha256, True)
        binaries = {}
        for label, source, libs in [("inventory", "inventory.c", ["-L/usr/local/lib", "-lgpgme", "-lgpg-error"]),
                                    ("engine", "crypto_engine.c", [])]:
            destination = helper_root / label
            if prebuilt:
                supplied_path = args.inventory_worker if label == "inventory" else args.crypto_engine
                expected_hash = args.inventory_worker_sha256 if label == "inventory" else args.crypto_engine_sha256
                shutil.copyfile(supplied_path, destination)
                require(hashlib.sha256(destination.read_bytes()).hexdigest() == expected_hash, "COPIED_WORKER_PIN_MISMATCH")
            else:
                ok(["/usr/bin/cc", "-std=c99", "-Wall", "-Wextra", "-Werror", "-I/usr/local/include",
                    source_directory / source] + libs + ["-o", destination])
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

        socket_identity = None

        def start():
            nonlocal socket_identity
            require(not address.exists() and not address.is_symlink(), "SERVICE_SOCKET_ALREADY_EXISTS")
            process = subprocess.Popen([str(root / "admin-service"), str(config), str(helper_key)],
                                       stdin=subprocess.DEVNULL, stdout=subprocess.PIPE, stderr=subprocess.PIPE,
                                       env=env, start_new_session=True, preexec_fn=demote(names["helper"]))
            processes.append(process)
            until = time.monotonic() + 5
            while not address.exists() and process.poll() is None and time.monotonic() < until:
                time.sleep(0.02)
            require(address.exists() and process.poll() is None, "ADMIN_SERVICE_START_REFUSED")
            info = address.lstat()
            require(stat.S_ISSOCK(info.st_mode) and info.st_uid == helper.pw_uid
                    and info.st_mode & 0o777 == 0o660 and info.st_nlink == 1, "ADMIN_SOCKET_CUSTODY_REFUSED")
            socket_identity = (info.st_dev, info.st_ino, info.st_uid, info.st_gid, info.st_mode)
            return process

        def remove_stopped_socket():
            info = address.lstat()
            require((info.st_dev, info.st_ino, info.st_uid, info.st_gid, info.st_mode) == socket_identity, "STOPPED_SOCKET_REPLACED")
            with socket.socket(socket.AF_UNIX, socket.SOCK_STREAM) as peer:
                peer.settimeout(0.25)
                try:
                    peer.connect(str(address))
                except OSError as error:
                    require(error.errno == errno.ECONNREFUSED, "STOPPED_SOCKET_UNCERTAIN")
                else:
                    raise Refused("STOPPED_SOCKET_STILL_LIVE")
            current = address.lstat()
            require((current.st_dev, current.st_ino, current.st_uid, current.st_gid, current.st_mode) == socket_identity, "STOPPED_SOCKET_REPLACED")
            address.unlink()

        process = start()
        originals = {home: ((home / "trustdb.gpg").read_bytes(),
                           {path.name: path.read_bytes() for path in (home / "private-keys-v1.d").glob("*.key")}) for home in homes}
        fixture("authorized", names["web"])
        checks["actual_service_client_public_import_remove_cas"] = True
        checks["private_primary_remove_and_secret_certificate_import_refused"] = True
        checks["web_keybox_dac_denial_and_cross_account_isolation"] = True
        settings["OSMAP_PUBLIC_ADMIN_PRINCIPAL_KEY"] = str(unauthorized_key)
        before = [(home / "pubring.kbx").read_bytes() for home in homes]
        reach = "import pathlib,socket,sys\nk=pathlib.Path(sys.argv[2]).read_bytes()\nif len(k)!=32:raise SystemExit(2)\ns=socket.socket(socket.AF_UNIX,socket.SOCK_STREAM);s.settimeout(1);s.connect(sys.argv[1]);s.close()\n"
        ok(["/usr/local/bin/python3", "-I", "-B", "-c", reach, address, unauthorized_key], user=names["unauthorized"])
        checks["unauthorized_uid_reaches_transport_and_reads_own_same_grant"] = True
        fixture("peer_denied", names["unauthorized"])
        require(before == [(home / "pubring.kbx").read_bytes() for home in homes], "PEER_REFUSAL_MUTATED_KEYBOX")
        checks["unauthorized_peer_with_same_hmac_refused"] = True
        settings["OSMAP_PUBLIC_ADMIN_PRINCIPAL_KEY"] = str(web_key)
        fixture("consume_once", names["web"])
        stop(process)
        remove_stopped_socket()
        process = start()
        before = [(home / "pubring.kbx").read_bytes() for home in homes]
        fixture("replay_after_restart", names["web"])
        require(before == [(home / "pubring.kbx").read_bytes() for home in homes], "REPLAY_MUTATED_KEYBOX")
        checks["durable_mutation_replay_refused_after_actual_helper_restart"] = True
        for home, (trust, private) in originals.items():
            require(trust == (home / "trustdb.gpg").read_bytes(), "TRUSTDB_CHANGED")
            require(private == {path.name: path.read_bytes() for path in (home / "private-keys-v1.d").glob("*.key")}, "PRIVATE_KEYS_CHANGED")
        checks["trustdb_and_private_files_unchanged"] = True
    except BaseException as error:
        failure = error.code if isinstance(error, Refused) else "NATIVE_OBSERVATION_UNAVAILABLE"
        counts = error.counts if isinstance(error, Refused) and error.counts else last_command
        try:
            for name, data in last_output.items():
                path = root / ("last-command." + name)
                with path.open("xb") as stream:
                    os.fchmod(stream.fileno(), 0o600)
                    stream.write(data)
                    stream.flush()
                    os.fsync(stream.fileno())
                private_command_evidence[name] = {"bytes": len(data), "sha256": hashlib.sha256(data).hexdigest()}
        except BaseException:
            private_command_evidence["retention"] = "UNCONFIRMED"
        print(json.dumps({"functional": "FAIL", "failure": failure, "last_command": counts,
                          "missing_observation": None if isinstance(error, Refused) else "Unexpected exception details were not retained; only fixed codes, counts and any bounded command streams are retained."}, sort_keys=True), flush=True)
    finally:
        cleaning = True
        cleanup_until = started + 330
        for process in reversed(processes):
            try:
                stop(process)
            except BaseException:
                cleanup_errors.append("SERVICE_STOP_UNCONFIRMED")
        for home in homes:
            try:
                require(run(["/usr/local/bin/gpgconf", "--homedir", home, "--kill", "gpg-agent"], user=names["helper"], timeout=15).returncode == 0, "AGENT_STOP_REFUSED")
            except BaseException:
                cleanup_errors.append("AGENT_STOP_UNCONFIRMED")
        # Revalidate each freshly created, exclusive UID before selecting its
        # descendants. Unknown/replaced identities are retained, never killed.
        for name in reversed(created):
            try:
                identity = pwd.getpwnam(name)
                require((identity.pw_uid, identity.pw_gid, identity.pw_dir) == identities[name], "CLEANUP_UID_REPLACED")
                result = run(["/usr/bin/pkill", "-KILL", "-u", str(identity.pw_uid)])
                require(result.returncode in (0, 1), "DISPOSABLE_PROCESS_STOP_REFUSED")
                until = time.monotonic() + 3
                while run(["/usr/bin/pgrep", "-u", str(identity.pw_uid)]).returncode == 0 and time.monotonic() < until:
                    time.sleep(0.02)
                require(run(["/usr/bin/pgrep", "-u", str(identity.pw_uid)]).returncode == 1, "DISPOSABLE_PROCESSES_REMAIN")
            except BaseException:
                cleanup_errors.append("UID_PROCESSES_UNCONFIRMED")
        if creation_uncertain:
            cleanup_errors.append("PRINCIPAL_CREATION_UNCONFIRMED")
        try:
            log_counts = service_log_counts(processes)
            checks["service_diagnostics_bounded_without_synthetic_plaintext"] = True
        except Refused as error:
            log_counts = error.counts
            cleanup_errors.append(error.code)
        except BaseException:
            cleanup_errors.append("SERVICE_LOG_VERIFICATION_UNCONFIRMED")
        if not cleanup_errors:
            try:
                for name in reversed(created):
                    ok(["/usr/sbin/userdel", name])
                    try:
                        pwd.getpwnam(name)
                    except KeyError:
                        pass
                    else:
                        raise Refused("DISPOSABLE_USER_REMAINS")
                if group_created:
                    require(grp.getgrnam(group).gr_gid == group_gid, "CLEANUP_GROUP_REPLACED")
                    ok(["/usr/sbin/groupdel", group])
                    try:
                        grp.getgrnam(group)
                    except KeyError:
                        pass
                    else:
                        raise Refused("DISPOSABLE_GROUP_REMAINS")
            except BaseException:
                cleanup_errors.append("PRINCIPAL_REMOVAL_UNCONFIRMED")
        scratch_identity = None
        try:
            info = root.lstat()
            require(not root.is_symlink() and (info.st_dev, info.st_ino) == root_identity, "SCRATCH_IDENTITY_REFUSED")
            root.chmod(0o700)
            scratch_identity = {"device": info.st_dev, "inode": info.st_ino, "uid": info.st_uid}
        except BaseException:
            cleanup_errors.append("SCRATCH_CUSTODY_UNCONFIRMED")
        print(json.dumps({"target": "obsd1.blackbagsecurity.com", "functional": "PASS" if failure is None else "FAIL",
                          "failure": failure, "cleanup": "PASS" if not cleanup_errors else "UNCONFIRMED",
                          "cleanup_scope": "SERVICES_AGENTS_PRINCIPALS_ONLY", "cleanup_failures": cleanup_errors, "retained_fixture": str(root) if root.exists() else None,
                          "service_log_counts": log_counts,
                          "private_command_evidence": private_command_evidence,
                          "scratch_disposition": "RETAINED_FOR_EVIDENCE_READBACK", "scratch_identity": scratch_identity,
                          "checks": checks, "all_passed": failure is None and not cleanup_errors,
                          "elapsed_seconds": round(time.monotonic() - started, 3)}, sort_keys=True), flush=True)
    if failure is not None or cleanup_errors:
        raise Refused("PRINCIPAL_RUN_REFUSED", reported=True)


if __name__ == "__main__":
    try:
        main()
    except SystemExit:
        raise
    except BaseException as error:
        if not isinstance(error, Refused) or not error.reported:
            print(json.dumps({"functional": "FAIL", "failure": error.code if isinstance(error, Refused) else "PREPARATION_UNAVAILABLE",
                              "cleanup": "NOT_STARTED", "counts": error.counts if isinstance(error, Refused) else {}}), flush=True)
        raise SystemExit(1) from None
