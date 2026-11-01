#!/usr/bin/env python3
"""Disposable OpenBSD service-principal qualification of production helper APIs.

Run as root with explicit candidate source, native lib-test and helper binaries.
Only synthetic key material is created. Public diagnostics contain fixed codes
and counts; bounded failed-command streams remain private. Agents/processes and
unique principals are cleaned here; scratch awaits external evidence readback.
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
    for name in ("source", "test-binary", "crypto-helper", "inventory-helper"):
        parser.add_argument("--" + name, required=True, type=pathlib.Path)
    for name in ("test-binary", "crypto-helper", "inventory-helper", "crypto-source", "engine-source", "inventory-source", "confinement-source"):
        parser.add_argument("--" + name + "-sha256", required=True)
    parser.add_argument("--rollback-inventory-helper", type=pathlib.Path)
    parser.add_argument("--rollback-inventory-helper-sha256")
    args = parser.parse_args()
    require(os.geteuid() == 0 and socket.gethostname() == "obsd1.blackbagsecurity.com", "NATIVE_TARGET_REFUSED")
    require(args.source.is_absolute() and args.source.resolve() == args.source and args.source.is_dir(), "SOURCE_PATH_REFUSED")
    for name in ("test_binary", "crypto_helper", "inventory_helper"):
        pinned_file(getattr(args, name), getattr(args, name + "_sha256"), True)
    require((args.rollback_inventory_helper is None) == (args.rollback_inventory_helper_sha256 is None), "ROLLBACK_PIN_PAIR_REFUSED")
    if args.rollback_inventory_helper is not None:
        pinned_file(args.rollback_inventory_helper, args.rollback_inventory_helper_sha256, True)
    for name, leaf in (("crypto", "crypto.c"), ("engine", "crypto_engine.c"), ("inventory", "inventory.c"), ("confinement", "confinement_test.c")):
        pinned_file(args.source / "maint/openpgp-runtime" / leaf, getattr(args, name + "_source_sha256"))
    os.umask(0o077)
    resource.setrlimit(resource.RLIMIT_CORE, (0, 0))
    root = pathlib.Path(tempfile.mkdtemp(prefix="osmap-principal-fixture-"))
    root.chmod(0o755)
    suffix = str(os.getpid())
    group = "osmq" + suffix
    names = {role: group + role[0] for role in ("helper", "web", "unauthorized")}
    created = []
    identities = {}
    group_created = False
    creation_uncertain = False
    homes = []
    processes = []
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

    def demote(user):
        identity = pwd.getpwnam(user)
        def apply():
            os.initgroups(user, identity.pw_gid)
            os.setgid(identity.pw_gid)
            os.setuid(identity.pw_uid)
        return apply

    def run(command, data=b"", user=None, settings=None, timeout=30, pass_fds=(), cwd=None):
        remaining = (cleanup_until if cleaning else started + 240) - time.monotonic()
        require(remaining > 0, "PRINCIPAL_DEADLINE")
        timeout = min(timeout, remaining)
        operation = {"cc": "COMPILE", "gpg": "GPG", "gpgconf": "AGENT_STOP", "tests": "LIBTEST", "osmap-libtest": "LIBTEST", "python3": "PEER_REACHABILITY", "groupadd": "GROUP_CREATE", "useradd": "USER_CREATE", "userdel": "USER_REMOVE", "groupdel": "GROUP_REMOVE", "pkill": "UID_PROCESS_STOP", "pgrep": "UID_PROCESS_CHECK", "sysctl": "SWAP_CHECK"}.get(pathlib.Path(str(command[0])).name, "FIXTURE_PROBE")
        last_command.clear()
        last_command.update(operation=operation)
        last_output.clear()
        try:
            result = bounded_command(command, data, env=env | (settings or {}), timeout=timeout,
                                     pass_fds=pass_fds, cwd=cwd or root,
                                     preexec_fn=demote(user) if user else None)
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

    def owned(path, uid, gid, mode):
        os.chown(path, uid, gid)
        path.chmod(mode)
        return path

    def gpg(home, arguments, data=b""):
        # Empty synthetic passphrase through standard input, never arguments.
        return ok(["/usr/local/bin/gpg", "--no-options", "--homedir", home, "--batch", "--pinentry-mode", "loopback", "--passphrase-fd", "0"] + arguments,
                  data=data if data else b"\n", user=names["helper"], timeout=60)

    def stop(process):
        stop_owned(process, cleanup_until if cleaning else started + 240)

    def interrupted(_signum, _frame):
        raise Refused("PRINCIPAL_INTERRUPTED")

    for signum in (signal.SIGINT, signal.SIGTERM, signal.SIGHUP):
        signal.signal(signum, interrupted)

    try:
        source_directory = root / "sources"
        source_directory.mkdir(mode=0o700)
        for name, leaf in (("crypto", "crypto.c"), ("engine", "crypto_engine.c"), ("inventory", "inventory.c"), ("confinement", "confinement_test.c")):
            shutil.copyfile(args.source / "maint/openpgp-runtime" / leaf, source_directory / leaf)
            pinned_file(source_directory / leaf, getattr(args, name + "_source_sha256"))
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
            private = root / role
            private.mkdir()
            try:
                pwd.getpwnam(name)
            except KeyError:
                pass
            else:
                raise Refused("DISPOSABLE_USER_ALREADY_EXISTS")
            creation_uncertain = True
            ok(["/usr/sbin/useradd", "-g", group, "-d", private, "-s", "/sbin/nologin", name])
            created.append(name)
            identity = pwd.getpwnam(name)
            require(identity.pw_gid == group_gid and identity.pw_dir == str(private), "DISPOSABLE_USER_IDENTITY_REFUSED")
            identities[name] = (identity.pw_uid, identity.pw_gid, identity.pw_dir)
            creation_uncertain = False
            owned(private, identity.pw_uid, identity.pw_gid, 0o700)
        hu = pwd.getpwnam(names["helper"])
        web = pwd.getpwnam(names["web"])
        require(len({hu.pw_uid, web.pw_uid, pwd.getpwnam(names["unauthorized"]).pw_uid}) == 3, "DISTINCT_UIDS_REFUSED")
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
            expected = {"tests": args.test_binary_sha256, "crypto-service": args.crypto_helper_sha256, "inventory-service": args.inventory_helper_sha256}[label]
            pinned_file(destination, expected, True)
            binaries[label] = destination
        inventory_candidate = root / "inventory-service.candidate"
        shutil.copyfile(binaries["inventory-service"], inventory_candidate)
        inventory_candidate.chmod(0o755)
        pinned_file(inventory_candidate, args.inventory_helper_sha256, True)
        inventory_previous = root / "inventory-service.before"
        if args.rollback_inventory_helper is not None:
            shutil.copyfile(args.rollback_inventory_helper, inventory_previous)
            inventory_previous.chmod(0o755)
            pinned_file(inventory_previous, args.rollback_inventory_helper_sha256, True)

        def publish_inventory(binary, digest):
            temporary = root / "inventory-service.publish"
            require(not temporary.exists() and not temporary.is_symlink(), "PUBLISH_PATH_EXISTS")
            shutil.copyfile(binary, temporary)
            temporary.chmod(0o755)
            pinned_file(temporary, digest, True)
            os.replace(temporary, binaries["inventory-service"])
            pinned_file(binaries["inventory-service"], digest, True)

        if args.rollback_inventory_helper is not None:
            publish_inventory(inventory_previous, args.rollback_inventory_helper_sha256)
        for label, source, libs in [("worker", "crypto.c", ["-L/usr/local/lib", "-lgpgme", "-lgpg-error"]),
                                    ("engine", "crypto_engine.c", []),
                                    ("inventory", "inventory.c", ["-L/usr/local/lib", "-lgpgme", "-lgpg-error"])]:
            destination = helper_root / label
            ok(["/usr/bin/cc", "-std=c99", "-Wall", "-Wextra", "-Werror", "-I/usr/local/include", source_directory / source] + libs + ["-o", destination])
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
                require((home / name).stat().st_mode & 0o077 == 0, "PUBLIC_KEYBOX_MODE_REFUSED")
        private_key = next((homes[0] / "private-keys-v1.d").glob("*.key"))
        # A positive unrestricted file open first establishes the descriptor
        # capability; exact worker startup closes it before confinement/key load.
        for label, implementation in [("crypto", "crypto.c"), ("inventory", "inventory.c")]:
            probe_source = root / (label + "-fd-probe.c")
            include = source_directory / implementation
            setup = "close_inherited_descriptors();" if label == "crypto" else "closefrom(3);"
            confinement = "confine(argv[1],argv[2],1)" if label == "crypto" else "confine(argv[1])"
            foreign = 'if(argc==4&&!strcmp(argv[3],"foreign-agent"))return confine(argv[1],argv[2],1)?22:0;' if label == "crypto" else ""
            probe_source.write_text('#define main hidden_worker_main\n#include "' + str(include) + '"\n#undef main\n#include <fcntl.h>\n#include <errno.h>\n#include <signal.h>\n#include <sys/wait.h>\nint main(int argc,char **argv){'
                                    'if(argc==2&&!strcmp(argv[1],"core")){struct rlimit actual;int result=hidden_worker_main(0,argv);'
                                    'if(result==0||getrlimit(RLIMIT_CORE,&actual)||actual.rlim_cur||actual.rlim_max)return 20;raise(SIGABRT);return 21;}'
                                    + foreign + 'if(argc!=4)return 1;int fd=open(argv[3],O_RDONLY);if(fd<3||fcntl(fd,F_GETFD)<0)return 2;'
                                    + setup + 'if(fcntl(fd,F_GETFD)>=0||errno!=EBADF)return 3;if(!' + confinement
                                    + ')return 4;if(open(argv[3],O_RDONLY)>=0)return 5;pid_t child=fork();if(child<0)return 6;if(!child){_exit(fcntl(fd,F_GETFD)<0&&errno==EBADF?0:7);}int status;if(waitpid(child,&status,0)!=child||!WIFEXITED(status)||WEXITSTATUS(status))return 8;return 0;}\n')
            probe = helper_root / (label + "-fd-probe")
            ok(["/usr/bin/cc", "-std=c99", "-Wall", "-Wextra", "-Werror", "-I/usr/local/include", probe_source, "-L/usr/local/lib", "-lgpgme", "-lgpg-error", "-o", probe])
            owned(probe, hu.pw_uid, hu.pw_gid, 0o700)
            ok([probe, homes[0], binaries["engine"], private_key], user=names["helper"])
            checks[label + "_inherited_fd_closed_and_private_file_denied"] = True
            crashed = run([probe, "core"], user=names["helper"], cwd=helper_root)
            require(crashed.returncode == -signal.SIGABRT, "WORKER_ZERO_CORE_GUARD_REFUSED")
            require(not list(helper_root.glob("*.core")) and not (helper_root / "core").exists(), "WORKER_CORE_FILE_CREATED")
            checks[label + "_entry_inherited_zero_core_checked_before_abort_no_file"] = True
            if label == "crypto":
                foreign_home = helper_root / "foreign-agent"
                foreign_home.mkdir()
                owned(foreign_home, hu.pw_uid, hu.pw_gid, 0o700)
                for leaf in ("pubring.kbx", "trustdb.gpg"):
                    shutil.copyfile(homes[0] / leaf, foreign_home / leaf)
                    owned(foreign_home / leaf, hu.pw_uid, hu.pw_gid, 0o600)
                with socket.socket(socket.AF_UNIX, socket.SOCK_STREAM) as foreign_agent:
                    address = foreign_home / "S.gpg-agent"
                    foreign_agent.bind(str(address))
                    address.chmod(0o666)
                    foreign_agent.listen(1)
                    require(address.lstat().st_uid != hu.pw_uid, "FOREIGN_AGENT_CONTROL_INVALID")
                    ok([probe, foreign_home, binaries["engine"], "foreign-agent"], user=names["helper"])
                address.unlink()
                checks["foreign_uid_agent_endpoint_refused"] = True
        outside = root / "synthetic-global.conf"
        outside.write_text("use-keyboxd\n")
        outside.chmod(0o644)
        confinement_probe = helper_root / "inventory-confinement"
        ok(["/usr/bin/cc", "-std=c99", "-Wall", "-Wextra", "-Werror", "-I/usr/local/include",
            source_directory / "confinement_test.c", "-L/usr/local/lib", "-lgpgme", "-lgpg-error", "-o", confinement_probe])
        owned(confinement_probe, hu.pw_uid, hu.pw_gid, 0o700)
        for denied in (outside, homes[1] / "pubring.kbx"):
            ok([confinement_probe, homes[0], denied], user=names["helper"])
        checks["inventory_exec_child_outside_and_other_home_denied_public_read_allowed"] = True
        inventory = json.loads(ok([binaries["inventory"], homes[0]], user=names["helper"]))
        require(inventory["ok"] is True and len(inventory["keys"]) == 2, "PUBLIC_INVENTORY_REFUSED")
        require(all(k["primary"]["fingerprint"] in fingerprints.values() for k in inventory["keys"]), "PUBLIC_FINGERPRINT_REFUSED")
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
        process = subprocess.Popen(invocation, env=env, stdin=subprocess.DEVNULL, stdout=subprocess.PIPE, stderr=subprocess.PIPE, start_new_session=True, preexec_fn=demote(names["helper"]))
        processes.append(process)
        deadline = time.monotonic() + 8
        while not crypto_socket.exists() and process.poll() is None and time.monotonic() < deadline:
            time.sleep(0.02)
        require(crypto_socket.exists() and process.poll() is None, "CRYPTO_SERVICE_START_REFUSED")
        require(crypto_socket.stat().st_uid == hu.pw_uid and crypto_socket.stat().st_mode & 0o777 == 0o660, "CRYPTO_SOCKET_CUSTODY_REFUSED")
        checks["production_service_serve_separate_uid_socket_permissions"] = True
        inventory_socket = transport / "inventory.sock"
        inventory_config = helper_root / "inventory.json"
        inventory_config.write_text(json.dumps({"version": 1, "worker": str(binaries["inventory"]), "engine": "/usr/local/bin/gpg", "socket": str(inventory_socket), "trusted_web_uid": web.pw_uid, "accounts": [{"account": account, "home": str(home)} for account, home in zip(("alice", "bob"), homes)]}))
        owned(inventory_config, hu.pw_uid, hu.pw_gid, 0o600)
        inventory_socket_identity = None

        def start_inventory():
            nonlocal inventory_socket_identity
            require(not inventory_socket.exists() and not inventory_socket.is_symlink(), "SERVICE_SOCKET_ALREADY_EXISTS")
            child = subprocess.Popen([str(binaries["inventory-service"]), str(inventory_config), str(keys["helper"])], env=env, stdin=subprocess.DEVNULL, stdout=subprocess.PIPE, stderr=subprocess.PIPE, start_new_session=True, preexec_fn=demote(names["helper"]))
            processes.append(child)
            deadline = time.monotonic() + 8
            while not inventory_socket.exists() and child.poll() is None and time.monotonic() < deadline:
                time.sleep(0.02)
            require(inventory_socket.exists() and child.poll() is None, "INVENTORY_SERVICE_START_REFUSED")
            info = inventory_socket.lstat()
            require(stat.S_ISSOCK(info.st_mode) and info.st_uid == hu.pw_uid and info.st_mode & 0o777 == 0o660 and info.st_nlink == 1, "INVENTORY_SOCKET_CUSTODY_REFUSED")
            inventory_socket_identity = (info.st_dev, info.st_ino, info.st_uid, info.st_gid, info.st_mode)
            return child

        def remove_inventory_socket():
            info = inventory_socket.lstat()
            require((info.st_dev, info.st_ino, info.st_uid, info.st_gid, info.st_mode) == inventory_socket_identity, "STOPPED_SOCKET_REPLACED")
            with socket.socket(socket.AF_UNIX, socket.SOCK_STREAM) as peer:
                peer.settimeout(0.25)
                try:
                    peer.connect(str(inventory_socket))
                except OSError as error:
                    require(error.errno == errno.ECONNREFUSED, "STOPPED_SOCKET_UNCERTAIN")
                else:
                    raise Refused("STOPPED_SOCKET_STILL_LIVE")
            current = inventory_socket.lstat()
            require((current.st_dev, current.st_ino, current.st_uid, current.st_gid, current.st_mode) == inventory_socket_identity, "STOPPED_SOCKET_REPLACED")
            inventory_socket.unlink()

        inventory_process = start_inventory()
        checks["production_inventory_service_serve_separate_uid_socket_permissions"] = True
        settings = {"OSMAP_CRYPTO_PRINCIPAL_INVENTORY_SOCKET": str(inventory_socket), "OSMAP_CRYPTO_PRINCIPAL_SOCKET": str(crypto_socket), "OSMAP_CRYPTO_PRINCIPAL_HELPER_UID": str(hu.pw_uid), "OSMAP_CRYPTO_PRINCIPAL_ALICE_FP": fingerprints["alice"], "OSMAP_CRYPTO_PRINCIPAL_BOB_FP": fingerprints["bob"], "OSMAP_CRYPTO_PRINCIPAL_ALICE_HOME": str(homes[0]), "OSMAP_CRYPTO_PRINCIPAL_BOB_HOME": str(homes[1])}
        inventory_test = "openpgp_inventory_runtime::tests::native_inventory_principal_client"

        def authorized_inventory():
            output = ok([binaries["tests"], inventory_test, "--exact", "--ignored", "--test-threads=1"], user=names["web"], settings=settings | {"OSMAP_CRYPTO_PRINCIPAL_KEY": str(keys["web"]), "OSMAP_CRYPTO_PRINCIPAL_MODE": "authorized"})
            require(b"1 passed; 0 failed" in output, "NATIVE_CLIENT_COUNT_REFUSED")

        protected_files = [inventory_config, keys["helper"]]
        for home in homes:
            protected_files.extend([home / "pubring.kbx", home / "trustdb.gpg"])
            protected_files.extend(sorted((home / "private-keys-v1.d").glob("*.key")))
        protected_before = {str(path): hashlib.sha256(path.read_bytes()).hexdigest() for path in protected_files}
        if args.rollback_inventory_helper is not None:
            authorized_inventory()
            checks["known_previous_inventory_binary_actual_client"] = True
            stop(inventory_process)
            remove_inventory_socket()
            publish_inventory(inventory_candidate, args.inventory_helper_sha256)
            inventory_process = start_inventory()
        # A same-grant unauthorized UID must actually reach each transport;
        # a generic client refusal alone could otherwise be a DAC failure.
        reach = "import pathlib,socket,sys\nk=pathlib.Path(sys.argv[2]).read_bytes()\nif len(k)!=32:raise SystemExit(2)\ns=socket.socket(socket.AF_UNIX,socket.SOCK_STREAM);s.settimeout(1);s.connect(sys.argv[1]);s.close()\n"
        for address in (crypto_socket, inventory_socket):
            ok(["/usr/local/bin/python3", "-I", "-B", "-c", reach, address, keys["unauthorized"]], user=names["unauthorized"])
        checks["unauthorized_uid_reaches_transport_and_reads_own_same_grant"] = True
        for role, mode in [("web", "authorized"), ("unauthorized", "peer_denied")]:
            current = settings | {"OSMAP_CRYPTO_PRINCIPAL_KEY": str(keys[role]), "OSMAP_CRYPTO_PRINCIPAL_MODE": mode}
            for label, test in [("crypto", "openpgp_crypto_runtime::tests::native_crypto_principal_client"), ("inventory", "openpgp_inventory_runtime::tests::native_inventory_principal_client")]:
                listing = ok([binaries["tests"], "--list", "--exact", test])
                require((test + ": test").encode() in listing.splitlines(), "ZERO_TEST_REFUSED")
                output = ok([binaries["tests"], test, "--exact", "--ignored", "--test-threads=1"], user=names[role], settings=current)
                require(b"1 passed; 0 failed" in output, "NATIVE_CLIENT_COUNT_REFUSED")
                checks[label + "_" + mode + "_actual_client"] = True
        if args.rollback_inventory_helper is not None:
            stop(inventory_process)
            remove_inventory_socket()
            publish_inventory(inventory_previous, args.rollback_inventory_helper_sha256)
            inventory_process = start_inventory()
            authorized_inventory()
            require(protected_before == {str(path): hashlib.sha256(path.read_bytes()).hexdigest() for path in protected_files}, "ROLLBACK_PROTECTED_FILES_CHANGED")
            checks["changed_inventory_candidate_then_previous_restored_actual_client"] = True
        output = ok([binaries["tests"], "openpgp_crypto_process::tests::duplex_stdin_deadlines_limits_and_descendant_cleanup", "--exact", "--test-threads=1"], user=names["helper"])
        require(b"1 passed; 0 failed" in output, "NATIVE_DUPLEX_COUNT_REFUSED")
        checks["native_duplex_deadline_output_limits_descendant_cleanup"] = True
        require(not (root / "never-default").exists(), "DEFAULT_HOME_CREATED")
        checks["no_default_home_created"] = True
        require(ok(["/sbin/sysctl", "-n", "vm.swapencrypt.enable"]).strip() == b"1", "SWAP_ENCRYPTION_REFUSED")
        checks["native_swap_encryption_enabled"] = True
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
