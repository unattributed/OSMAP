#!/usr/local/bin/python3
"""Bounded, peer-authenticated Unix-to-SSH relay for OSMAP development.

Run one instance for Dovecot auth and one for the mailbox helper. The remote
authorized key must force an exact Unix-socket connector command; this program
never accepts a client-supplied destination or remote command.
"""

import argparse
import ctypes
import errno
import os
import pathlib
import re
import selectors
import signal
import socket
import stat
import subprocess
import sys
import threading
import time


CHUNK = 64 * 1024
BUFFER_LIMIT = 256 * 1024
MAILBOX_REQUEST_LIMIT = (48 * 1024 * 1024 // 3 * 4) + 8192
PURPOSE_LIMITS = {
    "auth": (64 * 1024, 64 * 1024, 25.0),
    "mailbox": (MAILBOX_REQUEST_LIMIT, 1024 * 1024, 20.0),
}
MAX_CONNECTIONS = 4


class RelayError(Exception):
    """A local configuration, authority, or transport failure."""


def peer_ids(client):
    """Read the kernel's effective peer credentials; never trust socket mode alone."""
    libc = ctypes.CDLL(None, use_errno=True)
    function = getattr(libc, "getpeereid", None)
    if function is None:
        raise RelayError("native getpeereid is unavailable")
    function.argtypes = [ctypes.c_int, ctypes.POINTER(ctypes.c_uint), ctypes.POINTER(ctypes.c_uint)]
    function.restype = ctypes.c_int
    uid = ctypes.c_uint()
    gid = ctypes.c_uint()
    if function(client.fileno(), ctypes.byref(uid), ctypes.byref(gid)) != 0:
        number = ctypes.get_errno()
        raise RelayError(f"native getpeereid failed: errno {number}")
    return uid.value, gid.value


def authorize_peer(client, trusted_uid, identity_reader=peer_ids):
    uid, _ = identity_reader(client)
    if uid != trusted_uid:
        raise RelayError("local peer UID was not authorized")


def _absolute_path(value):
    path = pathlib.Path(value)
    if not path.is_absolute() or not re.fullmatch(r"/[A-Za-z0-9_./-]+", str(path)):
        raise RelayError("path must be an absolute static pathname")
    if ".." in path.parts or len(os.fsencode(path)) >= 100:
        raise RelayError("path is not a safe Unix-socket pathname")
    return path


def _regular_file(path, *, private=False):
    metadata = path.lstat()
    if not stat.S_ISREG(metadata.st_mode) or metadata.st_uid not in (0, os.geteuid()):
        raise RelayError("SSH material must be a regular root- or service-owned file")
    if metadata.st_mode & (0o077 if private else 0o022):
        raise RelayError("SSH material permissions are too broad")


def validate_config(config):
    if os.geteuid() == 0:
        raise RelayError("relay must run as its dedicated unprivileged principal")
    if config.purpose not in PURPOSE_LIMITS:
        raise RelayError("unknown relay purpose")
    if not re.fullmatch(r"[A-Za-z0-9][A-Za-z0-9.-]{0,252}", config.remote_host):
        raise RelayError("remote host is not a static hostname or address")
    for field in ("listen", "identity", "known_hosts", "control_path"):
        setattr(config, field, _absolute_path(getattr(config, field)))
    if config.identity.name != config.purpose or config.control_path.name != f"{config.purpose}-ssh.sock":
        raise RelayError("SSH identity and control socket must match relay purpose")
    if config.listen == config.control_path:
        raise RelayError("listener and SSH control socket must differ")
    for path in (config.listen, config.control_path):
        parent = path.parent
        metadata = parent.lstat()
        if not stat.S_ISDIR(metadata.st_mode) or metadata.st_uid != os.geteuid():
            raise RelayError("socket parent must be a service-owned directory")
        if parent.resolve() != parent or metadata.st_mode & 0o027:
            raise RelayError("socket parent must deny group write and all other-user access")
        if path == config.control_path and metadata.st_mode & 0o077:
            raise RelayError("SSH control socket parent must be owner-only")
    if config.listen.exists() or config.listen.is_symlink():
        raise RelayError("listener path already exists; inspect stale state before recovery")
    _regular_file(config.identity, private=True)
    _regular_file(config.known_hosts)
    if config.trusted_uid < 0 or config.trusted_uid > 0xFFFFFFFF:
        raise RelayError("trusted UID is outside native range")


def ssh_argv(config):
    """Use a distinct control socket and key for each forced remote command."""
    return [
        "/usr/bin/ssh", "-F", "/dev/null", "-T", "-a", "-x",
        "-i", str(config.identity),
        "-o", "BatchMode=yes", "-o", "IdentitiesOnly=yes",
        "-o", "IdentityAgent=none",
        "-o", "PasswordAuthentication=no", "-o", "KbdInteractiveAuthentication=no",
        "-o", "StrictHostKeyChecking=yes", "-o", "UpdateHostKeys=no",
        "-o", f"UserKnownHostsFile={config.known_hosts}",
        "-o", "ControlMaster=auto", "-o", "ControlPersist=60",
        "-o", f"ControlPath={config.control_path}",
        "-o", "ClearAllForwardings=yes", "-o", "ForwardAgent=no",
        "-o", "ConnectTimeout=5", "-o", "ConnectionAttempts=1",
        "-o", "ServerAliveInterval=5", "-o", "ServerAliveCountMax=1",
        f"_osmap@{config.remote_host}", "osmap-relay",
    ]


def _interest(selector, fileobj, events, tag):
    try:
        old = selector.get_key(fileobj)
    except KeyError:
        old = None
    if events:
        if old is None:
            selector.register(fileobj, events, tag)
        elif old.events != events:
            selector.modify(fileobj, events, tag)
    elif old is not None:
        selector.unregister(fileobj)


def pump(client, process, request_limit, response_limit, lifetime):
    """Copy full duplex with independent EOF, byte caps, and one wall deadline."""
    if process.stdin is None or process.stdout is None:
        raise RelayError("SSH pipes were unavailable")
    client.setblocking(False)
    input_fd = process.stdin.fileno()
    output_fd = process.stdout.fileno()
    os.set_blocking(input_fd, False)
    os.set_blocking(output_fd, False)
    to_remote = bytearray()
    to_client = bytearray()
    from_client = 0
    from_remote = 0
    client_eof = False
    remote_eof = False
    remote_input_closed = False
    deadline = time.monotonic() + lifetime

    with selectors.DefaultSelector() as selector:
        while True:
            if client_eof and not to_remote and not remote_input_closed:
                _interest(selector, process.stdin, 0, "remote_input")
                process.stdin.close()  # ssh forwards EOF; remote nc -N half-closes.
                remote_input_closed = True
            if remote_eof and not to_client:
                try:
                    client.shutdown(socket.SHUT_WR)
                except OSError:
                    pass
                if client_eof:
                    return
            if remote_eof and not to_client and process.poll() is not None:
                return

            local_events = 0
            if not client_eof and len(to_remote) < BUFFER_LIMIT:
                local_events |= selectors.EVENT_READ
            if to_client:
                local_events |= selectors.EVENT_WRITE
            _interest(selector, client, local_events, "client")
            _interest(selector, process.stdout, selectors.EVENT_READ if not remote_eof and len(to_client) < BUFFER_LIMIT else 0, "remote_output")
            if not remote_input_closed:
                _interest(selector, process.stdin, selectors.EVENT_WRITE if to_remote else 0, "remote_input")

            remaining = deadline - time.monotonic()
            if remaining <= 0:
                raise RelayError("relay connection deadline exceeded")
            if not selector.get_map():
                raise RelayError("relay had no live transport endpoints")
            for key, mask in selector.select(min(remaining, 1.0)):
                if key.data == "client":
                    if mask & selectors.EVENT_READ:
                        chunk = client.recv(min(CHUNK, BUFFER_LIMIT - len(to_remote)))
                        if not chunk:
                            client_eof = True
                        else:
                            from_client += len(chunk)
                            if from_client > request_limit:
                                raise RelayError("request byte limit exceeded")
                            to_remote.extend(chunk)
                    if mask & selectors.EVENT_WRITE:
                        written = client.send(to_client)
                        del to_client[:written]
                elif key.data == "remote_output":
                    chunk = os.read(output_fd, min(CHUNK, BUFFER_LIMIT - len(to_client)))
                    if not chunk:
                        remote_eof = True
                    else:
                        from_remote += len(chunk)
                        if from_remote > response_limit:
                            raise RelayError("response byte limit exceeded")
                        to_client.extend(chunk)
                elif key.data == "remote_input":
                    try:
                        written = os.write(input_fd, to_remote)
                    except BrokenPipeError as error:
                        raise RelayError("remote transport closed before request completed") from error
                    del to_remote[:written]


def relay_connection(client, config):
    try:
        authorize_peer(client, config.trusted_uid)
        process = subprocess.Popen(
            ssh_argv(config), stdin=subprocess.PIPE, stdout=subprocess.PIPE,
            stderr=subprocess.DEVNULL, close_fds=True,
        )
        try:
            request_limit, response_limit, lifetime = PURPOSE_LIMITS[config.purpose]
            pump(client, process, request_limit, response_limit, lifetime)
        finally:
            if process.poll() is None:
                try:
                    process.wait(timeout=1)
                except subprocess.TimeoutExpired:
                    process.terminate()
                    try:
                        process.wait(timeout=2)
                    except subprocess.TimeoutExpired:
                        process.kill()
                        process.wait(timeout=2)
            if process.stdin and not process.stdin.closed:
                process.stdin.close()
            if process.stdout:
                process.stdout.close()
    except (OSError, RelayError, subprocess.SubprocessError):
        # Never echo remote stderr or any authentication/message payload.
        pass
    finally:
        client.close()


def serve(config):
    validate_config(config)
    os.umask(0o077)
    capacity = threading.BoundedSemaphore(MAX_CONNECTIONS)
    listener = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
    listener_inode = None
    stopping = threading.Event()

    def stop(_signal, _frame):
        stopping.set()

    try:
        listener.bind(str(config.listen))
        metadata = config.listen.lstat()
        listener_inode = (metadata.st_dev, metadata.st_ino)
        os.chmod(config.listen, 0o660)
        listener.listen(MAX_CONNECTIONS)
        listener.settimeout(1.0)
        signal.signal(signal.SIGTERM, stop)
        signal.signal(signal.SIGINT, stop)
        while not stopping.is_set():
            try:
                client, _ = listener.accept()
            except socket.timeout:
                continue
            if not capacity.acquire(blocking=False):
                client.close()
                continue

            def work(connection):
                try:
                    relay_connection(connection, config)
                finally:
                    capacity.release()

            try:
                threading.Thread(target=work, args=(client,), daemon=True).start()
            except RuntimeError:
                client.close()
                capacity.release()
                raise
    finally:
        listener.close()
        try:
            current = config.listen.lstat()
            if listener_inode is not None and (current.st_dev, current.st_ino) == listener_inode and stat.S_ISSOCK(current.st_mode):
                config.listen.unlink()
        except FileNotFoundError:
            pass


def main(argv=None):
    parser = argparse.ArgumentParser()
    parser.add_argument("--purpose", choices=sorted(PURPOSE_LIMITS), required=True)
    parser.add_argument("--listen", required=True)
    parser.add_argument("--identity", required=True)
    parser.add_argument("--known-hosts", required=True)
    parser.add_argument("--control-path", required=True)
    parser.add_argument("--remote-host", required=True)
    parser.add_argument("--trusted-uid", type=int, required=True)
    config = parser.parse_args(argv)
    try:
        serve(config)
    except (OSError, RelayError) as error:
        print(f"OSMAP relay refused startup: {error}", file=sys.stderr)
        return 1
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
