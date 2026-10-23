"""One fixed root guardian/nonroot HTTP child; never installed activation.

The guardian and web remain in the SAME born root group. The trusted driver
owns the fresh group-only observation after direct web reap, and independently
proves whole-group absence after guardian reap. No caller UID/program/path or
successful password outcome is accepted as authority here.
"""
import ctypes
import grp
import hashlib
import json
import os
from pathlib import Path
import pwd
import re
import resource
import selectors
import signal
import socket
import stat
import struct
import subprocess
import sys
import time

sys.dont_write_bytecode = True
STAGE = Path(__file__).resolve().parent
SELECTOR = 'http::tests::password_tests::genuine_http_pilot::native_single_host_rust_http_password_runtime_entrypoint'
OLD_BINARY = '5c20fa256971b3d32ec4e7c7244929296b094cd584ddebfa6918a2b2e0bc3382'
UID = 1001
GID = 1001
GROUPS = [1001, 1002, 1003]
STOPS = {signal.SIGTERM, signal.SIGINT}
BEGAN = time.monotonic()
JOURNEY_SECONDS = 300
# One original lifetime: setup20 + journey300 + owned-child cleanup10.
END = BEGAN + 330
SETUP = min(END - 10, BEGAN + 20)
CANCELLED = False


class Refused(Exception):
    pass


def require(value, code):
    if not value:
        raise Refused(code)


def cancel(_number, _frame):
    global CANCELLED
    CANCELLED = True


def remaining(deadline, *, cleanup=False):
    require(cleanup or not CANCELLED, 'cancelled')
    left = min(deadline, END) - time.monotonic()
    require(left > 0, 'original_deadline')
    return left


def identity(info):
    return (info.st_dev, info.st_ino, info.st_uid, info.st_gid, info.st_mode,
            info.st_nlink, info.st_size, info.st_mtime_ns, info.st_ctime_ns)


def exact_directory(path, uid, gid, mode):
    remaining(SETUP)
    info = path.lstat()
    require(path.resolve(strict=True) == path and stat.S_ISDIR(info.st_mode)
            and (info.st_uid, info.st_gid, stat.S_IMODE(info.st_mode)) == (uid, gid, mode),
            'fixed_directory')
    return identity(info)


def public_bytes(path, cap, *, mode=0o400):
    remaining(SETUP)
    before = path.lstat()
    require(stat.S_ISREG(before.st_mode) and before.st_uid == before.st_gid == 0
            and before.st_nlink == 1 and stat.S_IMODE(before.st_mode) == mode
            and 0 < before.st_size <= cap, 'fixed_input')
    fd = os.open(path, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK)
    try:
        require(identity(os.fstat(fd)) == identity(before), 'opened_input')
        raw = os.read(fd, cap + 1)
        require(len(raw) == before.st_size and identity(os.fstat(fd)) == identity(before)
                and identity(path.lstat()) == identity(before), 'input_changed')
        remaining(SETUP)
        return raw
    finally:
        os.close(fd)


def unique(pairs):
    out = {}
    for key, value in pairs:
        require(key not in out, 'duplicate_field')
        out[key] = value
    return out


def json_value(raw):
    return json.loads(raw.decode('ascii'), object_pairs_hook=unique)


def namespace(raw):
    value = json_value(raw)
    require(type(value) is dict and set(value) == {'version', 'http_root'}
            and type(value['version']) is int and value['version'] == 1
            and type(value['http_root']) is str, 'namespace_schema')
    http = Path(value['http_root'])
    require(http.parent == Path('/var/run')
            and re.fullmatch('osmap-pxp-[a-f0-9]{16}', http.name), 'namespace_name')
    # Backend bootstrapping is independently owned on the authoritative host.
    # No historical Python factory context or private-front projection grants
    # authority to this actual frontend child.
    return http


def socket_identity(stream):
    info = os.fstat(stream.fileno())
    require(stat.S_ISSOCK(info.st_mode) and info.st_uid == 0
            and stream.family == socket.AF_UNIX
            and stream.getsockopt(socket.SOL_SOCKET, socket.SO_TYPE) == socket.SOCK_STREAM
            and stream.getsockname() in ('', b'') and stream.getpeername() in ('', b''),
            'unnamed_control')
    return identity(info)[:6]


def root_peer(stream):
    libc = ctypes.CDLL(None, use_errno=True)
    uid = ctypes.c_uint()
    gid = ctypes.c_uint()
    fn = libc.getpeereid
    fn.argtypes = (ctypes.c_int, ctypes.POINTER(ctypes.c_uint), ctypes.POINTER(ctypes.c_uint))
    fn.restype = ctypes.c_int
    require(fn(stream.fileno(), ctypes.byref(uid), ctypes.byref(gid)) == 0
            and (uid.value, gid.value) == (0, 0), 'root_control_peer')


class Control:
    def __init__(self, stream):
        self.stream = stream
        self.captured = socket_identity(stream)
        root_peer(stream)

    def current(self):
        require(socket_identity(self.stream) == self.captured, 'control_changed')
        root_peer(self.stream)

    def read(self, cap, deadline):
        self.current()

        def exact(size):
            result = bytearray()
            while len(result) < size:
                self.stream.settimeout(remaining(deadline))
                raw = self.stream.recv(size - len(result))
                require(raw, 'control_eof')
                result.extend(raw)
            return bytes(result)

        size = int.from_bytes(exact(4), 'big')
        require(0 < size <= cap, 'frame_bound')
        raw = exact(size)
        self.current()
        remaining(deadline)
        return raw

    def write(self, raw, deadline):
        require(type(raw) is bytes and 0 < len(raw) <= 2048, 'frame_bound')
        self.current()
        self.stream.settimeout(remaining(deadline))
        self.stream.sendall(len(raw).to_bytes(4, 'big') + raw)
        self.current()
        remaining(deadline)


def role():
    user = pwd.getpwuid(UID)
    group = grp.getgrgid(GID)
    require((user.pw_name, user.pw_uid, user.pw_gid)
            == ('_osmap', UID, GID)
            and (group.gr_name, group.gr_gid) == ('_osmap', GID)
            and sorted(os.getgrouplist('_osmap', GID)) == GROUPS
            and pwd.getpwnam('_osmap').pw_uid == UID and grp.getgrnam('_osmap').gr_gid == GID,
            'fixed_web_role')


def build_record():
    value = json_value(public_bytes(STAGE / 'http-build.json', 4096))
    require(type(value) is dict and set(value) == {'version', 'binary_sha256',
            'binary_bytes', 'source_manifest_sha256'} and type(value['version']) is int
            and value['version'] == 1 and type(value['binary_bytes']) is int
            and 0 < value['binary_bytes'] <= 134217728
            and all(type(value[name]) is str and re.fullmatch('[a-f0-9]{64}', value[name])
                    for name in ('binary_sha256', 'source_manifest_sha256'))
            and value['binary_sha256'] != OLD_BINARY, 'matching_build')
    raw = public_bytes(STAGE / 'source-input-manifest.json', 65536)
    require(hashlib.sha256(raw).hexdigest() == value['source_manifest_sha256'], 'source_manifest')
    pins = json_value(raw)
    require(type(pins) is dict and 'native_http_web_guardian.py' in pins
            and pins['native_http_web_guardian.py'] == hashlib.sha256(
                public_bytes(STAGE / 'native_http_web_guardian.py', 65536)).hexdigest(), 'guardian_pin')
    return value


def copy_binary(http, build):
    source = STAGE / 'qualified-openbsd-libtest'
    before = source.lstat()
    require(stat.S_ISREG(before.st_mode) and before.st_uid == before.st_gid == 0
            and before.st_nlink == 1 and stat.S_IMODE(before.st_mode) == 0o500
            and before.st_size == build['binary_bytes'], 'source_binary')
    code = http / 'web-code'
    code.mkdir(mode=0o700)
    os.chown(code, 0, GID)
    os.chmod(code, 0o750)
    exact_directory(code, 0, GID, 0o750)
    destination = code / 'qualified-libtest'
    src = os.open(source, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK)
    dst = None
    try:
        require(identity(os.fstat(src)) == identity(before), 'source_binary_changed')
        dst = os.open(destination, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW, 0o600)
        digest = hashlib.sha256()
        count = 0
        while True:
            remaining(SETUP)
            data = os.read(src, 65536)
            if not data:
                break
            count += len(data)
            require(count <= build['binary_bytes'], 'binary_bound')
            digest.update(data)
            offset = 0
            while offset < len(data):
                remaining(SETUP)
                written = os.write(dst, data[offset:])
                require(written > 0, 'copy_write')
                offset += written
        require(count == build['binary_bytes'] and digest.hexdigest() == build['binary_sha256']
                and identity(os.fstat(src)) == identity(before)
                and identity(source.lstat()) == identity(before), 'matching_binary_hash')
        os.fchown(dst, 0, GID)
        os.fchmod(dst, 0o550)
        os.fsync(dst)
        copied = identity(os.fstat(dst))
        require(identity(destination.lstat()) == copied and copied[5] == 1
                and copied[2:5] == (0, GID, stat.S_IFREG | 0o550), 'copied_binary')
        check = os.open(destination, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK)
        try:
            require(identity(os.fstat(check)) == copied, 'copied_binary_changed')
            observed = hashlib.sha256()
            count = 0
            while True:
                remaining(SETUP)
                data = os.read(check, 65536)
                if not data:
                    break
                count += len(data)
                require(count <= build['binary_bytes'], 'copied_binary_bound')
                observed.update(data)
            require(count == build['binary_bytes'] and observed.hexdigest() == build['binary_sha256']
                    and identity(os.fstat(check)) == copied
                    and identity(destination.lstat()) == copied, 'copied_binary_hash')
        finally:
            os.close(check)
        return code, destination, identity(code.lstat()), copied
    finally:
        os.close(src)
        if dst is not None:
            os.close(dst)


def drop(proof, parent, group):
    # Guardian is single threaded; this fixed preexec seam adds no selectable
    # command. Its born pipe closes before exec and cannot carry credentials.
    signal.pthread_sigmask(signal.SIG_UNBLOCK, STOPS)
    for number in STOPS:
        signal.signal(number, signal.SIG_DFL)
    resource.setrlimit(resource.RLIMIT_CORE, (0, 0))
    os.setgroups(GROUPS)
    os.setresgid(GID, GID, GID)
    os.setresuid(UID, UID, UID)
    require(os.getresuid() == (UID, UID, UID) and os.getresgid() == (GID, GID, GID)
            and sorted(os.getgroups()) == GROUPS and os.getppid() == parent and os.getpgrp() == group
            and os.getsid(0) == group,
            'irreversible_fixed_drop')
    fields = (os.getpid(), os.getppid(), os.getpgrp(), *os.getresuid(), *os.getresgid(), len(GROUPS), *GROUPS)
    raw = struct.pack('!13I', *fields)
    require(os.write(proof, raw) == len(raw), 'drop_proof_write')
    os.close(proof)


def drop_receipt(fd, child, group):
    raw = bytearray()
    os.set_blocking(fd, False)
    with selectors.DefaultSelector() as selector:
        selector.register(fd, selectors.EVENT_READ)
        while len(raw) < 52:
            require(selector.select(remaining(SETUP)), 'drop_proof_timeout')
            part = os.read(fd, 53 - len(raw))
            require(part, 'drop_proof_eof')
            raw.extend(part)
    require(len(raw) == 52 and struct.unpack('!13I', raw)
            == (child.pid, os.getpid(), group, UID, UID, UID, GID, GID, GID, len(GROUPS), *GROUPS), 'drop_proof')


def launch(binary, control_fd, proof_fd, guardian, group):
    env = {'PATH': '/usr/bin:/bin:/usr/local/bin', 'LC_ALL': 'C', 'TZ': 'UTC',
           'RUST_TEST_THREADS': '1', 'OSMAP_TEST_HTTP_PILOT_FD': str(control_fd)}
    return subprocess.Popen((str(binary), '--exact', SELECTOR, '--ignored', '--nocapture'),
        stdin=subprocess.DEVNULL, stdout=subprocess.PIPE, stderr=subprocess.PIPE,
        close_fds=True, pass_fds=(control_fd, proof_fd), start_new_session=False,
        cwd='/', env=env, preexec_fn=lambda: drop(proof_fd, guardian, group))


def drain(child, deadline):
    out = bytearray()
    err = bytearray()
    try:
        with selectors.DefaultSelector() as selector:
            for stream, target in ((child.stdout, out), (child.stderr, err)):
                os.set_blocking(stream.fileno(), False)
                selector.register(stream, selectors.EVENT_READ, target)
            while selector.get_map():
                for key, _ in selector.select(min(.05, remaining(deadline, cleanup=True))):
                    try:
                        data = os.read(key.fd, 4096)
                    except BlockingIOError:
                        continue
                    if not data:
                        selector.unregister(key.fileobj)
                        key.fileobj.close()
                        continue
                    key.data.extend(data)
                    require(len(out) <= 4096 and len(err) <= 4096, 'web_capture_bound')
        return {'stdout_bytes': len(out), 'stderr_bytes': len(err),
                'stdout_sha256': hashlib.sha256(out).hexdigest(),
                'stderr_sha256': hashlib.sha256(err).hexdigest()}
    finally:
        out.clear()
        err.clear()
        for stream in (child.stdin, child.stdout, child.stderr):
            if stream is not None and not stream.closed:
                stream.close()


def remove_code(code, binary, directory_lease, binary_lease):
    remaining(END, cleanup=True)
    require(identity(code.lstat())[:6] == directory_lease[:6]
            and sorted(p.name for p in code.iterdir()) == ['qualified-libtest']
            and identity(binary.lstat()) == binary_lease, 'code_removal_custody')
    binary.unlink()
    require(identity(code.lstat())[:6] == directory_lease[:6], 'code_directory_changed')
    code.rmdir()


def rust_report(raw):
    report = json_value(raw)
    require(type(report) is dict and set(report) == {'schema', 'handled_connections', 'elapsed_millis',
            'alice_epoch0_refused', 'alice_epoch1_admitted', 'bob_epoch0_admitted'}
            and report['schema'] == 'osmap-http-password-runtime-v1'
            and type(report['handled_connections']) is int and report['handled_connections'] == 18
            and type(report['elapsed_millis']) is int and 0 <= report['elapsed_millis'] <= JOURNEY_SECONDS * 1000
            and report['alice_epoch0_refused'] is True
            and type(report['alice_epoch1_admitted']) is int and report['alice_epoch1_admitted'] == 1
            and type(report['bob_epoch0_admitted']) is int and report['bob_epoch0_admitted'] == 0,
            'rust_report')



def main():
    for number in STOPS:
        signal.signal(number, cancel)
    require(sys.platform.startswith('openbsd') and socket.gethostname() == 'obsd1.blackbagsecurity.com'
            and os.getuid() == os.geteuid() == 0
            and os.getpid() == os.getpgrp() == os.getsid(0)
            and not signal.pthread_sigmask(signal.SIG_BLOCK, set()).intersection(STOPS), 'root_born_guardian')
    resource.setrlimit(resource.RLIMIT_CORE, (0, 0))
    os.umask(0o077)
    require(STAGE.parent == Path('/tmp') and re.fullmatch('osmap-pxp-stage-[a-f0-9]{16}', STAGE.name), 'root_stage_name')
    exact_directory(STAGE, 0, 0, 0o700)
    value = os.environ.get('OSMAP_TEST_HTTP_GUARDIAN_FD', '')
    require(re.fullmatch('[0-9]{1,4}', value) and 3 <= int(value) <= 1024, 'root_control_fd')
    parent = Control(socket.socket(fileno=int(value)))
    child = None
    peer = None
    proof_read = None
    proof_write = None
    web_end = None
    code_lease = None
    capture = None
    try:
        http = namespace(parent.read(2048, SETUP))
        original_http = exact_directory(http, 0, GID, 0o750)
        role()
        build = build_record()
        code_lease = copy_binary(http, build)
        code, binary, directory_lease, binary_lease = code_lease
        root_end, web_end = socket.socketpair()
        peer = Control(root_end)
        proof_read, proof_write = os.pipe2(os.O_CLOEXEC)
        guardian = os.getpid()
        group = os.getpgrp()
        child = launch(binary, web_end.fileno(), proof_write, guardian, group)
        web_end.close()
        web_end = None
        os.close(proof_write)
        proof_write = None
        drop_receipt(proof_read, child, group)
        os.close(proof_read)
        proof_read = None
        require(identity(http.lstat())[:5] == original_http[:5], 'HTTP_namespace_changed')
        custody = {'schema': 'osmap-http-web-custody-v1', 'web_uid': UID, 'web_gid': GID,
                   'binary_sha256': build['binary_sha256'], 'selector': SELECTOR,
                   'web_pid': child.pid, 'guardian_pid': guardian, 'guardian_group': group}
        parent.write(json.dumps(custody, separators=(',', ':')).encode('ascii'), SETUP)
        raw = parent.read(2048, SETUP)
        boot = json_value(raw)
        require(type(boot) is dict and set(boot) == {'version', 'root'}
                and type(boot['version']) is int and boot['version'] == 1
                and boot['root'] == str(http / 'http-state'), 'fixed_rust_bootstrap')
        peer.write(raw, SETUP)
        raw = peer.read(1024, SETUP)
        ready = json_value(raw)
        require(type(ready) is dict and set(ready) == {'schema', 'port', 'connections', 'totp_counter'}
                and ready['schema'] == 'osmap-http-password-ready-v1'
                and type(ready['port']) is int and 1 <= ready['port'] <= 65535
                and type(ready['connections']) is int and ready['connections'] == 18
                and type(ready['totp_counter']) is int and ready['totp_counter'] >= 0, 'rust_ready')
        parent.write(raw, SETUP)
        raw = parent.read(1, SETUP)
        require(raw == b'G', 'fixed_start')
        sequence = min(END - 10, time.monotonic() + JOURNEY_SECONDS)
        peer.write(raw, sequence)
        raw = peer.read(1024, sequence)
        rust_report(raw)
        parent.write(raw, sequence)
        child.wait(timeout=remaining(sequence))
        capture = drain(child, sequence)
        require(child.returncode == 0 and capture['stderr_bytes'] == 0, 'web_terminal')
        # Custody-only acknowledgment from the trusted root driver, which owns
        # the actual fresh external group inventory. It grants no seal, login
        # or mutation authority. Guardian performs no transient same-group ps.
        parent.write(b'WEB_DIRECT_REAPED', sequence)
        require(parent.read(64, sequence) == b'GROUP_ONLY_GUARDIAN', 'driver_group_observation')
        remove_code(*code_lease)
        code_lease = None
        parent.write(b'WEB_REAPED_GROUP_GONE', sequence)
        return 0
    except Exception as error:
        code = str(error) if type(error) is Refused else type(error).__name__
        # Only source-fixed refusal identifiers/classes and bounded scalar
        # capture metadata, never original exception/native stderr/frames.
        require(re.fullmatch('[A-Za-z_]{1,64}', code), 'closed_failure_code')
        report = {'schema': 'osmap-http-web-guardian-failure-v1', 'code': code,
                  'web_terminal': None if child is None else child.returncode, 'capture': capture}
        sys.stderr.write(json.dumps(report, separators=(',', ':')) + '\n')
        return 1
    finally:
        if child is not None and child.returncode is None:
            try:
                child.kill()  # Exact newly born, still-unreaped direct handle.
                child.wait(timeout=remaining(END, cleanup=True))
                drain(child, END)
            except BaseException:
                # Outer trusted driver still owns the held guardian group.
                pass
        for fd in (proof_read, proof_write):
            if fd is not None:
                os.close(fd)
        if peer is not None:
            peer.stream.close()
        if web_end is not None:
            web_end.close()
        parent.stream.close()
        # Failed code namespaces remain retained; only acknowledged direct
        # reap/group-only success permits the exact source-owned unlink above.


if __name__ == '__main__':
    raise SystemExit(main())
