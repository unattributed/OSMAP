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
import threading

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
                self.stream.settimeout(min(.1, remaining(deadline)))
                try:
                    raw = self.stream.recv(size - len(result))
                except socket.timeout:
                    continue
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


# Raw output remains private in these bounded in-memory prefixes. Only fixed
# source-owned observations and stream accounting cross the evidence boundary.
OUTPUT_LIMIT = 16384
CONFINEMENT_MARKER = b'OSMAP_SERVE_CONFINEMENT_V1'
CONFINEMENT_FIELDS = {'schema', 'stage', 'reason', 'syscall', 'errno', 'rule_ordinal'}
CONSTRUCTION_MARKER = b'OSMAP_ACCOUNT_CONSTRUCTION_V1'
CONSTRUCTION_FIELDS = {'schema', 'operation', 'check', 'category'}
CONSTRUCTION_OPERATIONS = frozenset(('core_dumps','socket_validation','key_load','custody_capture'))
CONSTRUCTION_CHECKS = frozenset(('ancestor_metadata','ancestor_directory','ancestor_owner',
    'ancestor_permissions','absolute_path','path_length','canonicalize','canonical_path',
    'parent_path','directory_metadata','directory_type','directory_owner','directory_permissions',
    'file_open','file_metadata','file_type','file_owner','file_size','file_permissions','executable',
    'key_read','key_length','socket_metadata','socket_type','socket_owner','socket_permissions',
    'socket_links','parent_metadata','key_metadata','key_links','descriptor_flags','close_on_exec',
    'parent_identity','socket_identity','key_descriptor_identity','key_path_identity','key_content',
    'core_dump_limit'))
CONSTRUCTION_CATEGORIES = frozenset(('invariant','absent','denied','invalid','busy','capacity',
    'deadline','interrupted','unsupported','other_io'))


def validate_construction(value):
    """Only the Rust construction/custody enums cross the diagnostic boundary."""
    require(type(value) is dict and set(value) == CONSTRUCTION_FIELDS, 'diagnostic_schema')
    require(value['schema'] == 'osmap-account-construction-v1'
        and type(value['operation']) is str and value['operation'] in CONSTRUCTION_OPERATIONS
        and type(value['check']) is str and value['check'] in CONSTRUCTION_CHECKS
        and type(value['category']) is str and value['category'] in CONSTRUCTION_CATEGORIES,
        'diagnostic_schema')
    return value


def validate_confinement(value):
    """Closed source-owned detail; paths and unrestricted error text cannot pass."""
    require(type(value) is dict and set(value) == CONFINEMENT_FIELDS, 'diagnostic_schema')
    require(value['schema'] == 'osmap-serve-confinement-v1'
        and type(value['stage']) is str and type(value['reason']) is str,
        'diagnostic_schema')
    stage, reason = value['stage'], value['reason']
    syscall = {'initial_pledge': 'pledge', 'final_pledge': 'pledge',
               'unveil_rule': 'unveil', 'unveil_lock': 'unveil'}.get(stage)
    require((stage == 'unveil_rule' and type(value['rule_ordinal']) is int
             and 1 <= value['rule_ordinal'] <= 2**32-1)
            or stage != 'unveil_rule' and value['rule_ordinal'] is None, 'diagnostic_schema')
    if reason == 'syscall_failed':
        require(syscall is not None and value['syscall'] == syscall
            and type(value['errno']) is int and 1 <= value['errno'] <= 4095, 'diagnostic_schema')
    else:
        require(value['syscall'] is None and value['errno'] is None, 'diagnostic_schema')
        require((reason == 'invalid_argument' and stage in
                 ('initial_pledge', 'final_pledge', 'unveil_rule'))
                or (reason == 'boundary_refused' and stage in ('dependency_plan',
                    'purpose_separation', 'admission_preflight', 'mutation_preflight',
                    'unsupported_platform')), 'diagnostic_schema')
    return value


NATIVE_MESSAGES = {
    b'HTTP fixture core limit refused': 'native_core_limit',
    b'HTTP fixture descriptor required': 'native_descriptor_required',
    b'HTTP fixture descriptor refused': 'native_descriptor',
    b'HTTP fixture fixed role/root peer refused': 'native_role_peer',
    b'HTTP fixture bootstrap refused': 'native_bootstrap',
    b'HTTP fixture namespace refused': 'native_namespace',
    b'HTTP fixture state refused': 'native_state',
    b'HTTP fixture account config required': 'native_account_config',
    b'HTTP fixture admission custody refused': 'native_admission_client',
    b'HTTP fixture mutation custody refused': 'native_mutation_client',
    b'HTTP fixture listener refused': 'native_listener',
    b'HTTP fixture listener mode refused': 'native_listener_mode',
    b'HTTP fixture listener identity refused': 'native_listener_identity',
    b'HTTP fixture actual Serve confinement refused': 'native_confinement',
    b'HTTP fixture ready refused': 'native_ready_transmission',
    b'HTTP fixture start refused': 'native_start',
    b'HTTP fixture report refused': 'native_report',
}
NATIVE_CODES = frozenset(NATIVE_MESSAGES.values()) | {'native_panic', 'native_entrypoint_not_selected', 'CAUSE_UNKNOWN'}
FAILURE_CODES = frozenset("""cancelled original_deadline fixed_directory fixed_input
opened_input input_changed duplicate_field namespace_schema namespace_name
unnamed_control root_control_peer control_changed control_eof frame_bound
fixed_web_role matching_build source_manifest guardian_pin source_binary
source_binary_changed binary_bound copy_write matching_binary_hash copied_binary
copied_binary_changed copied_binary_bound copied_binary_hash irreversible_fixed_drop
drop_proof_write drop_proof_timeout drop_proof_eof drop_proof code_removal_custody
code_directory_changed rust_report root_born_guardian root_stage_name root_control_fd
HTTP_namespace_changed fixed_rust_bootstrap rust_ready fixed_start web_terminal
driver_group_observation capture_io capture_deadline diagnostic_schema
diagnostic_write diagnostic_integrity exception_os exception_timeout exception_value
exception_subprocess exception_interrupted exception_unknown exception_file_not_found
exception_permission""".split())
STAGES = frozenset('initializing initialized namespace_validated binary_verified child_born '
                   'identity_confirmed custody_sent bootstrap_sent ready_validated ready_sent '
                   'start_sent report_received child_reaped group_confirmed code_removed'.split())
OPERATIONS = frozenset('initialize namespace build launch identity custody bootstrap '
                       'ready_read ready_validate ready_send start_read start_send report '
                       'reap capture group_observation preserve remove_code'.split())


def failure_code(error):
    if type(error) is Refused and str(error) in FAILURE_CODES:
        return str(error)
    if isinstance(error, (TimeoutError, subprocess.TimeoutExpired)):
        return 'exception_timeout'
    if isinstance(error, FileNotFoundError):
        return 'exception_file_not_found'
    if isinstance(error, PermissionError):
        return 'exception_permission'
    if isinstance(error, OSError):
        return 'exception_os'
    if isinstance(error, (ValueError, UnicodeError)):
        return 'exception_value'
    if isinstance(error, subprocess.SubprocessError):
        return 'exception_subprocess'
    if isinstance(error, (KeyboardInterrupt, SystemExit)):
        return 'exception_interrupted'
    return 'exception_unknown'


class Capture:
    """Continuously service both child pipes, including every startup wait.

    Each selector turn reads one chunk per ready stream. Hashes/counts cover
    all consumed bytes; a bounded prefix is used only for fixed-code parsing.
    The worker starts after Popen/preexec has returned, never before fork.
    """
    def __init__(self, child):
        self.child = child
        self.lock = threading.Lock()
        self.stop = threading.Event()
        self.error = None
        self.native_code = 'CAUSE_UNKNOWN'
        self.panic_seen = False
        self.confinement_detail = None
        self.confinement_status = 'NOT_EMITTED'
        self.confinement_markers = 0
        self.construction_detail = None
        self.construction_status = 'NOT_EMITTED'
        self.construction_markers = 0
        self.lines = {name: bytearray() for name in ('stdout', 'stderr')}
        self.line_overflow = {name: False for name in ('stdout', 'stderr')}
        self.streams = {}
        for name in ('stdout', 'stderr'):
            stream = getattr(child, name)
            os.set_blocking(stream.fileno(), False)
            self.streams[name] = {'stream': stream, 'prefix': bytearray(),
                                  'count': 0, 'hash': hashlib.sha256(), 'eof': False}
        self.worker = threading.Thread(target=self._run, daemon=True)
        self.worker.start()

    def _run(self):
        try:
            with selectors.DefaultSelector() as selector:
                for name, item in self.streams.items():
                    selector.register(item['stream'], selectors.EVENT_READ, name)
                while selector.get_map():
                    if self.stop.is_set() or time.monotonic() >= END:
                        with self.lock:
                            self.error = 'capture_deadline'
                        break
                    for key, _ in selector.select(.05):
                        try:
                            raw = os.read(key.fd, 65536)
                        except (BlockingIOError, InterruptedError):
                            continue
                        with self.lock:
                            item = self.streams[key.data]
                            if not raw:
                                item['eof'] = True
                                selector.unregister(key.fileobj)
                            else:
                                item['count'] += len(raw)
                                item['hash'].update(raw)
                                self._native_observation(raw, key.data)
                                item['prefix'].extend(raw[:max(0, OUTPUT_LIMIT-len(item['prefix']))])
        except Exception:
            with self.lock:
                self.error = 'capture_io'
        finally:
            for item in self.streams.values():
                item['stream'].close()

    def _native_observation(self, raw, name):
        # Every byte is serviced, including after prefix truncation. A fixed
        # 512-byte line prefix suffices for source-owned panic/expect markers;
        # arbitrary trailing Debug/error values are never retained for export.
        line = self.lines[name]
        parts = raw.split(b'\n')
        for index, part in enumerate(parts):
            self.line_overflow[name] |= len(line)+len(part) > 512
            line.extend(part[:max(0, 512-len(line))])
            if (name == 'stderr' and index < len(parts)-1
                    and line.startswith(CONFINEMENT_MARKER)):
                self.confinement_markers += 1
                if self.confinement_markers > 1:
                    self.confinement_status = 'DUPLICATE'
                    self.confinement_detail = None
                else:
                    try:
                        require(not self.line_overflow[name]
                            and line.startswith(CONFINEMENT_MARKER+b' '), 'diagnostic_schema')
                        value = validate_confinement(json_value(bytes(line[len(CONFINEMENT_MARKER)+1:])))
                        self.confinement_detail = value
                        self.confinement_status = 'AVAILABLE'
                        if self.native_code in ('CAUSE_UNKNOWN', 'native_panic'):
                            self.native_code = 'native_confinement'
                        elif self.native_code != 'native_confinement':
                            self.confinement_detail = None
                            self.confinement_status = 'CONFLICTING'
                    except (Refused, ValueError, TypeError, UnicodeError):
                        self.confinement_status = 'MALFORMED'
            if (name == 'stderr' and index < len(parts)-1
                    and line.startswith(CONSTRUCTION_MARKER)):
                self.construction_markers += 1
                if self.construction_markers > 1:
                    self.construction_status = 'DUPLICATE'
                    self.construction_detail = None
                else:
                    try:
                        require(not self.line_overflow[name]
                            and line.startswith(CONSTRUCTION_MARKER+b' '), 'diagnostic_schema')
                        value = validate_construction(json_value(bytes(line[len(CONSTRUCTION_MARKER)+1:])))
                        if self.native_code in ('CAUSE_UNKNOWN', 'native_panic', 'native_admission_client'):
                            self.construction_detail = value
                            self.construction_status = 'AVAILABLE'
                            self.native_code = 'native_admission_client'
                        else:
                            self.construction_status = 'CONFLICTING'
                    except (Refused, ValueError, TypeError, UnicodeError):
                        self.construction_status = 'MALFORMED'
            if (name == 'stdout' and index < len(parts)-1 and line == b'running 0 tests'
                    and self.native_code == 'CAUSE_UNKNOWN'):
                self.native_code = 'native_entrypoint_not_selected'
            if name == 'stderr' and b'panicked at ' in line:
                self.panic_seen = True
                if self.native_code == 'CAUSE_UNKNOWN':
                    self.native_code = 'native_panic'
            if self.panic_seen and self.native_code in ('CAUSE_UNKNOWN', 'native_panic'):
                for message, code in NATIVE_MESSAGES.items():
                    if line.startswith(message+b':') or (index < len(parts)-1 and line == message):
                        self.native_code = code
                        break
            if index < len(parts)-1:
                line.clear()
                self.line_overflow[name] = False

    def snapshot(self):
        with self.lock:
            result = {'native_code': self.native_code, 'capture_error': self.error}
            status, detail = self.confinement_status, self.confinement_detail
            pending = self.lines['stderr']
            if pending and (pending.startswith(CONFINEMENT_MARKER)
                    or CONFINEMENT_MARKER.startswith(pending)):
                status = 'DUPLICATE' if self.confinement_markers else 'INCOMPLETE'
                detail = None
            result.update(confinement_status=status, confinement_detail=detail)
            status, detail = self.construction_status, self.construction_detail
            if pending and (pending.startswith(CONSTRUCTION_MARKER)
                    or CONSTRUCTION_MARKER.startswith(pending)):
                status = 'DUPLICATE' if self.construction_markers else 'INCOMPLETE'
                detail = None
            result.update(construction_status=status, construction_detail=detail)
            for name, item in self.streams.items():
                result.update({name+'_bytes': item['count'],
                    name+'_sha256': item['hash'].hexdigest(),
                    name+'_stored_bytes': len(item['prefix']),
                    name+'_truncated': item['count'] > OUTPUT_LIMIT,
                    name+'_eof': item['eof']})
            return result

    def guardian_diagnostic(self):
        # This is for a trusted guardian producer only. Do not return any raw
        # text to callers; unsupported/partial output is explicitly unavailable.
        with self.lock:
            raw = bytes(self.streams['stderr']['prefix'])
        found = None
        for line in raw.splitlines():
            try:
                value = json_value(line)
                found = validate_diagnostic(value)
            except (Refused, ValueError, UnicodeError):
                if b'osmap-http-web-guardian-failure-' in line:
                    raise Refused('diagnostic_schema')
                continue
        return found

    def finish(self, deadline):
        left = max(0, min(deadline, END)-time.monotonic())
        self.worker.join(timeout=left)
        if self.worker.is_alive():
            with self.lock:
                if self.error is None:
                    self.error = 'capture_deadline'
            self.stop.set()
            # Never extend the original bound to wait for the collector.
            self.worker.join(timeout=max(0, min(.1, min(deadline, END)-time.monotonic())))
        result = self.snapshot()
        if self.worker.is_alive():
            result['capture_error'] = 'capture_deadline'
        return result


def validate_capture(capture):
    try:
        return _validate_capture(capture)
    except (KeyError, TypeError, ValueError):
        raise Refused('diagnostic_schema') from None


def _validate_capture(capture):
    if capture is not None:
        fields = {'native_code', 'capture_error'} | {name+'_'+field
            for name in ('stdout','stderr') for field in
            ('bytes','sha256','stored_bytes','truncated','eof')}
        require(type(capture) is dict and set(capture) in
            (fields, fields | {'confinement_status', 'confinement_detail'},
             fields | {'confinement_status', 'confinement_detail', 'construction_status', 'construction_detail'}),
            'diagnostic_schema')
        if 'confinement_status' in capture:
            require(capture['confinement_status'] in ('NOT_EMITTED', 'AVAILABLE',
                'MALFORMED', 'DUPLICATE', 'INCOMPLETE', 'CONFLICTING'), 'diagnostic_schema')
            require((capture['confinement_detail'] is not None) ==
                (capture['confinement_status'] == 'AVAILABLE'), 'diagnostic_schema')
            if capture['confinement_detail'] is not None:
                validate_confinement(capture['confinement_detail'])
                require(capture['native_code'] == 'native_confinement', 'diagnostic_schema')
            require(capture['confinement_status'] == 'NOT_EMITTED'
                or capture['stderr_bytes'] > 0, 'diagnostic_schema')
        if 'construction_status' in capture:
            require(capture['construction_status'] in ('NOT_EMITTED', 'AVAILABLE',
                'MALFORMED', 'DUPLICATE', 'INCOMPLETE', 'CONFLICTING'), 'diagnostic_schema')
            require((capture['construction_detail'] is not None) ==
                (capture['construction_status'] == 'AVAILABLE'), 'diagnostic_schema')
            if capture['construction_detail'] is not None:
                validate_construction(capture['construction_detail'])
                require(capture['native_code'] == 'native_admission_client', 'diagnostic_schema')
            require(capture['construction_status'] == 'NOT_EMITTED'
                or capture['stderr_bytes'] > 0, 'diagnostic_schema')
        require(capture['native_code'] in NATIVE_CODES and capture['capture_error'] in
                (None, 'capture_io', 'capture_deadline'), 'diagnostic_schema')
        for name in ('stdout', 'stderr'):
            require(type(capture[name+'_bytes']) is int and 0 <= capture[name+'_bytes'] < 2**63
                and type(capture[name+'_stored_bytes']) is int
                and capture[name+'_stored_bytes'] == min(capture[name+'_bytes'], OUTPUT_LIMIT)
                and type(capture[name+'_truncated']) is bool
                and capture[name+'_truncated'] == (capture[name+'_bytes'] > OUTPUT_LIMIT)
                and type(capture[name+'_eof']) is bool
                and type(capture[name+'_sha256']) is str
                and re.fullmatch('[a-f0-9]{64}', capture[name+'_sha256']), 'diagnostic_schema')
    return capture


def validate_diagnostic(value):
    try:
        return _validate_diagnostic(value)
    except (KeyError, TypeError, ValueError):
        raise Refused('diagnostic_schema') from None


def _validate_diagnostic(value):
    require(type(value) is dict and set(value) == {
        'schema', 'code', 'component', 'stage', 'operation', 'cause', 'web_terminal',
        'web_reaped', 'control_status', 'capture', 'cleanup', 'source'}, 'diagnostic_schema')
    require(value['schema'] == 'osmap-http-web-guardian-failure-v2'
        and value['code'] in FAILURE_CODES
        and value['component'] in ('guardian', 'native_http_child')
        and value['stage'] in STAGES and value['operation'] in OPERATIONS
        and value['cause'] in NATIVE_CODES
        and value['control_status'] in ('unavailable', 'open', 'eof', 'interrupted')
        and (value['web_terminal'] is None or type(value['web_terminal']) is int
             and -255 <= value['web_terminal'] <= 255)
        and type(value['web_reaped']) is bool
        and value['web_reaped'] == (value['web_terminal'] is not None), 'diagnostic_schema')
    validate_capture(value['capture'])
    capture = value['capture']
    require((capture is None and value['cause'] == 'CAUSE_UNKNOWN')
        or capture is not None and value['cause'] == capture['native_code']
        and (value['cause'] == 'CAUSE_UNKNOWN'
             or value['cause'] == 'native_entrypoint_not_selected' and capture['stdout_bytes'] > 0
             or value['cause'] != 'native_entrypoint_not_selected' and capture['stderr_bytes'] > 0),
        'diagnostic_schema')
    cleanup = value['cleanup']
    require(type(cleanup) is dict and set(cleanup) == {'status','code','kill_sent'}
        and cleanup['status'] in ('NOT_STARTED','PASS','UNKNOWN')
        and (cleanup['code'] is None or cleanup['code'] in FAILURE_CODES)
        and type(cleanup['kill_sent']) is bool, 'diagnostic_schema')
    source = value['source']
    require(type(source) is dict and set(source) == {'guardian_sha256','binary_sha256',
            'source_manifest_sha256'} and all(v is None or type(v) is str
            and re.fullmatch('[a-f0-9]{64}', v) for v in source.values()), 'diagnostic_schema')
    return value


class DiagnosticFile:
    """One root-owned stage artifact, held across pre-stop/final observations."""
    def __init__(self):
        self.fd = None
        self.path = None
        self.writes = 0

    def write(self, report):
        validate_diagnostic(report)
        raw = json.dumps(report, sort_keys=True, separators=(',', ':')).encode('ascii')+b'\n'
        require(len(raw) <= 8192, 'diagnostic_write')
        # Never rewrite the sole pre-stop evidence. A failed final write must
        # leave the verified first observation readable and unchanged.
        require(self.writes < 2, 'diagnostic_write')
        if self.fd is not None:
            os.close(self.fd)
            self.fd = None
        self.path = STAGE / ('native-http-diagnostic-before-stop.json' if self.writes == 0
                             else 'native-http-diagnostic.json')
        self.writes += 1
        self.fd = os.open(self.path, os.O_RDWR | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW, 0o600)
        info = os.fstat(self.fd)
        require(stat.S_ISREG(info.st_mode) and info.st_nlink == 1
            and info.st_uid == os.geteuid() and stat.S_IMODE(info.st_mode) == 0o600
            and identity(self.path.lstat()) == identity(info), 'diagnostic_integrity')
        os.lseek(self.fd, 0, os.SEEK_SET)
        offset = 0
        while offset < len(raw):
            n = os.write(self.fd, raw[offset:])
            require(n > 0, 'diagnostic_write')
            offset += n
        os.ftruncate(self.fd, len(raw))
        os.fsync(self.fd)
        os.lseek(self.fd, 0, os.SEEK_SET)
        require(os.read(self.fd, 8193) == raw
            and identity(self.path.lstat()) == identity(os.fstat(self.fd)), 'diagnostic_integrity')
        directory = os.open(STAGE, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW)
        try:
            os.fsync(directory)
        finally:
            os.close(directory)
        return hashlib.sha256(raw).hexdigest()

    def close(self):
        if self.fd is not None:
            os.close(self.fd)
            self.fd = None


def drain(child, deadline):
    capture = getattr(child, '_osmap_capture', None)
    if capture is None:
        capture = Capture(child)
        child._osmap_capture = capture
    return capture.finish(deadline)


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



def guardian_identity():
    require(sys.platform.startswith('openbsd') and socket.gethostname() == 'obsd1.blackbagsecurity.com'
            and os.getuid() == os.geteuid() == 0
            and os.getpid() == os.getpgrp() == os.getsid(0)
            and not signal.pthread_sigmask(signal.SIG_BLOCK, set()).intersection(STOPS), 'root_born_guardian')


def main():
    child = None
    peer = None
    parent = None
    proof_read = None
    proof_write = None
    web_end = None
    code_lease = None
    capture = None
    collector = None
    build = None
    stage = 'initializing'
    stage_custody = False
    operation = 'initialize'
    evidence = DiagnosticFile()
    try:
        for number in STOPS:
            signal.signal(number, cancel)
        guardian_identity()
        resource.setrlimit(resource.RLIMIT_CORE, (0, 0))
        os.umask(0o077)
        require(STAGE.parent == Path('/tmp') and re.fullmatch('osmap-pxp-stage-[a-f0-9]{16}', STAGE.name), 'root_stage_name')
        exact_directory(STAGE, 0, 0, 0o700)
        stage_custody = True
        value = os.environ.get('OSMAP_TEST_HTTP_GUARDIAN_FD', '')
        require(re.fullmatch('[0-9]{1,4}', value) and 3 <= int(value) <= 1024, 'root_control_fd')
        parent = Control(socket.socket(fileno=int(value)))
        stage = 'initialized'
        operation = 'namespace'
        http = namespace(parent.read(2048, SETUP))
        original_http = exact_directory(http, 0, GID, 0o750)
        role()
        stage = 'namespace_validated'
        operation = 'build'
        build = build_record()
        code_lease = copy_binary(http, build)
        code, binary, directory_lease, binary_lease = code_lease
        stage = 'binary_verified'
        root_end, web_end = socket.socketpair()
        peer = Control(root_end)
        proof_read, proof_write = os.pipe2(os.O_CLOEXEC)
        guardian = os.getpid()
        group = os.getpgrp()
        operation = 'launch'
        child = launch(binary, web_end.fileno(), proof_write, guardian, group)
        stage = 'child_born'
        operation = 'capture'
        collector = Capture(child)
        child._osmap_capture = collector
        web_end.close()
        web_end = None
        os.close(proof_write)
        proof_write = None
        operation = 'identity'
        drop_receipt(proof_read, child, group)
        stage = 'identity_confirmed'
        os.close(proof_read)
        proof_read = None
        require(identity(http.lstat())[:5] == original_http[:5], 'HTTP_namespace_changed')
        custody = {'schema': 'osmap-http-web-custody-v1', 'web_uid': UID, 'web_gid': GID,
                   'binary_sha256': build['binary_sha256'], 'selector': SELECTOR,
                   'web_pid': child.pid, 'guardian_pid': guardian, 'guardian_group': group}
        operation = 'custody'
        parent.write(json.dumps(custody, separators=(',', ':')).encode('ascii'), SETUP)
        stage = 'custody_sent'
        operation = 'bootstrap'
        raw = parent.read(2048, SETUP)
        boot = json_value(raw)
        require(type(boot) is dict and set(boot) == {'version', 'root'}
                and type(boot['version']) is int and boot['version'] == 1
                and boot['root'] == str(http / 'http-state'), 'fixed_rust_bootstrap')
        peer.write(raw, SETUP)
        stage = 'bootstrap_sent'
        operation = 'ready_read'
        raw = peer.read(1024, SETUP)
        operation = 'ready_validate'
        ready = json_value(raw)
        require(type(ready) is dict and set(ready) == {'schema', 'port', 'connections', 'totp_counter'}
                and ready['schema'] == 'osmap-http-password-ready-v1'
                and type(ready['port']) is int and 1 <= ready['port'] <= 65535
                and type(ready['connections']) is int and ready['connections'] == 18
                and type(ready['totp_counter']) is int and ready['totp_counter'] >= 0, 'rust_ready')
        stage = 'ready_validated'
        operation = 'ready_send'
        parent.write(raw, SETUP)
        stage = 'ready_sent'
        operation = 'start_read'
        raw = parent.read(1, SETUP)
        require(raw == b'G', 'fixed_start')
        sequence = min(END - 10, time.monotonic() + JOURNEY_SECONDS)
        operation = 'start_send'
        peer.write(raw, sequence)
        stage = 'start_sent'
        operation = 'report'
        raw = peer.read(1024, sequence)
        rust_report(raw)
        parent.write(raw, sequence)
        stage = 'report_received'
        operation = 'reap'
        child.wait(timeout=remaining(sequence))
        stage = 'child_reaped'
        operation = 'capture'
        capture = drain(child, sequence)
        require(child.returncode == 0 and capture['stderr_bytes'] == 0, 'web_terminal')
        # Custody-only acknowledgment from the trusted root driver, which owns
        # the actual fresh external group inventory. It grants no seal, login
        # or mutation authority. Guardian performs no transient same-group ps.
        operation = 'group_observation'
        parent.write(b'WEB_DIRECT_REAPED', sequence)
        require(parent.read(64, sequence) == b'GROUP_ONLY_GUARDIAN', 'driver_group_observation')
        stage = 'group_confirmed'
        operation = 'remove_code'
        remove_code(*code_lease)
        stage = 'code_removed'
        code_lease = None
        parent.write(b'WEB_REAPED_GROUP_GONE', sequence)
        return 0
    except BaseException as error:
        # Freeze the original failing boundary before any cleanup. A later
        # kill/wait/file failure cannot overwrite this code or stage.
        code = failure_code(error)
        cleanup = {'status': 'NOT_STARTED', 'code': None, 'kill_sent': False}
        source = {'guardian_sha256': None, 'binary_sha256': None,
                  'source_manifest_sha256': None}
        try:
            source['guardian_sha256'] = hashlib.sha256(Path(__file__).read_bytes()).hexdigest()
        except OSError:
            pass
        if build is not None:
            source.update({key: build[key] for key in ('binary_sha256','source_manifest_sha256')})
        report = {'schema': 'osmap-http-web-guardian-failure-v2', 'code': code,
            'component': 'guardian', 'stage': stage, 'operation': operation,
            'cause': 'CAUSE_UNKNOWN', 'web_terminal': None, 'web_reaped': False,
            'control_status': ('eof' if code == 'control_eof' else
                'interrupted' if code in ('cancelled','exception_interrupted') else
                'unavailable' if parent is None else 'open'),
            'capture': None, 'cleanup': cleanup, 'source': source}

        def observe():
            if collector is not None:
                report['capture'] = collector.snapshot()
                report['cause'] = report['capture']['native_code']
                if report['cause'] != 'CAUSE_UNKNOWN' or (code == 'control_eof'
                    and operation in ('ready_read', 'report', 'start_send')):
                    report['component'] = 'native_http_child'
            if child is not None:
                report['web_terminal'] = child.returncode
                report['web_reaped'] = child.returncode is not None

        observe()
        preserved = False
        try:
            # Verified pre-stop custody precedes killing the direct child.
            require(stage_custody, 'diagnostic_integrity')
            evidence.write(report)
            preserved = True
        except Exception as preserve_error:
            cleanup.update(status='UNKNOWN', code=failure_code(preserve_error))
        if child is not None and preserved:
            try:
                if child.returncode is None:
                    # A bounded wait records an already-exited child's original
                    # status. wait timeout leaves the exact handle unreaped.
                    try:
                        child.wait(timeout=min(.01, remaining(END, cleanup=True)))
                    except subprocess.TimeoutExpired:
                        child.kill()
                        cleanup['kill_sent'] = True
                        child.wait(timeout=remaining(END, cleanup=True))
                if collector is not None:
                    capture = collector.finish(END)
                if cleanup['code'] is None:
                    cleanup['status'] = 'PASS'
            except BaseException as cleanup_error:
                cleanup.update(status='UNKNOWN', code=failure_code(cleanup_error))
        elif cleanup['code'] is None:
            cleanup['status'] = 'PASS'
        observe()
        if capture is not None:
            report['capture'] = capture
        try:
            require(stage_custody, 'diagnostic_integrity')
            evidence.write(report)
        except Exception as preserve_error:
            cleanup.update(status='UNKNOWN', code=failure_code(preserve_error))
        # Stdout/stderr carry only the closed schema, never raw native text or
        # exception strings. Parent retains this before exact stage removal.
        sys.stderr.write(json.dumps(validate_diagnostic(report), separators=(',', ':'))+'\n')
        sys.stderr.flush()
        return 1
    finally:
        evidence.close()
        for fd in (proof_read, proof_write):
            if fd is not None:
                try:
                    os.close(fd)
                except OSError:
                    pass
        if peer is not None:
            peer.stream.close()
        if web_end is not None:
            web_end.close()
        if parent is not None:
            parent.stream.close()
        # Failed code namespaces and the diagnostic remain retained. The outer
        # trusted driver owns the held group and exact cleanup authorization.


if __name__ == '__main__':
    raise SystemExit(main())
