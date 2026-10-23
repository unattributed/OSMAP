"""Fixed root SQL/hash component fixture. Never import this as provisioning.

Root must bind BINARY_SHA256 to its reviewed current native test build before
freezing/executing this packet. No caller path, password or binary override.
All subprocess input/output containing private material remains in RAM.
"""
from datetime import datetime
import grp
import hashlib
import json
import os
from pathlib import Path
import pwd
import re
import resource
import secrets
import selectors
import signal
import socket
import stat
import subprocess
import sys
import time
import importlib.util

_schema_path = Path(__file__).resolve().parent / 'stock_schema.py'
_schema_spec = importlib.util.spec_from_file_location('osmap_custody_stock_schema', _schema_path)
_schema = importlib.util.module_from_spec(_schema_spec)
_schema_spec.loader.exec_module(_schema)
StockSchemaRefused = _schema.StockSchemaRefused
stock_fresh_reserved_schema = _schema.stock_fresh_reserved_schema

BINARY_SHA256 = 'e473ab9459042072dfc6badcb4c55f40a10ab1491e397834dbffb7598c521a54'  # REQUIRED: exact current reviewed OpenBSD test build.
TEST_SOURCE_SHA256 = 'f12c314d73328a27670ffa69d29476120d735a9eef77fb743ae7f6f09139f3df'
NATIVE_ERRORS = ('Alice persisted disposition unavailable', 'Alice persisted state unavailable', 'Alice write readback unavailable', 'Bob epoch changed or blocked', 'Bob persisted disposition unavailable', 'Bob preservation readback unavailable', 'actual parent seal refused', 'authoritative performed-write timestamp absent', 'core limit refused', 'durable containment publication refused', 'durable pending refused', 'fixed SQL role/configuration unavailable', 'fixed epoch store unavailable', 'fixed fixture receipt invalid', 'fixed fixture receipt unavailable', 'fixed hash role/configuration unavailable', 'fixed native root authority required', 'fixed parent plan unavailable', 'fixed working directory refused', 'fixture MAC refused', 'fixture account lock unavailable', 'fixture account no longer active', 'fixture action encoding refused', 'fixture clock overflow', 'fixture epoch lock refused', 'fixture lease expired before durable pending', 'fixture receipt authority, freshness or creation lease refused', 'fixture receipt metadata unavailable', 'fixture receipt overflow', 'fixture receipt ownership or mode refused', 'fixture receipt read refused', 'initial Alice SQL read refused', 'initial Bob SQL read refused', 'native clock overflow', 'native clock unavailable', 'native hash or conditional write settled refused', 'native random source unavailable', 'native write uncertain; no retry or credential restoration', 'native write/readback or Bob preservation mismatch', 'original component operation deadline expired', 'parent custody activation refused', 'persisted epoch/containment invariant failed', 'settled no-write state publication refused', 'typed fixture action refused', 'unexpected fixture epoch state', 'unexpected fixture prior write time', 'unexpected synthetic mailbox row; no credential write', 'verified timestamp publication refused')
TEST = 'account_password_backend::tests::native_parent_sealed_sql_hash_cas_preserves_bob_and_contains_alice'
ACCOUNTS = ('alice@osmap-password.invalid', 'bob@osmap-password.invalid')
NAMES = ('_osmapsql', '_osmaphash')
PRINCIPAL = "'osmap_account_mutation'@'localhost'"
SQL = ('/usr/local/bin/mariadb', '--no-defaults', '--protocol=socket',
       '--socket=/var/run/mysql/mysql.sock', '--user=root', '--batch',
       '--skip-column-names', '--raw')
HASH = ('/usr/local/bin/doveadm', '-O', 'pw', '-s', 'ARGON2ID')
ARGON = re.compile(r'\{ARGON2ID\}\$argon2id\$v=19\$m=65536,t=3,p=1\$[A-Za-z0-9+/]{22}\$[A-Za-z0-9+/]{43}')
STOPS = {signal.SIGALRM, signal.SIGHUP, signal.SIGTERM, signal.SIGINT}
EPOCH = Path('/var/db/osmap-account/epoch')
CONFIG = Path('/etc/osmap/account-mariadb.cnf')
PLAN = Path('/etc/osmap/account-runtime/sql-endpoint.json')
CONTEXT = Path('/etc/osmap/account-runtime/sql-native-fixture.json')
COLUMNS = ('username', 'password', 'name', 'maildir', 'quota', 'local_part',
           'domain', 'created', 'modified', 'active', 'phone', 'email_other',
           'token', 'token_validity', 'password_expiry', 'totp_secret', 'smtp_active')
GRANTS = {('username', 'SELECT'), ('password', 'SELECT'), ('modified', 'SELECT'),
          ('active', 'SELECT'), ('smtp_active', 'SELECT'), ('password', 'UPDATE'),
          ('modified', 'UPDATE')}


DIAGNOSTIC_FIELDS = ('stage', 'errno', 'status', 'stdout_len', 'stderr_len', 'sql_code', 'parser')


def valid_read_diagnostic(value):
    if not isinstance(value, dict) or set(value) != set(DIAGNOSTIC_FIELDS):
        return False
    if not all(type(value[key]) is int for key in DIAGNOSTIC_FIELDS):
        return False
    return (0 <= value['stage'] <= 9
            and (value['errno'] == -1 or 0 <= value['errno'] <= 65535)
            and -255 <= value['status'] <= 255
            and (value['stdout_len'] == -1 or 0 <= value['stdout_len'] <= 65536)
            and (value['stderr_len'] == -1 or 0 <= value['stderr_len'] <= 65536)
            and (value['sql_code'] == 0 or 1000 <= value['sql_code'] <= 9999)
            and 0 <= value['parser'] <= 11)


def parse_read_diagnostic(output):
    # Detect any occurrence so malformed, prefixed, duplicate or appended text
    # cannot be silently ignored while another line is accepted. Physical LF
    # framing is exact; the ignored Rust println starts with an explicit LF.
    if not isinstance(output, bytes):
        return 'UNKNOWN'
    physical = output.split(b'\n')
    if b'native_sql_read_diagnostic' in physical[-1]:
        return 'UNKNOWN'
    lines = [line for line in physical[:-1] if b'native_sql_read_diagnostic' in line]
    if len(lines) != 1:
        return 'UNKNOWN'
    scalar = rb'(0|-?[1-9][0-9]{0,4})'
    pattern = rb'native_sql_read_diagnostic ' + b' '.join(
        key.encode('ascii') + b'=' + scalar for key in DIAGNOSTIC_FIELDS)
    match = re.fullmatch(pattern, lines[0])
    if match is None:
        return 'UNKNOWN'
    value = dict(zip(DIAGNOSTIC_FIELDS, (int(part) for part in match.groups())))
    return value if valid_read_diagnostic(value) else 'UNKNOWN'


class Refused(RuntimeError):
    def __init__(self, code):
        self.code = code
        super().__init__('fixed SQL/hash fixture refused')


def require(value, code):
    if not value:
        raise Refused(code)


def identity(m):
    return (m.st_dev, m.st_ino, m.st_uid, m.st_gid, m.st_mode, m.st_nlink)


def file_identity(m):
    return identity(m) + (m.st_size, m.st_mtime_ns, m.st_ctime_ns)


def valid_stamp(value):
    if not isinstance(value, str) or re.fullmatch('[0-9]{14}', value) is None:
        return False
    try:
        datetime.strptime(value, '%Y%m%d%H%M%S')
        return True
    except ValueError:
        return False


def hexsql(value):
    require(isinstance(value, str) and 0 < len(value) <= 2048, 'fixed_SQL_value_shape')
    return 'CONVERT(0x' + value.encode('utf8').hex() + ' USING utf8mb4)'


def unique(pairs):
    result = {}
    for key, value in pairs:
        require(key not in result, 'duplicate_JSON_key')
        result[key] = value
    return result


class Fixture:
    def __init__(self):
        self.began = time.monotonic()
        self.end = self.began + 150
        self.stage = Path(__file__).resolve().parent
        self.binary = self.stage / 'osmap-tests'
        self.children = []
        self.files = {}
        self.dirs = {}
        self.users = {}
        self.groups = {}
        self.db_user = False
        self.db_user_lease = None
        self.db_grants_lease = None
        self.rows = False
        self.sql_uncertain = False
        self.identity_uncertain = False
        self.creation_uncertain = False
        self.process_uncertain = False
        self.baseline = None
        self.lease = secrets.token_hex(32)
        self.intent = hashlib.sha256(b'osmap native SQL/hash component fixture v1\0' + self.lease.encode('ascii')).hexdigest()
        self.phase = 'initial'
        self.report = {'result': 'FAIL', 'component_result': 'NOT_RUN', 'phase': self.phase, 'component_only': True,
                       'full_workflow_qualified': False, 'provider_traffic': False,
                       'operator_account_mutation': False, 'credential_retry': False,
                       'test_source_sha256': TEST_SOURCE_SHA256, 'groups': [],
                       'cleanup': {'rows_removed': 0, 'database_users_removed': 0,
                                   'users_removed': 0, 'groups_removed': 0,
                                   'files_removed': 0, 'directories_removed': 0}}

    def remaining(self, cleanup=False):
        left = self.end - time.monotonic() - (0 if cleanup else 35)
        require(left > 0, 'original_fixture_deadline')
        return left

    def private_read(self, path, cap, mode=0o600):
        self.remaining(True)
        before = path.lstat()
        require(stat.S_ISREG(before.st_mode) and before.st_uid == 0
                and before.st_nlink == 1 and stat.S_IMODE(before.st_mode) == mode
                and before.st_size <= cap, 'private_file_metadata')
        fd = os.open(path, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK | os.O_CLOEXEC)
        try:
            require(file_identity(os.fstat(fd)) == file_identity(before), 'private_file_open_continuity')
            raw = bytearray()
            while len(raw) <= cap:
                self.remaining(True)
                part = os.read(fd, min(65536, cap + 1 - len(raw)))
                if not part:
                    break
                raw.extend(part)
            require(len(raw) == before.st_size and len(raw) <= cap
                    and file_identity(os.fstat(fd)) == file_identity(before)
                    and file_identity(path.lstat()) == file_identity(before), 'private_file_read_continuity')
            return bytes(raw)
        finally:
            os.close(fd)

    def directory(self, path, mode):
        try:
            m = path.lstat()
        except FileNotFoundError:
            require(path.parent.is_dir() and path.parent.resolve() == path.parent,
                    'directory_parent_canonical')
            parent = path.parent.lstat()
            require(parent.st_uid == 0 and not parent.st_mode & 0o022,
                    'directory_parent_protected')
            self.creation_uncertain = True
            path.mkdir(mode=mode)
            self.dirs[path] = identity(path.lstat())
            self.creation_uncertain = False
            m = path.lstat()
        require(stat.S_ISDIR(m.st_mode) and m.st_uid == m.st_gid == 0
                and stat.S_IMODE(m.st_mode) == mode and path.resolve() == path,
                'fixed_directory_metadata')

    def publish(self, path, raw, mode=0o600, gid=0):
        self.remaining()
        require(isinstance(raw, bytes) and len(raw) <= 4096, 'private_publication_bound')
        self.creation_uncertain = True
        fd = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW | os.O_CLOEXEC, mode)
        try:
            # Capture successful O_EXCL birth before any fallible owner, mode,
            # write or fsync operation; unknown birth never means clean absence.
            self.files[path] = file_identity(os.fstat(fd))
            self.creation_uncertain = False
            os.fchown(fd, 0, gid)
            os.fchmod(fd, mode)
            self.files[path] = file_identity(os.fstat(fd))
            offset = 0
            while offset < len(raw):
                self.remaining()
                offset += os.write(fd, raw[offset:])
            os.fsync(fd)
            self.files[path] = file_identity(os.fstat(fd))
        finally:
            try:
                self.files[path] = file_identity(os.fstat(fd))
            except BaseException:
                self.creation_uncertain = True
                raise
            finally:
                os.close(fd)

    def test_descendants_absent(self, deadline):
        # Success-only fixed SQL/Hash proof, never session reconstruction.
        # Their exact production runner confirms each owned utility group before
        # returning success. Fresh dedicated UIDs and exact text inode provide
        # independent bounded observation without historical PID/SID authority.
        require(time.monotonic() < deadline, 'original_test_cleanup_deadline')
        raw = self.run(('/bin/ps', '-ax', '-o', 'uid='), 'component_role_inventory',
                       cleanup=True, absolute=deadline)
        rows = raw.splitlines()
        require(0 < len(rows) <= 4096 and all(re.fullmatch(rb'\s*[0-9]{1,10}\s*', r) for r in rows),
                'bounded_role_inventory')
        role_uids = {self.users[name][0] for name in NAMES}
        require(len(role_uids) == 2 and 0 not in role_uids
                and not any(int(r) in role_uids for r in rows), 'component_role_process_remains')
        raw = self.run(('/usr/bin/fstat', '-n', str(self.binary)), 'component_text_references',
                       cleanup=True, absolute=deadline)
        rows = raw.splitlines()
        require(len(rows) == 1 and b'USER' in rows[0] and b'PID' in rows[0] and b'FD' in rows[0],
                'component_text_reference_remains')
        require(file_identity(self.binary.lstat()) == self.binary_identity
                and time.monotonic() < deadline, 'component_text_identity_or_deadline')
        return True

    def run(self, argv, label, data=b'', cap=16384, seconds=5, cleanup=False, test=False, absolute=None):
        require(isinstance(data, bytes) and len(data) <= 32768, 'bounded_private_stdin')
        deadline = time.monotonic() + min(seconds, self.remaining(cleanup))
        if absolute is not None:
            deadline = min(deadline, absolute)
        io_end = deadline - (3 if test else 1)
        require(time.monotonic() < io_end, 'phase_expired_before_spawn')
        child = None
        failure = None
        output = [bytearray(), bytearray()]
        offset = 0
        previous = signal.pthread_sigmask(signal.SIG_BLOCK, STOPS)
        try:
            try:
                require(time.monotonic() < io_end, 'phase_expired_before_spawn')
                child = subprocess.Popen(argv, cwd='/', stdin=subprocess.PIPE,
                    stdout=subprocess.PIPE, stderr=subprocess.PIPE, start_new_session=True,
                    close_fds=True, env={'PATH': '/usr/local/bin:/usr/bin:/bin:/usr/sbin:/sbin',
                        'HOME': '/root', 'LC_ALL': 'C', 'CONFIG_FILE': '/dev/null',
                        'STATS_WRITER_SOCKET_PATH': ''},
                    preexec_fn=lambda: signal.pthread_sigmask(signal.SIG_SETMASK, previous))
                self.children.append(child)
            finally:
                signal.pthread_sigmask(signal.SIG_SETMASK, previous)
            with selectors.DefaultSelector() as selector:
                for pipe, event, kind in ((child.stdin, selectors.EVENT_WRITE, -1),
                        (child.stdout, selectors.EVENT_READ, 0), (child.stderr, selectors.EVENT_READ, 1)):
                    os.set_blocking(pipe.fileno(), False)
                    selector.register(pipe, event, kind)
                while time.monotonic() < io_end:
                    for key, _ in selector.select(min(.02, max(0, io_end - time.monotonic()))):
                        try:
                            if key.data == -1:
                                if offset < len(data):
                                    offset += os.write(key.fd, data[offset:offset + 4096])
                                if offset == len(data):
                                    selector.unregister(key.fileobj)
                                    key.fileobj.close()
                            else:
                                part = os.read(key.fd, 4096)
                                if not part:
                                    selector.unregister(key.fileobj)
                                output[key.data].extend(part)
                                require(len(output[key.data]) <= cap, 'phase_output_cap')
                        except BlockingIOError:
                            continue
                    if not selector.get_map():
                        observed = os.waitid(os.P_PID, child.pid, os.WEXITED | os.WNOHANG | os.WNOWAIT)
                        if observed is not None and observed.si_pid == child.pid:
                            break
                else:
                    raise Refused('phase_original_deadline')
        except BaseException as error:
            failure = error.code if isinstance(error, Refused) else type(error).__name__
        finally:
            if child is not None:
                mask = signal.pthread_sigmask(signal.SIG_BLOCK, STOPS)
                prior_uncertain = self.process_uncertain
                signal_ok = reaped = gone = component_absence = False
                confirmed = False
                try:
                    # Child was never polled/reaped; its born group is leased.
                    self.process_uncertain = True
                    try:
                        os.killpg(child.pid, signal.SIGKILL)
                        signal_ok = True
                    except ProcessLookupError:
                        signal_ok = True
                    # Always reap the exact born direct child before optional
                    # observations; a foreign getsid query is never valid here.
                    child.wait(timeout=max(.001, min(deadline, self.end) - time.monotonic()))
                    reaped = True
                    try:
                        os.killpg(child.pid, 0)
                    except ProcessLookupError:
                        gone = True
                    if test:
                        expected = (b'native_sql_hash_component phase="native SQL readback" result=PASS alice_state=Contained epoch=0 '
                            b'performed_write_time_known=true bob_epoch_preserved=true credential_retry=false full_workflow_qualified=false')
                        normal_success = (failure is None and child.returncode == 0
                            and bytes(output[0]).count(b'native_sql_hash_component ') == 1
                            and any(line.endswith(expected) for line in bytes(output[0]).splitlines()))
                        # Failed/timeout workflows preserve all namespaces for
                        # exact reconciliation, never retry the credential CAS.
                        if signal_ok and gone and normal_success:
                            component_absence = self.test_descendants_absent(deadline)
                    else:
                        component_absence = True
                    confirmed = signal_ok and reaped and gone and component_absence and time.monotonic() < deadline
                    self.process_uncertain = prior_uncertain or not confirmed
                except BaseException:
                    self.process_uncertain = True
                finally:
                    self.report['groups'].append({'operation': label, 'pid': child.pid,
                        'reaped': reaped, 'group_gone': gone,
                        'component_absence_confirmed': component_absence,
                        'session_reconstruction_claimed': False,
                        'failure': failure, 'code': child.returncode,
                        'stdout_bytes': len(output[0]), 'stderr_bytes': len(output[1]),
                        'sql_error_code': (int(match[1]) if (match := re.match(rb'ERROR ([0-9]{4}) \([A-Z0-9]{5}\)', output[1])) else None)})
                    for pipe in (child.stdin, child.stdout, child.stderr):
                        if pipe is not None and not pipe.closed:
                            pipe.close()
                    signal.pthread_sigmask(signal.SIG_SETMASK, mask)
        if test:
            # Only static error strings from the exact compiled test may be
            # exported; private stdout/stderr bytes are never retained.
            matches = ['G%02d' % index for index, value in enumerate(NATIVE_ERRORS)
                       if ('Error: "' + value + '"').encode('ascii') in bytes(output[1])]
            self.report['native_test_guard'] = matches[0] if len(matches) == 1 else 'UNKNOWN'
            self.report['sql_read_diagnostic'] = parse_read_diagnostic(bytes(output[0]))
        require(not failure and child is not None and child.returncode == 0
                and confirmed and not output[1], 'fixed_child_refused')
        return bytes(output[0])

    def sql(self, query, *, mutation=False, cleanup=False):
        # Session-local only; no global audit/binlog policy change. If either
        # permission is unavailable, no credential statement follows it.
        prefix = 'SET SESSION sql_log_off=1; SET SESSION sql_log_bin=0;\n'
        try:
            return self.run(SQL, 'root_sql_cleanup' if cleanup else 'root_sql',
                            (prefix + query).encode('ascii'), cleanup=cleanup)
        except BaseException:
            if mutation:
                self.sql_uncertain = True
            raise

    def row_read(self, cleanup=False):
        expression = 'JSON_OBJECT(' + ','.join("'" + k + "',`" + k + '`' for k in COLUMNS) + ')'
        raw = self.sql('SELECT ' + expression + ' FROM postfixadmin.mailbox WHERE BINARY username IN ('
                       + ','.join(hexsql(a) for a in ACCOUNTS) + ') ORDER BY username;\n', cleanup=cleanup)
        rows = [json.loads(line, object_pairs_hook=unique) for line in raw.splitlines()]
        require(len(rows) == 2 and tuple(r.get('username') for r in rows) == ACCOUNTS
                and all(set(r) == set(COLUMNS) for r in rows), 'reserved_row_exact_shape')
        return rows

    def own_principal(self, name):
        try:
            pwd.getpwnam(name)
            raise Refused('principal_collision')
        except KeyError:
            pass
        try:
            grp.getgrnam(name)
            raise Refused('group_collision')
        except KeyError:
            pass
        self.identity_uncertain = True
        self.run(('/usr/sbin/groupadd', name), 'group_create')
        g = grp.getgrnam(name)
        self.groups[name] = (g.gr_gid, tuple(g.gr_mem))
        self.identity_uncertain = False
        self.identity_uncertain = True
        self.run(('/usr/sbin/useradd', '-g', name, '-d', '/var/empty', '-s', '/sbin/nologin', name), 'user_create')
        p = pwd.getpwnam(name)
        require(p.pw_uid > 0 and p.pw_gid == g.gr_gid > 0 and p.pw_dir == '/var/empty'
                and p.pw_shell == '/sbin/nologin' and p.pw_passwd in ('*', '!', '!!')
                and not g.gr_mem, 'locked_purpose_principal')
        self.users[name] = (p.pw_uid, p.pw_gid, p.pw_dir, p.pw_shell)
        require(sum(x.pw_uid == p.pw_uid for x in pwd.getpwall()) == 1
                and sum(x.pw_gid == p.pw_gid for x in pwd.getpwall()) == 1
                and sum(x.gr_gid == p.pw_gid for x in grp.getgrall()) == 1
                and all(name not in x.gr_mem for x in grp.getgrall()), 'purpose_identity_no_alias')
        self.identity_uncertain = False

    def preflight(self):
        self.phase = 'fixed preflight'
        require(os.getuid() == os.geteuid() == 0 and socket.gethostname() == 'mail.blackbagsecurity.com'
                and (os.uname().sysname, os.uname().machine) == ('OpenBSD', 'amd64')
                and sys.byteorder == 'little', 'fixed_native_authority')
        require(isinstance(BINARY_SHA256, str) and re.fullmatch('[0-9a-f]{64}', BINARY_SHA256), 'native_binary_pin_not_bound')
        require(self.stage.parent == Path('/var/run') and re.fullmatch('osmap-sql-hash-root-[0-9a-f]{16}', self.stage.name), 'fixed_root_stage')
        m = self.stage.lstat()
        require(m.st_uid == m.st_gid == 0 and stat.S_IMODE(m.st_mode) == 0o700 and stat.S_ISDIR(m.st_mode), 'root_stage_metadata')
        binary = self.binary.lstat()
        require(stat.S_ISREG(binary.st_mode) and binary.st_uid == 0 and binary.st_nlink == 1
                and stat.S_IMODE(binary.st_mode) == 0o500 and 0 < binary.st_size <= 512 * 1024 * 1024, 'native_binary_metadata')
        digest = hashlib.sha256()
        with self.binary.open('rb') as source:
            require(file_identity(os.fstat(source.fileno())) == file_identity(binary), 'native_binary_at_open')
            while True:
                self.remaining()
                part = source.read(262144)
                if not part:
                    break
                digest.update(part)
            require(file_identity(os.fstat(source.fileno())) == file_identity(binary)
                    and file_identity(self.binary.lstat()) == file_identity(binary), 'native_binary_continuity')
        require(digest.hexdigest() == BINARY_SHA256, 'native_binary_hash')
        self.binary_identity = file_identity(binary)
        self.report['native_binary_sha256'] = BINARY_SHA256
        require(all(not path.exists() and not path.is_symlink() for path in (CONFIG, PLAN, CONTEXT)), 'fixed_file_collision')
        for name in NAMES:
            require(not any(p.pw_name == name for p in pwd.getpwall())
                    and not any(g.gr_name == name for g in grp.getgrall()), 'purpose_name_collision')
        raw = self.sql("SELECT CURRENT_USER(),VERSION(); SELECT COUNT(*) FROM mysql.user WHERE User='osmap_account_mutation'; "
            "SELECT COUNT(*) FROM postfixadmin.mailbox WHERE username IN ('alice@osmap-password.invalid','bob@osmap-password.invalid'); "
            "SELECT ENGINE FROM information_schema.TABLES WHERE TABLE_SCHEMA='postfixadmin' AND TABLE_NAME='mailbox'; "
            "SELECT COUNT(*) FROM information_schema.TRIGGERS WHERE EVENT_OBJECT_SCHEMA='postfixadmin' AND EVENT_OBJECT_TABLE='mailbox'; "
            "SELECT COUNT(*) FROM information_schema.KEY_COLUMN_USAGE WHERE TABLE_SCHEMA='postfixadmin' AND TABLE_NAME='mailbox' AND REFERENCED_TABLE_NAME IS NOT NULL;\n")
        try:
            schema = stock_fresh_reserved_schema(raw)
        except StockSchemaRefused as error:
            raise Refused(error.code) from None
        self.report['stock_schema'] = schema
        self.report['fresh_before_counts'] = {
            'database_user': schema['reserved_database_users'],
            'controlled_rows': schema['controlled_rows'],
        }

    def provision(self):
        self.phase = 'purpose provisioning'
        for name in NAMES:
            self.own_principal(name)
        require(self.users[NAMES[0]][0] != self.users[NAMES[1]][0]
                and self.users[NAMES[0]][1] != self.users[NAMES[1]][1], 'distinct_purpose_identities')
        directories = (('/etc/osmap', 0o755), ('/etc/osmap/account-runtime', 0o700),
            ('/etc/osmap/account-submission', 0o700), ('/var/db/osmap-account', 0o700),
            (str(EPOCH), 0o700), ('/var/run/osmap-account-submission', 0o700),
            ('/var/run/osmap-account-submission/login', 0o700))
        for name, mode in directories:
            self.directory(Path(name), mode)
        for account in ACCOUNTS:
            stem = hashlib.sha256(b'osmap-account-epoch-v1\0' + account.encode('ascii')).hexdigest()
            for suffix in ('.json', '.lock', '.uncertain'):
                p = EPOCH / (stem + suffix)
                require(not p.exists() and not p.is_symlink(), 'reserved_epoch_collision')
            self.publish(EPOCH / (stem + '.lock'), b'')
            self.publish(EPOCH / (stem + '.json'), b'{"epoch":0,"state":"active","changed_at":null,"intent":null,"used_intents":[]}\n')
        role_password = secrets.token_hex(32)
        self.sql('CREATE USER ' + PRINCIPAL + " IDENTIFIED BY '" + role_password + "';\n", mutation=True)
        self.db_user = True
        self.sql('GRANT SELECT(username,password,modified,active,smtp_active),UPDATE(password,modified) ON postfixadmin.mailbox TO ' + PRINCIPAL + ';\n', mutation=True)
        grantee = hexsql(PRINCIPAL)
        grants = self.sql('SELECT COLUMN_NAME,PRIVILEGE_TYPE FROM information_schema.COLUMN_PRIVILEGES WHERE GRANTEE=' + grantee + " AND TABLE_SCHEMA='postfixadmin' AND TABLE_NAME='mailbox';\n")
        require(set(tuple(r.split('\t')) for r in grants.decode('ascii').splitlines()) == GRANTS, 'exact_seven_column_grants')
        broad = self.sql('SELECT COUNT(*) FROM information_schema.USER_PRIVILEGES WHERE GRANTEE=' + grantee + " AND PRIVILEGE_TYPE<>'USAGE'; SELECT COUNT(*) FROM information_schema.SCHEMA_PRIVILEGES WHERE GRANTEE=" + grantee + '; SELECT COUNT(*) FROM information_schema.TABLE_PRIVILEGES WHERE GRANTEE=' + grantee + ';\n')
        require(broad == b'0\n0\n0\n', 'no_broad_database_grants')
        self.db_user_lease = self.sql('SHOW CREATE USER ' + PRINCIPAL + ';\n')
        require(0 < len(self.db_user_lease) <= 4096, 'created_database_user_lease')
        self.db_grants_lease = self.sql('SHOW GRANTS FOR ' + PRINCIPAL + ';\n')
        require(0 < len(self.db_grants_lease) <= 4096, 'created_database_grants_lease')
        self.report['restricted_column_grants'] = 7
        self.publish(CONFIG, ('[client]\nuser=osmap_account_mutation\npassword=' + role_password
            + '\nprotocol=SOCKET\nsocket=/var/run/mysql/mysql.sock\n').encode('ascii'), 0o440, self.users['_osmapsql'][1])
        self.publish(PLAN, json.dumps({'version': 1, 'authority': 'mail.blackbagsecurity.com',
            'purpose': 'osmap-account-mutation', 'server': '_mysql', 'socket': '/var/run/mysql/mysql.sock',
            'database_user': 'osmap_account_mutation'}, sort_keys=True).encode('ascii'))
        hashes = []
        for _ in ACCOUNTS:
            password = secrets.token_hex(32)
            hashed = self.run(HASH, 'initial_private_hash', (password + '\n' + password + '\n').encode('ascii'), seconds=10).decode('ascii').removesuffix('\n')
            require(ARGON.fullmatch(hashed), 'initial_actual_ARGON2ID')
            hashes.append(hashed)
        values = []
        for account, hashed in zip(ACCOUNTS, hashes):
            local = account.split('@')[0]
            values.append('(' + ','.join((hexsql(account), hexsql(hashed), hexsql('osmap fixture ' + self.lease),
                hexsql('osmap-password.invalid/' + local + '-' + self.lease + '/'), '0', hexsql(local),
                hexsql('osmap-password.invalid'), 'UTC_TIMESTAMP()', "'2000-01-01 00:00:00'", '1',
                "''", "''", "''", "'2000-01-01 00:00:00'", "'2099-01-01 00:00:00'", 'NULL', '1')) + ')')
        self.sql('START TRANSACTION; INSERT INTO postfixadmin.mailbox (' + ','.join(COLUMNS)
                 + ') VALUES ' + ','.join(values) + '; COMMIT;\n', mutation=True)
        self.rows = True
        self.baseline = self.row_read()
        require(all(r['password'] == h and r['name'] == 'osmap fixture ' + self.lease
                    and r['active'] == r['smtp_active'] == 1 for r, h in zip(self.baseline, hashes)), 'inserted_exact_owned_rows')
        now = int(time.time())
        self.publish(CONTEXT, json.dumps({'version': 1, 'authority': 'mail.blackbagsecurity.com',
            'purpose': 'osmap-password-native-sql-hash-fixture', 'issued_at': now, 'expires_at': now + 150,
            'lease_nonce': self.lease, 'rows': [{'account': r['username'],
                'initial_hash_sha256': hashlib.sha256(r['password'].encode('ascii')).hexdigest(),
                'modified': r['modified'].replace('-', '').replace(':', '').replace(' ', ''),
                'before_count': 0, 'inserted_count': 1} for r in self.baseline]}, sort_keys=True).encode('ascii'))

    def inspect_state(self, *, after_test):
        current = self.row_read(cleanup=True)
        require(self.baseline is not None and current[1] == self.baseline[1], 'Bob_all_columns_preserved')
        for key in COLUMNS:
            if key not in ('password', 'modified'):
                require(current[0][key] == self.baseline[0][key], 'Alice_noncredential_columns_preserved')
        require(ARGON.fullmatch(current[0]['password']), 'Alice_current_actual_ARGON2ID')
        changed = current[0]['password'] != self.baseline[0]['password']
        modified = current[0]['modified'].replace('-', '').replace(':', '').replace(' ', '')
        require(valid_stamp(modified), 'current_authoritative_stamp_shape')
        time_known = False
        state_files = []
        states = []
        for account in ACCOUNTS:
            stem = hashlib.sha256(b'osmap-account-epoch-v1\0' + account.encode('ascii')).hexdigest()
            path = EPOCH / (stem + '.json')
            record = json.loads(self.private_read(path, 4096), object_pairs_hook=unique)
            require(set(record) == {'epoch', 'state', 'changed_at', 'intent', 'used_intents'}
                    and record['epoch'] == 0 and record['state'] in ('active', 'pending', 'contained'), 'durable_epoch_shape')
            if account == ACCOUNTS[1]:
                require(record == {'epoch': 0, 'state': 'active', 'changed_at': None, 'intent': None, 'used_intents': []}, 'Bob_epoch_preserved')
            else:
                time_known = changed and valid_stamp(record['changed_at']) and record['changed_at'] == modified
                require(record['intent'] in (None, self.intent) and len(record['used_intents']) <= 1
                    and all(isinstance(x, list) and len(x) == 2 and x[0] == self.intent and isinstance(x[1], int)
                            for x in record['used_intents']), 'Alice_own_intent_state')
                if changed:
                    require(record['state'] in ('pending', 'contained') and record['intent'] == self.intent
                            and record['changed_at'] in (None, modified), 'changed_write_durable_refusal')
                if after_test:
                    require(changed and record['state'] == 'contained' and record['changed_at'] == modified,
                            'actual_test_write_contained_timestamp')
            state_files.append((path, file_identity(path.lstat())))
            marker = EPOCH / (stem + '.uncertain')
            if marker.exists() or marker.is_symlink():
                require(account == ACCOUNTS[0] and self.private_read(marker, 256)
                    == ('osmap-password-uncertain-v1\n' + self.intent + '\n').encode('ascii'), 'exact_own_uncertainty_marker')
                state_files.append((marker, file_identity(marker.lstat())))
            states.append(record['state'])
        self.report.update({'actual_write_count': int(changed), 'alice_state': states[0],
            'alice_epoch': 0, 'performed_write_time_known': time_known,
            'Bob_all_columns_preserved': True, 'Bob_epoch_preserved': True})
        return current, state_files

    def cleanup(self):
        # On any unconfirmed SQL/OS mutation or nested process disposition, keep
        # the exact namespace and authorities for root reconciliation, no retry.
        require(not self.sql_uncertain and not self.process_uncertain and not self.identity_uncertain
                and not self.creation_uncertain,
                'cleanup_uncertain_preserve_leases')
        self.phase = 'exact owned cleanup'
        for path, own in self.files.items():
            if path.parent != EPOCH or path.suffix == '.lock':
                require(file_identity(path.lstat()) == own, 'fixed_created_file_cleanup_continuity')
        if self.db_user:
            require(self.db_user_lease is not None and self.sql('SHOW CREATE USER ' + PRINCIPAL + ';\n', cleanup=True)
                    == self.db_user_lease and self.db_grants_lease is not None
                    and self.sql('SHOW GRANTS FOR ' + PRINCIPAL + ';\n', cleanup=True)
                    == self.db_grants_lease, 'created_database_user_cleanup_continuity')
        if self.rows:
            current, state_files = self.inspect_state(after_test=False)
            deletes = []
            for row in current:
                conditions = []
                for key in COLUMNS:
                    value = row[key]
                    if value is None:
                        conditions.append('`' + key + '` IS NULL')
                    elif type(value) is int:
                        conditions.append('`' + key + '`=' + str(value))
                    else:
                        require(isinstance(value, str), 'owned_cleanup_scalar_type')
                        conditions.append('BINARY `' + key + '`=BINARY ' + (hexsql(value) if value else "''"))
                deletes.append('DELETE FROM postfixadmin.mailbox WHERE ' + ' AND '.join(conditions) + '; SELECT ROW_COUNT();')
            out = self.sql('START TRANSACTION; ' + ' '.join(deletes) + ' COMMIT;\n', mutation=True, cleanup=True)
            counts = out.splitlines()
            require(len(counts) == 2 and all(value in (b'0', b'1') for value in counts),
                    'bounded_owned_row_delete_counts')
            self.report['cleanup']['rows_removed'] = sum(int(value) for value in counts)
            require(counts == [b'1', b'1'], 'exact_owned_row_delete_counts')
            self.rows = False
            for path, own in state_files:
                self.files[path] = own
        if self.db_user:
            self.sql('DROP USER ' + PRINCIPAL + ';\n', mutation=True, cleanup=True)
            self.report['cleanup']['database_users_removed'] = 1
            self.db_user = False
        for path, own in reversed(tuple(self.files.items())):
            require(file_identity(path.lstat()) == own, 'created_file_cleanup_identity')
            path.unlink()
            self.report['cleanup']['files_removed'] += 1
        for name, own in reversed(tuple(self.users.items())):
            p = pwd.getpwnam(name)
            require((p.pw_uid, p.pw_gid, p.pw_dir, p.pw_shell) == own
                and p.pw_passwd in ('*', '!', '!!') and all(name not in g.gr_mem for g in grp.getgrall()), 'created_user_cleanup_identity')
            self.identity_uncertain = True
            self.run(('/usr/sbin/userdel', name), 'user_remove', cleanup=True)
            require(not any(p.pw_name == name for p in pwd.getpwall()), 'created_user_removal_observed')
            self.report['cleanup']['users_removed'] += 1
            self.identity_uncertain = False
        for name, own in reversed(tuple(self.groups.items())):
            g = grp.getgrnam(name)
            require((g.gr_gid, tuple(g.gr_mem)) == own
                    and not any(p.pw_gid == g.gr_gid for p in pwd.getpwall()), 'created_group_cleanup_identity')
            self.identity_uncertain = True
            self.run(('/usr/sbin/groupdel', name), 'group_remove', cleanup=True)
            require(not any(g.gr_name == name for g in grp.getgrall()), 'created_group_removal_observed')
            self.report['cleanup']['groups_removed'] += 1
            self.identity_uncertain = False
        for path, own in reversed(tuple(self.dirs.items())):
            require(identity(path.lstat()) == own and not tuple(path.iterdir()), 'created_directory_cleanup_identity_empty')
            path.rmdir()
            self.report['cleanup']['directories_removed'] += 1
        if self.report.get('fresh_before_counts') is not None:
            remaining = self.sql("SELECT COUNT(*) FROM mysql.user WHERE User='osmap_account_mutation'; "
                "SELECT COUNT(*) FROM postfixadmin.mailbox WHERE username IN ('alice@osmap-password.invalid','bob@osmap-password.invalid');\n", cleanup=True)
            require(remaining == b'0\n0\n', 'final_SQL_absence_observed')
        self.report['cleanup_confirmed'] = True

    def main(self):
        require(len(sys.argv) == 1, 'no_caller_arguments')
        resource.setrlimit(resource.RLIMIT_CORE, (0, 0))
        resource.setrlimit(resource.RLIMIT_DATA, (4 * 1024**3, 4 * 1024**3))
        self.preflight()
        self.provision()
        self.phase = 'actual sealed Rust SQL hash test'
        require(self.remaining() >= 70, 'original_test_and_cleanup_budget')
        require(file_identity(self.binary.lstat()) == self.binary_identity, 'native_binary_before_execution_continuity')
        out = self.run((str(self.binary), '--ignored', '--exact', TEST, '--nocapture', '--test-threads=1'),
                       'actual_native_test', seconds=70, cap=131072, test=True)
        require(file_identity(self.binary.lstat()) == self.binary_identity, 'native_binary_after_execution_continuity')
        self.report['binary_identity_preserved'] = True
        expected = (b'native_sql_hash_component phase="native SQL readback" result=PASS alice_state=Contained epoch=0 '
                    b'performed_write_time_known=true bob_epoch_preserved=true credential_retry=false full_workflow_qualified=false')
        require(out.count(b'native_sql_hash_component ') == 1
                and any(line.endswith(expected) for line in out.splitlines()), 'actual_component_receipt')
        self.inspect_state(after_test=True)
        self.report['component_result'] = 'PASS'


def stop(_number, _frame):
    raise Refused('original_fixture_interrupted')


if __name__ == '__main__':
    for number in STOPS:
        signal.signal(number, stop)
    signal.signal(signal.SIGCHLD, signal.SIG_DFL)
    fixture = Fixture()
    signal.alarm(150)
    try:
        fixture.main()
    except BaseException as error:
        fixture.report['reason'] = error.code if isinstance(error, Refused) else type(error).__name__
        if fixture.phase == 'actual sealed Rust SQL hash test':
            fixture.report['component_result'] = 'FAIL'
    finally:
        mask = signal.pthread_sigmask(signal.SIG_BLOCK, STOPS)
        fixture.report['action_phase'] = fixture.phase
        try:
            fixture.cleanup()
        except BaseException as error:
            fixture.report['cleanup_reason'] = error.code if isinstance(error, Refused) else type(error).__name__
            fixture.report['cleanup_confirmed'] = False
        fixture.report['phase'] = fixture.phase
        fixture.report['sql_uncertain'] = fixture.sql_uncertain
        fixture.report['identity_uncertain'] = fixture.identity_uncertain
        fixture.report['creation_uncertain'] = fixture.creation_uncertain
        fixture.report['process_uncertain'] = fixture.process_uncertain
        fixture.report['elapsed_seconds'] = round(time.monotonic() - fixture.began, 3)
        fixture.report['stage_retained'] = str(fixture.stage)
        fixture.report['result'] = ('PASS' if fixture.report['component_result'] == 'PASS'
                                    and fixture.report.get('cleanup_confirmed') else 'FAIL')
        signal.alarm(0)
        print(json.dumps(fixture.report, sort_keys=True))
        # No pending stop can skip the single sanitized disposition record.
    raise SystemExit(0 if fixture.report['result'] == 'PASS'
                     and fixture.report.get('cleanup_confirmed') else 1)
