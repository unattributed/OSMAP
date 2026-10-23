#!/usr/local/bin/python3
"""Install only the fixed combined account helper and rc script.

The root delivery carrier verifies signed source and native qualification before
pinning admission.json by SHA-256. This component checks that exact admission
and artifact parity; it does not itself verify a Git signature or qualify UAT.
The default CLI performs no service, enablement, account, key, configuration or
Generation operation. The separately isolated FixedServiceBootstrap candidate
below has explicit service/configuration effects, no executable carrier yet,
and is NOT ADMISSIBLE for native dispatch until its retained gaps are closed.
"""
import argparse
import fcntl
import hashlib
import json
import os
from pathlib import Path
import re
import selectors
import signal
import socket
import stat
import subprocess
import time

RUNTIME = Path('/etc/osmap/account-runtime')
BINARY = Path('/usr/local/libexec/osmap/account-passwd')
RC = Path('/etc/rc.d/osmap_account_password')
BACKUPS = Path('/var/backups')
LIMIT = 128 * 1024 * 1024
STOPS = {signal.SIGALRM, signal.SIGHUP, signal.SIGTERM, signal.SIGINT}


class Refused(Exception):
    pass


def require(value, reason):
    if not value:
        raise Refused(reason)


def failure_code(error):
    """Export source-owned refusal codes without paths or exception payloads."""
    if (type(error) is Refused and len(error.args) == 1 and
            isinstance(error.args[0], str) and
            re.fullmatch(r'[a-z][a-z0-9_]{0,127}', error.args[0])):
        return error.args[0]
    if isinstance(error, OSError):
        return 'installation_os_error'
    if isinstance(error, ValueError):
        return 'installation_invalid_input'
    return 'installation_publication_refused'


def before(end):
    require(time.monotonic() < end, 'installation_deadline')


def digest(data):
    return hashlib.sha256(data).hexdigest()


def identity(metadata):
    return (metadata.st_dev, metadata.st_ino, metadata.st_uid,
            metadata.st_gid, metadata.st_mode, metadata.st_nlink,
            metadata.st_size, metadata.st_mtime_ns, metadata.st_ctime_ns)


def parents(path):
    result = []
    for parent in path.parents:
        m = parent.lstat()
        require(stat.S_ISDIR(m.st_mode) and m.st_uid == 0 and
                not m.st_mode & 0o022, 'protected_installation_parent')
        result.append((str(parent), identity(m)[:6]))
    return tuple(result)


def read_regular(path, cap, end):
    before(end)
    ancestry = parents(path)
    m = path.lstat()
    require(stat.S_ISREG(m.st_mode) and m.st_uid == os.geteuid() and
            m.st_nlink == 1 and not m.st_mode & 0o6022 and
            0 < m.st_size <= cap, 'installation_file_custody')
    fd = os.open(path, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK |
                 os.O_CLOEXEC)
    try:
        require(identity(os.fstat(fd)) == identity(m), 'installation_file_open')
        data = bytearray()
        while len(data) <= m.st_size:
            before(end)
            part = os.read(fd, min(262144, m.st_size + 1 - len(data)))
            if not part:
                break
            data.extend(part)
        require(len(data) == m.st_size and identity(os.fstat(fd)) == identity(m)
                and identity(path.lstat()) == identity(m) and
                parents(path) == ancestry, 'installation_file_continuity')
    finally:
        os.close(fd)
    return bytes(data), identity(m)


def snapshot(path, expected, cap, end):
    parents(path)
    try:
        data, metadata = read_regular(path, cap, end)
    except FileNotFoundError:
        require(expected is None, 'expected_installed_file_missing')
        return None
    require(expected is not None and digest(data) == expected,
            'unexpected_installed_file')
    return {'data': data, 'metadata': metadata, 'sha256': expected}


def same_snapshot(path, prior, cap, end):
    if prior is None:
        require(not os.path.lexists(path), 'prior_absence_changed')
    else:
        data, metadata = read_regular(path, cap, end)
        require(metadata == prior['metadata'] and digest(data) == prior['sha256'],
                'prior_installed_file_changed')


def sync_directory(path):
    fd = os.open(path, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW |
                 os.O_CLOEXEC)
    try:
        os.fsync(fd)
    finally:
        os.close(fd)


def write_exclusive(path, data, end):
    fd = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL |
                 os.O_NOFOLLOW | os.O_CLOEXEC, 0o600)
    try:
        view = memoryview(data)
        while view:
            before(end)
            count = os.write(fd, view[:262144])
            require(count > 0, 'backup_write_zero')
            view = view[count:]
        os.fsync(fd)
    finally:
        os.close(fd)


def publish(path, data, mode, owner, group, end, owned, *, recovery=None, readback_cap=None):
    """Existing same-directory exclusive temporary + atomic replace pattern."""
    ancestry = parents(path)
    directory = os.open(path.parent, os.O_RDONLY | os.O_DIRECTORY |
                        os.O_NOFOLLOW | os.O_CLOEXEC)
    temporary = '.osmap-account-password-' + os.urandom(8).hex()
    fd = None
    temporary_lease = None
    try:
        fd = os.open(temporary, os.O_WRONLY | os.O_CREAT | os.O_EXCL |
                     os.O_NOFOLLOW | os.O_CLOEXEC, 0o600, dir_fd=directory)
        # Keep birth custody even when write/chown/chmod/fsync refuses. The
        # still-open descriptor supplies the current metadata after our changes.
        temporary_lease = identity(os.fstat(fd))[:2]
        os.fchown(fd, owner, group)
        os.fchmod(fd, mode)
        view = memoryview(data)
        while view:
            before(end)
            count = os.write(fd, view[:262144])
            require(count > 0, 'publication_write_zero')
            view = view[count:]
        os.fsync(fd)
        published_lease = identity(os.fstat(fd))[:6]
        require(parents(path) == ancestry, 'publication_parent_changed')
        # Record the actual born inode BEFORE replace so a failed directory
        # sync still permits only that owned current publication to roll back.
        owned[path] = (published_lease, digest(data))
        if recovery is not None:
            recovery.publication('INTENT', path, identity(os.fstat(fd)), digest(data), temporary)
        os.replace(temporary, path.name, src_dir_fd=directory,
                   dst_dir_fd=directory)
        os.fsync(directory)
        cap = (LIMIT if path == BINARY else 16384) if readback_cap is None else readback_cap
        require(type(cap) is int and 0 < cap <= LIMIT, 'fixed_publication_readback_bound')
        actual, m = read_regular(path, cap, end)
        require(identity(os.fstat(fd))[:6] == published_lease and
                m[:6] == published_lease and digest(actual) == digest(data),
                'published_readback_refused')
        if recovery is not None:
            recovery.publication('READBACK', path, m, digest(actual))
    finally:
        try:
            m = os.stat(temporary, dir_fd=directory, follow_symlinks=False)
            if (temporary_lease is not None and identity(m)[:2] == temporary_lease
                    and identity(m)[:6] == identity(os.fstat(fd))[:6]):
                os.unlink(temporary, dir_fd=directory)
                os.fsync(directory)
        except FileNotFoundError:
            pass
        finally:
            if fd is not None:
                os.close(fd)
            os.close(directory)


def fixed_observation(program, end):
    require(program in ('ps', 'fstat'), 'fixed_installation_observation')
    argv = (('/bin/ps', '-ax', '-o', 'pid=,uid=,comm=') if program == 'ps'
            else ('/usr/bin/fstat', '-n'))
    end = min(end, time.monotonic() + 5)
    io_end = end - 1
    child = None
    output = [bytearray(), bytearray()]
    mask = signal.pthread_sigmask(signal.SIG_BLOCK, STOPS)
    try:
        try:
            before(io_end)
            child = subprocess.Popen(
                argv, cwd='/', stdin=subprocess.DEVNULL, stdout=subprocess.PIPE,
                stderr=subprocess.PIPE, env={'PATH': '/usr/bin:/bin', 'LC_ALL': 'C'},
                start_new_session=True, close_fds=True,
                preexec_fn=lambda: signal.pthread_sigmask(signal.SIG_SETMASK, mask))
        finally:
            signal.pthread_sigmask(signal.SIG_SETMASK, mask)
        with selectors.DefaultSelector() as selected:
            for index, pipe in enumerate((child.stdout, child.stderr)):
                os.set_blocking(pipe.fileno(), False)
                selected.register(pipe, selectors.EVENT_READ, index)
            while time.monotonic() < io_end:
                for key, _ in selected.select(min(.02, max(0, io_end-time.monotonic()))):
                    part = os.read(key.fileobj.fileno(), 65536)
                    if not part:
                        selected.unregister(key.fileobj)
                    else:
                        output[key.data].extend(part)
                        require(len(output[key.data]) <= (1048576 if key.data == 0 else 4096),
                                'installation_observation_output_cap')
                if not selected.get_map():
                    state = os.waitid(os.P_PID, child.pid,
                                      os.WEXITED | os.WNOHANG | os.WNOWAIT)
                    if state is not None and state.si_pid == child.pid:
                        break
            else:
                raise Refused('installation_observation_deadline')
    finally:
        if child is not None:
            cleanup_mask = signal.pthread_sigmask(signal.SIG_BLOCK, STOPS)
            try:
                try:
                    os.killpg(child.pid, signal.SIGKILL)
                except ProcessLookupError:
                    pass
                child.wait(timeout=max(.001, end-time.monotonic()))
                gone = False
                while time.monotonic() < end:
                    try:
                        os.killpg(child.pid, 0)
                    except ProcessLookupError:
                        gone = True
                        break
                    time.sleep(.001)
                require(gone, 'installation_observation_cleanup_unknown')
            finally:
                child.stdout.close()
                child.stderr.close()
                signal.pthread_sigmask(signal.SIG_SETMASK, cleanup_mask)
    require(child is not None and child.returncode == 0 and not output[1] and
            output[0].isascii(), 'installation_observation_refused')
    return bytes(output[0])


def require_helper_absent(images, end):
    for line in fixed_observation('ps', end).splitlines():
        fields = line.split()
        require(len(fields) == 3 and all(value.isdigit() for value in fields[:2]),
                'installation_ps_shape')
        require(fields[2].rsplit(b'/', 1)[-1] != b'account-passwd',
                'active_account_helper_or_worker')
    raw = fixed_observation('fstat', end)
    lines = raw.splitlines()
    require(lines and lines[0].split() ==
            [b'USER', b'CMD', b'PID', b'FD', b'DEV', b'INUM', b'MODE', b'R/W', b'SZ|DV', b'NAME'],
            'installation_fstat_header')
    for line in lines[1:]:
        fields = line.split()
        require(len(fields) >= 4 and fields[2].isdigit(), 'installation_fstat_shape')
        if fields[3] != b'text':
            continue
        match = re.fullmatch(rb'([0-9]+),\s*([0-9]+)\s+([0-9]+)\*?\s+([0-7]+)(?:\s+.*)?',
                             b' '.join(fields[4:]))
        require(match is not None, 'installation_fstat_text_shape')
        observed = tuple(int(match[index]) for index in (1, 2, 3))
        require(observed not in images, 'active_account_helper_text')


def admission(stage, expected_hash, source, end):
    require(re.fullmatch(r'[0-9a-f]{64}', expected_hash) and
            re.fullmatch(r'[0-9a-f]{40}', source), 'installation_admission_pin')
    require(stage.parent == Path('/var/run') and
            re.fullmatch(r'osmap-account-password-install-[0-9a-f]{16}', stage.name),
            'fixed_installation_stage')
    parents(stage / 'admission.json')
    m = stage.lstat()
    require(stat.S_ISDIR(m.st_mode) and m.st_uid == os.geteuid() and
            m.st_gid == os.getegid() and stat.S_IMODE(m.st_mode) == 0o700,
            'installation_stage_custody')
    names = []
    for index, path in enumerate(stage.iterdir()):
        require(index < 4, 'installation_stage_bound')
        names.append(path.name)
    require(set(names) == {'admission.json', 'account-passwd', 'osmap_account_password'},
            'installation_stage_membership')
    raw, _ = read_regular(stage / 'admission.json', 8192, end)
    require(digest(raw) == expected_hash, 'installation_admission_hash')
    def unique(pairs):
        result = {}
        for key, value in pairs:
            require(key not in result, 'duplicate_installation_admission_field')
            result[key] = value
        return result
    record = json.loads(raw, object_pairs_hook=unique)
    require(isinstance(record, dict) and set(record) == {
        'version', 'source_commit', 'source_manifest_sha256', 'qualification_report_sha256',
        'binary_sha256', 'rc_sha256', 'old_binary_sha256', 'old_rc_sha256'},
        'installation_admission_shape')
    require(record['version'] == 1 and record['source_commit'] == source,
            'installation_source_binding')
    for name in ('source_manifest_sha256', 'qualification_report_sha256',
                 'binary_sha256', 'rc_sha256', 'old_binary_sha256', 'old_rc_sha256'):
        value = record[name]
        require(value is None and name.startswith('old_') or
                isinstance(value, str) and re.fullmatch(r'[0-9a-f]{64}', value),
                'installation_hash_field')
    binary, binary_id = read_regular(stage / 'account-passwd', LIMIT, end)
    rc, rc_id = read_regular(stage / 'osmap_account_password', 16384, end)
    require(digest(binary) == record['binary_sha256'] and digest(rc) == record['rc_sha256'],
            'installation_artifact_parity')
    return record, binary, rc, (identity(m)[:6], binary_id, rc_id)


def install(stage, expected_hash, source, end):
    body_end = end - 15
    record, binary, rc, source_identity = admission(stage, expected_hash, source, body_end)
    parents(RUNTIME / 'unused')
    lock = os.open(RUNTIME, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW | os.O_CLOEXEC)
    backup = None
    result = {'result': 'FAIL', 'installed': False, 'activation': False,
              'enablement': 'UNKNOWN_UNMODIFIED', 'source_commit': source,
              'source_authenticity': 'EXTERNAL_SIGNED_ADMISSION_SHA256_PINNED',
              'service_controls_executed': False, 'rollback': 'NOT_REQUIRED'}
    try:
        m = os.fstat(lock)
        require(m.st_uid == os.geteuid() and m.st_gid == os.getegid() and
                stat.S_IMODE(m.st_mode) == 0o700, 'runtime_directory_custody')
        runtime_id = identity(m)[:6]
        require(identity(RUNTIME.lstat())[:6] == runtime_id, 'runtime_directory_open')
        fcntl.flock(lock, fcntl.LOCK_EX | fcntl.LOCK_NB)
        old = {BINARY: snapshot(BINARY, record['old_binary_sha256'], LIMIT, body_end),
               RC: snapshot(RC, record['old_rc_sha256'], 16384, body_end)}
        images = {(os.major(source_identity[1][0]), os.minor(source_identity[1][0]),
                   source_identity[1][1])}
        if old[BINARY] is not None:
            m = old[BINARY]['metadata']
            images.add((os.major(m[0]), os.minor(m[0]), m[1]))
        require_helper_absent(images, body_end)
        # Recheck fixed staged bytes and targets under the same lifetime lock.
        again = admission(stage, expected_hash, source, body_end)
        require(again[3] == source_identity, 'installation_stage_changed')
        for path, prior in old.items():
            same_snapshot(path, prior, LIMIT if path == BINARY else 16384, body_end)
        parents(BACKUPS / 'unused')
        backup = BACKUPS / ('osmap-account-password-' + os.urandom(8).hex())
        backup.mkdir(mode=0o700)
        result['backup'] = str(backup)
        saved = {}
        for path, label in ((BINARY, 'binary.before'), (RC, 'rc.before')):
            prior = old[path]
            saved[label] = None if prior is None else {
                'sha256': prior['sha256'], 'metadata': prior['metadata']}
            if prior is not None:
                write_exclusive(backup / label, prior['data'], body_end)
        manifest = {'source_commit': source, 'admission_sha256': expected_hash,
                    'before': saved, 'new_binary_sha256': record['binary_sha256'],
                    'new_rc_sha256': record['rc_sha256'],
                    'enablement': 'UNKNOWN_UNMODIFIED'}
        write_exclusive(backup / 'manifest.json',
                        json.dumps(manifest, sort_keys=True).encode() + b'\n', body_end)
        sync_directory(backup)
        sync_directory(BACKUPS)
        owned = {}
        try:
            for path, data, mode in ((BINARY, binary, 0o500), (RC, rc, 0o555)):
                before(body_end)
                require(identity(os.fstat(lock))[:6] == runtime_id and
                        identity(RUNTIME.lstat())[:6] == runtime_id,
                        'runtime_directory_changed')
                same_snapshot(path, old[path], LIMIT if path == BINARY else 16384, body_end)
                publish(path, data, mode, os.geteuid(), os.getegid(), body_end, owned)
            result.update(result='INSTALLED_NOT_ACTIVATED', installed=True)
        except BaseException as failure:
            # No historical PID signals or service changes during restoration.
            for number in (signal.SIGHUP, signal.SIGTERM, signal.SIGINT):
                signal.signal(number, signal.SIG_IGN)
            result['rollback'] = 'PASS'
            for path in (RC, BINARY):
                if path not in owned:
                    continue
                try:
                    prior = old[path]
                    try:
                        same_snapshot(path, prior, LIMIT if path == BINARY else 16384, end)
                        continue
                    except Refused:
                        pass
                    current, m = read_regular(path, LIMIT if path == BINARY else 16384, end)
                    require(m[:6] == owned[path][0] and digest(current) == owned[path][1],
                            'rollback_current_not_owned')
                    if prior is None:
                        os.unlink(path)
                        sync_directory(path.parent)
                        require(not os.path.lexists(path), 'rollback_absence_unknown')
                    else:
                        original = prior['metadata']
                        publish(path, prior['data'], stat.S_IMODE(original[4]),
                                original[2], original[3], end, {})
                        restored, m = read_regular(path, LIMIT if path == BINARY else 16384, end)
                        require(digest(restored) == prior['sha256'] and
                                (m[2], m[3], stat.S_IMODE(m[4])) ==
                                (original[2], original[3], stat.S_IMODE(original[4])),
                                'rollback_readback_unknown')
                except BaseException as rollback_failure:
                    result['rollback'] = 'UNKNOWN'
                    result.setdefault('rollback_failures', {})[str(path)] = failure_code(rollback_failure)
            result['failure'] = failure_code(failure)
        write_exclusive(backup / 'result.json',
                        json.dumps(result, sort_keys=True).encode() + b'\n', end)
        sync_directory(backup)
        return result
    finally:
        os.close(lock)


# Fixed S04-02 bootstrap candidate, called by the existing root fixture carrier.
# These functions confer no native qualification or caller-selected authority.
BOOTSTRAP_ACCOUNTS = ('alice@osmap-password.invalid', 'bob@osmap-password.invalid')
SUBMISSION_ROOT = Path('/etc/osmap/account-submission')
PUBLIC_SQL = Path('/etc/dovecot/dovecot-sql.conf.ext')
PUBLIC_IMAP = Path('/etc/dovecot/conf.d/99-osmap-account-epoch.conf')
POSTFIX_MAIN = Path('/etc/postfix/main.cf')
POSTFIX_MASTER = Path('/etc/postfix/master.cf')
PF_MAIN = Path('/etc/pf.conf')
PF_ANCHOR = Path('/etc/pf.osmap-account-submission.conf')
PLUGIN = Path('/usr/local/lib/dovecot/lib90_osmap_imap_epoch_plugin.so')
BOOTSTRAP_TARGETS = (PUBLIC_SQL, PUBLIC_IMAP, SUBMISSION_ROOT/'dovecot.conf',
    SUBMISSION_ROOT/'dovecot-sql.conf.ext', POSTFIX_MAIN, POSTFIX_MASTER,
    PF_MAIN, PF_ANCHOR, PLUGIN)
RESTRICTED_PRINCIPAL = "'osmap_account_mutation'@'localhost'"
COLUMN_GRANTS = {('username', 'SELECT'), ('password', 'SELECT'), ('modified', 'SELECT'),
    ('active', 'SELECT'), ('smtp_active', 'SELECT'), ('password', 'UPDATE'), ('modified', 'UPDATE')}


def assignment_spans(raw):
    """Existing fixed config assignments, with Dovecot logical continuations.

    Spans retain original physical bytes. Values stay private in RAM; this is
    not a SQL parser or a connection-string normalizer.
    """
    require(type(raw) is bytes and 0 < len(raw) <= 131072 and raw.isascii()
        and b'\0' not in raw and b'\r' not in raw, 'bootstrap_assignment_bytes')
    lines = raw.decode('ascii').splitlines(keepends=True)
    result, parts, first = [], [], None
    for index, physical in enumerate(lines):
        line = physical.strip()
        if not line or line.startswith('#'):
            continue
        if first is None:
            first = index
        more = line.endswith('\\')
        parts.append(line[:-1].rstrip() if more else line)
        value = ' '.join(parts)
        require(len(value) <= 16384, 'bootstrap_logical_assignment_bound')
        if more:
            continue
        require('=' in value, 'bootstrap_logical_assignment')
        key, value = value.split('=', 1)
        key, value = key.strip(), value.strip()
        require(re.fullmatch('[a-z_]+', key), 'bootstrap_assignment_key')
        result.append((key, value, first, index + 1))
        parts, first = [], None
    require(first is None, 'bootstrap_dangling_continuation')
    return lines, result


def fixed_assignments(raw):
    _, spans = assignment_spans(raw)
    result = {}
    for key, value, _, _ in spans:
        require(key not in result, 'bootstrap_assignment_key')
        result[key] = value
    return result


def replace_assignment(raw, key, value):
    require(re.fullmatch('[a-z_]+', key) and type(value) is str and value
        and not any(c in value for c in '\r\n\0'), 'bootstrap_assignment_value')
    lines, spans = assignment_spans(raw)
    selected = [(first, end) for name, _, first, end in spans if name == key]
    require(len(selected) == 1, 'bootstrap_exact_assignment')
    first, end = selected[0]
    require(lines[end - 1].endswith('\n'), 'bootstrap_exact_assignment')
    # Remove the complete selected logical value, including all continuation
    # bodies. Preserve comments/blank physical bytes inside that span and every
    # unrelated assignment exactly; in particular connect is never rewritten.
    retained = [line for line in lines[first + 1:end]
        if not line.strip() or line.lstrip().startswith('#')]
    lines[first:end] = [lines[first].split('=', 1)[0] + '= ' + value + '\n', *retained]
    return ''.join(lines).encode('ascii')



def authoritative_dsn(raw):
    """The existing Rust mysql_route grammar, without returning credentials."""
    require(type(raw) is bytes and 0 < len(raw) <= 4096 and raw.isascii(),
        'bootstrap_authoritative_DSN_bytes')
    text = raw.decode('ascii')
    at, fields = 0, {}
    while at < len(text):
        while at < len(text) and text[at].isspace():
            at += 1
        if at == len(text):
            break
        start = at
        while at < len(text) and text[at].isalpha():
            at += 1
        require(at > start and at < len(text) and text[at] == '=',
            'bootstrap_authoritative_DSN_shape')
        key = text[start:at]
        at += 1
        quote = text[at] if at < len(text) and text[at] in "'\"" else None
        if quote is not None:
            at += 1
        value, closed = [], quote is None
        while at < len(text):
            char = text[at]
            if char == quote:
                at += 1
                closed = True
                break
            if quote is None and char.isspace():
                break
            require(char != '\\' and 0x20 <= ord(char) <= 0x7e,
                'bootstrap_authoritative_DSN_shape')
            value.append(char)
            at += 1
        require(closed and (at == len(text) or text[at].isspace())
            and key not in fields and len(fields) < 8,
            'bootstrap_authoritative_DSN_shape')
        fields[key] = ''.join(value)
    require(set(fields) == {'host', 'dbname', 'user', 'password'}
        and fields['host'] == '/var/run/mysql/mysql.sock'
        and fields['dbname'] == 'postfixadmin'
        and 0 < len(fields['user']) <= 64 and 0 < len(fields['password']) <= 256,
        'bootstrap_authoritative_fixed_SQL_socket')
    # Never reconstruct, print or normalize this private connection string.
    return raw


def render_tokens(raw, replacements):
    require(type(raw) is bytes and raw.isascii(), 'bootstrap_template_bytes')
    tokens = re.findall(rb'@([A-Z_]+)@', raw)
    require(len(tokens) == len(set(tokens)) and set(tokens) == set(replacements),
        'bootstrap_exact_template_tokens')
    for token, value in replacements.items():
        require(type(token) is bytes and type(value) is bytes and value and value.isascii()
            and not any(c in value for c in (b'\0', b'\r', b'\n')),
            'bootstrap_private_render_value')
        raw = raw.replace(b'@' + token + b'@', value)
    require(re.search(rb'@[A-Z_]+@', raw) is None, 'bootstrap_unresolved_template')
    return raw


def managed_user_query(raw):
    fields = fixed_assignments(raw)
    query = ' '.join(fields.get('user_query', '').split())
    lower = query.lower()
    require(fields.get('driver') == 'mysql' and 'connect' in fields
        and re.fullmatch(r'SELECT .+ FROM mailbox WHERE .+', query, re.I)
        and lower.count('select ') == 1 and lower.count(' from ') == 1
        and not any(c in query for c in (';', chr(96), '\\'))
        and not any(word in lower for word in (' union ', ' join ', ' into ', '--', '/*'))
        and 'osmap_epoch_managed' not in lower and 'mail_access_groups' not in lower,
        'bootstrap_supported_userdb_projection')
    at = lower.index(' from ')
    field = (", CASE WHEN username IN ('alice@osmap-password.invalid','bob@osmap-password.invalid') THEN 'yes' ELSE NULL END AS osmap_epoch_managed"
        ", CASE WHEN username IN ('alice@osmap-password.invalid','bob@osmap-password.invalid') THEN '_osmapcontrol' ELSE NULL END AS mail_access_groups")
    result = replace_assignment(raw, 'user_query', query[:at] + field + query[at:])
    # Bind installer output to the matching helper's exact four metadata forms.
    password_query = ' '.join(fields.get('password_query', '').split())
    allowed = (
        "select password from mailbox where username = '%u' and active = 1",
        "select password from mailbox where username = '%u' and active = '1'",
        "select username as user, password from mailbox where username = '%u' and active = 1",
        "select username as user, password from mailbox where username = '%u' and active = '1'",
    )
    require(password_query.lower() in allowed, 'bootstrap_verified_password_projection')
    split = password_query.lower().index(' from ')
    password_query = password_query[:split] + ", 'after' AS osmap_epoch_phase" + password_query[split:]
    return replace_assignment(result, 'password_query', password_query)


def render_postfix_master(raw, fragment):
    require(raw.isascii() and fragment.isascii() and raw.endswith(b'\n'),
        'bootstrap_master_bytes')
    kept, removed = [], []
    selected = False
    for line in raw.splitlines(keepends=True):
        if not line.strip() or line.lstrip().startswith(b'#'):
            kept.append(line)
            continue
        if line[:1] in (b' ', b'\t'):
            if selected:
                removed[-1] += line
            else:
                kept.append(line)
            continue
        fields = line.split()
        require(len(fields) >= 8, 'bootstrap_master_entry')
        service = fields[0].rsplit(b':', 1)[-1]
        selected = fields[1] == b'inet' and service in (b'submission', b'submissions', b'smtps', b'587', b'465')
        if selected:
            require(fields[7] == b'smtpd', 'bootstrap_expected_public_submission')
            removed.append(line)
        else:
            require(fields[0] != b'127.0.0.1:2525', 'bootstrap_private_backend_collision')
            kept.append(line)
    require(1 <= len(removed) <= 4 and b'127.0.0.1:2525 inet ' in fragment,
        'bootstrap_submission_cutover_selection')
    require(not any(b'smtpd_sasl_auth_enable=yes' in line.replace(b' ', b'').replace(b'\t', b'')
        for line in kept if not line.lstrip().startswith(b'#')),
        'bootstrap_existing_other_AUTH_consumer_requires_review')
    return b''.join(kept) + b'\n' + fragment, tuple(digest(b) for b in removed)


def render_pf(raw):
    require(raw.isascii() and raw.endswith(b'\n') and b'osmap/account-submission' not in raw,
        'bootstrap_PF_source')
    lines = raw.splitlines(keepends=True)
    skipped = None
    for i, line in enumerate(lines):
        stripped = line.strip()
        if re.match(rb'^set\s+skip\s+on\b', stripped):
            require(stripped in (b'set skip on lo0', b'set skip on lo'),
                'bootstrap_review_required_for_other_skip_selection')
            require(skipped is None, 'bootstrap_unique_loopback_skip')
            skipped = stripped.split()[-1]
            lines[i] = b'# OSMAP submission requires loopback filtering.\n'
    depth = 0
    position = None
    for i, line in enumerate(lines):
        stripped = line.strip()
        if not stripped or stripped.startswith(b'#'):
            continue
        require(depth >= 0, 'bootstrap_PF_braces')
        if depth == 0 and re.match(rb'^(pass|block|anchor|antispoof)\b', stripped):
            position = i
            break
        depth += stripped.count(b'{') - stripped.count(b'}')
    require(position is not None and depth == 0, 'bootstrap_PF_filter_position')
    inserted = [b'anchor "osmap/account-submission"\n',
        b'load anchor "osmap/account-submission" from "/etc/pf.osmap-account-submission.conf"\n']
    if skipped is not None:
        inserted.append(b'pass quick on ' + skipped + b' all no state\n')
    lines[position:position] = inserted
    return b''.join(lines)


class FixedRecoveryReceipt:
    """Protected custody for this fixed paired fixture, never retry authority.

    The original execution expiry is provenance. A fresh custodian needs its own
    bounded disposition authority, actual process absence and matching leases.
    """
    def __init__(self, fixture, bootstrap, purpose, profile, stage, end, http):
        self.fixture, self.bootstrap, self.purpose = fixture, bootstrap, purpose
        self.profile, self.stage, self.end, self.http = profile, stage, end, http
        self.path, self.backup = stage/'paired-recovery.json', stage/'paired-recovery-before'
        self.lease, self.sha256 = None, None
        self.phase, self.sequence = 'INITIAL', 0
        self.fixture_setup_uncertain, self.helper_start_uncertain = True, False
        self.request_stop_confirmed, self.restoration_attempted = False, False
        self.intent, self.backups, self.rows, self.epoch_witnesses = {}, {}, {}, {}
        self.maildirs, self.imap_absence_observed = [], False
        self.mail_login_started = False
        self.actor_pid = os.getpid()
        self.actor_row = self.fixture.run(('/bin/ps', '-p', str(self.actor_pid),
            '-o', 'pid=,ppid=,uid=,lstart=,comm='), 'paired_root_actor_birth', cap=2048, seconds=5)
        fields = self.actor_row.split()
        require(len(fields) == 9 and fields[0] == str(self.actor_pid).encode('ascii')
            and fields[2] == b'0', 'paired_actual_root_actor_identity')
        self.last_marker, self.issuer = None, None
        self.backup.mkdir(mode=0o700)
        require(identity(self.backup.lstat())[2:5] == (0, 0, stat.S_IFDIR | 0o700),
            'paired_recovery_backup_custody')
        sync_directory(stage)
        self.checkpoint('INITIAL')

    @staticmethod
    def row_public(row):
        return [str(row[0]), row[1].decode('ascii')]

    def retained_file(self, path, cap=131072):
        raw, metadata = read_regular(path, cap, self.end)
        return {'path': str(path.relative_to(self.stage)), 'metadata': list(metadata),
            'sha256': digest(raw)}

    def keep(self, name, data):
        require(name in ('authorized', 'rc', 'db-create', 'db-grants', 'pf-rules'),
            'fixed_recovery_backup_name')
        if name not in self.backups:
            target = self.backup/name
            write_exclusive(target, data, self.end)
            sync_directory(self.backup)
            self.backups[name] = self.retained_file(target)
        else:
            target = self.stage/self.backups[name]['path']
            raw, metadata = read_regular(target, 131072, self.end)
            require(raw == data and list(metadata) == self.backups[name]['metadata']
                and digest(raw) == self.backups[name]['sha256'], 'paired_backup_continuity')
        return self.backups[name]

    def publication(self, event, path, metadata, sha256, temporary=None):
        allowed = set(BOOTSTRAP_TARGETS) | {RUNTIME/'imap-publication.json',
            self.purpose.AUTHORIZED} | {value[0] for value in self.purpose.CONNECTORS.values()}
        require(path in allowed and event in ('INTENT', 'READBACK'),
            'fixed_recovery_publication_scope')
        record = self.intent.setdefault(str(path), {})
        if event == 'INTENT':
            require(type(temporary) is str and re.fullmatch(
                r'\.osmap-account-password-[a-f0-9]{16}', temporary),
                'fixed_recovery_temporary_name')
            prior_owned = record.get('readback') or record.get('prior_owned')
            record.clear()
            if prior_owned is not None:
                record['prior_owned'] = prior_owned
            # Rename can alter ctime. Fresh recovery compares first7+hash for
            # this intent, and all9 only after actual published readback.
            record.update(intent={'metadata': list(metadata), 'sha256': sha256,
                'temporary_name': temporary}, readback=None)
        else:
            require('intent' in record and list(metadata[:7]) ==
                record['intent']['metadata'][:7] and sha256 == record['intent']['sha256'],
                'paired_publication_matches_born_intent')
            record['readback'] = {'metadata': list(metadata), 'sha256': sha256}
        self.checkpoint('PUBLICATION_' + event)

    def snapshot_observed(self, account, value):
        require(account in BOOTSTRAP_ACCOUNTS and value['account'] == account,
            'paired_fixed_snapshot_account')
        epoch, path = self.fixture.rust_epoch(account)
        raw, metadata = read_regular(path, 4096, self.end)
        require(json.loads(raw) == epoch and epoch['epoch'] == value['epoch']
            and epoch['state'] == value['state'], 'paired_epoch_snapshot_continuity')
        lock = path.with_suffix('.lock')
        lock_metadata = identity(lock.lstat())
        require(stat.S_ISREG(lock_metadata[4]) and lock_metadata[2] == 0
            and lock_metadata[5] == 1 and lock_metadata[6] == 0
            and not lock_metadata[4] & 0o6022, 'paired_empty_epoch_lock_custody')
        fd = os.open(lock, os.O_RDONLY | os.O_NOFOLLOW | os.O_CLOEXEC)
        try:
            require(identity(os.fstat(fd)) == lock_metadata and not os.read(fd, 1)
                and identity(lock.lstat()) == lock_metadata, 'paired_epoch_lock_continuity')
        finally:
            os.close(fd)
        self.epoch_witnesses[account] = {'path': str(path), 'metadata': list(metadata),
            'sha256': digest(raw), 'lock': {'path': str(lock),
                'metadata': list(lock_metadata), 'sha256': digest(b'')}}
        self.rows[account]['owned_current_full17_sha256'] = value['row_sha256']
        if value['epoch'] == 1:
            self.rows[account]['owned_current_postwrite_observed'] = True
        self.checkpoint('SNAPSHOT_OBSERVED')

    def prepare_maildirs(self):
        require(not self.maildirs and not self.request_stop_confirmed,
            'one_use_maildir_projection')
        for account in BOOTSTRAP_ACCOUNTS:
            values = {}
            for field in ('home', 'mail', 'uid', 'gid'):
                raw = self.fixture.run(('/usr/local/bin/doveadm', 'user', '-f', field, account),
                    'paired_fixed_maildir_' + field, cap=4096, seconds=5)
                require((raw == b'' and field == 'mail') or
                    raw.count(b'\n') == 1 and raw.endswith(b'\n') and b'\0' not in raw,
                    'paired_one_public_userdb_field')
                values[field] = raw.removesuffix(b'\n').decode('ascii')
            home = values['home']
            require(home.startswith('/') and str(Path(home)) == home and '\n' not in home
                and account.split('@')[0] + '-' + self.fixture.lease in Path(home).parts,
                'paired_unique_home_not_absolute_or_nonce')
            mail = values['mail']
            if not mail:
                raw = self.fixture.run(('/usr/local/bin/doveconf', '-c',
                    '/etc/dovecot/dovecot.conf', '-h', 'mail_location'),
                    'paired_fixed_effective_mail_location', cap=4096, seconds=5)
                require(raw.count(b'\n') == 1 and raw.endswith(b'\n'),
                    'paired_one_effective_mail_location')
                mail = raw[:-1].decode('ascii')
            require(mail.startswith('maildir:') and ':' not in mail[8:],
                'paired_exact_maildir_storage')
            mail = mail[8:]
            substitutions = {'%h': home, '%u': account,
                '%n': account.split('@')[0], '%d': account.split('@')[1]}
            if mail == '~' or mail.startswith('~/'):
                mail = home + mail[1:]
            for key, value in substitutions.items():
                mail = mail.replace(key, value)
            require('%' not in mail and mail.startswith('/') and str(Path(mail)) == mail
                and Path(mail).is_relative_to(Path(home))
                and account.split('@')[0] + '-' + self.fixture.lease in Path(mail).parts
                and '..' not in Path(home).parts and '..' not in Path(mail).parts
                and values['uid'].isdigit() and values['gid'].isdigit()
                and int(values['uid']) > 0 and int(values['gid']) > 0,
                'paired_fixed_nonce_maildir_projection')
            existing, absent = [], []
            for path in reversed((Path(home), *Path(home).parents)):
                if os.path.lexists(path):
                    metadata = identity(path.lstat())
                    require(stat.S_ISDIR(metadata[4]) and not metadata[4] & 0o002,
                        'paired_maildir_ancestor_custody')
                    existing.append({'path': str(path), 'metadata': list(metadata)})
                else:
                    absent.append(str(path))
            require(absent and not os.path.lexists(home) and not os.path.lexists(mail)
                and all(row['home'] != home for row in self.maildirs),
                'paired_maildir_absence_and_distinctness')
            self.maildirs.append({'account': account, 'home': home, 'path': mail,
                'uid': int(values['uid']), 'gid': int(values['gid']), 'lease': self.fixture.lease,
                'absent_before': True, 'existing_ancestors': existing,
                'absent_paths': absent, 'born': []})
        self.checkpoint('MAILDIR_ABSENCE_CAPTURED')
        # These are controlled fixture preparations, not Dovecot birth proof.
        born_parents = {}
        for row in self.maildirs:
            row['born_parents'] = []
            targets = [Path(text) for text in row['absent_paths']]
            target = Path(row['path'])
            for parent in reversed((target, *target.parents)):
                if parent.is_relative_to(Path(row['home'])) and parent not in targets:
                    targets.append(parent)
            targets.extend(target/name for name in ('cur', 'new', 'tmp'))
            for path in targets:
                if os.path.lexists(path):
                    require(str(path) in born_parents and list(identity(path.lstat())[:5]) ==
                        born_parents[str(path)][:5], 'paired_maildir_prepare_collision')
                    if not path.is_relative_to(Path(row['home'])):
                        row['born_parents'].append({'path': str(path),
                            'metadata': list(identity(path.lstat()))})
                    continue
                self.checkpoint('MAILDIR_CREATE_INTENT')
                path.mkdir(mode=0o700)
                os.chown(path, row['uid'], row['gid'])
                # Parent SGID inheritance is removed only on this new inode.
                os.chmod(path, 0o700)
                metadata = identity(path.lstat())
                require(metadata[2:5] == (row['uid'], row['gid'], stat.S_IFDIR | 0o700),
                    'paired_prepared_maildir_metadata')
                sync_directory(path.parent)
                born_parents[str(path)] = list(metadata)
                if not path.is_relative_to(Path(row['home'])):
                    row['born_parents'].append({'path': str(path), 'metadata': list(metadata)})
            row['born'] = self.maildir_tree(row)
            row['precreated_by_fixture'] = True
            self.checkpoint('MAILDIR_PREPARED')

    @staticmethod
    def metadata_name(name):
        return name in {'dovecot-uidlist', 'dovecot-uidvalidity', 'dovecot.index',
            'dovecot.index.cache', 'dovecot.index.log', 'dovecot.index.log.2',
            'dovecot.list.index', 'dovecot.list.index.log', 'dovecot.mailbox.log',
            'subscriptions', 'maildirfolder'} or re.fullmatch(
                r'dovecot-uidvalidity\.[a-f0-9]{1,32}', name) is not None

    def maildir_tree(self, row):
        root, entries = Path(row['home']), []
        ancestors = {item['path']: item['metadata'] for item in
            row['existing_ancestors'] + row.get('born_parents', [])}
        for parent in root.parents:
            actual = identity(parent.lstat())
            require(str(parent) in ancestors and stat.S_ISDIR(actual[4])
                and list(actual[:5]) == ancestors[str(parent)][:5],
                'paired_maildir_parent_identity')
        pending = [(root, 0)]
        while pending:
            path, depth = pending.pop()
            require(depth <= 8 and len(entries) < 64, 'paired_maildir_tree_bound')
            metadata = identity(path.lstat())
            require(metadata[2:4] == (row['uid'], row['gid'])
                and not metadata[4] & 0o6022 and not stat.S_ISLNK(metadata[4]),
                'paired_maildir_born_owner_mode')
            if stat.S_ISDIR(metadata[4]):
                children = tuple(path.iterdir())
                require(len(children) <= 32, 'paired_maildir_children_bound')
                if path.name in ('cur', 'new', 'tmp'):
                    require(not children, 'paired_maildir_message_or_temporary_body')
                for child in children:
                    require(child.name in ('cur', 'new', 'tmp', 'Maildir')
                        or self.metadata_name(child.name), 'paired_maildir_unknown_entry')
                    pending.append((child, depth + 1))
                kind = 'dir'
            else:
                require(stat.S_ISREG(metadata[4]) and metadata[5] == 1
                    and metadata[6] <= 1048576 and self.metadata_name(path.name),
                    'paired_maildir_metadata_only')
                kind = 'metadata'
            entries.append({'path': str(path), 'metadata': list(metadata), 'type': kind})
            require(identity(path.lstat()) == metadata, 'paired_maildir_observation_continuity')
        return entries

    def capture_maildirs(self):
        require(len(self.maildirs) == 2, 'paired_maildir_prior_absence_required')
        for row in self.maildirs:
            require(row.get('precreated_by_fixture') is True and row['born'],
                'paired_prepared_maildir_birth_required')
            prior = {item['path']: item for item in row['born']}
            actual = self.maildir_tree(row)
            require(all(item['path'] in {v['path'] for v in actual} and any(
                current['path'] == item['path'] and current['metadata'][:5] == item['metadata'][:5]
                for current in actual) for item in prior.values()),
                'paired_prepared_maildir_birth_changed')
            row['born'] = actual
            parents = []
            for text in row['absent_paths']:
                path = Path(text)
                if path == Path(row['home']):
                    continue
                m = identity(path.lstat())
                require(stat.S_ISDIR(m[4]) and m[2:4] == (row['uid'], row['gid'])
                    and not m[4] & 0o6022, 'paired_born_maildir_parent')
                parents.append({'path': text, 'metadata': list(m)})
            row['born_parents'] = parents
        self.checkpoint('MAILDIR_BIRTH_CAPTURED')

    def remove_maildirs(self):
        require(self.request_stop_confirmed and (self.imap_absence_observed
                or self.mail_login_started is False) and len(self.maildirs) == 2 and all(row['born'] for row in self.maildirs),
            'paired_maildir_producer_absence_required')
        for row in self.maildirs:
            current = self.maildir_tree(row)
            expected = {item['path']: item for item in row['born']}
            require({item['path'] for item in current} == set(expected)
                and all(item['metadata'][:6] == expected[item['path']]['metadata'][:6]
                    and item['type'] == expected[item['path']]['type'] for item in current),
                'paired_maildir_foreign_current_entry')
            self.checkpoint('MAILDIR_REMOVE_INTENT')
            for item in sorted(current, key=lambda item: len(Path(item['path']).parts), reverse=True):
                path = Path(item['path'])
                width = 5 if item['type'] == 'dir' else 6
                require(list(identity(path.lstat())[:width]) == item['metadata'][:width],
                    'paired_maildir_cleanup_inode')
                if item['type'] == 'dir':
                    require(not tuple(path.iterdir()), 'paired_maildir_cleanup_not_empty')
                    path.rmdir()
                else:
                    path.unlink()
                sync_directory(path.parent)
            row['removed'] = True
        born_parents = {item['path']: item for row in self.maildirs for item in row.get('born_parents', [])}
        for text, item in sorted(born_parents.items(), key=lambda pair: len(Path(pair[0]).parts), reverse=True):
            path = Path(text)
            require(list(identity(path.lstat())[:5]) == item['metadata'][:5]
                and not tuple(path.iterdir()), 'paired_born_mail_parent_current')
            path.rmdir()
            sync_directory(path.parent)
        self.checkpoint('MAILDIRS_REMOVED')

    def record(self):
        f, b, p = self.fixture, self.bootstrap, self.purpose
        marker = self.stage/'fixture.json'
        marker_record, issuer = None, None
        if hasattr(f, 'marker_sha256') and not (self.phase == 'RESTORED'
                and f.report.get('cleanup_confirmed') is True):
            raw, metadata = read_regular(marker, 16384, self.end)
            require(marker in f.files and f.files[marker] == metadata
                and digest(raw) == f.marker_sha256, 'paired_actual_marker_custody')
            issuer = json.loads(raw)
            marker_record = {'path': 'fixture.json', 'metadata': list(metadata), 'sha256': digest(raw)}
            self.last_marker, self.issuer = marker_record, issuer
        elif self.phase == 'RESTORED':
            marker_record, issuer = self.last_marker, self.issuer
        if f.baseline is not None and not self.rows:
            self.rows = {row['username']: {'account': row['username'],
                'initial_full17_sha256': self.http.digest_fields(row, self.http.COLUMNS),
                'immutable15_sha256': self.http.digest_fields(row, self.http.NONCREDENTIAL_COLUMNS),
                'owned_current_full17_sha256': self.http.digest_fields(row, self.http.COLUMNS),
                'owned_current_postwrite_observed': False}
                for row in f.baseline}
        db = None
        if f.db_user_lease is not None and f.db_grants_lease is not None:
            db = {'name': 'osmap_account_mutation',
                'create': self.keep('db-create', f.db_user_lease),
                'grants': self.keep('db-grants', f.db_grants_lease)}
        targets = []
        for index, path in enumerate(BOOTSTRAP_TARGETS):
            if path not in b.before:
                continue
            prior = b.before[path]
            original = None
            if prior is not None:
                backup = b.backup/str(index)
                kept = self.retained_file(backup, 1048576)
                require(kept['sha256'] == prior['sha256'], 'paired_config_backup_hash')
                original = {'metadata': list(prior['metadata']), 'sha256': prior['sha256'], 'backup': kept}
            targets.append({'path': str(path), 'original': original})
        authorized = None
        if p.authorized_before is not None:
            old = p.authorized_before
            authorized = {'metadata': list(old['metadata']), 'sha256': old['sha256'],
                'backup': self.keep('authorized', old['data'])}
        rc = None
        if hasattr(b, 'original_rc'):
            rc = {'metadata': list(b.original_rc_identity), 'sha256': digest(b.original_rc),
                'backup': self.keep('rc', b.original_rc)}
        original = lambda values: {str(path): {'sha256': v[0], 'metadata': list(v[1])}
            for path, v in values.items()}
        public_rows = lambda values: {name: self.row_public(row) for name, row in values.items()}
        return {'version': 2, 'purpose': 'osmap-paired-password-recovery',
            'stage': str(self.stage), 'signed_base_commit': self.profile['source_base_commit'],
            'candidate_manifest_sha256': self.profile['candidate_manifest_sha256'],
            'sources': self.profile['sources'], 'module_sha256': self.profile['module_sha256'],
            'helper_sha256': self.profile['helper_sha256'],
            'issued_at': None if issuer is None else issuer['issued_at'],
            'expires_at': None if issuer is None else issuer['expires_at'],
            'sequence': self.sequence, 'phase': self.phase,
            'actor': {'pid': self.actor_pid, 'row': self.actor_row.decode('ascii')},
            'maildirs': self.maildirs, 'imap_absence_observed': self.imap_absence_observed,
            'mail_login_started': self.mail_login_started,
            'fixture_marker': marker_record, 'fixture_setup_uncertain': self.fixture_setup_uncertain,
            'helper_start_uncertain': self.helper_start_uncertain,
            'request_stop_confirmed': self.request_stop_confirmed,
            'restoration_attempted': self.restoration_attempted,
            'publications': self.intent,
            'fixture': {'files': {str(path): list(v) for path, v in f.files.items()},
                'dirs': {str(path): list(v) for path, v in f.dirs.items()},
                'borrowed_dirs': {str(path): [list(item) for item in v] for path, v in f.borrowed_dirs.items()},
                'roles': {name: {'uid': v[0], 'gid': v[1], 'home': v[2], 'shell': v[3],
                    'locked': True, 'group_members': list(f.groups[name][1])} for name, v in f.users.items()},
                'groups': {name: [v[0], list(v[1])] for name, v in f.groups.items()},
                'database_user': db, 'rows': list(self.rows.values()),
                'epoch_witnesses': self.epoch_witnesses,
                'original': original(f.original), 'master': list(f.master),
                'provisioning_started': f.provisioning_started, 'fragments_published': f.fragments_published,
                'local_client': False, 'sql_uncertain': f.sql_uncertain,
                'process_uncertain': f.process_uncertain, 'identity_uncertain': f.identity_uncertain,
                'creation_uncertain': f.creation_uncertain,
                'cleanup_confirmed': f.report.get('cleanup_confirmed') is True, 'rows_created': f.rows, 'db_user_created': f.db_user},
            'bootstrap': {'targets': targets,
                'owned': {str(path): {'metadata6': list(v[0]), 'sha256': v[1]} for path, v in b.owned.items()},
                'runtime_owned': {str(path): {'metadata6': list(v[0]), 'sha256': v[1]} for path, v in b.runtime_owned.items()},
                'original_running': getattr(b, 'original_running', None),
                'original_enabled': getattr(b, 'original_enabled', None),
                'original_master_rows': public_rows(getattr(b, 'original_master_rows', {})),
                'new_master_rows': public_rows(getattr(b, 'new_master_rows', {})),
                'activation_cleanup_leases': f.report.get('bootstrap_actual_activation_cleanup_leases', {}),
                'original_rc': rc, 'pf_prestate': getattr(b, 'pf_prestate', None),
                'stop_attempted': b.stop_attempted,
                'pf_loaded': b.pf_loaded, 'pf_load_attempted': b.pf_load_attempted, 'generation_activated': b.generation_activated,
                'activation_uncertain': b.activation_uncertain,
                'published': b.published, 'quiescent': b.quiescent,
                'fixture_master_before': list(b.fixture_master_before),
                'fixture_original_before': original(b.fixture_original_before),
                'publication_parent_before': b.publication_parent_before,
                'publication_parent_intent': b.publication_parent_intent,
                'publication_parent_current': b.publication_parent_current},
            'purpose_ssh': {'authorized_original': authorized,
                'owned': {str(path): {'metadata6': list(v[0]), 'sha256': v[1]} for path, v in p.owned.items()}}}

    def checkpoint(self, phase):
        require(type(phase) is str and re.fullmatch('[A-Z_]{1,40}', phase),
            'paired_fixed_receipt_phase')
        self.phase, self.sequence = phase, self.sequence + 1
        value = self.record()
        raw = json.dumps(value, sort_keys=True, separators=(',', ':')).encode('ascii')
        require(len(raw) <= 131072, 'paired_receipt_bound')
        if self.lease is None:
            require(not os.path.lexists(self.path), 'paired_receipt_collision')
        else:
            current, metadata = read_regular(self.path, 131072, self.end)
            require(metadata == self.lease and digest(current) == self.sha256,
                'paired_receipt_current_not_owned')
        # The receipt itself has no callback: its exact protected current inode
        # and hash are checked above; no recursive publication authority.
        own = {}
        publish(self.path, raw, 0o600, 0, 0, self.end, own, readback_cap=131072)
        current, metadata = read_regular(self.path, 131072, self.end)
        require(metadata[:6] == own[self.path][0] and digest(current) == digest(raw),
            'paired_receipt_readback')
        self.lease, self.sha256 = metadata, digest(raw)


class FixedServiceBootstrap:
    """Finite actual effects through the existing reviewed root fixture.

    Its existing bounded SQL/process/principal methods retain ownership and
    cleanup. No receipt or metadata Boolean may substitute for qualification.
    """
    def __init__(self, fixture, stage, end):
        self.fixture, self.stage, self.end = fixture, stage, end
        self.before, self.owned, self.rendered = {}, {}, {}
        self.backup = None
        self.published = False
        self.quiescent = False
        self.pf_loaded = False
        self.generation_activated = False
        self.qualification = 'NOT_RUN'
        self.created_role_names = []
        # The original map is retained as evidence; only the explicitly changed
        # public SQL leaf may acquire a new current expectation after rollback.
        self.fixture_original_before = dict(fixture.original)
        self.fixture_master_before = fixture.master
        self.restored_source_identities = []
        self.stop_attempted = []
        self.runtime_owned = {}
        self.activation_uncertain = False
        self.pf_load_attempted = False
        self.publication_parent_before = None
        self.publication_parent_intent = None
        self.publication_parent_current = None

    def check_time(self):
        before(self.end)
        self.fixture.remaining(True)

    def provision_restricted_role(self):
        self.check_time()
        require(tuple(row['username'] for row in self.fixture.baseline) == BOOTSTRAP_ACCOUNTS,
            'bootstrap_existing_owned_SQL_rows')
        for name in ('_osmapsql', '_osmaphash', '_osmapsubmit'):
            require(name not in self.fixture.users, 'bootstrap_new_purpose_role_collision')
            self.fixture.own_principal(name)
            self.created_role_names.append(name)
        require(self.fixture.sql("SELECT COUNT(*) FROM mysql.user WHERE User='osmap_account_mutation' AND Host='localhost';\n") == b'0\n',
            'bootstrap_restricted_DB_role_absent')
        import secrets
        password = secrets.token_hex(32)
        self.fixture.sql('CREATE USER ' + RESTRICTED_PRINCIPAL + " IDENTIFIED BY '" + password + "';\n", mutation=True)
        self.fixture.db_user = True
        self.fixture.sql('GRANT SELECT(username,password,modified,active,smtp_active),UPDATE(password,modified) ON postfixadmin.mailbox TO ' + RESTRICTED_PRINCIPAL + ';\n', mutation=True)
        grantee = 'CONVERT(0x' + RESTRICTED_PRINCIPAL.encode().hex() + ' USING utf8mb4)'
        raw = self.fixture.sql('SELECT COLUMN_NAME,PRIVILEGE_TYPE FROM information_schema.COLUMN_PRIVILEGES WHERE GRANTEE=' + grantee + " AND TABLE_SCHEMA='postfixadmin' AND TABLE_NAME='mailbox';\n")
        require(set(tuple(line.split('\t')) for line in raw.decode('ascii').splitlines()) == COLUMN_GRANTS,
            'bootstrap_exact_seven_column_grants')
        broad = self.fixture.sql('SELECT COUNT(*) FROM information_schema.USER_PRIVILEGES WHERE GRANTEE=' + grantee + " AND PRIVILEGE_TYPE<>'USAGE'; SELECT COUNT(*) FROM information_schema.SCHEMA_PRIVILEGES WHERE GRANTEE=" + grantee + '; SELECT COUNT(*) FROM information_schema.TABLE_PRIVILEGES WHERE GRANTEE=' + grantee + ';\n')
        require(broad == b'0\n0\n0\n', 'bootstrap_no_broad_SQL_grants')
        self.fixture.db_user_lease = self.fixture.sql('SHOW CREATE USER ' + RESTRICTED_PRINCIPAL + ';\n')
        self.fixture.db_grants_lease = self.fixture.sql('SHOW GRANTS FOR ' + RESTRICTED_PRINCIPAL + ';\n')
        require(all(0 < len(value) <= 4096 for value in
            (self.fixture.db_user_lease, self.fixture.db_grants_lease)), 'bootstrap_SQL_role_lease')
        config = Path('/etc/osmap/account-mariadb.cnf')
        require(not os.path.lexists(config) and not os.path.lexists(RUNTIME/'sql-endpoint.json'),
            'bootstrap_SQL_config_collision')
        self.fixture.publish(config, ('[client]\nuser=osmap_account_mutation\npassword=' + password
            + '\nprotocol=SOCKET\nsocket=/var/run/mysql/mysql.sock\n').encode(),
            0o440, self.fixture.users['_osmapsql'][1])
        self.fixture.publish(RUNTIME/'sql-endpoint.json', json.dumps({
            'version': 1, 'authority': 'mail.blackbagsecurity.com',
            'purpose': 'osmap-account-mutation', 'server': '_mysql',
            'socket': '/var/run/mysql/mysql.sock', 'database_user': 'osmap_account_mutation'},
            sort_keys=True).encode())
        password = None

    def prepare_publication_reachability(self):
        # Reachability only: exact server-owned ticket/peer/lifetime checks in
        # Rust and the native plugin remain mandatory and independently tested.
        self.check_time()
        require(self.fixture.helper is None and not self.fixture.process_uncertain,
            'bootstrap_publication_requires_absent_helper')
        import grp
        import pwd
        role = self.fixture.users.get('_osmapcontrol')
        require(type(role) is tuple and len(role) == 4
            and pwd.getpwnam('_osmapcontrol').pw_uid == role[0]
            and pwd.getpwnam('_osmapcontrol').pw_gid == role[1]
            and grp.getgrnam('_osmapcontrol').gr_gid == role[1]
            and 0 < role[1] < 2**32 - 1, 'bootstrap_actual_control_identity')
        path = RUNTIME/'imap-publication.json'
        raw, metadata = read_regular(path, 4096, self.end)
        require(path in self.fixture.files and self.fixture.files[path] == metadata
            and metadata[2:6] == (0, 0, stat.S_IFREG | 0o600, 1),
            'bootstrap_fixture_publication_identity')
        record = json.loads(raw)
        require(type(record) is dict and set(record) ==
            {'version', 'authority', 'purpose', 'master_pid', 'connector_gid'}
            and record['version'] == 1 and record['authority'] == 'mail.blackbagsecurity.com'
            and record['purpose'] == 'osmap-imap-publication'
            and record['master_pid'] == int(self.fixture.master[0])
            and type(record['connector_gid']) is int and record['connector_gid'] > 0,
            'bootstrap_existing_fixture_publication_shape')
        parent = Path('/var/run/osmap-account')
        parents(parent)
        current = identity(parent.lstat())
        require(current[2:5] == (0, record['connector_gid'], stat.S_IFDIR | 0o750)
            and current[5] >= 2 and not tuple(parent.iterdir()), 'bootstrap_empty_owned_publication_parent')
        if parent in self.fixture.dirs:
            require(self.fixture.dirs[parent] == current[:6],
                'bootstrap_owned_publication_parent_identity')
        else:
            borrowed = self.fixture.borrowed_dirs.get(parent)
            require(type(borrowed) is tuple and len(borrowed) == 3
                and borrowed[2] == current[:6], 'bootstrap_borrowed_publication_parent_identity')
        self.publication_parent_before = current
        record['connector_gid'] = role[1]
        try:
            publish(path, json.dumps(record, sort_keys=True).encode(), 0o600, 0, 0,
                self.end, self.runtime_owned, recovery=getattr(self, 'recovery', None))
        finally:
            # A failed replace/fsync is not a licence to select a new inode.
            # Update deletion custody only for this exact born/current leaf.
            actual, actual_metadata = read_regular(path, 4096, self.end)
            if path in self.runtime_owned and actual_metadata[:6] == self.runtime_owned[path][0]:
                require(digest(actual) == self.runtime_owned[path][1],
                    'bootstrap_owned_publication_readback')
                self.fixture.files[path] = actual_metadata
            else:
                require(actual_metadata == metadata and actual == raw,
                    'bootstrap_publication_current_uncertain')
        require(identity(parent.lstat()) == current and not tuple(parent.iterdir()),
            'bootstrap_publication_parent_changed')
        self.publication_parent_intent = {'before': list(current), 'gid': role[1]}
        if hasattr(self, 'recovery'):
            self.recovery.checkpoint('PUBLICATION_PARENT_INTENT')
        os.chown(parent, 0, role[1])
        changed = identity(parent.lstat())
        require(changed[:3] == current[:3] and changed[3] == role[1]
            and changed[4:6] == current[4:6] and not tuple(parent.iterdir()),
            'bootstrap_publication_parent_group_readback')
        self.publication_parent_current = changed
        if parent in self.fixture.dirs:
            self.fixture.dirs[parent] = changed[:6]
        else:
            before, full, _ = self.fixture.borrowed_dirs[parent]
            self.fixture.borrowed_dirs[parent] = (before, full, changed[:6])
        if hasattr(self, 'recovery'):
            self.recovery.checkpoint('PUBLICATION_PARENT_READBACK')
        self.fixture.report['bootstrap_publication_reachability'] = {
            'path': str(parent), 'original_identity': current,
            'changed_identity': changed, 'group': '_osmapcontrol',
            'publication_authority_qualified': False,
        }

    def capture_activation_cleanup_leases(self):
        require(self.generation_activated and self.activation_uncertain,
            'bootstrap_actual_activation_required_for_leases')
        publication = RUNTIME/'imap-publication.json'
        generation = RUNTIME/'submission-generation.json'
        raw, metadata = read_regular(publication, 4096, self.end)
        record = json.loads(raw)
        require(metadata[2:6] == (0, 0, stat.S_IFREG | 0o600, 1)
            and type(record) is dict and set(record) ==
            {'version', 'authority', 'purpose', 'master_pid', 'connector_gid'}
            and record['version'] == 1 and record['authority'] == 'mail.blackbagsecurity.com'
            and record['purpose'] == 'osmap-imap-publication'
            and record['master_pid'] == int(self.new_master_rows['dovecot'][0])
            and record['connector_gid'] == self.fixture.users['_osmapcontrol'][1],
            'bootstrap_actual_publication_cleanup_shape')
        generated, generation_metadata = read_regular(generation, 16384, self.end)
        current = json.loads(generated)
        require(generation_metadata[2:6] == (0, 0, stat.S_IFREG | 0o600, 1)
            and type(current) is dict and set(current) == {'version', 'base', 'prestates'}
            and current['version'] == 1 and type(current['base']) is dict
            and type(current['prestates']) is list and len(current['prestates']) == 3
            and generation not in self.fixture.files,
            'bootstrap_actual_generation_cleanup_shape')
        # Both reads must pass before either current deletion lease changes.
        # These leases grant owned cleanup only, not service readiness.
        self.fixture.files[publication] = metadata
        self.fixture.files[generation] = generation_metadata
        self.fixture.report['bootstrap_actual_activation_cleanup_leases'] = {
            str(publication): {'identity': metadata, 'sha256': digest(raw)},
            str(generation): {'identity': generation_metadata, 'sha256': digest(generated)},
        }
        self.activation_uncertain = False

    def restore_publication_parent(self):
        if self.publication_parent_current is None:
            return
        require(self.fixture.helper is None or self.fixture.helper_stopped,
            'bootstrap_parent_restore_requires_absent_helper')
        path = Path('/var/run/osmap-account')
        current = identity(path.lstat())
        # The server may have created and then removed its owned socket; the
        # directory's inode/owner/group/full mode/link count must stay exact.
        require(current[:6] == self.publication_parent_current[:6]
            and not tuple(path.iterdir()), 'bootstrap_parent_restore_not_owned')
        old = self.publication_parent_before
        os.chown(path, old[2], old[3])
        restored = identity(path.lstat())
        require(restored[:6] == old[:6] and not tuple(path.iterdir()),
            'bootstrap_parent_restore_readback')
        if path in self.fixture.dirs:
            self.fixture.dirs[path] = restored[:6]
        else:
            before, full, _ = self.fixture.borrowed_dirs[path]
            self.fixture.borrowed_dirs[path] = (before, full, restored[:6])
        self.publication_parent_current = None

    def snapshot_targets(self, expected):
        require(set(expected) == {str(path) for path in BOOTSTRAP_TARGETS},
            'bootstrap_fixed_target_pins')
        self.check_time()
        self.before = {path: snapshot(path, expected[str(path)], 1048576, self.end)
            for path in BOOTSTRAP_TARGETS}
        require(PUBLIC_SQL in self.fixture_original_before
            and self.before[PUBLIC_SQL] is not None
            and self.fixture_original_before[PUBLIC_SQL] ==
                (self.before[PUBLIC_SQL]['sha256'], self.before[PUBLIC_SQL]['metadata']),
            'bootstrap_original_SQL_fixture_identity')
        self.backup = self.stage/'bootstrap-before'
        self.backup.mkdir(mode=0o700)
        for i, path in enumerate(BOOTSTRAP_TARGETS):
            prior = self.before[path]
            if prior is not None:
                write_exclusive(self.backup/str(i), prior['data'], self.end)
        sync_directory(self.backup)
        if hasattr(self, 'recovery'):
            self.recovery.checkpoint('CONFIG_BACKUPS_READY')

    def render_configuration(self, source_pins, template_pins, plugin_sha256):
        self.check_time()
        require(self.before and 1 <= len(source_pins) <= 64
            and '/etc/dovecot/dovecot.conf' in source_pins
            and str(PUBLIC_SQL) in source_pins, 'bootstrap_current_public_sources')
        sources = {}
        for name, expected in source_pins.items():
            path = Path(name)
            require(path.is_absolute() and '..' not in path.parts
                and path.is_relative_to('/etc/dovecot'), 'bootstrap_source_scope')
            raw, _ = read_regular(path, 131072, self.end)
            require(raw.isascii() and digest(raw) == expected, 'bootstrap_source_pin')
            sources[name] = raw
        require(sum(map(len, sources.values())) <= 1048576, 'bootstrap_source_total')
        main = sources['/etc/dovecot/dovecot.conf']
        require(any(line.strip() in (b'!include conf.d/*.conf', b'!include_try conf.d/*.conf',
            b'!include /etc/dovecot/conf.d/*.conf', b'!include_try /etc/dovecot/conf.d/*.conf')
            for line in main.splitlines()), 'bootstrap_public_fragment_selected')
        require(self.before[PUBLIC_SQL] is not None
            and sources[str(PUBLIC_SQL)] == self.before[PUBLIC_SQL]['data'],
            'bootstrap_selected_SQL_continuity')
        # The exact managed-only userdb group must not overwrite an existing
        # selected projection or nonempty effective public group requirement.
        for raw in sources.values():
            for line in raw.splitlines():
                match = re.fullmatch(rb'mail_access_groups\s*=\s*(.*)', line.strip())
                require(match is None or not match[1].strip(),
                    'bootstrap_existing_mail_access_groups_requires_preservation')
        selected = {}
        for key in ('ssl_cert', 'ssl_key'):
            values = []
            for raw in sources.values():
                for line in raw.splitlines():
                    match = re.fullmatch(key.encode() + rb'\s*=\s*(<[^\r\n]+)', line.strip())
                    if match:
                        values.append(match[1])
            require(len(values) == 1 and re.fullmatch(rb'<(/[A-Za-z0-9_./+:-]+)', values[0])
                and b'/../' not in values[0], 'bootstrap_selected_existing_TLS')
            selected[key] = values[0]
        names = ('dovecot.conf.in', 'dovecot-sql.conf.ext.in', 'pf-anchor.conf',
            'postfix-master.cf.fragment')
        require(set(template_pins) == set(names), 'bootstrap_fixed_template_set')
        templates = {}
        for name in names:
            raw, _ = read_regular(self.stage/'source/maint/account-runtime/submission'/name,
                16384, self.end)
            require(digest(raw) == template_pins[name], 'bootstrap_template_pin')
            templates[name] = raw
        key, _ = read_regular(RUNTIME/'imap-policy.key', 64, self.end)
        require(re.fullmatch(rb'[a-f0-9]{64}', key), 'bootstrap_existing_policy_key')
        sql = fixed_assignments(sources[str(PUBLIC_SQL)])
        # The authoritative DSN is copied privately, never output or converted
        # into a mutation credential. The separate role above owns mutation.
        dsn = sql.get('connect', '').encode('ascii')
        authoritative_dsn(dsn)
        submission = render_tokens(templates['dovecot.conf.in'], {
            b'EXISTING_SSL_CERT_VALUE': selected['ssl_cert'],
            b'EXISTING_SSL_KEY_VALUE': selected['ssl_key'],
            b'EXISTING_POLICY_API_HEADER': b'X-OSMAP-Policy: ' + key})
        frontend_sql = render_tokens(templates['dovecot-sql.conf.ext.in'], {
            b'EXISTING_AUTHORITATIVE_READONLY_SQL_DSN': dsn})
        require('_osmapcontrol' in self.fixture.users, 'bootstrap_actual_control_role')
        control_gid = self.fixture.users['_osmapcontrol'][1]
        imap = (b'# Fixed managed Alice/Bob hook; unrelated users bypass the final hook.\n'
            b'auth_cache_size = 0\n'
            b'auth_policy_server_url = http://127.0.0.1:10058/epoch/\n'
            b'auth_policy_server_api_header = X-OSMAP-Policy: ' + key + b'\n'
            b'auth_policy_hash_nonce = osmap-account-submission-epoch-v1\n'
            b'auth_policy_request_attributes = login=%{requested_username} protocol=%s session_id=%{session} phase=%{passdb:osmap_epoch_phase}\n'
            b'auth_policy_check_before_auth = yes\n'
            b'auth_policy_check_after_auth = yes\n'
            b'auth_policy_report_after_auth = no\n'
            b'auth_policy_reject_on_fail = no\n'
            b'auth_policy_log_only = no\n'
            b'auth_policy_server_timeout_msecs = 500\n'
            b'imap_hibernate_timeout = 0\n'
            b'protocol imap {\n mail_plugins = $mail_plugins osmap_imap_epoch\n}\n'
            b'service imap {\n client_limit = 1\n service_count = 1\n}\n')
        master, removed = render_postfix_master(self.before[POSTFIX_MASTER]['data'],
            templates['postfix-master.cf.fragment'])
        main_cf = self.before[POSTFIX_MAIN]['data']
        if not re.search(rb'(?m)^\s*smtpd_sasl_auth_enable\s*=', main_cf):
            main_cf += b'\nsmtpd_sasl_auth_enable = no\n'
        else:
            main_cf = replace_assignment(main_cf, 'smtpd_sasl_auth_enable', 'no')
        module, _ = read_regular(self.stage/'lib90_osmap_imap_epoch_plugin.so', 1048576, self.end)
        require(digest(module) == plugin_sha256 and module.startswith(b'\x7fELF'),
            'bootstrap_matching_candidate_module')
        self.rendered = {
            PUBLIC_SQL: (managed_user_query(sources[str(PUBLIC_SQL)]), 0o600, 0),
            PUBLIC_IMAP: (imap, 0o600, 0),
            SUBMISSION_ROOT/'dovecot.conf': (submission, 0o440, control_gid),
            SUBMISSION_ROOT/'dovecot-sql.conf.ext': (frontend_sql, 0o600, 0),
            POSTFIX_MAIN: (main_cf, stat.S_IMODE(self.before[POSTFIX_MAIN]['metadata'][4]),
                self.before[POSTFIX_MAIN]['metadata'][3]),
            POSTFIX_MASTER: (master, stat.S_IMODE(self.before[POSTFIX_MASTER]['metadata'][4]),
                self.before[POSTFIX_MASTER]['metadata'][3]),
            PF_MAIN: (render_pf(self.before[PF_MAIN]['data']),
                stat.S_IMODE(self.before[PF_MAIN]['metadata'][4]), self.before[PF_MAIN]['metadata'][3]),
            PF_ANCHOR: (templates['pf-anchor.conf'], 0o600, 0),
            PLUGIN: (module, 0o444, 0),
        }
        self.source_pins = source_pins.copy()
        self.removed_public_submission_hashes = removed

    def publish_rendered(self):
        require(self.before and self.quiescent and set(self.rendered) == set(BOOTSTRAP_TARGETS),
            'bootstrap_complete_fixed_render')
        for path in BOOTSTRAP_TARGETS:
            self.check_time()
            same_snapshot(path, self.before[path], 1048576, self.end)
            data, mode, gid = self.rendered[path]
            require(type(data) is bytes and len(data) <= 1048576, 'bootstrap_rendered_bound')
            publish(path, data, mode, 0, gid, self.end, self.owned,
                recovery=getattr(self, 'recovery', None))
        self.published = True

    def capture_availability(self):
        self.check_time()
        require(self.end - time.monotonic() >= 120, 'bootstrap_reserved_rollback_before_stop')
        require_helper_absent(set(), self.end)
        enabled = self.fixture.run(('/usr/sbin/rcctl', 'ls', 'on'),
            'bootstrap_original_enablement', cap=16384, seconds=5).splitlines()
        self.original_enabled = {name: name.encode() in enabled for name in ('dovecot', 'postfix')}
        self.original_running = {}
        self.original_master_rows = {}
        for name, pidfile, image in (
            ('dovecot', '/var/dovecot/master.pid', 'dovecot'),
            ('postfix', '/var/spool/postfix/pid/master.pid', 'master'),
        ):
            try:
                raw, _ = read_regular(Path(pidfile), 128, self.end)
            except FileNotFoundError:
                self.original_running[name] = False
                continue
            require(re.fullmatch(rb'[1-9][0-9]{0,9}\n?', raw), 'bootstrap_master_pidfile')
            pid = str(int(raw))
            row = self.fixture.run(('/bin/ps', '-p', pid, '-o', 'pid=,ppid=,uid=,lstart=,comm='),
                'bootstrap_current_master_birth', cap=2048, seconds=5)
            fields = row.split()
            require(len(fields) == 9 and fields[0] == pid.encode() and fields[2] == b'0'
                and fields[-1].rsplit(b'/', 1)[-1] == image.encode(), 'bootstrap_current_master_identity')
            self.original_master_rows[name] = (pid, row)
            self.original_running[name] = True
        require(not Path('/var/run/osmap-account-submission/master.pid').exists(),
            'bootstrap_existing_dedicated_instance_requires_review')
        self.original_rc, self.original_rc_identity = read_regular(Path('/etc/rc.conf.local'),
            131072, self.end)
        if hasattr(self, 'recovery'):
            info = self.fixture.run(('/sbin/pfctl', '-s', 'info'),
                'paired_original_PF_status', cap=16384, seconds=5)
            require(info.startswith(b'Status: Enabled'), 'paired_PF_original_enabled')
            rules = self.fixture.run(('/sbin/pfctl', '-sr'),
                'paired_original_effective_PF_rules', cap=131072, seconds=5)
            anchor = self.fixture.run(('/sbin/pfctl', '-a', 'osmap/account-submission', '-sr'),
                'paired_original_fixed_anchor_absence', cap=16384, seconds=5)
            require(not anchor.strip(), 'paired_original_anchor_not_empty')
            self.pf_prestate = {'enabled': True, 'rules': self.recovery.keep('pf-rules', rules),
                'anchor_empty': True, 'anchor_sha256': digest(anchor)}
        if hasattr(self, 'recovery'):
            self.recovery.checkpoint('AVAILABILITY_CAPTURED')

    def selected_absent(self):
        # Source-fixed installed service images, not numeric historical signals.
        # No matching master/worker image may remain before config restoration.
        images = (
            '/usr/local/sbin/dovecot',
            '/usr/local/libexec/dovecot/auth',
            '/usr/local/libexec/dovecot/auth-worker',
            '/usr/local/libexec/dovecot/anvil',
            '/usr/local/libexec/dovecot/config',
            '/usr/local/libexec/dovecot/imap',
            '/usr/local/libexec/dovecot/imap-login',
            '/usr/local/libexec/dovecot/ipc',
            '/usr/local/libexec/dovecot/lmtp',
            '/usr/local/libexec/dovecot/log',
            '/usr/local/libexec/dovecot/stats',
            '/usr/local/libexec/dovecot/submission',
            '/usr/local/libexec/dovecot/submission-login',
            '/usr/local/libexec/postfix/master',
            '/usr/local/libexec/postfix/smtpd',
        )
        for path in images:
            if not Path(path).exists():
                continue
            raw = self.fixture.run(('/usr/bin/fstat', '-n', path),
                'bootstrap_selected_image_absence', cap=65536, seconds=5, cleanup=True)
            rows = raw.splitlines()
            require(len(rows) == 1 and rows[0].split()[:4] == [b'USER', b'CMD', b'PID', b'FD'],
                'bootstrap_selected_service_absence_unconfirmed')

    def quiesce_original(self):
        self.check_time()
        require(self.end - time.monotonic() >= 120, 'bootstrap_reserved_rollback_before_stop')
        # Recheck selected source and exact current master births before the
        # supported service operations; no observed PID is ever signalled.
        for path, prior in self.before.items():
            same_snapshot(path, prior, 1048576, self.end)
        for name in ('postfix', 'dovecot'):
            if not self.original_running[name]:
                continue
            pid, prior = self.original_master_rows[name]
            current = self.fixture.run(('/bin/ps', '-p', pid, '-o', 'pid=,ppid=,uid=,lstart=,comm='),
                'bootstrap_recheck_current_master', cap=2048, seconds=5)
            require(current == prior, 'bootstrap_original_master_changed')
            # A nonzero supported stop may still have changed availability.
            # Retain the attempted scope before dispatch for finite restoration.
            self.stop_attempted.append(name)
            if hasattr(self, 'recovery'):
                self.recovery.checkpoint('SERVICE_STOP_INTENT')
            self.fixture.run(('/usr/sbin/rcctl', 'stop', name),
                'bootstrap_stop_original_' + name, cap=16384, seconds=10)
        self.selected_absent()
        self.quiescent = True
        if hasattr(self, 'recovery'):
            self.recovery.checkpoint('SERVICES_QUIESCENT')

    def validate_published_syntax(self):
        require(self.published and self.quiescent, 'bootstrap_quiescent_publication_required')
        # Actual selected paths are checked while ingress is stopped. This
        # avoids a second rewritten configuration tree and mixed live readers.
        self.fixture.run(('/usr/local/bin/doveconf', '-c', '/etc/dovecot/dovecot.conf', '-n'),
            'bootstrap_public_dovecot_syntax', cap=131072, seconds=10)
        self.fixture.run(('/usr/local/bin/doveconf', '-c',
            '/etc/osmap/account-submission/dovecot.conf', '-n'),
            'bootstrap_submission_dovecot_syntax', cap=65536, seconds=10)
        self.fixture.run(('/usr/local/sbin/postconf', '-M'),
            'bootstrap_selected_postfix_syntax', cap=65536, seconds=10)
        self.fixture.run(('/sbin/pfctl', '-nf', '/etc/pf.conf'),
            'bootstrap_selected_PF_syntax', cap=16384, seconds=10)

    def load_pf_and_activate(self):
        self.check_time()
        require(self.published and self.quiescent and self.end - time.monotonic() >= 120,
            'bootstrap_activation_and_rollback_reserve')
        # Ordinary rules reload preserves states; never -F states or -F all.
        # The fixed anchor was required absent before this candidate.
        self.pf_load_attempted = True
        if hasattr(self, 'recovery'):
            self.recovery.checkpoint('PF_LOAD_INTENT')
        self.fixture.run(('/sbin/pfctl', '-f', '/etc/pf.conf'),
            'bootstrap_load_selected_PF', cap=16384, seconds=10)
        self.pf_loaded = True
        self.activation_uncertain = True
        if hasattr(self, 'recovery'):
            self.recovery.checkpoint('GENERATION_ACTIVATION_INTENT')
        self.fixture.run((str(BINARY), '--activate-submission-generation'),
            'bootstrap_actual_Rust_generation_activation', cap=65536,
            seconds=min(240, self.end - time.monotonic() - 90),
            absolute=self.end - 90)
        self.quiescent = False
        self.generation_activated = True
        # Only the actual root-owned product may create the Generation. This
        # method never writes or restores one and does not claim plugin proof.
        generation, _ = read_regular(RUNTIME/'submission-generation.json', 16384, self.end)
        record = json.loads(generation)
        require(type(record) is dict and set(record) == {'version', 'base', 'prestates'}
            and record['version'] == 1, 'bootstrap_actual_generation_shape')
        self.new_master_rows = {}
        for name, pidfile, image in (
            ('dovecot', '/var/dovecot/master.pid', 'dovecot'),
            ('submission', '/var/run/osmap-account-submission/master.pid', 'dovecot'),
            ('postfix', '/var/spool/postfix/pid/master.pid', 'master'),
        ):
            raw, _ = read_regular(Path(pidfile), 128, self.end)
            require(re.fullmatch(rb'[1-9][0-9]{0,9}\n?', raw), 'bootstrap_new_master_pidfile')
            pid = str(int(raw))
            row = self.fixture.run(('/bin/ps', '-p', pid, '-o', 'pid=,ppid=,uid=,lstart=,comm='),
                'bootstrap_new_master_birth', cap=2048, seconds=5)
            fields = row.split()
            require(len(fields) == 9 and fields[0] == pid.encode() and fields[2] == b'0'
                and fields[-1].rsplit(b'/', 1)[-1] == image.encode(),
                'bootstrap_new_master_identity')
            self.new_master_rows[name] = (pid, row)
        self.capture_activation_cleanup_leases()
        if hasattr(self, 'recovery'):
            self.recovery.checkpoint('GENERATION_ACTIVE')

    def restore_availability(self):
        require(not self.fixture.process_uncertain and not self.activation_uncertain,
            'bootstrap_restore_processes_or_activation_uncertain')
        if not self.owned and not self.pf_loaded and not self.generation_activated:
            # A failed first/second stop is not evidence that both services are
            # absent. No configuration was published, so preserve and recheck
            # those exact originals, then restore supported original services.
            for path, prior in self.before.items():
                same_snapshot(path, prior, 1048576, self.end)
            self.restore_original_availability(partial_stop=True)
            return
        if self.fixture.helper is not None and not self.fixture.helper_stopped:
            self.fixture.stop_helper()
        # Recheck ownership before supported service controls. A foreign
        # concurrent config change retains state for root reconciliation.
        for path in self.owned:
            data, metadata = read_regular(path, 1048576, self.end)
            require(metadata[:6] == self.owned[path][0] and digest(data) == self.owned[path][1],
                'bootstrap_stop_restore_config_not_owned')
        if getattr(self, 'generation_activated', False):
            require(set(getattr(self, 'new_master_rows', {})) == {'dovecot', 'submission', 'postfix'},
                'bootstrap_new_master_custody_incomplete')
            for name in ('submission', 'postfix', 'dovecot'):
                pid, prior = self.new_master_rows[name]
                row = self.fixture.run(('/bin/ps', '-p', pid, '-o', 'pid=,ppid=,uid=,lstart=,comm='),
                    'bootstrap_restore_current_master_birth', cap=2048, seconds=5, cleanup=True)
                require(row == prior, 'bootstrap_restore_master_changed')
            self.fixture.run(('/usr/local/sbin/dovecot', '-c',
                '/etc/osmap/account-submission/dovecot.conf', 'stop'),
                'bootstrap_stop_owned_submission', cap=16384, seconds=10, cleanup=True)
            for name in ('postfix', 'dovecot'):
                self.fixture.run(('/usr/sbin/rcctl', 'stop', name),
                    'bootstrap_stop_owned_' + name, cap=16384, seconds=10, cleanup=True)
        self.selected_absent()
        if hasattr(self, 'recovery'):
            self.recovery.imap_absence_observed = True
            self.recovery.checkpoint('SELECTED_SERVICES_ABSENT')
        self.restore_owned_files()
        if getattr(self, 'pf_loaded', False):
            self.fixture.run(('/sbin/pfctl', '-nf', '/etc/pf.conf'),
                'bootstrap_original_PF_syntax', cap=16384, seconds=10, cleanup=True)
            self.fixture.run(('/sbin/pfctl', '-f', '/etc/pf.conf'),
                'bootstrap_restore_original_PF', cap=16384, seconds=10, cleanup=True)
            self.fixture.run(('/sbin/pfctl', '-a', 'osmap/account-submission', '-F', 'rules'),
                'bootstrap_remove_only_owned_anchor', cap=16384, seconds=10, cleanup=True)
        self.restore_original_availability(partial_stop=False)

    def restore_original_availability(self, *, partial_stop):
        require(type(partial_stop) is bool, 'bootstrap_restore_availability_mode')
        for name in ('dovecot', 'postfix'):
            if self.original_running[name] and (not partial_stop or name in self.stop_attempted):
                self.fixture.run(('/usr/sbin/rcctl', 'start', name),
                    'bootstrap_restore_original_' + name, cap=16384, seconds=10, cleanup=True)
        for name in ('dovecot', 'postfix'):
            if self.original_running[name]:
                self.fixture.run(('/usr/sbin/rcctl', 'check', name),
                    'bootstrap_restored_running_' + name, cap=16384, seconds=5, cleanup=True)
        enabled = self.fixture.run(('/usr/sbin/rcctl', 'ls', 'on'),
            'bootstrap_restore_enablement_witness', cap=16384, seconds=5, cleanup=True).splitlines()
        require({name: name.encode() in enabled for name in ('dovecot', 'postfix')} == self.original_enabled,
            'bootstrap_original_enablement_changed')
        rc, rc_identity = read_regular(Path('/etc/rc.conf.local'), 131072, self.end)
        require(rc == self.original_rc and rc_identity == self.original_rc_identity,
            'bootstrap_unrelated_rc_configuration_changed')
        # Config and availability restoration are prerequisites for replacing
        # the expected master birth in this one deliberate migration. This is
        # never used after a password-time unexpected service replacement.
        self.fixture.original_config_current()
        if self.original_running['dovecot']:
            restored_master = self.fixture.master_row()
            if partial_stop and 'dovecot' not in self.stop_attempted:
                require(restored_master == self.fixture_master_before,
                    'bootstrap_untouched_original_master_changed')
            else:
                self.fixture.report['bootstrap_master_restoration'] = {
                    'original_birth': self.fixture_master_before,
                    'restored_birth': restored_master,
                    'original_master_preserved': False,
                    'TCP_sessions_restored': False,
                }
                self.fixture.master = restored_master
        self.fixture.report['bootstrap_original_before_map'] = {
            str(path): {'sha256': value[0], 'identity': value[1]}
            for path, value in self.fixture_original_before.items()}
        self.fixture.report['bootstrap_source_restorations'] = self.restored_source_identities.copy()
        self.restore_publication_parent()

    def restore_owned_files(self):
        require((self.fixture.helper is None or self.fixture.helper_stopped)
            and not self.fixture.process_uncertain,
            'bootstrap_restore_requires_actual_helper_absence')
        for path in reversed(BOOTSTRAP_TARGETS):
            if path not in self.owned:
                continue
            prior = self.before[path]
            try:
                same_snapshot(path, prior, 1048576, self.end)
                continue
            except Refused:
                pass
            current, metadata = read_regular(path, 1048576, self.end)
            require(metadata[:6] == self.owned[path][0] and digest(current) == self.owned[path][1],
                'bootstrap_restore_current_not_owned')
            if prior is None:
                path.unlink()
                sync_directory(path.parent)
                require(not os.path.lexists(path), 'bootstrap_restore_absence_unknown')
            else:
                old = prior['metadata']
                publish(path, prior['data'], stat.S_IMODE(old[4]), old[2], old[3], self.end, {},
                    recovery=getattr(self, 'recovery', None))
                restored, actual = read_regular(path, 1048576, self.end)
                require(restored == prior['data'] and digest(restored) == prior['sha256']
                    and actual[2:6] == old[2:6], 'bootstrap_restore_readback_unknown')
                if path in self.fixture_original_before:
                    require(path == PUBLIC_SQL and self.fixture.original[path] ==
                        self.fixture_original_before[path] and
                        self.fixture_original_before[path] == (prior['sha256'], old),
                        'bootstrap_restore_fixture_refresh_scope')
                    self.restored_source_identities.append({
                        'path': str(path), 'original_identity': old,
                        'owned_replaced_identity': metadata,
                        'restored_identity': actual, 'restored_content': True,
                        'original_inode_preserved': False,
                    })
                    self.fixture.original[path] = (prior['sha256'], actual)
        self.published = False





class FixedPurposeSsh:
    """Two exact qualification identities; no operator-key or private-byte read.

    Runs through the existing root fixture's bounded command/owned-disposition
    methods. This provisions files only: SSH/native helper qualification and
    complete remote worker disposition remain the root custodian's duties.
    """
    NAMES = ('admission', 'mutation')
    KEYS = Path('/var/lib/osmap-bridge/keys')
    AUTHORIZED = Path('/var/lib/osmap-relay/.ssh/authorized_keys')
    AUTHORIZED_OBSERVED = (1024, 907247, 0, 0, 33188, 1, 355, 1792588146025100892, 1792588146025100892)
    CONNECTORS = {
        'admission': (Path('/usr/local/libexec/osmap/account-runtime/osmap_account_admission_connector'),
            '3df6054a42a90fc7a3d62bf46a9a2c59f3a5f59f10075784e7440f599f853973'),
        'mutation': (Path('/usr/local/libexec/osmap/account-runtime/osmap_account_mutation_connector'),
            'b20a6b92ce56198d16d85e385dd4c25edad7fc7fd1cf937a7bf12d1feef32ebe')}

    def __init__(self, fixture, stage, end):
        self.fixture, self.stage, self.end = fixture, stage, end
        self.stage_files, self.keys, self.owned = {}, {}, {}
        self.authorized_before = None
        self.stage_identity = None
        self.keys_identity = None
        self.report = {'native_qualification': False, 'private_bytes_read': False,
            'SSH_authentication': 'NOT_RUN', 'file_cleanup_confirmed': False}

    def check(self, host):
        before(self.end)
        self.fixture.remaining(True)
        require(os.getuid() == os.geteuid() == 0 and socket.gethostname() == host,
            'fixed_purpose_SSH_authority')

    @staticmethod
    def public_key(raw, purpose):
        import base64
        require(type(raw) is bytes and purpose in FixedPurposeSsh.NAMES
            and len(raw) <= 256, 'fixed_purpose_public_bound')
        match = re.fullmatch(rb'ssh-ed25519 ([A-Za-z0-9+/]+={0,2}) osmap-account-'
            + purpose.encode('ascii') + rb'\n', raw)
        require(match is not None, 'fixed_purpose_public_shape')
        try:
            decoded = base64.b64decode(match[1], validate=True)
        except ValueError:
            raise Refused('fixed_purpose_public_encoding') from None
        require(len(decoded) == 51 and decoded[:19] == b'\0\0\0\x0bssh-ed25519\0\0\0\x20',
            'fixed_purpose_ed25519_blob')
        return raw.rstrip(b'\n')

    @classmethod
    def authorized(cls, original, public):
        require(type(original) is bytes and 0 < len(original) <= 131072
            and b'\0' not in original and set(public) == set(cls.NAMES),
            'fixed_authorized_original')
        lines = {name: cls.public_key(public[name], name) for name in cls.NAMES}
        require(lines['admission'].split()[1] != lines['mutation'].split()[1],
            'distinct_purpose_keys_required')
        for name, (path, _) in cls.CONNECTORS.items():
            require(str(path).encode() not in original and lines[name].split()[1] not in original
                and ('osmap-account-' + name).encode() not in original,
                'purpose_entry_collision')
        separator = b'' if original.endswith(b'\n') else b'\n'
        additions = b''.join(b'restrict,command="' + str(cls.CONNECTORS[name][0]).encode()
            + b'" ' + lines[name] + b'\n' for name in cls.NAMES)
        return original + separator + additions

    def frontend_generate(self):
        import pwd
        self.check('obsd1.blackbagsecurity.com')
        bridge = pwd.getpwnam('_osmapbridge')
        require((bridge.pw_uid, bridge.pw_gid) == (1003, 1004), 'observed_bridge_identity')
        require(self.stage.parent == Path('/var/lib') and
            re.fullmatch('osmap-account-purpose-[a-f0-9]{16}', self.stage.name),
            'fixed_purpose_stage_name')
        parents(self.stage)
        m = self.stage.lstat()
        require(stat.S_ISDIR(m.st_mode) and (m.st_uid, m.st_gid, stat.S_IMODE(m.st_mode))
            == (0, 0, 0o700) and not tuple(self.stage.iterdir()), 'fresh_purpose_stage')
        self.stage_identity = identity(m)[:6]
        # The existing bridge-owned directory is deliberately not a root-only
        # installer parent. Hold its descriptor across no-overwrite publication.
        for parent in self.KEYS.parents:
            info = parent.lstat()
            require(stat.S_ISDIR(info.st_mode) and info.st_uid in (0, 1003)
                and not info.st_mode & 0o022 and parent.resolve() == parent,
                'purpose_keys_protected_ancestry')
        expected = self.KEYS.lstat()
        require(self.KEYS.resolve(strict=True) == self.KEYS and stat.S_ISDIR(expected.st_mode)
            and (expected.st_uid, expected.st_gid, stat.S_IMODE(expected.st_mode))
            == (1003, 1004, 0o700) and expected.st_dev == m.st_dev,
            'purpose_keys_directory_or_filesystem')
        directory = os.open(self.KEYS, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW | os.O_CLOEXEC)
        try:
            self.keys_identity = identity(os.fstat(directory))[:6]
            require(self.keys_identity == identity(expected)[:6], 'purpose_keys_open')
            require(all(not os.path.lexists(self.KEYS / name) for name in self.NAMES),
                'purpose_key_slot_collision')
            public = {}
            for name in self.NAMES:
                self.check('obsd1.blackbagsecurity.com')
                prefix = self.stage / name
                try:
                    raw = self.fixture.run(('/usr/bin/ssh-keygen', '-q', '-t', 'ed25519',
                        '-N', '', '-C', 'osmap-account-' + name, '-f', str(prefix)),
                        'fixed_' + name + '_purpose_keygen', cap=1024, seconds=5,
                        absolute=self.end)
                    require(raw == b'', 'purpose_keygen_output')
                finally:
                    for path in (prefix, prefix.with_suffix('.pub')):
                        if os.path.lexists(path):
                            info = path.lstat()
                            require(stat.S_ISREG(info.st_mode) and info.st_uid == info.st_gid == 0
                                and info.st_nlink == 1 and 0 < info.st_size <= 4096,
                                'purpose_generated_file_custody')
                            self.stage_files[path] = identity(info)
                pub = prefix.with_suffix('.pub')
                value, _ = read_regular(pub, 256, self.end)
                public[name] = self.public_key(value, name) + b'\n'
                info = prefix.lstat()
                require(stat.S_IMODE(info.st_mode) == 0o600 and identity(info)
                    == self.stage_files[prefix], 'purpose_private_metadata')
                self.check('obsd1.blackbagsecurity.com')
                require(identity(os.fstat(directory))[:6] == self.keys_identity
                    and identity(self.KEYS.lstat())[:6] == self.keys_identity,
                    'purpose_keys_directory_changed')
                # link is no-overwrite. Private bytes never enter Python RAM,
                # output, hashes or retained evidence.
                os.link(prefix, name, dst_dir_fd=directory, follow_symlinks=False)
                target = self.KEYS / name
                self.keys[target] = identity(os.stat(name, dir_fd=directory, follow_symlinks=False))
                require(identity(prefix.lstat()) == self.keys[target], 'purpose_link_stage_identity')
                self.stage_files[prefix] = self.keys[target]
                fd = os.open(name, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK | os.O_CLOEXEC,
                    dir_fd=directory)
                try:
                    require(identity(os.fstat(fd)) == self.keys[target]
                        and self.keys[target][:2] == self.stage_files[prefix][:2]
                        and self.keys[target][5] == 2, 'purpose_link_identity')
                    os.fchown(fd, 1003, 1004)
                    os.fchmod(fd, 0o600)
                    self.keys[target] = identity(os.fstat(fd))
                    self.stage_files[prefix] = identity(prefix.lstat())
                    require(self.stage_files[prefix] == self.keys[target], 'purpose_shared_inode')
                    prefix.unlink()
                    self.stage_files.pop(prefix)
                    self.keys[target] = identity(os.fstat(fd))
                    require(self.keys[target][2:6] == (1003, 1004, stat.S_IFREG | 0o600, 1)
                        and identity(target.lstat()) == self.keys[target], 'purpose_final_private_custody')
                finally:
                    # Retain current metadata even after partial own chown/link
                    # so cleanup cannot silently ignore a created private slot.
                    try:
                        self.keys[target] = identity(os.fstat(fd))
                        if prefix in self.stage_files:
                            require(identity(prefix.lstat()) == self.keys[target],
                                'purpose_partial_stage_custody')
                            self.stage_files[prefix] = self.keys[target]
                    finally:
                        os.close(fd)
            require(public['admission'].split()[1] != public['mutation'].split()[1],
                'purpose_keys_not_distinct')
            os.fsync(directory)
            self.report['public_keys_sha256'] = {k: digest(v) for k, v in public.items()}
            return public
        finally:
            os.close(directory)

    def backend_publish(self, public):
        import pwd
        self.check('mail.blackbagsecurity.com')
        user = pwd.getpwnam('_osmap')
        require((user.pw_uid, user.pw_gid) == (1001, 1003), 'observed_connector_identity')
        original, metadata = read_regular(self.AUTHORIZED, 131072, self.end)
        require(metadata == self.AUTHORIZED_OBSERVED, 'authorized_observed_identity_changed')
        self.authorized_before = {'data': original, 'metadata': metadata, 'sha256': digest(original)}
        if hasattr(self, 'recovery'):
            self.recovery.checkpoint('AUTHORIZED_ORIGINAL_CAPTURED')
        appended = self.authorized(original, public)
        sources = {}
        for name, (path, expected) in self.CONNECTORS.items():
            require(not os.path.lexists(path), 'purpose_connector_collision')
            raw, _ = read_regular(self.stage / 'source/maint/account-runtime' / ('osmap_account_' + name + '_connector'), 8192, self.end)
            require(digest(raw) == expected, 'fixed_connector_source_hash')
            sources[path] = raw
        for path, raw in sources.items():
            self.check('mail.blackbagsecurity.com')
            require(not os.path.lexists(path), 'purpose_connector_changed_before_publish')
            publish(path, raw, 0o555, 0, 0, self.end, self.owned,
                recovery=getattr(self, 'recovery', None))
        same_snapshot(self.AUTHORIZED, self.authorized_before, 131072, self.end)
        publish(self.AUTHORIZED, appended, stat.S_IMODE(metadata[4]), 0, 0, self.end, self.owned,
            recovery=getattr(self, 'recovery', None))
        self.report.update(authorized_original_sha256=digest(original),
            authorized_appended_sha256=digest(appended), connector_count=2)
        return self.report.copy()

    def backend_restore(self):
        self.check('mail.blackbagsecurity.com')
        # Restore only the exact current inode/hash this producer published.
        # Existing ordinary lines are restored byte-for-byte; old inode and
        # existing TCP session restoration are never claimed.
        if self.AUTHORIZED in self.owned:
            lease, sha = self.owned[self.AUTHORIZED]
            current, m = read_regular(self.AUTHORIZED, 131072, self.end)
            require(m[:6] == lease and digest(current) == sha and self.authorized_before is not None,
                'owned_authorized_restore_custody')
            old = self.authorized_before
            publish(self.AUTHORIZED, old['data'], stat.S_IMODE(old['metadata'][4]),
                old['metadata'][2], old['metadata'][3], self.end, self.owned,
                recovery=getattr(self, 'recovery', None))
            restored, m = read_regular(self.AUTHORIZED, 131072, self.end)
            require(restored == old['data'] and m[2:5] == old['metadata'][2:5],
                'authorized_original_bytes_metadata_restored')
            self.owned.pop(self.AUTHORIZED)
        for _name, (path, _) in reversed(tuple(self.CONNECTORS.items())):
            if path not in self.owned:
                continue
            lease, sha = self.owned[path]
            raw, m = read_regular(path, 8192, self.end)
            require(m[:6] == lease and digest(raw) == sha, 'owned_connector_restore_custody')
            path.unlink()
            sync_directory(path.parent)
            self.owned.pop(path)
        if hasattr(self, 'recovery'):
            self.recovery.checkpoint('PURPOSE_FILES_RESTORED')
        self.report['file_cleanup_confirmed'] = True
        self.report['original_inode_preserved'] = False
        return self.report.copy()

    def frontend_remove(self):
        self.check('obsd1.blackbagsecurity.com')
        require(all(not os.path.lexists('/var/lib/osmap-bridge/run/' + name + '.sock')
            for name in self.NAMES), 'purpose_relay_listeners_not_disposed')
        require(identity(self.KEYS.lstat())[:6] == self.keys_identity,
            'purpose_keys_cleanup_parent')
        for path, lease in reversed(tuple(self.keys.items())):
            require(identity(path.lstat()) == lease, 'purpose_key_cleanup_identity')
            prefix = self.stage / path.name
            if prefix in self.stage_files:
                require(identity(prefix.lstat()) == lease and lease[5] == 2,
                    'purpose_partial_shared_inode')
            path.unlink()
            self.keys.pop(path)
            if prefix in self.stage_files:
                current = identity(prefix.lstat())
                require(current[:2] == lease[:2] and current[2:5] == lease[2:5]
                    and current[5] == 1, 'purpose_partial_unlinked_custody')
                self.stage_files[prefix] = current
        require(identity(self.stage.lstat())[:6] == self.stage_identity,
            'purpose_stage_cleanup_identity')
        for path, lease in tuple(self.stage_files.items()):
            require(identity(path.lstat()) == lease, 'purpose_stage_file_cleanup_identity')
            path.unlink()
            self.stage_files.pop(path)
        require(not tuple(self.stage.iterdir()), 'purpose_stage_residue')
        self.report['file_cleanup_confirmed'] = True
        return self.report.copy()


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--stage', type=Path, required=True)
    parser.add_argument('--manifest-sha256', required=True)
    parser.add_argument('--source-commit', required=True)
    args = parser.parse_args()
    require(os.getuid() == os.geteuid() == os.getgid() == os.getegid() == 0 and
            socket.gethostname() == 'mail.blackbagsecurity.com' and
            (os.uname().sysname, os.uname().machine) == ('OpenBSD', 'amd64'),
            'fixed_installation_authority')
    def interrupted(_number, _frame):
        raise Refused('installation_signal')
    for number in STOPS:
        signal.signal(number, interrupted)
    signal.alarm(60)
    started = time.monotonic()
    try:
        result = install(args.stage, args.manifest_sha256, args.source_commit, started + 60)
        result['elapsed_seconds'] = round(time.monotonic() - started, 6)
        print(json.dumps(result, sort_keys=True))
        return 0 if result['installed'] else 1
    finally:
        signal.alarm(0)


if __name__ == '__main__':
    try:
        raise SystemExit(main())
    except (Refused, OSError, ValueError) as failure:
        print(json.dumps({'result': 'FAIL', 'installed': False, 'activation': False,
                          'enablement': 'UNKNOWN_UNMODIFIED',
                          'rollback': 'UNKNOWN',
                          'failure': failure_code(failure)}))
        raise SystemExit(1)
