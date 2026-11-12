#!/usr/local/bin/python3
"""Install only the fixed combined account helper and rc script.

The root delivery carrier verifies signed source and native qualification before
pinning admission.json by SHA-256. This component checks that exact admission
and artifact parity; it does not itself verify a Git signature or qualify UAT.
No service, enablement, account, key, configuration or Generation operation.
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


def publish(path, data, mode, owner, group, end, owned):
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
        os.replace(temporary, path.name, src_dir_fd=directory,
                   dst_dir_fd=directory)
        os.fsync(directory)
        actual, m = read_regular(path, LIMIT if path == BINARY else 16384, end)
        require(identity(os.fstat(fd))[:6] == published_lease and
                m[:6] == published_lease and digest(actual) == digest(data),
                'published_readback_refused')
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


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--stage', type=Path, required=True)
    parser.add_argument('--manifest-sha256', required=True)
    parser.add_argument('--source-commit', required=True)
    args = parser.parse_args()
    require(os.getuid() == os.geteuid() == os.getgid() == os.getegid() == 0 and
            socket.gethostname() == 'mail.blackbagsecurity.com' and
            (os.uname().sysname, os.uname().machine) ==
            ('OpenBSD', 'amd64'), 'fixed_installation_authority')
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
