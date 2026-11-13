#!/usr/bin/env python3
"""Provision the existing local account pair for a bounded recovery-contact rollout.

Run as root on the explicitly reviewed host. This does not start services or
configure a password writer/reset service. Keys are born on that host and copied
only to the Web principal. Existing account state and configuration are refused,
not replaced. The retained receipt contains fixed codes and public metadata only.
"""
import argparse
import hashlib
import json
import os
from pathlib import Path
import pwd
import re
import grp
import socket
import stat
import subprocess
import sys


class Refused(Exception):
    pass


def require(condition, code):
    if not condition:
        raise Refused(code)


def checked(command, journal):
    entry = {'utility': Path(command[0]).name, 'outcome': 'NOT_STARTED'}
    journal.append(entry)
    try:
        result = subprocess.run(command, stdin=subprocess.DEVNULL, stdout=subprocess.PIPE,
                                stderr=subprocess.PIPE, timeout=15, check=False)
        entry.update(outcome='EXITED', returncode=result.returncode,
                     stdout_bytes=len(result.stdout), stderr_bytes=len(result.stderr))
        require(result.returncode == 0, 'UTILITY_REFUSED')
    except subprocess.TimeoutExpired as error:
        entry.update(outcome='TIMEOUT', stdout_bytes=len(error.stdout or b''),
                     stderr_bytes=len(error.stderr or b''))
        raise Refused('UTILITY_TIMEOUT') from None
    except OSError:
        entry['outcome'] = 'EXEC_UNAVAILABLE'
        raise Refused('UTILITY_EXEC_UNAVAILABLE') from None


def directory(path, owner, group, mode, journal=None):
    created = not os.path.lexists(path)
    entry = {'path': str(path), 'state': 'DIRECTORY_CREATION_ATTEMPTED'}
    if created:
        if journal is not None:
            journal.append(entry)
        os.mkdir(path, mode)
    fd = os.open(path, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW)
    try:
        born = os.fstat(fd)
        if created:
            entry.update(device=born.st_dev, inode=born.st_ino, state='DIRECTORY_BORN')
            os.fchown(fd, owner, group)
            os.fchmod(fd, mode)
        info, current = os.fstat(fd), path.lstat()
        require(stat.S_ISDIR(info.st_mode) and info.st_uid == owner and
                info.st_gid == group and stat.S_IMODE(info.st_mode) == mode and
                (current.st_dev, current.st_ino) == (born.st_dev, born.st_ino) and
                stat.S_ISDIR(current.st_mode), 'DIRECTORY_CUSTODY')
        os.fsync(fd)
    finally:
        os.close(fd)


def exclusive(path, data, owner=0, group=0, mode=0o600, journal=None):
    fd = os.open(path, os.O_RDWR | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW, mode)
    born = os.fstat(fd)
    entry = {'path': str(path), 'device': born.st_dev, 'inode': born.st_ino,
             'state': 'FILE_BORN_UNVERIFIED'}
    if journal is not None:
        journal.append(entry)
    try:
        os.fchown(fd, owner, group)
        os.fchmod(fd, mode)
        with os.fdopen(fd, 'wb', closefd=False) as stream:
            stream.write(data)
            stream.flush()
            os.fsync(fd)
        os.lseek(fd, 0, os.SEEK_SET)
        require(os.read(fd, len(data) + 1) == data, 'FILE_READBACK')
        held, current = os.fstat(fd), path.lstat()
        identity = lambda m: (m.st_dev, m.st_ino, m.st_uid, m.st_gid,
                              m.st_mode, m.st_nlink, m.st_size)
        require(stat.S_ISREG(current.st_mode) and held.st_dev == born.st_dev and
                held.st_ino == born.st_ino and held.st_uid == owner and held.st_gid == group and
                stat.S_IMODE(held.st_mode) == mode and held.st_nlink == 1 and
                held.st_size == len(data) and identity(current) == identity(held),
                'FILE_IDENTITY_READBACK')
        entry.update(bytes=len(data), state='READBACK_VERIFIED')
        return dict(entry)
    finally:
        os.close(fd)


def epoch_record():
    return b'{"epoch":0,"state":"active","changed_at":null,"intent":null,"used_intents":[]}'


def epoch_stem(account):
    return hashlib.sha256(b'osmap-account-epoch-v1\0' + account.encode()).hexdigest()


def hash_identity():
    try:
        identity = pwd.getpwnam('_osmaphash')
    except KeyError:
        try:
            group = grp.getgrnam('_osmaphash')
            require(not group.gr_mem and group.gr_gid not in (0, 32766, 32767) and
                    sum(p.pw_gid == group.gr_gid for p in pwd.getpwall()) == 0,
                    'HASH_GROUP_REFUSED')
        except KeyError:
            pass
        return None
    group = grp.getgrnam('_osmaphash')
    users, groups = pwd.getpwall(), grp.getgrall()
    require(0 < identity.pw_uid < 2**31 and 0 < identity.pw_gid < 2**31 and
            identity.pw_uid not in (32766, 32767) and identity.pw_gid not in (32766, 32767) and
            identity.pw_gid == group.gr_gid and identity.pw_dir == '/var/empty' and
            identity.pw_shell == '/sbin/nologin' and not group.gr_mem and
            sum(p.pw_uid == identity.pw_uid for p in users) == 1 and
            sum(p.pw_gid == identity.pw_gid for p in users) == 1 and
            sum(g.gr_gid == group.gr_gid for g in groups) == 1 and
            all('_osmaphash' not in g.gr_mem for g in groups), 'HASH_IDENTITY_REFUSED')
    return identity


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--expected-host', required=True)
    parser.add_argument('--account', required=True)
    parser.add_argument('--apply', action='store_true')
    args = parser.parse_args()
    out = {'schema': 'osmap-recovery-contact-provision-v1', 'result': 'REFUSED',
           'code': 'NOT_DISPATCHED', 'created': [], 'services_changed': False,
           'sql_authority_created': False, 'owner_credentials_changed': False}
    try:
        require(os.getuid() == 0 and os.geteuid() == 0 and
                sys.platform.startswith('openbsd') and
                socket.gethostname() == args.expected_host, 'TARGET_REFUSED')
        require(args.expected_host == 'mail.blackbagsecurity.com' and
                len(args.account) <= 255 and
                re.fullmatch(r'[a-z0-9][a-z0-9._+-]{0,190}@[a-z0-9][a-z0-9.-]{0,63}',
                             args.account), 'SCOPE_REFUSED')
        os.umask(0o077)
        web = pwd.getpwnam('_osmap')
        group = grp.getgrnam('osmapgpg')
        require(web.pw_uid != 0 and web.pw_name in group.gr_mem, 'WEB_GROUP_REFUSED')
        targets = [Path('/etc/osmap/account-admission.json'),
                   Path('/etc/osmap/account-admission.key')]
        runtime = Path('/etc/osmap/account-runtime')
        targets += [runtime / x for x in ['config.json', 'mutation.key', 'session-proof.key']]
        web_keys = Path('/var/lib/osmap/secrets/account-runtime')
        targets += [web_keys / x for x in ['admission.key', 'mutation.key', 'session-proof.key']]
        epoch = Path('/var/db/osmap-account/epoch')
        stem = epoch_stem(args.account)
        targets += [epoch / (stem + suffix) for suffix in ['.json', '.lock', '.uncertain']]
        require(all(not os.path.lexists(p) for p in targets), 'EXISTING_STATE_REFUSED')
        # Writer and factor-reset authority remain outside this contact rollout.
        require(not os.path.lexists('/etc/osmap/account-mariadb.cnf') and
                not os.path.lexists(runtime / 'access-recovery.json'), 'UNEXPECTED_AUTHORITY')
        for parent in ['/etc', '/etc/osmap', '/var', '/var/lib', '/var/lib/osmap',
                       '/var/lib/osmap/secrets', '/var/run', '/var/db', '/var/db/osmap-account']:
            info = Path(parent).lstat()
            allowed_owner = web.pw_uid if parent in ('/var/lib/osmap', '/var/lib/osmap/secrets') else 0
            require(stat.S_ISDIR(info.st_mode) and not stat.S_ISLNK(info.st_mode) and
                    info.st_uid == allowed_owner and not info.st_mode & 0o022,
                    'ANCESTRY_REFUSED')
        require(not web_keys.exists(), 'WEB_KEYS_EXIST')
        expected_directories = [(runtime, 0, 0, 0o700), (epoch, 0, 0, 0o700),
                                (web_keys, web.pw_uid, web.pw_gid, 0o700)]
        expected_directories += [(Path('/var/run') / name, 0, group.gr_gid, 0o750)
                                 for name in ['osmap-account-admission', 'osmap-account-mutation']]
        for path, owner, group_id, mode in expected_directories:
            if os.path.lexists(path):
                info = path.lstat()
                require(stat.S_ISDIR(info.st_mode) and info.st_uid == owner and
                        info.st_gid == group_id and stat.S_IMODE(info.st_mode) == mode,
                        'DIRECTORY_CUSTODY')
        identity = hash_identity()
        if not args.apply:
            out.update(result='PASS', code='PREFLIGHT_ONLY')
        else:
            if identity is None:
                try:
                    grp.getgrnam('_osmaphash')
                except KeyError:
                    checked(['/usr/sbin/groupadd', '_osmaphash'], out['created'])
                    out['created'].append({'group': '_osmaphash',
                                           'gid': grp.getgrnam('_osmaphash').gr_gid})
                checked(['/usr/sbin/useradd', '-g', '_osmaphash', '-d', '/var/empty',
                         '-s', '/sbin/nologin', '_osmaphash'], out['created'])
                out['created'].append({'identity': '_osmaphash',
                                       'uid': pwd.getpwnam('_osmaphash').pw_uid})
                hash_identity()

            def publish(path, data, *identity):
                return exclusive(path, data, *identity, journal=out['created'])

            for path, owner, group_id, mode in expected_directories:
                directory(path, owner, group_id, mode, out['created'])
            configs = {
                targets[0]: {'version': 1, 'socket': '/var/run/osmap-account-admission/admission.sock',
                             'trusted_web_uid': web.pw_uid, 'accounts': [args.account]},
                runtime / 'config.json': {'version': 1, 'authority': args.expected_host,
                                         'purpose': 'osmap-account-mutation',
                                         'trusted_relay_uid': web.pw_uid,
                                         'accounts': [args.account]}}
            for path, value in configs.items():
                publish(path, json.dumps(value).encode())
            for name, service in [('admission.key', targets[1]),
                                  ('mutation.key', runtime / 'mutation.key'),
                                  ('session-proof.key', runtime / 'session-proof.key')]:
                key = os.urandom(64)
                publish(service, key)
                publish(web_keys / name, key, web.pw_uid, web.pw_gid)
                require(service.read_bytes() == (web_keys / name).read_bytes(), 'KEY_PARITY')
            require(len({targets[1].read_bytes(), (runtime / 'mutation.key').read_bytes(),
                         (runtime / 'session-proof.key').read_bytes()}) == 3, 'KEY_SEPARATION')
            publish(epoch / (stem + '.json'), epoch_record())
            publish(epoch / (stem + '.lock'), b'')
            out.update(result='PASS', code='PROVISIONED_NOT_ACTIVATED')
    except Refused as error:
        out['code'] = str(error)
    except FileExistsError:
        out['code'] = 'EXCLUSIVE_CREATE_REFUSED'
    except Exception:
        out['code'] = 'OBSERVATION_OR_UTILITY_UNAVAILABLE'
    # On failure, retain born resources for exact-owned recovery. Never delete
    # uncertain account authority or replay this operation automatically.
    print(json.dumps(out, sort_keys=True))
    return 0 if out['result'] == 'PASS' else 1


if __name__ == '__main__':
    sys.exit(main())
