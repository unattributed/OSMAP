"""Closed native SQL material admission; no provisioning or activation.

The private endpoint plan names only a source-allowed local SQL socket and fixed
principal. Its kernel peer is observed without sending credentials or SQL. This
preflight is NOT proof of the separate mariadb child's eventual connection or
of its database grants; native qualification remains closed until those and the
complete irreversible confinement graph are actually qualified.
"""
from dataclasses import dataclass
import hashlib
import json
import os
from pathlib import Path
import pwd
import re
import socket
import stat
import sys
import time

from account_epoch import EpochStore
from account_mutation_supervisor import AUTHORITY, PURPOSE, ENGINE, WORKER, _peer
from account_mutation_worker import Unavailable
from authoritative_password import AuthoritativePasswordAdapter, NativeExecutor
from operation_budget import OperationBudget

ROOT = Path('/etc/osmap/account-runtime')
PLAN = ROOT / 'sql-endpoint.json'
CONFIG = Path('/etc/osmap/account-mariadb.cnf')
SQL_SOCKETS = frozenset(('/var/run/mysql/mysql.sock',))
SERVER = '_mysql'
DATABASE_USER = 'osmap_account_mutation'
STARTUP_SECONDS = 5
PEER_SECONDS = 1
ENGINE_TARGET = 'python3.13'


def _identity(info):
    return (info.st_dev, info.st_ino, info.st_uid, info.st_gid, info.st_mode,
            info.st_nlink, info.st_size, info.st_mtime_ns, info.st_ctime_ns)


def _ancestry(path, owner, *, peer_uid=None):
    if type(path) is not type(Path('/')) or not path.is_absolute() or path.resolve(strict=True) != path:
        raise Unavailable('native SQL material ancestry unavailable')
    custody = []
    for parent in path.parents:
        info = parent.lstat()
        # /tmp is accepted only by private isolated fixture construction. Native
        # fixed paths/allowlist never route through it.
        sticky = parent == Path('/tmp') and info.st_uid == 0 and info.st_mode & stat.S_ISVTX
        owners = (0, owner) if peer_uid is None else (0, owner, peer_uid)
        if (not stat.S_ISDIR(info.st_mode) or info.st_uid not in owners
                or (info.st_mode & 0o022 and not sticky)):
            raise Unavailable('native SQL material ancestry unavailable')
        # Directory contents/mtime may change for unrelated services. Pin its
        # identity and permission boundary, not unrelated directory activity.
        custody.append((str(parent), info.st_dev, info.st_ino, info.st_uid,
                        info.st_gid, info.st_mode))
    return tuple(custody)


def _read(path, owner, private, limit, budget, *, executable=False):
    budget.remaining()
    ancestry = _ancestry(path, owner)
    before = path.lstat()
    # Refuse special files before opening. NONBLOCK also covers replacement
    # after lstat: a substituted FIFO must never wait for a writer before the
    # exact fstat/identity checks can reject it under the original budget.
    if (not stat.S_ISREG(before.st_mode) or before.st_uid != owner or before.st_nlink != 1
            or before.st_mode & (0o077 if private else 0o022)
            or before.st_mode & 0o6000 or not 0 < before.st_size <= limit
            or (executable and not before.st_mode & 0o111)):
        raise Unavailable('native SQL material unavailable')
    budget.remaining()
    fd = os.open(path, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK)
    try:
        info = os.fstat(fd)
        if (not stat.S_ISREG(info.st_mode) or info.st_uid != owner or info.st_nlink != 1
                or info.st_mode & (0o077 if private else 0o022)
                or info.st_mode & 0o6000 or not 0 < info.st_size <= limit
                or (executable and not info.st_mode & 0o111)
                or _identity(before) != _identity(info)):
            raise Unavailable('native SQL material unavailable')
        digest = hashlib.sha256()
        content = bytearray() if private else None
        count = 0
        while True:
            budget.remaining()
            part = os.read(fd, min(4096, limit + 1 - count))
            if not part:
                break
            count += len(part)
            if count > limit:
                raise Unavailable('native SQL material unavailable')
            digest.update(part)
            if content is not None:
                content.extend(part)
        if (count != info.st_size or _identity(os.fstat(fd)) != _identity(info)
                or _identity(path.lstat()) != _identity(info)
                or _ancestry(path, owner) != ancestry):
            raise Unavailable('native SQL material changed')
        budget.remaining()
        return (_identity(info), digest.digest(), ancestry), content
    finally:
        os.close(fd)


def _engine(path, owner, budget):
    # The current authoritative OpenBSD package exposes this ONE fixed relative
    # alias. No general symlink following: exact link + regular sibling target
    # receive separate custody identities/digests and are both rechecked.
    budget.remaining()
    _ancestry(path.parent, owner)
    before = path.lstat()
    if (not stat.S_ISLNK(before.st_mode) or before.st_uid != owner or before.st_nlink != 1
            or os.readlink(path) != ENGINE_TARGET):
        raise Unavailable('native mutation engine alias unavailable')
    state, _unused = _read(path.parent / ENGINE_TARGET, owner, False, 64*1024*1024,
                            budget, executable=True)
    if _identity(path.lstat()) != _identity(before) or os.readlink(path) != ENGINE_TARGET:
        raise Unavailable('native mutation engine alias changed')
    budget.remaining()
    return (_identity(before), ENGINE_TARGET, state)


@dataclass(frozen=True, repr=False)
class _SqlEndpoint:
    path: Path
    uid: int

    @classmethod
    def _parse(cls, raw, identity):
        try:
            value = json.loads(raw, object_pairs_hook=EpochStore._unique)
            if (type(value) is not dict or set(value) != {'version', 'authority', 'purpose', 'server', 'socket', 'database_user'}
                    or type(value['version']) is not int or value['version'] != 1
                    or value['authority'] != AUTHORITY or value['purpose'] != PURPOSE
                    or value['server'] != SERVER or value['database_user'] != DATABASE_USER
                    or type(value['socket']) is not str or value['socket'] not in SQL_SOCKETS):
                raise ValueError
            uid = identity()
            if type(uid) is not int or not 0 < uid < 2**32 - 1:
                raise ValueError
            return cls(Path(value['socket']), uid)
        except Exception:
            raise Unavailable('native SQL endpoint unavailable') from None


def _config(raw, endpoint):
    # Deliberately smaller than MariaDB's option-file language: no includes,
    # extra groups, unknown/duplicate options, quoting, escaping or comments.
    # The password is parsed only in bounded private memory, then discarded.
    try:
        if not raw or len(raw) > 16384 or not raw.endswith(b'\n') or b'\r' in raw:
            raise ValueError
        lines = raw.decode('ascii').splitlines()
        if len(lines) != 5 or lines[0] != '[client]':
            raise ValueError
        fields = {}
        for line in lines[1:]:
            name, value = line.split('=', 1)
            if name in fields:
                raise ValueError
            fields[name] = value
        if (set(fields) != {'user', 'password', 'protocol', 'socket'}
                or fields['user'] != DATABASE_USER or fields['protocol'] != 'SOCKET'
                or fields['socket'] != str(endpoint.path)
                or re.fullmatch(r'[A-Za-z0-9+/=_-]{20,256}', fields['password']) is None):
            raise ValueError
    except Exception:
        raise Unavailable('native SQL client configuration unavailable') from None


def _probe(endpoint, owner, budget):
    budget.remaining()
    ancestry = _ancestry(endpoint.path, owner, peer_uid=endpoint.uid)
    before = endpoint.path.lstat()
    if (not stat.S_ISSOCK(before.st_mode) or before.st_uid != endpoint.uid or before.st_nlink != 1):
        raise Unavailable('native SQL socket unavailable')
    with socket.socket(socket.AF_UNIX, socket.SOCK_STREAM) as stream:
        stream.settimeout(budget.cap_seconds(PEER_SECONDS))
        stream.connect(str(endpoint.path))
        if (_peer(stream) != endpoint.uid or _identity(endpoint.path.lstat()) != _identity(before)
                or _ancestry(endpoint.path, owner, peer_uid=endpoint.uid) != ancestry):
            raise Unavailable('native SQL peer unavailable')
        # No protocol bytes, credentials, query or authentication are sent.
        budget.remaining()
    return _identity(before), ancestry


class NativeMaterial:
    """Private immutable custody observations; caller reports cannot mint them."""
    def __init__(self, *_args, **_kwargs):
        raise Unavailable('native SQL material construction unavailable')

    @staticmethod
    def _server():
        return pwd.getpwnam(SERVER).pw_uid

    @classmethod
    def native(cls):
        if (os.geteuid() != 0 or not sys.platform.startswith('openbsd')
                or socket.gethostname() != AUTHORITY):
            raise Unavailable('native SQL authority unavailable')
        # This is startup only. Every operation below uses its original signed
        # budget; rechecks never create or reset a mutation deadline.
        budget = OperationBudget(int(time.time()) + STARTUP_SECONDS,
                                 maximum_seconds=STARTUP_SECONDS)
        return cls._load(PLAN, CONFIG, 0, cls._server, budget)

    @classmethod
    def _load(cls, plan, config, owner, identity, budget):
        if type(budget) is not OperationBudget:
            raise Unavailable('native SQL budget unavailable')
        try:
            plan_state, raw = _read(plan, owner, True, 4096, budget)
            endpoint = _SqlEndpoint._parse(raw, identity)
            raw.clear()
            config_state, raw = _read(config, owner, True, 16384, budget)
            try:
                _config(raw, endpoint)
            finally:
                raw.clear()
            programs = tuple(Path(p) for p in (AuthoritativePasswordAdapter.SQL_PROGRAM,
                             AuthoritativePasswordAdapter.HASH_PROGRAM, ENGINE, WORKER))
            states = []
            for program in programs:
                if program == Path(ENGINE):
                    state = _engine(program, owner, budget)
                else:
                    state, _unused = _read(program, owner, False, 64*1024*1024, budget,
                                           executable=program != Path(WORKER))
                states.append(state)
            socket_state = _probe(endpoint, owner, budget)
            value = object.__new__(cls)
            value._plan, value._config, value._owner = plan, config, owner
            value._endpoint, value._identity_source = endpoint, identity
            value._states = (plan_state, config_state, tuple(states), socket_state)
            budget.remaining()
            return value
        except Exception:
            raise Unavailable('native SQL material admission unavailable') from None

    def recheck(self, budget):
        if type(budget) is not OperationBudget or not budget.inherited_group():
            raise Unavailable('native SQL original budget unavailable')
        current = type(self)._load(self._plan, self._config, self._owner,
                                   self._identity_source, budget)
        if current._endpoint != self._endpoint or current._states != self._states:
            raise Unavailable('native SQL material custody changed')
        budget.remaining()


class MaterialExecutor(NativeExecutor):
    """Mandatory typed custody and command seal on the same original phase."""
    def __init__(self, budget, material):
        from account_command_kernel import CommandKernelSeal
        if type(material) is not NativeMaterial or type(budget) is not OperationBudget:
            raise Unavailable('native SQL executor material unavailable')
        super().__init__(budget)
        self._material=material
        self._seals={
            (AuthoritativePasswordAdapter.SQL_PROGRAM,AuthoritativePasswordAdapter.SQL_ARGS):
                CommandKernelSeal._for_material('sql',material,budget),
            (AuthoritativePasswordAdapter.HASH_PROGRAM,AuthoritativePasswordAdapter.HASH_ARGS):
                CommandKernelSeal._for_material('hash',material,budget)}
        if any(type(seal)is not CommandKernelSeal or seal._budget is not budget for seal in self._seals.values()):
            raise Unavailable('native command original seal unavailable')

    def _spawn(self, program, args, deadline):
        # NativeExecutor captures the phase BEFORE this public/private material
        # recheck; a slow recheck cannot reset or outlive the phase allowance.
        self._material.recheck(self._budget)
        if time.monotonic()>=deadline:raise Unavailable('native command phase expired')
        seal=self._seals.get((program,args))
        if seal is None:raise Unavailable('native command authority unavailable')
        return seal.spawn(program,args,deadline)
