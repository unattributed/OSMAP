"""Disabled helper-owned exact-account Dovecot containment dependency.

Installed 2.3.21.1 syntax and upstream response parsers inform this source;
neither help nor callback tests qualify actual cache invalidation or termination.
The observed authoritative Postfix submission services have SASL enabled. SMTP
is REQUIRED, and lacks qualified complete entrypoint routing/termination.
The typed composition below consumes helper-owned qualified topology material;
its source fixtures cannot produce native qualification. Native pre-write
admission remains unavailable. No browser/config opt-in exists.

Cache invalidation occurs after the conditional password write and before new
credential verification. Only the separate kick plus one who reconciliation
can confirm a bounded zero-connections observation. This does not exclude a
concurrent native login, revoke browser records or contain Postfix connections.
"""
from dataclasses import dataclass
from enum import Enum
import hashlib
import ipaddress
import json
import os
from pathlib import Path
import re
import stat

from authoritative_password import AuthoritativePasswordAdapter, Refused, Unconfirmed
from operation_budget import OperationBudget

NATIVE_CONFINEMENT_QUALIFIED = False
NATIVE_SMTP_TOPOLOGY_QUALIFIED = False


class SmtpTerminationScope(Enum):
    NOT_APPLICABLE = 'not-applicable'
    REQUIRED = 'required'
    UNKNOWN = 'unknown'


class MailSessionContainment:
    PROGRAM = '/usr/local/bin/doveadm'
    AUTH_SOCKET = '/var/dovecot/auth-master'
    ANVIL_SOCKET = '/var/dovecot/anvil'
    PHASE_SECONDS = 10
    OUTPUT_LIMIT = 4096
    WHO_HEADER = b'username\t#\tproto\t(pids)\t(ips)\n'

    def __init__(self, canonical_account, executor, budget, smtp_scope, *, proxy_control=None,
                 topology=None):
        self._account = AuthoritativePasswordAdapter._account(canonical_account)
        if (type(budget) is not OperationBudget or
                type(smtp_scope) is not SmtpTerminationScope or not callable(executor)):
            raise Refused('mail containment dependency unavailable')
        if proxy_control is not None and (type(proxy_control) is not SmtpProxyControl
                or not proxy_control.bound_to(self._account, budget)):
            raise Refused('SMTP proxy binding unavailable')
        self._proxy_control = proxy_control
        if topology is not None and (type(topology) is not OperatorOwnedSmtpTopology
                or proxy_control is None or not topology.bound_to(proxy_control, budget)):
            raise Refused('SMTP topology binding unavailable')
        self._topology = topology
        self._execute = executor
        self._budget = budget
        self._smtp_scope = smtp_scope
        self._state = 'new'

    def proxy_control(self, account):
        # Exposes the separately bound primitive, never topology admission.
        # Attachment alone cannot supply REQUIRED topology admission.
        if account != self._account or self._proxy_control is None:
            raise Refused('SMTP proxy binding unavailable')
        self._budget.remaining()
        return self._proxy_control

    @classmethod
    def commands(cls, account):
        account = AuthoritativePasswordAdapter._account(account)
        # No wildcard/IP/f/force/proxy/all-user selector or request socket.
        return {
            'flush': ('auth', 'cache', 'flush', '-a', cls.AUTH_SOCKET, account),
            'kick': ('kick', '-a', cls.ANVIL_SOCKET, account),
            'who': ('-f', 'tab', 'who', '-a', cls.ANVIL_SOCKET, account),
        }

    def _owned(self, account, state):
        if account != self._account or self._state != state:
            raise Refused('mail containment action refused')
        self._budget.remaining()

    def _run(self, name, *, post_write=False):
        error = Unconfirmed if post_write else Refused
        try:
            seconds = self._budget.cap_seconds(self.PHASE_SECONDS)
            result = self._execute(self.PROGRAM, self.commands(self._account)[name],
                                   b'', seconds, self.OUTPUT_LIMIT)
            self._budget.remaining()
            if (type(result) is not tuple or len(result) != 3 or
                    type(result[0]) is not int or type(result[1]) is not bytes or
                    type(result[2]) is not bytes or result[2] or
                    len(result[1]) > self.OUTPUT_LIMIT):
                raise ValueError
            return result[0], result[1]
        except Exception:
            self._state = 'contained' if post_write else 'unavailable'
            raise error('mail containment unconfirmed' if post_write else
                        'mail containment unavailable') from None

    def _who(self, *, post_write=False):
        error = Unconfirmed if post_write else Refused
        code, data = self._run('who', post_write=post_write)
        if code != 0 or not data.startswith(self.WHO_HEADER):
            raise error('mail connection acknowledgement unavailable')
        rows = data[len(self.WHO_HEADER):].splitlines()
        for row in rows:
            fields = row.split(b'\t')
            if (len(fields) != 5 or fields[0] != self._account.encode('ascii') or
                    not re.fullmatch(rb'[1-9][0-9]{0,9}', fields[1]) or
                    int(fields[1]) > 2**32 - 1 or
                    fields[2] not in (b'imap', b'pop3', b'sieve', b'managesieve', b'lmtp') or
                    not re.fullmatch(rb'\([0-9]+(?: [0-9]+)*\)', fields[3]) or
                    not re.fullmatch(rb'\([A-Fa-f0-9:. ]*\)', fields[4])):
                raise error('mail connection acknowledgement unavailable')
        self._budget.remaining()
        return len(rows)

    def ready(self, account):
        self._owned(account, 'new')
        if (self._smtp_scope is SmtpTerminationScope.UNKNOWN or
                (self._smtp_scope is SmtpTerminationScope.REQUIRED and
                 (self._topology is None or self._proxy_control is None))):
            self._state = 'unavailable'
            raise Refused('SMTP termination dependency unavailable')
        try:
            if self._smtp_scope is SmtpTerminationScope.REQUIRED:
                self._topology.recheck(self._budget)
                self._proxy_control.query(account)
                self._topology.recheck(self._budget)
            self._who()
            if self._topology is not None:
                self._topology.recheck(self._budget)
        except Exception:
            self._state = 'unavailable'
            raise Refused('mail containment unavailable') from None
        self._state = 'ready'
        return True

    def before_write(self, account):
        # The adapter calls this AFTER hashing, immediately before its one SQL
        # dispatch. Early ready() alone cannot attest unchanged routing.
        self._owned(account, 'ready')
        if self._smtp_scope is SmtpTerminationScope.REQUIRED:
            self._topology.recheck(self._budget)
        return True

    def invalidate_changed_auth(self, account):
        self._owned(account, 'ready')
        self._state = 'flush-dispatched'
        try:
            if self._topology is not None:
                self._topology.recheck(self._budget)
            code, data = self._run('flush', post_write=True)
            if code != 0 or not re.fullmatch(rb'(?:0|[1-9][0-9]{0,9}) cache entries flushed\n', data):
                raise ValueError
            if int(data.split(b' ', 1)[0]) > 2**32 - 1:
                raise ValueError
            self._budget.remaining()
            if self._topology is not None:
                self._topology.recheck(self._budget)
        except Exception:
            self._state = 'contained'
            raise Unconfirmed('authentication cache invalidation unconfirmed') from None
        self._state = 'flushed'
        return True

    def finish(self, account):
        self._owned(account, 'flushed')
        self._state = 'kick-dispatched'
        try:
            if self._smtp_scope is SmtpTerminationScope.REQUIRED:
                self._topology.recheck(self._budget)
                self._proxy_control.terminate(account)
                self._topology.recheck(self._budget)
            code, data = self._run('kick', post_write=True)
            no_users = code == 68 and data == b'no users kicked\n'
            kicked = (code == 0 and data == b'kicked connections from the following users:\n'
                      + self._account.encode('ascii') + b' \n')
            if not (no_users or kicked) or self._who(post_write=True) != 0:
                raise ValueError
            self._budget.remaining()
            if self._topology is not None:
                self._topology.recheck(self._budget)
        except Exception:
            self._state = 'contained'
            raise Unconfirmed('mail connection termination unconfirmed') from None
        self._state = 'finished'
        return True


def build_native_containment(canonical_account, budget, *, namespace=None, topology=None):
    """Helper-startup seam only. Native topology/SMTP/confinement is unqualified."""
    if not NATIVE_CONFINEMENT_QUALIFIED or not NATIVE_SMTP_TOPOLOGY_QUALIFIED:
        raise Refused('native mail containment unavailable')
    if namespace is None and topology is None:
        from smtp_topology import FixedSmtpRouting
        namespace, topology = FixedSmtpRouting.native(budget)
    # The actual currently observed scope is REQUIRED, not inferred N/A from
    # cache size0 or the earlier incomplete inet-only master-service parser.
    # Only a separately qualified helper startup loader may supply material;
    # there is no guessed production directory, backend, Boolean or browser
    # pathname. Current native bootstrap does not yet supply this authority.
    if (type(namespace) is not OperatorOwnedProxyNamespace or
            type(topology) is not OperatorOwnedSmtpTopology or
            topology._namespace is not namespace or namespace._owner != 0 or
            topology._certificate_version != 2):
        raise Refused('native SMTP topology unavailable')
    proxy = SmtpProxyControl(canonical_account, namespace,
                            ProxyControlExecutor(canonical_account, namespace, budget), budget)
    return MailSessionContainment(canonical_account,
                                  ContainmentExecutor(canonical_account, budget),
                                  budget, SmtpTerminationScope.REQUIRED,
                                  proxy_control=proxy, topology=topology)


@dataclass(frozen=True)
class SmtpProxyObservation:
    """Own-account bounded observation, not topology/dispatch authority."""
    account: str
    connections: int
    namespace_fingerprint: str


@dataclass(frozen=True)
class SmtpProxyTermination:
    account: str
    acknowledged_connections: int
    remaining_connections: int
    namespace_fingerprint: str


class OperatorOwnedProxyNamespace:
    """Trusted startup input only, never a browser/wire pathname.

    Fixed config and IPC children, private owner, bounded file and captured
    identities are rechecked before each command. This does not assert that
    every production SMTP listener uses this namespace. No config is created,
    edited or parsed as topology authority here.
    """
    CONFIG_LIMIT = 16384

    def __init__(self, root, owner_uid, backend_address, backend_port):
        if not isinstance(root, Path) or (
                type(owner_uid) is not int or owner_uid < 0 or
                type(backend_address) is not str or type(backend_port) is not int
                or not 1 <= backend_port <= 65535):
            raise Refused('SMTP proxy namespace unavailable')
        try:
            if not str(root).isascii() or not 1 <= len(str(root)) <= 512:
                raise ValueError
            address = ipaddress.ip_address(backend_address)
            if str(address) != backend_address:
                raise ValueError
        except ValueError:
            raise Refused('SMTP proxy namespace unavailable') from None
        self._root = root
        self._owner = owner_uid
        self._backend_address = backend_address
        self._backend_port = backend_port
        self._config = root / 'dovecot.conf'
        self._ipc = root / 'run' / 'login' / 'ipc-proxy'
        self._captured = self._snapshot()
        self._fingerprint = hashlib.sha256(repr(self._captured).encode('ascii')).hexdigest()

    @staticmethod
    def _identity(info):
        return (info.st_dev, info.st_ino, info.st_uid, info.st_gid,
                info.st_mode, info.st_nlink)

    def _snapshot(self):
        try:
            if not self._root.is_absolute() or self._root.resolve(strict=True) != self._root:
                raise ValueError
            for path in tuple(reversed(self._root.parents)) + (self._root,):
                info = path.lstat()
                sticky_root = (path == Path('/tmp') and info.st_uid == 0
                               and info.st_mode & stat.S_ISVTX)
                if (not stat.S_ISDIR(info.st_mode) or info.st_uid not in (0, self._owner)
                        or (info.st_mode & 0o022 and not sticky_root)):
                    raise ValueError
            directories = []
            for path in (self._root, self._root / 'run', self._root / 'run' / 'login'):
                info = path.lstat()
                if (not stat.S_ISDIR(info.st_mode) or info.st_uid != self._owner
                        or info.st_mode & 0o077):
                    raise ValueError
                directories.append(self._identity(info))
            before = self._config.lstat()
            if (not stat.S_ISREG(before.st_mode) or before.st_uid != self._owner
                    or before.st_nlink != 1 or before.st_mode & 0o077
                    or not 0 < before.st_size <= self.CONFIG_LIMIT):
                raise ValueError
            fd = os.open(self._config, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK)
            try:
                opened = os.fstat(fd)
                if self._identity(opened) != self._identity(before) or opened.st_size != before.st_size:
                    raise ValueError
                data = bytearray()
                while len(data) <= self.CONFIG_LIMIT:
                    chunk = os.read(fd, min(4096, self.CONFIG_LIMIT + 1 - len(data)))
                    if not chunk:
                        break
                    data.extend(chunk)
                after = os.fstat(fd)
                if (len(data) != before.st_size or len(data) > self.CONFIG_LIMIT
                        or after.st_size != opened.st_size
                        or after.st_mtime_ns != opened.st_mtime_ns
                        or self._identity(after) != self._identity(opened)
                        or self._identity(self._config.lstat()) != self._identity(opened)):
                    raise ValueError
            finally:
                os.close(fd)
            ipc = self._ipc.lstat()
            if (not stat.S_ISSOCK(ipc.st_mode) or ipc.st_uid != self._owner
                    or ipc.st_nlink != 1 or ipc.st_mode & 0o077):
                raise ValueError
            return (tuple(directories), self._identity(after), after.st_size,
                    hashlib.sha256(data).hexdigest(), self._identity(ipc),
                    str(self._config), str(self._ipc), self._backend_address, self._backend_port)
        except (OSError, ValueError, RuntimeError):
            raise Refused('SMTP proxy namespace unavailable') from None

    def recheck(self, budget):
        if type(budget) is not OperationBudget:
            raise Refused('SMTP proxy budget unavailable')
        budget.remaining()
        if self._snapshot() != self._captured:
            raise Refused('SMTP proxy namespace changed')
        budget.remaining()


class OperatorOwnedSmtpTopology:
    """Helper-owned configuration-continuity authority, never caller consent.

    The exact private certificate is produced only after independent complete
    entrypoint/namespace routing qualification. This consumer checks nonempty
    named coverage and unchanged native metadata; it does not discover hidden
    ingress or manufacture that qualification. Native startup remains disabled
    until that producer, listener coverage and post-write races are qualified.
    Callback fixtures prove this consumer/state machine only.
    """
    PROGRAM = '/usr/local/sbin/postconf'
    COMMANDS = {'master': ('-M',), 'services': ('-P',),
                'global_auth': ('-h', 'smtpd_sasl_auth_enable')}
    CERT_LIMIT = 8192
    OUTPUT_LIMIT = 16384

    def __init__(self, namespace, executor, budget, *, routing_plan=None):
        if (type(namespace) is not OperatorOwnedProxyNamespace or
                type(budget) is not OperationBudget or not callable(executor)):
            raise Refused('SMTP topology authority unavailable')
        self._namespace = namespace
        self._execute = executor
        self._budget = budget
        self._path = namespace._root / 'smtp-topology.json'
        namespace.recheck(budget)
        self._captured, certificate = self._read()
        self._validate(certificate)
        self._certificate_version = certificate['version']
        self._digests = certificate['metadata_sha256']
        self._routing_digests = certificate.get('routing_sha256')
        self._routing_plan = routing_plan
        if self._certificate_version == 2:
            from smtp_topology import PrivateRoutingPlan
            if (type(routing_plan) is not PrivateRoutingPlan
                    or not routing_plan.bound_to(namespace, budget)):
                raise Refused('SMTP private routing plan binding unavailable')
        elif routing_plan is not None:
            raise Refused('SMTP routing plan version mismatch')
        self.recheck(budget)

    @staticmethod
    def _unique(pairs):
        value = {}
        for key, item in pairs:
            if key in value:
                raise ValueError
            value[key] = item
        return value

    def _read(self):
        try:
            before = self._path.lstat()
            if (not stat.S_ISREG(before.st_mode) or before.st_uid != self._namespace._owner
                    or before.st_nlink != 1 or before.st_mode & 0o077
                    or not 0 < before.st_size <= self.CERT_LIMIT):
                raise ValueError
            fd = os.open(self._path, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK)
            try:
                opened = os.fstat(fd)
                if (self._namespace._identity(opened) != self._namespace._identity(before)
                        or opened.st_size != before.st_size):
                    raise ValueError
                data = bytearray()
                while len(data) <= self.CERT_LIMIT:
                    chunk = os.read(fd, min(4096, self.CERT_LIMIT + 1 - len(data)))
                    if not chunk:
                        break
                    data.extend(chunk)
                after = os.fstat(fd)
                if (len(data) != opened.st_size or after.st_size != opened.st_size
                        or after.st_mtime_ns != opened.st_mtime_ns
                        or self._namespace._identity(after) != self._namespace._identity(opened)
                        or self._namespace._identity(self._path.lstat()) != self._namespace._identity(opened)):
                    raise ValueError
            finally:
                os.close(fd)
            return ((self._namespace._identity(after), after.st_size, after.st_mtime_ns,
                     hashlib.sha256(data).hexdigest()),
                    json.loads(data.decode('ascii'), object_pairs_hook=self._unique))
        except (OSError, ValueError, UnicodeError, RuntimeError):
            raise Refused('SMTP topology certificate unavailable') from None

    def _validate(self, value):
        try:
            keys = {'version', 'namespace_fingerprint', 'backend_address', 'backend_port',
                    'entrypoints', 'metadata_sha256'}
            if type(value) is dict and value.get('version') == 2:
                keys.add('routing_sha256')
            if (type(value) is not dict or set(value) != keys
                    or type(value['version']) is not int or value['version'] not in (1, 2)
                    or value['namespace_fingerprint'] != self._namespace._fingerprint
                    or value['backend_address'] != self._namespace._backend_address
                    or type(value['backend_port']) is not int
                    or value['backend_port'] != self._namespace._backend_port):
                raise ValueError
            rows = value['entrypoints']
            if type(rows) is not list or not 1 <= len(rows) <= 32:
                raise ValueError
            observed = set()
            for row in rows:
                if (type(row) is not dict or set(row) != {'address', 'port', 'service'}
                        or type(row['address']) is not str
                        or str(ipaddress.ip_address(row['address'])) != row['address']
                        or type(row['port']) is not int or not 1 <= row['port'] <= 65535
                        or row['service'] != 'submission'):
                    raise ValueError
                binding = row['address'], row['port']
                if binding in observed:
                    raise ValueError
                observed.add(binding)
            digests = value['metadata_sha256']
            if (type(digests) is not dict or set(digests) != set(self.COMMANDS)
                    or any(type(v) is not str or not re.fullmatch('[a-f0-9]{64}', v)
                           for v in digests.values())):
                raise ValueError
            if value['version'] == 2:
                routing = value['routing_sha256']
                if (type(routing) is not dict or set(routing) != {'frontend', 'filter'}
                        or any(type(v) is not str or not re.fullmatch('[a-f0-9]{64}', v)
                               for v in routing.values())):
                    raise ValueError
        except (KeyError, ValueError, TypeError):
            raise Refused('SMTP topology coverage unavailable') from None

    def bound_to(self, proxy, budget):
        return (type(proxy) is SmtpProxyControl and proxy._namespace is self._namespace
                and budget is self._budget)

    def recheck(self, budget):
        if budget is not self._budget:
            raise Refused('SMTP topology budget mismatch')
        try:
            if self._routing_plan is not None:
                self._routing_plan.recheck(budget)
            self._namespace.recheck(budget)
            captured, _ = self._read()
            if captured != self._captured:
                raise ValueError
            for name, args in self.COMMANDS.items():
                seconds = budget.cap_seconds(10)
                result = self._execute(self.PROGRAM, args, b'', seconds, self.OUTPUT_LIMIT)
                budget.remaining()
                if (type(result) is not tuple or len(result) != 3 or type(result[0]) is not int
                        or result[0] != 0 or type(result[1]) is not bytes
                        or type(result[2]) is not bytes or result[2]
                        or len(result[1]) > self.OUTPUT_LIMIT
                        or (name != 'services' and not result[1])
                        or hashlib.sha256(result[1]).hexdigest() != self._digests[name]):
                    raise ValueError
            if self._routing_digests is not None:
                for name, (program, args) in self.routing_commands(self._namespace).items():
                    result = self._execute(program, args, b'', budget.cap_seconds(10), self.OUTPUT_LIMIT)
                    budget.remaining()
                    if (type(result) is not tuple or len(result) != 3 or type(result[0]) is not int
                            or result[0] != 0 or type(result[1]) is not bytes
                            or type(result[2]) is not bytes or result[2]
                            or not 0 < len(result[1]) <= self.OUTPUT_LIMIT
                            or hashlib.sha256(result[1]).hexdigest() != self._routing_digests[name]):
                        raise ValueError
            self._namespace.recheck(budget)
            if self._read()[0] != self._captured:
                raise ValueError
            if self._routing_plan is not None:
                self._routing_plan.recheck(budget)
            budget.remaining()
        except Exception:
            raise Refused('SMTP topology continuity unavailable') from None

    @staticmethod
    def routing_commands(namespace):
        if type(namespace) is not OperatorOwnedProxyNamespace:
            raise Refused('SMTP routing namespace unavailable')
        return {'frontend': ('/usr/local/bin/doveconf', ('-c', str(namespace._config), '-n')),
                'filter': ('/sbin/pfctl', ('-a', '*', '-sr'))}


class SmtpProxyControl:
    """Fixed command adapter only; no production topology promotion.

    query() is pre-write. terminate() is post-write and dispatches at most one
    exact account kick followed by one query. Every uncertainty is explicit;
    there is no automatic retry or fallback to another namespace/account.
    """
    PROGRAM = '/usr/local/bin/doveadm'
    PHASE_SECONDS = 10
    OUTPUT_LIMIT = 4096
    ROW_LIMIT = 64

    def __init__(self, canonical_account, namespace, executor, budget):
        self._account = AuthoritativePasswordAdapter._account(canonical_account)
        if (type(namespace) is not OperatorOwnedProxyNamespace or
                type(budget) is not OperationBudget or not callable(executor)):
            raise Refused('SMTP proxy control unavailable')
        namespace.recheck(budget)
        self._namespace = namespace
        self._execute = executor
        self._budget = budget
        self._state = 'new'

    def bound_to(self, account, budget):
        return account == self._account and budget is self._budget

    @staticmethod
    def commands(account, namespace):
        account = AuthoritativePasswordAdapter._account(account)
        if type(namespace) is not OperatorOwnedProxyNamespace:
            raise Refused('SMTP proxy namespace unavailable')
        prefix = ('-c', str(namespace._config), 'proxy')
        return {'list': prefix + ('list', '-a', str(namespace._ipc)),
                'kick': prefix + ('kick', '-a', str(namespace._ipc), account)}

    def _run(self, command):
        self._namespace.recheck(self._budget)
        seconds = self._budget.cap_seconds(self.PHASE_SECONDS)
        result = self._execute(self.PROGRAM,
            self.commands(self._account, self._namespace)[command], b'', seconds, self.OUTPUT_LIMIT)
        self._budget.remaining()
        self._namespace.recheck(self._budget)
        if (type(result) is not tuple or len(result) != 3 or type(result[0]) is not int
                or type(result[1]) is not bytes or type(result[2]) is not bytes
                or result[2] or len(result[1]) > self.OUTPUT_LIMIT):
            raise ValueError
        return result[0], result[1]

    def _list(self):
        code, data = self._run('list')
        if (code != 0 or not data.endswith(b'\n') or b'\r' in data or b'\x00' in data
                or any(value < 32 and value not in (9, 10) for value in data)):
            raise ValueError
        lines = data.decode('ascii').split('\n')
        if not re.fullmatch(r'username[ \t]+proto[ \t]+src ip[ \t]+dest ip[ \t]+port[ \t]*', lines[0]):
            raise ValueError
        rows = lines[1:-1]
        if len(rows) > self.ROW_LIMIT:
            raise ValueError
        own = 0
        for row in rows:
            fields = row.split()
            if len(fields) != 5:
                raise ValueError
            account = AuthoritativePasswordAdapter._account(fields[0])
            if account != fields[0] or fields[1] != 'submission':
                raise ValueError
            if (str(ipaddress.ip_address(fields[2])) != fields[2]
                    or fields[3] != self._namespace._backend_address
                    or fields[4] != str(self._namespace._backend_port)):
                raise ValueError
            own += account == self._account
        self._budget.remaining()
        return SmtpProxyObservation(self._account, own, self._namespace._fingerprint)

    def query(self, account):
        if account != self._account or self._state != 'new':
            raise Refused('SMTP proxy query refused')
        try:
            observation = self._list()
        except Exception:
            self._state = 'unavailable'
            raise Refused('SMTP proxy query unavailable') from None
        self._state = 'observed'
        return observation

    def terminate(self, account):
        if account != self._account or self._state != 'observed':
            raise Refused('SMTP proxy termination refused')
        self._state = 'kick-dispatched'
        try:
            code, data = self._run('kick')
            match = re.fullmatch(rb'(0|[1-9][0-9]{0,9}) connections kicked\n', data)
            if code != 0 or match is None or int(match[1]) > self.ROW_LIMIT:
                raise ValueError
            acknowledged = int(match[1])
            observation = self._list()
            if observation.connections != 0:
                raise ValueError
            self._budget.remaining()
        except Exception:
            self._state = 'contained'
            raise Unconfirmed('SMTP proxy termination unconfirmed') from None
        self._state = 'finished'
        return SmtpProxyTermination(self._account, acknowledged, 0, self._namespace._fingerprint)


class ContainmentExecutor:
    """Fixed three literal commands; one shared budget, bounded private pipes.

    Neither this class nor unit callback qualification activates a native worker.
    Actual host socket/privilege/confinement, acknowledgement and outer-watchdog
    qualification remain required. No password is accepted in this transport.
    """
    def __init__(self, canonical_account, budget):
        self._program = MailSessionContainment.PROGRAM
        self._output_limit = MailSessionContainment.OUTPUT_LIMIT
        self._commands = tuple(MailSessionContainment.commands(canonical_account).values())
        if type(budget) is not OperationBudget:
            raise Refused('mail containment budget unavailable')
        self._budget = budget

    def __call__(self, program, args, stdin, seconds, limit):
        import os
        import selectors
        import signal
        import subprocess
        import time

        if (type(args) is not tuple or not self._allows(program, args)
                or type(stdin) is not bytes or stdin != b'' or
                type(seconds) not in (int, float) or not 0 < seconds <= 10 or
                type(limit) is not int or limit != self._output_limit):
            raise Refused('mail containment process authority refused')
        duration = self._budget.cap_seconds(seconds)
        inherited = self._budget.inherited_group()
        child = subprocess.Popen((program,) + args, stdin=subprocess.DEVNULL,
                                 stdout=subprocess.PIPE, stderr=subprocess.PIPE,
                                 shell=False, close_fds=True, start_new_session=not inherited,
                                 env={'PATH': '/usr/bin:/usr/local/bin', 'LC_ALL': 'C'})
        deadline = time.monotonic() + duration
        output = bytearray()
        diagnostic = bytearray()
        try:
            with selectors.DefaultSelector() as selector:
                for pipe, kind in ((child.stdout, 'out'), (child.stderr, 'err')):
                    os.set_blocking(pipe.fileno(), False)
                    selector.register(pipe, selectors.EVENT_READ, kind)
                while selector.get_map():
                    remaining = min(deadline - time.monotonic(), self._budget.remaining())
                    if remaining <= 0:
                        raise TimeoutError
                    for key, _ in selector.select(min(remaining, 0.1)):
                        try:
                            data = os.read(key.fd, 4096)
                        except BlockingIOError:
                            continue
                        if not data:
                            selector.unregister(key.fileobj)
                            key.fileobj.close()
                            continue
                        dest = output if key.data == 'out' else diagnostic
                        dest.extend(data)
                        if len(dest) > limit:
                            raise Refused('mail containment output unavailable')
                remaining = min(deadline - time.monotonic(), self._budget.remaining())
                if remaining <= 0:
                    raise TimeoutError
                code = child.wait(timeout=remaining)
                if time.monotonic() >= deadline:
                    raise TimeoutError
                self._budget.remaining()
                return code, bytes(output), bytes(diagnostic)
        except BaseException:
            try:
                if inherited:
                    child.kill()
                else:
                    os.killpg(child.pid, signal.SIGKILL)
            except ProcessLookupError:
                pass
            child.wait(timeout=2)
            raise
        finally:
            for pipe in (child.stdout, child.stderr):
                if not pipe.closed:
                    pipe.close()

    def _allows(self, program, args):
        return program == self._program and args in self._commands


class ProxyControlExecutor(ContainmentExecutor):
    """Same inherited worker budget/process supervision, fixed proxy argv only."""
    def __init__(self, canonical_account, namespace, budget):
        if type(budget) is not OperationBudget or type(namespace) is not OperatorOwnedProxyNamespace:
            raise Refused('SMTP proxy process authority unavailable')
        namespace.recheck(budget)
        self._commands = tuple(SmtpProxyControl.commands(canonical_account, namespace).values())
        self._program = SmtpProxyControl.PROGRAM
        self._output_limit = SmtpProxyControl.OUTPUT_LIMIT
        self._namespace = namespace
        self._budget = budget

    def __call__(self, program, args, stdin, seconds, limit):
        self._namespace.recheck(self._budget)
        return super().__call__(program, args, stdin, seconds, limit)


class TopologyExecutor(ContainmentExecutor):
    """Only three fixed non-mutating Postfix metadata commands, private pipes."""
    def __init__(self, budget):
        if type(budget) is not OperationBudget:
            raise Refused('SMTP topology process authority unavailable')
        self._program = OperatorOwnedSmtpTopology.PROGRAM
        self._output_limit = OperatorOwnedSmtpTopology.OUTPUT_LIMIT
        self._commands = tuple(OperatorOwnedSmtpTopology.COMMANDS.values())
        self._budget = budget


class RoutingMetadataExecutor(ContainmentExecutor):
    """Exact metadata tuples only; no shell, filter/config mutation or secrets input."""
    def __init__(self, namespace, budget):
        if type(namespace) is not OperatorOwnedProxyNamespace or type(budget) is not OperationBudget:
            raise Refused('SMTP routing process authority unavailable')
        self._namespace = namespace
        self._pairs = tuple((OperatorOwnedSmtpTopology.PROGRAM, args)
            for args in OperatorOwnedSmtpTopology.COMMANDS.values()) + tuple(
                OperatorOwnedSmtpTopology.routing_commands(namespace).values())
        self._output_limit = OperatorOwnedSmtpTopology.OUTPUT_LIMIT
        self._budget = budget

    def _allows(self, program, args):
        return (program, args) in self._pairs

    def __call__(self, program, args, stdin, seconds, limit):
        self._namespace.recheck(self._budget)
        return super().__call__(program, args, stdin, seconds, limit)
