"""Disabled fixed helper bootstrap for REQUIRED SMTP configuration authority.

Source fixtures qualify exact private-plan parsing and metadata continuity only.
The compile-time native gate remains false until complete ingress restriction,
all-auth-entrypoint epoch fencing, privilege and native termination qualify.
An approved digest is not a proof of firewall semantics or live routing.
"""
import hashlib
import ipaddress
import json
import os
from pathlib import Path
import re
import shlex
import stat

from authoritative_password import Refused
from mail_session_containment import (OperatorOwnedProxyNamespace, OperatorOwnedSmtpTopology,
                                     RoutingMetadataExecutor)
from operation_budget import OperationBudget

NATIVE_ROUTING_BOOTSTRAP_QUALIFIED = False


class FixedSmtpRouting:
    ROOT = Path('/etc/osmap/account-runtime')
    PLAN = 'smtp-routing.json'
    LIMIT = 8192

    @classmethod
    def native(cls, budget):
        # No environment/config/browser opt-in or fallback certificate path.
        if (not NATIVE_ROUTING_BOOTSTRAP_QUALIFIED or os.geteuid() != 0
                or os.uname().sysname != 'OpenBSD'
                or os.uname().nodename != 'mail.blackbagsecurity.com'):
            raise Refused('native SMTP routing bootstrap unavailable')
        return cls.produce(cls.ROOT, 0, budget)

    @staticmethod
    def _identity(info):
        return (info.st_dev, info.st_ino, info.st_uid, info.st_gid,
                info.st_mode, info.st_nlink, info.st_size, info.st_mtime_ns)

    @classmethod
    def _private_read(cls, root, owner, budget):
        budget.remaining()
        try:
            if (not isinstance(root, Path) or not root.is_absolute()
                    or root.resolve(strict=True) != root or type(owner) is not int or owner < 0):
                raise ValueError
            for parent in tuple(reversed(root.parents)) + (root,):
                info = parent.lstat()
                sticky = parent == Path('/tmp') and info.st_uid == 0 and info.st_mode & stat.S_ISVTX
                if (not stat.S_ISDIR(info.st_mode) or info.st_uid not in (0, owner)
                        or (info.st_mode & 0o022 and not sticky)):
                    raise ValueError
            directory = root.lstat()
            if directory.st_uid != owner or directory.st_mode & 0o077:
                raise ValueError
            path = root / cls.PLAN
            before = path.lstat()
            if (not stat.S_ISREG(before.st_mode) or before.st_uid != owner
                    or before.st_mode & 0o077 or before.st_nlink != 1
                    or not 0 < before.st_size <= cls.LIMIT):
                raise ValueError
            fd = os.open(path, os.O_RDONLY | os.O_NOFOLLOW)
            try:
                opened = os.fstat(fd)
                if cls._identity(opened) != cls._identity(before):
                    raise ValueError
                data = bytearray()
                while len(data) <= cls.LIMIT:
                    budget.remaining()
                    chunk = os.read(fd, min(4096, cls.LIMIT + 1 - len(data)))
                    if not chunk:
                        break
                    data.extend(chunk)
                if (len(data) != opened.st_size or len(data) > cls.LIMIT
                        or cls._identity(os.fstat(fd)) != cls._identity(opened)
                        or cls._identity(path.lstat()) != cls._identity(opened)
                        or cls._identity(root.lstat()) != cls._identity(directory)):
                    raise ValueError
            finally:
                os.close(fd)
            value = json.loads(data.decode('ascii'), object_pairs_hook=OperatorOwnedSmtpTopology._unique)
            budget.remaining()
            return (cls._identity(directory), cls._identity(before), hashlib.sha256(data).hexdigest()), value
        except (OSError, ValueError, UnicodeError, RuntimeError):
            raise Refused('private SMTP routing plan unavailable') from None

    @classmethod
    def _plan(cls, value):
        try:
            if (type(value) is not dict or set(value) != {'version', 'namespace_root',
                    'backend_address', 'backend_port', 'entrypoints', 'metadata_sha256', 'routing_sha256'}
                    or type(value['version']) is not int or value['version'] != 1
                    or type(value['namespace_root']) is not str
                    or not value['namespace_root'].isascii()
                    or not 1 <= len(value['namespace_root']) <= 512):
                raise ValueError
            root = Path(value['namespace_root'])
            if not root.is_absolute() or root.resolve(strict=True) != root:
                raise ValueError
            if (type(value['backend_address']) is not str
                    or str(ipaddress.ip_address(value['backend_address'])) != value['backend_address']
                    or not ipaddress.ip_address(value['backend_address']).is_loopback
                    or type(value['backend_port']) is not int or not 1 <= value['backend_port'] <= 65535):
                raise ValueError
            rows = value['entrypoints']
            if type(rows) is not list or not 1 <= len(rows) <= 32:
                raise ValueError
            seen = set()
            for row in rows:
                if (type(row) is not dict or set(row) != {'address', 'port', 'service'}
                        or type(row['address']) is not str
                        or str(ipaddress.ip_address(row['address'])) != row['address']
                        or type(row['port']) is not int or not 1 <= row['port'] <= 65535
                        or row['service'] != 'submission'):
                    raise ValueError
                key = row['address'], row['port']
                if key in seen or key == (value['backend_address'], value['backend_port']):
                    raise ValueError
                seen.add(key)
            for key, names in [('metadata_sha256', set(OperatorOwnedSmtpTopology.COMMANDS)),
                               ('routing_sha256', {'frontend', 'filter'})]:
                digests = value[key]
                if (type(digests) is not dict or set(digests) != names
                        or any(type(v) is not str or not re.fullmatch('[a-f0-9]{64}', v)
                               for v in digests.values())):
                    raise ValueError
            return root
        except (OSError, ValueError, KeyError, TypeError, RuntimeError):
            raise Refused('SMTP routing plan shape unavailable') from None

    @staticmethod
    def _text(data):
        if type(data) is not bytes or len(data) > OperatorOwnedSmtpTopology.OUTPUT_LIMIT or b'\x00' in data:
            raise Refused('SMTP routing metadata unavailable')
        try:
            return data.decode('ascii')
        except UnicodeError:
            raise Refused('SMTP routing metadata unavailable') from None

    @staticmethod
    def _endpoint(service):
        try:
            # Require exact numeric canonical addresses/ports. Service aliases,
            # hostnames, wildcard listeners and ambiguous IPv6 syntax refuse.
            if service.startswith('['):
                match = re.fullmatch(r'\[([0-9a-f:]+)\]:([0-9]+)', service)
            else:
                match = re.fullmatch(r'([0-9.]+):([0-9]+)', service)
            if match is None:
                raise ValueError
            address, port = match.groups()
            if str(ipaddress.ip_address(address)) != address or str(int(port)) != port or not 1 <= int(port) <= 65535:
                raise ValueError
            return address, int(port)
        except ValueError:
            raise Refused('Postfix authenticated entrypoint unavailable') from None

    @classmethod
    def _postfix(cls, metadata, plan):
        """Reject every SMTP AUTH entrypoint outside the exact private backend."""
        try:
            global_auth = cls._text(metadata['global_auth']).strip()
            if global_auth not in ('yes', 'no'):
                raise ValueError
            overrides = {}
            for line in cls._text(metadata['services']).splitlines():
                if not line.strip():
                    continue
                key, separator, value = line.partition('=')
                parts = key.strip().split('/')
                if not separator or len(parts) != 3 or not all(parts) or key.strip() in overrides:
                    raise ValueError
                overrides[key.strip()] = value.strip()
            records = []; current = ''
            for line in cls._text(metadata['master']).splitlines():
                if not line.strip() or line.lstrip().startswith('#'):
                    continue
                if line[:1].isspace():
                    if not current:
                        raise ValueError
                    current += ' ' + line.strip()
                else:
                    if current:
                        records.append(current)
                    current = line
            if current:
                records.append(current)
            if not records or len(records) > 128:
                raise ValueError
            seen = set(); backend_found = False
            for line in records:
                fields = shlex.split(line)
                if len(fields) < 8:
                    raise ValueError
                service, kind = fields[:2]; program = fields[7]
                pair = service, kind
                if pair in seen or kind not in ('inet', 'unix', 'pass', 'fifo'):
                    raise ValueError
                seen.add(pair)
                if kind == 'inet' and program not in ('smtpd', 'postscreen'):
                    raise ValueError
                if program != 'smtpd':
                    continue
                inline = {}
                tail = fields[8:]; i = 0
                while i < len(tail):
                    if tail[i] == '-o':
                        i += 1
                        if i >= len(tail) or '=' not in tail[i]:
                            raise ValueError
                        key, value = tail[i].split('=', 1)
                        if key in inline:
                            raise ValueError
                        inline[key] = value
                    elif tail[i].startswith('-o'):
                        raise ValueError
                    i += 1
                key = service + '/' + kind + '/smtpd_sasl_auth_enable'
                auth = overrides.get(key, global_auth)
                if ('smtpd_sasl_auth_enable' in inline
                        and inline['smtpd_sasl_auth_enable'] != auth):
                    raise ValueError
                if auth not in ('yes', 'no'):
                    raise ValueError
                if auth == 'yes':
                    if kind != 'inet' or cls._endpoint(service) != (plan['backend_address'], plan['backend_port']):
                        raise ValueError
                    backend_found = True
                elif kind == 'inet' and cls._endpoint(service) == (plan['backend_address'], plan['backend_port']):
                    raise ValueError
            # A stale override for an absent master service cannot certify the
            # effective auth profile; reject ambiguous/incomplete snapshots.
            if any(tuple(key.split('/')[:2]) not in seen for key in overrides):
                raise ValueError
            if not backend_found:
                raise ValueError
        except (ValueError, KeyError, TypeError):
            raise Refused('Postfix SMTP AUTH coverage unavailable') from None

    @classmethod
    def _frontend(cls, data, plan):
        """Bounded effective doveconf grammar; no implicit listen defaults."""
        try:
            stack = []; global_listen = None; listeners = []; item = None
            for raw in cls._text(data).splitlines():
                line = raw.strip()
                if not line or line.startswith('#'):
                    continue
                if line.endswith('{'):
                    head = line[:-1].strip().split()
                    if not head or len(stack) >= 8:
                        raise ValueError
                    stack.append(tuple(head))
                    if head[0] == 'inet_listener':
                        if len(head) != 2 or len(stack) != 2 or stack[0] != ('service', 'submission-login'):
                            raise ValueError
                        item = {'port': 0, 'address': None, 'port_seen': False}
                    continue
                if line == '}':
                    if not stack:
                        raise ValueError
                    head = stack.pop()
                    if head[0] == 'inet_listener':
                        if item is None:
                            raise ValueError
                        listeners.append(item); item = None
                    continue
                key, separator, value = line.partition('=')
                if not separator or not key.strip() or '{' in line or '}' in line:
                    raise ValueError
                key = key.strip(); value = value.strip()
                if not stack and key == 'listen':
                    if global_listen is not None:
                        raise ValueError
                    global_listen = cls._addresses(value)
                if item is not None and len(stack) == 2:
                    if key == 'port':
                        if item['port_seen'] or not re.fullmatch(r'0|[1-9][0-9]{0,4}', value) or int(value) > 65535:
                            raise ValueError
                        item['port'] = int(value); item['port_seen'] = True
                    elif key == 'address':
                        if item['address'] is not None:
                            raise ValueError
                        item['address'] = cls._addresses(value)
            if stack or item is not None or not listeners:
                raise ValueError
            actual = set()
            for listener in listeners:
                if listener['port'] == 0:
                    continue
                addresses = listener['address'] if listener['address'] is not None else global_listen
                if not addresses:
                    raise ValueError
                for address in addresses:
                    key = address, listener['port']
                    if key in actual:
                        raise ValueError
                    actual.add(key)
            expected = {(r['address'], r['port']) for r in plan['entrypoints']}
            if actual != expected:
                raise ValueError
        except (ValueError, TypeError, KeyError):
            raise Refused('Dovecot SMTP listener coverage unavailable') from None

    @staticmethod
    def _addresses(value):
        values = value.replace(',', ' ').split()
        if not 1 <= len(values) <= 32:
            raise ValueError
        result = []
        for item in values:
            address = ipaddress.ip_address(item)
            if str(address) != item or item in result:
                raise ValueError
            result.append(item)
        return result

    @classmethod
    def produce(cls, root, owner, budget, *, executor=None):
        if type(budget) is not OperationBudget:
            raise Refused('SMTP bootstrap budget unavailable')
        captured, plan = cls._private_read(root, owner, budget)
        namespace_root = cls._plan(plan)
        namespace = OperatorOwnedProxyNamespace(namespace_root, owner, plan['backend_address'], plan['backend_port'])
        witness = PrivateRoutingPlan(root, owner, budget, namespace, captured)
        execute = executor if executor is not None else RoutingMetadataExecutor(namespace, budget)
        if not callable(execute):
            raise Refused('SMTP bootstrap metadata dependency unavailable')
        metadata = {}; routing = {}
        commands = [(name, OperatorOwnedSmtpTopology.PROGRAM, args, metadata, plan['metadata_sha256'])
                    for name, args in OperatorOwnedSmtpTopology.COMMANDS.items()]
        commands += [(name, program, args, routing, plan['routing_sha256'])
                     for name, (program, args) in OperatorOwnedSmtpTopology.routing_commands(namespace).items()]
        for name, program, args, destination, pins in commands:
            result = execute(program, args, b'', budget.cap_seconds(10), OperatorOwnedSmtpTopology.OUTPUT_LIMIT)
            budget.remaining()
            if (type(result) is not tuple or len(result) != 3 or type(result[0]) is not int or result[0] != 0
                    or type(result[1]) is not bytes or type(result[2]) is not bytes or result[2]
                    or len(result[1]) > OperatorOwnedSmtpTopology.OUTPUT_LIMIT
                    or (name != 'services' and not result[1])
                    or hashlib.sha256(result[1]).hexdigest() != pins[name]):
                raise Refused('SMTP bootstrap metadata continuity unavailable')
            destination[name] = result[1]
        cls._postfix(metadata, plan)
        cls._frontend(routing['frontend'], plan)
        # Filter bytes are a continuity witness only. A separately qualified
        # native bootstrap must prove ingress/identity/epoch enforcement, not
        # infer it from this digest or an empty rule set.
        if not cls._text(routing['filter']).strip():
            raise Refused('SMTP filter metadata unavailable')
        namespace.recheck(budget)
        if cls._private_read(root, owner, budget)[0] != captured:
            raise Refused('SMTP routing plan changed')
        certificate = {'version': 2, 'namespace_fingerprint': namespace._fingerprint,
            'backend_address': plan['backend_address'], 'backend_port': plan['backend_port'],
            'entrypoints': plan['entrypoints'], 'metadata_sha256': plan['metadata_sha256'],
            'routing_sha256': plan['routing_sha256']}
        encoded = json.dumps(certificate, sort_keys=True, separators=(',', ':')).encode('ascii')
        path = namespace_root / 'smtp-topology.json'
        try:
            fd = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW, 0o600)
        except FileExistsError:
            existing = OperatorOwnedSmtpTopology(namespace, execute, budget, routing_plan=witness)
            if existing._read()[1] != certificate:
                raise Refused('SMTP topology certificate changed') from None
            return namespace, existing
        except OSError:
            raise Refused('SMTP topology publication unavailable') from None
        try:
            budget.remaining()
            if os.write(fd, encoded) != len(encoded):
                raise OSError
            os.fsync(fd)
            budget.remaining()
        except Exception:
            # Never overwrite/reset an uncertain partial publication. Next
            # startup refuses its malformed or changed private record.
            raise Refused('SMTP topology publication unconfirmed') from None
        finally:
            os.close(fd)
        dfd = os.open(namespace_root, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW)
        try:
            os.fsync(dfd)
        finally:
            os.close(dfd)
        namespace.recheck(budget)
        if cls._private_read(root, owner, budget)[0] != captured:
            raise Refused('SMTP routing plan changed')
        topology = OperatorOwnedSmtpTopology(namespace, execute, budget, routing_plan=witness)
        budget.remaining()
        return namespace, topology


class PrivateRoutingPlan:
    """Typed owned plan continuity witness; no caller truth-value authority."""
    def __init__(self, root, owner, budget, namespace, captured):
        if (type(namespace) is not OperatorOwnedProxyNamespace
                or type(budget) is not OperationBudget or namespace._owner != owner):
            raise Refused('SMTP routing plan witness unavailable')
        current, value = FixedSmtpRouting._private_read(root, owner, budget)
        if current != captured or FixedSmtpRouting._plan(value) != namespace._root:
            raise Refused('SMTP routing plan witness changed')
        self._root = root
        self._owner = owner
        self._budget = budget
        self._namespace = namespace
        self._captured = current

    def bound_to(self, namespace, budget):
        return namespace is self._namespace and budget is self._budget

    def recheck(self, budget):
        if budget is not self._budget:
            raise Refused('SMTP routing plan budget mismatch')
        budget.remaining()
        if FixedSmtpRouting._private_read(self._root, self._owner, budget)[0] != self._captured:
            raise Refused('SMTP private routing plan changed')
        budget.remaining()
