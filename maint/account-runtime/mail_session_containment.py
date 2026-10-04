"""Disabled helper-owned exact-account Dovecot containment dependency.

Installed 2.3.21.1 syntax and upstream response parsers inform this source;
neither help nor callback tests qualify actual cache invalidation or termination.
The observed authoritative Postfix submission services have SASL enabled. SMTP
is REQUIRED, and lacks qualified own-account connection termination. Therefore
native pre-write admission remains unavailable. No browser/config opt-in exists.

Cache invalidation occurs after the conditional password write and before new
credential verification. Only the separate kick plus one who reconciliation
can confirm a bounded zero-connections observation. This does not exclude a
concurrent native login, revoke browser records or contain Postfix connections.
"""
from enum import Enum
import re

from authoritative_password import AuthoritativePasswordAdapter, Refused, Unconfirmed
from operation_budget import OperationBudget

NATIVE_CONFINEMENT_QUALIFIED = False


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

    def __init__(self, canonical_account, executor, budget, smtp_scope):
        self._account = AuthoritativePasswordAdapter._account(canonical_account)
        if (type(budget) is not OperationBudget or
                type(smtp_scope) is not SmtpTerminationScope or not callable(executor)):
            raise Refused('mail containment dependency unavailable')
        self._execute = executor
        self._budget = budget
        self._smtp_scope = smtp_scope
        self._state = 'new'

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
        if self._smtp_scope is not SmtpTerminationScope.NOT_APPLICABLE:
            self._state = 'unavailable'
            raise Refused('SMTP termination dependency unavailable')
        try:
            self._who()
        except Exception:
            self._state = 'unavailable'
            raise Refused('mail containment unavailable') from None
        self._state = 'ready'
        return True

    def invalidate_changed_auth(self, account):
        self._owned(account, 'ready')
        self._state = 'flush-dispatched'
        try:
            code, data = self._run('flush', post_write=True)
            if code != 0 or not re.fullmatch(rb'(?:0|[1-9][0-9]{0,9}) cache entries flushed\n', data):
                raise ValueError
            if int(data.split(b' ', 1)[0]) > 2**32 - 1:
                raise ValueError
            self._budget.remaining()
        except Exception:
            self._state = 'contained'
            raise Unconfirmed('authentication cache invalidation unconfirmed') from None
        self._state = 'flushed'
        return True

    def finish(self, account):
        self._owned(account, 'flushed')
        self._state = 'kick-dispatched'
        try:
            code, data = self._run('kick', post_write=True)
            no_users = code == 68 and data == b'no users kicked\n'
            kicked = (code == 0 and data == b'kicked connections from the following users:\n'
                      + self._account.encode('ascii') + b' \n')
            if not (no_users or kicked) or self._who(post_write=True) != 0:
                raise ValueError
            self._budget.remaining()
        except Exception:
            self._state = 'contained'
            raise Unconfirmed('mail connection termination unconfirmed') from None
        self._state = 'finished'
        return True


def build_native_containment(canonical_account, budget):
    """Helper-startup seam only. Native topology/SMTP/confinement is unqualified."""
    if not NATIVE_CONFINEMENT_QUALIFIED:
        raise Refused('native mail containment unavailable')
    # The actual currently observed scope is REQUIRED, not inferred N/A from
    # cache size0 or the earlier incomplete inet-only master-service parser.
    return MailSessionContainment(canonical_account,
                                  ContainmentExecutor(canonical_account, budget),
                                  budget, SmtpTerminationScope.REQUIRED)


class ContainmentExecutor:
    """Fixed three literal commands; one shared budget, bounded private pipes.

    Neither this class nor unit callback qualification activates a native worker.
    Actual host socket/privilege/confinement, acknowledgement and outer-watchdog
    qualification remain required. No password is accepted in this transport.
    """
    def __init__(self, canonical_account, budget):
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

        if (program != MailSessionContainment.PROGRAM or type(args) is not tuple or
                args not in self._commands or type(stdin) is not bytes or stdin != b'' or
                type(seconds) not in (int, float) or not 0 < seconds <= 10 or
                type(limit) is not int or limit != 4096):
            raise Refused('mail containment process authority refused')
        duration = self._budget.cap_seconds(seconds)
        child = subprocess.Popen((program,) + args, stdin=subprocess.DEVNULL,
                                 stdout=subprocess.PIPE, stderr=subprocess.PIPE,
                                 shell=False, close_fds=True, start_new_session=True,
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
                os.killpg(child.pid, signal.SIGKILL)
            except ProcessLookupError:
                pass
            child.wait(timeout=2)
            raise
        finally:
            for pipe in (child.stdout, child.stderr):
                if not pipe.closed:
                    pipe.close()
