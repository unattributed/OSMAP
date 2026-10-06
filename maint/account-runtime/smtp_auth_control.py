"""Disabled accepted-channel control for the broker's held epoch cutoff.

This supplies no listener, provisioning or complete-ingress qualification. A
trusted supervisor must construct the operation with its authenticated original
budget and independently produced version2 topology; no wire deadline or
Boolean can construct that authority. Native construction remains unavailable.
The same connection holds a source-owned cutoff between capture and cancellation.
An acknowledgment proves SASL closure only, never Postfix TCP absence.
"""
import re
import socket

from authoritative_password import AuthoritativePasswordAdapter, Refused, Unconfirmed
from mail_session_containment import OperatorOwnedProxyNamespace, OperatorOwnedSmtpTopology
from operation_budget import OperationBudget
from smtp_auth_lifecycle import SmtpAuthLifecycle, _Cutoff, _kernel_peer, _socket_identity
from smtp_control_authorization import VerifiedControlAuthorization

NATIVE_CONTROL_QUALIFIED = False
LIMIT = 512
CAPTURE = b'OSMAP-SMTP-CAPTURE\t'
CAPTURED = b'OSMAP-SMTP-CAPTURED\n'
CANCEL = b'OSMAP-SMTP-CANCEL\n'
CLOSED = b'OSMAP-SMTP-CLOSED\t'


def _line(stream, budget):
    value = bytearray()
    while not value.endswith(b'\n'):
        stream.settimeout(budget.cap_seconds(1))
        block = stream.recv(LIMIT + 1 - len(value))
        if not block or len(value) + len(block) > LIMIT:
            raise Refused('SMTP control frame unavailable')
        value.extend(block)
    budget.remaining()
    if value.count(b'\n') != 1 or b'\r' in value or b'\0' in value:
        raise Refused('SMTP control frame refused')
    return bytes(value)


def _send(stream, value, budget):
    stream.settimeout(budget.cap_seconds(1))
    stream.sendall(value)
    budget.remaining()


class LifecycleControlOperation:
    """One trusted startup operation, never a wire factory or reusable budget."""
    def __init__(self, registry, namespace, topology, budget, *, admitted_account=None, admitted_authorization=None, listener_recheck=None):
        if (type(registry) is not SmtpAuthLifecycle
                or type(namespace) is not OperatorOwnedProxyNamespace
                or type(topology) is not OperatorOwnedSmtpTopology
                or type(budget) is not OperationBudget
                or topology._namespace is not namespace or topology._budget is not budget
                or topology._certificate_version != 2
                or topology._routing_plan is None
                or not topology._routing_plan.bound_to(namespace, budget)
                or registry._store.uid != namespace._owner
                or registry._store.root == namespace._root
                or registry._authority._port != namespace._backend_port
                or namespace._backend_address != '127.0.0.1'):
            raise Refused('SMTP control startup authority unavailable')
        self._registry = registry
        self._namespace = namespace
        self._topology = topology
        self._budget = budget
        self._state = 'new'
        if admitted_account is not None:
            AuthoritativePasswordAdapter._account(admitted_account)
            if admitted_account not in registry._accounts:
                raise Refused('SMTP control admitted account unavailable')
        if admitted_authorization is not None:
            if (type(admitted_authorization) is not VerifiedControlAuthorization
                    or admitted_authorization.account != admitted_account):
                raise Refused('SMTP control sealed binding unavailable')
        self._admitted_account = admitted_account
        if listener_recheck is not None and not callable(listener_recheck):
            raise Refused('SMTP control listener continuity unavailable')
        self._listener_recheck = listener_recheck
        self._admitted_authorization = admitted_authorization
        topology.recheck(budget)

    @classmethod
    def native(cls, *_args):
        # No environment/caller activation, files, connection or listener.
        raise Refused('native SMTP control composition unavailable')

    def _authority(self, stream, identity):
        self._budget.remaining()
        if (getattr(self._registry, '_control_uncertain', False)
                or _socket_identity(stream) != identity
                or _kernel_peer(stream)[0] != self._namespace._owner):
            raise Refused('SMTP control peer or continuity refused')
        self._topology.recheck(self._budget)
        if self._listener_recheck is not None:
            self._listener_recheck()

    def _capture(self, account):
        if self._admitted_authorization is None:
            return self._registry.pending_cutoff_locked(account, self._budget)
        # Mint from the SAME durable record checked against the independently
        # MACed original operation; routing/journal time cannot swap its intent.
        with self._registry._guard(self._budget):
            value = self._registry._record(account)
            authorization = self._admitted_authorization
            if (value['state'] not in ('pending', 'contained')
                    or value['epoch'] != authorization.epoch
                    or value['intent'] != authorization.intent_reference
                    or len(self._registry._cutoffs) >= self._registry.MAX_CUTOFFS):
                raise Refused('SMTP control original pending binding changed')
            cutoff = _Cutoff(self._registry, account, value['epoch'], value['intent'])
            self._registry._cutoffs.add(cutoff)
            return cutoff

    def serve(self, stream):
        try:
            return self._serve(stream, lambda value, budget: _send(stream, value, budget))
        finally:
            stream.close()

    def _serve(self, stream, terminal_sink):
        # Private trusted supervisor composition may defer terminal publication
        # until its durable purpose grant is committed under this same budget.
        if self._state != 'new':
            raise Refused('SMTP control operation already consumed')
        self._state = 'serving'
        cutoff = None
        try:
            identity = _socket_identity(stream)
            self._authority(stream, identity)
            raw = _line(stream, self._budget)
            if not raw.startswith(CAPTURE) or raw.count(b'\t') != 1:
                raise Refused('SMTP control request refused')
            account = raw[len(CAPTURE):-1].decode('ascii')
            AuthoritativePasswordAdapter._account(account)
            if (account not in self._registry._accounts or
                    self._admitted_account is not None and account != self._admitted_account):
                raise Refused('SMTP control account refused')
            self._authority(stream, identity)
            # Trusted mutation owner already holds the same account flock.
            # Durable pending/contained state supplies epoch+intent; no RPC
            # field can choose either. Reacquiring that flock would deadlock.
            cutoff = self._capture(account)
            self._authority(stream, identity)
            _send(stream, CAPTURED, self._budget)
            if _line(stream, self._budget) != CANCEL:
                raise Refused('SMTP control cancellation refused')
            self._authority(stream, identity)
            count = self._registry.cancel_cutoff_locked(cutoff, self._budget)
            if type(count) is not int or not 0 <= count <= self._registry.MAX_CHANNELS:
                raise Unconfirmed('SMTP control closure unconfirmed')
            self._authority(stream, identity)
            terminal_sink(CLOSED + str(count).encode('ascii') + b'\n', self._budget)
            self._state = 'complete'
            return count
        except Exception:
            self._state = 'unconfirmed' if cutoff is not None else 'refused'
            if cutoff is not None:
                # No abandoned-cutoff retry/reset or new budget. Retain local
                # uncertainty; a late/missing ACK cannot prove TCP containment.
                self._registry._control_uncertain = True
                raise Unconfirmed('SMTP control requires reconciliation') from None
            raise Refused('SMTP control unavailable') from None


class LifecycleControlClient:
    """Accepted private descriptor and original budget from trusted supervisor."""
    def __init__(self, stream, namespace, budget):
        if type(namespace) is not OperatorOwnedProxyNamespace or type(budget) is not OperationBudget:
            raise Refused('SMTP control client authority unavailable')
        self._stream = stream
        self._namespace = namespace
        self._budget = budget
        self._identity = _socket_identity(stream)
        self._state = 'new'
        self._recheck()

    def _recheck(self):
        self._budget.remaining()
        self._namespace.recheck(self._budget)
        if (_socket_identity(self._stream) != self._identity
                or _kernel_peer(self._stream)[0] != self._namespace._owner):
            raise Refused('SMTP control client peer refused')

    def capture(self, account):
        if self._state != 'new':
            raise Refused('SMTP control capture already consumed')
        self._state = 'capture-dispatched'
        try:
            AuthoritativePasswordAdapter._account(account)
            self._recheck()
            _send(self._stream, CAPTURE + account.encode('ascii') + b'\n', self._budget)
            if _line(self._stream, self._budget) != CAPTURED:
                raise Refused('SMTP control capture acknowledgment unavailable')
            self._recheck()
            self._state = 'captured'
        except Exception:
            self._stream.close()
            raise Unconfirmed('SMTP control capture unconfirmed') from None

    def cancel(self):
        if self._state != 'captured':
            raise Refused('SMTP control cancellation unavailable')
        self._state = 'cancel-dispatched'
        try:
            self._recheck()
            _send(self._stream, CANCEL, self._budget)
            value = _line(self._stream, self._budget)
            if not value.startswith(CLOSED):
                raise ValueError
            raw = value[len(CLOSED):-1]
            if not re.fullmatch(rb'(?:0|[1-9][0-9]{0,2})', raw) or int(raw) > 256:
                raise ValueError
            self._recheck()
            self._state = 'complete'
            return int(raw)
        except Exception:
            raise Unconfirmed('SMTP control cancellation unconfirmed') from None
        finally:
            self._stream.close()
