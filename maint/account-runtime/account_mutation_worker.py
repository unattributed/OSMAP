"""Disabled authenticated mutation component with durable intent ownership.

Helper-only constructors provide private key, exact allowed accounts, stores and
qualified coordinator/session dependencies. None is a wire field. Native socket,
worker privilege, actual current session and mail/SMTP containment qualification
are still required. No existing admission worker, startup or browser route
imports this module. A failed reply never implies a failed credential write.
"""
from contextlib import contextmanager
import fcntl
import hashlib
import json
import os
import socket
import struct
import sys
import time

from account_epoch import EpochStore
from authoritative_password import AuthoritativePasswordAdapter, Refused, Unconfirmed
from account_mutation_codec import (LIMIT, Invalid, VerifiedRequest, encoded, key_valid,
                                    lower_hex, response, uint, valid_outcome, verify_request)
from operation_budget import OperationBudget
from prepared_password import PreparedPasswordCoordinator

NATIVE_CONFINEMENT_QUALIFIED = False


class Unavailable(Exception):
    """No trustworthy no-write outcome; reconcile rather than retry."""


class IntentStore(EpochStore):
    """Separate helper-private journal; one bounded lock per exact account.

    Provision is an explicit operator action. Missing/corrupt/unconfirmed records
    never recreate consumed authority. Pending/uncertain work blocks the account
    until operator reconciliation; expiry cannot silently clear uncertainty.
    The lock order is session (Rust) -> intent -> account epoch. No coordinator
    callback may reacquire the intent/session lock while this lease is held.
    """
    RECORD_LIMIT = 16384
    MAX_ENTRIES = 32

    def _paths(self, account):
        AuthoritativePasswordAdapter._account(account)
        name = hashlib.sha256(b'osmap-account-mutation-intents-v1\0' + account.encode()).hexdigest()
        return self.root / (name + '.lock'), self.root / (name + '.json')

    def provision(self, account):
        with super().locked(account) as path:
            if path.exists() or path.is_symlink():
                raise Refused('mutation journal already provisioned')
            self._publish(path, {'version': 1, 'high_water': 0, 'entries': []})

    def _publish(self, path, value):
        # Reuse the reviewed atomic replace/fsync writer without interpreting a
        # journal timestamp or modified SQL value as an account epoch.
        import tempfile
        raw = encoded(value)
        if len(raw) > self.RECORD_LIMIT:
            raise Unavailable('mutation journal unavailable')
        descriptor, name = tempfile.mkstemp(prefix='.mutation-intents-', dir=self.root)
        try:
            os.fchmod(descriptor, 0o600)
            with os.fdopen(descriptor, 'wb') as handle:
                handle.write(raw)
                handle.flush()
                os.fsync(handle.fileno())
            os.replace(name, path)
            directory = os.open(self.root, os.O_RDONLY | os.O_DIRECTORY)
            try:
                os.fsync(directory)
            finally:
                os.close(directory)
        finally:
            try:
                os.unlink(name)
            except FileNotFoundError:
                pass

    def _record(self, path):
        try:
            descriptor = self._private(path, os.O_RDONLY)
            with os.fdopen(descriptor, 'rb') as handle:
                data = handle.read(self.RECORD_LIMIT + 1)
            if len(data) > self.RECORD_LIMIT:
                raise ValueError
            value = json.loads(data, object_pairs_hook=self._unique)
            if (type(value) is not dict or set(value) != {'version', 'high_water', 'entries'} or
                    type(value['version']) is not int or value['version'] != 1 or
                    not uint(value['high_water']) or type(value['entries']) is not list or
                    len(value['entries']) > self.MAX_ENTRIES):
                raise ValueError
            seen = set()
            for entry in value['entries']:
                if (type(entry) is not dict or set(entry) != {'intent', 'mac', 'issued', 'expires',
                                                          'epoch', 'state', 'outcome'} or
                        not lower_hex(entry['intent']) or not lower_hex(entry['mac']) or
                        entry['intent'] in seen or not uint(entry['issued']) or entry['issued'] == 0 or
                        not uint(entry['expires']) or entry['expires'] != entry['issued'] + 300 or
                        not uint(entry['epoch']) or entry['state'] not in ('pending', 'complete', 'uncertain') or
                        (entry['state'] != 'complete' and entry['outcome'] is not None)):
                    raise ValueError
                if entry['state'] == 'complete':
                    valid_outcome(entry['outcome'], entry['epoch'])
                seen.add(entry['intent'])
            return value
        except (OSError, ValueError, TypeError, Refused, RecursionError):
            raise Unavailable('mutation journal unavailable') from None

    @contextmanager
    def claim(self, request, now, budget):
        if type(request) is not VerifiedRequest or type(budget) is not OperationBudget or not uint(now):
            raise Unavailable('mutation ownership unavailable')
        account = request.action.account
        lock, path = self._paths(account)
        descriptor = None
        try:
            descriptor = self._private(lock, os.O_RDWR | os.O_CREAT)
            deadline = time.monotonic() + budget.cap_seconds(self.LOCK_WAIT_SECONDS)
            while True:
                budget.remaining()
                try:
                    fcntl.flock(descriptor, fcntl.LOCK_EX | fcntl.LOCK_NB)
                    break
                except BlockingIOError:
                    remaining = min(deadline - time.monotonic(), budget.remaining())
                    if remaining <= 0:
                        raise Unavailable('mutation ownership unavailable')
                    time.sleep(min(remaining, 0.01))
            budget.remaining()
            value = self._record(path)
            if now < value['high_water']:
                raise Unavailable('mutation ownership unavailable')
            # Never retire unresolved state because the original action expired.
            if any(e['state'] != 'complete' for e in value['entries']):
                raise Unavailable('mutation reconciliation required')
            entries = [e for e in value['entries'] if e['expires'] > now]
            if (any(e['intent'] == request.action.intent_reference for e in entries) or
                    len(entries) >= self.MAX_ENTRIES):
                raise Unavailable('mutation ownership unavailable')
            a = request.action
            entry = {'intent': a.intent_reference, 'mac': request.signature, 'issued': a.issued,
                     'expires': a.expires, 'epoch': a.epoch, 'state': 'pending', 'outcome': None}
            value = {'version': 1, 'high_water': now, 'entries': entries + [entry]}
            # Publication must be confirmed before the coordinator is constructed
            # or called. Failed publication supplies no no-write response claim.
            self._publish(path, value)
            budget.remaining()
            yield Lease(self, path, value, entry)
        except (OSError, Refused):
            raise Unavailable('mutation ownership unavailable') from None
        finally:
            if descriptor is not None:
                fcntl.flock(descriptor, fcntl.LOCK_UN)
                os.close(descriptor)


class Lease:
    def __init__(self, store, path, value, entry):
        self._store = store
        self._path = path
        self._value = value
        self._entry = entry
        self._used = False

    def complete(self, outcome, now):
        if self._used or not uint(now) or now < self._value['high_water']:
            raise Unavailable('mutation outcome unavailable')
        self._used = True
        self._entry.update(state='complete', outcome=valid_outcome(outcome, self._entry['epoch']))
        self._value['high_water'] = now
        try:
            self._store._publish(self._path, self._value)
        except Exception:
            raise Unavailable('mutation outcome publication unavailable') from None


class _BudgetedAdapter:
    """Phase-boundary checks do not replace a finite native executor/watchdog."""
    def __init__(self, adapter, budget):
        self._adapter = adapter
        self._budget = budget
        self._account = adapter._account
        self.validate_new = adapter.validate_new

    def read(self, account):
        self._budget.remaining()
        result = self._adapter.read(account)
        self._budget.remaining()
        return result

    def replace(self, *args):
        self._budget.remaining()
        result = self._adapter.replace(*args)
        try:
            self._budget.remaining()
        except Exception:
            # A returned receipt can already follow a committed SQL write.
            raise Unconfirmed('mutation writer deadline unconfirmed') from None
        return result


def _budgeted(callback, budget):
    def call(*args):
        budget.remaining()
        result = callback(*args)
        budget.remaining()
        return result
    return call


class MutationWorker:
    """Coordinator execution after authenticated bytes, under durable ownership.

    The builder is a fixed helper dependency, never decoded from a request. It
    must return the real PreparedPasswordCoordinator using this exact epoch
    store, clock and authorizer. Actual native current-session authority remains
    a qualified dependency; HMAC alone is not a live session proof.
    """
    def __init__(self, key, accounts, journal, epoch_store, builder, session_authority,
                 clock=lambda: int(time.time()), monotonic=time.monotonic, *, session_key=None):
        key_valid(key)
        if (type(accounts) is not frozenset or not 1 <= len(accounts) <= 128 or
                type(journal) is not IntentStore or type(epoch_store) is not EpochStore or
                not callable(builder) or not callable(session_authority)):
            raise Unavailable('mutation dependency unavailable')
        for account in accounts:
            AuthoritativePasswordAdapter._account(account)
        self._key = key
        self._accounts = accounts
        self._journal = journal
        self._epoch_store = epoch_store
        self._builder = builder
        self._session_authority = session_authority
        self._clock = clock
        self._monotonic = monotonic
        # Native bootstrap owns a separate session-proof key. It is never a
        # decoded field, ordinary request HMAC, callback Boolean or optional
        # fallback to the legacy session authority dependency.
        if session_key is not None:
            key_valid(session_key)
            if session_key == key:
                raise Unavailable('guarded mutation dependency unavailable')
        self._session_key = session_key

    def execute(self, raw, *, maximum_seconds=60):
        """Source component only; native dispatch enters through a qualified peer."""
        try:
            began = self._clock()
            request = verify_request(raw, self._key, began)
            if request.action.account not in self._accounts:
                raise Invalid('mutation account unavailable')
            budget = OperationBudget(request.action.expires, maximum_seconds=maximum_seconds,
                                     monotonic=self._monotonic, wall=self._clock)
        except Exception:
            raise Unavailable('mutation request unavailable') from None

        return self._execute_verified(request, began, budget)

    def execute_budget(self, raw, *, clock_millis=None):
        """Private additive supervised entry; no production startup/activation."""
        from account_mutation_budget import wall_millis, verify_envelope, operation_budget
        sample = clock_millis or wall_millis
        received_mono = self._monotonic()
        received_millis = sample()
        try:
            proof = verify_envelope(raw, self._key, received_millis)
            if proof.request.action.account not in self._accounts:
                raise Invalid('mutation account unavailable')
            budget = operation_budget(proof, received_mono=received_mono,
                                      received_millis=received_millis,
                                      monotonic=self._monotonic, clock_millis=sample)
            # The enclosing fixed supervisor must be this process-group leader.
            # Nested SQL/hash/containment executors retain this same owned group.
            budget.attach_owned_process_group()
            began = self._clock()
            proof.request.verify(self._key, began)
            budget.remaining()
        except Exception:
            raise Unavailable('mutation budget unavailable') from None
        return self._execute_verified(proof.request, began, budget)

    def execute_guarded(self, raw, *, clock_millis=None, _continuity_stream=None, _reply_budget=False):
        """Disabled fixed-dependency guarded proof entry, not a live lease claim.

        The exact independently authenticated session assertion is consumed
        under the same budget as the durable intent and real coordinator. The
        native issuer-continuity handshake remains a separate prerequisite.
        """
        from account_guarded_mutation import verify_guarded
        from account_mutation_budget import wall_millis, operation_budget
        if self._session_key is None:
            raise Unavailable('guarded mutation dependency unavailable')
        sample = clock_millis or wall_millis
        received_mono = self._monotonic()
        received_millis = sample()
        try:
            guarded = verify_guarded(raw, self._key, self._session_key, received_millis)
            if guarded.budget.request.action.account not in self._accounts:
                raise Invalid('guarded mutation account unavailable')
            budget = operation_budget(guarded.budget, received_mono=received_mono,
                                      received_millis=received_millis,
                                      monotonic=self._monotonic, clock_millis=sample)
            budget.attach_owned_process_group()
            began = self._clock()
            guarded.budget.request.verify(self._key, began)
            budget.remaining()
        except Exception:
            raise Unavailable('guarded mutation authority unavailable') from None
        confirmation = None
        if _continuity_stream is not None:
            from account_mutation_continuity import PendingIssuerConfirmation
            confirmation = PendingIssuerConfirmation(_continuity_stream, guarded, raw,
                                                     self._key, budget, sample)
        reply=self._execute_verified(guarded.budget.request, began, budget,
                                      session_authority=guarded.authorize,
                                      pending_confirmation=confirmation)
        # Internal continuous listener carries this SAME budget through reply
        # send and final return; no fresh connection-level timeout renews it.
        return (reply,budget) if _reply_budget else reply

    def _execute_verified(self, request, began, budget, *, session_authority=None,
                          pending_confirmation=None):
        def authorize(action, at):
            budget.remaining()
            request.verify(self._key, at)
            accepted = (action is request.action and
                        (session_authority or self._session_authority)(action, at) is True)
            budget.remaining()
            return accepted

        with self._journal.claim(request, began, budget) as lease:
            try:
                coordinator = self._builder(request.action, budget, authorize)
                if (type(coordinator) is not PreparedPasswordCoordinator or
                        coordinator.store is not self._epoch_store or
                        coordinator.authorize_action is not authorize or
                        coordinator.clock is not self._clock):
                    raise Unavailable('mutation coordinator unavailable')
                budget.remaining()
                if pending_confirmation is not None:
                    coordinator.pending_confirmation = _budgeted(pending_confirmation,budget)
                coordinator.adapter = _BudgetedAdapter(coordinator.adapter, budget)
                for attribute in ('verify_current', 'verify_changed', 'containment_ready',
                                  'invalidate_changed_auth', 'finish_containment'):
                    callback = getattr(coordinator, attribute)
                    if not callable(callback):
                        raise Unavailable('mutation coordinator unavailable')
                    setattr(coordinator, attribute, _budgeted(callback, budget))
            except Exception:
                # Construction/foreign dependencies cannot manufacture a trusted
                # KnownRefused result. Leave the exact intent pending for review.
                raise Unavailable('mutation coordinator unavailable') from None
            try:
                epoch, stamp = coordinator.change(request.action)
            except Unconfirmed:
                outcome = {'status': 'contained'}
            except Refused:
                # The reviewed coordinator defines Refused only before write or
                # confirmed zero-row conditional update; other exceptions below
                # remain unresolved and can never be converted to KnownRefused.
                outcome = {'status': 'known_refused'}
            except BaseException:
                raise Unavailable('mutation dispatch unconfirmed') from None
            else:
                # Post-success shape/receipt errors can follow a real write.
                # They must never enter the coordinator's no-write exception
                # classification or publish KnownRefused.
                try:
                    outcome = valid_outcome({'status': 'changed', 'epoch': epoch,
                                             'changed_at': stamp}, request.action.epoch)
                except Exception:
                    raise Unavailable('mutation outcome unconfirmed') from None
            now = self._clock()
            lease.complete(outcome, now)
            try:
                budget.remaining()
                return response(request, outcome, self._key, now)
            except Exception:
                # A verified outcome can be retained while its reply is lost;
                # subsequent requests still cannot execute this intent again.
                raise Unavailable('mutation reply unavailable') from None

    def connection(self, stream, trusted_web_uid):
        if not NATIVE_CONFINEMENT_QUALIFIED:
            raise Unavailable('native mutation worker unavailable')
        return self._connection(stream, trusted_web_uid)

    def budget_connection(self, stream, trusted_web_uid):
        if not NATIVE_CONFINEMENT_QUALIFIED:
            raise Unavailable('native mutation worker unavailable')
        return self._connection(stream, trusted_web_uid, original_budget=True)

    def guarded_connection(self, stream, trusted_web_uid):
        if not NATIVE_CONFINEMENT_QUALIFIED:
            raise Unavailable('native guarded mutation worker unavailable')
        return self._connection(stream, trusted_web_uid, guarded_session=True)

    def continuous_guarded_connection(self, stream, trusted_web_uid):
        if not NATIVE_CONFINEMENT_QUALIFIED:
            raise Unavailable('native continuous guarded worker unavailable')
        return self._connection(stream,trusted_web_uid,guarded_session=True,continuous_issuer=True)

    def _connection(self, stream, trusted_web_uid, original_budget=False, *, guarded_session=False,
                    continuous_issuer=False):
        """Private finite reviewed transport seam; tests use actual local peers."""
        if type(trusted_web_uid) is not int or trusted_web_uid <= 0:
            raise Unavailable('mutation peer unavailable')
        try:
            if hasattr(stream, 'getpeereid'):
                uid, _ = stream.getpeereid()
            elif sys.platform.startswith('linux'):
                _, uid, _ = struct.unpack('3i', stream.getsockopt(socket.SOL_SOCKET, socket.SO_PEERCRED, 12))
            else:
                raise Unavailable('mutation peer unavailable')
            if uid != trusted_web_uid:
                raise Unavailable('mutation peer unavailable')
            deadline = self._monotonic() + 60
            def read_exact(size):
                data = bytearray()
                while len(data) < size:
                    remaining = deadline - self._monotonic()
                    if remaining <= 0:
                        raise Unavailable('mutation transport unavailable')
                    stream.settimeout(remaining)
                    part = stream.recv(size - len(data))
                    if not part:
                        raise Unavailable('mutation transport unavailable')
                    data.extend(part)
                return bytes(data)
            size = int.from_bytes(read_exact(4), 'big')
            from account_mutation_budget import LIMIT as BUDGET_LIMIT
            if not 1 <= size <= (BUDGET_LIMIT if original_budget or guarded_session else LIMIT):
                raise Unavailable('mutation frame unavailable')
            raw = read_exact(size)
            remaining = deadline - self._monotonic()
            reply_budget=None
            if guarded_session:
                # Current guarded client submits exactly one frame and a write
                # half-close. EOF establishes framing only, NOT issuer liveness.
                if self._session_key is None or remaining <= 0:
                    raise Unavailable('guarded mutation transport unavailable')
                stream.settimeout(remaining)
                if continuous_issuer:
                    # Bidirectional peer remains open for the authenticated ACK
                    # only after the shared coordinator publishes epoch pending.
                    reply,reply_budget = self.execute_guarded(raw,_continuity_stream=stream,_reply_budget=True)
                else:
                    if stream.recv(1) != b'':
                        raise Unavailable('guarded mutation frame unavailable')
                    reply = self.execute_guarded(raw)
            else:
                reply = (self.execute_budget(raw) if original_budget else
                         self.execute(raw, maximum_seconds=min(60, remaining)))
            remaining = deadline - self._monotonic()
            if remaining <= 0:
                raise Unavailable('mutation reply unavailable')
            if reply_budget is not None:
                remaining=min(remaining,reply_budget.remaining())
            stream.settimeout(remaining)
            stream.sendall(len(reply).to_bytes(4, 'big') + reply)
            if reply_budget is not None:reply_budget.remaining()
        except Exception:
            raise Unavailable('mutation connection unavailable') from None
