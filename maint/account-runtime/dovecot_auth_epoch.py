"""Disabled Dovecot 2.3 before/after authentication epoch policy primitive.

This is not a listener, credential verifier, or session-establishment authority.
A future trusted policy endpoint must use both Dovecot checks, reject-on-failure,
log-only off, and the fixed passdb phase extra field. No report authorizes.
Connection-key retries/replays, cache/master paths and the interval after the
final policy callback remain native qualification dependencies. Missing after
captures (including restart) refuse; no durable account state is written.
"""
from contextlib import contextmanager
from dataclasses import dataclass
import fcntl
import json
import math
import os
import re
import stat
import threading
import time

from account_epoch import EpochStore
from authoritative_password import AuthoritativePasswordAdapter, Refused

NATIVE_POLICY_ENDPOINT_QUALIFIED = False


@dataclass(frozen=True, repr=False)
class _Capture:
    epoch: int
    expires: float
    used: bool = False


class EpochPolicyFence:
    MAX_BODY = 4096
    MAX_ENTRIES = 256
    CAPTURE_SECONDS = 30.0
    CALLBACK_SECONDS = 0.5
    # Below 2**52, binary64 retains the half-second callback increment.
    # Compare this bound before isfinite converts an arbitrary-sized integer.
    MAX_CLOCK_SECONDS = 2 ** 52 - 1
    PROTOCOLS = frozenset(('imap', 'pop3', 'smtp', 'submission'))
    ALLOW = b'{"status":0}'
    DENY = b'{"status":-1}'

    def __init__(self, store, accounts, *, clock=time.monotonic):
        # Caller configuration is server authority, never request JSON. There
        # is deliberately no native factory or default account provisioning.
        if (not isinstance(store, EpochStore) or type(accounts) is not frozenset
                or not 1 <= len(accounts) <= 64 or not callable(clock)):
            raise Refused('authentication epoch policy unavailable')
        for account in accounts:
            AuthoritativePasswordAdapter._account(account)
        self._store = store
        self._accounts = accounts
        self._clock = clock
        self._lock = threading.Lock()
        self._captures = {}
        self._last_time = None
        self._clock_failed = False
        self._root = self._root_identity()

    def _root_identity(self):
        info = self._store.root.lstat()
        if (not stat.S_ISDIR(info.st_mode) or info.st_uid != self._store.uid
                or info.st_mode & 0o077
                or self._store.root.resolve() != self._store.root):
            raise Refused('authentication epoch policy unavailable')
        return info.st_dev, info.st_ino

    def _now(self):
        try:
            value = self._clock()
            if (type(value) not in (int, float)
                    or not 0 <= value <= self.MAX_CLOCK_SECONDS
                    or not math.isfinite(value) or self._clock_failed
                    or (self._last_time is not None and value < self._last_time)):
                raise ValueError
        except Exception:
            self._clock_failed = True
            raise Refused('authentication epoch policy clock unavailable') from None
        self._last_time = value
        return value

    def _request(self, body):
        if type(body) is not bytes or not 1 <= len(body) <= self.MAX_BODY:
            raise ValueError
        value = json.loads(body.decode('utf-8'), object_pairs_hook=EpochStore._unique)
        if (type(value) is not dict
                or set(value) != {'login', 'protocol', 'session_id', 'phase', 'tls'}):
            raise ValueError
        if (type(value['login']) is not str or value['login'] not in self._accounts
                or type(value['protocol']) is not str or value['protocol'] not in self.PROTOCOLS
                or type(value['session_id']) is not str
                or not re.fullmatch(r'[A-Za-z0-9/+_=.-]{1,128}', value['session_id'])
                or type(value['phase']) is not str or value['phase'] not in ('before', 'after')
                or type(value['tls']) is not bool):
            raise ValueError
        # TLS is also bound across the pair. It is not a substitute for trusted
        # origin authentication; listener/transport qualification is deferred.
        key = (value['login'], value['protocol'], value['session_id'], value['tls'])
        return key, value['phase']

    @contextmanager
    def _account_lock(self, account):
        # A policy callback never waits two seconds on the mutation lock: busy
        # means reject. The actual durable store inode/private-file parser is
        # reused, under exactly the same account lock as password mutation.
        if self._root_identity() != self._root:
            raise Refused('authentication epoch policy root changed')
        lock, path = self._store._paths(account)
        descriptor = self._store._private(lock, os.O_RDWR | os.O_CREAT)
        try:
            try:
                fcntl.flock(descriptor, fcntl.LOCK_EX | fcntl.LOCK_NB)
            except BlockingIOError:
                raise Refused('authentication epoch policy busy') from None
            if self._root_identity() != self._root:
                raise Refused('authentication epoch policy root changed')
            yield path
        finally:
            fcntl.flock(descriptor, fcntl.LOCK_UN)
            os.close(descriptor)

    def allow(self, body):
        """Return only Dovecot status JSON. Any refusal/unavailability rejects.

        No request value can create or reset an epoch record, set account
        authority, obtain a credential, or turn a report into an allow request.
        A used capture remains a tombstone until its original expiry; another
        before cannot overwrite it. After expiry the same connection key can
        start a new pair: endpoint/request-replay qualification remains open.
        """
        if not self._lock.acquire(blocking=False):
            return self.DENY
        try:
            began = self._now()
            key, phase = self._request(body)
            # Bound all outstanding and used records; remove only expired
            # entries, never evict a live capture to admit another account.
            self._captures = {k: v for k, v in self._captures.items() if v.expires > began}
            if phase == 'before':
                if key in self._captures or len(self._captures) >= self.MAX_ENTRIES:
                    return self.DENY
                # Reserve before I/O so an unavailable/late lookup cannot be
                # retried against a newer epoch under the same connection key.
                capture = _Capture(-1, began + self.CAPTURE_SECONDS, True)
                self._captures[key] = capture
            else:
                capture = self._captures.get(key)
                if capture is None or capture.used:
                    return self.DENY
                # Consume before durable I/O, even when that lookup refuses.
                self._captures[key] = _Capture(capture.epoch, capture.expires, True)
            deadline = min(began + self.CALLBACK_SECONDS, capture.expires)
            with self._account_lock(key[0]) as path:
                value = self._store._read(path)
                if (value['state'] != 'active'
                        or (phase == 'after' and value['epoch'] != capture.epoch)):
                    return self.DENY
                now = self._now()
                if now >= deadline or self._root_identity() != self._root:
                    return self.DENY
            # The final root validation and lock cleanup may themselves cross
            # the callback's original deadline. Sample after both; never issue
            # a live before capture or an allow response on that late path.
            if self._now() >= deadline:
                return self.DENY
            if phase == 'before':
                self._captures[key] = _Capture(value['epoch'], capture.expires)
            return self.ALLOW
        except Exception:
            # Never return status=0 on schema, permission, clock or store error.
            # No body, exception text, account, session or credential is logged.
            return self.DENY
        finally:
            self._lock.release()
