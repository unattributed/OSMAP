"""Public disposable codec fixture; no native adapter, auth, SQL or helper startup.

Only the fixed reserved account/key and synthetic in-memory callbacks are used.
Rust tests pass public sealed-dispatch bytes on stdin. No persistent evidence or
credential file is created; temporary owner-private epoch/intent fixtures clean up
on every outcome. This executable test adapter is not a production constructor.
"""
import json
import os
import pathlib
import sys
import tempfile

from account_epoch import EpochStore
from account_mutation_codec import verify_request, response
from account_mutation_worker import IntentStore, MutationWorker
from authoritative_password import AuthoritativePasswordAdapter as Adapter, Receipt, Unconfirmed
from prepared_password import PreparedPasswordCoordinator

KEY = bytes([17]) * 32
ACCOUNT = 'alice@example.test'
STAMP = '19700101000140'


def run(command):
    raw = bytes.fromhex(command['raw_hex'])
    now = command['now']
    mode = command['mode']
    try:
        request = verify_request(raw, KEY, now)
        if request.action.account != ACCOUNT:
            raise ValueError('public fixture account only')
        if mode == 'decode':
            return dict(accepted=True, issued=request.action.issued,
                        expires=request.action.expires, epoch=request.action.epoch,
                        payload_hex=request.payload().hex())
        outcome = command['outcome']
        if mode == 'response':
            reply = response(request, outcome, KEY, now)
            return dict(accepted=True, response_hex=reply.hex())
        if mode != 'worker' or outcome['status'] not in ('changed', 'contained', 'known_refused'):
            raise ValueError('public fixture mode only')
        status = outcome['status']
        with tempfile.TemporaryDirectory(prefix='osmap-public-wire-') as temp:
            root = pathlib.Path(temp)
            for name in ['epoch', 'intent']:
                (root / name).mkdir(mode=0o700)
            store = EpochStore(root / 'epoch', os.getuid())
            store.provision(ACCOUNT)
            with store.locked(ACCOUNT) as path:
                value = store._read(path)
                store._write(path, dict(value, epoch=request.action.epoch))
            journal = IntentStore(root / 'intent', os.getuid())
            journal.provision(ACCOUNT)
            calls = dict(read=0, replace=0, primary=0, second_factor=0)

            class Backend:
                _account = staticmethod(Adapter._account)
                validate_new = staticmethod(Adapter.validate_new)
                def read(self, account):
                    calls['read'] += 1
                    return object()
                def replace(self, *args):
                    calls['replace'] += 1
                    if status == 'contained':
                        raise Unconfirmed('public ambiguous disposable writer')
                    return Receipt(STAMP)

            clock = lambda: now
            def primary(*args):
                calls['primary'] += 1
                return status != 'known_refused'
            def builder(action, budget, authorize):
                return PreparedPasswordCoordinator(
                    store, Backend(), authorize, primary,
                    lambda *args: True, lambda *args: True, lambda *args: True,
                    clock, invalidate_changed_auth=lambda *args: True)
            worker = MutationWorker(KEY, frozenset([ACCOUNT]), journal, store, builder,
                                    lambda *args: True, clock)
            reply = worker.execute(raw)
            replay_refused = False
            try:
                worker.execute(raw)
            except Exception:
                replay_refused = True
            entries = journal._record(journal._paths(ACCOUNT)[1])['entries']
            return dict(accepted=True, response_hex=reply.hex(), calls=calls,
                        replay_refused=replay_refused, journal_entries=len(entries))
    except Exception:
        return dict(accepted=False)


if __name__ == '__main__':
    data = sys.stdin.buffer.read(16385)
    if len(data) > 16384:
        raise SystemExit(2)
    command = json.loads(data.decode('utf-8'))
    print(json.dumps(run(command), separators=(',', ':')))
