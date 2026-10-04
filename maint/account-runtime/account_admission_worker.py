"""Own-account auth/epoch admission under the password coordinator's durable lock.

This worker cannot change/provision passwords or epochs. Only the authenticated
Rust helper sends frames; no socket, process, database or account path comes
from a request. Production activation remains separately unqualified.
"""
import json
import os
import selectors
import subprocess
import sys
import time

if __name__ == '__main__':
    sys.path.insert(0, '/usr/local/libexec/osmap/account-runtime')

from account_epoch import EpochStore, valid_epoch
from authoritative_password import AuthoritativePasswordAdapter, Refused

SCHEMA = 'osmap-account-admission-worker-v1'
ROOT = '/var/db/osmap-account/epoch'
LIMIT = 4096


class CleanupUnconfirmed(Refused):
    """No later worker admission until the helper's cleanup is reconciled."""


def fixed_authenticate(account, password):
    """Fixed native invocation, password stdin only; never return backend text."""
    process = subprocess.Popen(
        ['/usr/local/bin/doveadm', '-o', 'stats_writer_socket_path=',
         'auth', 'test', '-x', 'service=imap', account],
        stdin=subprocess.PIPE, stdout=subprocess.PIPE, stderr=subprocess.PIPE,
        env={'PATH': '/usr/local/bin:/usr/bin:/bin', 'LC_ALL': 'C'},
        # Stay in the private Rust supervisor's process group so expiry kills
        # the worker and every descendant; never create an escaping auth group.
        start_new_session=False)
    selector = selectors.DefaultSelector()
    output = bytearray()
    pending = memoryview((password + '\n').encode('utf-8'))
    deadline = time.monotonic() + 25
    try:
        for pipe in (process.stdin, process.stdout, process.stderr):
            os.set_blocking(pipe.fileno(), False)
        selector.register(process.stdin, selectors.EVENT_WRITE, 'input')
        selector.register(process.stdout, selectors.EVENT_READ, 'output')
        selector.register(process.stderr, selectors.EVENT_READ, 'error')
        total = 0
        while selector.get_map():
            remaining = deadline - time.monotonic()
            if remaining <= 0:
                raise Refused('authentication unavailable')
            for key, _ in selector.select(min(remaining, .1)):
                pipe = key.fileobj
                if key.data == 'input':
                    try:
                        pending = pending[os.write(pipe.fileno(), pending):]
                    except BlockingIOError:
                        continue
                    if not pending:
                        selector.unregister(pipe)
                        pipe.close()
                else:
                    try:
                        data = os.read(pipe.fileno(), 4096)
                    except BlockingIOError:
                        continue
                    if not data:
                        selector.unregister(pipe)
                        pipe.close()
                    total += len(data)
                    if total > LIMIT:
                        raise Refused('authentication unavailable')
                    # stderr is discarded; secret diagnostics never reach RPC.
                    if key.data == 'output':
                        output.extend(data)
        code = process.wait(timeout=max(.01, deadline-time.monotonic()))
        text = output.decode('utf-8', errors='strict')
        users = [line.strip()[5:].strip() for line in text.splitlines()
                 if line.strip().startswith('user=')]
        if code == 77 or 'auth failed' in text:
            return False
        if code != 0 or 'auth succeeded' not in text or users != [account]:
            raise Refused('authentication unavailable')
        return True
    except (OSError, ValueError, subprocess.SubprocessError):
        raise Refused('authentication unavailable') from None
    finally:
        selector.close()
        if process.poll() is None:
            process.kill()
            try:
                process.wait(timeout=1)
            except subprocess.TimeoutExpired:
                # Worker exits; parent process transport quarantines unconfirmed
                # descendants instead of admitting another operation.
                raise CleanupUnconfirmed('authentication cleanup unconfirmed') from None
        for pipe in (process.stdin, process.stdout, process.stderr):
            if not pipe.closed:
                pipe.close()


def execute(frame, store, authenticate=fixed_authenticate):
    """Tests supply dependencies; RPC can never supply a callback or root."""
    if not isinstance(frame, dict) or frame.get('schema') != SCHEMA:
        raise Refused('account request refused')
    operation = frame.get('operation')
    fields = {'schema', 'operation', 'account'}
    if operation == 'authenticate':
        fields.add('password')
    elif operation == 'admit':
        fields.add('epoch')
    else:
        raise Refused('account request refused')
    if set(frame) != fields:
        raise Refused('account request refused')
    account = AuthoritativePasswordAdapter._account(frame['account'])
    if operation == 'authenticate':
        password = frame['password']
        if not isinstance(password, str):
            raise Refused('account request refused')
        try:
            length = len(password.encode('utf-8'))
        except UnicodeError:
            raise Refused('account request refused') from None
        if not 1 <= length <= 1024 or any(ord(c) < 32 or 127 <= ord(c) <= 159 for c in password):
            raise Refused('account request refused')
    else:
        epoch = frame['epoch']
        if not valid_epoch(epoch):
            raise Refused('account request refused')
    # Exact shared durable account lock also used by PasswordCoordinator.change.
    # Authentication and captured epoch are indivisible relative to mutation.
    with store.locked(account) as path:
        value = store._read(path)
        if value['state'] != 'active':
            raise Refused('account admission refused')
        if operation == 'admit' and value['epoch'] != epoch:
            raise Refused('account admission refused')
        if operation == 'authenticate' and not authenticate(account, password):
            return {'schema': SCHEMA, 'account': account, 'status': 'rejected', 'epoch': None}
        return {'schema': SCHEMA, 'account': account, 'status': 'active', 'epoch': value['epoch']}


def main():
    # Duplicate fields and oversized requests are refused before any callback.
    try:
        raw = sys.stdin.buffer.read(LIMIT + 1)
        if len(raw) > LIMIT:
            raise Refused('account request refused')
        frame = json.loads(raw, object_pairs_hook=EpochStore._unique)
        result = execute(frame, EpochStore(ROOT))
    except CleanupUnconfirmed:
        result = {'schema': SCHEMA, 'status': 'cleanup_unconfirmed', 'account': None, 'epoch': None}
    except Exception:
        result = {'schema': SCHEMA, 'status': 'unavailable', 'account': None, 'epoch': None}
    sys.stdout.write(json.dumps(result, separators=(',', ':')))


if __name__ == '__main__':
    main()
