"""Own-account auth/epoch admission under the password coordinator's durable lock.

This worker cannot change/provision passwords or epochs. Only the authenticated
Rust helper sends frames; no socket, process, database or account path comes
from a request. Production activation remains separately unqualified.
"""
import json
import os
import sys
import time

if __name__ == '__main__':
    sys.path.insert(0, '/usr/local/libexec/osmap/account-runtime')

from account_epoch import EpochStore, valid_epoch
from authoritative_password import AuthoritativePasswordAdapter, Refused
from operation_budget import OperationBudget, _OriginalReceipt
from account_native_material import NativeMaterial
from mutation_primary import NativePrimaryVerifier
from account_command_kernel import AdmissionWorkerStartup

SCHEMA = 'osmap-account-admission-worker-v1'
ROOT = '/var/db/osmap-account/epoch'
LIMIT = 4096


class CleanupUnconfirmed(Refused):
    """No later worker admission until the helper's cleanup is reconciled."""


def _original_budget(budget):
    receipt=getattr(budget,'_original_receipt',None)
    if (type(budget)is not OperationBudget or type(receipt)is not _OriginalReceipt
            or not budget.inherited_group()):
        raise Refused('account original budget unavailable')
    budget.require_original(sent_millis=receipt.sent_millis,
        deadline_millis=receipt.deadline_millis,expires_at=receipt.expires_at)


def fixed_authenticate(account, password, budget, *, startup=None, store=None):
    """Actual fixed material/private-primary factory; no ordinary auth fallback."""
    _original_budget(budget)
    verifier=None
    try:
        if type(startup)is not AdmissionWorkerStartup:
            raise Refused('admission worker startup unavailable')
        material=NativeMaterial.native(budget)
        seal=startup.bind(account,store,budget,material)
        verifier=NativePrimaryVerifier(account,budget,material,admission_seal=seal)
        result=verifier(account,password)
        _original_budget(budget)
        if type(result)is not bool:raise Refused('authentication unavailable')
        return result
    except Exception:
        raise Refused('authentication unavailable')from None
    finally:
        # Existing primary transport retains any unreaped child and refuses.
        # Translate that exact disposition to the helper's existing quarantine.
        if verifier is not None and (verifier._uncertain or verifier._retained):
            raise CleanupUnconfirmed('authentication cleanup unconfirmed')from None


def execute(frame, store, authenticate=None, *, budget=None, startup=None):
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
    if authenticate is None:
        _original_budget(budget)
        if type(startup)is not AdmissionWorkerStartup:
            raise Refused('admission worker startup unavailable')
        if operation=='admit':
            startup.bind(account,store,budget).apply(account,None,budget)
    elif budget is not None:
        _original_budget(budget)
    # Exact shared durable account lock also used by PasswordCoordinator.change.
    # Authentication and captured epoch are indivisible relative to mutation.
    with store.locked(account) as path:
        if budget is not None:_original_budget(budget)
        value = store._read(path)
        if budget is not None:_original_budget(budget)
        if value['state'] != 'active':
            raise Refused('account admission refused')
        if operation == 'admit' and value['epoch'] != epoch:
            raise Refused('account admission refused')
        if operation == 'authenticate':
            accepted=(fixed_authenticate(account,password,budget,startup=startup,store=store)if authenticate is None else authenticate(account,password))
            if budget is not None:_original_budget(budget)
            if not accepted:
                return {'schema': SCHEMA, 'account': account, 'status': 'rejected', 'epoch': None}
        result={'schema': SCHEMA, 'account': account, 'status': 'active', 'epoch': value['epoch']}
        # Same active account/epoch lock as authentication and mutation. Never
        # expose contained/pending records or derive password history from SQL
        # mailbox metadata. Genuinely absent historical data remains absent.
        if value['changed_at'] is not None:
            result['changed_at']=value['changed_at']
        return result


def main():
    # Receipt is captured before stdin read/parse. Only the verified fixed Rust
    # parent supplies these internal fields, bounded by its original Instant.
    received_mono=time.monotonic();received_millis=int(time.time()*1000)
    # Duplicate fields and oversized requests are refused before any callback.
    try:
        startup=AdmissionWorkerStartup.native()
        raw = sys.stdin.buffer.read(LIMIT + 1)
        if len(raw) > LIMIT:
            raise Refused('account request refused')
        frame = json.loads(raw, object_pairs_hook=EpochStore._unique)
        if type(frame)is not dict:raise Refused('account request refused')
        sent=frame.pop('sent_millis');deadline=frame.pop('deadline_millis');expires=frame.pop('expires_at')
        budget=OperationBudget.from_original_deadline(expires,received_mono=received_mono,
            received_millis=received_millis,sent_millis=sent,deadline_millis=deadline,
            wall_millis=lambda:int(time.time()*1000))
        budget.attach_owned_process_group()
        result = execute(frame, EpochStore(ROOT),budget=budget,startup=startup)
    except CleanupUnconfirmed:
        result = {'schema': SCHEMA, 'status': 'cleanup_unconfirmed', 'account': None, 'epoch': None}
    except Exception:
        result = {'schema': SCHEMA, 'status': 'unavailable', 'account': None, 'epoch': None}
    sys.stdout.write(json.dumps(result, separators=(',', ':')))


if __name__ == '__main__':
    main()
