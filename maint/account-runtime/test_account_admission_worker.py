import pathlib
import tempfile
import threading
import unittest

from account_epoch import EpochStore
from account_admission_worker import execute, fixed_authenticate, main, CleanupUnconfirmed, SCHEMA
from authoritative_password import Refused
import os
import time
from operation_budget import OperationBudget
import account_admission_worker as worker
from unittest.mock import patch
import io
import json
from types import SimpleNamespace

ACCOUNT = 'alice@example.test'


class AdmissionTests(unittest.TestCase):
    def setUp(self):
        self.directory = tempfile.TemporaryDirectory()
        self.root = pathlib.Path(self.directory.name)
        self.root.chmod(0o700)
        self.store = EpochStore(self.root, os.geteuid())
        self.store.provision(ACCOUNT)
        self.calls = 0

    def tearDown(self):
        self.directory.cleanup()

    def auth(self, account, password):
        self.calls += 1
        return account == ACCOUNT and password == 'synthetic credential'

    def frame(self, operation='authenticate', **fields):
        return dict(schema=SCHEMA, operation=operation, account=ACCOUNT, **fields)

    def test_primary_acceptance_captures_epoch_rejection_has_none(self):
        result = execute(self.frame(password='synthetic credential'), self.store, self.auth)
        self.assertEqual(result['epoch'], 0)
        self.assertNotIn('synthetic credential', str(result))
        rejected = execute(self.frame(password='incorrect synthetic'), self.store, self.auth)
        self.assertEqual(rejected['status'], 'rejected')
        self.assertIsNone(rejected['epoch'])

    def test_pending_contained_or_stale_refuse_before_auth(self):
        for state in ['pending', 'contained']:
            with self.store.locked(ACCOUNT) as path:
                value = self.store._read(path)
                self.store._write(path, dict(value, state=state, intent='a'*64))
            with self.assertRaises(Refused):
                execute(self.frame(password='synthetic credential'), self.store, self.auth)
        self.assertEqual(self.calls, 0)
        with self.store.locked(ACCOUNT) as path:
            self.store._write(path, dict(value, state='active', epoch=3, intent=None))
        with self.assertRaises(Refused):
            execute(self.frame('admit', epoch=2), self.store, self.auth)
        self.assertEqual(execute(self.frame('admit', epoch=3), self.store, self.auth)['epoch'], 3)

    def test_unprovisioned_foreign_does_not_create_record(self):
        before = sorted(self.root.glob('*.json'))
        frame = self.frame(password='synthetic credential')
        frame['account'] = 'bob@example.test'
        with self.assertRaises(Refused):
            execute(frame, self.store, self.auth)
        self.assertEqual(sorted(self.root.glob('*.json')), before)
        self.assertEqual(self.calls, 0)

    def test_request_program_fields_controls_and_epoch_boolean_refused(self):
        for f in [self.frame(password='synthetic', program='/tmp/evil'),
                  self.frame('change', password='synthetic'),
                  self.frame(password='line\ninjection'),
                  self.frame(password='\ud800'),
                  self.frame('admit', epoch=True)]:
            with self.assertRaises(Refused):
                execute(f, self.store, self.auth)
        self.assertEqual(self.calls, 0)

    def test_last_readable_epoch_authentication_and_admission_boundaries(self):
        with self.store.locked(ACCOUNT) as path:
            value = self.store._read(path)
            self.store._write(path, dict(value, epoch=2**64-2))
            before = path.read_bytes()
        self.assertEqual(execute(self.frame(password='synthetic credential'), self.store,
                                 self.auth)['epoch'], 2**64-2)
        self.assertEqual(execute(self.frame('admit', epoch=2**64-2), self.store,
                                 self.auth)['epoch'], 2**64-2)
        self.assertEqual(self.calls, 1)
        for epoch in [-1, True, 2**64-1, 2**64]:
            with self.assertRaises(Refused):
                execute(self.frame('admit', epoch=epoch), self.store, self.auth)
            self.assertEqual(path.read_bytes(), before)
        self.assertEqual(self.calls, 1)

    @staticmethod
    def original_budget():
        mono=time.monotonic();millis=int(time.time()*1000)
        return OperationBudget.from_original_deadline((millis+35000+999)//1000,
            received_mono=mono,received_millis=millis,sent_millis=millis,
            deadline_millis=millis+30000,wall_millis=lambda:int(time.time()*1000))

    def test_private_primary_factory_same_original_budget_and_no_ordinary_fallback(self):
        budget=self.original_budget();material=object();events=[]
        verifier=SimpleNamespace(_uncertain=False,_retained=[])
        def verify(account,password):
            events.append(('verify',account));return True
        class Primary:
            _uncertain=False;_retained=[]
            def __call__(self,account,password):return verify(account,password)
        def build(account,original,owned):
            self.assertIs(original,budget);self.assertIs(owned,material);events.append(('build',account));return Primary()
        with patch.object(budget,'inherited_group',return_value=True),patch.object(worker.NativeMaterial,'native',return_value=material)as load,patch.object(worker,'NativePrimaryVerifier',side_effect=build),patch('subprocess.Popen',side_effect=AssertionError('ordinary broad auth invoked')):
            self.assertTrue(worker.fixed_authenticate(ACCOUNT,'synthetic secret value',budget));load.assert_called_once_with(budget)
            self.assertEqual(events,[('build',ACCOUNT),('verify',ACCOUNT)])
        with patch.object(budget,'inherited_group',return_value=True),patch.object(worker.NativeMaterial,'native',side_effect=Refused('native unavailable')),patch('subprocess.Popen',side_effect=AssertionError('ordinary fallback invoked')):
            with self.assertRaisesRegex(Refused,'^authentication unavailable$'):worker.fixed_authenticate(ACCOUNT,'synthetic',budget)

    def test_private_primary_cleanup_quarantines_and_expired_budget_never_dispatches(self):
        budget=self.original_budget()
        class Unreaped:
            _uncertain=True;_retained=[object()]
            def __call__(self,*args):raise Refused('private child details')
        with patch.object(budget,'inherited_group',return_value=True),patch.object(worker.NativeMaterial,'native',return_value=object()),patch.object(worker,'NativePrimaryVerifier',return_value=Unreaped()):
            with self.assertRaises(CleanupUnconfirmed):worker.fixed_authenticate(ACCOUNT,'synthetic',budget)
        with patch.object(budget,'inherited_group',return_value=True),patch.object(budget,'remaining',side_effect=Refused('expired')),patch.object(worker.NativeMaterial,'native',side_effect=AssertionError('expired material read')):
            with self.assertRaises(Refused):worker.fixed_authenticate(ACCOUNT,'synthetic',budget)
        with patch.object(worker.NativeMaterial,'native',side_effect=AssertionError('generic material read')):
            with self.assertRaises(Refused):worker.fixed_authenticate(ACCOUNT,'synthetic',OperationBudget(int(time.time())+30))

    def test_private_primary_auth_and_epoch_lock_share_exact_budget(self):
        budget=self.original_budget();entered=threading.Event();attempted=threading.Event();obtained=threading.Event()
        class Primary:
            _uncertain=False;_retained=[]
            def __call__(inner,account,password):
                entered.set();self.assertTrue(attempted.wait(1));self.assertFalse(obtained.wait(.05));return True
        def mutate():
            self.assertTrue(entered.wait(1));attempted.set()
            with self.store.locked(ACCOUNT)as path:
                obtained.set();value=self.store._read(path);self.store._write(path,dict(value,epoch=1))
        thread=threading.Thread(target=mutate)
        with patch.object(budget,'inherited_group',return_value=True),patch.object(worker.NativeMaterial,'native',return_value=object())as material,patch.object(worker,'NativePrimaryVerifier',return_value=Primary())as primary:
            thread.start()
            try:result=execute(self.frame(password='synthetic'),self.store,budget=budget)
            finally:thread.join(2)
            self.assertFalse(thread.is_alive());self.assertTrue(obtained.is_set());self.assertEqual(result['epoch'],0)
            material.assert_called_once_with(budget);self.assertIs(primary.call_args.args[1],budget)

    def test_unconfirmed_cleanup_has_distinct_finite_response(self):
        output = io.StringIO()
        millis=int(time.time()*1000)
        request = io.BytesIO(json.dumps(self.frame(password='synthetic credential',sent_millis=millis,deadline_millis=millis+30000,expires_at=(millis+35000+999)//1000)).encode())
        def store_factory(_root):return self.store
        store_factory._unique=EpochStore._unique
        with patch('account_admission_worker.sys.stdin', SimpleNamespace(buffer=request)), \
             patch('account_admission_worker.sys.stdout', output), \
             patch('account_admission_worker.EpochStore', store_factory), \
             patch.object(OperationBudget,'attach_owned_process_group',return_value=None), \
             patch('account_admission_worker.execute', side_effect=CleanupUnconfirmed('private child diagnostics must not escape')):
            main()
        result = json.loads(output.getvalue())
        self.assertEqual(result['status'], 'cleanup_unconfirmed')
        self.assertIsNone(result['account'])
        self.assertIsNone(result['epoch'])
        self.assertNotIn('private child diagnostics', output.getvalue())

    def test_auth_and_credential_mutation_share_durable_lock(self):
        entered = threading.Event()
        attempted = threading.Event()
        obtained = threading.Event()
        results = []
        def verify(account, password):
            entered.set()
            self.assertTrue(attempted.wait(1))
            self.assertFalse(obtained.wait(.05))
            return True
        def mutate():
            self.assertTrue(entered.wait(1))
            attempted.set()
            with self.store.locked(ACCOUNT) as path:
                obtained.set()
                value = self.store._read(path)
                self.store._write(path, dict(value, epoch=1))
        thread = threading.Thread(target=mutate)
        thread.start()
        results.append(execute(self.frame(password='synthetic credential'), self.store, verify))
        thread.join(2)
        self.assertFalse(thread.is_alive())
        self.assertTrue(obtained.is_set())
        self.assertEqual(results[0]['epoch'], 0)
        with self.assertRaises(Refused):
            execute(self.frame('admit', epoch=0), self.store, self.auth)


if __name__ == '__main__':
    unittest.main()
