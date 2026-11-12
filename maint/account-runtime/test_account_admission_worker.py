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
from contextlib import contextmanager
import account_command_kernel as kernel
from account_native_material import NativeMaterial
from types import SimpleNamespace

ACCOUNT = 'alice@example.test'


class NativeCall:
    def __init__(self,name,events):self.name=name;self.events=events;self.fail=False
    def __call__(self,*args):
        self.events.append((self.name,args))
        return -1 if self.fail else 0


@contextmanager
def projected_startup(root):
    # Local source construction projection, not a native confinement result.
    events=[];lib=SimpleNamespace(pledge=NativeCall('pledge',events),unveil=NativeCall('unveil',events))
    info=root.lstat();identity=(info.st_dev,info.st_ino,info.st_uid,info.st_gid,info.st_mode)
    with patch.object(kernel,'_ADMISSION_ROOT',str(root)),patch.object(kernel,'_ADMISSION_UID',os.geteuid()), \
         patch.object(kernel.AdmissionWorkerStartup,'_authority'), \
         patch.object(kernel.AdmissionWorkerStartup,'_libc',return_value=lib), \
         patch.object(kernel.AdmissionWorkerSeal,'_observe_directories',return_value=((str(root),identity),)), \
         patch('account_command_kernel.os.getpgrp',side_effect=os.getpid):
        yield kernel.AdmissionWorkerStartup.native(),events,lib



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

    def test_main_signable_stale_denial_preserves_nonactive_unavailability(self):
        cases=[('active',2,'rejected',ACCOUNT,None),
               ('active',3,'active',ACCOUNT,3),
               ('pending',3,'unavailable',None,None),
               ('contained',3,'unavailable',None,None),
               ('active',True,'unavailable',None,None)]
        for state,epoch,status,account,returned_epoch in cases:
            with self.subTest(state=state,epoch=epoch):
                with self.store.locked(ACCOUNT) as path:
                    value=self.store._read(path)
                    self.store._write(path,dict(value,state=state,epoch=3,
                        intent=None if state=='active' else 'a'*64,changed_at='20261016140432'))
                    before=path.read_bytes()
                millis=int(time.time()*1000)
                frame=dict(self.frame('admit',epoch=epoch),sent_millis=millis,
                    deadline_millis=millis+30000,expires_at=(millis+35000+999)//1000)
                output=io.StringIO()
                with projected_startup(self.root) as(startup,_,_), \
                     patch.object(worker.AdmissionWorkerStartup,'native',return_value=startup), \
                     patch.object(worker,'EpochStore',wraps=EpochStore) as constructor, \
                     patch.object(OperationBudget,'inherited_group',return_value=True), \
                     patch.object(worker.sys,'stdin',SimpleNamespace(buffer=io.BytesIO(json.dumps(frame).encode()))), \
                     patch.object(worker.sys,'stdout',output):
                    constructor.side_effect=lambda root:self.store
                    main()
                result=json.loads(output.getvalue())
                expected=dict(schema=SCHEMA,status=status,account=account,epoch=returned_epoch)
                if status=='active':expected['changed_at']='20261016140432'
                self.assertEqual(result,expected)
                self.assertEqual(path.read_bytes(),before)
        self.assertEqual(self.calls,0)

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
        budget=self.original_budget();material=object.__new__(NativeMaterial);events=[]
        verifier=SimpleNamespace(_uncertain=False,_retained=[])
        def verify(account,password):
            events.append(('verify',account));return True
        class Primary:
            _uncertain=False;_retained=[]
            def __call__(self,account,password):return verify(account,password)
        def build(account,original,owned,*,admission_seal):
            self.assertIs(type(admission_seal),kernel.AdmissionWorkerSeal)
            admission_seal.check(account,owned,original)
            self.assertIs(original,budget);self.assertIs(owned,material);events.append(('build',account));return Primary()
        with projected_startup(self.root)as(startup,_,_),patch.object(budget,'inherited_group',return_value=True),patch.object(worker.NativeMaterial,'native',return_value=material)as load,patch.object(worker,'NativePrimaryVerifier',side_effect=build),patch('subprocess.Popen',side_effect=AssertionError('ordinary broad auth invoked')):
            self.assertTrue(worker.fixed_authenticate(ACCOUNT,'synthetic secret value',budget,startup=startup,store=self.store));load.assert_called_once_with(budget)
            self.assertEqual(events,[('build',ACCOUNT),('verify',ACCOUNT)])
        with projected_startup(self.root)as(startup,_,_),patch.object(budget,'inherited_group',return_value=True),patch.object(worker.NativeMaterial,'native',side_effect=Refused('native unavailable')),patch('subprocess.Popen',side_effect=AssertionError('ordinary fallback invoked')):
            with self.assertRaisesRegex(Refused,'^authentication unavailable$'):worker.fixed_authenticate(ACCOUNT,'synthetic',budget,startup=startup,store=self.store)

    def test_private_primary_cleanup_quarantines_and_expired_budget_never_dispatches(self):
        budget=self.original_budget()
        class Unreaped:
            _uncertain=True;_retained=[object()]
            def __call__(self,*args):raise Refused('private child details')
        with projected_startup(self.root)as(startup,_,_),patch.object(budget,'inherited_group',return_value=True),patch.object(worker.NativeMaterial,'native',return_value=object.__new__(NativeMaterial)),patch.object(worker,'NativePrimaryVerifier',return_value=Unreaped()):
            with self.assertRaises(CleanupUnconfirmed):worker.fixed_authenticate(ACCOUNT,'synthetic',budget,startup=startup,store=self.store)
        with patch.object(budget,'inherited_group',return_value=True),patch.object(budget,'remaining',side_effect=Refused('expired')),patch.object(worker.NativeMaterial,'native',side_effect=AssertionError('expired material read')):
            with self.assertRaises(Refused):worker.fixed_authenticate(ACCOUNT,'synthetic',budget,startup=startup,store=self.store)
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
        with projected_startup(self.root)as(startup,_,_),patch.object(budget,'inherited_group',return_value=True),patch.object(worker.NativeMaterial,'native',return_value=object.__new__(NativeMaterial))as material,patch.object(worker,'NativePrimaryVerifier',return_value=Primary())as primary:
            thread.start()
            try:result=execute(self.frame(password='synthetic'),self.store,budget=budget,startup=startup)
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
             patch.object(worker.AdmissionWorkerStartup,'native',return_value=object()), \
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

    def test_native_startup_precedes_input_and_missing_startup_refuses_before_store(self):
        events=[];millis=int(time.time()*1000)
        class Input:
            def read(inner,size):events.append('read');raise ValueError
        output=io.StringIO()
        with patch.object(worker.AdmissionWorkerStartup,'native',side_effect=lambda:events.append('early')or object()), \
             patch.object(worker.sys,'stdin',SimpleNamespace(buffer=Input())),patch.object(worker.sys,'stdout',output):
            main()
        self.assertEqual(events,['early','read'])
        self.assertEqual(json.loads(output.getvalue())['status'],'unavailable')
        lib=SimpleNamespace(pledge=NativeCall('pledge',events),unveil=NativeCall('unveil',events))
        lib.pledge.fail=True;output=io.StringIO()
        with patch.object(worker.AdmissionWorkerStartup,'_authority'), \
             patch.object(worker.AdmissionWorkerStartup,'_libc',return_value=lib), \
             patch.object(worker.sys,'stdin',SimpleNamespace(buffer=SimpleNamespace(read=lambda size:self.fail('input before early pledge')))), \
             patch.object(worker.sys,'stdout',output):
            main()
        self.assertEqual(json.loads(output.getvalue())['status'],'unavailable')
        budget=self.original_budget()
        with patch.object(budget,'inherited_group',return_value=True),patch.object(self.store,'locked',side_effect=AssertionError('unsealed store')):
            with self.assertRaises(Refused):execute(self.frame('admit',epoch=0),self.store,budget=budget)

    def test_admit_typed_seal_precedes_lock_exact_paths_and_single_use(self):
        budget=self.original_budget();original=self.store.locked
        with projected_startup(self.root)as(startup,events,lib),patch.object(budget,'inherited_group',return_value=True):
            @contextmanager
            def locked(account):
                self.assertEqual(events[-1],('pledge',(kernel._ADMISSION_FINAL,kernel._ADMISSION_FINAL)))
                with original(account)as path:yield path
            with patch.object(self.store,'locked',side_effect=locked):
                self.assertEqual(execute(self.frame('admit',epoch=0),self.store,budget=budget,startup=startup)['epoch'],0)
            lock,record=self.store._paths(ACCOUNT)
            self.assertEqual(events,[('pledge',(kernel._ADMISSION_EARLY,None)),
                ('unveil',(os.fsencode(self.root),b'')),('unveil',(os.fsencode(record),b'r')),
                ('unveil',(os.fsencode(lock),b'rwc')),('unveil',(None,None)),
                ('pledge',(kernel._ADMISSION_FINAL,kernel._ADMISSION_FINAL))])
            with self.assertRaises(Refused):startup.bind(ACCOUNT,self.store,budget)

    def test_seal_foreign_material_budget_store_reuse_and_native_failure_refuse(self):
        budget=self.original_budget();material=object.__new__(NativeMaterial)
        with projected_startup(self.root)as(startup,events,lib),patch.object(budget,'inherited_group',return_value=True):
            seal=startup.bind(ACCOUNT,self.store,budget,material)
            for account,owned,original in [('bob@example.test',material,budget),(ACCOUNT,object.__new__(NativeMaterial),budget),(ACCOUNT,material,self.original_budget())]:
                with self.assertRaises(Refused):seal.check(account,owned,original)
            self.assertEqual(len(events),1)
            self.store.uid=-1
            with self.assertRaises(Refused):seal.check(ACCOUNT,material,budget)
            self.store.uid=os.geteuid()
            lib.unveil.fail=True
            with patch('account_command_kernel.os.getpgid',return_value=os.getpid()),self.assertRaises(Refused):
                seal.apply(ACCOUNT,material,budget,SimpleNamespace(pid=os.getpid()+1))
            self.assertEqual(seal._phase,'sealing')
            with self.assertRaises(Refused):seal.require_sealed(ACCOUNT,material,budget)
            count=len(events)
            with self.assertRaises(Refused):seal.apply(ACCOUNT,material,budget)
            self.assertEqual(len(events),count)

    def test_sealed_phase_requires_unveil_lock_and_final_pledge(self):
        budget=self.original_budget()
        with projected_startup(self.root)as(startup,events,lib),patch.object(budget,'inherited_group',return_value=True):
            seal=startup.bind(ACCOUNT,self.store,budget)
            lib.pledge.fail=True
            with self.assertRaises(Refused):seal.apply(ACCOUNT,None,budget)
            self.assertIn(('unveil',(None,None)),events)
            self.assertEqual(events[-1],('pledge',(kernel._ADMISSION_FINAL,kernel._ADMISSION_FINAL)))
            self.assertEqual(seal._phase,'sealing')
            with self.assertRaises(Refused):seal.require_sealed(ACCOUNT,None,budget)


if __name__ == '__main__':
    unittest.main()
