import pathlib,tempfile,os,unittest,json,threading,time
from authoritative_password import AuthoritativePasswordAdapter as Adapter,Refused,Unconfirmed,Receipt
from account_epoch import EpochStore,PasswordCoordinator
ACCOUNT='alice@example.test';REF='a'*64;NOW=1000;NEW='long synthetic password'
class Backend:
    _account=staticmethod(Adapter._account);validate_new=staticmethod(Adapter.validate_new)
    def __init__(self):self.writes=0;self.result=Receipt('20261004170000')
    def read(self,account):return object()
    def replace(self,*args):
        self.writes+=1
        if isinstance(self.result,BaseException):raise self.result
        return self.result
class EpochTests(unittest.TestCase):
    def setUp(self):
        self.tmp=tempfile.TemporaryDirectory();self.root=pathlib.Path(self.tmp.name)
        self.store=EpochStore(self.root,os.getuid());self.store.provision(ACCOUNT)
        self.backend=Backend();self.fresh=True;self.ready=True;self.changed=True;self.finished=True
        self.coordinator=PasswordCoordinator(self.store,self.backend,lambda *a:self.fresh,lambda *a:self.changed,lambda *a:self.ready,lambda *a:self.finished)
        self.coordinator.invalidate_changed_auth=lambda *a:True
    def tearDown(self):self.tmp.cleanup()
    def change(self,epoch=0,reference=REF):return self.coordinator.change(ACCOUNT,epoch,reference,'old',NEW,NEW,'public-fixture',NOW)
    def test_success_bumps_epoch_only_after_verified_write_and_containment(self):
        self.assertEqual(self.change(),(1,'20261004170000'));self.assertEqual(self.store.admission(ACCOUNT),(1,'20261004170000'))
        with self.assertRaises(Refused):self.store.admission(ACCOUNT,0)
    def test_fresh_failure_or_unqualified_containment_never_writes_or_revokes(self):
        for field in ['fresh','ready']:
            setattr(self,field,False)
            with self.assertRaises(Refused):self.change()
            self.assertEqual(self.backend.writes,0);self.assertEqual(self.store.admission(ACCOUNT),(0,None))
            setattr(self,field,True)
    def test_exact_failed_writer_preserves_epoch_but_consumes_intent(self):
        self.backend.result=Refused('synthetic CAS refusal')
        with self.assertRaises(Refused):self.change()
        self.assertEqual(self.store.admission(ACCOUNT),(0,None))
        with self.assertRaises(Refused):self.change()
        self.assertEqual(self.backend.writes,1)
    def test_ambiguous_writer_durably_contains_and_cannot_auto_retry(self):
        self.backend.result=Unconfirmed('synthetic ambiguous receipt')
        with self.assertRaises(Unconfirmed):self.change()
        reopened=EpochStore(self.root,os.getuid())
        with self.assertRaises(Refused):reopened.admission(ACCOUNT)
        with self.assertRaises(Refused):self.change(reference='b'*64)
        self.assertEqual(self.backend.writes,1)
    def test_changed_credential_partial_failure_never_reports_success(self):
        for field in ['changed','finished']:
            setattr(self,field,False)
            with self.assertRaises(Unconfirmed):self.change()
            with self.assertRaises(Refused):self.store.admission(ACCOUNT)
            break
    def test_verified_changed_credential_containment_failure_is_durable(self):
        self.finished=False
        with self.assertRaises(Unconfirmed):self.change()
        self.assertEqual(self.backend.writes,1)
        with self.assertRaises(Refused):EpochStore(self.root,os.getuid()).admission(ACCOUNT)
    def test_missing_corrupt_foreign_and_symlink_records_refuse_no_recreation(self):
        with self.assertRaises(Refused):self.store.admission('bob@example.test')
        _,path=self.store._paths(ACCOUNT);path.unlink()
        with self.assertRaises(Refused):self.store.admission(ACCOUNT)
        self.assertFalse(path.exists())
        path.write_text('{}');path.chmod(0o600)
        with self.assertRaises(Refused):self.store.admission(ACCOUNT)
        path.unlink();path.symlink_to('/dev/null')
        with self.assertRaises(Refused):self.store.admission(ACCOUNT)
    def test_generated_state_contains_no_password_totp_or_account_text(self):
        self.change()
        for file in self.root.iterdir():
            self.assertEqual(file.stat().st_mode&0o077,0)
            data=file.read_bytes()
            for value in [b'old',NEW.encode(),b'public-fixture',ACCOUNT.encode()]:self.assertNotIn(value,data)
    def test_contained_restart_state_blocks_concurrent_login_admission(self):
        entered=threading.Event();release=threading.Event();finished=[]
        def write(*args):entered.set();release.wait(2);return Receipt('20261004170000')
        self.backend.replace=write
        changer=threading.Thread(target=lambda:finished.append(self.change()));changer.start();self.assertTrue(entered.wait(1))
        admits=[]
        def admit():
            try:admits.append(self.store.admission(ACCOUNT,0))
            except Refused:admits.append('refused')
        login=threading.Thread(target=admit);login.start();time.sleep(0.02);self.assertTrue(login.is_alive())
        release.set();changer.join(2);login.join(2)
        self.assertEqual(admits,['refused']);self.assertEqual(finished,[(1,'20261004170000')])
    def test_stale_epoch_and_foreign_account_never_dispatch(self):
        with self.assertRaises(Refused):self.change(epoch=1)
        with self.assertRaises(Refused):self.coordinator.change('bob@example.test',0,REF,'old',NEW,NEW,'public',NOW)
        self.assertEqual(self.backend.writes,0)
    def test_busy_account_lock_refuses_within_bounded_deadline(self):
        entered=threading.Event()
        def hold():
            with self.store.locked(ACCOUNT):entered.set();time.sleep(0.25)
        holder=threading.Thread(target=hold);holder.start();self.assertTrue(entered.wait(1))
        second=EpochStore(self.root,os.getuid());second.LOCK_WAIT_SECONDS=0.05
        start=time.monotonic()
        try:
            with self.assertRaises(Refused):second.admission(ACCOUNT)
            self.assertLess(time.monotonic()-start,0.2)
        finally:holder.join(1)
    def test_prewrite_dependency_error_is_redacted_without_mutation(self):
        def fail(*args):raise ValueError('private diagnostic never returned')
        self.coordinator.verify_fresh=fail
        with self.assertRaises(Refused) as error:self.change()
        self.assertNotIn('private',str(error.exception));self.assertEqual(self.backend.writes,0)
        self.assertEqual(self.store.admission(ACCOUNT),(0,None))
    def test_terminal_epoch_refuses_before_every_backend_callback_and_state_write(self):
        for state in ['active','pending','contained']:
            with self.store.locked(ACCOUNT) as path:
                value=self.store._read(path)
                self.store._write(path,dict(value,epoch=2**64-2,state=state,
                                           intent=None if state=='active' else REF))
                before=path.read_bytes()
            calls=[]
            def callback(*args):calls.append('callback');return True
            self.coordinator.verify_fresh=callback;self.coordinator.containment_ready=callback
            self.coordinator.verify_changed=callback;self.coordinator.finish_containment=callback
            self.backend.read=callback
            with self.assertRaises(Refused):self.change(epoch=2**64-2)
            self.assertEqual(calls,[]);self.assertEqual(self.backend.writes,0)
            self.assertEqual(path.read_bytes(),before)

    def test_last_allowed_transition_remains_readable_and_next_refusal_preserves_state(self):
        with self.store.locked(ACCOUNT) as path:
            value=self.store._read(path);self.store._write(path,dict(value,epoch=2**64-3))
        self.assertEqual(self.change(epoch=2**64-3),(2**64-2,'20261004170000'))
        self.assertEqual(self.store.admission(ACCOUNT),(2**64-2,'20261004170000'))
        before=path.read_bytes()
        with self.assertRaises(Refused):self.change(epoch=2**64-2,reference='b'*64)
        self.assertEqual(self.backend.writes,1);self.assertEqual(path.read_bytes(),before)

    def test_epoch_bounds_and_boolean_refused_without_durable_state_mutation(self):
        with self.store.locked(ACCOUNT) as path:
            value=self.store._read(path);self.store._write(path,dict(value,epoch=1))
            before=path.read_bytes()
            for epoch in [-1,True,2**64-1,2**64]:
                with self.assertRaises(Refused):self.store._write(path,dict(value,epoch=epoch))
                self.assertEqual(path.read_bytes(),before)
        for epoch in [-1,True,2**64-1,2**64]:
            with self.assertRaises(Refused):self.store.admission(ACCOUNT,epoch)
            self.assertEqual(path.read_bytes(),before)

if __name__=='__main__':unittest.main()
