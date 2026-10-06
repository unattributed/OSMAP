"""Actual owned child and issuer/control Unix descriptors; no native activation."""
import fcntl,json,os,selectors,signal,socket,subprocess,sys,tempfile,time,unittest
from pathlib import Path
from unittest.mock import patch
from account_mutation_continuity import verify,signed
from account_mutation_supervisor import COMPLETE,_Bootstrap
from account_mutation_worker import MutationWorker,Unavailable
from authoritative_password import AuthoritativePasswordAdapter,Refused
from mail_session_containment import MailSessionContainment,SmtpProxyControl,SmtpTerminationScope
from prepared_password import PreparedPasswordCoordinator
from smtp_control_authorization import ControlAuthority
from smtp_guarded_builder import GuardedSmtpBinding
import test_smtp_mutation_containment as fixtures
import test_account_mutation_supervisor as supervisor_fixtures
import test_guarded_mutation_worker as guarded_fixtures
import test_account_mutation_worker as worker_fixtures
import hashlib,hmac

class GuardedBuilder(unittest.TestCase):
    def exchange(self,mode='positive',*,owned_group=True):
        with tempfile.TemporaryDirectory(prefix='osmap-guarded-smtp-',dir=str(Path.home()/'.cache'))as td:
            root=Path(td);root.chmod(0o700)
            issuer=os.open(root/'issuer.lock',os.O_RDWR|os.O_CREAT,0o600);fcntl.flock(issuer,fcntl.LOCK_EX)
            server,peer=socket.socketpair();end=time.monotonic()+4
            child=subprocess.Popen((sys.executable,'-I',str(Path(__file__).with_name('guarded_smtp_worker_fixture.py'))),stdin=subprocess.PIPE,stdout=server,stderr=subprocess.PIPE,close_fds=True,start_new_session=owned_group,
                env={'PATH':'/usr/bin:/bin','LC_ALL':'C','OSMAP_TEST_GUARDED_SMTP_WITNESS_ROOT':td})
            server.close();sent=int(time.time()*1000);now=sent//1000
            raw=guarded_fixtures.guarded(worker_fixtures.frame(account=fixtures.fixtures.fixtures.ALICE,issued=now,expires=now+300),sent=sent,deadline=sent+1500)
            value=json.loads(raw);p=value['session_proof'];p.update(session_expires=now+500,idle_expires=now+400)
            p['signature']=hmac.new(fixtures.fixtures.SESSION_KEY,guarded_fixtures.payload(p),hashlib.sha256).hexdigest();raw=guarded_fixtures.encoded(value)
            if mode=='proof':
                value=json.loads(raw);value['session_proof']['signature']='0'*64;raw=fixtures.fixtures.encoded(value)
            try:
                child.stdin.write(len(raw).to_bytes(4,'big')+raw);child.stdin.close()
                def exact(n):
                    result=bytearray()
                    while len(result)<n:
                        peer.settimeout(max(.001,end-time.monotonic()));part=peer.recv(n-len(result))
                        if not part:raise EOFError
                        result.extend(part)
                    return bytes(result)
                reply=None;challenge_seen=False;lock_held=False
                try:
                    size=int.from_bytes(exact(4),'big');self.assertLessEqual(size,4096)
                    challenge=verify(exact(size),fixtures.fixtures.KEY,'challenge');challenge_seen=True
                    info=json.loads((root/'worker-witness.json').read_bytes())
                    self.assertTrue(info['owned_group']);self.assertEqual(info['pid'],child.pid);self.assertEqual(info['group'],child.pid)
                    self.assertEqual(json.loads(Path(info['epoch_record']).read_bytes())['state'],'pending')
                    self.assertEqual(json.loads(Path(info['intent_record']).read_bytes())['entries'][-1]['state'],'pending')
                    fd=os.open(info['intent_lock'],os.O_RDWR)
                    try:
                        with self.assertRaises(BlockingIOError):fcntl.flock(fd,fcntl.LOCK_EX|fcntl.LOCK_NB)
                        lock_held=True
                    finally:os.close(fd)
                    if mode=='eof':peer.shutdown(socket.SHUT_WR)
                    else:
                        ack=dict(challenge,phase='ack');ack.pop('signature')
                        if mode=='nonce':ack['nonce']='0'*64
                        payload=signed(ack,fixtures.fixtures.KEY)
                        peer.sendall(len(payload).to_bytes(4,'big')+payload);peer.shutdown(socket.SHUT_WR)
                    size=int.from_bytes(exact(4),'big');self.assertLessEqual(size,4096);reply=json.loads(exact(size))
                    self.assertEqual(peer.recv(1),b'')
                except (EOFError,ConnectionResetError):pass
                child.wait(timeout=max(.001,end-time.monotonic()))
                marker=child.stderr.read(len(COMPLETE)+1);self.assertLessEqual(len(marker),len(COMPLETE))
                info=json.loads((root/'worker-witness.json').read_bytes())
                if owned_group:
                    with self.assertRaises(ProcessLookupError):os.killpg(child.pid,0)
                return reply,info,challenge_seen,lock_held,marker,child.returncode
            finally:
                peer.close()
                if child.returncode is None:
                    # Only original unreaped exclusive owned child/group.
                    if owned_group:
                        try:os.killpg(child.pid,signal.SIGKILL)
                        except ProcessLookupError:pass
                    else:child.kill()
                    child.wait(timeout=1)
                child.stderr.close();os.close(issuer)
    def test_actual_guarded_worker_issuer_held_intent_control_SQL_SASL_terminal_reap(self):
        reply,info,challenge,lock,marker,code=self.exchange()
        self.assertEqual((code,marker),(0,COMPLETE));self.assertTrue(challenge and lock)
        self.assertEqual(reply['outcome']['status'],'changed');self.assertEqual(info['sql_calls'],1)
        self.assertEqual(info['epoch_state'],'active');self.assertEqual(info['active_epoch'],1)
        self.assertTrue(info['alice_closed']and info['saslend_eof']and info['owned_descriptor_closed']);self.assertFalse(info['bob_closed'])
    def test_wrong_nonce_and_issuer_EOF_stay_contained_before_SQL_or_capture(self):
        for mode in ('nonce','eof'):
            reply,info,challenge,lock,marker,code=self.exchange(mode)
            self.assertTrue(challenge and lock);self.assertEqual(reply['outcome']['status'],'contained')
            self.assertEqual((info['sql_calls'],info['captures']),(0,0));self.assertEqual(info['epoch_state'],'contained')
            self.assertTrue(info['owned_descriptor_closed']);self.assertEqual((code,marker),(0,COMPLETE))
    def test_foreign_guard_or_nonleader_child_never_builder_issuer_SQL_capture(self):
        for mode,owned in (('proof',True),('positive',False)):
            reply,info,challenge,lock,marker,code=self.exchange(mode,owned_group=owned)
            self.assertIsNone(reply);self.assertFalse(challenge or lock);self.assertNotEqual(code,0);self.assertEqual(marker,b'')
            self.assertEqual((info['sql_calls'],info['captures']),(0,0));self.assertNotIn('intent_lock',info)

class Startup(unittest.TestCase):
    def setUp(self):
        self.case=fixtures.MutationContainment('runTest');self.case.setUp();self.addCleanup(self.case.doCleanups)
        self.boot=_Bootstrap(fixtures.fixtures.KEY,fixtures.fixtures.SESSION_KEY,self.case.f.authority.accounts,os.getuid())
    def test_purpose_keys_accounts_callback_and_native_flag_never_mint_binding(self):
        for authority in (ControlAuthority(fixtures.fixtures.KEY,self.boot.accounts),ControlAuthority(fixtures.fixtures.SESSION_KEY,self.boot.accounts),ControlAuthority(bytes([23])*32,frozenset((self.case.alice,)))):
            with self.assertRaises(Refused):GuardedSmtpBinding(self.boot,authority,self.case.endpoint,clock_millis=lambda:1000000)
        with self.assertRaises(Refused):GuardedSmtpBinding.native()
    def base(self):
        c=self.case
        proxy=SmtpProxyControl(c.alice,c.namespace,c.proxy,c.budget)
        mail=MailSessionContainment(c.alice,c.imap,c.budget,SmtpTerminationScope.REQUIRED,proxy_control=proxy,topology=c.topology)
        coordinator=PreparedPasswordCoordinator(c.local.store,AuthoritativePasswordAdapter(c.execute_sql,before_write=mail.before_write),lambda *_:False,
            lambda *_:True,lambda *_:True,mail.ready,mail.finish,c.now,mail.invalidate_changed_auth)
        return coordinator,mail
    def test_exact_local_guarded_binding_rewires_one_coordinator_without_password_transport(self):
        coordinator,mail=self.base();binding=GuardedSmtpBinding(self.boot,self.case.f.authority,self.case.endpoint,clock_millis=lambda:1000000)
        with patch.object(self.case.budget,'inherited_group',return_value=True):
            result=binding.compose(coordinator,self.case.guarded,fixtures.fixtures.guarded(),self.case.budget)
        self.assertIs(result,coordinator);dependency=coordinator.containment_ready.__self__
        self.assertIs(dependency._mail,mail);self.assertIs(dependency._budget,self.case.budget)
        self.assertEqual(coordinator.pending_confirmation,dependency.capture_pending)
        self.assertEqual(coordinator.release_containment,dependency.abandon)
        self.assertEqual(coordinator.adapter._before_write,dependency.before_write)
        for value in (b'public synthetic credential',b'request_hex',fixtures.fixtures.KEY.hex().encode(),fixtures.fixtures.SESSION_KEY.hex().encode()):self.assertNotIn(value,dependency._authorization)
    def test_changed_original_frame_missing_owned_group_and_native_startup_refuse_before_rewire(self):
        binding=GuardedSmtpBinding(self.boot,self.case.f.authority,self.case.endpoint,clock_millis=lambda:1000000)
        for frame in (b'{}',fixtures.fixtures.guarded(deadline=1002000)):
            coordinator,mail=self.base()
            with patch.object(self.case.budget,'inherited_group',return_value=True):
                with self.assertRaises(Refused):binding.compose(coordinator,self.case.guarded,frame,self.case.budget)
            self.assertEqual(coordinator.adapter._before_write,mail.before_write);self.assertIsNone(coordinator.pending_confirmation)
        coordinator,_=self.base()
        with self.assertRaises(Refused):binding.compose(coordinator,self.case.guarded,fixtures.fixtures.guarded(),self.case.budget)
    def test_native_dependency_registers_same_bootstrap_and_guarded_builder_without_enabling_factory(self):
        from account_mutation_native import NativeDependencies
        binding=GuardedSmtpBinding(self.boot,self.case.f.authority,self.case.endpoint,clock_millis=lambda:1000000)
        dependencies=NativeDependencies(self.boot,self.case.journal,self.case.local.store,self.case.now,smtp_control=binding)
        worker=dependencies.worker();self.assertEqual(worker._guarded_builder,dependencies._build_guarded)
        coordinator,_=self.base();authority=lambda *_:False
        with patch.object(dependencies,'_build',return_value=coordinator)as base,patch.object(self.case.budget,'inherited_group',return_value=True):
            self.assertIs(dependencies._build_guarded(self.case.guarded,fixtures.fixtures.guarded(),self.case.budget,authority),coordinator)
        base.assert_called_once_with(self.case.guarded.budget.request.action,self.case.budget,authority)
        with self.assertRaises(Unavailable):NativeDependencies(self.boot,self.case.journal,self.case.local.store,smtp_control={'PASS':True})
        with self.assertRaises(Unavailable):NativeDependencies.native()
    def test_guarded_builder_requires_owned_issuer_descriptor_and_legacy_cannot_dispatch(self):
        calls=[]
        worker=MutationWorker(fixtures.fixtures.KEY,self.boot.accounts,self.case.journal,self.case.local.store,lambda *_:calls.append('legacy'),lambda *_:False,self.case.now,self.case.clock,
            session_key=fixtures.fixtures.SESSION_KEY,guarded_builder=lambda *_:calls.append('guarded'))
        for stream in (None,True,object()):
            with self.assertRaises(Unavailable):worker.execute_guarded(fixtures.fixtures.guarded(),clock_millis=lambda:1000000,_continuity_stream=stream)
        with self.assertRaises(Unavailable):worker.execute(fixtures.fixtures.encoded({}))
        self.assertEqual(calls,[]);self.assertEqual(self.case.journal._record(self.case.journal._paths(self.case.alice)[1])['entries'],[])
if __name__=='__main__':unittest.main(verbosity=2)
