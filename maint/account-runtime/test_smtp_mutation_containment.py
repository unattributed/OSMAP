"""Real coordinator/control descriptors with public SQL/mail source projections."""
import fcntl,json,os,socket,threading,time,unittest
from pathlib import Path
from unittest.mock import patch
from account_guarded_mutation import verify_guarded
from account_mutation_budget import operation_budget
from account_mutation_worker import MutationWorker,IntentStore,Lease,Unavailable
from authoritative_password import AuthoritativePasswordAdapter,Refused,Unconfirmed
from mail_session_containment import MailSessionContainment,SmtpProxyControl,SmtpTerminationScope
from prepared_password import PreparedPasswordCoordinator
import smtp_auth_control_service as service
import smtp_mutation_containment as bridge
import test_smtp_control_service as fixtures
import test_required_mail_containment as sqlfixtures

class MutationContainment(unittest.TestCase):
    def setUp(self):
        self.f=fixtures.ServiceTests('runTest');self.f.setUp();self.addCleanup(self.f.doCleanups)
        self.local=self.f.fixture;self.clock=self.f.clock;self.calls=[];self.dependencies=[]
        self.now=lambda:int(self.clock.now)
        self.guarded=verify_guarded(fixtures.guarded(),fixtures.KEY,fixtures.SESSION_KEY,1000000)
        self.budget=operation_budget(self.guarded.budget,received_mono=1000,received_millis=1000000,monotonic=self.clock,clock_millis=lambda:int(self.clock.now*1000))
        self.namespace,self.topology=self.f.routing.admit(self.budget)
        self.root=self.f.f.root/'mutation-intents';self.root.mkdir(mode=0o700)
        self.journal=IntentStore(self.root,os.getuid());self.journal.provision(fixtures.fixtures.ALICE)
        self.sql=sqlfixtures.RequiredTests('runTest');self.sql.calls=[];self.sql.sql_updates=0;self.sql.hash_hook=None;self.sql.flush_hook=None
        self.proxy_rows=b'username proto src ip dest ip port\n'
        self.alice=fixtures.fixtures.ALICE;self.bob=fixtures.fixtures.BOB
        self.own=(self.alice+' submission 127.0.0.1 127.0.0.1 2525\n').encode()
        self.other=(self.bob+' submission 127.0.0.1 127.0.0.1 2525\n').encode()
        self.proxy_results=[(0,self.proxy_rows+self.own+self.other,b''),(0,b'1 connections kicked\n',b''),(0,self.proxy_rows+self.other,b'')]
        self.imap_results=[(0,MailSessionContainment.WHO_HEADER,b''),(0,b'0 cache entries flushed\n',b''),(68,b'no users kicked\n',b''),(0,MailSessionContainment.WHO_HEADER,b'')]
        self.listener_results=[];parent=self.f.f.root/'worker-listener';parent.mkdir(mode=0o700);self.path=parent/'control.sock'
        listener=service.PrivateControlListener(self.path,os.getuid(),self.f.supervisor)
        def listen():
            try:self.listener_results.append(listener.one())
            except Exception as e:self.listener_results.append(e)
        self.thread=threading.Thread(target=listen);self.thread.start()
        self.addCleanup(lambda:self.thread.join(2))
        # If a pre-pending denial never connects, release only this local listener.
        def release():
            if self.path.exists():
                stream=socket.socket(socket.AF_UNIX)
                try:stream.connect(str(self.path))
                except OSError:pass
                finally:stream.close()
        self.addCleanup(release)
        end=time.monotonic()+1
        while not self.path.exists()and time.monotonic()<end:time.sleep(.005)
        self.endpoint=bridge.PrivateControlEndpoint(self.path,os.getuid())
    def proxy(self,program,args,*rest):self.calls.append('proxy-'+('kick'if 'kick'in args else 'query'));return self.proxy_results.pop(0)
    def imap(self,program,args,*rest):self.calls.append('imap-'+args[0]);return self.imap_results.pop(0)
    def execute_sql(self,*args):
        if args[0]==AuthoritativePasswordAdapter.SQL_PROGRAM and args[2].startswith(b'START TRANSACTION;'):
            self.calls.append('SQL')
            self.assertEqual(self.local.store._read(self.local.store._paths(self.alice)[1])['state'],'pending')
            self.assertEqual(self.dependencies[-1]._state,'captured')
        return self.sql.sql(*args)
    def builder(self,action,budget,authorize):
        self.assertIs(budget,self.budget)
        proxy=SmtpProxyControl(self.alice,self.namespace,self.proxy,budget)
        mail=MailSessionContainment(self.alice,self.imap,budget,SmtpTerminationScope.REQUIRED,proxy_control=proxy,topology=self.topology)
        dependency=bridge.GuardedSmtpContainment(mail,self.endpoint,self.f.raw,self.f.authority,self.guarded,clock_millis=lambda:int(self.clock.now*1000))
        self.dependencies.append(dependency);self.addCleanup(dependency.abandon)
        def pending(action):
            result=dependency.capture_pending(action);self.calls.append('capture');return result
        return PreparedPasswordCoordinator(self.local.store,AuthoritativePasswordAdapter(self.execute_sql,before_write=dependency.before_write),authorize,
            lambda *_:True,lambda *_:True,dependency.ready,dependency.finish,self.now,dependency.invalidate_changed_auth,pending_confirmation=pending,release_containment=dependency.abandon)
    def issuer(self,action):
        value=self.local.store._read(self.local.store._paths(action.account)[1]);self.assertEqual((value['state'],value['intent']),('pending',action.intent_reference));self.calls.append('issuer');return True
    def run_worker(self,issuer=None):
        worker=MutationWorker(fixtures.KEY,frozenset((self.alice,)),self.journal,self.local.store,self.builder,lambda *_:False,self.now,self.clock,session_key=fixtures.SESSION_KEY)
        return worker._execute_verified(self.guarded.budget.request,1000,self.budget,session_authority=self.guarded.authorize,pending_confirmation=self.issuer if issuer is None else issuer)
    def epoch(self):return self.local.store._read(self.local.store._paths(self.alice)[1])
    def test_actual_pending_issuer_capture_SQL_SASL_TCP_IMAP_before_active_epoch(self):
        old,front,upstream=self.local.channel(self.alice);bob,_,_=self.local.channel(self.bob,2)
        raw=self.run_worker();value=json.loads(raw);self.assertEqual(value['outcome']['status'],'changed');self.assertEqual(self.epoch()['epoch'],1)
        self.assertLess(self.calls.index('issuer'),self.calls.index('capture'));self.assertLess(self.calls.index('capture'),self.calls.index('SQL'))
        self.assertTrue(old.closed);self.assertFalse(bob.closed)
        for peer in (front,upstream):peer.settimeout(.2);self.assertEqual(peer.recv(1),b'')
        self.assertEqual(self.sql.sql_updates,1);self.assertEqual(self.proxy_results,[]);self.assertEqual(self.imap_results,[])
        self.thread.join(2);self.assertEqual(self.listener_results,[1]);self.assertEqual(self.dependencies[0]._state,'finished');self.assertEqual(self.dependencies[0]._client._stream.fileno(),-1)
    def test_original_issuer_refusal_never_captures_or_writes(self):
        raw=self.run_worker(issuer=lambda _:False);self.assertEqual(json.loads(raw)['outcome']['status'],'contained')
        self.assertEqual(self.sql.sql_updates,0);self.assertNotIn('capture',self.calls);self.assertNotIn('SQL',self.calls)
        self.assertEqual(self.epoch()['state'],'contained');self.assertEqual(self.f.record()['entries'],[])
    def test_lost_broker_ack_after_write_consumption_never_active_or_repeat_SQL(self):
        old,_,_=self.local.channel(self.alice)
        with patch.object(service,'_send',side_effect=BrokenPipeError('synthetic final ACK loss')):
            raw=self.run_worker()
        self.assertEqual(json.loads(raw)['outcome']['status'],'contained');self.assertEqual(self.epoch()['state'],'contained')
        self.assertEqual(self.sql.sql_updates,1);self.assertTrue(old.closed);self.assertTrue(self.local.registry._control_uncertain);self.assertEqual(self.dependencies[0]._client._stream.fileno(),-1)
        self.assertEqual(len(self.local.registry._cutoffs),0);self.assertEqual(self.proxy_results[0][1],b'1 connections kicked\n')
        with self.assertRaises(Exception):self.run_worker()
        self.assertEqual(self.sql.sql_updates,1)
    def test_independent_proxy_TCP_residual_after_broker_success_stays_contained(self):
        old,_,_=self.local.channel(self.alice);self.proxy_results[-1]=(0,self.proxy_rows+self.own+self.other,b'')
        raw=self.run_worker();self.assertEqual(json.loads(raw)['outcome']['status'],'contained')
        self.assertTrue(old.closed);self.assertEqual(self.sql.sql_updates,1);self.assertEqual(self.epoch()['state'],'contained')
        self.assertEqual(sum(x=='proxy-kick'for x in self.calls),1);self.assertNotIn('imap-kick',self.calls)
    def test_expired_original_budget_before_capture_never_SQL_or_new_connection(self):
        def issuer(action):self.issuer(action);self.clock.now=1001;return True
        with self.assertRaises(Unavailable):self.run_worker(issuer)
        self.assertEqual(self.sql.sql_updates,0);self.assertEqual(self.epoch()['state'],'contained');self.assertEqual(self.f.record()['entries'],[])
    def test_worker_releases_captured_descriptor_on_unknown_SQL_exception_under_lease(self):
        self.local.channel(self.alice)
        original=self.execute_sql
        def SQL(*args):
            if args[0]==AuthoritativePasswordAdapter.SQL_PROGRAM and args[2].startswith(b'START TRANSACTION;'):
                raise RuntimeError('synthetic unknown SQL result')
            return original(*args)
        self.execute_sql=SQL
        complete=Lease.complete;checked=[]
        def finish(lease,*args):
            self.assertEqual(self.dependencies[0]._client._stream.fileno(),-1)
            fd=os.open(self.journal._paths(self.alice)[0],os.O_RDWR)
            try:
                with self.assertRaises(BlockingIOError):fcntl.flock(fd,fcntl.LOCK_EX|fcntl.LOCK_NB)
            finally:os.close(fd)
            checked.append(True);return complete(lease,*args)
        with patch.object(Lease,'complete',finish):
            self.assertEqual(json.loads(self.run_worker())['outcome']['status'],'contained')
        self.assertEqual(checked,[True])
        self.assertEqual(self.dependencies[0]._client._stream.fileno(),-1)
        self.assertEqual(self.epoch()['state'],'contained')
        self.thread.join(2);self.assertTrue(self.local.registry._control_uncertain)
        self.assertEqual(self.f.record()['entries'][0]['state'],'uncertain')
    def test_foreign_action_same_account_epoch_intent_cannot_use_original_cutoff(self):
        import dataclasses
        action=self.guarded.budget.request.action
        proxy=SmtpProxyControl(self.alice,self.namespace,self.proxy,self.budget)
        mail=MailSessionContainment(self.alice,self.imap,self.budget,SmtpTerminationScope.REQUIRED,proxy_control=proxy,topology=self.topology)
        dependency=bridge.GuardedSmtpContainment(mail,self.endpoint,self.f.raw,self.f.authority,self.guarded,clock_millis=lambda:1000000)
        dependency.ready(self.alice)
        with self.assertRaises(Refused):dependency.capture_pending(dataclasses.replace(action,new='foreign new public phrase',confirmation='foreign new public phrase'))
        self.assertEqual(self.f.record()['entries'],[]);self.assertEqual(len(self.local.registry._cutoffs),0)
    def test_same_expiry_generic_budget_with_fresh_routing_cannot_substitute_original_receipt(self):
        from operation_budget import OperationBudget
        generic=OperationBudget(1001,monotonic=self.clock,wall=self.clock)
        namespace,topology=self.f.routing.admit(generic)
        proxy=SmtpProxyControl(self.alice,namespace,self.proxy,generic)
        mail=MailSessionContainment(self.alice,self.imap,generic,SmtpTerminationScope.REQUIRED,proxy_control=proxy,topology=topology)
        self.assertEqual(generic._expires,self.budget._expires)
        self.assertEqual(generic._deadline,1060);self.assertEqual(self.budget._deadline,1001)
        with self.assertRaises(Refused):bridge.GuardedSmtpContainment(mail,self.endpoint,self.f.raw,self.f.authority,self.guarded,clock_millis=lambda:1000000)
        self.assertEqual(self.f.record()['entries'],[])
    def test_changed_original_sent_deadline_receipt_or_monotonic_cap_refused(self):
        from dataclasses import replace
        original=self.budget._original_receipt
        for receipt,deadline in ((replace(original,sent_millis=original.sent_millis-1),1001),
                (replace(original,deadline_millis=original.deadline_millis+1),1001),
                (replace(original,received_millis=original.received_millis+1),1001),
                (replace(original,received_mono=original.received_mono+1),1001),
                (original,1060)):
            self.budget._original_receipt=receipt;self.budget._deadline=deadline
            proxy=SmtpProxyControl(self.alice,self.namespace,self.proxy,self.budget)
            mail=MailSessionContainment(self.alice,self.imap,self.budget,SmtpTerminationScope.REQUIRED,proxy_control=proxy,topology=self.topology)
            with self.assertRaises(Refused):bridge.GuardedSmtpContainment(mail,self.endpoint,self.f.raw,self.f.authority,self.guarded,clock_millis=lambda:1000000)
        self.budget._original_receipt=original;self.budget._deadline=1001
        self.budget.require_original(sent_millis=original.sent_millis,deadline_millis=original.deadline_millis,expires_at=original.expires_at)
        self.assertEqual(self.f.record()['entries'],[])
    def test_foreign_budget_or_native_flags_never_offer_source_factory(self):
        proxy=SmtpProxyControl(self.alice,self.namespace,self.proxy,self.local.budget)
        with self.assertRaises(Refused):bridge.GuardedSmtpContainment(MailSessionContainment(self.alice,self.imap,self.local.budget,SmtpTerminationScope.REQUIRED,proxy_control=proxy,topology=self.local.topology),self.endpoint,self.f.raw,self.f.authority,self.guarded,clock_millis=lambda:1000000)
        with patch.object(bridge,'NATIVE_MUTATION_SMTP_CONTROL_QUALIFIED',True):
            with self.assertRaises(Refused):bridge.PrivateControlEndpoint.native()
            with self.assertRaises(Refused):bridge.GuardedSmtpContainment.native()
if __name__=='__main__':unittest.main()
