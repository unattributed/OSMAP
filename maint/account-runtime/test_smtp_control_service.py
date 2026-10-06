"""Password-free delegation, real local descriptors and durable grant controls."""
import hashlib,hmac,json,os,socket,threading,time,unittest,tempfile
from pathlib import Path
from unittest.mock import patch
from account_guarded_mutation import canonical,payload,SCHEMA as GUARD_SCHEMA
from account_mutation_budget import envelope
from account_mutation_codec import encoded,ACTION,SCHEMA
from authoritative_password import Refused,Unconfirmed
import smtp_control_authorization as proof
import smtp_auth_control_service as service
import smtp_auth_control as control
import test_smtp_auth_control as fixtures

KEY=bytes([17])*32;SESSION_KEY=bytes([19])*32;CONTROL_KEY=bytes([23])*32

def guarded(account=fixtures.ALICE,sent=1000000,deadline=1001000):
    value=dict(schema=SCHEMA,action=ACTION,account=account,epoch=0,intent_reference='a'*64,
      session_id='b'*64,request_id='public-request',source='127.0.0.1',issued=1000,expires=1300,
      current='old public synthetic credential',new='new public synthetic credential',confirmation='new public synthetic credential')
    values=[SCHEMA,ACTION,'request',*[value[k]for k in ('account','epoch','intent_reference','session_id','request_id','source','issued','expires','current','new','confirmation')]]
    value['signature']=hmac.new(KEY,encoded(values),hashlib.sha256).hexdigest();raw=encoded(value)
    budget=json.loads(envelope(raw,KEY,sent,deadline))
    p=dict(schema=GUARD_SCHEMA,account=account,epoch=0,session_id='b'*64,request_id='public-request',source='127.0.0.1',intent_reference='a'*64,
      request_sha256=hashlib.sha256(raw).hexdigest(),budget_sha256=hashlib.sha256(canonical(budget)).hexdigest(),checked_millis=sent,
      session_expires=1500,idle_expires=1400,issued=1000,expires=1300,deadline_millis=deadline)
    p['signature']=hmac.new(SESSION_KEY,payload(p),hashlib.sha256).hexdigest()
    return encoded(dict(budget=budget,session_proof=p))

class ServiceTests(unittest.TestCase):
    def setUp(self):
        self.fixture=fixtures.ControlTests('runTest')
        temporary=tempfile.TemporaryDirectory
        def private_temporary(*args,**kwargs):
            kwargs['dir']=str(Path.home()/'.cache');return temporary(*args,**kwargs)
        with patch.object(tempfile,'TemporaryDirectory',side_effect=private_temporary):self.fixture.setUp()
        self.addCleanup(self.fixture.doCleanups)
        self.f=self.fixture.fixture;self.clock=self.f.clock
        self.authority=proof.ControlAuthority(CONTROL_KEY,frozenset((fixtures.ALICE,fixtures.BOB)))
        self.raw=proof.derive_authorization(guarded(),KEY,SESSION_KEY,self.authority,1000000)
        root=self.f.root/'control-grants';root.mkdir(mode=0o700)
        self.journal=service.ControlGrantStore(root,os.getuid())
        for account in (fixtures.ALICE,fixtures.BOB):self.journal.provision(account)
        self.routing=service.ControlTopologyAdmission(self.f.planroot,os.getuid(),self.f.execute)
        self.supervisor=self.build();self.results=[]
    def build(self):return service.GuardedControlSupervisor(self.authority,self.fixture.registry,self.journal,self.routing,monotonic=self.clock,clock_millis=lambda:int(self.clock.now*1000))
    def pair(self,raw=None,supervisor=None):
        server,client=socket.socketpair();self.addCleanup(server.close);self.addCleanup(client.close)
        def serve():
            try:self.results.append((supervisor or self.supervisor).connection(server))
            except Exception as e:self.results.append(e)
        thread=threading.Thread(target=serve);thread.start();self.addCleanup(lambda:thread.join(2))
        raw=self.raw if raw is None else raw;client.sendall(len(raw).to_bytes(4,'big')+raw)
        return client,thread
    def client(self,stream):return control.LifecycleControlClient(stream,self.fixture.namespace,self.fixture.budget)
    def record(self):return self.journal._record(self.journal._paths(fixtures.ALICE)[1])
    def test_wire_and_journal_exclude_passwords_complete_original_request_and_signing_keys(self):
        value=json.loads(self.raw)
        self.assertEqual(set(value),proof.FIELDS)
        for secret in (b'public synthetic credential',b'confirmation',b'request_hex',KEY.hex().encode(),SESSION_KEY.hex().encode()):self.assertNotIn(secret,self.raw)
        checked=proof.verify_authorization(self.raw,self.authority,1000000)
        self.assertEqual((checked.account,checked.epoch,checked.deadline_millis),(fixtures.ALICE,0,1001000))
        self.assertEqual(self.record()['entries'],[])
    def test_authenticated_grant_accepted_once_held_flock_and_replay_after_restart_refused(self):
        alice,front,upstream=self.fixture.channel();self.fixture.state()
        with self.fixture.store.locked(fixtures.ALICE):
            stream,t=self.pair();client=self.client(stream);client.capture(fixtures.ALICE);self.assertEqual(client.cancel(),1);t.join(2)
        self.assertTrue(alice.closed)
        for peer in (front,upstream):peer.settimeout(.2);self.assertEqual(peer.recv(1),b'')
        self.assertEqual(self.record()['entries'][0]['state'],'complete')
        stream,t=self.pair(supervisor=self.build());stream.settimeout(1);self.assertEqual(stream.recv(1),b'');t.join(2)
        self.assertEqual(len(self.record()['entries']),1);self.assertEqual(len(self.fixture.registry._cutoffs),0)
        self.assertEqual(self.results[0],1);self.assertIsInstance(self.results[1],Unconfirmed)
    def test_altered_bindings_expired_future_and_whole_guarded_request_deny_before_cutoff(self):
        self.fixture.state();cases=[guarded(),b'[]',b'x'*2049]
        for k,v in [('deadline_millis',1002000),('epoch',1),('account',fixtures.BOB),('session_id','c'*64),('request_id','other'),('guard_sha256','c'*64),('signature','0'*64)]:
            value=json.loads(self.raw);value[k]=v;cases.append(encoded(value))
        for raw in cases:
            stream,t=self.pair(raw);stream.settimeout(1)
            try:self.assertEqual(stream.recv(1),b'')
            except ConnectionResetError:pass
            t.join(2)
        self.assertEqual(self.record()['entries'],[]);self.assertEqual(len(self.fixture.registry._cutoffs),0)
        for now in (999999,1001000):
            with self.assertRaises(Exception):proof.verify_authorization(self.raw,self.authority,now)
    def test_same_original_deadline_deducts_frame_parsing_and_refuses_future_sample(self):
        checked=proof.verify_authorization(self.raw,self.authority,1000000)
        budget=checked.budget(received_mono=1000,received_millis=1000000,monotonic=self.clock,clock_millis=lambda:int(self.clock.now*1000))
        self.clock.now=1000.3;self.assertAlmostEqual(budget.remaining(),.7,places=3)
        self.clock.now=1001
        with self.assertRaises(Exception):budget.remaining()
        self.clock.now=1000
        with self.assertRaises(Exception):checked.budget(received_mono=1000,received_millis=999999,monotonic=self.clock,clock_millis=lambda:1000000)
    def test_foreign_topology_changed_pending_epoch_intent_or_capture_account_denied(self):
        self.fixture.state(epoch=1);stream,t=self.pair();stream.settimeout(1);self.assertEqual(stream.recv(1),b'');t.join(2)
        self.fixture.state();self.f.metadata['filter']=b'changed\n';stream,t=self.pair();stream.settimeout(1);self.assertEqual(stream.recv(1),b'');t.join(2)
        self.assertEqual(self.record()['entries'],[]);self.assertEqual(len(self.fixture.registry._cutoffs),0)
        self.f.metadata['filter']=b'block in all\n';stream,t=self.pair();stream.sendall(control.CAPTURE+fixtures.BOB.encode()+b'\n');stream.settimeout(1);self.assertEqual(stream.recv(1),b'');t.join(2)
        self.assertEqual(len(self.fixture.registry._cutoffs),0);self.assertEqual(self.record()['entries'][0]['state'],'uncertain')
    def test_late_terminal_ack_failure_after_actual_consumption_preserves_bob_new_generation(self):
        old,_,_=self.fixture.channel();bob,_,_=self.fixture.channel(fixtures.BOB,2);self.fixture.state()
        original=service._send
        def lost(*args):raise BrokenPipeError('public synthetic terminal loss')
        with patch.object(service,'_send',side_effect=lost):
            stream,t=self.pair();client=self.client(stream);client.capture(fixtures.ALICE)
            self.fixture.state(epoch=1,state='active');new,_,_=self.fixture.channel(request=3)
            with self.assertRaises(Unconfirmed):client.cancel()
            t.join(2)
        self.assertTrue(old.closed);self.assertFalse(bob.closed);self.assertFalse(new.closed)
        self.assertEqual(len(self.fixture.registry._cutoffs),0);self.assertTrue(self.fixture.registry._control_uncertain)
        self.assertEqual(self.record()['entries'][0]['state'],'complete')
        self.assertIsInstance(self.results[-1],Unconfirmed)
        stream,t=self.pair(supervisor=self.build());stream.settimeout(1);self.assertEqual(stream.recv(1),b'');t.join(2)
        self.assertEqual(len(self.record()['entries']),1);self.assertFalse(new.closed)
    def test_completion_publish_failure_withholds_terminal_and_latches_after_consumption(self):
        old,_,_=self.fixture.channel();self.fixture.state();publish=self.journal._publish
        def fail(path,value):
            if value['entries']and value['entries'][-1]['state']=='complete':raise OSError('synthetic durable commit failure')
            return publish(path,value)
        with patch.object(self.journal,'_publish',side_effect=fail):
            stream,t=self.pair();client=self.client(stream);client.capture(fixtures.ALICE)
            with self.assertRaises(Unconfirmed):client.cancel()
            t.join(2)
        self.assertTrue(old.closed);self.assertEqual(len(self.fixture.registry._cutoffs),0)
        self.assertTrue(self.fixture.registry._control_uncertain);self.assertEqual(self.record()['entries'][0]['state'],'uncertain')
    def test_real_private_listener_current_kernel_descriptor_and_owned_path_cleanup(self):
        self.fixture.state();parent=self.f.root/'listener';parent.mkdir(mode=0o700);path=parent/'control.sock'
        listener=service.PrivateControlListener(path,os.getuid(),self.supervisor);result=[]
        def serve():
            try:result.append(listener.one())
            except Exception as e:result.append(e)
        thread=threading.Thread(target=serve);thread.start();self.addCleanup(lambda:thread.join(2))
        end=time.monotonic()+1
        while not path.exists()and time.monotonic()<end:time.sleep(.005)
        self.assertEqual(path.stat().st_mode&0o777,0o600)
        stream=socket.socket(socket.AF_UNIX);stream.connect(str(path));stream.sendall(len(self.raw).to_bytes(4,'big')+self.raw)
        client=self.client(stream);client.capture(fixtures.ALICE);self.assertEqual(client.cancel(),0);thread.join(2)
        self.assertEqual(result,[0]);self.assertFalse(path.exists())
    def test_pending_intent_changed_after_admission_denies_before_source_cutoff(self):
        self.fixture.state();claimed=threading.Event();publish=self.journal._publish
        def observed_publish(path,value):
            result=publish(path,value)
            if value['entries']and value['entries'][-1]['state']=='claimed':claimed.set()
            return result
        # Observe successful publication under the source claim lock; no capture yet.
        with patch.object(self.journal,'_publish',side_effect=observed_publish):
            stream,t=self.pair();self.assertTrue(claimed.wait(1),'source grant claim was not published within original wait')
            with self.fixture.store.locked(fixtures.ALICE)as path:
                value=self.fixture.store._read(path);value['intent']='c'*64;self.fixture.store._write(path,value)
            stream.sendall(control.CAPTURE+fixtures.ALICE.encode()+b'\n');stream.settimeout(1)
            self.assertEqual(stream.recv(1),b'');t.join(2)
            self.assertEqual(len(self.fixture.registry._cutoffs),0);self.assertEqual(self.record()['entries'][0]['state'],'uncertain')
    def test_foreign_kernel_uid_refuses_before_initial_frame_or_journal_claim(self):
        left,right=socket.socketpair();self.addCleanup(right.close)
        with patch.object(service,'_kernel_peer',return_value=(os.getuid()+1,os.getgid())),patch.object(self.supervisor,'_frame')as frame:
            with self.assertRaises(Unconfirmed):self.supervisor.connection(left)
            frame.assert_not_called()
        self.assertEqual(self.record()['entries'],[]);self.assertEqual(len(self.fixture.registry._cutoffs),0)
    def test_listener_never_replaces_preexisting_name_or_removes_foreign_replacement(self):
        parent=self.f.root/'listener';parent.mkdir(mode=0o700);path=parent/'control.sock'
        path.write_bytes(b'public foreign marker');path.chmod(0o600)
        listener=service.PrivateControlListener(path,os.getuid(),self.supervisor)
        with self.assertRaises(Refused):listener.one()
        self.assertEqual(path.read_bytes(),b'public foreign marker');path.unlink()
        self.fixture.state();results=[]
        def serve():
            try:results.append(listener.one())
            except Exception as e:results.append(e)
        thread=threading.Thread(target=serve);thread.start();self.addCleanup(lambda:thread.join(2))
        end=time.monotonic()+1
        while not path.exists()and time.monotonic()<end:time.sleep(.005)
        stream=socket.socket(socket.AF_UNIX);stream.connect(str(path))
        stream.sendall(len(self.raw).to_bytes(4,'big')+self.raw);client=self.client(stream);client.capture(fixtures.ALICE)
        path.unlink();path.write_bytes(b'public replacement');path.chmod(0o600)
        with self.assertRaises(Unconfirmed):client.cancel()
        thread.join(2)
        self.assertEqual(path.read_bytes(),b'public replacement');self.assertIsInstance(results[0],Refused)
        self.assertTrue(self.fixture.registry._control_uncertain);self.assertEqual(len(self.fixture.registry._cutoffs),1)
    def test_busy_supervisor_closes_descriptor_before_frame_or_grant(self):
        left,right=socket.socketpair();self.addCleanup(right.close)
        self.supervisor._busy.acquire()
        try:
            with patch.object(self.supervisor,'_frame')as frame:
                with self.assertRaises(Refused):self.supervisor.connection(left)
                frame.assert_not_called()
        finally:self.supervisor._busy.release()
        self.assertEqual(left.fileno(),-1);self.assertEqual(self.record()['entries'],[])
    def test_key_separation_and_native_flags_never_mint_activation(self):
        for key in (KEY,SESSION_KEY):
            with self.assertRaises(Exception):proof.derive_authorization(guarded(),KEY,SESSION_KEY,proof.ControlAuthority(key,self.authority.accounts),1000000)
        with patch.object(service,'NATIVE_CONTROL_SERVICE_QUALIFIED',True):
            with self.assertRaises(Refused):service.GuardedControlSupervisor.native()
            with self.assertRaises(Refused):service.PrivateControlListener.native()
if __name__=='__main__':unittest.main()
