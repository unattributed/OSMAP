"""Actual local persistent listener: no installed listener/native admission."""
import os,socket,threading,time,unittest
from pathlib import Path
from unittest.mock import patch
from authoritative_password import Refused,Unconfirmed
import smtp_auth_control_service as service
import smtp_control_authorization as proof
import test_smtp_control_service as fixtures

class PersistentTests(unittest.TestCase):
    def setUp(self):
        self.f=fixtures.ServiceTests('runTest');self.f.setUp();self.addCleanup(self.f.doCleanups)
        self.parent=self.f.f.root/'persistent';self.parent.mkdir(mode=0o700);self.path=self.parent/'control.sock'
        self.listener=service.PrivateControlListener(self.path,os.getuid(),self.f.supervisor)
        self.stop=threading.Event();self.results=[]
    def wait(self,predicate):
        end=time.monotonic()+1
        while not predicate()and time.monotonic()<end:time.sleep(.005)
        self.assertTrue(predicate())
    def start(self):
        def serve():
            try:self.results.append(self.listener.serve(self.stop))
            except Exception as error:self.results.append(error)
        self.thread=threading.Thread(target=serve);self.thread.start()
        self.addCleanup(self.stop.set);self.addCleanup(lambda:self.thread.join(2))
        self.wait(lambda:self.path.exists()and(self.path.stat().st_mode&0o777)==0o600)
        self.assertEqual(self.path.stat().st_mode&0o777,0o600)
        return self.path.stat().st_dev,self.path.stat().st_ino
    def connect(self,raw=None):
        stream=socket.socket(socket.AF_UNIX);self.addCleanup(stream.close);stream.settimeout(1)
        stream.connect(str(self.path));raw=self.f.raw if raw is None else raw
        stream.sendall(len(raw).to_bytes(4,'big')+raw);return stream
    def join(self):
        self.thread.join(2);self.assertFalse(self.thread.is_alive())
    def bob_proof(self):
        return proof.derive_authorization(fixtures.guarded(fixtures.fixtures.BOB),fixtures.KEY,fixtures.SESSION_KEY,self.f.authority,1000000)
    def test_two_independent_signed_accounts_same_owned_inode_serial_real_channels(self):
        alice,af,au=self.f.fixture.channel();bob,bf,bu=self.f.fixture.channel(fixtures.fixtures.BOB,2)
        self.f.fixture.state();self.f.fixture.state(fixtures.fixtures.BOB)
        inode=self.start()
        for account,raw in ((fixtures.fixtures.ALICE,self.f.raw),(fixtures.fixtures.BOB,self.bob_proof())):
            client=self.f.client(self.connect(raw));client.capture(account);self.assertEqual(client.cancel(),1)
            self.assertEqual((self.path.stat().st_dev,self.path.stat().st_ino),inode)
            self.assertEqual(self.f.journal._record(self.f.journal._paths(account)[1])['entries'][0]['state'],'complete')
        self.assertTrue(alice.closed);self.assertTrue(bob.closed)
        for stream in (af,au,bf,bu):stream.settimeout(.2);self.assertEqual(stream.recv(1),b'')
        self.stop.set();self.join();self.assertEqual(self.results,[2]);self.assertFalse(self.path.exists())
    def test_completed_replay_halts_without_another_cutoff_or_budget(self):
        old,_,_=self.f.fixture.channel();self.f.fixture.state();inode=self.start()
        client=self.f.client(self.connect());client.capture(fixtures.fixtures.ALICE);self.assertEqual(client.cancel(),1)
        self.assertEqual((self.path.stat().st_dev,self.path.stat().st_ino),inode)
        with patch.object(self.f.fixture.registry,'pending_cutoff_locked',wraps=self.f.fixture.registry.pending_cutoff_locked)as cutoff:
            replay=self.connect();self.assertEqual(replay.recv(1),b'');self.join();cutoff.assert_not_called()
        self.assertTrue(old.closed);self.assertEqual(len(self.f.record()['entries']),1)
        self.assertEqual(len(self.f.fixture.registry._cutoffs),0);self.assertIsInstance(self.results[0],Unconfirmed)
        self.assertFalse(self.path.exists())
    def test_stop_event_only_ends_future_admission_original_capture_must_finish(self):
        self.f.fixture.state();self.start();client=self.f.client(self.connect());client.capture(fixtures.fixtures.ALICE)
        self.stop.set();time.sleep(.15);self.assertTrue(self.thread.is_alive())
        self.assertTrue(self.path.exists());self.assertEqual(len(self.f.fixture.registry._cutoffs),1)
        self.assertEqual(client.cancel(),0);self.join();self.assertEqual(self.results,[1]);self.assertFalse(self.path.exists())
    def test_stop_event_does_not_renew_expired_operation_or_clear_held_cutoff(self):
        old,_,_=self.f.fixture.channel();self.f.fixture.state();self.start()
        client=self.f.client(self.connect());client.capture(fixtures.fixtures.ALICE);self.stop.set();self.f.clock.now=1001
        with self.assertRaises(Unconfirmed):client.cancel()
        self.join();self.assertFalse(old.closed);self.assertEqual(len(self.f.fixture.registry._cutoffs),1)
        self.assertTrue(self.f.fixture.registry._control_uncertain)
        self.assertEqual(self.f.record()['entries'][0]['state'],'uncertain');self.assertFalse(self.path.exists())
    def test_terminal_loss_halts_after_consumption_preserves_bob_and_no_next_grant(self):
        old,_,_=self.f.fixture.channel();bob,_,_=self.f.fixture.channel(fixtures.fixtures.BOB,2)
        self.f.fixture.state();self.f.fixture.state(fixtures.fixtures.BOB);self.start()
        with patch.object(service,'_send',side_effect=BrokenPipeError('public synthetic terminal loss')):
            client=self.f.client(self.connect());client.capture(fixtures.fixtures.ALICE)
            with self.assertRaises(Unconfirmed):client.cancel()
            self.join()
        self.assertTrue(old.closed);self.assertFalse(bob.closed);self.assertEqual(len(self.f.fixture.registry._cutoffs),0)
        self.assertTrue(self.f.fixture.registry._control_uncertain);self.assertEqual(self.f.record()['entries'][0]['state'],'complete')
        self.assertEqual(self.f.journal._record(self.f.journal._paths(fixtures.fixtures.BOB)[1])['entries'],[])
        with self.assertRaises(Unconfirmed):self.listener.serve(threading.Event())
        self.assertTrue(self.f.fixture.registry._control_uncertain);self.assertFalse(self.path.exists())
    def test_current_namespace_replacement_on_idle_is_retained_foreign_file(self):
        self.start();self.path.unlink();self.path.write_bytes(b'public foreign replacement');self.path.chmod(0o600)
        self.join();self.assertIsInstance(self.results[0],Refused)
        self.assertEqual(self.path.read_bytes(),b'public foreign replacement')
        self.assertEqual(self.f.record()['entries'],[]);self.assertEqual(len(self.f.fixture.registry._cutoffs),0)
    def accept_barrier(self,uncertain):
        entered=threading.Event();release=threading.Event();original=socket.socket.accept
        def gated(server,*args,**kwargs):
            entered.set()
            if not release.wait(1):raise RuntimeError('accept barrier deadline')
            return original(server,*args,**kwargs)
        self.f.fixture.state()
        with patch.object(socket.socket,'accept',gated),patch.object(self.f.supervisor,'_frame',wraps=self.f.supervisor._frame)as frame:
            self.start();self.wait(entered.is_set)
            if uncertain:self.f.fixture.registry._control_uncertain=True
            else:self.stop.set()
            stream=self.connect();stream.settimeout(2);release.set()
            try:self.assertEqual(stream.recv(1),b'')
            except ConnectionResetError:pass
            self.join();frame.assert_not_called()
        self.assertFalse(self.path.exists());self.assertEqual(self.f.record()['entries'],[])
        self.assertEqual(len(self.f.fixture.registry._cutoffs),0)
    def test_stop_during_kernel_accept_refuses_new_grant_before_any_frame(self):
        self.accept_barrier(False);self.assertEqual(self.results,[0])
    def test_uncertainty_during_kernel_accept_refuses_before_frame_grant(self):
        self.accept_barrier(True);self.assertIsInstance(self.results[0],Unconfirmed)
        self.assertTrue(self.f.fixture.registry._control_uncertain)
    def test_single_serve_ownership_stop_type_and_native_refuse_before_new_dispatch(self):
        for stop in (None,True,lambda:False,object()):
            with self.assertRaises(Refused):self.listener.serve(stop)
        self.assertFalse(self.path.exists());inode=self.start()
        for call in (self.listener.one,lambda:self.listener.serve(threading.Event())):
            with self.assertRaises(Refused):call()
        self.assertEqual((self.path.stat().st_dev,self.path.stat().st_ino),inode)
        with patch.object(service,'NATIVE_CONTROL_SERVICE_QUALIFIED',True):
            with self.assertRaises(Refused):service.PrivateControlListener.native()
            with self.assertRaises(Refused):service.GuardedControlSupervisor.native()
        self.stop.set();self.join();self.assertEqual(self.results,[0]);self.assertFalse(self.path.exists())

if __name__=='__main__':unittest.main(verbosity=2)
