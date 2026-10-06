"""Owned local sockets/private topology fixtures, no native or provider action."""
import base64
import os
import socket
import threading
import unittest
from unittest.mock import patch

from account_epoch import EpochStore
from authoritative_password import Refused, Unconfirmed
from operation_budget import OperationBudget
import smtp_auth_control as control
from smtp_auth_lifecycle import OwnedSmtpPeerAuthority, SmtpAuthLifecycle, _kernel_peer
import test_smtp_topology_producer as topology_fixtures

ALICE = 'alice@fixture.invalid'
BOB = 'bob@fixture.invalid'


class ControlTests(unittest.TestCase):
    def setUp(self):
        self.fixture = topology_fixtures.ProducerTests('runTest'); self.fixture.setUp()
        self.addCleanup(self.fixture.doCleanups)
        self.namespace, self.topology = self.fixture.produce()
        self.budget = self.fixture.budget
        root = self.fixture.root / 'epoch'; root.mkdir(mode=0o700)
        self.store = EpochStore(root, os.getuid())
        for account in (ALICE, BOB): self.store.provision(account)
        authority = OwnedSmtpPeerAuthority((os.getuid(),os.getgid()),
            (os.getuid(),os.getgid()),2525,lambda pid,deadline:(123,'127.0.0.1',2525,40123))
        self.registry = SmtpAuthLifecycle(self.store,frozenset((ALICE,BOB)),authority)
        self.results = []

    def channel(self, account=ALICE, request=1):
        c,f = socket.socketpair(); u,b = socket.socketpair()
        for s in (c,f,u,b): self.addCleanup(s.close)
        auth = b'AUTH\t'+str(request).encode()+b'\tPLAIN\tservice=smtp\tresp='+base64.b64encode(
            b'\0'+account.encode()+b'\0public synthetic phrase')+b'\n'
        channel = self.registry.begin(c,u,b'CPID\t123\n',auth,self.budget)
        self.addCleanup(self.registry.close,channel)
        return channel,f,b

    def state(self, account=ALICE, epoch=0, state='pending'):
        with self.store.locked(account) as path:
            value=self.store._read(path)
            self.store._write(path,dict(value,state=state,epoch=epoch,
                intent=None if state=='active' else 'a'*64))

    def pair(self):
        server,client=socket.socketpair()
        self.addCleanup(server.close); self.addCleanup(client.close)
        operation=control.LifecycleControlOperation(self.registry,self.namespace,self.topology,self.budget)
        def serve():
            try:self.results.append(operation.serve(server))
            except Exception as error:self.results.append(error)
        thread=threading.Thread(target=serve); thread.start()
        self.addCleanup(lambda:thread.join(timeout=2))
        return operation,client,thread

    def test_real_kernel_peer_bound_pending_cutoff_and_untargeted_bob(self):
        alice,front,back=self.channel(); bob,bf,_=self.channel(BOB,2)
        with self.store.locked(ALICE) as path:
            self.store._write(path,dict(self.store._read(path),state='pending',intent='a'*64))
            with patch.object(control,'_kernel_peer',wraps=_kernel_peer) as peers:
                operation,stream,thread=self.pair()
                client=control.LifecycleControlClient(stream,self.namespace,self.budget)
                client.capture(ALICE); self.assertEqual(client.cancel(),1)
                thread.join(timeout=2); self.assertFalse(thread.is_alive())
                self.assertGreaterEqual(peers.call_count,6)
        self.assertEqual(self.results,[1]); self.assertEqual(operation._state,'complete')
        for peer in (front,back):peer.settimeout(.2);self.assertEqual(peer.recv(1),b'')
        receipt=self.registry.verified(bob,b'OK\t2\tuser='+BOB.encode()+b'\n')
        self.assertTrue(self.registry.publish(bob,receipt));bf.settimeout(.2)
        self.assertEqual(bf.recv(4096),b'OK\t2\tuser='+BOB.encode()+b'\n')

    def test_connection_held_old_cutoff_never_cancels_new_generation(self):
        old,front,_=self.channel();self.state()
        _,stream,thread=self.pair();client=control.LifecycleControlClient(stream,self.namespace,self.budget)
        client.capture(ALICE);self.state(epoch=1,state='active')
        new,nf,_=self.channel(request=2)
        self.assertEqual(client.cancel(),1);thread.join(timeout=2)
        self.assertTrue(old.closed);self.assertFalse(new.closed)
        self.assertTrue(self.registry.publish(new,self.registry.verified(new,b'OK\t2\tuser='+ALICE.encode()+b'\n')))
        nf.settimeout(.2);self.assertEqual(nf.recv(4096),b'OK\t2\tuser='+ALICE.encode()+b'\n')

    def test_active_record_and_unknown_account_refuse_before_cutoff(self):
        for account in (ALICE,'other@fixture.invalid'):
            _,stream,thread=self.pair();stream.sendall(control.CAPTURE+account.encode()+b'\n')
            stream.settimeout(1);self.assertEqual(stream.recv(1),b'');thread.join(timeout=2)
        self.assertTrue(all(type(v)is Refused for v in self.results))
        self.assertEqual(len(self.registry._cutoffs),0)

    def test_wire_epoch_pid_socket_boolean_deadline_or_pipeline_refuse(self):
        self.state()
        for raw in (control.CAPTURE+ALICE.encode()+b'\tepoch=0\n',
                    b'CAPTURE\ttrue\n',control.CAPTURE+ALICE.encode()+b'\n'+control.CANCEL,
                    b'OSMAP-SMTP-CAPTURE\t'+b'x'*513+b'\n'):
            _,stream,thread=self.pair();stream.sendall(raw);stream.settimeout(1)
            try:self.assertEqual(stream.recv(1),b'')
            except ConnectionResetError:pass
            thread.join(timeout=2)
        self.assertEqual(len(self.registry._cutoffs),0)

    def test_foreign_kernel_uid_never_reads_or_creates_cutoff(self):
        self.state();server,peer=socket.socketpair()
        self.addCleanup(server.close);self.addCleanup(peer.close)
        operation=control.LifecycleControlOperation(self.registry,self.namespace,self.topology,self.budget)
        with patch.object(control,'_kernel_peer',return_value=(os.getuid()+1,os.getgid())),\
             patch.object(control,'_line')as reader:
            with self.assertRaises(Refused):operation.serve(server)
            reader.assert_not_called()
        self.assertEqual(len(self.registry._cutoffs),0)

    def test_changed_topology_after_capture_refuses_zero_channel_closure_and_latches(self):
        channel,_,_=self.channel();self.state()
        _,stream,thread=self.pair();client=control.LifecycleControlClient(stream,self.namespace,self.budget)
        client.capture(ALICE);self.fixture.metadata['filter']=b'changed after capture\n'
        with self.assertRaises(Unconfirmed):client.cancel()
        thread.join(timeout=2);self.assertFalse(channel.closed)
        self.assertTrue(self.registry._control_uncertain)
        self.assertEqual(len(self.registry._cutoffs),1)

    def test_expired_original_budget_cannot_dispatch_cancel_or_restart(self):
        channel,_,_=self.channel();self.state()
        operation,stream,thread=self.pair();client=control.LifecycleControlClient(stream,self.namespace,self.budget)
        client.capture(ALICE);self.fixture.clock.now=1061
        with self.assertRaises(Unconfirmed):client.cancel()
        thread.join(timeout=2);self.assertFalse(channel.closed)
        with self.assertRaises(Refused):operation.serve(stream)
        self.assertEqual(client._state,'cancel-dispatched')

    def test_abandoned_capture_latches_without_retry_or_broader_cutoff(self):
        self.state();_,stream,thread=self.pair()
        stream.sendall(control.CAPTURE+ALICE.encode()+b'\n');stream.settimeout(1)
        self.assertEqual(stream.recv(512),control.CAPTURED);stream.close();thread.join(timeout=2)
        self.assertTrue(self.registry._control_uncertain);self.assertEqual(len(self.registry._cutoffs),1)
        _,stream,thread=self.pair();stream.settimeout(1)
        self.assertEqual(stream.recv(1),b'');thread.join(timeout=2)
        self.assertEqual(len(self.registry._cutoffs),1)

    def test_boolean_foreign_budget_and_native_activation_refused(self):
        for topology,budget in ((True,self.budget),(self.topology,OperationBudget(1300,
                monotonic=self.fixture.clock,wall=self.fixture.clock))):
            with self.assertRaises(Refused):control.LifecycleControlOperation(self.registry,self.namespace,topology,budget)
        with patch.object(control,'NATIVE_CONTROL_QUALIFIED',True):
            with self.assertRaises(Refused):control.LifecycleControlOperation.native()

if __name__=='__main__':unittest.main(verbosity=2)
