"""Public owned-store and local peer continuity controls; no native SQL/auth."""
import unittest
import test_account_mutation_worker as fixtures
from account_mutation_codec import verify_request
from authoritative_password import Unconfirmed, Refused
from operation_budget import OperationBudget

class PendingControls(unittest.TestCase):
    setUp=fixtures.WorkerTests.setUp
    tearDown=fixtures.WorkerTests.tearDown
    build=fixtures.WorkerTests.build
    def test_missing_live_issuer_ack_after_pending_never_dispatches_credential_write(self):
        action=verify_request(fixtures.frame(),fixtures.KEY,1000).action
        budget=OperationBudget(1300,monotonic=self.monotonic,wall=self.clock)
        coordinator=self.build(action,budget,lambda a,t:a is action)
        coordinator.pending_confirmation=lambda a:a is not action
        with self.assertRaises(Unconfirmed):coordinator.change(action)
        self.assertEqual(self.backend.writes,0)


import json
import os
import socket
import threading
from unittest.mock import patch
from account_mutation_continuity import verify, signed
import test_guarded_mutation_worker as guarded_fixtures
from account_mutation_worker import Unavailable

class ChannelControls(unittest.TestCase):
    setUp=fixtures.WorkerTests.setUp
    tearDown=fixtures.WorkerTests.tearDown
    build=fixtures.WorkerTests.build
    record=fixtures.WorkerTests.record
    check_reply=fixtures.WorkerTests.check_reply
    worker=guarded_fixtures.GuardedWorkerTests.worker

    def _exchange(self,mode):
        left,right=socket.socketpair();worker=self.worker();errors=[];millis=[1000000]
        original=worker.execute_guarded
        def execute(raw,**kwargs):
            with patch('operation_budget.OperationBudget.attach_owned_process_group'):
                return original(raw,clock_millis=lambda:millis[0],**kwargs)
        worker.execute_guarded=execute
        def server():
            try:worker._connection(left,os.getuid(),guarded_session=True,continuous_issuer=True)
            except BaseException as error:errors.append(error)
            finally:left.close()
        thread=threading.Thread(target=server);thread.start();raw=guarded_fixtures.guarded()
        def exact(n):
            data=bytearray()
            while len(data)<n:
                part=right.recv(n-len(data))
                if not part:raise EOFError
                data.extend(part)
            return bytes(data)
        def framed():
            n=int.from_bytes(exact(4),'big');self.assertLessEqual(n,4096);return exact(n)
        try:
            right.settimeout(1);right.sendall(len(raw).to_bytes(4,'big')+raw)
            challenge=verify(framed(),fixtures.KEY,'challenge')
            pending=json.loads(next(self.epoch_root.glob('*.json')).read_bytes())
            self.assertEqual(pending['state'],'pending');self.assertEqual(self.backend.writes,0)
            self.assertEqual(challenge['intent_reference'],'a'*64)
            self.assertEqual(challenge['epoch'],0)
            ack=dict(challenge,phase='ack');ack.pop('signature')
            if mode=='issuer_loss':right.close()
            else:
                if mode=='nonce_retarget':ack['nonce']='0'*64
                if mode=='late':millis[0]=1001000
                payload=signed(ack,fixtures.KEY)
                if mode=='tamper':payload=payload.replace(b'"ack"',b'"bad"')
                right.sendall(len(payload).to_bytes(4,'big')+payload+(b'X' if mode=='trailing' else b''));right.shutdown(socket.SHUT_WR)
                if mode=='good':self.check_reply(framed(),'changed');self.assertEqual(right.recv(1),b'')
                elif mode!='late':self.check_reply(framed(),'contained');self.assertEqual(right.recv(1),b'')
        finally:right.close();thread.join(timeout=2)
        self.assertFalse(thread.is_alive())
        if mode=='good':
            self.assertEqual(errors,[]);self.assertEqual(self.backend.writes,1)
            self.assertEqual(self.store.admission(fixtures.ACCOUNT),(1,'20261004170000'))
        else:
            self.assertEqual(self.backend.writes,0)
            with self.assertRaises(Refused):self.store.admission(fixtures.ACCOUNT)
            self.assertEqual(self.record()['entries'][0]['outcome']['status'],'contained')
            if mode in ('issuer_loss','late'):self.assertTrue(errors)
            else:self.assertEqual(errors,[])
        with self.assertRaises(Unavailable):
            guarded_fixtures.GuardedWorkerTests.execute_guarded(self,worker=self.worker())
        self.assertEqual(self.backend.writes,1 if mode=='good' else 0)

    def test_actual_peer_ack_follows_pending_and_allows_single_exact_workflow(self):self._exchange('good')
    def test_actual_peer_issuer_death_after_pending_contains_and_never_writes(self):self._exchange('issuer_loss')
    def test_actual_peer_tampered_ack_contains_and_never_writes(self):self._exchange('tamper')
    def test_actual_peer_signed_other_nonce_contains_and_never_writes(self):self._exchange('nonce_retarget')
    def test_actual_peer_trailing_ack_contains_and_never_writes(self):self._exchange('trailing')
    def test_actual_peer_late_ack_contains_with_original_millisecond_budget(self):self._exchange('late')
    def test_default_continuity_connection_is_disabled_before_peer_access(self):
        with self.assertRaises(Unavailable):self.worker().continuous_guarded_connection(None,os.getuid())

    def test_internal_reply_retains_exact_original_budget_instead_of_connection_sixty_seconds(self):
        worker=self.worker()
        with patch('operation_budget.OperationBudget.attach_owned_process_group'):
            reply,budget=worker.execute_guarded(guarded_fixtures.guarded(),clock_millis=lambda:1000000,_reply_budget=True)
        self.check_reply(reply,'changed')
        self.mono=10.99
        self.assertLess(budget.remaining(),.011)
        self.mono=11.0
        with self.assertRaises(Refused):budget.remaining()
        self.assertEqual(self.backend.writes,1)

if __name__=='__main__':unittest.main()
