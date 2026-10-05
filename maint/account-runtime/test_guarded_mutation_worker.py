"""Public fixtures for guarded proof -> durable journal -> real coordinator.
No native SQL, provider, actual password or distributed lease qualification.
"""
import dataclasses
import threading
import hashlib
import hmac
import json
import os
import socket
import unittest
from unittest.mock import patch

from account_guarded_mutation import canonical, payload, SCHEMA as GUARD_SCHEMA
from account_mutation_budget import envelope
from account_mutation_codec import encoded
from account_mutation_worker import Unavailable, MutationWorker
from authoritative_password import Unconfirmed, Refused
import test_account_mutation_worker as fixtures
from test_account_mutation_worker import frame, ACCOUNT, KEY

SESSION_KEY = bytes([19]) * 32


def guarded(raw=None, *, sent=1000000, deadline=1001000):
    raw = frame() if raw is None else raw
    budget = json.loads(envelope(raw, KEY, sent, deadline))
    value = json.loads(raw)
    proof = dict(schema=GUARD_SCHEMA, account=value['account'], epoch=value['epoch'],
                 session_id=value['session_id'], request_id=value['request_id'],
                 source=value['source'], intent_reference=value['intent_reference'],
                 request_sha256=hashlib.sha256(raw).hexdigest(),
                 budget_sha256=hashlib.sha256(canonical(budget)).hexdigest(),
                 checked_millis=sent, session_expires=1500, idle_expires=1400,
                 issued=value['issued'], expires=value['expires'], deadline_millis=deadline)
    proof['signature'] = hmac.new(SESSION_KEY, payload(proof), hashlib.sha256).hexdigest()
    return encoded(dict(budget=budget, session_proof=proof))


class GuardedWorkerTests(unittest.TestCase):
    # Reuse only the public fixture lifecycle/builders; no inherited test copies.
    setUp = fixtures.WorkerTests.setUp
    tearDown = fixtures.WorkerTests.tearDown
    build = fixtures.WorkerTests.build
    record = fixtures.WorkerTests.record
    check_reply = fixtures.WorkerTests.check_reply
    def worker(self, builder=None, journal=None):
        return MutationWorker(KEY, frozenset([ACCOUNT]), journal or self.journal,
                              self.store, builder or self.build,
                              lambda *args: self.calls.append('session') or self.session,
                              self.clock, self.monotonic, session_key=SESSION_KEY)

    def execute_guarded(self, raw=None, *, sample=None, worker=None):
        sample = sample or (lambda: self.now * 1000)
        # Synthetic local test process is not an owned process-group leader;
        # native group supervision has separate actual tests and remains off.
        with patch('operation_budget.OperationBudget.attach_owned_process_group'):
            return (worker or self.worker()).execute_guarded(
                raw or guarded(), clock_millis=sample)

    def test_independent_proof_authority_reaches_durable_journal_real_coordinator(self):
        self.session = False
        reply = self.check_reply(self.execute_guarded(), 'changed')
        self.assertEqual(reply['outcome']['epoch'], 1)
        self.assertEqual(self.backend.writes, 1)
        self.assertNotIn('session', self.calls)
        self.assertEqual(self.record()['entries'][0]['state'], 'complete')
        with self.assertRaises(Unavailable):
            self.execute_guarded()
        self.assertEqual(self.backend.writes, 1)

    def test_invalid_proof_never_claims_journal_despite_valid_inner_request(self):
        initial = next(self.intent_root.glob('*.json')).read_bytes()
        cases = []
        for field, replacement in [('signature','0'*64), ('epoch',1),
                                   ('request_id','other'), ('source','192.0.2.1'),
                                   ('session_id','d'*64), ('account','bob@example.test'),
                                   ('deadline_millis',1002000), ('budget_sha256','0'*64)]:
            value = json.loads(guarded()); value['session_proof'][field] = replacement
            cases.append(encoded(value))
        for field in ['fresh', 'totp_verified', 'live_session']:
            value = json.loads(guarded()); value['session_proof'][field] = True
            cases.append(encoded(value))
        cases += [frame(), b'[]', b'x'*12289, b'{"budget":{},"budget":{}}']
        for raw in cases:
            with self.subTest(size=len(raw)), self.assertRaises(Unavailable):
                self.execute_guarded(raw)
        self.assertEqual(next(self.intent_root.glob('*.json')).read_bytes(),initial)
        self.assertEqual((self.builders,self.backend.writes), (0,0))

    def test_missing_or_same_proof_key_refuses_without_a_legacy_authority_fallback(self):
        legacy = fixtures.WorkerTests.worker(self)
        with self.assertRaises(Unavailable):
            self.execute_guarded(worker=legacy)
        with self.assertRaises(Unavailable):
            MutationWorker(KEY, frozenset([ACCOUNT]), self.journal,self.store,self.build,
                           lambda *a: True,self.clock,self.monotonic,session_key=KEY)
        self.assertEqual(self.calls, [])

    def test_original_millisecond_deadline_exhausted_by_primary_never_writes(self):
        millis = [1000000]
        def build(*args):
            coordinator = self.build(*args)
            def delayed(*values):
                millis[0] = 1001000  # wall seconds unchanged at1000
                return True
            coordinator.verify_current = delayed
            return coordinator
        with self.assertRaises(Unavailable):
            self.execute_guarded(worker=self.worker(builder=build),sample=lambda:millis[0])
        self.assertEqual(self.now,1000)
        self.assertEqual(self.backend.writes,0)
        self.assertEqual(self.store.admission(ACCOUNT),(0,None))
        with self.assertRaises(Unavailable):
            self.execute_guarded()
        self.assertEqual(self.builders,1)

    def test_copied_action_cannot_substitute_the_authenticated_exact_action(self):
        checked=[]
        def build(action,budget,authorize):
            checked.append(authorize(dataclasses.replace(action),self.now))
            return self.build(action,budget,authorize)
        self.check_reply(self.execute_guarded(worker=self.worker(builder=build)),'changed')
        self.assertEqual(checked,[False])
        self.assertNotIn('session',self.calls)
        self.assertEqual(self.backend.writes,1)

    def test_ambiguous_writer_stays_contained_and_durable_restart_never_retries(self):
        self.backend.result=Unconfirmed('public synthetic lost SQL reply')
        self.check_reply(self.execute_guarded(),'contained')
        with self.assertRaises(Refused):self.store.admission(ACCOUNT)
        with self.assertRaises(Unavailable):self.execute_guarded()
        self.assertEqual(self.backend.writes,1)
        self.assertEqual(self.record()['entries'][0]['outcome']['status'],'contained')

    def test_exact_deadline_future_sender_and_unconfirmed_group_refuse_before_claim(self):
        for millis in [999999,1001000]:
            with self.assertRaises(Unavailable):self.execute_guarded(sample=lambda:millis)
        with patch('operation_budget.OperationBudget.attach_owned_process_group',side_effect=Refused('public group refusal')):
            with self.assertRaises(Unavailable):
                self.worker().execute_guarded(guarded(),clock_millis=lambda:1000000)
        self.assertEqual((self.builders,self.backend.writes),(0,0))
        self.assertEqual(self.record()['entries'],[])

    def test_public_native_entry_stays_disabled_before_peer_or_key_use(self):
        with self.assertRaises(Unavailable):self.worker().guarded_connection(None,os.getuid())
        self.assertEqual(self.builders,0)

    def test_actual_private_peer_guarded_frame_eof_contract_rejects_trailing_before_dispatch(self):
        left,right=socket.socketpair()
        try:
            raw=guarded();right.sendall(len(raw).to_bytes(4,'big')+raw+b'X')
            right.shutdown(socket.SHUT_WR)
            with self.assertRaises(Unavailable):self.worker()._connection(left,os.getuid(),guarded_session=True)
            self.assertEqual((self.builders,self.backend.writes),(0,0))
        finally:left.close();right.close()

    def test_actual_private_peer_wrong_uid_refuses_before_frame_read_or_journal(self):
        left,right=socket.socketpair()
        try:
            with self.assertRaises(Unavailable):self.worker()._connection(left,os.getuid()+1,guarded_session=True)
            self.assertEqual((self.builders,self.backend.writes),(0,0))
        finally:left.close();right.close()

    def test_guarded_connection_routes_exact_proof_to_one_bounded_reply(self):
        left,right=socket.socketpair();errors=[]
        worker=self.worker()
        # Pin only synthetic clocks/group ownership. This actual socket fixture
        # does not qualify native groups, operator peers or current issuer life.
        original=worker.execute_guarded
        def execute(raw):
            with patch('operation_budget.OperationBudget.attach_owned_process_group'):
                return original(raw,clock_millis=lambda:1000000)
        worker.execute_guarded=execute
        def server():
            try:worker._connection(left,os.getuid(),guarded_session=True)
            except BaseException as error:errors.append(error)
            finally:left.close()
        thread=threading.Thread(target=server);thread.start()
        try:
            right.settimeout(1);raw=guarded();right.sendall(len(raw).to_bytes(4,'big')+raw);right.shutdown(socket.SHUT_WR)
            prefix=right.recv(4);self.assertEqual(len(prefix),4);size=int.from_bytes(prefix,'big');self.assertLessEqual(size,4096)
            reply=bytearray()
            while len(reply)<size:reply.extend(right.recv(size-len(reply)))
            self.check_reply(bytes(reply),'changed');self.assertEqual(right.recv(1),b'')
        finally:right.close();thread.join(timeout=1)
        self.assertFalse(thread.is_alive());self.assertEqual(errors,[]);self.assertEqual(self.backend.writes,1)


if __name__ == '__main__':
    unittest.main()
