import hashlib
import hmac
import json
import os
import pathlib
import socket
import tempfile
import threading
import unittest
from unittest.mock import patch

from account_epoch import EpochStore, MAX_EPOCH
from account_mutation_codec import ACTION, SCHEMA, Invalid, encoded, verify_request, valid_outcome
from account_mutation_worker import IntentStore, MutationWorker, Unavailable
from authoritative_password import AuthoritativePasswordAdapter as Adapter, Receipt, Refused, Unconfirmed
from prepared_password import PreparedPasswordCoordinator

ACCOUNT = 'alice@example.test'
KEY = bytes([17]) * 32
CURRENT = 'old public synthetic credential'
NEW = 'new public synthetic credential'


def frame(**changes):
    value = dict(schema=SCHEMA, action=ACTION, account=ACCOUNT, epoch=0,
                 intent_reference='a' * 64, session_id='b' * 64,
                 request_id='public-request', source='127.0.0.1', issued=1000,
                 expires=1300, current=CURRENT, new=NEW, confirmation=NEW)
    value.update(changes)
    payload = [value[k] for k in ('schema', 'action')]
    payload += ['request']
    payload += [value[k] for k in ('account', 'epoch', 'intent_reference', 'session_id',
                                 'request_id', 'source', 'issued', 'expires',
                                 'current', 'new', 'confirmation')]
    value['signature'] = hmac.new(KEY, encoded(payload), hashlib.sha256).hexdigest()
    return encoded(value)


class Backend:
    _account = staticmethod(Adapter._account)
    validate_new = staticmethod(Adapter.validate_new)

    def __init__(self):
        self.writes = 0
        self.reads = 0
        self.result = Receipt('20261004170000')

    def read(self, account):
        self.reads += 1
        return object()

    def replace(self, *args):
        self.writes += 1
        if isinstance(self.result, BaseException):
            raise self.result
        return self.result


class WorkerTests(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.root = pathlib.Path(self.tmp.name)
        self.epoch_root = self.root / 'epochs'
        self.intent_root = self.root / 'intents'
        self.epoch_root.mkdir(mode=0o700)
        self.intent_root.mkdir(mode=0o700)
        self.store = EpochStore(self.epoch_root, os.getuid())
        self.store.provision(ACCOUNT)
        self.journal = IntentStore(self.intent_root, os.getuid())
        self.journal.provision(ACCOUNT)
        self.backend = Backend()
        self.now = 1000
        self.mono = 10.0
        self.clock = lambda: self.now
        self.monotonic = lambda: self.mono
        self.session = True
        self.primary = True
        self.builders = 0
        self.calls = []

    def tearDown(self):
        self.tmp.cleanup()

    def build(self, action, budget, authorize):
        self.builders += 1
        self.calls.append('build')
        return PreparedPasswordCoordinator(
            self.store, self.backend, authorize,
            lambda *args: self.calls.append('primary') or self.primary,
            lambda *args: self.calls.append('new-auth') or True,
            lambda *args: self.calls.append('preflight') or True,
            lambda *args: self.calls.append('finish') or True,
            self.clock, invalidate_changed_auth=lambda *args: self.calls.append('flush') or True)

    def worker(self, builder=None, journal=None):
        return MutationWorker(KEY, frozenset([ACCOUNT]), journal or self.journal,
                              self.store, builder or self.build,
                              lambda *args: self.calls.append('session') or self.session,
                              self.clock, self.monotonic)

    def record(self):
        return json.loads(next(self.intent_root.glob('*.json')).read_bytes())

    def check_reply(self, raw, status):
        reply = json.loads(raw)
        self.assertEqual(reply['outcome']['status'], status)
        payload = [SCHEMA, ACTION, 'response', reply['account'], reply['intent_reference'],
                   reply['request_id'], reply['request_signature'], reply['responded_at'],
                   reply['outcome']]
        self.assertEqual(reply['signature'], hmac.new(KEY, encoded(payload), hashlib.sha256).hexdigest())
        return reply

    def test_malformed_postsuccess_receipt_is_never_known_refused(self):
        self.backend.result = Receipt('invalid-public-stamp')
        with self.assertRaises(Unavailable):
            self.worker().execute(frame())
        self.assertEqual(self.backend.writes, 1)
        self.assertEqual(self.record()['entries'][0]['state'], 'pending')
        with self.assertRaises(Unavailable):
            self.worker().execute(frame())
        self.assertEqual(self.backend.writes, 1)

    def test_changed_response_binds_exact_request_and_preserves_original_deadline(self):
        reply = self.check_reply(self.worker().execute(frame()), 'changed')
        self.assertEqual(reply['outcome'], dict(status='changed', epoch=1, changed_at='20261004170000'))
        self.assertEqual(self.store.admission(ACCOUNT), (1, '20261004170000'))
        self.assertEqual(self.calls, ['build', 'preflight', 'session', 'primary', 'flush', 'new-auth', 'finish'])
        self.assertEqual(self.backend.writes, 1)
        entry = self.record()['entries'][0]
        self.assertEqual((entry['issued'], entry['expires'], entry['state']), (1000, 1300, 'complete'))
        self.assertEqual(reply['request_signature'], json.loads(frame())['signature'])

    def test_restart_replay_retarged_intent_and_consumed_no_write_refuse_dispatch(self):
        self.primary = False
        self.check_reply(self.worker().execute(frame()), 'known_refused')
        self.primary = True
        journal = IntentStore(self.intent_root, os.getuid())
        for raw in [frame(), frame(request_id='other-public-request'), frame(epoch=1)]:
            with self.assertRaises(Unavailable):
                self.worker(journal=journal).execute(raw)
        self.assertEqual((self.backend.writes, self.builders), (0, 1))
        self.assertEqual(self.store.admission(ACCOUNT), (0, None))

    def test_authenticated_wire_tamper_unknown_duplicate_and_bad_shapes_refuse_before_claim(self):
        initial = next(self.intent_root.glob('*.json')).read_bytes()
        cases = []
        for field, value in [('current', 'different public'), ('new', NEW + 'x'),
                             ('action', 'delete_user'), ('signature', '0' * 64)]:
            changed = json.loads(frame())
            changed[field] = value
            cases.append(encoded(changed))
        for extra in ['totp_verified', 'admin', 'path', 'fresh']:
            changed = json.loads(frame())
            changed[extra] = True
            cases.append(encoded(changed))
        cases += [b'{"schema":"x","schema":"y"}', b'[]', b'x' * 4097,
                  b'{"epoch":NaN}', b'\xff']
        for changes in [dict(epoch=True), dict(epoch=MAX_EPOCH), dict(issued=True),
                        dict(expires=1301), dict(session_id='c'), dict(request_id=' '),
                        dict(source='*'), dict(current=''), dict(current='x' * 1025),
                        dict(new='short', confirmation='short'), dict(current='bad\n'),
                        dict(account='bob@example.test')]:
            cases.append(frame(**changes))
        for raw in cases:
            with self.subTest(size=len(raw)), self.assertRaises(Unavailable):
                self.worker().execute(raw)
        self.assertEqual(self.calls, [])
        self.assertEqual(next(self.intent_root.glob('*.json')).read_bytes(), initial)

    def test_exact_expiry_and_clock_before_issue_refuse_without_dispatch(self):
        for self.now in [999, 1300, 1301, True]:
            with self.assertRaises(Unavailable):
                self.worker().execute(frame())
        self.assertEqual(self.calls, [])

    def test_scoped_ipv6_disallowed_by_rust_ipaddr_is_not_admitted(self):
        with self.assertRaises(Unavailable):
            self.worker().execute(frame(source='fe80::1%eth0'))
        self.assertEqual(self.calls, [])
        self.assertEqual(self.backend.writes, 0)

    def test_non_utf8_json_cannot_expand_rust_wire_encoding(self):
        for raw in [frame().decode().encode('utf-16'), b'\xef\xbb\xbf' + frame()]:
            with self.assertRaises(Unavailable):
                self.worker().execute(raw)
        self.assertEqual(self.calls, [])

    def test_current_session_false_or_truthy_does_not_authorize_primary_or_sql(self):
        for count, self.session in enumerate([False, 'yes']):
            self.check_reply(self.worker().execute(frame(intent_reference=f'{count:064x}')), 'known_refused')
        self.assertNotIn('primary', self.calls)
        self.assertEqual(self.backend.writes, 0)

    def test_ambiguous_sql_is_contained_and_never_replayed_across_restart(self):
        self.backend.result = Unconfirmed('public lost reply')
        self.check_reply(self.worker().execute(frame()), 'contained')
        with self.assertRaises(Refused):
            self.store.admission(ACCOUNT)
        with self.assertRaises(Unavailable):
            self.worker(journal=IntentStore(self.intent_root, os.getuid())).execute(frame())
        self.check_reply(self.worker().execute(frame(intent_reference='c' * 64)), 'known_refused')
        self.assertEqual(self.backend.writes, 1)

    def test_interrupted_pending_intent_blocks_new_request_even_after_original_expiry(self):
        def interrupted(*args):
            raise SystemExit('public interruption')
        with self.assertRaises(SystemExit):
            self.worker(builder=interrupted).execute(frame())
        self.assertEqual(self.record()['entries'][0]['state'], 'pending')
        self.now = 1400
        with self.assertRaises(Unavailable):
            self.worker(journal=IntentStore(self.intent_root, os.getuid())).execute(
                frame(intent_reference='c' * 64, issued=1400, expires=1700))
        self.assertEqual(self.builders, 0)
        self.assertEqual(self.backend.writes, 0)

    def test_foreign_builder_or_exception_cannot_manufacture_known_refused(self):
        with self.assertRaises(Unavailable):
            self.worker(builder=lambda *args: object()).execute(frame())
        self.assertEqual(self.record()['entries'][0]['state'], 'pending')
        self.assertEqual(self.backend.writes, 0)

    def test_reply_expiry_after_write_retains_outcome_and_no_retry(self):
        def build(*args):
            coordinator = self.build(*args)
            def delay(*values):
                self.now = 1300
                return True
            coordinator.finish_containment = delay
            return coordinator
        with self.assertRaises(Unavailable):
            self.worker(builder=build).execute(frame())
        self.assertEqual(self.backend.writes, 1)
        self.assertEqual(self.record()['entries'][0]['outcome']['status'], 'contained')
        with self.assertRaises(Refused):
            self.store.admission(ACCOUNT)
        self.now = 1299
        with self.assertRaises(Unavailable):
            self.worker().execute(frame())
        self.assertEqual(self.backend.writes, 1)

    def test_monotonic_budget_exhausted_by_primary_refuses_before_sql(self):
        def build(*args):
            coordinator = self.build(*args)
            def delay(*values):
                self.mono += 61
                return True
            coordinator.verify_current = delay
            return coordinator
        with self.assertRaises(Unavailable):
            self.worker(builder=build).execute(frame())
        self.assertEqual(self.backend.reads, 0)
        self.assertEqual(self.backend.writes, 0)
        self.assertEqual(self.store.admission(ACCOUNT), (0, None))

    def test_failed_final_publication_preserves_pending_no_automatic_retry(self):
        original = self.journal._publish
        def fail_complete(path, value):
            if value['entries'] and value['entries'][-1]['state'] == 'complete':
                raise OSError('public durability failure')
            return original(path, value)
        with patch.object(self.journal, '_publish', fail_complete):
            with self.assertRaises(Unavailable):
                self.worker().execute(frame())
        self.assertEqual(self.record()['entries'][0]['state'], 'pending')
        with self.assertRaises(Unavailable):
            self.worker().execute(frame())
        self.assertEqual(self.backend.writes, 1)

    def test_monotonic_deadline_crossed_after_sql_stays_contained_not_known_refused(self):
        replace = self.backend.replace
        def delayed(*args):
            result = replace(*args)
            self.mono += 61
            return result
        self.backend.replace = delayed
        with self.assertRaises(Unavailable):
            self.worker().execute(frame())
        self.assertEqual(self.backend.writes, 1)
        self.assertEqual(self.record()['entries'][0]['outcome']['status'], 'contained')
        with self.assertRaises(Refused):
            self.store.admission(ACCOUNT)
        self.assertNotIn('flush', self.calls)

    def test_confirmed_zero_row_adapter_refusal_is_known_and_consumed_once(self):
        self.backend.result = Refused('public confirmed zero-row update')
        self.check_reply(self.worker().execute(frame()), 'known_refused')
        self.assertEqual(self.store.admission(ACCOUNT), (0, None))
        with self.assertRaises(Unavailable):
            self.worker().execute(frame())
        self.assertEqual(self.backend.writes, 1)

    def test_different_owner_or_authorizer_coordinator_is_never_dispatched(self):
        def foreign(*args):
            coordinator = self.build(*args)
            coordinator.authorize_action = lambda *values: True
            return coordinator
        with self.assertRaises(Unavailable):
            self.worker(builder=foreign).execute(frame())
        self.assertEqual(self.backend.reads, 0)
        self.assertEqual(self.backend.writes, 0)
        self.assertEqual(self.record()['entries'][0]['state'], 'pending')

    def test_truncated_and_oversize_private_frames_refuse_no_builder(self):
        for raw in [b'\0\0\0\0', (4097).to_bytes(4, 'big'), b'\0\0',
                    (100).to_bytes(4, 'big') + b'{}']:
            server, client = socket.socketpair()
            try:
                client.sendall(raw)
                client.shutdown(socket.SHUT_WR)
                with self.assertRaises(Unavailable):
                    self.worker()._connection(server, os.getuid())
                self.assertEqual(self.builders, 0)
            finally:
                client.close()
                server.close()

    def test_initial_unconfirmed_publication_never_constructs_coordinator(self):
        with patch.object(self.journal, '_publish', side_effect=OSError('public fsync uncertainty')):
            with self.assertRaises(Unavailable):
                self.worker().execute(frame())
        self.assertEqual(self.builders, 0)
        self.assertEqual(self.backend.writes, 0)

    def test_durable_highwater_clock_regression_refuses_new_intent(self):
        self.primary = False
        self.check_reply(self.worker().execute(frame()), 'known_refused')
        self.now = 999
        with self.assertRaises(Unavailable):
            self.worker(journal=IntentStore(self.intent_root, os.getuid())).execute(
                frame(issued=900, expires=1200, intent_reference='c' * 64))
        self.assertEqual(self.builders, 1)

    def test_private_journal_corruption_permissions_and_missing_never_reset(self):
        path = next(self.intent_root.glob('*.json'))
        original = path.read_bytes()
        for raw in [b'[]', b'{}', b'x' * 16385, b'{"version":1,"version":1}',
                    encoded(dict(version=1, high_water=True, entries=[]))]:
            path.write_bytes(raw)
            with self.assertRaises(Unavailable):
                self.worker().execute(frame())
            self.assertEqual(path.read_bytes(), raw)
        path.write_bytes(original)
        path.chmod(0o644)
        with self.assertRaises(Unavailable):
            self.worker().execute(frame())
        path.chmod(0o600)
        path.unlink()
        with self.assertRaises(Unavailable):
            self.worker().execute(frame())
        self.assertFalse(path.exists())
        self.assertEqual(self.builders, 0)

    def test_private_journal_symlink_and_hardlink_refuse(self):
        path = next(self.intent_root.glob('*.json'))
        other = self.root / 'other'
        path.rename(other)
        path.symlink_to(other)
        with self.assertRaises(Unavailable):
            self.worker().execute(frame())
        path.unlink()
        os.link(other, path)
        with self.assertRaises(Unavailable):
            self.worker().execute(frame())
        self.assertEqual(self.builders, 0)

    def test_same_account_inflight_lease_is_owned_and_second_request_bounded(self):
        entered, release = threading.Event(), threading.Event()
        results = []
        def build(*args):
            entered.set()
            self.assertTrue(release.wait(2))
            return self.build(*args)
        def first():
            results.append(self.worker(builder=build).execute(frame()))
        thread = threading.Thread(target=first)
        thread.start()
        self.assertTrue(entered.wait(2))
        with patch.object(IntentStore, 'LOCK_WAIT_SECONDS', 0.05):
            with self.assertRaises(Unavailable):
                self.worker().execute(frame(intent_reference='c' * 64))
        self.assertEqual(self.backend.writes, 0)
        release.set()
        thread.join(2)
        self.assertFalse(thread.is_alive())
        self.check_reply(results[0], 'changed')
        self.assertEqual(self.backend.writes, 1)

    def test_maximum_journal_capacity_preserves_records_and_refuses_new_admission(self):
        self.primary = False
        for i in range(32):
            self.check_reply(self.worker().execute(frame(intent_reference=f'{i:064x}')), 'known_refused')
        before = next(self.intent_root.glob('*.json')).read_bytes()
        with self.assertRaises(Unavailable):
            self.worker().execute(frame(intent_reference='c' * 64))
        self.assertEqual(next(self.intent_root.glob('*.json')).read_bytes(), before)
        self.assertEqual(self.backend.writes, 0)

    def test_journal_contains_no_private_inputs_and_repr_is_redacted(self):
        self.worker().execute(frame())
        data = b''.join(p.read_bytes() for p in self.root.rglob('*') if p.is_file())
        for value in [ACCOUNT, CURRENT, NEW, 'public-request', '127.0.0.1', 'b' * 64]:
            self.assertNotIn(value.encode(), data)
        request = verify_request(frame(), KEY, self.now)
        self.assertNotIn(CURRENT, repr(request))
        self.assertNotIn(NEW, repr(request.action))

    def test_native_activation_false_and_actual_private_peer_mismatch_before_read(self):
        server, client = socket.socketpair()
        try:
            with self.assertRaises(Unavailable):
                self.worker().connection(server, os.getuid())
            with self.assertRaises(Unavailable):
                self.worker()._connection(server, os.getuid() + 1)
            self.assertEqual(self.builders, 0)
        finally:
            server.close()
            client.close()

    def test_actual_local_private_peer_frame_and_response(self):
        server, client = socket.socketpair()
        errors = []
        def serve():
            try:
                self.worker()._connection(server, os.getuid())
            except BaseException as error:
                errors.append(type(error).__name__)
        thread = threading.Thread(target=serve)
        thread.start()
        try:
            client.settimeout(2)
            raw = frame()
            client.sendall(len(raw).to_bytes(4, 'big') + raw)
            size = int.from_bytes(client.recv(4), 'big')
            reply = b''
            while len(reply) < size:
                reply += client.recv(size - len(reply))
            self.check_reply(reply, 'changed')
        finally:
            thread.join(2)
            server.close()
            client.close()
        self.assertEqual(errors, [])
        self.assertFalse(thread.is_alive())

    def test_outcome_type_and_unit_extra_fields_are_strict(self):
        for value in [dict(status='known_refused', epoch=1), dict(status='contained', x=1),
                      dict(status='changed', epoch=True, changed_at='20261004170000'),
                      dict(status='changed', epoch=2, changed_at='20261004170000'),
                      dict(status='changed', epoch=1, changed_at='20261304170000')]:
            with self.assertRaises(Invalid):
                valid_outcome(value, 0)


if __name__ == '__main__':
    unittest.main()
