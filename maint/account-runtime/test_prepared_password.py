import dataclasses
import os
import pathlib
import tempfile
import unittest

from account_epoch import EpochStore, MAX_EPOCH
from authoritative_password import AuthoritativePasswordAdapter as Adapter, Receipt, Refused, Unconfirmed
from prepared_password import PreparedAction, PreparedPasswordCoordinator

ACCOUNT = 'alice@example.test'
NEW = 'long synthetic password'


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


class PreparedTests(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.root = pathlib.Path(self.tmp.name)
        self.store = EpochStore(self.root, os.getuid())
        self.store.provision(ACCOUNT)
        self.backend = Backend()
        self.now = 1000
        self.action = PreparedAction(ACCOUNT, 0, 'a' * 64, 'session-fixture',
                                     'request-fixture', '192.0.2.1', 900, 1200,
                                     'old', NEW, NEW)
        self.authorized = True
        self.primary = True
        self.finished = True
        self.calls = []

        def authorize(action, now):
            self.calls.append(('authorize', action, now))
            return self.authorized and action == self.action

        def primary(account, password):
            self.calls.append(('primary', account))
            return self.primary and account == ACCOUNT and password == 'old'

        self.coordinator = PreparedPasswordCoordinator(
            self.store, self.backend, authorize, primary,
            lambda *args: True, lambda *args: True,
            lambda *args: self.finished, lambda: self.now,
            invalidate_changed_auth=lambda *args: True)

    def tearDown(self):
        self.tmp.cleanup()

    def test_consumed_factor_action_rechecks_primary_without_second_totp(self):
        self.assertEqual(self.coordinator.change(self.action), (1, '20261004170000'))
        self.assertEqual([entry[0] for entry in self.calls], ['authorize', 'primary'])
        self.assertEqual(self.backend.writes, 1)
        self.assertFalse(hasattr(self.action, 'totp'))
        self.assertNotIn('old', repr(self.action))
        with self.assertRaises(dataclasses.FrozenInstanceError):
            self.action.epoch = 1

    def test_exact_binding_tamper_refused_before_write(self):
        for field, value in [('session_id', 'other'), ('request_id', 'other'),
                             ('source', '192.0.2.2'), ('intent_reference', 'b' * 64),
                             ('new', 'another synthetic password'), ('current', 'other')]:
            with self.assertRaises(Refused):
                self.coordinator.change(dataclasses.replace(self.action, **{field: value}))
            self.assertEqual(self.backend.writes, 0)
        self.assertEqual(self.store.admission(ACCOUNT), (0, None))

    def test_expiry_boundary_and_clock_rollback_refuse_before_callbacks(self):
        for self.now in [899, 1200, 1201, True]:
            with self.assertRaises(Refused):
                self.coordinator.change(self.action)
        self.assertEqual(self.calls, [])
        self.assertEqual(self.backend.reads, 0)

    def test_expiry_during_primary_or_snapshot_never_enters_pending(self):
        for callback in ['primary', 'read']:
            before = next(self.root.glob('*.json')).read_bytes()
            if callback == 'primary':
                def delay(*args):
                    self.now = 1200
                    return True
                self.coordinator.verify_current = delay
            else:
                self.coordinator.verify_current = lambda *args: True
                def delay(*args):
                    self.now = 1200
                    return object()
                self.backend.read = delay
            self.now = 1000
            with self.assertRaises(Refused):
                self.coordinator.change(self.action)
            self.assertEqual(self.backend.writes, 0)
            self.assertEqual(next(self.root.glob('*.json')).read_bytes(), before)

    def test_missing_authority_or_changed_current_refuses_without_write(self):
        self.authorized = False
        with self.assertRaises(Refused):
            self.coordinator.change(self.action)
        self.authorized = True
        self.primary = False
        with self.assertRaises(Refused):
            self.coordinator.change(self.action)
        self.assertEqual(self.backend.writes, 0)

    def test_epoch_terminal_and_stale_never_call_authority(self):
        with self.assertRaises(Refused):
            self.coordinator.change(dataclasses.replace(self.action, epoch=1))
        with self.store.locked(ACCOUNT) as path:
            value = self.store._read(path)
            self.store._write(path, dict(value, epoch=MAX_EPOCH))
        with self.assertRaises(Refused):
            self.coordinator.change(dataclasses.replace(self.action, epoch=MAX_EPOCH))
        self.assertEqual(self.calls, [])

    def test_known_no_write_consumes_intent_and_survives_restart(self):
        self.backend.result = Refused('fixture zero-row CAS')
        with self.assertRaises(Refused):
            self.coordinator.change(self.action)
        self.coordinator.store = EpochStore(self.root, os.getuid())
        with self.assertRaises(Refused):
            self.coordinator.change(self.action)
        self.assertEqual(self.backend.writes, 1)
        self.assertEqual(self.store.admission(ACCOUNT), (0, None))

    def test_ambiguous_or_incomplete_containment_does_not_report_success(self):
        self.finished = False
        with self.assertRaises(Unconfirmed):
            self.coordinator.change(self.action)
        with self.assertRaises(Refused):
            EpochStore(self.root, os.getuid()).admission(ACCOUNT)
        with self.assertRaises(Refused):
            self.coordinator.change(self.action)
        self.assertEqual(self.backend.writes, 1)

    def test_ambiguous_writer_stays_contained_and_is_never_replayed(self):
        self.backend.result = Unconfirmed('fixture response lost after dispatch')
        with self.assertRaises(Unconfirmed):
            self.coordinator.change(self.action)
        self.coordinator.store = EpochStore(self.root, os.getuid())
        with self.assertRaises(Refused):
            self.coordinator.change(self.action)
        self.assertEqual(self.backend.writes, 1)

    def test_authority_callback_delay_cannot_extend_or_reset_original_window(self):
        def delay(*args):
            self.now = 1200
            return True
        self.coordinator.authorize_action = delay
        with self.assertRaises(Refused):
            self.coordinator.change(self.action)
        self.assertEqual(self.backend.writes, 0)
        self.assertEqual(self.store.admission(ACCOUNT), (0, None))

    def test_invalid_preparation_shape_or_truthy_callback_never_dispatches(self):
        for change in [dict(epoch=True), dict(issued=True), dict(expires=1201),
                       dict(session_id=''), dict(request_id='x' * 257),
                       dict(source='x\n'), dict(source='\ud800'),
                       dict(intent_reference='A' * 64)]:
            with self.assertRaises(Refused):
                self.coordinator.change(dataclasses.replace(self.action, **change))
        self.coordinator.authorize_action = lambda *args: 'yes'
        with self.assertRaises(Refused):
            self.coordinator.change(self.action)
        self.assertEqual(self.backend.writes, 0)

    def test_persisted_state_has_no_credentials_session_or_source(self):
        self.coordinator.change(self.action)
        data = b''.join(path.read_bytes() for path in self.root.iterdir())
        for secret in ['old', NEW, 'session-fixture', 'request-fixture', '192.0.2.1', ACCOUNT]:
            self.assertNotIn(secret.encode(), data)

    def test_truthy_containment_or_verification_status_is_not_success(self):
        self.coordinator.containment_ready = lambda *args: 'unavailable'
        with self.assertRaises(Refused):
            self.coordinator.change(self.action)
        self.assertEqual(self.backend.writes, 0)
        self.coordinator.containment_ready = lambda *args: True
        self.coordinator.verify_changed = lambda *args: 'unavailable'
        with self.assertRaises(Unconfirmed):
            self.coordinator.change(self.action)
        self.assertEqual(self.backend.writes, 1)
        with self.assertRaises(Refused):
            self.store.admission(ACCOUNT)

    def test_truthy_finish_is_not_containment_proof(self):
        self.coordinator.finish_containment = lambda *args: 'pending'
        with self.assertRaises(Unconfirmed):
            self.coordinator.change(self.action)
        with self.assertRaises(Refused):
            self.store.admission(ACCOUNT)

    def test_current_password_bounds_match_prepared_rust_request(self):
        for current in ['', 'a' * 1025, '\u00e9' * 513, 'old\n', 'old\u0085']:
            self.calls = []
            with self.assertRaises(Refused):
                self.coordinator.change(dataclasses.replace(self.action, current=current))
            self.assertEqual(self.calls, [])
            self.assertEqual(self.backend.writes, 0)


if __name__ == '__main__':
    unittest.main()
