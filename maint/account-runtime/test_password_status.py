"""Changed-boundary source tests only; no native/provider qualification."""
import json
import os
import pathlib
import tempfile
import unittest

from account_epoch import EpochStore, PasswordCoordinator
from account_admission_worker import execute, SCHEMA
from authoritative_password import AuthoritativePasswordAdapter as Adapter, Receipt, Refused, Unconfirmed
import test_authoritative_password as sql_fixture
import test_account_epoch as epoch_fixture
import test_account_mutation_worker as worker_fixture

ACCOUNT = 'alice@example.test'
STAMP = '20261004170001'


class PasswordStatusTests(unittest.TestCase):
    def fixture(self, backend=None):
        temp = tempfile.TemporaryDirectory()
        self.addCleanup(temp.cleanup)
        root = pathlib.Path(temp.name)
        root.chmod(0o700)
        store = EpochStore(root, os.getuid())
        store.provision(ACCOUNT)
        backend = backend or epoch_fixture.Backend()
        coordinator = PasswordCoordinator(store, backend, lambda *a: True,
            lambda *a: True, lambda *a: True, lambda *a: True,
            invalidate_changed_auth=lambda *a: True)
        return store, backend, coordinator

    def change(self, coordinator, epoch=0):
        return coordinator.change(ACCOUNT, epoch, 'a'*64, 'old',
            sql_fixture.PASSPHRASE, sql_fixture.PASSPHRASE, 'public', 1000)

    def record(self, store):
        with store.locked(ACCOUNT) as path:
            return store._read(path)

    def test_exact_update_time_reaches_reopened_active_summary_without_mailbox_inference(self):
        executor = sql_fixture.Executor()
        adapter = Adapter(executor)
        store, _, coordinator = self.fixture(adapter)
        # Merely reading generic mailbox.modified cannot populate status.
        executor.responses = [executor.row()]
        adapter.read(ACCOUNT)
        self.assertNotIn('changed_at', execute(dict(schema=SCHEMA,
            operation='admit', account=ACCOUNT, epoch=0), store, lambda *a: True))
        executor.responses = [executor.row(),
            (0, (sql_fixture.NEW+'\n').encode(), b''), executor.receipt()]
        self.assertEqual(self.change(coordinator), (1, STAMP))
        reopened = EpochStore(store.root, os.getuid())
        result = execute(dict(schema=SCHEMA, operation='admit',
            account=ACCOUNT, epoch=1), reopened, lambda *a: True)
        self.assertEqual(result['changed_at'], STAMP)
        self.assertEqual(sum(b'UPDATE mailbox' in call[2] for call in executor.calls), 1)
        with self.assertRaises(Refused):
            execute(dict(schema=SCHEMA, operation='admit', account=ACCOUNT, epoch=0),
                reopened, lambda *a: True)
        store.provision('bob@example.test')
        bob = execute(dict(schema=SCHEMA, operation='admit',
            account='bob@example.test', epoch=0), reopened, lambda *a: True)
        self.assertNotIn('changed_at', bob)

    def test_known_no_write_preserves_prior_time_and_epoch(self):
        store, backend, coordinator = self.fixture()
        with store.locked(ACCOUNT) as path:
            store._write(path, dict(store._read(path), epoch=1, changed_at=STAMP))
        backend.result = Refused('public zero-row refusal')
        with self.assertRaises(Refused):
            self.change(coordinator, 1)
        self.assertEqual(store.admission(ACCOUNT), (1, STAMP))
        self.assertEqual(backend.writes, 1)

    def test_unknown_new_write_does_not_relabel_prior_time_and_stays_contained(self):
        store, backend, coordinator = self.fixture()
        with store.locked(ACCOUNT) as path:
            store._write(path, dict(store._read(path), epoch=1, changed_at=STAMP))
        backend.result = Unconfirmed('public ambiguous dispatch')
        with self.assertRaises(Unconfirmed) as failure:
            self.change(coordinator, 1)
        self.assertIsNone(failure.exception.changed_at)
        self.assertEqual((self.record(store)['state'], self.record(store)['changed_at']),
            ('contained', None))
        with self.assertRaises(Refused):
            store.admission(ACCOUNT)

    def test_missing_new_time_cannot_become_success(self):
        for stamp in [None, 'invalid', '20260230010203']:
            store, backend, coordinator = self.fixture()
            backend.result = Receipt(stamp)
            with self.assertRaises(Unconfirmed):
                self.change(coordinator)
            self.assertEqual((self.record(store)['state'], self.record(store)['changed_at']),
                ('contained', None))
            self.assertEqual(backend.writes, 1)

    def worker(self):
        fixture = worker_fixture.WorkerTests()
        fixture.setUp()
        self.addCleanup(fixture.tearDown)
        return fixture

    def test_verified_write_incomplete_effects_keep_durable_time_and_authenticated_terminal(self):
        f = self.worker()
        def build(*args):
            coordinator = f.build(*args)
            coordinator.finish_containment = lambda *a: False
            return coordinator
        reply = f.check_reply(f.worker(builder=build).execute(worker_fixture.frame()),
            'changed_incomplete')
        self.assertEqual(reply['outcome']['changed_at'], '20261004170000')
        reopened = EpochStore(f.epoch_root, os.getuid())
        with reopened.locked(ACCOUNT) as path:
            record = reopened._read(path)
        self.assertEqual((record['state'], record['epoch'], record['changed_at']),
            ('contained', 0, '20261004170000'))
        for operation in [dict(operation='admit', epoch=0),
                          dict(operation='authenticate', password='public')]:
            with self.assertRaises(Refused):
                execute(dict(schema=SCHEMA, account=ACCOUNT, **operation), reopened,
                    lambda *a: self.fail('contained record reached authentication'))
        with self.assertRaises(worker_fixture.Unavailable):
            f.worker(builder=build).execute(worker_fixture.frame())
        self.assertEqual(f.backend.writes, 1)

    def test_postwrite_original_deadline_failure_preserves_time_without_reply_or_retry(self):
        f = self.worker()
        replace = f.backend.replace
        def delayed(*args):
            result = replace(*args)
            f.mono += 61
            return result
        f.backend.replace = delayed
        with self.assertRaises(worker_fixture.Unavailable):
            f.worker().execute(worker_fixture.frame())
        with f.store.locked(ACCOUNT) as path:
            record = f.store._read(path)
        self.assertEqual((record['state'], record['changed_at']),
            ('contained', '20261004170000'))
        self.assertEqual(f.record()['entries'][0]['outcome']['status'], 'changed_incomplete')
        self.assertNotIn('flush', f.calls)
        self.assertEqual(f.backend.writes, 1)


if __name__ == '__main__':
    unittest.main()
