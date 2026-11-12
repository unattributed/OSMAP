"""Owned-file source tests; no native authentication or listener is invoked."""
import importlib.util
import json
import threading
import os
from pathlib import Path
import tempfile
import unittest

from account_epoch import EpochStore

ALICE = 'alice@fixture.invalid'
BOB = 'bob@fixture.invalid'


class EpochPolicyTests(unittest.TestCase):
    def setUp(self):
        self.scratch = tempfile.TemporaryDirectory(prefix='osmap-policy-epoch-')
        self.addCleanup(self.scratch.cleanup)
        self.root = Path(self.scratch.name)
        self.root.chmod(0o700)
        self.store = EpochStore(self.root, expected_uid=os.getuid())
        self.store.provision(ALICE)
        self.store.provision(BOB)
        self.now = 10.0

    def fence(self):
        spec = importlib.util.find_spec('dovecot_auth_epoch')
        self.assertIsNotNone(spec, 'before/after epoch policy processor is absent')
        import dovecot_auth_epoch
        return dovecot_auth_epoch.EpochPolicyFence(
            self.store, frozenset((ALICE, BOB)), clock=lambda: self.now)

    def body(self, phase, *, account=ALICE, protocol='imap', session='PublicSession001', tls=True):
        return json.dumps(dict(login=account, protocol=protocol,
                               session_id=session, phase=phase, tls=tls)).encode()

    def change_epoch(self, epoch=1, state='active'):
        with self.store.locked(ALICE) as path:
            value = self.store._read(path)
            value.update(epoch=epoch, state=state,
                         intent=None if state == 'active' else 'a' * 64)
            self.store._write(path, value)

    def test_epoch_change_between_before_and_after_is_refused(self):
        fence = self.fence()
        self.assertEqual(fence.allow(self.body('before')), b'{"status":0}')
        self.change_epoch()
        self.assertEqual(fence.allow(self.body('after')), b'{"status":-1}')


    def test_success_binds_same_account_protocol_session_and_preserves_records(self):
        fence = self.fence()
        before = {p.name: p.read_bytes() for p in self.root.glob('*.json')}
        self.assertEqual(fence.allow(self.body('before')), fence.ALLOW)
        self.assertEqual(fence.allow(self.body('after')), fence.ALLOW)
        self.assertEqual(before, {p.name: p.read_bytes() for p in self.root.glob('*.json')})

    def test_pending_before_and_contained_after_deny_without_reopening(self):
        self.change_epoch(state='pending')
        fence = self.fence()
        self.assertEqual(fence.allow(self.body('before')), fence.DENY)
        self.change_epoch(state='active')
        self.assertEqual(fence.allow(self.body('after')), fence.DENY)
        self.assertEqual(fence.allow(self.body('before', session='SecondPublic001')), fence.ALLOW)
        self.change_epoch(state='contained')
        self.assertEqual(fence.allow(self.body('after', session='SecondPublic001')), fence.DENY)
        self.assertEqual(self.store._read(self.store._paths(ALICE)[1])['state'], 'contained')

    def test_duplicate_before_never_refreshes_captured_epoch(self):
        fence = self.fence()
        self.assertEqual(fence.allow(self.body('before')), fence.ALLOW)
        self.change_epoch()
        self.assertEqual(fence.allow(self.body('before')), fence.DENY)
        self.assertEqual(fence.allow(self.body('after')), fence.DENY)

    def test_after_consumes_once_even_after_durable_refusal(self):
        fence = self.fence()
        self.assertEqual(fence.allow(self.body('before')), fence.ALLOW)
        self.assertEqual(fence.allow(self.body('after')), fence.ALLOW)
        self.assertEqual(fence.allow(self.body('after')), fence.DENY)
        self.assertEqual(fence.allow(self.body('before')), fence.DENY)

    def test_out_of_order_and_restart_do_not_reconstruct_capture(self):
        fence = self.fence()
        self.assertEqual(fence.allow(self.body('after')), fence.DENY)
        self.assertEqual(fence.allow(self.body('before')), fence.ALLOW)
        self.assertEqual(self.fence().allow(self.body('after')), fence.DENY)

    def test_identity_changes_and_tls_changes_do_not_match_original_capture(self):
        fence = self.fence()
        self.assertEqual(fence.allow(self.body('before')), fence.ALLOW)
        for fields in (dict(account=BOB), dict(protocol='pop3'),
                       dict(session='OtherPublic001'), dict(tls=False)):
            with self.subTest(fields=fields):
                self.assertEqual(fence.allow(self.body('after', **fields)), fence.DENY)
        self.assertEqual(fence.allow(self.body('after')), fence.ALLOW)

    def test_foreign_unsupported_partial_duplicate_and_credential_fields_deny(self):
        fence = self.fence()
        baseline = {p.name: p.read_bytes() for p in self.root.glob('*.json')}
        valid = json.loads(self.body('before'))
        invalid = [self.body('before', account='foreign@fixture.invalid'),
                   self.body('before', protocol='doveadm'),
                   self.body('', session='Public001'), self.body('after-auth'),
                   self.body('before', tls=1), self.body('before', session='bad session'),
                   b'{"login":"alice@fixture.invalid","login":"bob@fixture.invalid"}',
                   b'[]', b'null', b'\xff', b' ' * 4097]
        for field in ('password', 'hashed_password', 'request_id', 'master_user', 'success', 'policy_reject'):
            invalid.append(json.dumps(dict(valid, **{field: 'public'})).encode())
        for field in valid:
            missing = dict(valid); del missing[field]
            invalid.append(json.dumps(missing).encode())
        for body in invalid:
            with self.subTest(length=len(body)):
                self.assertEqual(fence.allow(body), fence.DENY)
        self.assertEqual(baseline, {p.name: p.read_bytes() for p in self.root.glob('*.json')})

    def test_reports_are_non_authorizing_and_cannot_clear_capture(self):
        fence = self.fence()
        self.assertEqual(fence.allow(self.body('before')), fence.ALLOW)
        report = dict(json.loads(self.body('after')), success=True, policy_reject=False)
        self.assertEqual(fence.allow(json.dumps(report).encode()), fence.DENY)
        self.assertEqual(fence.allow(self.body('before')), fence.DENY)
        self.assertEqual(fence.allow(self.body('after')), fence.ALLOW)

    def test_original_pair_expiry_and_new_pair_bound(self):
        fence = self.fence()
        self.assertEqual(fence.allow(self.body('before')), fence.ALLOW)
        self.now += fence.CAPTURE_SECONDS
        self.assertEqual(fence.allow(self.body('after')), fence.DENY)
        # This intentional reuse is not a transport anti-replay guarantee.
        self.assertEqual(fence.allow(self.body('before')), fence.ALLOW)
        self.assertEqual(fence.allow(self.body('after')), fence.ALLOW)

    def test_backward_and_nonfinite_clock_latch_refusal(self):
        fence = self.fence()
        self.assertEqual(fence.allow(self.body('before')), fence.ALLOW)
        self.now -= 1
        self.assertEqual(fence.allow(self.body('after')), fence.DENY)
        self.now = 100
        self.assertEqual(fence.allow(self.body('before', session='NewPublic001')), fence.DENY)
        for value in (float('nan'), float('inf'), True, -1):
            with self.subTest(value=str(value)):
                other = self.fence(); self.now = value
                self.assertEqual(other.allow(self.body('before')), other.DENY)
        self.now = 10.0

    def test_clock_exception_latches_refusal_until_restart(self):
        fence = self.fence()
        def unavailable():
            raise OSError('synthetic clock unavailable')
        fence._clock = unavailable
        self.assertEqual(fence.allow(self.body('before')), fence.DENY)
        fence._clock = lambda: self.now
        self.assertEqual(fence.allow(self.body('before')), fence.DENY)

    def test_lookup_crossing_callback_deadline_is_denied_and_not_retryable(self):
        fence = self.fence()
        original = self.store._read
        def slow(path):
            value = original(path)
            self.now += fence.CALLBACK_SECONDS
            return value
        self.store._read = slow
        self.assertEqual(fence.allow(self.body('before')), fence.DENY)
        self.store._read = original
        self.assertEqual(fence.allow(self.body('before')), fence.DENY)
        self.assertEqual(fence.allow(self.body('after')), fence.DENY)

    def test_overflowing_integer_clock_latches_new_session_refusal_without_record_changes(self):
        fence = self.fence()
        baseline = {p.name: p.read_bytes() for p in self.root.glob('*.json')}
        self.assertEqual(fence.allow(self.body('before')), fence.ALLOW)
        self.now = 10 ** 1000
        self.assertEqual(fence.allow(self.body('after')), fence.DENY)
        self.now = 100.0
        self.assertEqual(fence.allow(self.body('before', session='NewPublic001')), fence.DENY)
        self.assertEqual(fence.allow(self.body('after')), fence.DENY)
        self.assertEqual(baseline, {p.name: p.read_bytes() for p in self.root.glob('*.json')})

    def test_out_of_bound_finite_clock_latches_after_recovery(self):
        fence = self.fence()
        baseline = {p.name: p.read_bytes() for p in self.root.glob('*.json')}
        self.now = 2 ** 52
        self.assertEqual(fence.allow(self.body('before')), fence.DENY)
        self.assertIsNone(fence._last_time)
        self.now = 100.0
        self.assertEqual(fence.allow(self.body('before', session='NewPublic001')), fence.DENY)
        self.assertEqual(baseline, {p.name: p.read_bytes() for p in self.root.glob('*.json')})

    def test_largest_clock_bound_preserves_fractional_callback_deadline(self):
        fence = self.fence()
        self.now = 2 ** 52 - 1
        self.assertEqual(fence.allow(self.body('before')), fence.ALLOW)
        self.assertEqual(fence.allow(self.body('after')), fence.ALLOW)

    def test_after_deadline_crossing_consumes_original_capture(self):
        fence = self.fence()
        self.assertEqual(fence.allow(self.body('before')), fence.ALLOW)
        original = self.store._read
        def slow(path):
            value = original(path)
            self.now += fence.CALLBACK_SECONDS
            return value
        self.store._read = slow
        self.assertEqual(fence.allow(self.body('after')), fence.DENY)
        self.store._read = original
        self.assertEqual(fence.allow(self.body('after')), fence.DENY)

    def test_final_root_validation_crossing_deadline_is_refused(self):
        fence = self.fence()
        original = fence._root_identity
        count = 0
        def delayed_root():
            nonlocal count
            count += 1
            identity = original()
            if count == 3:
                self.now += fence.CALLBACK_SECONDS
            return identity
        fence._root_identity = delayed_root
        self.assertEqual(fence.allow(self.body('before')), fence.DENY)
        fence._root_identity = original
        self.assertEqual(fence.allow(self.body('after')), fence.DENY)

    def test_actual_account_mutation_lock_busy_is_nonblocking_refusal(self):
        fence = self.fence()
        with self.store.locked(ALICE):
            self.assertEqual(fence.allow(self.body('before')), fence.DENY)
        self.assertEqual(fence.allow(self.body('before')), fence.DENY)
        self.assertEqual(fence.allow(self.body('after')), fence.DENY)

    def test_capacity_does_not_evict_live_account_capture(self):
        fence = self.fence()
        for i in range(fence.MAX_ENTRIES):
            self.assertEqual(fence.allow(self.body('before', session=f'Public{i}')), fence.ALLOW)
        self.assertEqual(fence.allow(self.body('before', account=BOB)), fence.DENY)
        self.assertEqual(fence.allow(self.body('after', session='Public0')), fence.ALLOW)
        self.now += fence.CAPTURE_SECONDS
        self.assertEqual(fence.allow(self.body('before', account=BOB)), fence.ALLOW)

    def test_missing_corrupt_unsafe_record_is_never_provisioned_or_reset(self):
        for kind in ('missing', 'corrupt', 'oversize', 'hardlink', 'symlink', 'mode'):
            with self.subTest(kind=kind):
                path = self.store._paths(ALICE)[1]
                saved = path.read_bytes()
                path.unlink()
                other = self.root / 'public-sentinel'
                if kind == 'corrupt': path.write_bytes(b'{}')
                if kind == 'oversize': path.write_bytes(b' ' * 4097)
                if kind == 'hardlink': other.write_bytes(saved); os.link(other, path)
                if kind == 'symlink': other.write_bytes(saved); path.symlink_to(other)
                if kind == 'mode': path.write_bytes(saved); path.chmod(0o644)
                if kind in ('corrupt', 'oversize', 'hardlink'): path.chmod(0o600)
                fence = self.fence()
                self.assertEqual(fence.allow(self.body('before')), fence.DENY)
                if kind == 'missing': self.assertFalse(path.exists())
                if path.exists() or path.is_symlink(): path.unlink()
                if other.exists(): other.unlink()
                path.write_bytes(saved); path.chmod(0o600)

    def test_root_replacement_never_opens_a_different_store(self):
        fence = self.fence()
        parked = self.root.with_name(self.root.name + '-parked')
        self.root.rename(parked)
        self.root.mkdir(mode=0o700)
        try:
            self.assertEqual(fence.allow(self.body('before')), fence.DENY)
            self.assertEqual(list(self.root.iterdir()), [])
        finally:
            self.root.rmdir(); parked.rename(self.root)

    def test_concurrent_after_is_exactly_once_with_held_private_account_lock(self):
        fence = self.fence()
        self.assertEqual(fence.allow(self.body('before')), fence.ALLOW)
        entered = threading.Event(); release = threading.Event()
        original = self.store._read
        def held(path):
            entered.set()
            if not release.wait(1): raise RuntimeError('fixture barrier timeout')
            return original(path)
        self.store._read = held
        results = []
        child = threading.Thread(target=lambda: results.append(fence.allow(self.body('after'))))
        child.start()
        try:
            self.assertTrue(entered.wait(1))
            self.assertEqual(fence.allow(self.body('after')), fence.DENY)
        finally:
            release.set(); child.join(1); self.store._read = original
        self.assertFalse(child.is_alive())
        self.assertEqual(results, [fence.ALLOW])
        self.assertEqual(fence.allow(self.body('after')), fence.DENY)

if __name__ == '__main__':
    unittest.main()
