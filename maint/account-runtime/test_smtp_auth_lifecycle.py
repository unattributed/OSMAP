"""Synthetic socket/epoch tests; no service, SQL or provider is contacted."""
import base64
import importlib
import os
from pathlib import Path
import socket
import tempfile
import threading
import time
import unittest

from account_epoch import EpochStore
from authoritative_password import Refused, Unconfirmed
from operation_budget import OperationBudget

ALICE = 'alice@fixture.invalid'
BOB = 'bob@fixture.invalid'


class LifecycleTests(unittest.TestCase):
    def setUp(self):
        self.scratch = tempfile.TemporaryDirectory(prefix='osmap-auth-lifecycle-')
        self.addCleanup(self.scratch.cleanup)
        self.root = Path(self.scratch.name)
        self.root.chmod(0o700)
        self.store = EpochStore(self.root, expected_uid=os.getuid())
        for account in (ALICE, BOB):
            self.store.provision(account)
        self.module = importlib.import_module('smtp_auth_lifecycle')
        self.identity = (123, '127.0.0.1', 2525, 40123)
        self.authority = self.module.OwnedSmtpPeerAuthority(
            (os.getuid(), os.getgid()), (os.getuid(), os.getgid()),
            2525, lambda pid, deadline: self.identity)
        self.registry = self.module.SmtpAuthLifecycle(
            self.store, frozenset((ALICE, BOB)), self.authority)

    def budget(self):
        return OperationBudget(int(time.time()) + 60)

    def channel(self, account=ALICE, request=1):
        client, frontend = socket.socketpair()
        upstream, backend = socket.socketpair()
        for item in (client, frontend, upstream, backend):
            self.addCleanup(item.close)
        raw = base64.b64encode(b'\0' + account.encode() + b'\0public-test-passphrase')
        line = b'AUTH\t' + str(request).encode() + b'\tPLAIN\tservice=smtp\tresp=' + raw + b'\n'
        channel = self.registry.begin(client, upstream, b'CPID\t123\n', line, self.budget())
        self.addCleanup(self.registry.close, channel)
        return channel, frontend, backend

    def ok(self, channel, account=ALICE, request=1):
        return self.registry.verified(channel, b'OK\t' + str(request).encode()
                                      + b'\tuser=' + account.encode() + b'\n')

    def state(self, account=ALICE, epoch=0, state='pending'):
        with self.store.locked(account) as path:
            value = self.store._read(path)
            value.update(epoch=epoch, state=state, intent=None if state == 'active' else 'a' * 64)
            self.store._write(path, value)

    def eof(self, peer):
        peer.settimeout(0.2)
        self.assertEqual(peer.recv(4096), b'')

    def test_actual_verified_ok_published_once_and_registered(self):
        channel, front, _ = self.channel()
        receipt = self.ok(channel)
        self.assertTrue(self.registry.publish(channel, receipt))
        front.settimeout(0.2)
        self.assertEqual(front.recv(4096), b'OK\t1\tuser=' + ALICE.encode() + b'\n')
        with self.assertRaises(Refused):
            self.registry.publish(channel, receipt)

    def test_stale_verified_success_cannot_publish_after_epoch_change(self):
        channel, front, back = self.channel()
        receipt = self.ok(channel)
        self.state(epoch=1, state='active')
        with self.assertRaises(Refused):
            self.registry.publish(channel, receipt)
        self.eof(front)
        self.eof(back)

    def test_pending_cancel_uses_existing_account_lock_and_preserves_bob(self):
        alice, af, ab = self.channel()
        bob, bf, _ = self.channel(BOB, request=2)
        receipt = self.ok(alice)
        with self.store.locked(ALICE) as path:
            value = self.store._read(path)
            self.store._write(path, dict(value, state='pending', intent='a' * 64))
            started = time.monotonic()
            self.assertEqual(self.registry.cancel_pending_locked(ALICE, self.budget()), 1)
            self.assertLess(time.monotonic() - started, 0.2)
        self.eof(af)
        self.eof(ab)
        with self.assertRaises(Refused):
            self.registry.publish(alice, receipt)
        self.assertTrue(self.registry.publish(bob, self.ok(bob, BOB, 2)))
        bf.settimeout(0.2)
        self.assertEqual(bf.recv(4096), b'OK\t2\tuser=' + BOB.encode() + b'\n')

    def test_cancellation_does_not_kill_new_epoch_or_untargeted_channels(self):
        old, of, ob = self.channel()
        self.state()
        cutoff = self.registry.pending_cutoff_locked(ALICE, self.budget())
        self.state(epoch=1, state='active')
        new, nf, _ = self.channel(request=2)
        self.assertEqual(self.registry.cancel_cutoff_locked(cutoff, self.budget()), 1)
        self.eof(of)
        self.eof(ob)
        self.assertTrue(self.registry.publish(new, self.ok(new, request=2)))
        nf.settimeout(0.2)
        self.assertEqual(nf.recv(4096), b'OK\t2\tuser=' + ALICE.encode() + b'\n')
        with self.assertRaises(Refused):
            self.registry.cancel_cutoff_locked(cutoff, self.budget())

    def test_busy_account_lock_refuses_success_and_shutdowns_held_channel(self):
        channel, front, back = self.channel()
        receipt = self.ok(channel)
        result = []
        with self.store.locked(ALICE):
            thread = threading.Thread(target=lambda: self.publish_result(channel, receipt, result))
            thread.start()
            thread.join(0.5)
            self.assertFalse(thread.is_alive())
        self.assertEqual(result, ['refused'])
        self.eof(front)
        self.eof(back)

    def publish_result(self, channel, receipt, result):
        try:
            self.registry.publish(channel, receipt)
            result.append('published')
        except Refused:
            result.append('refused')

    def test_wrong_verified_identity_request_or_boolean_refused(self):
        for line in (b'OK\t2\tuser=' + ALICE.encode() + b'\n',
                     b'OK\t1\tuser=' + BOB.encode() + b'\n',
                     b'OK\t1\tuser=' + ALICE.encode() + b'\tuser=' + ALICE.encode() + b'\n',
                     b'OK\t1\tuser=' + ALICE.encode() + b'\nFAIL\t1\n'):
            channel, front, back = self.channel()
            with self.assertRaises(Refused):
                self.registry.verified(channel, line)
            self.eof(front)
            self.eof(back)
        channel, front, _ = self.channel()
        with self.assertRaises(Refused):
            self.registry.publish(channel, True)
        self.eof(front)

    def test_cpid_witness_replacement_denies_real_ok_before_write(self):
        channel, front, back = self.channel()
        receipt = self.ok(channel)
        self.identity = (123, '127.0.0.1', 2525, 40124)
        with self.assertRaises(Refused):
            self.registry.publish(channel, receipt)
        self.eof(front)
        self.eof(back)

    def test_kernel_peer_mismatch_cannot_register(self):
        authority = self.module.OwnedSmtpPeerAuthority(
            (os.getuid() + 1, os.getgid()), (os.getuid(), os.getgid()),
            2525, lambda pid, deadline: self.identity)
        self.registry = self.module.SmtpAuthLifecycle(self.store, frozenset((ALICE, BOB)), authority)
        with self.assertRaises(Refused):
            self.channel()

    def test_closed_unix_descriptor_cannot_replace_original_ownership(self):
        channel, front, _ = self.channel()
        receipt = self.ok(channel)
        self.registry.close(channel)
        with self.assertRaises(Refused):
            self.registry.publish(channel, receipt)
        self.eof(front)

    def test_pending_or_contained_store_prevents_begin(self):
        for state in ('pending', 'contained'):
            self.state(state=state)
            with self.assertRaises(Refused):
                self.channel()

    def test_same_socket_cannot_be_multiplexed_across_accounts(self):
        channel, _, _ = self.channel()
        with self.assertRaises(Refused):
            self.registry.begin(channel.client, channel.upstream, b'CPID\t123\n',
                                b'AUTH\t2\tPLAIN\tservice=smtp\tresp='
                                + base64.b64encode(b'\0' + BOB.encode() + b'\0public-pass') + b'\n',
                                self.budget())

    def test_cutoff_is_not_a_caller_epoch_and_active_store_cannot_mint(self):
        with self.assertRaises(Refused):
            self.registry.pending_cutoff_locked(ALICE, self.budget())
        with self.assertRaises(Refused):
            self.registry.cancel_cutoff_locked(0, self.budget())

    def test_flags_false_and_durable_epoch_bytes_preserved(self):
        self.assertFalse(self.module.NATIVE_AUTH_BROKER_QUALIFIED)
        before = {p.name: p.read_bytes() for p in self.root.glob('*.json')}
        channel, _, _ = self.channel()
        self.registry.publish(channel, self.ok(channel))
        self.assertEqual(before, {p.name: p.read_bytes() for p in self.root.glob('*.json')})

    def test_original_capture_deadline_is_not_refreshed_by_backend_ok(self):
        channel, front, back = self.channel()
        receipt = self.ok(channel)
        channel.capture_expires = time.monotonic() - 1
        with self.assertRaises(Refused):
            self.registry.publish(channel, receipt)
        self.eof(front)
        self.eof(back)

    def test_original_operation_budget_expiry_closes_without_publishing(self):
        channel, front, back = self.channel()
        receipt = self.ok(channel)
        channel.budget._deadline = time.monotonic() - 1
        with self.assertRaises(Refused):
            self.registry.publish(channel, receipt)
        self.eof(front)
        self.eof(back)

    def test_failed_shutdown_is_unconfirmed_not_a_success_count(self):
        channel, _, _ = self.channel()
        channel.upstream.close()
        self.state()
        with self.assertRaises(Unconfirmed):
            self.registry.cancel_pending_locked(ALICE, self.budget())

    def test_reset_same_epoch_cannot_authorize_an_old_cancellation_cutoff(self):
        channel, front, _ = self.channel()
        self.state()
        cutoff = self.registry.pending_cutoff_locked(ALICE, self.budget())
        self.state(state='active')
        with self.assertRaises(Refused):
            self.registry.cancel_cutoff_locked(cutoff, self.budget())
        self.assertTrue(self.registry.publish(channel, self.ok(channel)))
        front.settimeout(0.2)
        self.assertTrue(front.recv(4096).startswith(b'OK\t1\t'))

    def test_auth_parser_cannot_mix_service_or_switch_authorization_identity(self):
        responses = (b'\0' + ALICE.encode() + b'\0public-pass',
                     BOB.encode() + b'\0' + ALICE.encode() + b'\0public-pass')
        for response, service in ((responses[0], b'service=smtp\tservice=imap'),
                                  (responses[0], b'service=imap'),
                                  (responses[1], b'service=smtp')):
            client, frontend = socket.socketpair()
            upstream, backend = socket.socketpair()
            for item in (client, frontend, upstream, backend):
                self.addCleanup(item.close)
            with self.assertRaises(Refused):
                self.registry.begin(client, upstream, b'CPID\t123\n',
                                    b'AUTH\t1\tPLAIN\t' + service + b'\tresp='
                                    + base64.b64encode(response) + b'\n', self.budget())

    def test_final_shared_account_lock_is_held_at_success_publication(self):
        channel, front, _ = self.channel()
        receipt = self.ok(channel)
        original = self.authority._inspect
        observed = []
        def inspect(pid, deadline):
            # Independent policy callback uses nonblocking acquisition of the
            # same account lock. It must deny while publication is in progress.
            import dovecot_auth_epoch
            fence = dovecot_auth_epoch.EpochPolicyFence(self.store, frozenset((ALICE, BOB)))
            body = ('{"login":"' + ALICE + '","protocol":"smtp",'
                    '"session_id":"PublicSession001","phase":"before","tls":true}').encode()
            observed.append(fence.allow(body))
            return original(pid, deadline)
        self.authority._inspect = inspect
        self.registry.publish(channel, receipt)
        self.assertEqual(observed, [b'{"status":-1}'])
        front.settimeout(0.2)
        self.assertTrue(front.recv(4096).startswith(b'OK\t1\t'))


if __name__ == '__main__':
    unittest.main()
