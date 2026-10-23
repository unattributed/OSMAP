"""Local driver regression only: controlled transport is not native product proof.

Run the real journey, FrontDriver HTTP encoder/parser, cookie consumer and
persisted session/replay readers. The local peer below substitutes backend
effects solely to discriminate observation/refusal and one-shot behaviour.
"""
import hashlib
import importlib.util
import json
import os
from pathlib import Path
import tempfile
import threading
import time
from types import SimpleNamespace
import unittest
from unittest.mock import patch
from urllib.parse import parse_qs


ROOT = Path(__file__).resolve().parent


def load(name, leaf):
    spec = importlib.util.spec_from_file_location(name, ROOT / 'sources/frontend' / leaf)
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


front = load('password_journey_front', 'native_http_front_driver.py')
password = load('password_journey_password', 'native_http_password_driver.py')


class ControlledPeer:
    def __init__(self, root, fault=None):
        self.root, self.fault = root, fault
        self.requests, self.cookies, self.sessions, self.counters = [], [], {}, {}
        self.writes = 0
        self.finished = False
        self.counter = int(time.time()) // 30
        self.boot = {'alice_password': 'a' * 64, 'bob_password': 'b' * 64,
            'new_password': 'c' * 64}
        (root / 'http-state/sessions').mkdir(parents=True)
        (root / 'http-state/cache/totp-replay').mkdir(parents=True)

    def persist(self, record):
        path = self.root / 'http-state/sessions' / (record['session_id'] + '.session')
        path.write_text(''.join(f'{key}={value}\n' for key, value in record.items()))
        path.chmod(0o600)

    def replay(self, account, code):
        counter = next(n for n in range(self.counter, self.counter + 5) if front.code(n) == code)
        password.require(counter > self.counters.get(account, -1), 'local_peer_replay')
        self.counters[account] = counter
        path = self.root / 'http-state/cache/totp-replay' / (account.encode().hex() + '.counter')
        path.write_text(str(counter))
        path.chmod(0o600)

    def session(self, account):
        token = format(len(self.cookies) + 1, '064x')
        cookie = 'osmap_session=' + token
        record = {'session_id': hashlib.sha256(('session-id:' + token).encode()).hexdigest(),
            'csrf_token': 'd' * 64, 'canonical_username': account, 'factor': 'totp',
            'account_epoch': str(self.writes if account == password.ALICE else 0),
            'issued_at': str(int(time.time())), 'expires_at': str(int(time.time()) + 3600),
            'last_seen_at': str(int(time.time())), 'revoked_at': '',
            'remote_addr': '127.0.0.1', 'user_agent': front.AGENT}
        if account == password.ALICE and len(self.cookies) == 2:
            if self.fault == 'duplicate_session':
                return self.cookies[1]
            field, value = {'wrong_factor': ('factor', 'password'),
                'wrong_epoch': ('account_epoch', '1'), 'already_revoked': ('revoked_at', '1'),
                'expired': ('expires_at', '1')}.get(self.fault, (None, None))
            if field:
                record[field] = value
        self.cookies.append(cookie)
        self.sessions[cookie] = record
        self.persist(record)
        return cookie

    def reply(self, status, body=b'', headers=()):
        head = [('Content-Length', str(len(body))), *headers]
        return (f'HTTP/1.1 {status} Local\r\n' + ''.join(f'{k}: {v}\r\n' for k, v in head)
            + '\r\n').encode() + body

    def respond(self, raw):
        head, _, body = raw.partition(b'\r\n\r\n')
        lines = head.decode().split('\r\n')
        method, path, _ = lines[0].split(' ')
        headers = dict(line.split(': ', 1) for line in lines[1:])
        form = {key: value[0] for key, value in parse_qs(body.decode()).items()}
        cookie = headers.get('Cookie')
        self.requests.append((method, path, cookie))
        if method == 'POST' and path == '/login':
            account = form['username']
            expected = self.boot['new_password' if self.writes and account == password.ALICE
                else 'alice_password' if account == password.ALICE else 'bob_password']
            old_still_valid = self.fault == 'old_password_still_valid' and self.writes \
                and account == password.ALICE and form['password'] == self.boot['alice_password']
            if form['password'] != expected and not old_still_valid:
                return self.reply(401)
            counter = next(n for n in range(self.counter, self.counter + 5)
                if front.code(n) == form['totp_code'])
            if counter <= self.counters.get(account, -1):
                return self.reply(401)
            self.replay(account, form['totp_code'])
            cookie = self.session(account)
            return self.reply(303, headers=(('Set-Cookie', cookie + '; Secure; HttpOnly; SameSite=Strict'),))
        if path == '/login':
            return self.reply(200)
        record = self.sessions[cookie]
        if method == 'POST':
            password.require(path == '/settings/password' and self.writes == 0, 'local_peer_one_write')
            password.require(form['current_password'] == self.boot['alice_password']
                and form['new_password'] == form['confirmation'] == self.boot['new_password']
                and form['csrf_token'] == record['csrf_token'], 'local_peer_mutation_form')
            self.replay(password.ALICE, form['totp_code'])
            self.writes += 1
            for old_cookie, session in self.sessions.items():
                if session['canonical_username'] == password.ALICE:
                    if self.fault == 'other_not_revoked' and old_cookie == self.cookies[2]:
                        continue
                    session['revoked_at'] = str(int(time.time()))
                    self.persist(session)
            if self.fault == 'response_lost':
                raise TimeoutError('local_uncertain_response')
            return self.reply(200, b'Your password was changed',
                (('Set-Cookie', 'osmap_session=; Max-Age=0'),))
        if record['revoked_at'] and not (self.fault == 'other_cookie_admitted' and cookie == self.cookies[2]):
            return self.reply(303, headers=(('Location', '/login'),))
        if path == '/settings/password':
            return self.reply(200, b'<form id="password-change-form"><input name="csrf_token" value="'
                + record['csrf_token'].encode() + b'"></form>')
        history = b'Last changed 2026-10-23 12:00:01 UTC' if self.writes and record['canonical_username'] == password.ALICE else b'Last change unknown'
        return self.reply(200, history)

    def snapshot(self, account):
        changed = self.writes and account == password.ALICE
        return {'account': account, 'row_count': 1, 'row_sha256': ('e' if changed else 'a') * 64,
            'password_sha256': ('f' if changed else 'b') * 64, 'noncredential_sha256': 'c' * 64,
            'epoch': int(bool(changed)), 'state': 'active',
            'changed_at': '20261023120001' if changed else None,
            'sql_changed_at': '20261023120001' if changed else '20261023120000'}

    def exchange(self, tag, end):
        password.require(time.monotonic() < end, 'local_original_deadline')
        if tag.startswith('SNAPSHOT_'):
            return {'phase': tag, 'snapshot': self.snapshot(password.BOB if tag[9] == 'B' else password.ALICE)}
        return {'phase': tag, 'result': {'result': 'PASS', 'bob_mail_projection_preserved': True,
            'bob_home_absent': True, 'bob_mail_absent': True, 'bob_projection_sha256': 'a' * 64,
            'public_cache_zero': True,
            'public_original25_preserved': True, 'public_master_preserved': True,
            'external_sessions_terminated': False, 'flush_performed': False}}

    def finish(self, end):
        password.require(len(self.requests) == 18, 'local_connection_count')
        self.finished = True
        return {'local_only': True}


class ControlledSocket:
    def __init__(self, peer):
        self.peer = peer
        self.response = b''

    def settimeout(self, value):
        password.require(value > 0, 'local_transport_deadline')

    def sendall(self, raw):
        self.response = self.peer.respond(raw)

    def recv(self, size):
        result, self.response = self.response[:size], self.response[size:]
        return result

    def close(self):
        pass


class PasswordJourneyTests(unittest.TestCase):
    def exercise(self, fault=None):
        with tempfile.TemporaryDirectory() as name:
            root = Path(name)
            peer = ControlledPeer(root, fault)
            node = SimpleNamespace(cancelled=threading.Event(), http_root=root,
                socket_lock=threading.Lock(), http_stream=None, ready={'port': 1},
                sequence_end=time.monotonic() + 90, capture_generated_directories=lambda: None,
                capture_replay_directory=lambda: None, exchange=peer.exchange, finish_http=peer.finish)
            driver = front.FrontDriver(node, peer.boot)
            checkpoint_writes = []

            def checkpoint():
                password.require(driver.mutation_submission_started and driver.mutation_requests == 1,
                    'local_checkpoint_fence')
                checkpoint_writes.append(peer.writes)
                if fault == 'checkpoint_failed':
                    raise RuntimeError('local_checkpoint_failed')

            driver.mutation_submission_checkpoint = checkpoint
            error, result = None, None
            with patch.object(front, 'WEB_UID', os.getuid()), patch.object(front, 'WEB_GID', os.getgid()), \
                    patch.object(front.socket, 'create_connection', side_effect=lambda *a, **k: ControlledSocket(peer)), \
                    patch.object(front, 'accepted_counter', side_effect=lambda end, minimum=0: (max(peer.counter, minimum), 0)):
                try:
                    result = password.journey(driver)
                except (ValueError, RuntimeError, TimeoutError) as caught:
                    error = caught
        self.assertFalse(root.exists(), 'local fixture cleanup must run on success and failure')
        self.assertEqual(driver.sequence_end, node.sequence_end)
        self.assertEqual(checkpoint_writes, [0] if driver.mutation_submission_started else [])
        return peer, driver, result, error

    def test_two_distinct_persisted_sessions_one_change_eighteen_requests(self):
        peer, driver, result, error = self.exercise()
        self.assertIsNone(error)
        self.assertTrue(peer.finished)
        self.assertEqual((peer.writes, len(peer.requests), driver.mutation_requests), (1, 18, 1))
        self.assertTrue(driver.mutation_submission_started)
        old = result['mutation_evidence']['alice_sessions']
        self.assertEqual(len({record['session_id_sha256'] for record in old}), 2)
        self.assertTrue(all(record['revoked'] and record['old_cookie_status'] == 303 for record in old))
        self.assertGreaterEqual(result['timings']['mutation_seconds'], 0)
        self.assertNotIn('osmap_session=', json.dumps(result))
        self.assertNotIn('PASS', result['qualification'])

    def test_invalid_other_session_refuses_before_submission(self):
        for fault in ('duplicate_session', 'wrong_factor', 'wrong_epoch', 'already_revoked', 'expired'):
            with self.subTest(fault=fault):
                peer, driver, result, error = self.exercise(fault)
                self.assertIsNotNone(error)
                self.assertEqual((peer.writes, driver.mutation_requests), (0, 0))
                self.assertFalse(driver.mutation_submission_started)
                self.assertIsNone(result)

    def test_missing_second_revocation_or_denial_is_not_success(self):
        for fault, reason in (('other_not_revoked', 'browser_containment_and_bob'),
                ('other_cookie_admitted', 'old_cookie')):
            with self.subTest(fault=fault):
                peer, driver, result, error = self.exercise(fault)
                self.assertEqual(str(error), reason)
                self.assertEqual((peer.writes, driver.mutation_requests), (1, 1))
                self.assertTrue(driver.mutation_submission_started)
                self.assertFalse(peer.finished)
                self.assertIsNone(result)

    def test_uncertain_response_has_one_submission_and_no_retry(self):
        peer, driver, result, error = self.exercise('response_lost')
        self.assertIsInstance(error, TimeoutError)
        self.assertEqual((peer.writes, driver.mutation_requests), (1, 1))
        self.assertEqual(sum(method == 'POST' and path == '/settings/password'
            for method, path, _ in peer.requests), 1)
        self.assertTrue(driver.mutation_submission_started)
        self.assertFalse(peer.finished)
        self.assertIsNone(result)
        self.assertGreaterEqual(driver.milestone_timings['mutation_seconds'], 0)

    def test_old_password_still_valid_is_detected_with_unused_totp(self):
        peer, driver, result, error = self.exercise('old_password_still_valid')
        self.assertEqual(str(error), 'old_password')
        self.assertEqual((peer.writes, driver.mutation_requests), (1, 1))
        # The erroneous old-password acceptance consumed the fresh factor and
        # persisted another session. A replayed step-up code would return401
        # without this evidence and would falsely pass the former observer.
        self.assertEqual(peer.counters[password.ALICE], peer.counter + 3)
        self.assertEqual(len(peer.cookies), 4)
        self.assertEqual(peer.sessions[peer.cookies[-1]]['account_epoch'], '1')
        self.assertFalse(peer.finished)
        self.assertIsNone(result)

    def test_failed_durable_checkpoint_prevents_mutation_request(self):
        peer, driver, result, error = self.exercise('checkpoint_failed')
        self.assertEqual(str(error), 'local_checkpoint_failed')
        self.assertEqual(peer.writes, 0)
        self.assertFalse(any(method == 'POST' and path == '/settings/password'
            for method, path, _ in peer.requests))
        self.assertTrue(driver.mutation_submission_started)
        self.assertIsNone(result)


if __name__ == '__main__':
    unittest.main()
