"""Local driver regression only: controlled transport is not native product proof.

Run the real journey, FrontDriver HTTP encoder/parser, cookie consumer and
persisted session/replay readers. The local peer below substitutes backend
effects solely to discriminate observation/refusal and one-shot behaviour.
"""
import ast
from contextlib import redirect_stdout, redirect_stderr
import hashlib
import importlib.util
import io
import json
import os
from pathlib import Path
import re
import signal
import subprocess
import sys
import tempfile
import threading
import time
from types import SimpleNamespace
import unittest
from unittest.mock import MagicMock, Mock, patch
from urllib.parse import parse_qs


ROOT = Path(__file__).resolve().parent


def load(name, leaf):
    spec = importlib.util.spec_from_file_location(name, ROOT / 'sources/frontend' / leaf)
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


def frontend_node(keeper):
    # Instantiate all real controller state; only pinned host module loading is
    # replaced in these narrow clock/cleanup unit regressions.
    with patch.object(keeper,'module',return_value=SimpleNamespace()):
        return keeper.Frontend(None)


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
    def test_shared_fixture_birth_interrupt_is_inside_owned_cleanup(self):
        path = ROOT.parent / 'browser_workflows.py'
        tree = ast.parse(path.read_text())
        functions = [node for node in tree.body if isinstance(node, ast.FunctionDef)
            and node.name in ('require', '_reap_server', 'start_server')]
        with tempfile.TemporaryDirectory() as name:
            root = Path(name)
            child = subprocess.Popen((sys.executable, '-I', '-c', 'import time; time.sleep(60)'),
                stdin=subprocess.DEVNULL, stdout=subprocess.DEVNULL,
                stderr=subprocess.DEVNULL, start_new_session=True)
            namespace = dict(os=os, re=re, signal=signal, time=time, json=json,
                SERVER_STOP_SECONDS=.2, subprocess=SimpleNamespace(Popen=Mock(return_value=child),
                    STDOUT=subprocess.STDOUT, TimeoutExpired=subprocess.TimeoutExpired))
            exec(compile(ast.Module(body=functions, type_ignores=[]), str(path), 'exec'), namespace)
            try:
                # Deliver the pending handled interruption at mask restoration,
                # immediately after Popen returned its owned direct handle.
                with patch.object(signal, 'pthread_sigmask', side_effect=[set(), KeyboardInterrupt, set()]):
                    with self.assertRaises(KeyboardInterrupt):
                        namespace['start_server'](root, root, None)
                self.assertIsNotNone(child.returncode)
                with self.assertRaises(ProcessLookupError):
                    os.killpg(child.pid, 0)
            finally:
                if child.returncode is None:
                    os.killpg(child.pid, signal.SIGKILL)
                    child.wait(timeout=2)

    def test_preview_bounds_main_wait_and_retains_uncertain_state(self):
        path = ROOT.parent / 'preview.py'
        spec = importlib.util.spec_from_file_location('local_preview_review', path)
        preview = importlib.util.module_from_spec(spec)
        spec.loader.exec_module(preview)
        self.assertEqual(preview.preview_origin({'synthetic': True,
            'origin': 'http://127.0.0.1:1234'}), 'http://127.0.0.1:1234')
        for value in ([], {'synthetic': True, 'origin': 'http://127.0.0.1:1@outside.invalid'},
                {'synthetic': True, 'origin': 'http://127.0.0.1:0'},
                {'synthetic': True, 'origin': 'http://127.0.0.1:65536'}):
            with self.assertRaisesRegex(RuntimeError, 'synthetic loopback origin'):
                preview.preview_origin(value)
        for uncertain in (False, True):
            with self.subTest(uncertain=uncertain), tempfile.TemporaryDirectory() as name:
                root = Path(name) / 'preview'
                root.mkdir(mode=0o700)
                child = SimpleNamespace(returncode=0, wait=Mock(return_value=0))

                def spawn(*args, **kwargs):
                    self.assertTrue(kwargs['start_new_session'])
                    (root / 'ready.json').write_text(json.dumps({'synthetic': True,
                        'origin': 'http://127.0.0.1:1234'}))
                    return child

                output, error = io.StringIO(), io.StringIO()
                with patch.object(preview.sys, 'argv', [str(path), '--minutes', '1']), \
                        patch.object(preview.signal, 'signal'), \
                        patch.object(preview.tempfile, 'mkdtemp', return_value=str(root)), \
                        patch.object(preview.subprocess, 'Popen', side_effect=spawn), \
                        patch.object(preview, 'stop_preview',
                            side_effect=RuntimeError('local_cleanup_uncertain') if uncertain else None,
                            return_value=None), redirect_stdout(output), redirect_stderr(error):
                    if uncertain:
                        with self.assertRaisesRegex(RuntimeError, 'local_cleanup_uncertain'):
                            preview.main()
                    else:
                        preview.main()
                child.wait.assert_called_once_with(timeout=65)
                self.assertEqual(root.exists(), uncertain)
                self.assertEqual('Preview stopped; disposable data removed.' in output.getvalue(), not uncertain)
                self.assertEqual('retained disposable state' in error.getvalue(), uncertain)

    def test_failed_stop_marker_still_reaps_shared_and_standalone_fixture(self):
        tree = ast.parse((ROOT.parent / 'browser_workflows.py').read_text())
        functions = [node for node in tree.body if isinstance(node, ast.FunctionDef)
            and node.name in ('require', '_reap_server')]
        shared = dict(os=os, signal=signal, subprocess=subprocess, SERVER_STOP_SECONDS=.2)
        exec(compile(ast.Module(body=functions, type_ignores=[]), '<shared-fixture>', 'exec'), shared)
        spec = importlib.util.spec_from_file_location('local_preview_stop', ROOT.parent / 'preview.py')
        preview = importlib.util.module_from_spec(spec)
        spec.loader.exec_module(preview)
        for standalone in (False, True):
            with self.subTest(standalone=standalone), tempfile.TemporaryDirectory() as name:
                child = subprocess.Popen((sys.executable, '-I', '-c', 'import time; time.sleep(60)'),
                    stdin=subprocess.DEVNULL, stdout=subprocess.DEVNULL,
                    stderr=subprocess.DEVNULL, start_new_session=True)
                marker_error = OSError('local_marker_refused')
                try:
                    with patch.object(Path, 'touch', side_effect=marker_error), \
                            patch.object(preview, 'STOP_SECONDS', .2):
                        if standalone:
                            self.assertIs(preview.stop_preview(child, Path(name)), marker_error)
                        else:
                            with self.assertRaises(OSError) as caught:
                                shared['_reap_server'](child, Path(name))
                            self.assertIs(caught.exception, marker_error)
                    self.assertIsNotNone(child.returncode)
                    with self.assertRaises(ProcessLookupError):
                        os.killpg(child.pid, 0)
                finally:
                    if child.returncode is None:
                        os.killpg(child.pid, signal.SIGKILL)
                        child.wait(timeout=2)

    def test_shared_browser_fixture_reaps_readiness_failure_and_normal_stop(self):
        path = ROOT.parent / 'browser_workflows.py'
        tree = ast.parse(path.read_text())
        functions = [node for node in tree.body if isinstance(node, ast.FunctionDef)
            and node.name in ('require', '_reap_server', 'start_server', 'stop_server')]
        for valid in (False, True):
            with self.subTest(valid=valid), tempfile.TemporaryDirectory() as name:
                root = Path(name)
                children = []
                real_popen = subprocess.Popen
                real_killpg = os.killpg
                signals = []

                def spawn(*args, **kwargs):
                    self.assertTrue(kwargs['start_new_session'])
                    body = 'import time; time.sleep(60)' if not valid else \
                        'import pathlib,sys,time\np=pathlib.Path(sys.argv[1])/"stop"\nwhile not p.exists(): time.sleep(.01)'
                    child = real_popen((sys.executable, '-I', '-c', body, str(root)),
                        stdin=subprocess.DEVNULL, stdout=subprocess.DEVNULL,
                        stderr=subprocess.DEVNULL, start_new_session=True)
                    children.append(child)
                    (root / 'ready.json').write_text(json.dumps({'synthetic': True,
                        'origin': 'http://127.0.0.1:1234' if valid else 'http://127.0.0.1:1@outside.invalid'}))
                    return child

                def owned_signal(pid, number):
                    self.assertEqual(pid, children[0].pid)
                    if number:
                        self.assertIsNone(children[0].returncode,
                            'historical reaped PID must not be signalled')
                    signals.append(number)
                    return real_killpg(pid, number)

                namespace = dict(os=os, re=re, signal=signal, time=time, json=json,
                    SERVER_STOP_SECONDS=.2, subprocess=SimpleNamespace(Popen=spawn,
                        STDOUT=subprocess.STDOUT, TimeoutExpired=subprocess.TimeoutExpired))
                exec(compile(ast.Module(body=functions, type_ignores=[]), str(path), 'exec', optimize=2), namespace)
                try:
                    with patch.object(os, 'killpg', side_effect=owned_signal):
                        if valid:
                            child, origin = namespace['start_server'](root, root, None)
                            self.assertEqual(origin, 'http://127.0.0.1:1234')
                            namespace['stop_server'](child, root)
                            namespace['stop_server'](child, root)
                            self.assertEqual(signals, [0, 0])
                        else:
                            with self.assertRaisesRegex(AssertionError, 'synthetic loopback origin refused'):
                                namespace['start_server'](root, root, None)
                            self.assertIn(signal.SIGTERM, signals)
                    self.assertIsNotNone(children[0].returncode)
                    with self.assertRaises(ProcessLookupError):
                        real_killpg(children[0].pid, 0)
                finally:
                    # Test ownership cleanup remains bounded even on regression.
                    for child in children:
                        if child.returncode is None:
                            real_killpg(child.pid, signal.SIGKILL)
                            child.wait(timeout=2)

    def test_sprint_workflow_actions_and_checks_survive_python_optimization(self):
        ux = ROOT.parent
        names = ('general_preferences_workflows.py', 'appearance_workflows.py',
            'session_workflows.py', 'general_workflows.py', 'reading_workflows.py',
            'composition_workflows.py', 'signature_workflows.py',
            'security_settings_workflows.py', 'browser_workflows.py', 'capture_pages.py')
        for name in names:
            self.assertFalse(any(isinstance(node, ast.Assert)
                for node in ast.walk(ast.parse((ux / name).read_text()))), name)
        helper = next(node for node in ast.parse((ux / 'browser_workflows.py').read_text()).body
            if isinstance(node, ast.FunctionDef) and node.name == 'require')
        workflow = ast.parse((ux / 'general_preferences_workflows.py').read_text())
        operation = next(node for node in ast.walk(workflow) if isinstance(node, ast.Expr)
            and isinstance(node.value, ast.Call) and isinstance(node.value.func, ast.Name)
            and node.value.func.id == 'require' and any(isinstance(child, ast.Call)
                and isinstance(child.func, ast.Name) and child.func.id == 'post'
                and child.args and isinstance(child.args[0], ast.Constant)
                and child.args[0].value == '/settings/reading'
                for child in ast.walk(node)))
        source = ast.Module(body=[helper, operation], type_ignores=[])
        for optimized in (0, 2):
            for status in (200, 500):
                with self.subTest(optimized=optimized, status=status):
                    post = Mock(return_value=SimpleNamespace(status=status))
                    namespace = {'post': post}
                    compiled = compile(source, '<actual-sprint-workflow-check>', 'exec', optimize=optimized)
                    if status == 200:
                        exec(compiled, namespace)
                    else:
                        with self.assertRaises(AssertionError):
                            exec(compiled, namespace)
                    post.assert_called_once_with('/settings/reading',
                        dict(start_page='inbox', date_order='oldest'))
                    diagnostic = Mock(return_value='local_failure')
                    namespace['require'](True, diagnostic)
                    diagnostic.assert_not_called()
                    with self.assertRaisesRegex(AssertionError, 'local_failure'):
                        namespace['require'](False, diagnostic)
                    diagnostic.assert_called_once_with()

    def test_frontend_setup_does_not_inherit_guardian_helpers_import_clock(self):
        keeper = load('password_journey_clock', '../backend/local_frontend.py')
        now = time.monotonic()
        custody = {'schema':'osmap-http-web-custody-v1','web_uid':keeper.UID,
            'web_gid':keeper.GID,'binary_sha256':'a'*64,'selector':'local-selector',
            'web_pid':12346,'guardian_pid':12345,'guardian_group':12345}
        ready = {'schema':'osmap-http-password-ready-v1','port':1234,'connections':18,
            'totp_counter':int(time.time())//30}
        control = SimpleNamespace(write=Mock(), read=Mock(side_effect=[
            json.dumps(custody).encode(),json.dumps(ready).encode()]))
        guard = SimpleNamespace(END=now+1,Control=Mock(return_value=control),Capture=Mock(return_value=None))
        node = frontend_node(keeper)
        node.directory = node.file = node.capture_guardian_code = node.group = Mock()
        node.ownership_callback = None
        node.http_module = SimpleNamespace(FrontDriver=Mock(),JOURNEY_SECONDS=front.JOURNEY_SECONDS)
        child = SimpleNamespace(fileno=lambda:7,close=Mock())
        boot = dict.fromkeys(('alice_password','bob_password','new_password',
            'admission_key','mutation_key','session_proof_key'),'a'*64)
        boot['version'] = 1
        with patch.object(keeper,'module',return_value=guard), \
                patch.object(keeper,'END',now+600),patch.object(keeper,'WORK',now+450), \
                patch.object(keeper,'STAGE','/local-fixture'), \
                patch.object(keeper.socket,'socketpair',return_value=(object(),child)), \
                patch.object(keeper.signal,'pthread_sigmask',return_value=set()), \
                patch.object(keeper.subprocess,'Popen',return_value=SimpleNamespace(pid=12345)):
            node.setup(boot)
        guard.Capture.assert_called_once_with(node.guardian)
        self.assertEqual(guard.END,now+600)
        self.assertGreaterEqual(node.sequence_end,now+300)
        self.assertLessEqual(node.sequence_end,time.monotonic()+300)
        node.http_module.FrontDriver.assert_called_once_with(node,boot)

    def test_real_totp_wait_uses_existing_window_and_original_deadline(self):
        for deadline, succeeds in ((40, True), (10, False)):
            with self.subTest(deadline=deadline):
                clock = SimpleNamespace(elapsed=0.0)

                def advance(seconds):
                    self.assertGreater(seconds, 0)
                    self.assertLessEqual(seconds, .25)
                    clock.elapsed += seconds

                with patch.object(front, 'CANCEL', None), \
                        patch.object(time, 'monotonic', side_effect=lambda: clock.elapsed), \
                        patch.object(time, 'time', side_effect=lambda: 300.125 + clock.elapsed), \
                        patch.object(time, 'sleep', side_effect=advance):
                    if succeeds:
                        self.assertEqual(front.accepted_counter(deadline, minimum=12), (12, 1))
                        self.assertAlmostEqual(clock.elapsed, 29.875)
                    else:
                        with self.assertRaisesRegex(RuntimeError, 'original_http_deadline'):
                            front.accepted_counter(deadline, minimum=12)
                        self.assertEqual(clock.elapsed, deadline)

    def test_minimum_and_maximum_permitted_fresh_counter_waits(self):
        for delay, expected_wait in ((0, 60), (30, 0)):
            with self.subTest(delay=delay):
                clock = SimpleNamespace(elapsed=0.0)
                with patch.object(front, 'CANCEL', None), \
                        patch.object(time, 'monotonic', side_effect=lambda: clock.elapsed), \
                        patch.object(time, 'time', side_effect=lambda: 300 + clock.elapsed), \
                        patch.object(time, 'sleep', side_effect=lambda n: setattr(clock, 'elapsed', clock.elapsed+n)):
                    initial = front.accepted_counter(300)[0]
                    other = front.accepted_counter(300, initial+1)[0]
                    clock.elapsed += delay
                    stepup = front.accepted_counter(300, other+1)[0]
                    clock.elapsed += delay
                    fresh = front.accepted_counter(300, stepup+1)[0]
                self.assertEqual((initial,other,stepup,fresh),(10,11,12,13))
                self.assertEqual(clock.elapsed-2*delay, expected_wait)

    def test_full_journey_slow_valid_password_and_original_whole_timeout(self):
        # The real18-request producer/consumer and actual counter selector use a
        # deterministic clock. Only the native peer is substituted locally.
        for ceiling, mutation_seconds in ((300,59),(90,59),(300,300)):
            with self.subTest(ceiling=ceiling,mutation_seconds=mutation_seconds), tempfile.TemporaryDirectory() as name:
                clock=SimpleNamespace(elapsed=0.0)
                def advance(n):clock.elapsed+=n
                with patch.object(time,'monotonic',side_effect=lambda:clock.elapsed), \
                        patch.object(time,'time',side_effect=lambda:300.125+clock.elapsed), \
                        patch.object(time,'sleep',side_effect=advance):
                    peer=ControlledPeer(Path(name))
                    node=SimpleNamespace(cancelled=threading.Event(),http_root=Path(name),
                        socket_lock=threading.Lock(),http_stream=None,ready={'port':1},
                        sequence_end=ceiling,capture_generated_directories=lambda:None,
                        capture_replay_directory=lambda:None,exchange=peer.exchange,finish_http=peer.finish)
                    driver=front.FrontDriver(node,peer.boot)
                    original=peer.respond
                    def respond(raw):
                        advance(mutation_seconds if raw.startswith(b'POST /settings/password ') else 2)
                        return original(raw)
                    peer.respond=respond
                    with patch.object(front,'WEB_UID',os.getuid()),patch.object(front,'WEB_GID',os.getgid()), \
                            patch.object(front.socket,'create_connection',side_effect=lambda *a,**k:ControlledSocket(peer)):
                        if ceiling==300 and mutation_seconds==59:
                            result=password.journey(driver)
                            self.assertEqual(result['observed_http_requests'],18)
                            self.assertGreater(clock.elapsed,90)
                            self.assertEqual(driver.milestone_timings['mutation_seconds'],59)
                            self.assertTrue(peer.finished)
                        else:
                            with self.assertRaisesRegex(RuntimeError,'original_http_deadline'):
                                password.journey(driver)
                            self.assertFalse(peer.finished)
                    self.assertEqual(driver.sequence_end,ceiling)
                    self.assertEqual(driver.mutation_requests,1)
                    self.assertEqual(peer.writes,1)
                    self.assertEqual(sum(m=='POST'and p=='/settings/password'for m,p,_ in peer.requests),1)

    def test_timing_contract_report_and_prebirth_actor_reserve(self):
        guardian=load('timing_guardian','native_http_web_guardian.py')
        keeper=load('timing_keeper','../backend/local_frontend.py')
        self.assertEqual(front.JOURNEY_SECONDS,guardian.JOURNEY_SECONDS)
        self.assertEqual(guardian.END-guardian.BEGAN,330)
        self.assertEqual(keeper.END-keeper.WORK,150)
        rust=(ROOT.parents[2]/'src/http/password_tests.rs').read_text()
        self.assertIn('let deadline = began + Duration::from_secs(300);',rust)
        report={'schema':'osmap-http-password-runtime-v1','handled_connections':18,
            'elapsed_millis':299999,'alice_epoch0_refused':True,'alice_epoch1_admitted':1,'bob_epoch0_admitted':0}
        guardian.rust_report(json.dumps(report).encode())
        report['elapsed_millis']=300001
        with self.assertRaisesRegex(guardian.Refused,'rust_report'):
            guardian.rust_report(json.dumps(report).encode())
        node=frontend_node(keeper);node.http_module=front
        with patch.object(keeper,'WORK',329),patch.object(time,'monotonic',return_value=0), \
                patch.object(keeper.subprocess,'Popen') as spawn:
            with self.assertRaisesRegex(RuntimeError,'insufficient_original_journey_budget'):
                node.setup({})
            spawn.assert_not_called()

    def test_interrupted_frontend_cleanup_keeps_original_actor_end(self):
        keeper=load('timing_cleanup_keeper','../backend/local_frontend.py')
        node=frontend_node(keeper)
        node.cancelled=threading.Event();node.socket_lock=threading.Lock()
        node.http_stream=None;node.guardian=None;node.process_uncertain=False
        node.worker=SimpleNamespace(join=Mock(),is_alive=lambda:False)
        node.capture_generated_directories=Mock()
        with patch.object(keeper,'END',600),patch.object(keeper,'WORK',450), \
                patch.object(time,'monotonic',return_value=450):
            node.stop_requests()
            node.worker.join.assert_called_once_with(140)
            self.assertEqual(node.remaining(cleanup=True),150)
            self.assertEqual(keeper.END,600)
        self.assertTrue(node.cancelled.is_set()and node.requests_stopped)
        with patch.object(keeper,'END',600),patch.object(time,'monotonic',return_value=600):
            with self.assertRaisesRegex(RuntimeError,'original_frontend_horizon'):
                node.remaining(cleanup=True)

    def test_reaped_guardian_cleanup_confirms_absence_without_historical_signal(self):
        keeper = load('password_journey_keeper', '../backend/local_frontend.py')
        for absent in (True, False):
            with self.subTest(absent=absent):
                node = frontend_node(keeper)
                node.cancelled = threading.Event()
                node.socket_lock = threading.Lock()
                node.http_stream = node.control = node.worker = None
                node.guardian = SimpleNamespace(pid=12345, returncode=1)
                node.requests_stopped = node.process_uncertain = False
                node.group = Mock(side_effect=AssertionError('reaped identity must not be rediscovered'))
                node.capture_generated_directories = Mock()
                with patch.object(keeper.os, 'killpg',
                        side_effect=ProcessLookupError if absent else None) as signal_group:
                    if absent:
                        node.stop_requests()
                        self.assertTrue(node.requests_stopped)
                        node.capture_generated_directories.assert_called_once_with()
                    else:
                        with self.assertRaisesRegex(RuntimeError, 'unconfirmed_front_request_group'):
                            node.stop_requests()
                        self.assertFalse(node.requests_stopped)
                        node.capture_generated_directories.assert_not_called()
                    signal_group.assert_called_once_with(12345, 0)
                    node.group.assert_not_called()

    def test_front_program_preserves_failure_reason_and_incomplete_reap(self):
        keeper = load('password_journey_program', '../backend/local_frontend.py')
        for reap_fails in (False, True):
            with self.subTest(reap_fails=reap_fails):
                node = frontend_node(keeper)
                node.program_lock = threading.Lock()
                node.children = []
                node.report = {'groups': []}
                node.process_uncertain = False
                child = SimpleNamespace(pid=12345, returncode=-9,
                    stdout=SimpleNamespace(fileno=lambda: 3, close=Mock()),
                    stderr=SimpleNamespace(fileno=lambda: 4, close=Mock()),
                    wait=Mock(side_effect=keeper.subprocess.TimeoutExpired('ps', 1)
                        if reap_fails else None))
                selected = MagicMock()
                selected.__enter__.return_value = selected
                selected.select.side_effect = RuntimeError('front_program_io_deadline')
                with patch.object(keeper, 'WORK', time.monotonic() + 30), \
                        patch.object(keeper, 'END', time.monotonic() + 60), \
                        patch.object(keeper.subprocess, 'Popen', return_value=child), \
                        patch.object(keeper.signal, 'pthread_sigmask', return_value=set()), \
                        patch.object(keeper.selectors, 'DefaultSelector', return_value=selected), \
                        patch.object(keeper.os, 'set_blocking'), \
                        patch.object(keeper.os, 'killpg', side_effect=[None, ProcessLookupError]):
                    expected = keeper.subprocess.TimeoutExpired if reap_fails else RuntimeError
                    with self.assertRaises(expected) as caught:
                        node.run(('/bin/ps', '-ax', '-o', 'pid=,ppid=,pgid=,uid=,comm='), 'local_ps')
                if not reap_fails:
                    self.assertEqual(str(caught.exception), 'front_program_io_deadline')
                self.assertEqual(node.process_uncertain, reap_fails)
                self.assertEqual(node.report['groups'][0]['reaped'], not reap_fails)
                self.assertEqual(node.report['groups'][0]['group_gone'], not reap_fails)
                child.stdout.close.assert_called_once_with()
                child.stderr.close.assert_called_once_with()

    def test_authority_observation_uses_reserved_cleanup_without_renewing_end(self):
        backend = load('password_journey_backend', '../backend/rust_http_driver.py')
        for driver_module in (password, backend):
            with self.subTest(driver=driver_module.__name__):
                class Authority(driver_module.RustAuthoritativeCustodian):
                    def __init__(self):
                        self.reads = []

                    def remaining(self, cleanup=False):
                        left = (120 if cleanup else 90) - time.monotonic()
                        driver_module.require(left > 0, 'original_local_deadline')
                        return left

                    def row_read(self, cleanup=False):
                        self.remaining(cleanup)
                        self.reads.append(cleanup)
                        return [{**dict.fromkeys(driver_module.COLUMNS),
                            'username': account, 'password': 'local-verifier',
                            'modified': '2026-10-23 12:00:00'}
                            for account in driver_module.ACCOUNTS]

                    def private_read(self, path, cap):
                        self.remaining(True)
                        return b'{"epoch":0,"state":"active","changed_at":null,"intent":null,"used_intents":[]}'

                authority = Authority()
                with patch.object(time, 'monotonic', return_value=80):
                    initial = authority.authoritative_snapshot(driver_module.ALICE, 90)
                self.assertEqual(authority.reads, [False])
                with patch.object(time, 'monotonic', return_value=100):
                    with self.assertRaisesRegex(ValueError, 'original_local_deadline'):
                        authority.authoritative_snapshot(driver_module.ALICE, 120)
                    final = authority.authoritative_snapshot(driver_module.ALICE, 120, cleanup=True)
                self.assertEqual(initial, final)
                self.assertEqual(authority.reads, [False, True])
                with patch.object(time, 'monotonic', return_value=120):
                    with self.assertRaisesRegex(ValueError, 'snapshot_original_deadline'):
                        authority.authoritative_snapshot(driver_module.ALICE, 120, cleanup=True)
                self.assertEqual(authority.reads, [False, True])

    def exercise(self, fault=None):
        with tempfile.TemporaryDirectory() as name:
            root = Path(name)
            peer = ControlledPeer(root, fault)
            node = SimpleNamespace(cancelled=threading.Event(), http_root=root,
                socket_lock=threading.Lock(), http_stream=None, ready={'port': 1},
                sequence_end=time.monotonic() + front.JOURNEY_SECONDS, capture_generated_directories=lambda: None,
                capture_replay_directory=lambda: None, exchange=peer.exchange, finish_http=peer.finish)
            driver = front.FrontDriver(node, peer.boot)
            checkpoint_writes = []

            def checkpoint():
                password.require(driver.mutation_submission_started and driver.mutation_requests == 0,
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
        self.assertEqual(driver.mutation_requests, 0)
        self.assertFalse(any(method == 'POST' and path == '/settings/password'
            for method, path, _ in peer.requests))
        self.assertTrue(driver.mutation_submission_started)
        self.assertIsNone(result)


if __name__ == '__main__':
    unittest.main()
