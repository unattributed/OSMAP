"""Public isolated fixtures only: no native account, authentication or mail."""
import os
from pathlib import Path
import tempfile
import unittest

from account_epoch import EpochStore, PasswordCoordinator
from authoritative_password import AuthoritativePasswordAdapter, Receipt, Refused, Unconfirmed
from mail_session_containment import (MailSessionContainment, ContainmentExecutor,
                                     SmtpTerminationScope, build_native_containment)
from operation_budget import OperationBudget

ACCOUNT = 'alice@example.test'
CURRENT = 'public old fixture'
NEW = 'long public new fixture'


class CacheOrderingTests(unittest.TestCase):
    def test_cache_invalidation_precedes_positive_auth_after_write(self):
        calls = []
        cache = {'old': True}

        class Adapter:
            _account = staticmethod(AuthoritativePasswordAdapter._account)
            validate_new = staticmethod(AuthoritativePasswordAdapter.validate_new)

            def read(self, account):
                calls.append('read')
                return object()

            def replace(self, *args):
                calls.append('write')
                return Receipt('20261004170000')

        def invalidate(account):
            self.assertEqual(account, ACCOUNT)
            calls.append('flush')
            cache['old'] = False
            return True

        def changed(account, password):
            calls.append('new-auth')
            return cache['old'] is False

        with tempfile.TemporaryDirectory() as tmp:
            store = EpochStore(Path(tmp), os.getuid())
            store.provision(ACCOUNT)
            coordinator = PasswordCoordinator(store, Adapter(), lambda *args: True,
                                              changed, lambda account: True,
                                              lambda account: calls.append('kick-who') or True)
            # The previous coordinator ignores this dependency and tries new-auth
            # against stale cached state. This is an executed ordering countercase.
            coordinator.invalidate_changed_auth = invalidate
            self.assertEqual(coordinator.change(ACCOUNT, 0, 'a' * 64, CURRENT, NEW,
                                               NEW, 'public-factor', 1000),
                             (1, '20261004170000'))
            self.assertEqual(calls, ['read', 'write', 'flush', 'new-auth', 'kick-who'])


class FixtureClock:
    def __init__(self):
        self.now = 1000

    def __call__(self):
        return self.now


class PublicExecutor:
    def __init__(self):
        self.calls = []
        self.results = []

    def __call__(self, program, args, data, seconds, limit):
        self.calls.append((program, args, data, seconds, limit))
        if self.results:
            result = self.results.pop(0)
            if isinstance(result, BaseException):
                raise result
            if callable(result):
                return result()
            return result
        if args[0] == 'auth':
            return 0, b'0 cache entries flushed\n', b''
        if args[0] == 'kick':
            return 68, b'no users kicked\n', b''
        return 0, MailSessionContainment.WHO_HEADER, b''


class ContainmentTests(unittest.TestCase):
    def setUp(self):
        self.clock = FixtureClock()
        self.budget = OperationBudget(1300, monotonic=self.clock, wall=self.clock)
        self.executor = PublicExecutor()
        # Explicit reserved-account fixture scope, not actual SMTP qualification.
        self.dependency = MailSessionContainment(ACCOUNT, self.executor, self.budget,
                                                SmtpTerminationScope.NOT_APPLICABLE)

    def test_exact_scoped_ready_flush_kick_reconcile_order(self):
        self.assertIs(self.dependency.ready(ACCOUNT), True)
        self.assertIs(self.dependency.invalidate_changed_auth(ACCOUNT), True)
        self.assertIs(self.dependency.finish(ACCOUNT), True)
        commands = [call[1] for call in self.executor.calls]
        expected = MailSessionContainment.commands(ACCOUNT)
        self.assertEqual(commands, [expected['who'], expected['flush'], expected['kick'], expected['who']])
        for program, args, data, seconds, limit in self.executor.calls:
            self.assertEqual(program, '/usr/local/bin/doveadm')
            self.assertEqual(args[-1], ACCOUNT)
            self.assertEqual(data, b'')
            self.assertEqual(seconds, 10)
            self.assertEqual(limit, 4096)
        with self.assertRaises(Refused):
            self.dependency.finish(ACCOUNT)
        self.assertEqual(len(self.executor.calls), 4)

    def test_shared_remaining_budget_does_not_restart_per_phase(self):
        self.dependency.ready(ACCOUNT)
        self.clock.now = 1055
        self.dependency.invalidate_changed_auth(ACCOUNT)
        self.assertEqual(self.executor.calls[-1][3], 5)
        self.clock.now = 1060
        with self.assertRaises(Refused):
            self.dependency.finish(ACCOUNT)
        self.assertEqual(len(self.executor.calls), 2)

    def test_actual_smtp_required_or_unknown_refuses_before_commands(self):
        for scope in (SmtpTerminationScope.REQUIRED, SmtpTerminationScope.UNKNOWN):
            dependency = MailSessionContainment(ACCOUNT, self.executor, self.budget, scope)
            with self.assertRaises(Refused):
                dependency.ready(ACCOUNT)
        self.assertEqual(self.executor.calls, [])

    def test_default_native_factory_never_constructs_process_dependency(self):
        with self.assertRaises(Refused):
            build_native_containment(ACCOUNT, self.budget)
        self.assertEqual(self.executor.calls, [])

    def test_wildcards_options_foreign_account_and_early_finish_refused(self):
        for account in ('*', '*@example.test', '-f', 'a?@example.test', 'a\n@example.test'):
            with self.assertRaises(Refused):
                MailSessionContainment.commands(account)
        for action in (self.dependency.ready, self.dependency.invalidate_changed_auth,
                       self.dependency.finish):
            with self.assertRaises(Refused):
                action('bob@example.test')
        with self.assertRaises(Refused):
            self.dependency.finish(ACCOUNT)
        self.assertEqual(self.executor.calls, [])

    def test_preflight_existing_owned_connections_is_not_termination(self):
        row = ACCOUNT.encode() + b'\t1\timap\t(123)\t(192.0.2.1)\n'
        self.executor.results = [(0, self.dependency.WHO_HEADER + row, b'')]
        self.assertIs(self.dependency.ready(ACCOUNT), True)
        with self.assertRaises(Refused):
            self.dependency.finish(ACCOUNT)
        self.assertEqual(len(self.executor.calls), 1)

    def test_preflight_bad_acknowledgements_refuse_without_mutation(self):
        foreign = b'bob@example.test\t1\timap\t(123)\t(192.0.2.1)\n'
        for result in [(0, b'', b''), (0, b'anything', b''),
                       (0, self.dependency.WHO_HEADER + foreign, b''),
                       (0, self.dependency.WHO_HEADER + b'partial', b''),
                       (0, b'x' * 4097, b''), (1, self.dependency.WHO_HEADER, b''),
                       (0, self.dependency.WHO_HEADER, b'private fixture diagnostic'),
                       (True, self.dependency.WHO_HEADER, b'')]:
            executor = PublicExecutor()
            executor.results = [result]
            dependency = MailSessionContainment(ACCOUNT, executor, self.budget,
                                                SmtpTerminationScope.NOT_APPLICABLE)
            with self.assertRaises(Refused) as error:
                dependency.ready(ACCOUNT)
            self.assertNotIn('fixture', str(error.exception))
            self.assertEqual(len(executor.calls), 1)

    def test_flush_failure_is_unconfirmed_and_never_retried(self):
        for result in [(0, b'', b''), (0, b'4294967296 cache entries flushed\n', b''),
                       (1, b'0 cache entries flushed\n', b''),
                       (0, b'0 cache entries flushed\n', b'private fixture'),
                       TimeoutError('private fixture')]:
            executor = PublicExecutor()
            dependency = MailSessionContainment(ACCOUNT, executor, self.budget,
                                                SmtpTerminationScope.NOT_APPLICABLE)
            dependency.ready(ACCOUNT)
            executor.results = [result]
            with self.assertRaises(Unconfirmed) as error:
                dependency.invalidate_changed_auth(ACCOUNT)
            self.assertNotIn('private', str(error.exception))
            with self.assertRaises(Refused):
                dependency.invalidate_changed_auth(ACCOUNT)
            with self.assertRaises(Refused):
                dependency.finish(ACCOUNT)
            self.assertEqual(len(executor.calls), 2)

    def test_exact_kick_acknowledgement_and_zero_who_required(self):
        self.dependency.ready(ACCOUNT)
        self.dependency.invalidate_changed_auth(ACCOUNT)
        self.executor.results = [(0, b'kicked connections from the following users:\n'
                                  + ACCOUNT.encode() + b' \n', b'')]
        self.assertIs(self.dependency.finish(ACCOUNT), True)

    def test_no_users_acknowledgement_alone_is_not_empty_reconciliation(self):
        self.dependency.ready(ACCOUNT)
        self.dependency.invalidate_changed_auth(ACCOUNT)
        row = ACCOUNT.encode() + b'\t1\timap\t(123)\t(192.0.2.1)\n'
        self.executor.results = [(68, b'no users kicked\n', b''),
                                 (0, self.dependency.WHO_HEADER + row, b'')]
        with self.assertRaises(Unconfirmed):
            self.dependency.finish(ACCOUNT)
        with self.assertRaises(Refused):
            self.dependency.finish(ACCOUNT)
        self.assertEqual(len(self.executor.calls), 4)

    def test_foreign_kick_force_warning_or_ambiguous_receipt_never_reconcile(self):
        for result in [(0, b'kicked connections from the following users:\nbob@example.test \n', b''),
                       (0, b'warning: other connections would also be kicked', b''),
                       (0, b'no users kicked\n', b''), (68, b'', b''),
                       (0, b'', b'private fixture'), TimeoutError('private fixture')]:
            executor = PublicExecutor()
            dependency = MailSessionContainment(ACCOUNT, executor, self.budget,
                                                SmtpTerminationScope.NOT_APPLICABLE)
            dependency.ready(ACCOUNT)
            dependency.invalidate_changed_auth(ACCOUNT)
            executor.results = [result]
            with self.assertRaises(Unconfirmed):
                dependency.finish(ACCOUNT)
            self.assertEqual(len(executor.calls), 3)

    def test_late_callback_acknowledgement_refuses_with_shared_deadline(self):
        self.dependency.ready(ACCOUNT)
        def late():
            self.clock.now = 1060
            return 0, b'0 cache entries flushed\n', b''
        self.executor.results = [late]
        with self.assertRaises(Unconfirmed):
            self.dependency.invalidate_changed_auth(ACCOUNT)
        self.assertEqual(len(self.executor.calls), 2)

    def test_process_executor_refuses_unowned_program_args_input_or_bounds(self):
        executor = ContainmentExecutor(ACCOUNT, self.budget)
        args = self.dependency.commands(ACCOUNT)['kick']
        for program, command, stdin, seconds, limit in [
                ('/bin/sh', args, b'', 10, 4096),
                (self.dependency.PROGRAM, ('kick', '*'), b'', 10, 4096),
                (self.dependency.PROGRAM, ('kick', '-f', ACCOUNT), b'', 10, 4096),
                (self.dependency.PROGRAM, args[:-1] + ('bob@example.test',), b'', 10, 4096),
                (self.dependency.PROGRAM, args, b'public password fixture', 10, 4096),
                (self.dependency.PROGRAM, args, b'', float('nan'), 4096),
                (self.dependency.PROGRAM, args, b'', 10, 8192),
                (self.dependency.PROGRAM, args, b'', True, 4096)]:
            with self.assertRaises(Refused):
                executor(program, command, stdin, seconds, limit)


class DurableCoordinatorTests(unittest.TestCase):
    def test_missing_invalidation_dependency_refuses_before_any_sql(self):
        class Adapter:
            _account = staticmethod(AuthoritativePasswordAdapter._account)
            validate_new = staticmethod(AuthoritativePasswordAdapter.validate_new)
            def read(self, account):
                raise AssertionError('no read allowed')
        with tempfile.TemporaryDirectory() as tmp:
            store = EpochStore(Path(tmp), os.getuid())
            store.provision(ACCOUNT)
            path = next(Path(tmp).glob('*.json'))
            before = path.read_bytes()
            coordinator = PasswordCoordinator(store, Adapter(), lambda *a: True,
                                              lambda *a: True, lambda *a: True, lambda *a: True)
            with self.assertRaises(Refused):
                coordinator.change(ACCOUNT, 0, 'a' * 64, CURRENT, NEW, NEW, 'factor', 1000)
            self.assertEqual(path.read_bytes(), before)

    def test_smtp_dependency_refusal_preserves_credential_and_epoch(self):
        for scope in (SmtpTerminationScope.REQUIRED, SmtpTerminationScope.UNKNOWN):
            with tempfile.TemporaryDirectory() as tmp:
                store = EpochStore(Path(tmp), os.getuid())
                store.provision(ACCOUNT)
                path = next(Path(tmp).glob('*.json'))
                before = path.read_bytes()
                clock = FixtureClock()
                budget = OperationBudget(1300, monotonic=clock, wall=clock)
                executor = PublicExecutor()
                dependency = MailSessionContainment(ACCOUNT, executor, budget, scope)
                class Adapter:
                    _account = staticmethod(AuthoritativePasswordAdapter._account)
                    validate_new = staticmethod(AuthoritativePasswordAdapter.validate_new)
                    def read(self, account):
                        raise AssertionError('SMTP refusal before SQL')
                coordinator = PasswordCoordinator(store, Adapter(), lambda *a: True,
                                                  lambda *a: True, dependency.ready, dependency.finish,
                                                  dependency.invalidate_changed_auth)
                with self.assertRaises(Refused):
                    coordinator.change(ACCOUNT, 0, 'a' * 64, CURRENT, NEW, NEW, 'factor', 1000)
                self.assertEqual(path.read_bytes(), before)
                self.assertEqual(executor.calls, [])

    def test_postwrite_flush_failure_retains_containment_and_no_auth_finish_retry(self):
        calls = []
        class Adapter:
            _account = staticmethod(AuthoritativePasswordAdapter._account)
            validate_new = staticmethod(AuthoritativePasswordAdapter.validate_new)
            def read(self, account):
                return object()
            def replace(self, *args):
                calls.append('write')
                return Receipt('20261004170000')
        with tempfile.TemporaryDirectory() as tmp:
            store = EpochStore(Path(tmp), os.getuid())
            store.provision(ACCOUNT)
            coordinator = PasswordCoordinator(store, Adapter(), lambda *a: True,
                                              lambda *a: calls.append('new-auth') or True,
                                              lambda *a: True,
                                              lambda *a: calls.append('finish') or True,
                                              lambda *a: calls.append('flush') or False)
            with self.assertRaises(Unconfirmed):
                coordinator.change(ACCOUNT, 0, 'a' * 64, CURRENT, NEW, NEW, 'factor', 1000)
            with self.assertRaises(Refused):
                EpochStore(Path(tmp), os.getuid()).admission(ACCOUNT)
            with self.assertRaises(Refused):
                coordinator.change(ACCOUNT, 0, 'b' * 64, CURRENT, NEW, NEW, 'factor', 1000)
            self.assertEqual(calls, ['write', 'flush'])


class PrivateProcessTests(unittest.TestCase):
    def execute_public_child(self, script, maximum=60):
        import subprocess
        import sys
        import time
        from unittest.mock import patch
        budget = OperationBudget(int(time.time()) + 300, maximum_seconds=maximum)
        executor = ContainmentExecutor(ACCOUNT, budget)
        original = subprocess.Popen
        self.children = []
        self.invocations = []

        def public_child(argv, **kwargs):
            self.invocations.append((argv, kwargs))
            child = original((sys.executable, '-c', script), **kwargs)
            self.children.append(child)
            return child

        # Test-only Popen injection runs actual bounded public child processes.
        # It does not qualify the fixed native program, accounts or sockets.
        with patch('subprocess.Popen', public_child):
            return executor(MailSessionContainment.PROGRAM,
                            MailSessionContainment.commands(ACCOUNT)['flush'], b'', 10, 4096)

    def test_actual_public_process_bounded_output_and_private_transport(self):
        import subprocess
        result = self.execute_public_child("import sys; assert sys.stdin.buffer.read()==b''; print('0 cache entries flushed')")
        self.assertEqual(result, (0, b'0 cache entries flushed\n', b''))
        argv, kwargs = self.invocations[0]
        self.assertEqual(argv, (MailSessionContainment.PROGRAM,) + MailSessionContainment.commands(ACCOUNT)['flush'])
        self.assertEqual(kwargs['stdin'], subprocess.DEVNULL)
        self.assertEqual(kwargs['env'], {'PATH': '/usr/bin:/usr/local/bin', 'LC_ALL': 'C'})
        self.assertIs(kwargs['shell'], False)
        self.assertIs(kwargs['close_fds'], True)
        self.assertIs(kwargs['start_new_session'], True)
        self.assertEqual(self.children[0].poll(), 0)

    def test_actual_public_stdout_and_stderr_flood_refused_and_child_reaped(self):
        for stream in ('stdout', 'stderr'):
            with self.assertRaises(Refused):
                self.execute_public_child("import sys; sys." + stream + ".buffer.write(b'x'*10000)")
            self.assertIsNotNone(self.children[0].poll())

    def test_actual_shared_budget_timeout_kills_and_reaps_public_child(self):
        import time
        began = time.monotonic()
        with self.assertRaises((Refused, TimeoutError)):
            self.execute_public_child('import time; time.sleep(30)', maximum=0.1)
        self.assertLess(time.monotonic() - began, 2)
        self.assertIsNotNone(self.children[0].poll())


if __name__ == '__main__':
    unittest.main()
