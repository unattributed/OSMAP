"""Process startup and final pipe cleanup consume the original phase budget."""
import subprocess
import sys
import time
import unittest
from unittest.mock import call, patch

from authoritative_password import AuthoritativePasswordAdapter as Adapter
from native_transport_test_support import PublicFixtureExecutor as NativeExecutor
from authoritative_password import Refused
from operation_budget import OperationBudget


class PhaseDeadlineTests(unittest.TestCase):
    def test_containment_late_reaped_child_never_receives_another_signal(self):
        from mail_session_containment import ContainmentExecutor
        now = [100.0]
        budget = OperationBudget(1000, monotonic=lambda: now[0], wall=lambda: 100)
        executor = ContainmentExecutor('alice@example.test', budget)
        executor._program = sys.executable
        args = ('-I', '-c', 'print("public synthetic")')
        executor._commands = (args,)
        real_popen = subprocess.Popen
        children = []

        def late_wait(*argv, **kwargs):
            child = real_popen(*argv, **kwargs)
            children.append(child)
            real_wait = child.wait

            def wait(*wait_args, **wait_kwargs):
                code = real_wait(*wait_args, **wait_kwargs)
                now[0] += 11.0
                return code

            child.wait = wait
            return child

        with patch('subprocess.Popen', side_effect=late_wait), \
                patch('time.monotonic', side_effect=lambda: now[0]), \
                patch('os.killpg', side_effect=ProcessLookupError) as signal_group:
            with self.assertRaises(TimeoutError):
                executor(sys.executable, args, b'', 10, 4096)
        self.assertEqual(children[0].returncode, 0)
        self.assertEqual(signal_group.call_args_list, [call(children[0].pid, 0)])
        self.assertTrue(all(pipe.closed for pipe in
                            (children[0].stdout, children[0].stderr)))

    def test_containment_process_startup_cannot_restart_phase_deadline(self):
        from mail_session_containment import ContainmentExecutor
        now = [100.0]
        budget = OperationBudget(1000, monotonic=lambda: now[0], wall=lambda: 100)
        executor = ContainmentExecutor('alice@example.test', budget)
        executor._program = sys.executable
        args = ('-I', '-c', 'print("public synthetic")')
        executor._commands = (args,)
        real_popen = subprocess.Popen
        children = []

        def delayed_start(*argv, **kwargs):
            child = real_popen(*argv, **kwargs)
            children.append(child)
            now[0] += 11.0
            return child

        with patch('subprocess.Popen', side_effect=delayed_start), \
                patch('time.monotonic', side_effect=lambda: now[0]):
            with self.assertRaises(TimeoutError):
                executor(sys.executable, args, b'', 10, 4096)
        self.assertEqual(len(children), 1)
        self.assertIsNotNone(children[0].returncode)
        self.assertTrue(all(pipe.closed for pipe in
                            (children[0].stdout, children[0].stderr)))

    def test_operation_without_owned_group_refuses_before_process_startup(self):
        from authoritative_password import NativeExecutor as ProductionNativeExecutor
        budget = OperationBudget(int(time.time()) + 30)
        with patch('subprocess.Popen', side_effect=AssertionError('unowned process started')) as spawn:
            with self.assertRaises(Refused):
                ProductionNativeExecutor(budget)(Adapter.SQL_PROGRAM, Adapter.SQL_ARGS, b'', 10, 4096)
            spawn.assert_not_called()

    def test_process_startup_cannot_restart_phase_deadline(self):
        # Real disposable process, deterministic elapsed clock: startup consumes
        # eleven seconds of the existing ten-second phase, without a long sleep.
        now = [100.0]
        real_popen = subprocess.Popen
        children = []
        script = 'import sys; sys.stdout.buffer.write(b"public synthetic")'

        def delayed_start(*args, **kwargs):
            child = real_popen(*args, **kwargs)
            children.append(child)
            now[0] += 11.0
            return child

        with patch.object(Adapter, 'SQL_PROGRAM', sys.executable), \
                patch.object(Adapter, 'SQL_ARGS', ('-c', script)), \
                patch('subprocess.Popen', side_effect=delayed_start), \
                patch('time.monotonic', side_effect=lambda: now[0]):
            with self.assertRaises(TimeoutError):
                NativeExecutor()(sys.executable, ('-c', script), b'', 10, 4096)
        self.assertEqual(len(children), 1)
        self.assertIsNotNone(children[0].returncode)
        self.assertTrue(all(pipe.closed for pipe in
                            (children[0].stdin, children[0].stdout, children[0].stderr)))


if __name__ == '__main__':
    unittest.main()
