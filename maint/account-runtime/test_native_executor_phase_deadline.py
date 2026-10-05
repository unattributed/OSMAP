"""Process startup and final pipe cleanup consume the original phase budget."""
import subprocess
import sys
import time
import unittest
from unittest.mock import patch

from authoritative_password import AuthoritativePasswordAdapter as Adapter, NativeExecutor
from authoritative_password import Refused
from operation_budget import OperationBudget


class PhaseDeadlineTests(unittest.TestCase):
    def test_operation_without_owned_group_refuses_before_process_startup(self):
        budget = OperationBudget(int(time.time()) + 30)
        with patch('subprocess.Popen', side_effect=AssertionError('unowned process started')) as spawn:
            with self.assertRaises(Refused):
                NativeExecutor(budget)(Adapter.SQL_PROGRAM, Adapter.SQL_ARGS, b'', 10, 4096)
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
