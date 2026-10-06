import math
import os
from pathlib import Path
import subprocess
import sys
import time
import unittest
from unittest.mock import patch

from authoritative_password import AuthoritativePasswordAdapter as Adapter, NativeExecutor, Refused
from operation_budget import OperationBudget
from native_transport_test_support import OwnedFixtureExecutor


class Clock:
    def __init__(self):
        self.mono = 100.0
        self.wall = 1000.0

    def budget(self, expires=1300, seconds=60):
        return OperationBudget(expires, maximum_seconds=seconds,
                               monotonic=lambda: self.mono, wall=lambda: self.wall)


class BudgetTests(unittest.TestCase):
    def _owned_group_case(self):
        # Transport positives require a real disposable session leader. Never
        # turn a false ownership check into a test-only constant-True callback.
        if os.getpid() == os.getpgrp():
            return False
        directory = str(Path(__file__).resolve().parent)
        source = ('import sys,unittest; sys.path.insert(0,' + repr(directory) + '); '
                  'suite=unittest.defaultTestLoader.loadTestsFromName(' +
                  repr('test_operation_budget.BudgetTests.' + self._testMethodName) + '); '
                  'result=unittest.TextTestRunner().run(suite); '
                  'sys.exit(not result.wasSuccessful())')
        result = subprocess.run((sys.executable, '-B', '-c', source),
                                start_new_session=True, capture_output=True, timeout=3)
        self.assertEqual(result.returncode, 0, result.stderr.decode('utf-8', 'replace'))
        return True

    def test_shared_phases_cannot_restart_total_window(self):
        clock = Clock()
        budget = clock.budget()
        self.assertEqual(budget.cap_seconds(10), 10)
        clock.mono += 55
        clock.wall += 55
        self.assertEqual(budget.cap_seconds(10), 5)
        clock.mono += 5
        clock.wall += 5
        with self.assertRaises(Refused):
            budget.cap_seconds(10)

    def test_prepared_expiry_boundary_can_be_earlier_than_process_budget(self):
        clock = Clock()
        budget = clock.budget(expires=1005)
        self.assertEqual(budget.cap_seconds(25), 5)
        clock.wall = 1005
        with self.assertRaises(Refused):
            budget.remaining()

    def test_clock_rollback_and_invalid_samples_refuse(self):
        for field, value in [('mono', 99), ('wall', 999), ('mono', math.nan),
                             ('wall', math.inf), ('wall', True)]:
            clock = Clock()
            budget = clock.budget()
            setattr(clock, field, value)
            with self.assertRaises(Refused):
                budget.remaining()

    def test_invalid_total_and_phase_caps_do_not_relax_limits(self):
        clock = Clock()
        for seconds in [0, -1, 61, True, math.inf, math.nan]:
            with self.assertRaises(Refused):
                clock.budget(seconds=seconds)
        budget = clock.budget()
        for seconds in [0, -1, 61, True, math.inf, math.nan]:
            with self.assertRaises(Refused):
                budget.cap_seconds(seconds)

    def test_untyped_budget_cannot_supply_an_unbounded_native_deadline(self):
        with self.assertRaises(Refused):
            NativeExecutor(object())

    def test_real_child_uses_remaining_total_and_is_reaped_on_timeout(self):
        if self._owned_group_case():
            return
        script = 'import time; time.sleep(5)'
        children = []
        original = subprocess.Popen

        def track(*args, **kwargs):
            child = original(*args, **kwargs)
            children.append(child)
            return child

        budget = OperationBudget(int(time.time()) + 300, maximum_seconds=0.08)
        budget.attach_owned_process_group()
        began = time.monotonic()
        with patch.object(Adapter, 'SQL_PROGRAM', sys.executable), \
                patch.object(Adapter, 'SQL_ARGS', ('-c', script)), \
                patch.object(subprocess, 'Popen', track):
            with self.assertRaises((Refused, TimeoutError)):
                OwnedFixtureExecutor(budget)(sys.executable, ('-c', script), b'fixture', 10, 4096)
        self.assertEqual(len(children), 1)
        self.assertIsNotNone(children[0].poll())
        self.assertLess(time.monotonic() - began, 1)

    def test_expired_budget_refuses_before_starting_another_process(self):
        clock = Clock()
        executor = NativeExecutor(clock.budget())
        clock.mono += 60
        clock.wall += 60
        with patch.object(subprocess, 'Popen') as start:
            with self.assertRaises(Refused):
                executor(Adapter.SQL_PROGRAM, Adapter.SQL_ARGS, b'fixture', 10, 4096)
            start.assert_not_called()

    def test_two_real_phases_share_one_deadline(self):
        if self._owned_group_case():
            return
        script = 'import time; time.sleep(0.05); print("fixture")'
        budget = OperationBudget(int(time.time()) + 300, maximum_seconds=0.14)
        budget.attach_owned_process_group()
        with patch.object(Adapter, 'SQL_PROGRAM', sys.executable), \
                patch.object(Adapter, 'SQL_ARGS', ('-c', script)):
            executor = OwnedFixtureExecutor(budget)
            self.assertEqual(executor(sys.executable, ('-c', script), b'fixture', 10, 4096)[0], 0)
            time.sleep(0.08)
            with self.assertRaises((Refused, TimeoutError)):
                executor(sys.executable, ('-c', script), b'fixture', 10, 4096)

    def test_successful_wait_cannot_return_after_prepared_wall_expiry(self):
        if self._owned_group_case():
            return
        clock = Clock()
        budget = clock.budget()
        budget.attach_owned_process_group()
        script = 'pass'
        original = subprocess.Popen
        children = []

        def track(*args, **kwargs):
            child = original(*args, **kwargs)
            children.append(child)
            original_wait = child.wait

            def wait(*args, **kwargs):
                result = original_wait(*args, **kwargs)
                clock.wall = 1300
                return result

            child.wait = wait
            return child

        with patch.object(Adapter, 'SQL_PROGRAM', sys.executable), \
                patch.object(Adapter, 'SQL_ARGS', ('-c', script)), \
                patch.object(subprocess, 'Popen', track):
            with self.assertRaises(Refused):
                OwnedFixtureExecutor(budget)(sys.executable, ('-c', script), b'fixture', 10, 4096)
        self.assertEqual(len(children), 1)
        self.assertIsNotNone(children[0].returncode)


if __name__ == '__main__':
    unittest.main()
