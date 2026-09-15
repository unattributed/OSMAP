#!/usr/bin/env python3
"""Fail-closed orchestration tests for native synthetic qualification."""
import importlib.util
from pathlib import Path
import subprocess
import unittest
from unittest import mock

SPEC = importlib.util.spec_from_file_location(
    "native_check", Path(__file__).with_name("osmap-totp-native-check.py"))
native = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(native)


class NativeCheckTests(unittest.TestCase):
    def test_other_platform_is_refused_without_running_tests(self):
        with mock.patch.object(native.platform, "system", return_value="Linux"), \
                mock.patch.object(native.subprocess, "run") as run:
            with self.assertRaises(SystemExit):
                native.main()
            run.assert_not_called()

    def test_missing_dependency_is_refused_without_running_tests(self):
        with mock.patch.object(native.platform, "system", return_value="OpenBSD"), \
                mock.patch.object(native.shutil, "which", return_value=None), \
                mock.patch.object(native.subprocess, "run") as run:
            with self.assertRaises(SystemExit):
                native.main()
            run.assert_not_called()

    def run_fixture(self, fail=False):
        calls, scratch = [], []

        def run(command, *, env, check):
            self.assertTrue(check)
            directory = Path(env["PATH"].split(":")[0])
            scratch.append(directory)
            self.assertTrue((directory / "sha256sum").is_file())
            self.assertFalse((directory / "stat").exists())
            self.assertFalse((directory / "sha256").exists())
            calls.append(Path(command[1]).name)
            if fail:
                raise subprocess.CalledProcessError(1, command)

        with mock.patch.object(native.platform, "system", return_value="OpenBSD"), \
                mock.patch.object(native.shutil, "which", return_value="present"), \
                mock.patch.object(native.subprocess, "run", side_effect=run), \
                mock.patch("builtins.print"):
            if fail:
                with self.assertRaises(subprocess.CalledProcessError):
                    native.main()
            else:
                native.main()
        self.assertTrue(scratch)
        self.assertTrue(all(not path.exists() for path in scratch))
        return calls

    def test_runs_both_suites_without_adapting_native_remote_utilities(self):
        self.assertEqual(self.run_fixture(), ["test-osmap-totp-rotation.py",
                                              "test-osmap-totp-recovery.py"])

    def test_failed_suite_stops_and_cleans_scratch(self):
        self.assertEqual(self.run_fixture(fail=True), ["test-osmap-totp-rotation.py"])


if __name__ == "__main__":
    unittest.main()
