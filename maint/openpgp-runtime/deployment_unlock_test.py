#!/usr/bin/env python3
"""Focused mailbox-agent policy tests; never imports or unlocks a real key.

Run native verification on obsd1 with OSMAP_UNLOCK_NATIVE=1. It replaces only
an agent in disposable scratch and checks the running process configuration.
"""
import importlib.util
import os
import pathlib
import socket
import subprocess
import tempfile
import time
import unittest
from unittest.mock import patch

SOURCE = pathlib.Path(__file__).with_name("deployment_unlock.py")
SPEC = importlib.util.spec_from_file_location("deployment_unlock", SOURCE)
unlock = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(unlock)


class AgentPolicyTests(unittest.TestCase):
    def test_stopped_helpers_are_checked_without_secret_input(self):
        calls = []

        def run(command, **kwargs):
            calls.append(command)
            self.assertEqual(kwargs["stdin"], subprocess.DEVNULL)
            self.assertEqual(kwargs["timeout"], 15)
            return subprocess.CompletedProcess(command, 1)

        unlock.require_stopped_helpers({}, run)
        self.assertEqual([c[-1] for c in calls],
                         ["osmap_crypto", "osmap_public_inventory", "osmap_public_admin"])

    def test_running_or_unknown_helper_state_refuses(self):
        for status in (0, 2):
            with self.subTest(status=status), self.assertRaises(AssertionError):
                unlock.require_stopped_helpers({}, lambda command, **_: subprocess.CompletedProcess(command, status))

    def test_existing_agent_is_replaced_with_bounded_cache(self):
        with tempfile.TemporaryDirectory(prefix="osmap-unlock-policy-") as directory:
            home = pathlib.Path(directory)
            agent_socket = home / "S.gpg-agent"
            agent_socket.touch()
            calls = []

            def run(command, **kwargs):
                calls.append(command)
                self.assertEqual(kwargs["stdin"], subprocess.DEVNULL)
                self.assertEqual(kwargs["stdout"], subprocess.DEVNULL)
                self.assertEqual(kwargs["stderr"], subprocess.DEVNULL)
                self.assertEqual(kwargs["cwd"], home)
                self.assertEqual(kwargs["timeout"], 15)
                self.assertNotIn("input", kwargs)
                if command[0].endswith("gpgconf"):
                    agent_socket.unlink()
                return subprocess.CompletedProcess(command, 0)

            unlock.restart_bounded_agent(home, {}, None, run)
            self.assertEqual(len(calls), 2)
            self.assertEqual(calls[0][-2:], ["--kill", "gpg-agent"])
            agent = calls[1]
            for option in ("--default-cache-ttl", "--max-cache-ttl"):
                self.assertEqual(agent[agent.index(option) + 1], "300")
            self.assertIn("--no-allow-external-cache", agent)
            self.assertIn("--no-options", agent)

    def test_failed_agent_stop_or_start_never_reuses_existing_policy(self):
        with tempfile.TemporaryDirectory(prefix="osmap-unlock-policy-") as directory:
            home = pathlib.Path(directory)
            calls = []

            def failure(command, **_):
                calls.append(command)
                return subprocess.CompletedProcess(command, 1)

            with self.assertRaises(AssertionError):
                unlock.restart_bounded_agent(home, {}, None, failure)
            self.assertEqual(len(calls), 1)
            calls.clear()

            def startup_failure(command, **_):
                calls.append(command)
                return subprocess.CompletedProcess(command, int(command[0].endswith("gpg-agent")))

            with self.assertRaises(AssertionError):
                unlock.restart_bounded_agent(home, {}, None, startup_failure)
            self.assertEqual(len(calls), 2)

    def test_stale_socket_refuses_new_daemon_after_bounded_wait(self):
        with tempfile.TemporaryDirectory(prefix="osmap-unlock-policy-") as directory:
            home = pathlib.Path(directory)
            (home / "S.gpg-agent").touch()
            calls = []

            def stopped(command, **_):
                calls.append(command)
                return subprocess.CompletedProcess(command, 0)

            with patch.object(unlock.time, "monotonic", side_effect=[0, 6]), self.assertRaises(AssertionError):
                unlock.restart_bounded_agent(home, {}, None, stopped)
            self.assertEqual(len(calls), 1)

    @unittest.skipUnless(os.environ.get("OSMAP_UNLOCK_NATIVE") == "1", "requires disposable obsd1 native agent")
    def test_native_existing_agent_is_replaced_and_actual_flags_are_bounded(self):
        self.assertEqual(socket.gethostname(), "obsd1.blackbagsecurity.com")
        with tempfile.TemporaryDirectory(prefix="osmap-unlock-native-") as directory:
            home = pathlib.Path(directory)
            env = {"PATH": "/usr/local/bin:/usr/bin:/bin", "LC_ALL": "C", "HOME": directory}

            def pid():
                result = subprocess.run(["/usr/local/bin/gpg-connect-agent", "--homedir", directory,
                                         "--no-autostart", "GETINFO pid", "/bye"],
                                        env=env, capture_output=True, timeout=10, check=True)
                return int(next(line[2:] for line in result.stdout.decode().splitlines() if line.startswith("D ")))

            try:
                subprocess.run(["/usr/local/bin/gpg-agent", "--no-options", "--homedir", directory, "--daemon"],
                               env=env, stdin=subprocess.DEVNULL, stdout=subprocess.DEVNULL,
                               stderr=subprocess.DEVNULL, timeout=15, check=True)
                old = pid()
                unlock.restart_bounded_agent(home, env, None)
                current = pid()
                self.assertNotEqual(old, current)
                command = subprocess.check_output(["/bin/ps", "-ww", "-p", str(current), "-o", "args="], env=env, timeout=10).decode()
                self.assertIn("--default-cache-ttl 300", command)
                self.assertIn("--max-cache-ttl 300", command)
                self.assertIn("--no-allow-external-cache", command)
                self.assertEqual(list((home / "private-keys-v1.d").glob("*.key")), [])
            finally:
                subprocess.run(["/usr/local/bin/gpgconf", "--homedir", directory, "--kill", "gpg-agent"],
                               env=env, capture_output=True, timeout=15, check=True)
                until = time.monotonic() + 5
                while (home / "S.gpg-agent").exists() and time.monotonic() < until:
                    time.sleep(0.02)
                self.assertFalse((home / "S.gpg-agent").exists())


if __name__ == "__main__":
    unittest.main(verbosity=2)
