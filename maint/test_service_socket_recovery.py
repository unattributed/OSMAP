"""Real disposable Unix listeners; no application, key or mailbox access."""
import errno
import importlib.util
import os
import pathlib
import socket
import stat
import subprocess
import tempfile
import types
import unittest
from unittest import mock

spec = importlib.util.spec_from_file_location("recovery", pathlib.Path(__file__).with_name("service_socket_recovery.py"))
recovery = importlib.util.module_from_spec(spec)
spec.loader.exec_module(recovery)


class RecoveryTests(unittest.TestCase):
    def setUp(self):
        self.directory = tempfile.TemporaryDirectory(prefix="osmap-recovery-")
        self.root = pathlib.Path(self.directory.name)
        self.path = self.root / "listener.sock"
        self.uid = os.geteuid()
        self.process_calls = []

    def tearDown(self):
        self.directory.cleanup()

    def stopped(self, uid, prefixes):
        self.assertEqual(uid, self.uid)
        self.process_calls.append(prefixes)

    def stale(self):
        with socket.socket(socket.AF_UNIX, socket.SOCK_STREAM) as listener:
            listener.bind(str(self.path))
        self.path.chmod(0o660)

    def test_abandoned_actual_socket_recovers_after_two_absence_checks(self):
        self.stale()
        self.assertEqual(recovery.recover(self.path, self.uid, ("fixture",), self.stopped), "recovered")
        self.assertFalse(self.path.exists())
        self.assertEqual(self.process_calls, [("fixture",), ("fixture",)])

    def test_absent_listener_needs_no_cleanup_or_process_probe(self):
        self.assertEqual(recovery.recover(self.path, self.uid, (), self.stopped), "absent")
        self.assertEqual(self.process_calls, [])

    def test_observed_public_0755_stale_socket_recovers_under_private_parent(self):
        self.stale(); self.path.chmod(0o755)
        modes = recovery.SERVICES["osmap_public_inventory"][3]
        self.assertEqual(recovery.recover(self.path, self.uid, (), self.stopped, modes=modes), "recovered")
        self.assertFalse(self.path.exists())

    def test_observed_relay_0700_recovers_and_other_modes_refuse(self):
        self.stale(); self.path.chmod(0o700)
        modes = recovery.SERVICES["osmap_auth_relay"][3]
        self.assertEqual(recovery.recover(self.path, self.uid, (), self.stopped, modes=modes), "recovered")
        for mode in (0o777, 0o755, 0o666):
            self.stale(); self.path.chmod(mode)
            with self.subTest(mode=mode), self.assertRaises(recovery.Refused):
                recovery.recover(self.path, self.uid, (), self.stopped, modes=modes)
            self.path.unlink()

    def test_actual_live_listener_is_preserved_and_receives_zero_bytes(self):
        with socket.socket(socket.AF_UNIX, socket.SOCK_STREAM) as listener:
            listener.bind(str(self.path)); self.path.chmod(0o660); listener.listen(1)
            before = recovery.identity(self.path.lstat())
            with self.assertRaisesRegex(recovery.Refused, "live"):
                recovery.recover(self.path, self.uid, (), self.stopped)
            connection, _ = listener.accept()
            with connection:
                connection.settimeout(0.25)
                self.assertEqual(connection.recv(1), b"")
            self.assertEqual(recovery.identity(self.path.lstat()), before)

    def test_bound_before_listen_process_presence_refuses(self):
        with socket.socket(socket.AF_UNIX, socket.SOCK_STREAM) as listener:
            listener.bind(str(self.path)); self.path.chmod(0o660)
            with self.assertRaises(recovery.Refused):
                recovery.recover(self.path, self.uid, (), lambda *_: (_ for _ in ()).throw(recovery.Refused("present")))
            self.assertTrue(self.path.exists())

    def test_process_appearing_after_probe_refuses(self):
        self.stale()
        def check(*_):
            if self.process_calls:
                raise recovery.Refused("present")
            self.process_calls.append(True)
        with self.assertRaises(recovery.Refused):
            recovery.recover(self.path, self.uid, (), check)
        self.assertTrue(self.path.exists())

    def test_symlink_refused_without_touching_target(self):
        target = self.root / "target"
        target.write_text("preserved")
        self.path.symlink_to(target)
        with self.assertRaises(recovery.Refused):
            recovery.recover(self.path, self.uid, (), self.stopped)
        self.assertTrue(self.path.is_symlink())
        self.assertEqual(target.read_text(), "preserved")

    def test_regular_file_and_fifo_refused(self):
        for kind in ("file", "fifo"):
            with self.subTest(kind=kind):
                if kind == "file": self.path.write_text("preserved")
                else: os.mkfifo(self.path, 0o600)
                with self.assertRaises(recovery.Refused):
                    recovery.recover(self.path, self.uid, (), self.stopped)
                self.assertTrue(self.path.exists())
                self.path.unlink()

    def test_foreign_socket_owner_refused(self):
        self.stale()
        original = pathlib.Path.lstat
        def metadata(path):
            value = original(path)
            if path == self.path:
                return types.SimpleNamespace(st_mode=value.st_mode, st_uid=self.uid + 1)
            return value
        with mock.patch.object(pathlib.Path, "lstat", metadata), self.assertRaises(recovery.Refused):
            recovery.recover(self.path, self.uid, (), self.stopped)
        self.assertTrue(self.path.exists())

    def test_replacement_inode_refused(self):
        self.stale()
        old = self.root / "original.sock"
        def replace(path):
            path.rename(old)
            self.stale()
        with self.assertRaisesRegex(recovery.Refused, "changed"):
            recovery.recover(self.path, self.uid, (), self.stopped, replace)
        self.assertTrue(old.exists())
        self.assertTrue(self.path.exists())

    def test_changed_mode_refused(self):
        self.stale()
        with self.assertRaisesRegex(recovery.Refused, "changed"):
            recovery.recover(self.path, self.uid, (), self.stopped, lambda path: path.chmod(0o600))
        self.assertTrue(self.path.exists())

    def test_parent_mode_changed_after_probe_refuses(self):
        self.stale()
        with self.assertRaisesRegex(recovery.Refused, "parent changed"):
            recovery.recover(self.path, self.uid, (), self.stopped, lambda _: self.root.chmod(0o777))
        self.assertTrue(self.path.exists())
        self.root.chmod(0o700)

    def test_main_exclusive_lock_refusal_never_reaches_recovery(self):
        directory = types.SimpleNamespace(st_mode=stat.S_IFDIR | 0o755, st_uid=0)
        lock_info = types.SimpleNamespace(st_mode=stat.S_IFREG | 0o600, st_uid=0, st_nlink=1)
        with mock.patch.object(os, "geteuid", return_value=0), \
             mock.patch.object(recovery.sys, "argv", ["recovery", "osmap_auth_relay"]), \
             mock.patch.object(recovery.sys, "platform", "openbsd"), \
             mock.patch.object(recovery.pwd, "getpwnam", return_value=types.SimpleNamespace(pw_uid=123)), \
             mock.patch.object(pathlib.Path, "lstat", return_value=directory), \
             mock.patch.object(os, "open", return_value=42), \
             mock.patch.object(os, "fstat", return_value=lock_info), \
             mock.patch.object(recovery.fcntl, "flock", side_effect=BlockingIOError), \
             mock.patch.object(os, "close") as close, \
             mock.patch.object(recovery, "recover") as recover:
            with self.assertRaises(BlockingIOError): recovery.main()
            recover.assert_not_called()
            close.assert_called_once_with(42)

    def test_broad_parent_and_symlink_parent_refused(self):
        self.root.chmod(0o777)
        with self.assertRaises(recovery.Refused):
            recovery.recover(self.path, self.uid, (), self.stopped)
        self.root.chmod(0o700)
        alias = self.root / "alias"
        alias.symlink_to(self.root, target_is_directory=True)
        with self.assertRaises(recovery.Refused):
            recovery.recover(alias / "listener.sock", self.uid, (), self.stopped)

    def test_probe_other_error_refuses(self):
        for number in (errno.EACCES, errno.ENOENT, errno.EAGAIN, errno.ETIMEDOUT):
            with self.subTest(errno=number), mock.patch.object(socket.socket, "connect", side_effect=OSError(number, "fixture")):
                with self.assertRaises(recovery.Refused): recovery.refused_connection(self.path)

    def test_pgrep_absence_is_exact_and_bounded(self):
        with mock.patch.object(subprocess, "run", return_value=types.SimpleNamespace(returncode=1)) as run:
            recovery.absent_process(123, ("/a/b.py --purpose auth ",))
            self.assertEqual(run.call_args.args[0][:4], ["/usr/bin/pgrep", "-u", "123", "-f"])
            self.assertEqual(run.call_args.kwargs["timeout"], 2)
            self.assertEqual(run.call_args.kwargs["stdout"], subprocess.DEVNULL)
        for code in (0, 2, 255):
            with self.subTest(code=code), mock.patch.object(subprocess, "run", return_value=types.SimpleNamespace(returncode=code)):
                with self.assertRaises(recovery.Refused): recovery.absent_process(123, ("fixture",))

    def test_root_and_fixed_service_selection_required(self):
        with mock.patch.object(os, "geteuid", return_value=1000), self.assertRaises(recovery.Refused): recovery.main()
        with mock.patch.object(os, "geteuid", return_value=0), mock.patch.object(recovery.sys, "argv", ["recovery", "caller-path"]), self.assertRaises(recovery.Refused): recovery.main()


if __name__ == "__main__":
    unittest.main()
