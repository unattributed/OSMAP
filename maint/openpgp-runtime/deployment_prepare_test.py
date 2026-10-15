"""Disposable foreground listener; no application, account or key operations."""
import importlib.util
import os
import pathlib
import re
import shutil
import signal
import socket
import subprocess
import tempfile
import unittest


HERE = pathlib.Path(__file__).resolve().parent
KSH = shutil.which("ksh")
spec = importlib.util.spec_from_file_location("deployment_prepare", HERE / "deployment_prepare.py")
prepare = importlib.util.module_from_spec(spec)
spec.loader.exec_module(prepare)
RECOVERY = pathlib.Path(os.environ.get("OSMAP_TEST_RECOVERY_SOURCE", HERE.parent / "service_socket_recovery.py"))
spec = importlib.util.spec_from_file_location("socket_recovery", RECOVERY)
recovery = importlib.util.module_from_spec(spec)
spec.loader.exec_module(recovery)

FIXTURE = r'''
#include <sys/socket.h>
#include <sys/un.h>
#include <unistd.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
int main(int argc, char **argv) {
    struct sockaddr_un address = {0};
    const char *path = getenv("OSMAP_TEST_SOCKET");
    if (argc != 3 || !path || strlen(path) >= sizeof(address.sun_path)) return 1;
    (void) argv;
    int fd = socket(AF_UNIX, SOCK_STREAM, 0);
    if (fd == -1) return 2;
    address.sun_family = AF_UNIX;
#ifdef __OpenBSD__
    address.sun_len = sizeof(address);
#endif
    memcpy(address.sun_path, path, strlen(path) + 1);
    if (bind(fd, (struct sockaddr *)&address, sizeof(address)) || listen(fd, 1)) return 3;
    printf("%ld\n", (long)getpid()); fflush(stdout);
    for (;;) pause();
}
'''


class CryptoServiceScripts(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.directory = tempfile.TemporaryDirectory(prefix="osmap-rc-")
        cls.root = pathlib.Path(cls.directory.name)
        for name in ("bin", "config", "run"):
            (cls.root / name).mkdir(mode=0o700)
        cls.binary = cls.root / "bin/osmap_crypto_helper"
        source = cls.root / "listener.c"
        source.write_text(FIXTURE)
        subprocess.run([shutil.which("cc"), "-Wall", "-Wextra", "-Werror", str(source), "-o", str(cls.binary)], check=True, timeout=10)
        cls.old_root = prepare.ROOT
        prepare.ROOT = cls.root
        cls.wrapper = cls.root / "bin/osmap_crypto-run.ksh"
        cls.socket = cls.root / "run/crypto.sock"
        for name in ("crypto.json", "crypto.key"):
            (cls.root / "config" / name).write_text("synthetic fixture only\n")

    @classmethod
    def tearDownClass(cls):
        prepare.ROOT = cls.old_root
        cls.directory.cleanup()

    def start(self, legacy=False):
        wrapper, _ = prepare.crypto_service_scripts()
        if legacy:
            # Exact previous background-child/trap structure. No product file
            # or standard service is executed by this regression control.
            wrapper = wrapper.replace('exec "', '"')
            wrapper = wrapper.rstrip() + ' &\nchild=$!\n'
            wrapper += 'cleanup() { kill "$child" 2>/dev/null || true; wait "$child" 2>/dev/null || true; [ ! -S "$socket" ] || rm -f "$socket"; }\n'
            wrapper += 'trap cleanup EXIT HUP INT TERM\nwait "$child"\n'
        self.wrapper.write_text(wrapper)
        self.wrapper.chmod(0o700)
        process = subprocess.Popen([KSH, str(self.wrapper)], stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True,
                                   env=dict(os.environ, OSMAP_TEST_SOCKET=str(self.socket)), start_new_session=True)
        self.addCleanup(self.stop, process)
        # Output is emitted only after the real kernel listen succeeds.
        import select
        self.assertTrue(select.select([process.stdout], [], [], 2)[0], "listener startup timed out")
        pid = int(process.stdout.readline())
        return process, pid

    def stop(self, process):
        if process.poll() is None:
            os.killpg(process.pid, signal.SIGTERM)
            try:
                process.wait(timeout=2)
            except subprocess.TimeoutExpired:
                os.killpg(process.pid, signal.SIGKILL)
                process.wait(timeout=2)
        process.stdout.close()
        process.stderr.close()
        if self.socket.exists():
            self.socket.unlink()

    def test_managed_pid_is_the_listener_not_a_background_child(self):
        process, listener_pid = self.start(legacy=os.environ.get("OSMAP_TEST_OLD_WRAPPER") == "1")
        self.assertEqual(listener_pid, process.pid)
        self.assertIsNone(process.poll())
        with socket.socket(socket.AF_UNIX, socket.SOCK_STREAM) as probe:
            probe.settimeout(0.25)
            probe.connect(str(self.socket))

    def test_term_reaps_listener_and_only_dead_socket_recovery_removes_inode(self):
        process, listener_pid = self.start()
        self.assertEqual(listener_pid, process.pid)
        self.socket.chmod(0o660)
        original = recovery.identity(self.socket.lstat())
        with self.assertRaisesRegex(recovery.Refused, "present"):
            recovery.recover(self.socket, os.getuid(), (str(self.binary) + " ",))
        self.assertEqual(recovery.identity(self.socket.lstat()), original)
        process.terminate()
        self.assertEqual(process.wait(timeout=2), -signal.SIGTERM)
        self.assertTrue(self.socket.exists(), "no shell may unlink on an unverified stop")
        self.assertEqual(recovery.recover(self.socket, os.getuid(), (str(self.binary) + " ",)), "recovered")
        self.assertFalse(self.socket.exists())

    def test_existing_live_socket_is_preserved_before_exec(self):
        with socket.socket(socket.AF_UNIX, socket.SOCK_STREAM) as listener:
            listener.bind(str(self.socket)); listener.listen(1)
            original = recovery.identity(self.socket.lstat())
            wrapper, _ = prepare.crypto_service_scripts()
            self.wrapper.write_text(wrapper)
            result = subprocess.run([KSH, str(self.wrapper)], stdin=subprocess.DEVNULL,
                                    stdout=subprocess.PIPE, stderr=subprocess.PIPE, timeout=2)
            self.assertNotEqual(result.returncode, 0)
            self.assertEqual(recovery.identity(self.socket.lstat()), original)
        self.socket.unlink()

    def test_rc_matches_only_exact_helper_arguments_and_keeps_fixed_recovery(self):
        wrapper, rc = prepare.crypto_service_scripts()
        pattern = next(line for line in rc.splitlines() if line.startswith("pexp=")).split('"')[1]
        exact = f"{self.binary} {self.root}/config/crypto.json {self.root}/config/crypto.key"
        self.assertIsNotNone(re.fullmatch(pattern, exact))
        for changed in (exact + " other", exact.replace("crypto.json", "cryptoXjson"), f"/bin/ksh {self.wrapper}"):
            self.assertIsNone(re.fullmatch(pattern, changed))
        self.assertIn("service_socket_recovery.py osmap_crypto\n", rc)
        self.assertNotIn("rm ", wrapper)
        self.assertNotIn("trap ", wrapper)
        self.assertEqual(subprocess.run([KSH, "-n"], input=wrapper.encode(), timeout=2).returncode, 0)
        self.assertEqual(subprocess.run([KSH, "-n"], input=rc.encode(), timeout=2).returncode, 0)


if __name__ == "__main__":
    unittest.main()
