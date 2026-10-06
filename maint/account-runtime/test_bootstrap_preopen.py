"""Actual writerless FIFO admission, public files and owned child cleanup only."""
import os
from pathlib import Path
import selectors
import subprocess
import sys
import tempfile
import time
import unittest

if __name__ == '__main__':
    sys.path.insert(0, str(Path(__file__).resolve().parent))

import account_mutation_supervisor as supervisor


def child(root, name, replace):
    descriptor = os.open(root, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW)
    original = os.open

    def observed(path, flags, *args, **kwargs):
        if path == name and kwargs.get('dir_fd') == descriptor:
            if replace:
                os.unlink(path, dir_fd=descriptor)
                os.mkfifo(path, 0o600, dir_fd=descriptor)
            os.write(1, b'OPEN\n')
        return original(path, flags, *args, **kwargs)

    supervisor.os.open = observed
    try:
        try:
            supervisor._private(descriptor, name, os.getuid(), 16384)
        except supervisor.Unavailable:
            os.write(1, b'REFUSED\n')
            return 0
        return 2
    finally:
        os.close(descriptor)


class BootstrapPreopenTests(unittest.TestCase):
    def refused(self, name, replace):
        # Bootstrap ancestry excludes writable shared ancestors. Keep this
        # owner-only synthetic directory under the actual home, as its suite does.
        with tempfile.TemporaryDirectory(dir=str(Path.home())) as directory:
            root = Path(directory)
            path = root / name
            if replace:
                path.write_bytes(b'public synthetic material')
                path.chmod(0o600)
            else:
                os.mkfifo(path, 0o600)
            process = subprocess.Popen((sys.executable, '-I', '-B', __file__,
                '--owned-fifo-child', directory, name, 'replace' if replace else 'fifo'),
                stdout=subprocess.PIPE, stderr=subprocess.PIPE, close_fds=True,
                env={'PATH': '/usr/bin:/bin', 'LC_ALL': 'C'})
            began = time.monotonic()
            output = bytearray()
            witnessed = False
            try:
                os.set_blocking(process.stdout.fileno(), False)
                with selectors.DefaultSelector() as selector:
                    selector.register(process.stdout, selectors.EVENT_READ)
                    while time.monotonic() - began < 1:
                        for key, _ in selector.select(.01):
                            part = os.read(key.fileobj.fileno(), 128)
                            if not part:
                                selector.unregister(key.fileobj)
                                break
                            output.extend(part)
                            self.assertLessEqual(len(output), 128)
                            witnessed = b'OPEN\n' in output
                        if not selector.get_map():
                            break
                self.assertTrue(witnessed, 'did not reach the actual file open')
                self.assertEqual(bytes(output), b'OPEN\nREFUSED\n',
                    'writerless material blocked admission before fstat')
                self.assertEqual(process.wait(timeout=.2), 0)
                self.assertEqual(process.stderr.read(), b'')
                self.assertLess(time.monotonic() - began, 1)
            finally:
                # Only this direct unreaped Popen child; never a retained PID.
                if process.returncode is None:
                    process.kill()
                    process.wait(timeout=1)
                process.stdout.close()
                process.stderr.close()

    def test_writerless_bootstrap_material_refuses_without_blocking(self):
        for name in ('config.json', 'mutation.key', 'session-proof.key'):
            with self.subTest(name=name):
                self.refused(name, False)

    def test_replacement_at_actual_open_refuses_without_blocking(self):
        for name in ('config.json', 'mutation.key', 'session-proof.key'):
            with self.subTest(name=name):
                self.refused(name, True)

    def test_ordinary_private_material_preserves_exact_bytes(self):
        with tempfile.TemporaryDirectory(dir=str(Path.home())) as directory:
            root = Path(directory)
            path = root / 'config.json'
            path.write_bytes(b'public synthetic material')
            path.chmod(0o600)
            descriptor = os.open(root, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW)
            try:
                self.assertEqual(supervisor._private(descriptor, path.name,
                    os.getuid(), 16384), b'public synthetic material')
            finally:
                os.close(descriptor)


if __name__ == '__main__':
    # -I excludes the script directory; admit this exact private test package.
    if len(sys.argv) == 5 and sys.argv[1] == '--owned-fifo-child':
        raise SystemExit(child(sys.argv[2], sys.argv[3], sys.argv[4] == 'replace'))
    unittest.main()
