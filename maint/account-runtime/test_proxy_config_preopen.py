"""Real private-file race controls; no mail, credentials, or native calls."""
import importlib.util
import os
from pathlib import Path
import select
import socket
import subprocess
import sys
import tempfile
import time
import unittest

HERE = Path(__file__).resolve().parent
RUNTIME = Path(os.environ.get('OSMAP_PROXY_RUNTIME', str(HERE)))
SOURCE = Path(os.environ.get('OSMAP_PROXY_CONFIG_SOURCE', str(HERE / 'mail_session_containment.py')))


def child(source, mode, name, reader):
    sys.path.insert(0, str(RUNTIME))
    spec = importlib.util.spec_from_file_location('proxy_preopen_subject', source)
    module = importlib.util.module_from_spec(spec)
    sys.modules[spec.name] = module
    spec.loader.exec_module(module)
    from operation_budget import OperationBudget
    root = Path(name)
    os.chmod(root, 0o700)
    (root / 'run').mkdir(mode=0o700)
    (root / 'run/login').mkdir(mode=0o700)
    config = root / 'dovecot.conf'
    config.write_bytes(b'public synthetic fixture\n')
    os.chmod(config, 0o600)
    with socket.socket(socket.AF_UNIX) as ipc:
        ipc.bind(str(root / 'run/login/ipc-proxy'))
        os.chmod(root / 'run/login/ipc-proxy', 0o600)
        namespace = module.OperatorOwnedProxyNamespace(root, os.getuid(), '127.0.0.1', 49123)
        if reader == 'certificate':
            config = root / 'smtp-topology.json'
            config.write_bytes(b'{"public":true}\n')
            os.chmod(config, 0o600)
            topology = object.__new__(module.OperatorOwnedSmtpTopology)
            topology._namespace = namespace
            topology._path = config
        payload = config.read_bytes()
        if mode == 'existing-fifo':
            config.unlink()
            os.mkfifo(config, 0o600)
        real_open = os.open
        changed = False

        def racing_open(path, flags, *args, **kwargs):
            nonlocal changed
            selected = Path(path) == config and not changed
            if selected and mode == 'fifo-at-open':
                changed = True
                config.rename(root / 'original-config')
                os.mkfifo(config, 0o600)
                os.write(1, b'writerless_fifo_open_witness\n')
            fd = real_open(path, flags, *args, **kwargs)
            if selected and mode == 'replace-after-open':
                changed = True
                config.rename(root / 'original-config')
                config.write_bytes(payload)
                os.chmod(config, 0o600)
                os.write(1, b'regular_path_replacement_witness\n')
            return fd

        os.open = racing_open
        try:
            if reader == 'certificate':
                _, value = topology._read()
                assert value == {'public': True}
            else:
                namespace.recheck(OperationBudget(int(time.time()) + 30, maximum_seconds=2))
            os.write(1, b'accepted\n')
            return 0
        except module.Refused:
            os.write(1, b'refused\n')
            return 0
        finally:
            os.open = real_open


class PrivateConfigPreopen(unittest.TestCase):
    def invoke(self, mode, reader="configuration"):
        scratch = tempfile.TemporaryDirectory(prefix='osmap-proxy-config-', dir='/tmp')
        process = subprocess.Popen(
            [sys.executable, '-B', str(Path(__file__).resolve()), '--child', str(SOURCE), mode, scratch.name, reader],
            stdout=subprocess.PIPE, stderr=subprocess.PIPE, start_new_session=True)
        data = bytearray()
        deadline = time.monotonic() + 3
        witnessed = False
        blocked = False
        try:
            while process.poll() is None:
                remaining = deadline - time.monotonic()
                if remaining <= 0:
                    blocked = True
                    break
                if select.select([process.stdout], [], [], min(.05, remaining))[0]:
                    part = os.read(process.stdout.fileno(), 1024)
                    data.extend(part)
                    self.assertLessEqual(len(data), 4096)
                    if b'writerless_fifo_open_witness\n' in data and not witnessed:
                        witnessed = True
                        deadline = time.monotonic() + .3
            if blocked:
                self.assertIsNone(process.poll())
                self.assertEqual(os.getpgid(process.pid), process.pid)
                process.kill()
                process.wait(timeout=2)
            rest, errors = process.communicate(timeout=2)
            data.extend(rest)
            self.assertLessEqual(len(data) + len(errors), 4096)
            try:
                os.killpg(process.pid, 0)
            except ProcessLookupError:
                group_gone = True
            else:
                group_gone = False
            self.assertTrue(group_gone, 'owned child group must be absent')
            if blocked:
                self.assertTrue(witnessed, 'no timeout without actual open witness')
                self.fail('witnessed writerless FIFO blocked; owned child killed, reaped, group absent')
            self.assertEqual(process.returncode, 0, errors.decode('utf-8', 'replace'))
            self.assertEqual(errors, b'')
            return bytes(data)
        finally:
            if process.poll() is None:
                process.kill()
                process.wait(timeout=2)
            process.stdout.close()
            process.stderr.close()
            try:
                os.killpg(process.pid, 0)
            except ProcessLookupError:
                scratch.cleanup()
                self.assertFalse(Path(scratch.name).exists(), 'owned private scratch must be absent')
            else:
                scratch._finalizer.detach()
                self.fail('owned group absence unconfirmed; private scratch retained')

    def test_original_regular_private_file_is_accepted(self):
        self.assertEqual(self.invoke('ordinary'), b'accepted\n')

    def test_writerless_fifo_replacement_at_open_refuses_without_blocking(self):
        self.assertEqual(self.invoke('fifo-at-open'), b'writerless_fifo_open_witness\nrefused\n')

    def test_existing_fifo_refuses_before_open(self):
        self.assertEqual(self.invoke('existing-fifo'), b'refused\n')

    def test_regular_path_replacement_after_open_refuses(self):
        self.assertEqual(self.invoke('replace-after-open'), b'regular_path_replacement_witness\nrefused\n')


class PrivateCertificatePreopen(PrivateConfigPreopen):
    def invoke(self, mode):
        return super().invoke(mode, 'certificate')


if __name__ == '__main__':
    if len(sys.argv) == 6 and sys.argv[1] == '--child':
        raise SystemExit(child(Path(sys.argv[2]), sys.argv[3], sys.argv[4], sys.argv[5]))
    unittest.main()
