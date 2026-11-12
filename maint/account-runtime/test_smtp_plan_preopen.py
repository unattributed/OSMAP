"""Actual writerless FIFO replacement must not consume the routing budget."""
import os
from pathlib import Path
import signal
import sys
import tempfile
import time
import unittest
from unittest.mock import patch

if len(sys.argv) > 1 and sys.argv[1] in ('source', 'red-source'):
    sys.path.insert(0, str(Path(__file__).parent / sys.argv.pop(1)))
from smtp_topology import FixedSmtpRouting
from operation_budget import OperationBudget
from authoritative_password import Refused


class RoutingPreopen(unittest.TestCase):
    def test_replacement_with_writerless_fifo_refuses_before_original_cutoff(self):
        with tempfile.TemporaryDirectory(prefix='osmap-routing-preopen-', dir='/tmp') as name:
            root = Path(name)
            plan = root / FixedSmtpRouting.PLAN
            plan.write_bytes(b'{}\n')
            plan.chmod(0o600)
            read_fd, write_fd = os.pipe()
            child = os.fork()
            if child == 0:
                os.close(read_fd)
                original = os.open
                def replace_before_open(path, flags, *args, **kwargs):
                    if Path(path) == plan:
                        plan.unlink()
                        os.mkfifo(plan, 0o600)
                        os.write(write_fd, b'open-race\n')
                    return original(path, flags, *args, **kwargs)
                try:
                    with patch('smtp_topology.os.open', side_effect=replace_before_open):
                        FixedSmtpRouting._private_read(root, os.getuid(),
                            OperationBudget(int(time.time()) + 5, maximum_seconds=2))
                except Refused:
                    os.write(write_fd, b'refused\n')
                    os._exit(0)
                except BaseException:
                    os.write(write_fd, b'wrong-error\n')
                    os._exit(2)
                os.write(write_fd, b'accepted\n')
                os._exit(3)
            os.close(write_fd)
            started = time.monotonic()
            cutoff = started + 1
            status = None
            try:
                while time.monotonic() < cutoff:
                    pid, value = os.waitpid(child, os.WNOHANG)
                    if pid == child:
                        status = value
                        break
                    time.sleep(0.005)
                if status is None:
                    # This exact fork child is still unreaped and owned. No
                    # native/foreign/historical process is signalled.
                    os.kill(child, signal.SIGKILL)
                    os.waitpid(child, 0)
                self.assertIsNotNone(status, 'writerless FIFO blocked before original budget checks')
                self.assertEqual(os.waitstatus_to_exitcode(status), 0)
                self.assertEqual(os.read(read_fd, 64), b'open-race\nrefused\n')
                self.assertLess(time.monotonic() - started, 1)
            finally:
                os.close(read_fd)


if __name__ == '__main__':
    unittest.main()
