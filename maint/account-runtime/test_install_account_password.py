"""Local installer refusal/disposition checks; no installed paths or services."""
import importlib.util
import json
from pathlib import Path
import subprocess
import sys
import tempfile
import time
import unittest
from unittest.mock import patch

import install_account_password as installer


class InstallerFailures(unittest.TestCase):
    def test_entrypoint_preserves_exact_refusal_and_unknown_disposition(self):
        script = (
            'import runpy,socket,sys;'
            'socket.gethostname=lambda:"unqualified.invalid";'
            'sys.argv=[sys.argv[1],"--stage","/nonexistent",'
            '"--manifest-sha256","a"*64,"--source-commit","b"*40];'
            'runpy.run_path(sys.argv[0],run_name="__main__")'
        )
        result = subprocess.run(
            [sys.executable, '-I', '-B', '-c', script, installer.__file__],
            stdout=subprocess.PIPE, stderr=subprocess.PIPE, timeout=5,
            check=False)
        self.assertEqual(result.returncode, 1)
        self.assertEqual(result.stderr, b'')
        body = json.loads(result.stdout)
        self.assertEqual(body['failure'], 'fixed_installation_authority')
        self.assertEqual(body['rollback'], 'UNKNOWN')
        self.assertFalse(body['installed'])

    def test_exception_payloads_are_not_exported(self):
        for error in (OSError(13, 'private password or path'),
                      ValueError('private password or path'),
                      installer.Refused('private password or path')):
            with self.subTest(error_type=type(error).__name__):
                self.assertNotIn('private', installer.failure_code(error))
        self.assertEqual(installer.failure_code(installer.Refused('publication_write_zero')),
                         'publication_write_zero')

    def test_publication_and_rollback_keep_separate_failure_causes(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            runtime = root / 'runtime'
            runtime.mkdir(mode=0o700)
            backups = root / 'backups'
            backups.mkdir()
            binary, rc = root / 'binary', root / 'rc'
            record = {'old_binary_sha256': None, 'old_rc_sha256': None,
                      'binary_sha256': 'a' * 64, 'rc_sha256': 'b' * 64}
            source_identity = ((), (0, 1), ())

            def publication(path, data, mode, owner, group, end, owned):
                path.write_bytes(data)
                path.chmod(0o600)
                owned[path] = ((), 'c' * 64)
                raise installer.Refused('published_readback_refused')

            def same(path, prior, cap, end):
                if path.exists():
                    raise installer.Refused('prior_absence_changed')

            with patch.multiple(installer, RUNTIME=runtime, BINARY=binary, RC=rc,
                                BACKUPS=backups), \
                    patch.object(installer, 'parents', return_value=()), \
                    patch.object(installer, 'admission', return_value=(
                        record, b'local binary', b'local rc', source_identity)), \
                    patch.object(installer, 'snapshot', return_value=None), \
                    patch.object(installer, 'same_snapshot', side_effect=same), \
                    patch.object(installer, 'require_helper_absent'), \
                    patch.object(installer, 'publish', side_effect=publication), \
                    patch.object(installer.signal, 'signal'):
                result = installer.install(root / 'stage', 'd' * 64, 'e' * 40,
                                           time.monotonic() + 60)
            self.assertEqual(result['failure'], 'published_readback_refused')
            self.assertEqual(result['rollback'], 'UNKNOWN')
            self.assertEqual(result['rollback_failures'], {
                str(binary): 'rollback_current_not_owned'})
            self.assertEqual(binary.read_bytes(), b'local binary')
            self.assertFalse(rc.exists())
            self.assertEqual(json.loads((Path(result['backup']) / 'result.json').read_bytes()),
                             result)


class NumericFstatContract(unittest.TestCase):
    def observe(self, header, images=()):
        row = b'root account-passwd 42 text 4, 2 88 100555 r 9041720\n'
        def producer(name, end):
            return b'' if name == 'ps' else header + b'\n' + row
        with patch.object(installer, 'fixed_observation', side_effect=producer):
            installer.require_helper_absent(set(images), time.monotonic() + 2)

    def test_numeric_header_without_optional_name_accepts_and_still_checks_image(self):
        header = b'USER CMD PID FD DEV INUM MODE R/W SZ|DV'
        self.observe(header)
        with self.assertRaises(installer.Refused) as error:
            self.observe(header, [(4, 2, 88)])
        self.assertEqual(str(error.exception), 'active_account_helper_text')

    def test_optional_name_is_accepted_but_changed_columns_refuse(self):
        header = b'USER CMD PID FD DEV INUM MODE R/W SZ|DV'
        self.observe(header + b' NAME')
        with self.assertRaises(installer.Refused) as error:
            self.observe(header.replace(b'DEV', b'MOUNT'))
        self.assertEqual(str(error.exception), 'installation_fstat_header')


class CandidateInstallerFailures(InstallerFailures):
    def setUp(self):
        path = (Path(__file__).resolve().parents[1] / 'ux' /
                's04_02_startup_candidate/sources/backend/install_account_password.py')
        spec = importlib.util.spec_from_file_location('review_candidate_installer', path)
        candidate = importlib.util.module_from_spec(spec)
        spec.loader.exec_module(candidate)
        replacement = patch(__name__ + '.installer', candidate)
        replacement.start()
        self.addCleanup(replacement.stop)


if __name__ == '__main__':
    unittest.main()
